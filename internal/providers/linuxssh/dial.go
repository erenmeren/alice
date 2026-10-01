package linuxssh

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// Budgets of one connection and one command (R37 item 17).
const (
	DefaultDialTimeout      = 10 * time.Second
	DefaultHandshakeTimeout = 15 * time.Second
	DefaultCommandTimeout   = 30 * time.Second
	LongCommandTimeout      = 60 * time.Second
	DefaultMaxOutput        = 8 << 20

	maxStderr      = 64 << 10
	osReleaseLimit = 64 << 10
	maxFactLength  = 200
)

// Algorithms (SEC-080). x/crypto adds the curve25519-sha256@libssh.org alias itself when
// curve25519-sha256 is requested.
var (
	kexAlgorithms = []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519,
		ssh.KeyExchangeECDHP256, ssh.KeyExchangeECDHP384, ssh.KeyExchangeECDHP521}
	cipherAlgorithms     = []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM}
	macAlgorithms        = []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM}
	allHostKeyAlgorithms = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
)

// hostKeyAlgorithmsFor restricts the handshake to the pinned key's algorithms: an RSA key is
// accepted only with SHA-2 signatures.
func hostKeyAlgorithmsFor(pinnedType string) []string {
	if pinnedType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{pinnedType}
}

func sshConfig() ssh.Config {
	return ssh.Config{KeyExchanges: kexAlgorithms, Ciphers: cipherAlgorithms, MACs: macAlgorithms}
}

// HostKeyOf converts an SSH public key into the stored form.
func HostKeyOf(k ssh.PublicKey) providers.HostKey {
	return providers.HostKey{Type: k.Type(), PublicKey: k.Marshal(), Fingerprint: ssh.FingerprintSHA256(k)}
}

// Config is the SSH endpoint of a target (targets.config).
type Config struct {
	Host     string
	Port     int
	Username string
}

func (c Config) addr() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }

// ServiceUser is the account the setup script creates on every target.
const ServiceUser = "alice-svc"

// ParseConfig reads a target configuration. The inventory normalizes and validates the address
// when a target is added; this is the provider's own check (no network).
func ParseConfig(cfg providers.TargetConfig) (Config, []validate.FieldError) {
	var errs validate.Errors
	c := Config{Port: 22, Username: ServiceUser}
	host, _ := cfg["host"].(string)
	switch {
	case host == "":
		errs.Add("host", validate.Required, nil)
	case len(host) > 253 || strings.ContainsAny(host, " \t\r\n/\\@'\"`$;|&<>()*?~") || !utf8.ValidString(host):
		errs.Add("host", validate.Pattern, nil)
	default:
		c.Host = host
	}
	if v, ok := cfg["port"]; ok && v != nil {
		p, ok := toInt(v)
		if !ok || p < 1 || p > 65535 {
			errs.Add("port", validate.OutOfRange, map[string]string{"min": "1", "max": "65535"})
		} else {
			c.Port = p
		}
	}
	if v, ok := cfg["username"]; ok && v != nil {
		u, _ := v.(string)
		if !helperproto.ValidUser(u) {
			errs.Add("username", validate.Pattern, nil)
		} else {
			c.Username = u
		}
	}
	if len(errs) == 0 {
		return c, nil
	}
	return c, []validate.FieldError(errs)
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		if n < -1<<31 || n > 1<<31-1 {
			return 0, false
		}
		return int(n), true
	case float64:
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < -1<<31 || i > 1<<31-1 {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

// Dialer opens SSH connections that trust only the pinned host key of a target (SEC-080).
type Dialer struct {
	Clock            clock.Clock
	HostKeys         providers.HostKeyStore
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	NetDial          func(ctx context.Context, network, addr string) (net.Conn, error) // nil = net.Dialer
}

func (d *Dialer) clk() clock.Clock {
	if d.Clock == nil {
		return clock.Real{}
	}
	return d.Clock
}

func (d *Dialer) dialTimeout() time.Duration {
	if d.DialTimeout <= 0 {
		return DefaultDialTimeout
	}
	return d.DialTimeout
}

func (d *Dialer) handshakeTimeout() time.Duration {
	if d.HandshakeTimeout <= 0 {
		return DefaultHandshakeTimeout
	}
	return d.HandshakeTimeout
}

var (
	errHostKeyRefused = errors.New("linuxssh: host key refused")
	errConnClosed     = errors.New("linuxssh: connection closed")
	errOutputTooLarge = errors.New("linuxssh: command output too large")
)

// hostKeyDecision is what the host-key callback saw. The callback runs on x/crypto's key-exchange
// goroutine, so it does no I/O and only records the presented key under a mutex; Dial reads the
// record after the handshake returned and calls the store from its own goroutine.
type hostKeyDecision struct {
	mu        sync.Mutex
	called    bool
	refused   bool
	presented providers.HostKey
}

func (h *hostKeyDecision) record(k providers.HostKey, refused bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.called, h.refused, h.presented = true, refused, k
}

func (h *hostKeyDecision) snapshot() (called, refused bool, presented providers.HostKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.called, h.refused, h.presented
}

// lazyAuth fetches the client key only when the server asks for public-key authentication, i.e.
// after the host key matched its pin; an unknown or changed server never causes a decryption.
type lazyAuth struct {
	cred providers.CredentialSource
	ctx  context.Context

	mu        sync.Mutex
	attempted bool
	err       error
	signer    ssh.Signer
	release   func()
}

func (l *lazyAuth) signers() ([]ssh.Signer, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempted = true
	if l.signer != nil { // a second round (AuthenticationMethods publickey,publickey) reuses the key
		return []ssh.Signer{l.signer}, nil
	}
	signer, release, err := l.cred.SSHSigner(l.ctx)
	if err != nil {
		l.err = err
		return nil, err
	}
	l.signer, l.release = signer, release
	return []ssh.Signer{signer}, nil
}

func (l *lazyAuth) done() (attempted bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.release != nil {
		l.release()
		l.release = nil
	}
	return l.attempted, l.err
}

// observe records a presented key through the store within the handshake budget. The store call
// runs in its own goroutine so a store that ignores its context cannot hang Dial.
func (d *Dialer) observe(ctx context.Context, target uuid.UUID, k providers.HostKey, changed bool) error {
	ctx, cancel := context.WithTimeout(ctx, d.handshakeTimeout())
	defer cancel()
	res := make(chan error, 1)
	go func() { res <- d.HostKeys.Observed(ctx, target, k, changed) }()
	select {
	case err := <-res:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Dial connects to target. Without a pinned key the presented key is recorded as observed and the
// connection stops before authentication (target.host_key_unconfirmed); a key other than the
// pinned one, or a server that no longer offers the pinned algorithm, is recorded as changed and
// the connection stops before authentication (target.host_key_changed). Background work can never
// pin a key: only the inventory's confirmation does. The client key is decrypted only once the
// host key matched.
func (d *Dialer) Dial(ctx context.Context, target uuid.UUID, cfg Config, cred providers.CredentialSource) (*Conn, error) {
	if d.HostKeys == nil {
		return nil, providers.NewError("internal.unexpected", false, errors.New("linuxssh: dialer has no host key store"), nil)
	}
	pinned, err := d.HostKeys.Pinned(ctx, target)
	havePin := err == nil
	if err != nil && !errors.Is(err, providers.ErrNoPinnedKey) {
		return nil, providers.NewError("internal.unexpected", true, err, nil)
	}
	var dec hostKeyDecision
	auth := &lazyAuth{cred: cred, ctx: ctx}
	algorithms := allHostKeyAlgorithms
	if havePin {
		algorithms = hostKeyAlgorithmsFor(pinned.Type)
	}
	conf := &ssh.ClientConfig{
		Config:            sshConfig(),
		User:              cfg.Username,
		Auth:              []ssh.AuthMethod{ssh.PublicKeysCallback(auth.signers)},
		HostKeyAlgorithms: algorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			match := havePin && subtle.ConstantTimeCompare(key.Marshal(), pinned.PublicKey) == 1
			dec.record(HostKeyOf(key), !match)
			if match {
				return nil
			}
			return errHostKeyRefused
		},
	}
	r := d.handshake(ctx, cfg.addr(), conf)
	attempted, credErr := auth.done()
	called, refused, presented := dec.snapshot()
	if r.dialErr != nil {
		return nil, providers.NewError("ssh.unreachable", true, r.dialErr, nil)
	}
	if r.err != nil {
		switch {
		case credErr != nil:
			return nil, providers.NewError("internal.unexpected", false, credErr, nil)
		case refused:
			if err := d.observe(ctx, target, presented, havePin); err != nil {
				return nil, providers.NewError("internal.unexpected", true, err, nil)
			}
			if havePin {
				return nil, changedError(pinned, presented)
			}
			return nil, providers.NewError("target.host_key_unconfirmed", false, nil,
				map[string]string{"fingerprint": presented.Fingerprint})
		case r.timedOut:
			return nil, providers.NewError("ssh.timeout", true, r.err, nil)
		case havePin && !called:
			return nil, d.probeChanged(ctx, target, cfg, pinned, r.err)
		case called:
			// The host key matched, so a later failure is the authentication phase.
			reason := "key_rejected"
			if !attempted {
				reason = "publickey_not_offered"
			}
			return nil, providers.NewError("ssh.auth_failed", false, r.err, map[string]string{"reason": reason})
		default:
			return nil, providers.NewError("ssh.unreachable", true, r.err, nil)
		}
	}
	return &Conn{client: r.client, target: target, cfg: cfg, hostKey: presented, clock: d.clk()}, nil
}

func changedError(old, presented providers.HostKey) error {
	return providers.NewError("target.host_key_changed", false, nil,
		map[string]string{"old_fingerprint": old.Fingerprint, "new_fingerprint": presented.Fingerprint})
}

// probeChanged runs after a handshake with the pinned algorithms failed before any host key was
// presented: it asks once for any host key (and always aborts before authentication). A key other
// than the pinned one means the server's identity changed.
func (d *Dialer) probeChanged(ctx context.Context, target uuid.UUID, cfg Config, pinned providers.HostKey, cause error) error {
	var mu sync.Mutex
	var seenRaw *providers.HostKey
	conf := &ssh.ClientConfig{
		Config:            sshConfig(),
		User:              cfg.Username,
		HostKeyAlgorithms: allHostKeyAlgorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hk := HostKeyOf(key)
			mu.Lock()
			seenRaw = &hk
			mu.Unlock()
			return errHostKeyRefused
		},
	}
	r := d.handshake(ctx, cfg.addr(), conf)
	if r.client != nil {
		_ = r.client.Close() // cannot happen: the callback always refuses
	}
	mu.Lock()
	seen := seenRaw
	mu.Unlock()
	switch {
	case seen == nil && r.dialErr != nil:
		return providers.NewError("ssh.unreachable", true, r.dialErr, nil)
	case seen == nil && r.timedOut:
		return providers.NewError("ssh.timeout", true, cause, nil)
	case seen == nil, subtle.ConstantTimeCompare(seen.PublicKey, pinned.PublicKey) == 1:
		return providers.NewError("ssh.protocol_error", false, cause, nil)
	}
	if err := d.observe(ctx, target, *seen, true); err != nil {
		return providers.NewError("internal.unexpected", true, err, nil)
	}
	return changedError(pinned, *seen)
}

type handshakeResult struct {
	client   *ssh.Client
	dialErr  error
	err      error
	timedOut bool
}

// handshake dials addr and runs the SSH handshake within the handshake budget of the injected
// clock; cancelling ctx aborts it.
func (d *Dialer) handshake(ctx context.Context, addr string, conf *ssh.ClientConfig) handshakeResult {
	dial := d.NetDial
	if dial == nil {
		dial = (&net.Dialer{Timeout: d.dialTimeout()}).DialContext
	}
	dctx, cancelDial := context.WithTimeout(ctx, d.dialTimeout())
	defer cancelDial()
	nc, err := dial(dctx, "tcp", addr)
	if err != nil {
		return handshakeResult{dialErr: err}
	}
	done := make(chan struct{})
	var timedOut atomic.Bool
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			timedOut.Store(true)
			_ = nc.Close()
		case <-d.clk().After(d.handshakeTimeout()):
			timedOut.Store(true)
			_ = nc.Close()
		}
	}()
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, conf)
	close(done)
	if err != nil {
		_ = nc.Close()
		return handshakeResult{err: err, timedOut: timedOut.Load()}
	}
	client := ssh.NewClient(c, chans, reqs)
	if timedOut.Load() {
		_ = client.Close()
		return handshakeResult{err: errConnClosed, timedOut: true}
	}
	return handshakeResult{client: client}
}

// Conn is one authenticated SSH connection to a target whose host key matched its pin.
type Conn struct {
	client  *ssh.Client
	target  uuid.UUID
	cfg     Config
	hostKey providers.HostKey
	clock   clock.Clock

	mu     sync.Mutex
	broken bool
	closed bool
}

// Result is what a command returned. Helper exit codes stay here; DecodeHelper interprets them.
type Result struct {
	Stdout   []byte
	ExitCode int
}

// HostKey is the (pinned) key the server presented.
func (c *Conn) HostKey() providers.HostKey { return c.hostKey }

// Healthy reports whether the connection may run further commands.
func (c *Conn) Healthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.broken && !c.closed
}

func (c *Conn) markBroken() {
	c.mu.Lock()
	c.broken = true
	c.mu.Unlock()
	_ = c.client.Close()
}

// Close closes the connection.
func (c *Conn) Close() error {
	c.mu.Lock()
	already := c.closed
	c.closed = true
	c.mu.Unlock()
	if already {
		return nil
	}
	return c.client.Close()
}

// Run executes one constructor-built command in a new session. A command that exceeds its time
// budget, a cancelled context or an output flood closes the whole connection (it is never reused).
// Remote stderr is capped and discarded: it is never logged or shown (SC-4).
func (c *Conn) Run(ctx context.Context, cmd HelperCommand) (Result, error) {
	line := cmd.Line()
	params := map[string]string{"subcommand": cmd.Subcommand()}
	if line == "" {
		return Result{}, providers.NewError("ssh.protocol_error", false, ErrInvalidArgument, params)
	}
	if err := ctx.Err(); err != nil {
		// Checked first: a select below would pick between a finished command and the context at
		// random. Nothing ran, so the connection stays usable.
		return Result{}, providers.NewError("ssh.timeout", true, err, params)
	}
	if !c.Healthy() {
		return Result{}, providers.NewError("ssh.unreachable", true, errConnClosed, params)
	}
	sess, err := c.client.NewSession()
	if err != nil {
		c.markBroken()
		return Result{}, providers.NewError("ssh.unreachable", true, err, params)
	}
	defer func() { _ = sess.Close() }()
	stdout := &cappedWriter{max: cmd.maxOutput, onOverflow: func() { _ = sess.Close() }}
	sess.Stdout = stdout
	sess.Stderr = &cappedWriter{max: maxStderr, discard: true}
	sess.Stdin = bytes.NewReader(cmd.stdin)
	timeout := cmd.timeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(line) }()
	var runErr error
	select {
	case runErr = <-done:
	case <-c.clock.After(timeout):
		c.markBroken()
		<-done
		return Result{}, providers.NewError("ssh.timeout", true, nil, params)
	case <-ctx.Done():
		c.markBroken()
		<-done
		return Result{}, providers.NewError("ssh.timeout", true, ctx.Err(), params)
	}
	if stdout.overflowed() {
		c.markBroken()
		return Result{}, providers.NewError("ssh.output_too_large", false, errOutputTooLarge, params)
	}
	var exitErr *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case runErr == nil:
		return Result{Stdout: stdout.bytes()}, nil
	case errors.As(runErr, &exitErr) && (exitErr.Signal() != "" || exitErr.ExitStatus() < 0):
		return Result{}, providers.NewError("ssh.protocol_error", false, runErr, params)
	case errors.As(runErr, &exitErr):
		return Result{Stdout: stdout.bytes(), ExitCode: exitErr.ExitStatus()}, nil
	case errors.As(runErr, &missing):
		return Result{}, providers.NewError("ssh.protocol_error", false, runErr, params)
	default:
		c.markBroken()
		return Result{}, providers.NewError("ssh.unreachable", true, runErr, params)
	}
}

// OSRelease runs the one fixed non-helper command and keeps ID, VERSION_ID and PRETTY_NAME.
func (c *Conn) OSRelease(ctx context.Context) (providers.OSRelease, error) {
	res, err := c.Run(ctx, HelperCommand{fixed: OSReleaseCommand, timeout: DefaultCommandTimeout, maxOutput: osReleaseLimit})
	if err != nil {
		return providers.OSRelease{}, err
	}
	if res.ExitCode != 0 {
		return providers.OSRelease{}, providers.NewError("ssh.protocol_error", false, nil, map[string]string{"subcommand": "os-release"})
	}
	var r providers.OSRelease
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		switch k {
		case "ID":
			r.ID = cleanValue(v, maxFactLength)
		case "VERSION_ID":
			r.VersionID = cleanValue(v, maxFactLength)
		case "PRETTY_NAME":
			r.PrettyName = cleanValue(v, maxFactLength)
		}
	}
	return r, nil
}

// cleanValue makes remote text safe to store and show: quotes around it removed, invalid UTF-8
// and control characters (terminal escapes) dropped, length limited (SC-4).
func cleanValue(v string, limit int) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	v = strings.ToValidUTF8(v, "")
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, v)
	if utf8.RuneCountInString(v) > limit {
		v = string([]rune(v)[:limit])
	}
	return v
}

// cappedWriter keeps at most max bytes. Over the cap it either discards (stderr) or fails and
// closes the session through onOverflow (stdout).
type cappedWriter struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	max        int64
	discard    bool
	over       bool
	onOverflow func()
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.over {
		if w.discard {
			return len(p), nil
		}
		return 0, errOutputTooLarge
	}
	if int64(w.buf.Len())+int64(len(p)) > w.max {
		w.over = true
		if w.discard {
			w.buf.Write(p[:int(w.max)-w.buf.Len()])
			return len(p), nil
		}
		if w.onOverflow != nil {
			go w.onOverflow() // not inside Write: the session's copy goroutine is calling us
		}
		return 0, errOutputTooLarge
	}
	w.buf.Write(p)
	return len(p), nil
}

func (w *cappedWriter) overflowed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.over && !w.discard
}

func (w *cappedWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

var helperCodeRE = regexp.MustCompile(`^[A-Z][A-Z_]{0,39}$`)

// decodeOne decodes exactly one JSON value.
func decodeOne(b []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("linuxssh: trailing data after the helper's answer")
	}
	return nil
}

// helperReason maps a helper error code to a provider reason. Codes Alice acts on have their own
// reason; every other code (USAGE, NOT_ROOT, PATH_NOT_ALLOWED, UNSAFE_FILE, SSHD_FAILED, IO_ERROR,
// …) is ssh.helper_refused, and its helper_code parameter tells the UI which one.
func helperReason(exit int, code string) (reason string, retryable bool) {
	switch {
	case code == helperproto.CodeHashMismatch && exit == helperproto.ExitPrecondition:
		return "ssh.file_changed", true // the file changed between read and write (F-38)
	case code == helperproto.CodeAuthorizedKeysCommand:
		return "ssh.keys_managed_elsewhere", false // sshd takes this user's keys from a program (F-35)
	default:
		return "ssh.helper_refused", false
	}
}

// DecodeHelper turns a helper Result into its typed answer or a *providers.Error. Exit 0 must carry
// {"ok": true, …}; exits 2, 3 and 4 carry the helper's error code (only a fixed-format code is
// kept: remote text never reaches messages); any other exit means sudo or the helper itself is
// missing (spec §12.9).
func DecodeHelper[T any](r Result, sub string) (T, error) {
	var zero T
	params := map[string]string{"subcommand": sub}
	protocol := func(cause error) (T, error) {
		return zero, providers.NewError("ssh.protocol_error", false, cause, map[string]string{"subcommand": sub})
	}
	switch r.ExitCode {
	case helperproto.ExitOK:
		var head struct {
			OK *bool `json:"ok"`
		}
		if err := decodeOne(r.Stdout, &head); err != nil {
			return protocol(err)
		}
		if head.OK == nil || !*head.OK {
			return protocol(errors.New("linuxssh: helper answer without ok=true"))
		}
		var out T
		if err := decodeOne(r.Stdout, &out); err != nil {
			return protocol(err)
		}
		return out, nil
	case helperproto.ExitRefused, helperproto.ExitPrecondition, helperproto.ExitFailed:
		var e helperproto.ErrorResponse
		if err := decodeOne(r.Stdout, &e); err != nil {
			return protocol(err)
		}
		if e.OK || !helperCodeRE.MatchString(e.Code) {
			return protocol(errors.New("linuxssh: malformed helper error"))
		}
		params["helper_code"] = e.Code
		reason, retryable := helperReason(r.ExitCode, e.Code)
		return zero, providers.NewError(reason, retryable, nil, params)
	default:
		params["exit_code"] = strconv.Itoa(r.ExitCode)
		return zero, providers.NewError("ssh.helper_missing", false, nil, params)
	}
}
