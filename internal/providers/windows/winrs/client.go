package winrs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	ntlmssp "github.com/Azure/go-ntlmssp"
	"github.com/google/uuid"

	"alice/internal/platform/netaddr"
)

// Client runs one program per call in one WinRS shell on one TLS connection (R71 Rulings 12 and 28).
type Client struct {
	TLS  *tls.Config // the pin (tlspin); no client certificate
	User string      // as Ruling 6 sends it ("alice", "HOST\alice", "DOMAIN\alice")
	// Password is for this call only. shortcut: go-ntlmssp takes the password as a Go string, which cannot be
	// zeroed; the caller zeroes its own copy after Run. Upgrade only if go-ntlmssp gains a byte-slice API.
	Password string
	// Dial opens the call's TCP connection; nil is netaddr.DialContext with DefaultDialTimeout.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Call is one program run.
type Call struct {
	Addr      string            // host:port
	Program   string            // winproto.HelperPath, passed in by the caller
	Args      []string          // ["ssh"]
	Env       map[string]string // {"SSH_ORIGINAL_COMMAND": line}
	Stdin     []byte            // nil for none
	Timeout   time.Duration
	MaxOutput int64
}

// Result is a finished program: its stdout, its exit code, and the SubjectPublicKeyInfo of the leaf the listener
// presented.
type Result struct {
	Stdout   []byte
	ExitCode int
	PeerSPKI []byte
}

// The call's errors. Each error of a call wraps its stage: everything up to and including the Create response
// (the NTLM exchange included) also wraps ErrNotSent, since the program cannot have started. *FaultError and
// ErrProtocol carry their stage the same way. No error keeps a server text or a credential.
var (
	ErrBadConfig      = errors.New("winrs: the call's configuration is refused")
	ErrAuthRefused    = errors.New("winrs: the server refused the sign-in")
	ErrTimeout        = errors.New("winrs: the call ran out of time")
	ErrUnreachable    = errors.New("winrs: the server could not be reached")
	ErrOutputTooLarge = errors.New("winrs: the program's output is too large")
	ErrNotSent        = errors.New("winrs: nothing reached the program")

	errSecondDial = errors.New("winrs: a call opens one connection only")
)

const (
	// ShellIdleSlack is added to the call's timeout for the shell's IdleTimeOut, so a shell Alice could not delete
	// is reaped by the server soon after the call's end.
	ShellIdleSlack = 60 * time.Second
	// DefaultDialTimeout and DefaultHandshakeTimeout are linuxssh's values (winrs does not import linuxssh; a test
	// in internal/providers/windows compares them).
	DefaultDialTimeout      = 10 * time.Second
	DefaultHandshakeTimeout = 15 * time.Second

	// maxDialsPerCall: the call's one connection carries the NTLM sign-in and everything after it (Windows binds
	// the logon to the connection). F24 (d) raises it to 2 only if Windows closes the connection after the
	// anonymous 401.
	maxDialsPerCall = 1
	receiveTimeout  = 20 * time.Second
	cleanupBudget   = 5 * time.Second
	// faultTimedOut is w:TimedOut: a Receive that saw no output within its OperationTimeout. It is asked again.
	faultTimedOut = 2150858793
)

func notSent(err error) error { return fmt.Errorf("%w (%w)", err, ErrNotSent) }

func (c *Client) check(call Call) error {
	t := c.TLS
	if t == nil || t.MinVersion < tls.VersionTLS12 || (t.MaxVersion != 0 && t.MaxVersion < tls.VersionTLS12) ||
		len(t.Certificates) > 0 || t.GetClientCertificate != nil || (t.InsecureSkipVerify && t.VerifyConnection == nil) ||
		c.User == "" || strings.Contains(c.User, ":") || c.Password == "" || call.Timeout <= 0 || call.MaxOutput <= 0 ||
		!validEnv(call.Env) || !validCommand(call.Program, call.Args) {
		return ErrBadConfig
	}
	if _, _, err := net.SplitHostPort(call.Addr); err != nil {
		return ErrBadConfig
	}
	return nil
}

// Run runs call: Create (the NTLM exchange happens here), Command, the stdin Sends, Receive until Done, and Delete
// on every path after a successful Create but a refused sign-in. A timeout or an output overflow also sends Signal
// terminate. Each cleanup request has its own budget, detached from ctx. A refused sign-in is never retried.
func (c *Client) Run(ctx context.Context, call Call) (Result, error) {
	if err := c.check(call); err != nil {
		return Result{}, notSent(err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, notSent(fmt.Errorf("%w: %w", ErrTimeout, err))
	}
	host, port, _ := net.SplitHostPort(call.Addr)
	url := "https://" + net.JoinHostPort(host, port) + "/wsman"
	create, err := CreateShellRequest(Header{To: url, MessageID: "uuid:" + uuid.NewString()}, call.Env, call.Timeout+ShellIdleSlack)
	if err != nil {
		return Result{}, notSent(ErrBadConfig)
	}
	s := c.newSession(ctx, call, url)
	defer s.close()
	ctx, cancel := context.WithTimeout(ctx, call.Timeout)
	defer cancel()

	resp, err := s.post(ctx, create)
	if err == nil {
		var shellID string
		if shellID, err = ParseShellCreated(resp); err == nil {
			res, cmdID, err := s.run(ctx, shellID)
			if !errors.Is(err, ErrAuthRefused) { // a refused sign-in is never tried again: the idle time reaps the shell
				s.cleanup(ctx, shellID, cmdID, errors.Is(err, ErrTimeout) || errors.Is(err, ErrOutputTooLarge))
			}
			if err != nil {
				return Result{}, err
			}
			res.PeerSPKI = s.peerSPKI()
			return res, nil
		}
	}
	return Result{}, notSent(err)
}

// session is one call's connection and its requests.
type session struct {
	call           Call
	url            string
	user, password string
	tr             *http.Transport
	client         *http.Client
	dialer         *dialer
	reqCtx         context.Context // outlives the call's ctx, so an abandoned request can free the connection
	stop           context.CancelFunc
	wg             sync.WaitGroup

	mu   sync.Mutex
	spki []byte
}

func (c *Client) newSession(ctx context.Context, call Call, url string) *session {
	d := &dialer{dial: c.Dial}
	if d.dial == nil {
		d.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netaddr.DialContext(ctx, &net.Dialer{Timeout: DefaultDialTimeout}, network, addr)
		}
	}
	cfg := c.TLS.Clone()
	cfg.NextProtos = nil // HTTP/1.1 only
	tr := &http.Transport{
		DialContext:         d.dialContext,
		TLSClientConfig:     cfg,
		TLSHandshakeTimeout: DefaultHandshakeTimeout,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	s := &session{call: call, url: url, user: c.User, password: c.Password, tr: tr, dialer: d}
	s.client = &http.Client{
		Transport:     ntlmssp.Negotiator{RoundTripper: tr},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	s.reqCtx, s.stop = context.WithCancel(context.WithoutCancel(ctx))
	return s
}

// close ends every request still running, closes the connection and waits for the requests' goroutines.
func (s *session) close() {
	s.stop()
	s.tr.CloseIdleConnections()
	s.dialer.closeAll()
	s.wg.Wait()
}

func (s *session) header(operationTimeout time.Duration) Header {
	return Header{To: s.url, MessageID: "uuid:" + uuid.NewString(), OperationTimeout: operationTimeout}
}

func (s *session) peerSPKI() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spki
}

// run is Command, the Sends and the Receive loop of the created shell.
func (s *session) run(ctx context.Context, shellID string) (Result, string, error) {
	req, err := CommandRequest(s.header(0), shellID, s.call.Program, s.call.Args)
	if err != nil {
		return Result{}, "", ErrBadConfig
	}
	resp, err := s.post(ctx, req)
	if err != nil {
		return Result{}, "", err
	}
	cmdID, err := ParseCommandStarted(resp)
	if err != nil {
		return Result{}, "", err
	}
	in := s.call.Stdin
	for {
		n := min(len(in), MaxSendChunk)
		req, err := SendRequest(s.header(0), shellID, cmdID, in[:n], n == len(in))
		if err != nil {
			return Result{}, cmdID, err
		}
		if _, err := s.post(ctx, req); err != nil {
			return Result{}, cmdID, err
		}
		if in = in[n:]; len(in) == 0 {
			break
		}
	}
	res, err := s.receive(ctx, shellID, cmdID)
	return res, cmdID, err
}

func (s *session) receive(ctx context.Context, shellID, cmdID string) (Result, error) {
	var out []byte
	for {
		// The server answers by the call's deadline, so Signal and Delete find the connection free.
		wait := receiveTimeout
		if dl, ok := ctx.Deadline(); ok {
			wait = min(wait, max(time.Until(dl), time.Second))
		}
		req, err := ReceiveRequest(s.header(wait), shellID, cmdID)
		if err != nil {
			return Result{}, err
		}
		resp, err := s.post(ctx, req)
		var fe *FaultError
		if errors.As(err, &fe) && fe.Code == faultTimedOut {
			continue
		}
		if err != nil {
			return Result{}, err
		}
		r, err := ParseReceived(resp, cmdID)
		if err != nil {
			return Result{}, err
		}
		if int64(len(out))+int64(len(r.Stdout)) > s.call.MaxOutput {
			return Result{}, ErrOutputTooLarge
		}
		out = append(out, r.Stdout...) // stderr is never kept
		if r.Done {
			return Result{Stdout: out, ExitCode: r.ExitCode}, nil
		}
	}
}

// cleanup sends Signal terminate (when signal is set and the command started), then Delete, each on its own
// budget detached from ctx. Their failures change nothing: the shell's idle time reaps it.
func (s *session) cleanup(ctx context.Context, shellID, cmdID string, signal bool) {
	send := func(req []byte, err error) {
		if err != nil {
			return
		}
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupBudget)
		defer cancel()
		_, _ = s.post(cctx, req)
	}
	if signal && cmdID != "" {
		send(SignalRequest(s.header(0), shellID, cmdID, SignalTerminate))
	}
	send(DeleteRequest(s.header(0), shellID))
}

// post sends one request on the call's connection and waits for its answer or the end of ctx. A request left
// behind keeps running until it ends or the session closes.
func (s *session) post(ctx context.Context, body []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	type answer struct {
		body []byte
		err  error
	}
	ch := make(chan answer, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		b, err := s.roundTrip(body)
		ch <- answer{b, err}
	}()
	select {
	case a := <-ch:
		return a.body, a.err
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrTimeout, ctx.Err())
	}
}

func (s *session) roundTrip(body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(s.reqCtx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return nil, ErrBadConfig
	}
	req.Header.Set("Content-Type", ContentType)
	req.SetBasicAuth(s.user, s.password) // read by the Negotiator, never forwarded (Ruling 28)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		s.mu.Lock()
		if s.spki == nil {
			s.spki = append([]byte(nil), resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo...)
		}
		s.mu.Unlock()
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	case len(b) > MaxResponseBody:
		return nil, ErrProtocol
	case resp.StatusCode == http.StatusOK:
		return b, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		if s.dialer.wasRefused() { // the exchange needed a connection the call may not open
			return nil, fmt.Errorf("%w: %w", ErrUnreachable, errSecondDial)
		}
		return nil, ErrAuthRefused
	}
	if fe, ok := ParseFault(b); ok {
		return nil, fe
	}
	return nil, ErrProtocol
}

// dialer opens the call's one connection and refuses any other.
type dialer struct {
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	mu      sync.Mutex
	dials   int
	refused bool
	conns   []net.Conn
}

func (d *dialer) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	if d.dials >= maxDialsPerCall {
		d.refused = true
		d.mu.Unlock()
		return nil, errSecondDial
	}
	d.dials++
	d.mu.Unlock()
	c, err := d.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return c, nil
}

func (d *dialer) wasRefused() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.refused
}

func (d *dialer) closeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		_ = c.Close()
	}
}
