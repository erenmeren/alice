package linuxssh

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"alice/internal/providers/linuxssh/helperproto"
)

// HelperCommand is one remote command line. Its fields are unexported, so a command can only be
// built by the constructors below: every argument passed helperproto's vocabulary check and
// quoteArg (spec §6.6, SEC-063), or, for a forced-command target, ForcedCommand's token check
// (R60 Ruling 5). There is no way to send a free-form shell string.
type HelperCommand struct {
	sub    string
	tokens []string // rendered arguments: constant flag names or quoteArg output
	// stdin is behind two pointers: a command held in an unexported field of another struct is
	// formatted by fmt without Format (fmt cannot call methods there). A pointer below the top
	// level prints as an address for %v; for any other verb fmt's bad-verb path expands it once
	// (&{...}), and the second pointer inside is then printed as an address again, never as the
	// key bytes. Copies of a command share the input.
	stdin *stdinBuf
	sudo  bool
	// bare: the line is sub and tokens only (ForcedCommand). sshd runs one program for every session
	// and hands it the line verbatim, so there is neither sudo nor a helper path to name.
	bare      bool
	fixed     string // the one fixed non-helper command (cat /etc/os-release); set only in dial.go
	timeout   time.Duration
	maxOutput int64
}

const (
	smallOutput    = 64 << 10
	hostKeysOutput = 1 << 20
	readOutput     = 2 << 20 // base64 of a 1 MiB file plus the JSON around it
	// probeOutput: base64 of helperproto.MaxProbeChainBytes of presented chain plus the JSON around it (R51)
	probeOutput = 128 << 10
)

// OSReleaseCommand is the only command Alice runs that is not alice-helper (spec §6.6).
const OSReleaseCommand = "cat /etc/os-release"

// ErrInvalidArgument means a value is outside the helper's argument vocabulary; no command is built.
var ErrInvalidArgument = errors.New("linuxssh: argument outside the allowed vocabulary")

// quoteArg is the single audited quoting function for remote command lines (SEC-063). The value
// must be in helperproto's vocabulary ([A-Za-z0-9._/@:+-], no ".." component, no leading '-'),
// which contains no quote, no space and no shell metacharacter, so single quotes make it one
// literal word for the remote shell.
func quoteArg(s string) (string, error) {
	if !helperproto.ValidArg(s) || strings.ContainsRune(s, '\'') {
		return "", ErrInvalidArgument
	}
	return "'" + s + "'", nil
}

func privileged(sub string, timeout time.Duration, maxOutput int64, tokens ...string) HelperCommand {
	return HelperCommand{sub: sub, tokens: tokens, sudo: true, timeout: timeout, maxOutput: maxOutput}
}

// CmdVersion asks the helper for its version; it runs without sudo (sudoers does not list it).
func CmdVersion() HelperCommand {
	return HelperCommand{sub: helperproto.SubVersion, timeout: DefaultCommandTimeout, maxOutput: smallOutput}
}

// CmdSSHDDump returns the effective sshd configuration (sshd -T).
func CmdSSHDDump() HelperCommand {
	return privileged(helperproto.SubSSHDDump, LongCommandTimeout, DefaultMaxOutput)
}

// CmdHostKeys lists the server's host keys with their fingerprints.
func CmdHostKeys() HelperCommand {
	return privileged(helperproto.SubHostKeys, DefaultCommandTimeout, hostKeysOutput)
}

// CmdAuthKeysList lists the users and the authorized_keys files sshd would read for them.
func CmdAuthKeysList() HelperCommand {
	return privileged(helperproto.SubAuthKeysList, LongCommandTimeout, DefaultMaxOutput)
}

// CmdAuthKeysRead reads one authorized_keys file (the helper accepts only paths it computed itself).
func CmdAuthKeysRead(path string) (HelperCommand, error) {
	if !helperproto.ValidPath(path) {
		return HelperCommand{}, ErrInvalidArgument
	}
	q, err := quoteArg(path)
	if err != nil {
		return HelperCommand{}, err
	}
	// The helper scans every listed user (sshd -T each) before it reads, as for authkeys-list.
	return privileged(helperproto.SubAuthKeysRead, LongCommandTimeout, readOutput, q), nil
}

// CmdAuthKeysWrite replaces one authorized_keys file with content when its current SHA-256 is
// expectSHA256 (helperproto.AbsentSHA256 for a file that does not exist yet). op names the backup.
// The SHA-256 of content goes on the command line too (--content-sha256, protocol 3): the helper
// refuses stdin that does not match it, so a connection that drops while the content is sent
// never leaves a truncated file (the helper would otherwise take the early EOF for the end).
func CmdAuthKeysWrite(path, expectSHA256 string, op uuid.UUID, content []byte) (HelperCommand, error) {
	if !helperproto.ValidPath(path) || !helperproto.ValidSHA256(expectSHA256) || op == uuid.Nil || !helperproto.ValidOpID(op.String()) {
		return HelperCommand{}, ErrInvalidArgument
	}
	if len(content) > helperproto.MaxAuthorizedKeysSize {
		return HelperCommand{}, fmt.Errorf("%w: content is larger than %d bytes", ErrInvalidArgument, helperproto.MaxAuthorizedKeysSize)
	}
	qp, err := quoteArg(path)
	if err != nil {
		return HelperCommand{}, err
	}
	qh, err := quoteArg(expectSHA256)
	if err != nil {
		return HelperCommand{}, err
	}
	sum := sha256.Sum256(content)
	qc, err := quoteArg(hex.EncodeToString(sum[:]))
	if err != nil {
		return HelperCommand{}, err
	}
	qo, err := quoteArg(op.String())
	if err != nil {
		return HelperCommand{}, err
	}
	// The scan of authkeys-list plus the lock wait; the helper stops after helperproto.HelperBudget.
	c := privileged(helperproto.SubAuthKeysWrite, LongCommandTimeout, smallOutput, qp, "--expect-sha256", qh, "--content-sha256", qc, "--op", qo)
	c.stdin = owned(content)
	return c, nil
}

// CmdCleanup removes the helper's backup directory of one operation. For an operation that holds
// Nginx state the helper waits up to 30 s for its Nginx lock and may answer BUSY (retryable), so the
// command gets the long timeout; an authorized_keys operation never waits for that lock.
func CmdCleanup(op uuid.UUID) (HelperCommand, error) {
	return opCommand(helperproto.SubCleanup, op, LongCommandTimeout)
}

// CmdNginxDump returns the parsed Nginx configuration and the referenced certificate files
// (nginx -V and nginx -T, each bounded; the helper stops after helperproto.HelperBudget).
func CmdNginxDump() HelperCommand {
	return privileged(helperproto.SubNginxDump, LongCommandTimeout, helperproto.ServerDumpOutput)
}

// CmdApacheDump returns the parsed Apache configuration and the referenced certificate files
// (apache-dump takes no arguments and writes nothing).
func CmdApacheDump() HelperCommand {
	return privileged(helperproto.SubApacheDump, LongCommandTimeout, helperproto.ServerDumpOutput)
}

// CmdHAProxyDump returns the parsed HAProxy configuration and the referenced certificate files
// (haproxy-dump takes no arguments and writes nothing).
func CmdHAProxyDump() HelperCommand {
	return privileged(helperproto.SubHAProxyDump, LongCommandTimeout, helperproto.ServerDumpOutput)
}

// CmdNginxTest runs nginx -t.
func CmdNginxTest() HelperCommand {
	return privileged(helperproto.SubNginxTest, LongCommandTimeout, smallOutput)
}

// CmdNginxDeploy replaces a certificate/key pair in one helper transaction. input is the JSON
// helperproto.NginxDeployInput (it carries the private key): it goes on stdin only, with its
// SHA-256 on the command line (--content-sha256), so a dropped connection never deploys a prefix.
// The command line carries paths and hashes, never key material. A timeout of the run is an
// uncertain outcome that the caller settles with CmdNginxStatus.
func CmdNginxDeploy(op uuid.UUID, certPath, keyPath, expectCertSHA256 string, input []byte) (HelperCommand, error) {
	if op == uuid.Nil || !helperproto.ValidOpID(op.String()) || !helperproto.ValidPath(certPath) || !helperproto.ValidPath(keyPath) ||
		certPath == "/" || keyPath == "/" || certPath == keyPath ||
		!helperproto.ValidSHA256(expectCertSHA256) || expectCertSHA256 == helperproto.AbsentSHA256 || len(input) == 0 {
		return HelperCommand{}, ErrInvalidArgument
	}
	if len(input) > helperproto.MaxDeployInput {
		return HelperCommand{}, fmt.Errorf("%w: input is larger than %d bytes", ErrInvalidArgument, helperproto.MaxDeployInput)
	}
	sum := sha256.Sum256(input)
	tokens, err := quoteAll(op.String(), certPath, keyPath, expectCertSHA256, hex.EncodeToString(sum[:]))
	if err != nil {
		return HelperCommand{}, err
	}
	c := privileged(helperproto.SubNginxDeploy, DeployCommandTimeout, smallOutput,
		"--op", tokens[0], "--cert", tokens[1], "--key", tokens[2], "--expect-cert-sha256", tokens[3], "--content-sha256", tokens[4])
	c.stdin = owned(input)
	return c, nil
}

// CmdNginxRestore restores the files an operation replaced (DeployCommandTimeout, like the deploy).
func CmdNginxRestore(op uuid.UUID) (HelperCommand, error) {
	return opCommand(helperproto.SubNginxRestore, op, DeployCommandTimeout)
}

// CmdNginxRestoreGuarded is CmdNginxRestore with the rollback guard on stdin (protocol 10, R48:
// helperproto.NginxRestoreInput, at most MaxRestoreInput bytes). The argument vector is the same,
// so the sudoers line of every setup admits it; only a helper of RollbackGuardMinProtocol reads the
// input (an older one ignores it: the caller checks the protocol first).
func CmdNginxRestoreGuarded(op uuid.UUID, input []byte) (HelperCommand, error) {
	if len(input) == 0 || len(input) > helperproto.MaxRestoreInput {
		return HelperCommand{}, fmt.Errorf("%w: the restore input is empty or larger than %d bytes", ErrInvalidArgument, helperproto.MaxRestoreInput)
	}
	c, err := opCommand(helperproto.SubNginxRestore, op, DeployCommandTimeout)
	if err != nil {
		return HelperCommand{}, err
	}
	c.stdin = owned(input)
	return c, nil
}

// CmdNginxStatus reports an operation's journal: the cheap poll after an uncertain deploy.
func CmdNginxStatus(op uuid.UUID) (HelperCommand, error) {
	return opCommand(helperproto.SubNginxStatus, op, DefaultCommandTimeout)
}

// CmdNginxFence fences an operation (AUD-05): it waits for the helper's Nginx lock like
// nginx-restore, so it gets the deploy's timeout.
func CmdNginxFence(op uuid.UUID) (HelperCommand, error) {
	return opCommand(helperproto.SubNginxFence, op, DeployCommandTimeout)
}

func opCommand(sub string, op uuid.UUID, timeout time.Duration) (HelperCommand, error) {
	if op == uuid.Nil || !helperproto.ValidOpID(op.String()) {
		return HelperCommand{}, ErrInvalidArgument
	}
	qo, err := quoteArg(op.String())
	if err != nil {
		return HelperCommand{}, err
	}
	return privileged(sub, timeout, smallOutput, "--op", qo), nil
}

// CmdTLSProbe checks a TLS endpoint from the server itself. It runs without sudo (the helper's
// tls-probe is unprivileged and not in sudoers). sni "" sends no server name.
func CmdTLSProbe(addr string, port int, sni, keyType string) (HelperCommand, error) {
	if sni == "" {
		sni = helperproto.NoSNI
	}
	ps := strconv.Itoa(port)
	if !helperproto.ValidIP(addr) || !helperproto.ValidPort(ps) || (sni != helperproto.NoSNI && !helperproto.ValidSNI(sni)) ||
		(keyType != helperproto.ProbeAny && keyType != helperproto.ProbeRSA && keyType != helperproto.ProbeECDSA) {
		return HelperCommand{}, ErrInvalidArgument
	}
	t, err := quoteAll(addr, ps, sni, keyType)
	if err != nil {
		return HelperCommand{}, err
	}
	return HelperCommand{sub: helperproto.SubTLSProbe, tokens: []string{"--addr", t[0], "--port", t[1], "--sni", t[2], "--key-type", t[3]},
		timeout: DefaultCommandTimeout, maxOutput: probeOutput}, nil
}

// quoteToken quotes an HTTP-01 token (helperproto.ValidACMEToken: 22 to 128 characters of
// [A-Za-z0-9_-]). It is quoteArg for the one value that may start with "-": a base64url token does
// so one time in 64, and quoteArg refuses a leading "-" because it would read as an option. The
// helper's acme-challenge-* subcommands take exactly "--token <value>" by position, so the value is
// never parsed as an option; its vocabulary holds no quote, space or shell metacharacter, so single
// quotes make it one literal word.
func quoteToken(token string) (string, error) {
	if !helperproto.ValidACMEToken(token) {
		return "", ErrInvalidArgument
	}
	return "'" + token + "'", nil
}

// CmdACMEChallengePut publishes an HTTP-01 key authorization as the token file
// helperproto.ACMEChallengePath(token) (protocol 7). The key authorization goes on stdin; it must be
// exactly the token, ".", and the account key's thumbprint (helperproto.ValidKeyAuthorization), which
// the helper checks again, so a body cut short in transit is refused rather than published.
func CmdACMEChallengePut(token string, keyAuthorization []byte) (HelperCommand, error) {
	if !helperproto.ValidKeyAuthorization(token, keyAuthorization) {
		return HelperCommand{}, ErrInvalidArgument
	}
	q, err := quoteToken(token)
	if err != nil {
		return HelperCommand{}, err
	}
	c := privileged(helperproto.SubACMEChallengePut, DefaultCommandTimeout, smallOutput, "--token", q)
	c.stdin = owned(keyAuthorization)
	return c, nil
}

// CmdACMEChallengeRm removes the token file of an HTTP-01 challenge (protocol 7); a missing file is
// success.
func CmdACMEChallengeRm(token string) (HelperCommand, error) {
	q, err := quoteToken(token)
	if err != nil {
		return HelperCommand{}, err
	}
	return privileged(helperproto.SubACMEChallengeRm, DefaultCommandTimeout, smallOutput, "--token", q), nil
}

// The vocabulary and limits of a forced command line (R60 Ruling 5). They equal winproto.ValidToken,
// MaxTokens and MaxLineBytes (the Windows provider's tests compare them: linuxssh does not import the
// Windows protocol). A token holds no space, no quote and no metacharacter of a shell or of cmd.exe
// (no '%', '^', '&', '|', '<', '>', '!', backslash, double quote or single quote), so no program on the
// target can read one token as two, or as anything but a literal word.
var forcedTokenRE = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,253}$`)

const (
	maxForcedTokens = 16
	maxForcedLine   = 4096
)

// ForcedCommand is the one audited constructor for a target whose sshd forces every session to one
// program (a Windows server's alice-helper.exe, R60 Ruling 5): the line is the subcommand and its
// arguments joined by one ASCII space, nothing else: no sudo, no helper path, no quoting. sshd hands
// the line verbatim to the forced program in SSH_ORIGINAL_COMMAND and the program splits it itself
// (winproto.SplitCommandLine); no shell or cmd.exe parses it. Every token must match
// ^[A-Za-z0-9._:@+-]{1,253}$, there are 1 to 16 of them, the line is at most 4096 bytes, and the
// command needs a positive time budget and output bound; anything else is ErrInvalidArgument and
// builds no command. stdin (nil for none) is copied: the command owns its input, prints only its line
// (Format, LogValue) and is wiped with WipeInput, as the Linux commands are.
func ForcedCommand(tokens []string, stdin []byte, timeout time.Duration, maxOutput int64) (HelperCommand, error) {
	if len(tokens) == 0 || len(tokens) > maxForcedTokens || timeout <= 0 || maxOutput <= 0 {
		return HelperCommand{}, ErrInvalidArgument
	}
	n := len(tokens) - 1 // the separating spaces
	for _, t := range tokens {
		if !forcedTokenRE.MatchString(t) {
			return HelperCommand{}, ErrInvalidArgument
		}
		n += len(t)
	}
	if n > maxForcedLine {
		return HelperCommand{}, ErrInvalidArgument
	}
	c := HelperCommand{sub: tokens[0], tokens: append([]string(nil), tokens[1:]...), bare: true, timeout: timeout, maxOutput: maxOutput}
	if stdin != nil {
		c.stdin = owned(stdin)
	}
	return c, nil
}

func quoteAll(values ...string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, v := range values {
		q, err := quoteArg(v)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, nil
}

// stdinBuf holds a command's input; see HelperCommand.stdin for why it is two pointers deep.
type stdinBuf struct{ p *[]byte }

// owned is the command's own copy of its input.
func owned(b []byte) *stdinBuf {
	cp := append([]byte(nil), b...)
	return &stdinBuf{p: &cp}
}

// input is the stdin to send (nil when none).
func (c HelperCommand) input() []byte {
	if c.stdin == nil || c.stdin.p == nil {
		return nil
	}
	return *c.stdin.p
}

// WipeInput overwrites the command's stdin (the private key of nginx-deploy) with zeros. The
// command keeps its own copy of the input, so the caller wipes it after Run (SEC-044, best
// effort). Copies of a command share that copy: wiping one wipes them all, and a wiped command
// sends zeros (the helper answers CONTENT_MISMATCH), so a re-send needs a newly built command.
func (c HelperCommand) WipeInput() { clear(c.input()) }

// Format prints the command line only, for every verb and flag: stdin holds the private key of
// nginx-deploy, and fmt would otherwise print it (%s as text, %v and %d as bytes, %x as hex).
// The value receiver covers pointers too.
func (c HelperCommand) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, c.Line()) }

// LogValue keeps the command's stdin out of slog output: only the command line is logged.
func (c HelperCommand) LogValue() slog.Value { return slog.StringValue(c.Line()) }

// Line is the exact command line sent over the SSH exec channel ("" for the zero value).
func (c HelperCommand) Line() string {
	if c.fixed != "" {
		return c.fixed
	}
	if c.sub == "" {
		return ""
	}
	var b strings.Builder
	if c.bare {
		b.WriteString(c.sub)
		for _, t := range c.tokens {
			b.WriteByte(' ')
			b.WriteString(t)
		}
		return b.String()
	}
	if c.sudo {
		b.WriteString("sudo -n ")
	}
	b.WriteString(helperproto.HelperPath)
	b.WriteByte(' ')
	b.WriteString(c.sub)
	for _, t := range c.tokens {
		b.WriteByte(' ')
		b.WriteString(t)
	}
	return b.String()
}

// Input is the command's own copy of its stdin (nil when none), for a transport other than SSH (the WinRM
// transport, R71 Ruling 15). WipeInput wipes it; the caller never keeps it after the call.
func (c HelperCommand) Input() []byte { return c.input() }

// Timeout is the command's time budget.
func (c HelperCommand) Timeout() time.Duration { return c.timeout }

// MaxOutput is the bound on the command's stdout.
func (c HelperCommand) MaxOutput() int64 { return c.maxOutput }

// Subcommand names the helper subcommand ("os-release" for the fixed command).
func (c HelperCommand) Subcommand() string {
	if c.fixed != "" {
		return "os-release"
	}
	return c.sub
}
