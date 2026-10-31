package wintest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/winrs"
)

// The emulated WinRM listener (R71 Ruling 20): WS-Man's WinRS subset over HTTPS, behind the NTLMv2 check
// (NTLMServer), with shells that run the helper's forced entry on the model.

// winrmAppID is WinRM's http.sys application id: the record whose port serves WS-Man.
const winrmAppID = "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}"

// The emulator's limits and fault codes. Code 2 (ERROR_FILE_NOT_FOUND, F29) and w:TimedOut are Windows' own; the
// others are what the emulator answers until F26 and F27 record the measured ones.
const (
	maxShellsPerUser = 30          // MaxShellsPerUser's default
	maxReceiveChunk  = 64 << 10    // the stdout of one Receive
	maxWinRMStdin    = 1 << 20     // the stdin one command collects
	maxWinRMLog      = 1024        // the latest requests WinRMLog keeps
	defaultOpTimeout = time.Minute // a Receive without OperationTimeout

	faultFileNotFound = 2 // Command: the helper with arguments other than ssh
	// notRecognizedExit is cmd.exe's exit for a program that does not exist: WinRS starts the program through cmd.exe
	// even with WINRS_SKIP_CMD_SHELL, so a missing helper is a finished command, not a fault (F29, runner runs 6 and 7).
	notRecognizedExit     = 9009
	faultBadRequest       = 87         // ERROR_INVALID_PARAMETER: a request outside the subset or out of order
	faultShellNotFound    = 2150858843 // the shell does not exist (deleted, or never made)
	faultMaxShells        = 2150859173 // the user's MaxShellsPerUser is reached
	faultEnvelopeTooLarge = 2150858817 // the request is larger than MaxEnvelopeSize (F26 records the real code)
	faultTimedOut         = 2150858793 // w:TimedOut: no output within the Receive's OperationTimeout
)

// WinRMRequest is one HTTP request the WinRM listener got: the action ("Create", "Command", "Send", "Receive",
// "Signal", "Delete"; "" for a request that never reached WS-Man), the environment variable names of a Create, the
// program and arguments of a Command, the connection's number and the authentication step ("none", "negotiate" for
// an NTLM type 1, "authenticate" for a type 3, "basic", "other"). Line is a Create's SSH_ORIGINAL_COMMAND (the
// helper line, which the SSH server's command log keeps too) and CommandLine a Command's raw rsp:CommandLine element
// as it arrived, for the cmd.exe tests (amended Ruling 4). Never stdin, another environment value or a password.
type WinRMRequest struct {
	Action      string
	EnvNames    []string
	Program     string
	Args        []string
	Line        string
	CommandLine string
	Conn        int
	Auth        string
}

type winrmAccount struct{ user, password string }

type winrmShell struct {
	env map[string]string
	cmd *winrmCommand
}

type winrmCommand struct {
	id     string
	absent string // the program cmd.exe did not find: Send runs nothing, Receive answers notRecognizedExit
	stdin  []byte
	ended  bool
	done   chan struct{} // closed when the helper's answer may be read
	stdout []byte        // what Receive has not returned yet
	stderr []byte        // likewise, for stderr
	exit   int
}

// SetWinRMAccount sets the one account the WinRM listener accepts (Ruling 20): user with password, in the domain
// "", ".", the model's computer name or none other (the demo host is in a workgroup).
func (m *Model) SetWinRMAccount(user, password string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.winrmAcct = &winrmAccount{user, password}
}

// ClearWinRMAccount removes the account: every sign-in is refused.
func (m *Model) ClearWinRMAccount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.winrmAcct = nil
}

// FailWinRM makes the next signed-in request fault with code.
func (m *Model) FailWinRM(code uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.winrmFail = code
}

// WinRMLog is the WinRM listener's request log (the latest maxWinRMLog), oldest first.
func (m *Model) WinRMLog() []WinRMRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.winrmLog)
}

// WinRMShells is the number of open shells.
func (m *Model) WinRMShells() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.winrmShells)
}

func (m *Model) logWinRM(r WinRMRequest) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.winrmLog) == maxWinRMLog {
		m.winrmLog = slices.Delete(m.winrmLog, 0, 1)
	}
	m.winrmLog = append(m.winrmLog, r)
}

// winrmRecordLocked is the http.sys record of WinRM's application (the first ipport one).
func (m *Model) winrmRecordLocked() *winproto.SSLBinding {
	for i := range m.bindings {
		if b := &m.bindings[i]; b.Type == winproto.BindingIPPort && fold(b.AppID) == winrmAppID {
			return b
		}
	}
	return nil
}

// winrmPortLocked reports whether port is the WinRM record's.
func (m *Model) winrmPortLocked(port int) bool {
	b := m.winrmRecordLocked()
	return b != nil && b.Port == port
}

// WinRMSPKI is the SubjectPublicKeyInfo of the certificate the WinRM record serves now; false when the model has no
// WinRM record or it serves nothing.
func (m *Model) WinRMSPKI() ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.winrmCertLocked()
	if err != nil {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, false
	}
	return leaf.RawSubjectPublicKeyInfo, true
}

func (m *Model) winrmCertLocked() (*tls.Certificate, error) {
	b := m.winrmRecordLocked()
	if b == nil {
		return nil, errNoCertificate
	}
	return m.presentedLocked(b)
}

// WinRMServer is a test WinRM listener on 127.0.0.1 with the model's WinRM certificate.
type WinRMServer struct {
	Addr  string
	SPKI  []byte
	conns *atomic.Int64
}

// Connections is the number of connections the listener accepted.
func (s *WinRMServer) Connections() int { return int(s.conns.Load()) }

// NewWinRMServer starts a WinRM listener on 127.0.0.1:0 that serves the certificate of the model's WinRM record; it
// stops with the test.
func NewWinRMServer(t testing.TB, m *Model) *WinRMServer {
	t.Helper()
	spki, ok := m.WinRMSPKI()
	if !ok {
		t.Fatal("wintest: the model has no WinRM record with a usable certificate")
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wintest: listen: %v", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.winrmCertLocked()
	}}
	s := &WinRMServer{Addr: ln.Addr().String(), SPKI: spki, conns: &atomic.Int64{}}
	srv := m.winrmHTTPServer(s.conns)
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

// serveWinRM serves WS-Man on a listener of the WinRM record's port until ctx ends (Serve).
func (m *Model) serveWinRM(ctx context.Context, ln net.Listener, cfg *tls.Config) {
	defer m.serving.Done()
	srv := m.winrmHTTPServer(&atomic.Int64{})
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	_ = srv.Serve(tls.NewListener(ln, cfg))
}

type winrmEntryKey struct{}

var connSeq atomic.Int64 // numbers every WinRM connection of the process, for WinRMRequest.Conn

// winrmHTTPServer is the listener's HTTP server: each connection signs in once (NTLMServer, connection-bound), and
// every request is logged.
func (m *Model) winrmHTTPServer(conns *atomic.Int64) *http.Server {
	clock := func() time.Time {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.nowLocked()
	}
	ws := http.HandlerFunc(m.serveWSMan)
	var ntlmConnContext func(context.Context, net.Conn) context.Context
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := &WinRMRequest{Auth: authStep(r.Header.Get("Authorization"))}
		if id, ok := r.Context().Value(winrmConnKey{}).(int); ok {
			e.Conn = id
		}
		r = r.WithContext(context.WithValue(r.Context(), winrmEntryKey{}, e))
		m.mu.Lock()
		acct := m.winrmAcct
		computer := m.winrmComputer
		m.mu.Unlock()
		next := ws
		if acct == nil {
			// Without an account no sign-in can succeed: the exchange still runs, and its end is refused.
			acct = &winrmAccount{}
			next = func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
		// The account is read per request so ctl winrm-account applies at once; the sign-in state lives in the
		// connection's context, which every NTLMServer shares.
		nh, _ := NTLMServer(NTLMAccount{User: acct.user, Password: acct.password, Computer: computer}, clock, next)
		nh.ServeHTTP(w, r)
		m.logWinRM(*e)
	})
	// The NTLM connection-context key is package-level, so this throwaway NTLMServer's connContext serves every per-request handler.
	_, ntlmConnContext = NTLMServer(NTLMAccount{}, clock, nil)
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: handshakeTimeout,
		ErrorLog:          log.New(io.Discard, "", 0), // a client's refused handshake is not the test's output
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			conns.Add(1)
			ctx = context.WithValue(ctx, winrmConnKey{}, int(connSeq.Add(1)))
			return ntlmConnContext(ctx, c)
		},
	}
}

type winrmConnKey struct{}

// authStep names a request's Authorization for the log, never its content.
func authStep(h string) string {
	scheme, token, _ := strings.Cut(h, " ")
	switch {
	case h == "":
		return "none"
	case strings.EqualFold(scheme, "Basic"):
		return "basic"
	case scheme != "Negotiate" && scheme != "NTLM":
		return "other"
	}
	msg, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(msg) < 12 || string(msg[:8]) != ntlmSignature {
		return "other"
	}
	switch binary.LittleEndian.Uint32(msg[8:]) {
	case 1:
		return "negotiate"
	case 3:
		return "authenticate"
	}
	return "other"
}

var commandLineRE = regexp.MustCompile(`<rsp:CommandLine>.*?</rsp:CommandLine>`)

var opTimeoutRE = regexp.MustCompile(`<w:OperationTimeout>PT([0-9]{1,6})S</w:OperationTimeout>`)

// serveWSMan answers one signed-in request of the WinRS subset.
func (m *Model) serveWSMan(w http.ResponseWriter, r *http.Request) {
	e, _ := r.Context().Value(winrmEntryKey{}).(*WinRMRequest)
	if e == nil {
		e = &WinRMRequest{}
	}
	fault := func(relatesTo string, code uint32) {
		w.Header().Set("Content-Type", winrs.ContentType)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(winrs.FaultResponse(relatesTo, code))
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, winrs.MaxEnvelopeSize+1))
	if err != nil {
		return
	}
	if len(body) > winrs.MaxEnvelopeSize {
		fault("", faultEnvelopeTooLarge)
		return
	}
	req, err := winrs.ParseRequest(body)
	if err != nil {
		fault("", faultBadRequest)
		return
	}
	e.Action = req.Action[strings.LastIndexByte(req.Action, '/')+1:]
	for k := range req.Env {
		e.EnvNames = append(e.EnvNames, k)
	}
	slices.Sort(e.EnvNames)
	e.Program, e.Args, e.Line = req.Program, req.Args, req.Env["SSH_ORIGINAL_COMMAND"]
	if req.Action == winrs.ActionCommand {
		e.CommandLine = string(commandLineRE.Find(body))
	}

	m.mu.Lock()
	failCode := m.winrmFail
	m.winrmFail = 0
	m.mu.Unlock()
	if failCode != 0 {
		fault(req.MessageID, failCode)
		return
	}
	var answer []byte
	code := uint32(0)
	switch req.Action {
	case winrs.ActionCreate:
		answer, code = m.winrmCreate(req)
	case winrs.ActionCommand:
		answer, code = m.winrmStart(req)
	case winrs.ActionSend:
		answer, code = m.winrmSend(req)
	case winrs.ActionReceive:
		wait := defaultOpTimeout
		if s := opTimeoutRE.FindSubmatch(body); s != nil {
			n, _ := strconv.Atoi(string(s[1]))
			wait = time.Duration(n) * time.Second
		}
		answer, code = m.winrmReceive(r.Context(), req, wait)
	case winrs.ActionSignal:
		answer, code = m.winrmCommandOf(req, func(*winrmShell) []byte { return winrs.EmptyResponse(req.MessageID, req.Action) })
	case winrs.ActionDelete:
		m.mu.Lock()
		_, ok := m.winrmShells[req.ShellID]
		delete(m.winrmShells, req.ShellID)
		m.mu.Unlock()
		if !ok {
			code = faultShellNotFound
		}
		answer = winrs.EmptyResponse(req.MessageID, req.Action)
	}
	if code != 0 {
		fault(req.MessageID, code)
		return
	}
	w.Header().Set("Content-Type", winrs.ContentType)
	_, _ = w.Write(answer)
}

// winrmID is a shell or command id as Windows writes it: an upper-case UUID.
func winrmID() string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'f' {
			return r - 'a' + 'A'
		}
		return r
	}, uuid.NewString())
}

// winrmCreate makes a shell. Its environment must be exactly SSH_ORIGINAL_COMMAND (the line Alice sends, Ruling 4).
func (m *Model) winrmCreate(req winrs.Request) ([]byte, uint32) {
	if _, ok := req.Env["SSH_ORIGINAL_COMMAND"]; !ok || len(req.Env) != 1 {
		return nil, faultBadRequest
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.winrmShells) >= maxShellsPerUser {
		return nil, faultMaxShells
	}
	id := winrmID()
	m.winrmShells[id] = &winrmShell{env: req.Env}
	return winrs.ShellCreatedResponse(req.MessageID, id), 0
}

// winrmStart starts the shell's one command: the helper with the argument ssh (other arguments fault 2). A program
// that does not exist, or the helper on a host without it, starts too and ends as cmd.exe ends it (notRecognizedExit).
func (m *Model) winrmStart(req winrs.Request) ([]byte, uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sh := m.winrmShells[req.ShellID]
	switch {
	case sh == nil:
		return nil, faultShellNotFound
	case sh.cmd != nil:
		return nil, faultBadRequest
	case req.Program == winproto.HelperPath && !slices.Equal(req.Args, []string{"ssh"}):
		return nil, faultFileNotFound
	}
	sh.cmd = &winrmCommand{id: winrmID(), done: make(chan struct{})}
	if req.Program != winproto.HelperPath || m.helperMissing {
		sh.cmd.absent = req.Program
	}
	return winrs.CommandStartedResponse(req.MessageID, sh.cmd.id), 0
}

// winrmCommandOf runs answer on the shell of a request that names the shell's command.
func (m *Model) winrmCommandOf(req winrs.Request, answer func(*winrmShell) []byte) ([]byte, uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sh := m.winrmShells[req.ShellID]
	if sh == nil {
		return nil, faultShellNotFound
	}
	if sh.cmd == nil || sh.cmd.id != req.CommandID {
		return nil, faultBadRequest
	}
	return answer(sh), 0
}

// winrmSend collects stdin; at End the helper runs with the shell's SSH_ORIGINAL_COMMAND, as under sshd.
func (m *Model) winrmSend(req winrs.Request) ([]byte, uint32) {
	var run *winrmShell
	answer, code := m.winrmCommandOf(req, func(sh *winrmShell) []byte {
		c := sh.cmd
		if c.ended || len(c.stdin)+len(req.Stream) > maxWinRMStdin {
			return nil
		}
		c.stdin = append(c.stdin, req.Stream...)
		if c.ended = req.End; c.ended {
			run = sh
		}
		return winrs.EmptyResponse(req.MessageID, req.Action)
	})
	if code == 0 && answer == nil {
		return nil, faultBadRequest
	}
	if run != nil && run.cmd.absent != "" {
		m.mu.Lock()
		run.cmd.stdin, run.cmd.exit = nil, notRecognizedExit
		run.cmd.stderr = []byte("'" + run.cmd.absent + "' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n")
		m.mu.Unlock()
		close(run.cmd.done)
	} else if run != nil {
		m.mu.Lock()
		line, stdin := run.env["SSH_ORIGINAL_COMMAND"], run.cmd.stdin
		run.cmd.stdin = nil
		m.mu.Unlock()
		res := m.runHelper(line, stdin)
		m.mu.Lock()
		run.cmd.stdout, run.cmd.exit = res.Stdout, res.Exit
		m.mu.Unlock()
		done := run.cmd.done
		if res.Delay > 0 {
			time.AfterFunc(res.Delay, func() { close(done) })
		} else {
			close(done)
		}
	}
	return answer, code
}

// winrmReceive answers stdout in chunks of at most maxReceiveChunk, and Done with the exit code once all of it was
// read. A command that is not done within wait answers w:TimedOut, as Windows does.
func (m *Model) winrmReceive(ctx context.Context, req winrs.Request, wait time.Duration) ([]byte, uint32) {
	var done chan struct{}
	if _, code := m.winrmCommandOf(req, func(sh *winrmShell) []byte { done = sh.cmd.done; return nil }); code != 0 {
		return nil, code
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		return nil, faultTimedOut
	case <-ctx.Done():
		return nil, faultTimedOut
	}
	return m.winrmCommandOf(req, func(sh *winrmShell) []byte {
		c := sh.cmd
		n := min(len(c.stdout), maxReceiveChunk)
		chunk := c.stdout[:n]
		c.stdout = c.stdout[n:]
		errChunk := c.stderr
		c.stderr = nil
		return winrs.ReceivedStreamsResponse(req.MessageID, c.id, chunk, errChunk, len(c.stdout) == 0, c.exit)
	})
}
