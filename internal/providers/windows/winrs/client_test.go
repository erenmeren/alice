package winrs_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
	"alice/internal/providers/windows/winrs"
	"alice/internal/providers/windows/wintest"
)

const helper = `C:\Program Files\Alice\alice-helper.exe`

// rawRequest is one HTTP request as the listener received it, before the NTLM check.
type rawRequest struct {
	conn int
	auth string
	url  string
	head string
	body []byte
}

// served is one request the NTLM check let through, parsed.
type served struct {
	conn int
	auth string
	req  winrs.Request
	body []byte
}

type connKey struct{}

// fakeWinRM is a WinRM HTTPS listener built from the codec's server half behind wintest.NTLMServer.
type fakeWinRM struct {
	t    *testing.T
	srv  *httptest.Server
	acct wintest.NTLMAccount

	mu     sync.Mutex
	raw    []rawRequest
	served []served
	stdin  []byte
	conns  int
	closed int
	ids    int
	stdout []byte
	exit   int
	hook   func(w http.ResponseWriter, s served) bool // true: the hook answered
	// closeFirst closes the connection after each of the call's first closeFirst responses (Windows closes it
	// after the anonymous 401, F24 (d)).
	closeFirst int
}

func newFake(t *testing.T, opts ...wintest.NTLMOption) *fakeWinRM {
	t.Helper()
	f := &fakeWinRM{t: t, acct: wintest.NTLMAccount{User: "alice", Password: password(t), Domain: "CORP", Computer: "HOST"}, stdout: []byte(`{"ok":true}`)}
	ntlm, cc := wintest.NTLMServer(f.acct, time.Now, http.HandlerFunc(f.app), opts...)
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var head bytes.Buffer
		_ = r.Header.Write(&head)
		f.mu.Lock()
		f.raw = append(f.raw, rawRequest{conn: r.Context().Value(connKey{}).(int), auth: r.Header.Get("Authorization"), url: r.URL.String(), head: head.String(), body: body})
		if f.closeFirst > 0 {
			f.closeFirst--
			w.Header().Set("Connection", "close")
		}
		f.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		ntlm.ServeHTTP(w, r)
	}))
	f.srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		f.mu.Lock()
		f.conns++
		n := f.conns
		f.mu.Unlock()
		return context.WithValue(cc(ctx, c), connKey{}, n)
	}
	f.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			f.mu.Lock()
			f.closed++
			f.mu.Unlock()
		}
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func password(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

func (f *fakeWinRM) id() string {
	f.ids++
	return fmt.Sprintf("%08X-0000-4000-8000-%012X", f.ids, f.ids)
}

func (f *fakeWinRM) app(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	req, err := winrs.ParseRequest(body)
	if err != nil {
		f.t.Errorf("the client sent a request the codec refuses: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s := served{conn: r.Context().Value(connKey{}).(int), auth: r.Header.Get("Authorization"), req: req, body: body}
	f.mu.Lock()
	f.served = append(f.served, s)
	hook := f.hook
	f.mu.Unlock()
	if hook != nil && hook(w, s) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch req.Action {
	case winrs.ActionCreate:
		_, _ = w.Write(winrs.ShellCreatedResponse(req.MessageID, f.id()))
	case winrs.ActionCommand:
		_, _ = w.Write(winrs.CommandStartedResponse(req.MessageID, f.id()))
	case winrs.ActionSend:
		f.stdin = append(f.stdin, req.Stream...)
		_, _ = w.Write(winrs.EmptyResponse(req.MessageID, req.Action))
	case winrs.ActionReceive:
		_, _ = w.Write(winrs.ReceivedResponse(req.MessageID, req.CommandID, f.stdout, true, f.exit))
	default:
		_, _ = w.Write(winrs.EmptyResponse(req.MessageID, req.Action))
	}
}

func (f *fakeWinRM) setHook(h func(w http.ResponseWriter, s served) bool) {
	f.mu.Lock()
	f.hook = h
	f.mu.Unlock()
}

func (f *fakeWinRM) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, s := range f.served {
		out = append(out, s.req.Action[strings.LastIndex(s.req.Action, "/")+1:])
	}
	return out
}

func (f *fakeWinRM) rawRequests() []rawRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]rawRequest(nil), f.raw...)
}

func (f *fakeWinRM) client() *winrs.Client {
	return &winrs.Client{TLS: f.tlsConfig(), User: "alice", Password: f.acct.Password}
}

// tlsConfig is a pin on the test server's key, as tlspin's would be.
func (f *fakeWinRM) tlsConfig() *tls.Config {
	want := f.srv.Certificate().RawSubjectPublicKeyInfo
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, //nolint:gosec // pinned below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if !bytes.Equal(cs.PeerCertificates[0].RawSubjectPublicKeyInfo, want) {
				return errors.New("not the pinned key")
			}
			return nil
		}}
}

func (f *fakeWinRM) call() winrs.Call {
	return winrs.Call{Addr: f.srv.Listener.Addr().String(), Program: helper, Args: []string{"ssh"},
		Env: map[string]string{"SSH_ORIGINAL_COMMAND": "version"}, Timeout: 10 * time.Second, MaxOutput: 1 << 20}
}

// faultAt answers the first request of action with a WS-Management fault.
func faultAt(action string, code uint32) func(http.ResponseWriter, served) bool {
	return func(w http.ResponseWriter, s served) bool {
		if s.req.Action != action {
			return false
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(winrs.FaultResponse(s.req.MessageID, code))
		return true
	}
}

func malformedAt(action string) func(http.ResponseWriter, served) bool {
	return func(w http.ResponseWriter, s served) bool {
		if s.req.Action != action {
			return false
		}
		_, _ = w.Write([]byte("<not xml"))
		return true
	}
}

// neverDone answers every Receive with no output and the command still running.
func neverDone(w http.ResponseWriter, s served) bool {
	if s.req.Action != winrs.ActionReceive {
		return false
	}
	time.Sleep(20 * time.Millisecond)
	_, _ = w.Write(winrs.ReceivedResponse(s.req.MessageID, s.req.CommandID, nil, false, 0))
	return true
}

func (f *fakeWinRM) waitClosed(t *testing.T) {
	t.Helper()
	assert.Eventually(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.closed == f.conns
	}, 5*time.Second, 10*time.Millisecond, "every connection of the call is closed when it ends")
}

func TestWinRSRunsOneShellPerCall(t *testing.T) {
	f := newFake(t)
	f.exit = 3
	res, err := f.client().Run(context.Background(), f.call())
	require.NoError(t, err)
	assert.Equal(t, 3, res.ExitCode)
	assert.Equal(t, f.stdout, res.Stdout)
	assert.Equal(t, f.srv.Certificate().RawSubjectPublicKeyInfo, res.PeerSPKI)
	assert.Equal(t, []string{"Create", "Command", "Send", "Receive", "Delete"}, f.actions())
	raw := f.rawRequests()
	require.Len(t, raw, 7, "Create costs three requests (anonymous, type 1, type 3), every later one request")
	for _, r := range raw {
		assert.Equal(t, 1, r.conn, "one TLS connection")
	}
	f.waitClosed(t)

	_, err = f.client().Run(context.Background(), f.call())
	require.NoError(t, err)
	raw = f.rawRequests()[7:]
	require.Len(t, raw, 7, "the second call signs in again on its own connection")
	for _, r := range raw {
		assert.Equal(t, 2, r.conn)
	}
	assert.Empty(t, raw[0].auth)
	assert.True(t, strings.HasPrefix(raw[1].auth, "Negotiate "))
	assert.True(t, strings.HasPrefix(raw[2].auth, "Negotiate "))
	f.waitClosed(t)
}

func TestWinRSSendsOnlyTheHelper(t *testing.T) {
	f := newFake(t)
	f.setHook(func(w http.ResponseWriter, s served) bool { // one Receive without the end first
		if s.req.Action == winrs.ActionReceive && len(f.actions()) == 4 {
			_, _ = w.Write(winrs.ReceivedResponse(s.req.MessageID, s.req.CommandID, []byte("x"), false, 0))
			return true
		}
		return false
	})
	call := f.call()
	call.Env = map[string]string{"SSH_ORIGINAL_COMMAND": "iis-dump"}
	_, err := f.client().Run(context.Background(), call)
	require.NoError(t, err)
	allowed := map[string]bool{winrs.ActionCreate: true, winrs.ActionCommand: true, winrs.ActionSend: true, winrs.ActionReceive: true,
		winrs.ActionSignal: true, winrs.ActionDelete: true}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.served {
		assert.True(t, allowed[s.req.Action], s.req.Action)
		assert.Contains(t, string(s.body), winrs.ResourceCmd)
		switch s.req.Action {
		case winrs.ActionCreate:
			assert.Equal(t, call.Env, s.req.Env)
		case winrs.ActionCommand:
			assert.Equal(t, helper, s.req.Program)
			assert.Equal(t, []string{"ssh"}, s.req.Args)
		}
		assert.Empty(t, s.req.Signal)
	}
	assert.Equal(t, []string{"Create", "Command", "Send", "Receive", "Receive", "Delete"}, f.actionsLocked())
}

func (f *fakeWinRM) actionsLocked() []string {
	var out []string
	for _, s := range f.served {
		out = append(out, s.req.Action[strings.LastIndex(s.req.Action, "/")+1:])
	}
	return out
}

func TestWinRSKeyOnlyInSend(t *testing.T) {
	f := newFake(t)
	marker := []byte("-----BEGIN PRIVATE KEY-----")
	stdin := make([]byte, 200<<10)
	_, err := rand.Read(stdin)
	require.NoError(t, err)
	copy(stdin[150<<10:], marker)
	call := f.call()
	call.Stdin = stdin
	_, err = f.client().Run(context.Background(), call)
	require.NoError(t, err)

	// The marker's base64 at each of the three alignments.
	var encoded [][]byte
	for shift := range 3 {
		e := base64.StdEncoding.EncodeToString(append(make([]byte, shift), marker...))
		encoded = append(encoded, []byte(e[4*((shift+2)/3)+4:len(e)-4]))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Equal(t, stdin, f.stdin)
	var sizes []int
	var ends []bool
	for _, s := range f.served {
		if s.req.Action == winrs.ActionSend {
			sizes = append(sizes, len(s.req.Stream))
			ends = append(ends, s.req.End)
			assert.Equal(t, 1, s.conn, "stdin goes only on the call's authenticated connection")
			assert.Empty(t, s.auth, "on a connection that is already signed in")
		}
	}
	assert.Equal(t, []int{96 << 10, 96 << 10, 8 << 10}, sizes)
	assert.Equal(t, []bool{false, false, true}, ends)
	found := false
	for _, r := range f.raw {
		isSend := bytes.Contains(r.body, []byte(winrs.ActionSend))
		for _, e := range encoded {
			in := bytes.Contains(r.body, e)
			found = found || in
			if !isSend {
				assert.False(t, in, "key material outside Send")
			}
			assert.NotContains(t, r.head+r.url, string(e))
		}
		assert.NotContains(t, string(r.body), string(marker))
	}
	assert.True(t, found, "positive control: the marker's base64 is in a Send")

	// No stdin: one empty Send that ends the stream.
	f.served, f.stdin = nil, nil
	f.mu.Unlock()
	_, err = f.client().Run(context.Background(), f.call())
	f.mu.Lock()
	require.NoError(t, err)
	var sends []winrs.Request
	for _, s := range f.served {
		if s.req.Action == winrs.ActionSend {
			sends = append(sends, s.req)
		}
	}
	require.Len(t, sends, 1)
	assert.Empty(t, sends[0].Stream)
	assert.True(t, sends[0].End)
}

func assertNoBasic(t *testing.T, f *fakeWinRM, pw string) {
	t.Helper()
	for _, r := range f.rawRequests() {
		assert.False(t, strings.HasPrefix(r.auth, "Basic"), "a Basic Authorization was sent")
		assert.NotContains(t, r.head, pw)
		assert.NotContains(t, string(r.body), pw)
		assert.NotContains(t, r.head, base64.StdEncoding.EncodeToString([]byte("alice:"+pw)))
	}
}

func TestWinRSNeverSendsBasic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		f := newFake(t)
		_, err := f.client().Run(context.Background(), f.call())
		require.NoError(t, err)
		assertNoBasic(t, f, f.acct.Password)
	})
	t.Run("wrong password", func(t *testing.T) {
		f := newFake(t)
		c := f.client()
		c.Password = password(t)
		_, err := c.Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrAuthRefused)
		assertNoBasic(t, f, c.Password)
	})
	t.Run("Basic only", func(t *testing.T) {
		f := newFake(t, wintest.OfferBasicOnly())
		_, err := f.client().Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrAuthRefused)
		assertNoBasic(t, f, f.acct.Password)
	})
	for _, action := range []string{winrs.ActionCreate, winrs.ActionCommand, winrs.ActionSend, winrs.ActionReceive} {
		t.Run("401 at "+action, func(t *testing.T) {
			f := newFake(t)
			f.setHook(func(w http.ResponseWriter, s served) bool {
				if s.req.Action != action {
					return false
				}
				w.Header().Add("WWW-Authenticate", "Negotiate")
				w.Header().Add("WWW-Authenticate", `Basic realm="WSMAN"`)
				w.WriteHeader(http.StatusUnauthorized)
				return true
			})
			_, err := f.client().Run(context.Background(), f.call())
			require.ErrorIs(t, err, winrs.ErrAuthRefused)
			assertNoBasic(t, f, f.acct.Password)
			assert.Equal(t, 2, signIns(f), "one exchange (type 1, type 3) on Create, never another")
		})
	}
}

// signIns counts the requests that carried an Authorization header.
func signIns(f *fakeWinRM) int {
	n := 0
	for _, r := range f.rawRequests() {
		if r.auth != "" {
			n++
		}
	}
	return n
}

// Only Create carries the credentials: a 401 on a later request is final, with no new exchange and no resent body.
func TestWinRSSignsInOnCreateOnly(t *testing.T) {
	f := newFake(t)
	f.setHook(func(w http.ResponseWriter, s served) bool {
		if s.req.Action != winrs.ActionSend {
			return false
		}
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return true
	})
	call := f.call()
	call.Stdin = []byte("key material")
	_, err := f.client().Run(context.Background(), call)
	require.ErrorIs(t, err, winrs.ErrAuthRefused)
	assert.NotErrorIs(t, err, winrs.ErrNotSent, "after Command, what reached the program is uncertain")
	sends := 0
	for _, r := range f.rawRequests() {
		if bytes.Contains(r.body, []byte(winrs.ActionSend)) {
			sends++
		}
	}
	assert.Equal(t, 1, sends, "the Send was not sent again")
	assert.Equal(t, 2, signIns(f), "no new exchange after the 401")
	f.mu.Lock()
	assert.Empty(t, f.stdin)
	f.mu.Unlock()
	assert.Equal(t, []string{"Create", "Command", "Send", "Delete"}, f.actions(), "the cleanup is still attempted")
}

func TestWinRSRefusesEverythingButNTLMOverTLS(t *testing.T) {
	f := newFake(t)
	bad := map[string]func(c *winrs.Client, call *winrs.Call){
		"TLS 1.1":            func(c *winrs.Client, _ *winrs.Call) { c.TLS.MinVersion = tls.VersionTLS11 },
		"no minimum":         func(c *winrs.Client, _ *winrs.Call) { c.TLS.MinVersion = 0 },
		"maximum below 1.2":  func(c *winrs.Client, _ *winrs.Call) { c.TLS.MaxVersion = tls.VersionTLS11 },
		"client certificate": func(c *winrs.Client, _ *winrs.Call) { c.TLS.Certificates = []tls.Certificate{{}} },
		"get client cert": func(c *winrs.Client, _ *winrs.Call) {
			c.TLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, nil }
		},
		"skip without a check": func(c *winrs.Client, _ *winrs.Call) { c.TLS.VerifyConnection = nil },
		"no TLS":               func(c *winrs.Client, _ *winrs.Call) { c.TLS = nil },
		"empty user":           func(c *winrs.Client, _ *winrs.Call) { c.User = "" },
		"empty password":       func(c *winrs.Client, _ *winrs.Call) { c.Password = "" },
		"no timeout":           func(_ *winrs.Client, call *winrs.Call) { call.Timeout = 0 },
		"no output bound":      func(_ *winrs.Client, call *winrs.Call) { call.MaxOutput = 0 },
		"bad address":          func(_ *winrs.Client, call *winrs.Call) { call.Addr = "no-port" },
		"the HTTP port 5985":   func(_ *winrs.Client, call *winrs.Call) { call.Addr = "127.0.0.1:5985" },
		"two variables":        func(_ *winrs.Client, call *winrs.Call) { call.Env = map[string]string{"A": "1", "B": "2"} },
		"quoted program":       func(_ *winrs.Client, call *winrs.Call) { call.Program = `"x"` },
		// Amended Ruling 4: cmd.exe parses the program line, so only the helper's forced entry is sent.
		"no argument":       func(_ *winrs.Client, call *winrs.Call) { call.Args = nil },
		"another argument":  func(_ *winrs.Client, call *winrs.Call) { call.Args = []string{"version"} },
		"a second argument": func(_ *winrs.Client, call *winrs.Call) { call.Args = []string{"ssh", "x"} },
		"no variable":       func(_ *winrs.Client, call *winrs.Call) { call.Env = nil },
		"another variable":  func(_ *winrs.Client, call *winrs.Call) { call.Env = map[string]string{"PATH": "version"} },
		"an extra variable": func(_ *winrs.Client, call *winrs.Call) {
			call.Env = map[string]string{"SSH_ORIGINAL_COMMAND": "version", "A": "1"}
		},
		"a control character": func(_ *winrs.Client, call *winrs.Call) { call.Program += "\t" },
	}
	for _, m := range "%&<>|^()!" {
		bad["the program has "+string(m)] = func(_ *winrs.Client, call *winrs.Call) { call.Program = `C:\x` + string(m) + `.exe` }
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			dials := 0
			c := f.client()
			c.Dial = func(context.Context, string, string) (net.Conn, error) { dials++; return nil, errors.New("dialled") }
			call := f.call()
			mutate(c, &call)
			_, err := c.Run(context.Background(), call)
			require.ErrorIs(t, err, winrs.ErrBadConfig)
			assert.ErrorIs(t, err, winrs.ErrNotSent)
			assert.Zero(t, dials, "refused before any dial")
		})
	}

	t.Run("Basic only", func(t *testing.T) {
		f := newFake(t, wintest.OfferBasicOnly())
		_, err := f.client().Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrAuthRefused)
		assert.ErrorIs(t, err, winrs.ErrNotSent)
		raw := f.rawRequests()
		require.Len(t, raw, 1)
		assert.Empty(t, raw[0].auth)
	})
	t.Run("wrong password", func(t *testing.T) {
		f := newFake(t)
		c := f.client()
		c.Password = password(t)
		_, err := c.Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrAuthRefused)
		assert.ErrorIs(t, err, winrs.ErrNotSent)
		assert.Len(t, f.rawRequests(), 3)
	})
	t.Run("403 after the exchange", func(t *testing.T) {
		f := newFake(t)
		f.setHook(func(w http.ResponseWriter, _ served) bool { w.WriteHeader(http.StatusForbidden); return true })
		_, err := f.client().Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrAuthRefused)
		assert.ErrorIs(t, err, winrs.ErrNotSent)
		assert.Len(t, f.rawRequests(), 3)
	})
	t.Run("redirect", func(t *testing.T) {
		f := newFake(t)
		f.setHook(func(w http.ResponseWriter, _ served) bool {
			w.Header().Set("Location", "http://127.0.0.1:1/wsman")
			w.WriteHeader(http.StatusFound)
			return true
		})
		_, err := f.client().Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrProtocol)
		assert.Len(t, f.rawRequests(), 3, "the redirect is not followed")
	})
	t.Run("proxy in the environment", func(t *testing.T) {
		// Go never proxies a loopback address, so the target is a name; Dial sends it to the fake listener.
		proxy, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = proxy.Close() })
		connects := make(chan struct{}, 1)
		go func() {
			if c, err := proxy.Accept(); err == nil {
				connects <- struct{}{}
				_ = c.Close()
			}
		}()
		for _, v := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
			t.Setenv(v, "http://"+proxy.Addr().String())
		}
		t.Setenv("NO_PROXY", "")
		t.Setenv("no_proxy", "")
		f := newFake(t)
		const target = "winrm.example:5986"
		var mu sync.Mutex
		var dialled []string
		c := f.client()
		c.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialled = append(dialled, addr)
			mu.Unlock()
			if addr == target {
				addr = f.srv.Listener.Addr().String()
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		call := f.call()
		call.Addr = target
		_, err = c.Run(context.Background(), call)
		require.NoError(t, err)
		mu.Lock()
		assert.Equal(t, []string{target}, dialled, "only the target is dialled")
		mu.Unlock()
		select {
		case <-connects:
			t.Fatal("the proxy saw a connection")
		default:
		}
	})
	t.Run("plain HTTP", func(t *testing.T) {
		plain := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(plain.Close)
		call := f.call()
		call.Addr = plain.Listener.Addr().String()
		_, err := f.client().Run(context.Background(), call)
		require.ErrorIs(t, err, winrs.ErrUnreachable)
		assert.ErrorIs(t, err, winrs.ErrNotSent)
	})
	t.Run("connection closed after Create", func(t *testing.T) {
		f := newFake(t)
		f.setHook(func(w http.ResponseWriter, s served) bool {
			if s.req.Action != winrs.ActionCreate {
				return false
			}
			w.Header().Set("Connection", "close")
			_, _ = w.Write(winrs.ShellCreatedResponse(s.req.MessageID, "11111111-0000-4000-8000-000000000001"))
			return true
		})
		dials := 0
		c := f.client()
		c.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials++
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		_, err := c.Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrUnreachable)
		assert.NotErrorIs(t, err, winrs.ErrNotSent, "the shell exists: what follows is uncertain")
		assert.Equal(t, 1, dials, "after Create's answer a dial is refused before it reaches Dial")
		assert.Equal(t, []string{"Create"}, f.actions(), "no Send was written")
	})
}

// F24 (d): Windows closes the connection after the anonymous 401, so the sign-in takes a second connection; everything
// after Create goes on that authenticated connection. A third dial is never allowed.
func TestWinRSSignInMayTakeASecondConnection(t *testing.T) {
	counting := func(c *winrs.Client, dials *int) {
		c.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			*dials++
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	}
	t.Run("closed after the anonymous 401", func(t *testing.T) {
		f := newFake(t)
		f.closeFirst = 1
		dials := 0
		c := f.client()
		counting(c, &dials)
		call := f.call()
		call.Stdin = []byte("key material")
		res, err := c.Run(context.Background(), call)
		require.NoError(t, err)
		assert.Equal(t, f.stdout, res.Stdout)
		assert.Equal(t, 2, dials)
		raw := f.rawRequests()
		require.Len(t, raw, 7)
		assert.Equal(t, 1, raw[0].conn, "the anonymous request")
		for _, r := range raw[1:] {
			assert.Equal(t, 2, r.conn, "the exchange and every later request, the Send included, on the second connection")
		}
		f.waitClosed(t)
	})
	t.Run("a third dial during the sign-in", func(t *testing.T) {
		f := newFake(t)
		f.closeFirst = 2 // also after the type 2: the type 3 would need a third connection
		dials := 0
		c := f.client()
		counting(c, &dials)
		_, err := c.Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrUnreachable)
		assert.ErrorIs(t, err, winrs.ErrNotSent)
		assert.Equal(t, 2, dials, "the third dial is refused before it reaches Dial")
		assert.Empty(t, f.actions())
	})
	// A fault on the second connection is the transport's, not a refused password (the Negotiator would hand back
	// the anonymous 401).
	t.Run("the pin refused on the second connection", func(t *testing.T) {
		f := newFake(t)
		f.closeFirst = 1
		refusal := errors.New("the identity is not the pinned one")
		c := f.client()
		verify, handshakes := c.TLS.VerifyConnection, 0
		c.TLS.VerifyConnection = func(cs tls.ConnectionState) error {
			if handshakes++; handshakes > 1 {
				return refusal
			}
			return verify(cs)
		}
		_, err := c.Run(context.Background(), f.call())
		require.ErrorIs(t, err, refusal)
		assert.ErrorIs(t, err, winrs.ErrUnreachable)
		assert.ErrorIs(t, err, winrs.ErrNotSent)
		assert.NotErrorIs(t, err, winrs.ErrAuthRefused)
		assert.Len(t, f.rawRequests(), 1, "only the anonymous request reached the listener")
	})
	t.Run("the second dial refused", func(t *testing.T) {
		f := newFake(t)
		f.closeFirst = 1
		dials := 0
		c := f.client()
		c.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dials++; dials > 1 {
				return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		_, err := c.Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrUnreachable)
		assert.ErrorIs(t, err, syscall.ECONNREFUSED)
		assert.ErrorIs(t, err, winrs.ErrNotSent)
		assert.NotErrorIs(t, err, winrs.ErrAuthRefused)
	})
}

func TestWinRSPinBeforeAnyRequest(t *testing.T) {
	f := newFake(t)
	refusal := errors.New("the identity is not the pinned one")
	c := f.client()
	c.TLS.VerifyConnection = func(tls.ConnectionState) error { return refusal }
	_, err := c.Run(context.Background(), f.call())
	require.ErrorIs(t, err, refusal)
	assert.ErrorIs(t, err, winrs.ErrUnreachable)
	assert.ErrorIs(t, err, winrs.ErrNotSent)
	assert.Empty(t, f.rawRequests(), "no request, so no NTLM message, reached an unpinned listener")
}

func TestWinRSNotSentStages(t *testing.T) {
	tests := []struct {
		name    string
		hook    func(http.ResponseWriter, served) bool
		mutate  func(*winrs.Client, *winrs.Call)
		want    error
		notSent bool
	}{
		{name: "dial refused", mutate: func(_ *winrs.Client, call *winrs.Call) { call.Addr = "169.254.169.254:5986" }, want: netaddr.ErrNotAllowed, notSent: true},
		{name: "NTLM refused", mutate: func(c *winrs.Client, _ *winrs.Call) { c.Password += "x" }, want: winrs.ErrAuthRefused, notSent: true},
		{name: "Create fault", hook: faultAt(winrs.ActionCreate, 5), want: &winrs.FaultError{Code: 5, Action: winrs.ActionCreate}, notSent: true},
		{name: "Create malformed", hook: malformedAt(winrs.ActionCreate), want: winrs.ErrProtocol, notSent: true},
		{name: "Command fault 2", hook: faultAt(winrs.ActionCommand, 2), want: &winrs.FaultError{Code: 2, Action: winrs.ActionCommand}},
		{name: "Command malformed", hook: malformedAt(winrs.ActionCommand), want: winrs.ErrProtocol},
		{name: "Send fault", hook: faultAt(winrs.ActionSend, 7), want: &winrs.FaultError{Code: 7, Action: winrs.ActionSend}},
		{name: "Receive malformed", hook: malformedAt(winrs.ActionReceive), want: winrs.ErrProtocol},
		{name: "Receive fault", hook: faultAt(winrs.ActionReceive, 9), want: &winrs.FaultError{Code: 9, Action: winrs.ActionReceive}},
		{name: "Receive never done", hook: neverDone, mutate: func(_ *winrs.Client, call *winrs.Call) { call.Timeout = 500 * time.Millisecond }, want: winrs.ErrTimeout},
		{name: "a server error without a fault", hook: func(w http.ResponseWriter, s served) bool {
			if s.req.Action != winrs.ActionSend {
				return false
			}
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}, want: winrs.ErrProtocol},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.setHook(tt.hook)
			c, call := f.client(), f.call()
			if tt.mutate != nil {
				tt.mutate(c, &call)
			}
			_, err := c.Run(context.Background(), call)
			var fe, want *winrs.FaultError
			if errors.As(tt.want, &want) {
				require.ErrorAs(t, err, &fe)
				assert.Equal(t, want.Code, fe.Code)
				assert.Equal(t, want.Action, fe.Action, "the fault names the request it answered")
			} else {
				require.ErrorIs(t, err, tt.want)
			}
			assert.Equal(t, tt.notSent, errors.Is(err, winrs.ErrNotSent), "ErrNotSent: %v", err)
		})
	}
}

func TestWinRSAlwaysDeletesTheShell(t *testing.T) {
	tests := []struct {
		name        string
		hook        func(http.ResponseWriter, served) bool
		mutate      func(*winrs.Call)
		want        error
		signal, del bool
	}{
		{name: "timeout", hook: neverDone, mutate: func(c *winrs.Call) { c.Timeout = 300 * time.Millisecond }, want: winrs.ErrTimeout, signal: true, del: true},
		{name: "overflow", mutate: func(c *winrs.Call) { c.MaxOutput = 3 }, want: winrs.ErrOutputTooLarge, signal: true, del: true},
		{name: "Send fault", hook: faultAt(winrs.ActionSend, 7), del: true},
		{name: "Receive protocol error", hook: malformedAt(winrs.ActionReceive), want: winrs.ErrProtocol, del: true},
		{name: "Create fault", hook: faultAt(winrs.ActionCreate, 5)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.setHook(tt.hook)
			call := f.call()
			if tt.mutate != nil {
				tt.mutate(&call)
			}
			_, err := f.client().Run(context.Background(), call)
			require.Error(t, err)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
			}
			acts := f.actions()
			assert.Equal(t, tt.signal, contains(acts, "Signal"), acts)
			assert.Equal(t, tt.del, contains(acts, "Delete"), acts)
			if tt.del {
				assert.Equal(t, "Delete", acts[len(acts)-1])
			}
			f.waitClosed(t)
		})
	}
	t.Run("auth refusal", func(t *testing.T) {
		f := newFake(t)
		c := f.client()
		c.Password = password(t)
		_, err := c.Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrAuthRefused)
		assert.Empty(t, f.actions())
		f.waitClosed(t)
	})
	t.Run("context cancelled mid-Receive", func(t *testing.T) {
		f := newFake(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.setHook(func(w http.ResponseWriter, s served) bool {
			if s.req.Action != winrs.ActionReceive {
				return false
			}
			cancel()
			time.Sleep(50 * time.Millisecond)
			_, _ = w.Write(winrs.ReceivedResponse(s.req.MessageID, s.req.CommandID, nil, false, 0))
			return true
		})
		_, err := f.client().Run(ctx, f.call())
		require.ErrorIs(t, err, winrs.ErrTimeout)
		assert.ErrorIs(t, err, context.Canceled)
		acts := f.actions()
		assert.Equal(t, []string{"Signal", "Delete"}, acts[len(acts)-2:])
		f.waitClosed(t)
	})
	t.Run("context already ended", func(t *testing.T) {
		f := newFake(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := f.client().Run(ctx, f.call())
		require.ErrorIs(t, err, winrs.ErrTimeout)
		assert.ErrorIs(t, err, winrs.ErrNotSent)
		assert.Empty(t, f.rawRequests())
	})
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestWinRSBounds(t *testing.T) {
	t.Run("stdout over MaxOutput", func(t *testing.T) {
		f := newFake(t)
		call := f.call()
		call.MaxOutput = int64(len(f.stdout)) - 1
		_, err := f.client().Run(context.Background(), call)
		require.ErrorIs(t, err, winrs.ErrOutputTooLarge)
		call.MaxOutput = int64(len(f.stdout))
		res, err := f.client().Run(context.Background(), call)
		require.NoError(t, err)
		assert.Equal(t, f.stdout, res.Stdout)
	})
	t.Run("response over MaxResponseBody", func(t *testing.T) {
		f := newFake(t)
		f.setHook(func(w http.ResponseWriter, s served) bool {
			if s.req.Action != winrs.ActionReceive {
				return false
			}
			_, _ = w.Write(winrs.ReceivedResponse(s.req.MessageID, s.req.CommandID, make([]byte, winrs.MaxResponseBody), true, 0))
			return true
		})
		_, err := f.client().Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrProtocol)
	})
	t.Run("response header over 64 KiB", func(t *testing.T) {
		f := newFake(t)
		f.setHook(func(w http.ResponseWriter, s served) bool {
			if s.req.Action != winrs.ActionReceive {
				return false
			}
			w.Header().Set("X-Big", strings.Repeat("a", 70<<10))
			_, _ = w.Write(winrs.ReceivedResponse(s.req.MessageID, s.req.CommandID, nil, true, 0))
			return true
		})
		_, err := f.client().Run(context.Background(), f.call())
		require.ErrorIs(t, err, winrs.ErrUnreachable)
	})
	t.Run("stderr over 64 KiB", func(t *testing.T) {
		f := newFake(t)
		f.setHook(func(w http.ResponseWriter, s served) bool {
			if s.req.Action != winrs.ActionReceive {
				return false
			}
			resp := winrs.ReceivedResponse(s.req.MessageID, s.req.CommandID, []byte("out"), true, 0)
			stderr := `<rsp:Stream Name="stderr" CommandId="` + s.req.CommandID + `">` + base64.StdEncoding.EncodeToString(make([]byte, 100<<10)) + `</rsp:Stream>`
			_, _ = w.Write(bytes.Replace(resp, []byte("<rsp:ReceiveResponse>"), []byte("<rsp:ReceiveResponse>"+stderr), 1))
			return true
		})
		res, err := f.client().Run(context.Background(), f.call())
		require.NoError(t, err)
		assert.Equal(t, []byte("out"), res.Stdout)
	})
	t.Run("a Receive that times out on the server is asked again", func(t *testing.T) {
		f := newFake(t)
		n := 0
		f.setHook(func(w http.ResponseWriter, s served) bool {
			if s.req.Action != winrs.ActionReceive || n > 0 {
				return false
			}
			n++
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(winrs.FaultResponse(s.req.MessageID, 2150858793)) // w:TimedOut
			return true
		})
		res, err := f.client().Run(context.Background(), f.call())
		require.NoError(t, err)
		assert.Equal(t, f.stdout, res.Stdout)
		assert.Equal(t, []string{"Create", "Command", "Send", "Receive", "Receive", "Delete"}, f.actions())
	})
}

func TestWinRSShellIdle(t *testing.T) {
	f := newFake(t)
	call := f.call()
	call.Timeout = 30 * time.Second
	_, err := f.client().Run(context.Background(), call)
	require.NoError(t, err)
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Contains(t, string(f.served[0].body), "<rsp:IdleTimeOut>PT90S</rsp:IdleTimeOut>")
}
