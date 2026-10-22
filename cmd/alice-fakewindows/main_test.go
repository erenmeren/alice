package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers/windows"
	"alice/internal/providers/windows/winproto"
)

type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestParseServe(t *testing.T) {
	cfg, err := parseServe(nil, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Equal(t, serveConfig{Listen: ":22", TLSBind: "0.0.0.0", Ctl: "127.0.0.1:9093"}, cfg)

	cfg, err = parseServe([]string{"--listen", "127.0.0.1:0", "--tls-bind", "127.0.0.1:0", "--ctl", "[::1]:0"}, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Equal(t, serveConfig{Listen: "127.0.0.1:0", TLSBind: "127.0.0.1:0", Ctl: "[::1]:0"}, cfg)

	for name, args := range map[string][]string{
		"ctl not loopback":     {"--ctl", "0.0.0.0:9093"},
		"ctl a name":           {"--ctl", "localhost:9093"},
		"tls bind a name":      {"--tls-bind", "fakewindows"},
		"tls bind fixed port":  {"--tls-bind", "127.0.0.1:443"},
		"tls bind bad address": {"--tls-bind", "nowhere:0"},
		"listen without port":  {"--listen", "127.0.0.1"},
		"extra argument":       {"extra"},
		"unknown flag":         {"--nope"},
	} {
		_, err := parseServe(args, &bytes.Buffer{})
		assert.Error(t, err, name)
	}
}

func TestCheckLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:9093", "127.1.2.3:1", "[::1]:9093"} {
		assert.NoError(t, checkLoopback(ok), ok)
	}
	for _, bad := range []string{"0.0.0.0:9093", "10.0.0.1:9093", "localhost:9093", "[::ffff:127.0.0.1]:9093", "127.0.0.1", "127.0.0.1:x", "[fe80::1%lo]:1", ":9093"} {
		assert.Error(t, checkLoopback(bad), bad)
	}
	assert.NoError(t, boundLoopback(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}))
	assert.Error(t, boundLoopback(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}))
}

func TestAuthorizedKeyOf(t *testing.T) {
	key := clientKey(t)
	pub := key.PublicKey()
	line := keyLineFor(key)
	script := setupScriptFor(t, key)
	got, err := authorizedKeyOf([]byte(script))
	require.NoError(t, err)
	assert.Equal(t, pub.Marshal(), got.Marshal())

	// CRLF line ends (a script saved on Windows) are fine.
	got, err = authorizedKeyOf([]byte(strings.ReplaceAll(script, "\n", "\r\n")))
	require.NoError(t, err)
	assert.Equal(t, pub.Marshal(), got.Marshal())

	keyLine := "$AuthorizedKey = '" + line + "'"
	require.Contains(t, script, keyLine)
	for name, bad := range map[string]string{
		"no key line":       strings.ReplaceAll(script, keyLine, "# no key"),
		"two key lines":     strings.ReplaceAll(script, keyLine, keyLine+"\n"+keyLine),
		"unquoted":          strings.ReplaceAll(script, keyLine, "$AuthorizedKey = "+line),
		"not a key":         strings.ReplaceAll(script, keyLine, "$AuthorizedKey = 'restrict ssh-ed25519 notbase64!'"),
		"no forced command": strings.ReplaceAll(script, keyLine, "$AuthorizedKey = 'restrict "+pubText(key)+"'"),
		"another command": strings.ReplaceAll(script, keyLine,
			`$AuthorizedKey = 'restrict,command="\"C:\Windows\System32\cmd.exe\" ssh" `+pubText(key)+"'"),
		"empty":             "",
		"only another name": "$AuthorizedKeysFile = 'C:\\ProgramData\\ssh\\administrators_authorized_keys'\n",
	} {
		_, err := authorizedKeyOf([]byte(bad))
		assert.Error(t, err, name)
	}
}

type stack struct {
	ssh     string
	ctl     string
	hostKey ssh.PublicKey
	logs    *logBuffer
	done    chan error
}

func startStack(t *testing.T) *stack {
	t.Helper()
	st := &stack{logs: &logBuffer{}, done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	cfg := serveConfig{Listen: "127.0.0.1:0", TLSBind: "127.0.0.1:0", Ctl: "127.0.0.1:0",
		ready: func(sshAddr, ctl string, hostKey ssh.PublicKey) {
			st.ssh, st.ctl, st.hostKey = sshAddr, ctl, hostKey
			close(ready)
		}}
	go func() { st.done <- serve(ctx, cfg, slog.New(slog.NewTextHandler(st.logs, nil))) }()
	select {
	case <-ready:
	case err := <-st.done:
		cancel()
		t.Fatalf("serve stopped: %v", err)
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("serve did not start")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-st.done:
			assert.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("serve did not stop")
		}
	})
	return st
}

func (st *stack) ctlRun(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(context.Background(), append([]string{"ctl", "--ctl", st.ctl}, args...), strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func clientKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return s
}

func pubText(key ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
}

func keyLineFor(key ssh.Signer) string {
	return windows.AuthorizedKeysLine(pubText(key), "")
}

// setupScriptFor is the Windows setup script Alice shows for key (a development build: no helper checksums here).
func setupScriptFor(t *testing.T, key ssh.Signer) string {
	t.Helper()
	script, err := windows.SetupScript(keyLineFor(key), true)
	require.NoError(t, err)
	return script
}

// dial signs in as alice, accepting only a host key whose fingerprint is want.
func dial(addr string, key ssh.Signer, want string) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "alice",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if ssh.FingerprintSHA256(k) != want {
				return errors.New("unexpected host key")
			}
			return nil
		},
		Timeout: 10 * time.Second,
	})
}

func execLine(t *testing.T, c *ssh.Client, cmd string) []byte {
	t.Helper()
	s, err := c.NewSession()
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	out, err := s.Output(cmd)
	require.NoError(t, err, cmd)
	return out
}

func TestFakeWindowsServesTheDemoHostAfterPrepare(t *testing.T) {
	st := startStack(t)
	key := clientKey(t)

	code, out, errOut := st.ctlRun(t, "", "ping")
	require.Equal(t, 0, code, errOut)
	assert.JSONEq(t, `{"ok":true}`, out)

	code, out, errOut = st.ctlRun(t, "", "hostkey")
	require.Equal(t, 0, code, errOut)
	fingerprint := strings.TrimSpace(out)
	assert.Equal(t, ssh.FingerprintSHA256(st.hostKey), fingerprint, "ctl hostkey prints the server's key")
	assert.Regexp(t, `^SHA256:[A-Za-z0-9+/]+$`, fingerprint)

	_, err := dial(st.ssh, key, fingerprint)
	require.Error(t, err, "no key is authorized before ctl prepare")

	code, out, errOut = st.ctlRun(t, setupScriptFor(t, key), "prepare")
	require.Equal(t, 0, code, errOut)
	assert.JSONEq(t, `{"ok":true}`, out)

	c, err := dial(st.ssh, key, fingerprint)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	var v winproto.VersionResponse
	require.NoError(t, json.Unmarshal(execLine(t, c, winproto.SubVersion), &v))
	assert.Equal(t, winproto.Protocol, v.Protocol)
	assert.Equal(t, winproto.Version, v.Helper)
	// Windows OpenSSH (W0): a second session on the same connection runs the first session's command.
	v = winproto.VersionResponse{}
	require.NoError(t, json.Unmarshal(execLine(t, c, winproto.SubWinFacts), &v))
	assert.Equal(t, winproto.Protocol, v.Protocol, "the second session sees the first command")

	// A fresh connection per call, as the provider does: the demo host's facts and bindings.
	c2, err := dial(st.ssh, key, fingerprint)
	require.NoError(t, err)
	defer func() { _ = c2.Close() }()
	facts := string(execLine(t, c2, winproto.SubWinFacts))
	assert.Contains(t, facts, "Windows Server 2022 Datacenter")
	assert.Contains(t, facts, "10.0.20348.2700")
	c3, err := dial(st.ssh, key, fingerprint)
	require.NoError(t, err)
	defer func() { _ = c3.Close() }()
	dump := string(execLine(t, c3, winproto.SubIISDump))
	for _, want := range []string{"www.win.example.test", "Default Web Site", "Intranet", "WebHosting", "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}"} {
		assert.Contains(t, dump, want)
	}

	// A second prepare with another key replaces the authorized key.
	other := clientKey(t)
	code, _, errOut = st.ctlRun(t, setupScriptFor(t, other), "prepare")
	require.Equal(t, 0, code, errOut)
	_, err = dial(st.ssh, key, fingerprint)
	require.Error(t, err, "the old key is no longer authorized")
	c4, err := dial(st.ssh, other, fingerprint)
	require.NoError(t, err)
	_ = c4.Close()

	assert.Contains(t, st.logs.String(), "alice-fakewindows is serving")
	assert.NotContains(t, st.logs.String(), "PRIVATE KEY")
}

func TestFakeWindowsServesTheDemoBindingsOverTLS(t *testing.T) {
	st := startStack(t)
	// The control API names the TLS listeners (tests listen on random ports).
	code, out, errOut := st.ctlRun(t, "", "endpoints")
	require.Equal(t, 0, code, errOut)
	var eps map[string]string
	require.NoError(t, json.Unmarshal([]byte(out), &eps))
	require.Len(t, eps, 3, "443, 8443 and 5986")
	conn, err := tls.Dial("tcp", eps["443"], &tls.Config{ServerName: "www.win.example.test", InsecureSkipVerify: true}) //nolint:gosec // reads what the fake presents
	require.NoError(t, err)
	assert.Equal(t, "www.win.example.test", conn.ConnectionState().PeerCertificates[0].Subject.CommonName)
	_ = conn.Close()
}

func TestPrepareRefusesScriptsWithoutOrWithTwoKeyLines(t *testing.T) {
	st := startStack(t)
	key := clientKey(t)
	script := setupScriptFor(t, key)
	line := "$AuthorizedKey = '" + keyLineFor(key) + "'"
	require.Contains(t, script, line)
	for name, bad := range map[string]string{
		"without the line": strings.ReplaceAll(script, line, "# none"),
		"with two lines":   strings.ReplaceAll(script, line, line+"\n"+line),
	} {
		code, out, errOut := st.ctlRun(t, bad, "prepare")
		assert.Equal(t, 1, code, name)
		assert.Empty(t, out, name)
		assert.Contains(t, errOut, "$AuthorizedKey", name)
	}
	_, err := dial(st.ssh, key, ssh.FingerprintSHA256(st.hostKey))
	assert.Error(t, err, "a refused script authorizes nothing")
}

func TestCtlUsageErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	assert.Equal(t, 2, run(context.Background(), nil, strings.NewReader(""), &out, &errOut))
	assert.Contains(t, errOut.String(), "Usage")
	errOut.Reset()
	assert.Equal(t, 2, run(context.Background(), []string{"bogus"}, strings.NewReader(""), &out, &errOut))
	assert.Contains(t, errOut.String(), "unknown command")
	for name, args := range map[string][]string{
		"no command":       {"ctl"},
		"unknown command":  {"ctl", "bogus"},
		"argument":         {"ctl", "ping", "extra"},
		"ctl not loopback": {"ctl", "--ctl", "10.0.0.1:9093", "ping"},
		"bad flag":         {"ctl", "--nope"},
		"bad serve flag":   {"serve", "--nope"},
	} {
		errOut.Reset()
		assert.Equal(t, 2, run(context.Background(), args, strings.NewReader(""), &out, &errOut), name)
		assert.NotEmpty(t, errOut.String(), name)
	}
	assert.Empty(t, out.String())
}

func TestCtlFailures(t *testing.T) {
	// Nothing listens.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	var out, errOut bytes.Buffer
	assert.Equal(t, 1, run(context.Background(), []string{"ctl", "--ctl", addr, "ping"}, strings.NewReader(""), &out, &errOut))
	assert.Contains(t, errOut.String(), "does not answer")

	// A server that answers an error without a JSON body, and one with a body that is too large.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			_, _ = w.Write(bytes.Repeat([]byte("x"), int(maxCtlBody)+1))
			return
		}
		http.Error(w, "nope", http.StatusTeapot)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	errOut.Reset()
	assert.Equal(t, 1, run(context.Background(), []string{"ctl", "--ctl", host, "hostkey"}, strings.NewReader(""), &out, &errOut))
	assert.Contains(t, errOut.String(), strconv.Itoa(http.StatusTeapot))
	errOut.Reset()
	assert.Equal(t, 1, run(context.Background(), []string{"ctl", "--ctl", host, "ping"}, strings.NewReader(""), &out, &errOut))
	assert.Contains(t, errOut.String(), "larger than")

	// A script larger than the control API takes.
	errOut.Reset()
	assert.Equal(t, 1, run(context.Background(), []string{"ctl", "--ctl", host, "prepare"},
		io.LimitReader(letters{}, maxScript+1), &out, &errOut))
	assert.Contains(t, errOut.String(), "larger than")
	assert.Empty(t, out.String())
}

type letters struct{}

func (letters) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestControlHandlerRefusesOtherRequests(t *testing.T) {
	st := startStack(t)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/prepare"}, {http.MethodPost, "/ping"}, {http.MethodGet, "/nope"},
	} {
		req, err := http.NewRequestWithContext(context.Background(), tc.method, "http://"+st.ctl+tc.path, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.GreaterOrEqual(t, resp.StatusCode, 400, "%s %s", tc.method, tc.path)
	}
}

func TestServeFailsWhenAnAddressIsTaken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	taken := ln.Addr().String()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for name, cfg := range map[string]serveConfig{
		"ssh": {Listen: taken, TLSBind: "127.0.0.1:0", Ctl: "127.0.0.1:0"},
		"ctl": {Listen: "127.0.0.1:0", TLSBind: "127.0.0.1:0", Ctl: taken},
	} {
		assert.Error(t, serve(context.Background(), cfg, log), name)
	}
	var out, errOut bytes.Buffer
	assert.Equal(t, 1, run(context.Background(), []string{"serve", "--listen", taken, "--tls-bind", "127.0.0.1:0", "--ctl", "127.0.0.1:0"},
		strings.NewReader(""), &out, &errOut))
	assert.Contains(t, errOut.String(), "stopped")
}

func TestServeReturnsWhenItsContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--tls-bind", "127.0.0.1:0", "--ctl", "127.0.0.1:0"}, strings.NewReader(""), &out, &errOut), errOut.String())
}

func TestPrepareRefusesAnOversizedBodyAndAnUnreadableScript(t *testing.T) {
	st := startStack(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+st.ctl+"/prepare", io.LimitReader(letters{}, maxScript+1))
	require.NoError(t, err)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

	code, out, errOut := st.ctlRun(t, "", "prepare")
	assert.Equal(t, 1, code)
	assert.Empty(t, out)
	assert.Contains(t, errOut, "exactly one")
	var o, e bytes.Buffer
	assert.Equal(t, 1, run(context.Background(), []string{"ctl", "--ctl", st.ctl, "prepare"}, iotestErr{}, &o, &e))
	assert.Contains(t, e.String(), "read the script")
}

type iotestErr struct{}

func (iotestErr) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }
