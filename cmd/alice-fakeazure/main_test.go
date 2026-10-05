package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logBuffer is a log sink the serve goroutine and the test read safely.
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

// stack is a running fake: serve on loopback ports, its admin address, its CA file.
type stack struct {
	t      *testing.T
	listen string
	admin  string
	caFile string
	logs   *logBuffer
}

func startStack(t *testing.T) *stack {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "azure", "ca") // the directory is created
	st := &stack{t: t, caFile: filepath.Join(dir, "ca.pem"), logs: &logBuffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan [2]string, 1)
	done := make(chan error, 1)
	cfg := serveConfig{Listen: "127.0.0.1:0", Admin: "127.0.0.1:0", CAOut: st.caFile, VaultName: "alice-e2e",
		ready: func(listen, admin string) { ready <- [2]string{listen, admin} }}
	go func() { done <- serve(ctx, cfg, slog.New(slog.NewTextHandler(st.logs, nil))) }()
	select {
	case addrs := <-ready:
		st.listen, st.admin = addrs[0], addrs[1]
	case err := <-done:
		cancel()
		t.Fatalf("serve ended before it was ready: %v", err)
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("serve was not ready")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("serve did not stop")
		}
	})
	return st
}

// ctl runs "ctl --admin <addr> args..." and returns the exit status, stdout and stderr.
func (st *stack) ctl(args ...string) (int, string, string) {
	st.t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), append([]string{"ctl", "--admin", st.admin}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

// ctlJSON runs a ctl command that must succeed and decodes its one JSON object.
func (st *stack) ctlJSON(args ...string) map[string]any {
	st.t.Helper()
	code, out, errOut := st.ctl(args...)
	require.Equal(st.t, 0, code, "ctl %v: %s", args, errOut)
	var m map[string]any
	require.NoError(st.t, json.Unmarshal([]byte(out), &m), out)
	return m
}

// client reaches the fake the way Alice does in the e2e stack: the Azure host names are dialled at the
// fake's listener (Docker's DNS does that in compose) and its CA, read from the file serve wrote,
// is the only root.
func (st *stack) client() *http.Client {
	st.t.Helper()
	raw, err := os.ReadFile(st.caFile)
	require.NoError(st.t, err)
	pool := x509.NewCertPool()
	require.True(st.t, pool.AppendCertsFromPEM(raw))
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, st.listen)
		},
	}
	st.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}

func (st *stack) do(c *http.Client, method, target string, form url.Values, bearer string) (int, http.Header, []byte) {
	st.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, body)
	require.NoError(st.t, err)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	require.NoError(st.t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(st.t, err)
	return resp.StatusCode, resp.Header, b
}

// token signs in with the credentials ctl prints and returns the access token (status 0 body on refusal).
func (st *stack) token(c *http.Client, creds map[string]any) (int, string) {
	st.t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {creds["client_id"].(string)},
		"client_secret": {creds["client_secret"].(string)}, "scope": {"https://vault.azure.net/.default"}}
	status, _, body := st.do(c, http.MethodPost, "https://login.microsoftonline.com/"+creds["tenant_id"].(string)+"/oauth2/v2.0/token", form, "")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(body, &tok)
	return status, tok.AccessToken
}

func (st *stack) names(c *http.Client, token, kind string) []string {
	st.t.Helper()
	status, _, body := st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/"+kind+"?api-version=2025-07-01", nil, token)
	require.Equal(st.t, http.StatusOK, status, string(body))
	var list struct {
		Value []struct {
			ID  string `json:"id"`
			Kid string `json:"kid"` // keys name themselves with kid
		} `json:"value"`
	}
	require.NoError(st.t, json.Unmarshal(body, &list))
	var out []string
	for _, v := range list.Value {
		id := v.ID
		if id == "" {
			id = v.Kid
		}
		out = append(out, id[strings.LastIndex(id, "/")+1:])
	}
	return out
}

func (st *stack) signedIn(c *http.Client) string {
	st.t.Helper()
	status, tok := st.token(c, st.ctlJSON("credentials"))
	require.Equal(st.t, http.StatusOK, status)
	require.NotEmpty(st.t, tok)
	return tok
}

// serve writes its CA (world-readable: Alice reads it as another user), seeds the vault and serves
// the Azure hosts over TLS with that CA.
func TestServeWritesTheCAAndSeedsTheVault(t *testing.T) {
	st := startStack(t)
	info, err := os.Stat(st.caFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	raw, err := os.ReadFile(st.caFile)
	require.NoError(t, err)
	block, rest := pem.Decode(raw)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Empty(t, bytes.TrimSpace(rest), "one certificate: the root")
	root, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, root.IsCA)
	entries, err := os.ReadDir(filepath.Dir(st.caFile))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file is left next to the CA")

	c := st.client()
	tok := st.signedIn(c)
	assert.ElementsMatch(t, []string{"web-cert", "monitor-only"}, st.names(c, tok, "certificates"))
	assert.Contains(t, st.names(c, tok, "keys"), "signing-key") // a certificate's backing key is listed too, as in Azure
	assert.Contains(t, st.names(c, tok, "secrets"), "db-password")

	status, _, body := st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/certificates/monitor-only?api-version=2025-07-01", nil, tok)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, string(body), `"exportable":false`, "monitor-only is not exportable")
	status, _, body = st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/certificates/web-cert?api-version=2025-07-01", nil, tok)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, string(body), `"exportable":true`)
	assert.Contains(t, string(body), "www.example.test")
}

func TestCtlCredentialsPrintsTheSignInDetails(t *testing.T) {
	st := startStack(t)
	creds := st.ctlJSON("credentials")
	assert.ElementsMatch(t, []string{"tenant_id", "client_id", "client_secret", "vault_url"}, keysOf(creds))
	assert.Equal(t, "https://alice-e2e.vault.azure.net", creds["vault_url"])
	assert.Regexp(t, `^fake-[0-9a-f]{40}$`, creds["client_secret"])
	assert.Regexp(t, `^[0-9a-f-]{36}$`, creds["tenant_id"])
	assert.Regexp(t, `^[0-9a-f-]{36}$`, creds["client_id"])
	// The secret is what the sign-in accepts, and it never reaches serve's log.
	status, tok := st.token(st.client(), creds)
	assert.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, tok)
	assert.NotContains(t, st.logs.String(), creds["client_secret"].(string))
	assert.NotContains(t, st.logs.String(), tok)
}

func keysOf(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCtlRenewAndLeaf(t *testing.T) {
	st := startStack(t)
	before := st.ctlJSON("leaf", "web-cert")["fingerprint"].(string)
	assert.Regexp(t, `^[0-9a-f]{64}$`, before, "lower-case SHA-256 of the leaf, no colons")
	renewed := st.ctlJSON("renew", "web-cert")
	assert.Regexp(t, `^[0-9a-f]{32}$`, renewed["version"])
	after := st.ctlJSON("leaf", "web-cert")["fingerprint"].(string)
	assert.NotEqual(t, before, after, "the current leaf is the new version's")
	assert.Equal(t, before, st.ctlJSON("leaf", "web-cert", "--version", st.firstVersion("web-cert"))["fingerprint"])
	assert.Equal(t, after, st.ctlJSON("leaf", "web-cert", "--version", renewed["version"].(string))["fingerprint"])

	for _, args := range [][]string{{"renew", "no-such-cert"}, {"leaf", "no-such-cert"}, {"renew", "../x"}, {"renew"}, {"leaf", "web-cert", "--version", "zz"}} {
		code, _, errOut := st.ctl(args...)
		assert.Equal(t, 1, code, "%v", args)
		assert.NotEmpty(t, errOut, "%v", args)
	}
}

// firstVersion is the version ID the seed created: the oldest of the versions the fake lists.
func (st *stack) firstVersion(name string) string {
	st.t.Helper()
	c := st.client()
	tok := st.signedIn(c)
	status, _, body := st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/certificates/"+name+"/versions?api-version=2025-07-01", nil, tok)
	require.Equal(st.t, http.StatusOK, status)
	var list struct {
		Value []struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"value"`
	}
	require.NoError(st.t, json.Unmarshal(body, &list))
	oldest, created := "", float64(1<<62)
	for _, v := range list.Value {
		if c, _ := v.Attributes["created"].(float64); c <= created {
			created, oldest = c, v.ID[strings.LastIndex(v.ID, "/")+1:]
		}
	}
	return oldest
}

func TestCtlRolesRevokeGrantAndSet(t *testing.T) {
	st := startStack(t)
	c := st.client()
	tok := st.signedIn(c)
	ver := st.firstVersion("web-cert") // the vault's secrets are read by version, as Alice does
	get := func() int {
		s, _, _ := st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/secrets/web-cert/"+ver+"?api-version=2025-07-01", nil, tok)
		return s
	}
	require.Equal(t, http.StatusOK, get())
	st.ctlJSON("revoke-role", "secrets/get")
	assert.Equal(t, http.StatusForbidden, get())
	st.ctlJSON("grant-role", "secrets/get")
	assert.Equal(t, http.StatusOK, get())

	st.ctlJSON("set-roles", "Key Vault Reader")
	assert.Equal(t, http.StatusForbidden, get(), "a Reader reads no secret value")
	st.ctlJSON("set-roles", "Key Vault Secrets User", "Key Vault Certificates Officer")
	assert.Equal(t, http.StatusOK, get())
	st.ctlJSON("grant-all")
	assert.Equal(t, http.StatusOK, get())

	for _, args := range [][]string{{"revoke-role", "secrets/nope"}, {"grant-role"}, {"set-roles", "Owner"}} {
		code, _, errOut := st.ctl(args...)
		assert.Equal(t, 1, code, "%v", args)
		assert.NotEmpty(t, errOut)
	}
}

func TestCtlPing(t *testing.T) {
	st := startStack(t)
	code, out, _ := st.ctl("ping")
	assert.Equal(t, 0, code)
	assert.JSONEq(t, `{"ok":true}`, out)

	// Nothing listens there: ping fails (the container's health check).
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	var o, e bytes.Buffer
	assert.Equal(t, 1, run(context.Background(), []string{"ctl", "--admin", addr, "ping"}, &o, &e))
	assert.NotEmpty(t, e.String())
}

// The admin API has no authentication beyond the loopback address: serve refuses to bind it elsewhere,
// ctl refuses to talk to anything else, and the handler refuses a caller that is not loopback.
func TestAdminIsLoopbackOnly(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, addr := range []string{"0.0.0.0:9090", ":9090", "10.1.2.3:9090", "example.com:9090", "[::]:9090", "172.18.0.2:9090", "9090",
		"localhost:9090", "[::1%lo]:9090", "[::ffff:127.0.0.1]:9090", "127.0.0.1", "127.0.0.1:99999", "127.0.0.1:x"} {
		out.Reset()
		errOut.Reset()
		// A short context: were the check missing, ctl would try to connect and fail after a while
		// instead of refusing at once, and the test must fail rather than wait for the network.
		ctlCtx, cancelCtl := context.WithTimeout(context.Background(), 2*time.Second)
		assert.Equal(t, 2, run(ctlCtx, []string{"ctl", "--admin", addr, "ping"}, &out, &errOut), addr)
		cancelCtl()
		assert.Contains(t, errOut.String(), "loopback", addr)
		assert.Empty(t, out.String())

		// Port 0 and a short context: were the check missing, serve would bind a wildcard port
		// for 2 s and return nil, so the test fails instead of hanging or holding a real port.
		zero := strings.TrimSuffix(addr, ":9090")
		if zero != addr {
			zero += ":0"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cfg := serveConfig{Listen: "127.0.0.1:0", Admin: zero, VaultName: "alice-e2e"}
		err := serve(ctx, cfg, slog.New(slog.DiscardHandler))
		cancel()
		require.Error(t, err, addr)
		assert.Contains(t, err.Error(), "loopback", addr)
	}
	for _, addr := range []string{"127.0.0.1:9090", "127.0.0.2:0", "[::1]:9090"} {
		assert.NoError(t, checkLoopback(addr), addr)
	}
	// The address a listener really bound is checked again.
	assert.NoError(t, boundLoopback(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}))
	assert.NoError(t, boundLoopback(&net.TCPAddr{IP: net.IPv6loopback, Port: 1}))
	for _, ip := range []string{"0.0.0.0", "10.1.2.3", "::", "172.18.0.2"} {
		assert.Error(t, boundLoopback(&net.TCPAddr{IP: net.ParseIP(ip), Port: 1}), ip)
	}

	// Defence in depth: whatever the listener, a caller that is not loopback gets nothing.
	f, err := newFake("alice-e2e")
	require.NoError(t, err)
	t.Cleanup(f.close)
	h := adminHandler(f)
	for remote, want := range map[string]int{"127.0.0.1:5000": http.StatusOK, "[::1]:5000": http.StatusOK,
		"10.0.0.5:5000": http.StatusForbidden, "172.18.0.3:5000": http.StatusForbidden, "garbage": http.StatusForbidden} {
		req := httptest.NewRequest(http.MethodGet, "/credentials", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, want, rec.Code, remote)
		if want == http.StatusForbidden {
			assert.NotContains(t, rec.Body.String(), "fake-", "no secret to a stranger")
		}
	}
}

// reset keeps the CA and the listener (so Alice's trust file stays right), clears what a journey
// changed, reseeds the vault and issues a new client secret; the old one stops working.
func TestCtlResetReseedsAndRotatesTheSecret(t *testing.T) {
	st := startStack(t)
	caBefore, err := os.ReadFile(st.caFile)
	require.NoError(t, err)
	old := st.ctlJSON("credentials")
	c := st.client()
	tok := st.signedIn(c)

	st.ctlJSON("renew", "web-cert")
	st.ctlJSON("revoke-role", "secrets/get")
	st.ctlJSON("delete", "monitor-only")
	st.ctlJSON("throttle")
	st.ctlJSON("firewall", "203.0.113.7")

	fresh := st.ctlJSON("reset")
	assert.ElementsMatch(t, []string{"tenant_id", "client_id", "client_secret", "vault_url"}, keysOf(fresh))
	assert.Equal(t, old["tenant_id"], fresh["tenant_id"])
	assert.Equal(t, old["client_id"], fresh["client_id"])
	assert.NotEqual(t, old["client_secret"], fresh["client_secret"])
	assert.Equal(t, fresh, st.ctlJSON("credentials"), "credentials answers the new secret")

	caAfter, err := os.ReadFile(st.caFile)
	require.NoError(t, err)
	assert.Equal(t, caBefore, caAfter, "the CA Alice trusts survives a reset")

	status, _ := st.token(c, old)
	assert.NotEqual(t, http.StatusOK, status, "the old secret is refused")
	status, tok2 := st.token(c, fresh)
	require.Equal(t, http.StatusOK, status)
	assert.NotEqual(t, tok, tok2)
	assert.ElementsMatch(t, []string{"web-cert", "monitor-only"}, st.names(c, tok2, "certificates"), "reseeded: monitor-only is back, no throttle, no firewall")
	assert.Equal(t, 1, countVersions(t, st, c, tok2, "web-cert"), "the renewal is gone")
	status, _, _ = st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/secrets/web-cert/"+st.firstVersion("web-cert")+"?api-version=2025-07-01", nil, tok2)
	assert.Equal(t, http.StatusOK, status, "roles are granted again")
}

func countVersions(t *testing.T, st *stack, c *http.Client, tok, name string) int {
	t.Helper()
	status, _, body := st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/certificates/"+name+"/versions?api-version=2025-07-01", nil, tok)
	require.Equal(t, http.StatusOK, status)
	var list struct {
		Value []any `json:"value"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	return len(list.Value)
}

func TestCtlFaultsThrottleAndFirewall(t *testing.T) {
	st := startStack(t)
	c := st.client()
	tok := st.signedIn(c)
	list := func() (int, http.Header, []byte) {
		return st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/certificates?api-version=2025-07-01", nil, tok)
	}
	status, _, _ := list()
	require.Equal(t, http.StatusOK, status)

	st.ctlJSON("throttle", "--retry-after", "7")
	status, h, _ := list()
	assert.Equal(t, http.StatusTooManyRequests, status)
	assert.Equal(t, "7", h.Get("Retry-After"))
	st.ctlJSON("unfault")
	status, _, _ = list()
	assert.Equal(t, http.StatusOK, status)

	// A one-shot fault on one path: the next authenticated request fails, the one after works.
	st.ctlJSON("fault", "/certificates", "503", "--times", "1")
	status, _, _ = list()
	assert.Equal(t, http.StatusServiceUnavailable, status)
	status, _, _ = list()
	assert.Equal(t, http.StatusOK, status)

	st.ctlJSON("firewall", "203.0.113.7")
	status, _, body := list()
	assert.Equal(t, http.StatusForbidden, status)
	assert.Contains(t, string(body), "ForbiddenByFirewall")
	assert.Contains(t, string(body), "203.0.113.7")
	st.ctlJSON("firewall", "off")
	status, _, _ = list()
	assert.Equal(t, http.StatusOK, status)

	st.ctlJSON("expire-secret", "on")
	status, _ = st.token(c, st.ctlJSON("credentials"))
	assert.NotEqual(t, http.StatusOK, status, "an expired client secret is refused")
	st.ctlJSON("expire-secret", "off")
	status, _ = st.token(c, st.ctlJSON("credentials"))
	assert.Equal(t, http.StatusOK, status)

	for _, args := range [][]string{{"fault"}, {"fault", "/certificates", "999"}, {"fault", "certificates", "503"}, {"fault", "/certificates", "x"},
		{"fault", "/certificates", "503", "--times", "-1"}, {"throttle", "--retry-after", "abc"}, {"firewall"}, {"expire-secret", "maybe"}} {
		code, _, errOut := st.ctl(args...)
		assert.Equal(t, 1, code, "%v", args)
		assert.NotEmpty(t, errOut, "%v", args)
	}
}

func TestCtlChangesToCertificates(t *testing.T) {
	st := startStack(t)
	c := st.client()
	tok := st.signedIn(c)
	statusOf := func(path string) int {
		s, _, _ := st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net"+path+"?api-version=2025-07-01", nil, tok)
		return s
	}

	// Non-exportable and exportable again.
	st.ctlJSON("set-exportable", "web-cert", "false")
	_, _, body := st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/certificates/web-cert?api-version=2025-07-01", nil, tok)
	assert.Contains(t, string(body), `"exportable":false`)
	st.ctlJSON("set-exportable", "web-cert", "true")

	// Disable the newest version (or a named one), then enable it again.
	renewed := st.ctlJSON("renew", "web-cert")["version"].(string)
	got := st.ctlJSON("disable-version", "web-cert")
	assert.Equal(t, renewed, got["version"], "the newest version by default")
	_, _, body = st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/certificates/web-cert/"+renewed+"?api-version=2025-07-01", nil, tok)
	assert.Contains(t, string(body), `"enabled":false`)
	st.ctlJSON("enable-version", "web-cert", "--version", renewed)
	_, _, body = st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/certificates/web-cert/"+renewed+"?api-version=2025-07-01", nil, tok)
	assert.Contains(t, string(body), `"enabled":true`)

	// Delete and recover.
	st.ctlJSON("delete", "web-cert")
	assert.Equal(t, http.StatusNotFound, statusOf("/certificates/web-cert"))
	st.ctlJSON("recover", "web-cert")
	assert.Equal(t, http.StatusOK, statusOf("/certificates/web-cert"))

	// A certificate added by name, with its own common name.
	added := st.ctlJSON("add-cert", "other-cert", "--cn", "other.example.test", "--exportable", "false")
	assert.Regexp(t, `^[0-9a-f]{32}$`, added["version"])
	assert.Equal(t, http.StatusOK, statusOf("/certificates/other-cert"))
	for _, args := range [][]string{{"add-cert", "web-cert"}, {"add-cert", "bad name"}, {"add-cert", "x", "--exportable", "maybe"}, {"set-exportable", "web-cert"},
		{"disable-version", "no-such"}, {"delete", "no-such"}, {"recover", "no-such"}} {
		code, _, errOut := st.ctl(args...)
		assert.Equal(t, 1, code, "%v", args)
		assert.NotEmpty(t, errOut, "%v", args)
	}
}

// requests counts what the fake answered, so a journey can assert "nothing was sent" (or how many
// calls reached which host); clear-requests starts a new count.
func TestCtlRequestsCountsAndClears(t *testing.T) {
	st := startStack(t)
	st.ctlJSON("clear-requests")
	zero := st.ctlJSON("requests")
	assert.EqualValues(t, 0, zero["count"])
	assert.EqualValues(t, 0, zero["vault"])
	assert.EqualValues(t, 0, zero["login"])

	c := st.client()
	tok := st.signedIn(c)
	_ = st.names(c, tok, "certificates")
	got := st.ctlJSON("requests")
	assert.EqualValues(t, 1, got["login"])
	assert.Positive(t, got["vault"])
	assert.EqualValues(t, got["login"].(float64)+got["vault"].(float64), got["count"])
	// Only the vault host, only authenticated calls.
	assert.EqualValues(t, 1, st.ctlJSON("requests", "--authenticated")["vault"])

	st.ctlJSON("clear-requests")
	assert.EqualValues(t, 0, st.ctlJSON("requests")["count"])
}

func TestCtlUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	assert.Equal(t, 2, run(context.Background(), nil, &out, &errOut))
	assert.Contains(t, errOut.String(), "Usage")
	errOut.Reset()
	assert.Equal(t, 2, run(context.Background(), []string{"nonsense"}, &out, &errOut))
	assert.Contains(t, errOut.String(), "Usage")
	errOut.Reset()
	assert.Equal(t, 2, run(context.Background(), []string{"ctl"}, &out, &errOut))
	assert.Contains(t, errOut.String(), "Usage")
	errOut.Reset()
	st := startStack(t)
	code, _, e := st.ctl("no-such-command")
	assert.Equal(t, 2, code)
	assert.Contains(t, e, "unknown")
	assert.Empty(t, out.String())
}

// A reset is atomic for the Azure hosts: a request that arrives while it runs never sees the emptied
// vault (the fake clears its state and the tool reseeds it as one step).
func TestResetNeverShowsAnEmptyVault(t *testing.T) {
	st := startStack(t)
	c := st.client()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				var out, errOut bytes.Buffer
				run(context.Background(), []string{"ctl", "--admin", st.admin, "reset"}, &out, &errOut)
			}
		}
	}()
	defer func() { close(stop); <-done }()
	deadline := time.Now().Add(20 * time.Second) //nolint:forbidigo // wall-clock test deadline, not product time
	seen := 0
	for tok := ""; seen < 25 && time.Now().Before(deadline); { //nolint:forbidigo // same
		if tok == "" {
			_, tok = st.token(c, st.ctlJSON("credentials"))
		}
		status, _, body := st.do(c, http.MethodGet, "https://alice-e2e.vault.azure.net/certificates?api-version=2025-07-01", nil, tok)
		switch status {
		case http.StatusOK:
			seen++
			assert.Contains(t, string(body), "web-cert", "a reset showed a vault without its seed")
			assert.Contains(t, string(body), "monitor-only")
		default:
			tok = "" // the reset replaced the secret and cleared the tokens
		}
	}
	assert.Equal(t, 25, seen, "the poller saw answers while resets ran")
}
