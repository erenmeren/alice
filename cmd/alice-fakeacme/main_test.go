package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
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

type stack struct {
	t      *testing.T
	listen string
	admin  string
	caFile string
	logs   *logBuffer
}

func startStack(t *testing.T, mod func(*serveConfig)) *stack {
	t.Helper()
	st := &stack{t: t, caFile: filepath.Join(t.TempDir(), "acme", "ca", "ca.pem"), logs: &logBuffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan [2]string, 1)
	done := make(chan error, 1)
	cfg := serveConfig{Listen: "127.0.0.1:0", Admin: "127.0.0.1:0", CAOut: st.caFile, BaseURL: "https://acme.test.alice",
		ready: func(listen, admin string) { ready <- [2]string{listen, admin} }}
	if mod != nil {
		mod(&cfg)
	}
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

func (st *stack) ctl(args ...string) (int, string, string) {
	st.t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), append([]string{"ctl", "--admin", st.admin}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

func (st *stack) ctlJSON(args ...string) map[string]any {
	st.t.Helper()
	code, out, errOut := st.ctl(args...)
	require.Equal(st.t, 0, code, "ctl %v: %s", args, errOut)
	var m map[string]any
	require.NoError(st.t, json.Unmarshal([]byte(out), &m), out)
	return m
}

// client reaches the fake the way Alice does in the e2e stack: acme.test.alice is dialled at the
// fake's listener (Docker's DNS does that in compose) and the CA file serve wrote is the only root.
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

func TestServeWritesTheCAAndServesTheDirectory(t *testing.T) {
	st := startStack(t, nil)
	raw, err := os.ReadFile(st.caFile)
	require.NoError(t, err)
	block, rest := pem.Decode(raw)
	require.NotNil(t, block)
	assert.Empty(t, bytes.TrimSpace(rest), "exactly one certificate (what the e2e trust hook accepts)")
	ca, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, ca.IsCA)
	info, err := os.Stat(st.caFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	resp, err := st.client().Get("https://acme.test.alice/directory") //nolint:noctx // test
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var d map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&d))
	assert.Equal(t, "https://acme.test.alice/acme/new-order", d["newOrder"])

	logs := st.logs.String()
	assert.Contains(t, logs, "alice-fakeacme is serving")
	creds := st.ctlJSON("credentials")
	assert.NotContains(t, logs, creds["hook_secret"])
	assert.NotContains(t, logs, creds["eab_hmac"])
	// ctl ca prints the TLS CA the client above trusts (what a CA bundle field takes).
	caDoc := st.ctlJSON("ca")
	assert.Contains(t, caDoc["ca_pem"], "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, caDoc["issuer_root_pem"], "-----BEGIN CERTIFICATE-----")
	assert.NotEqual(t, caDoc["ca_pem"], caDoc["issuer_root_pem"])
}

func TestAnOrderThroughTheTool(t *testing.T) {
	st := startStack(t, nil)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	c := &acme.Client{Key: key, DirectoryURL: "https://acme.test.alice/directory", HTTPClient: st.client(),
		RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return time.Millisecond }}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = c.Register(ctx, &acme.Account{Contact: []string{"mailto:a@example.test"}}, acme.AcceptTOS)
	require.NoError(t, err)

	// The requests so far, and "CA contacted N times".
	before := st.ctlJSON("counters")
	assert.EqualValues(t, 1, before["new-account"])

	o, err := c.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: "www.example.test"}})
	require.NoError(t, err)
	az, err := c.GetAuthorization(ctx, o.AuthzURLs[0])
	require.NoError(t, err)
	for _, ch := range az.Challenges {
		if ch.Type != "dns-01" {
			continue
		}
		rec, err := c.DNS01ChallengeRecord(ch.Token)
		require.NoError(t, err)
		st.ctlJSON("dns", "set", "_acme-challenge.www.example.test", rec)
		_, err = c.Accept(ctx, ch)
		require.NoError(t, err)
	}
	_, err = c.WaitAuthorization(ctx, az.URI)
	require.NoError(t, err)
	o, err = c.WaitOrder(ctx, o.URI)
	require.NoError(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "www.example.test"}, DNSNames: []string{"www.example.test"}}, key)
	require.NoError(t, err)
	der, _, err := c.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	require.NoError(t, err)
	assert.Len(t, der, 2)

	cnt := st.ctlJSON("counters")
	assert.EqualValues(t, 1, cnt["finalize"])
	assert.EqualValues(t, 1, cnt["issued"])
	assert.NotEmpty(t, st.ctlJSON("dns", "list")["_acme-challenge.www.example.test"])
	st.ctlJSON("dns", "clear")
	assert.Empty(t, st.ctlJSON("dns", "list"))
	assert.NotEmpty(t, st.ctlJSON("requests")["requests"])
	st.ctlJSON("clear-requests")
	assert.Empty(t, st.ctlJSON("requests")["requests"])
	st.ctlJSON("reset")
	assert.Zero(t, st.ctlJSON("counters")["requests"])
}

func TestHookThroughTheTool(t *testing.T) {
	st := startStack(t, nil)
	creds := st.ctlJSON("credentials")
	secret := creds["hook_secret"].(string)
	assert.Equal(t, "https://acme.test.alice/hook", creds["hook_url"])
	body := `{"action":"present","fqdn":"_acme-challenge.h.example.test","value":"abc","ttl":60}`
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, creds["hook_url"].(string), strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Alice-Signature", hex.EncodeToString(m.Sum(nil)))
	resp, err := st.client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, []any{"abc"}, st.ctlJSON("dns", "list")["_acme-challenge.h.example.test"])
}

func TestEveryCtlCommandReachesTheFake(t *testing.T) {
	st := startStack(t, func(c *serveConfig) { c.Alternates = 1; c.RequireEAB = true })
	for _, args := range [][]string{
		{"ping"}, {"credentials"}, {"ca"}, {"counters"}, {"requests"}, {"clear-requests"},
		{"fault", "set", "new-order", "rateLimited", "--times", "2", "--retry-after", "30"},
		{"fault", "set", "*", "slow", "--delay", "10ms"},
		{"fault", "clear"},
		{"dns", "set", "a.test", "v"}, {"dns", "clear", "a.test", "v"}, {"dns", "clear"}, {"dns", "list"},
		{"http-target", "a.test", "127.0.0.1:8080"}, {"http-target", "a.test", "off"},
		{"eab", "off"}, {"eab", "on"}, {"lifetime", "48h"}, {"stuck", "on"}, {"stuck", "off"},
		{"reject", "bad.test"}, {"reject", "clear"},
		{"validation-fail", "dns-01", "on"}, {"validation-fail", "dns-01", "off"},
		{"challenges", "dns-01"}, {"challenges", "http-01,dns-01"}, {"processing-polls", "0"},
		{"ari", "default"}, {"ari", "window", "2030-01-01T00:00:00Z", "2030-01-02T00:00:00Z"},
		{"ari", "relative", "72h", "2h"}, {"ari", "relative", "72h"},
		{"replacements"},
		{"advertise", "newOrder", "http://169.254.169.254/x"}, {"advertise", "newOrder"}, {"advertise", "renewalInfo", "off"}, {"advertise", "renewalInfo"},
		{"clock", "2031-01-01T00:00:00Z"}, {"clock", "real"}, {"reset"},
	} {
		code, out, errOut := st.ctl(args...)
		assert.Equal(t, 0, code, "ctl %v: %s", args, errOut)
		assert.True(t, json.Valid([]byte(out)), "%v: %q", args, out)
	}
	// require-eab and alternates reached the fake.
	resp, err := st.client().Get("https://acme.test.alice/directory") //nolint:noctx // test
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var d map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&d))
	assert.Equal(t, true, d["meta"].(map[string]any)["externalAccountRequired"])
}

func TestCtlRefusals(t *testing.T) {
	st := startStack(t, nil)
	for _, args := range [][]string{
		{"fault", "set", "nope", "slow"}, {"fault", "set", "new-order"}, {"fault", "set", "new-order", "slow", "--bogus"},
		{"fault", "set", "new-order", "slow", "--times"}, {"eab", "maybe"}, {"lifetime", "soon"},
		{"clock", "yesterday"}, {"advertise", "bogus", "x"}, {"dns", "set", "a.test"}, {"ari", "window", "x", "y"},
		{"ari", "certificate", "abc", "2030-01-01T00:00:00Z", "2030-01-02T00:00:00Z"},
	} {
		code, _, errOut := st.ctl(args...)
		assert.Equal(t, 1, code, "%v", args)
		assert.Contains(t, errOut, "alice-fakeacme ctl", "%v", args)
	}
	code, _, errOut := st.ctl("nonsense")
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "Usage:")
}

func TestUsageAndFlagErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	assert.Equal(t, 2, run(context.Background(), nil, &out, &errOut))
	assert.Equal(t, 2, run(context.Background(), []string{"bogus"}, &out, &errOut))
	assert.Equal(t, 2, run(context.Background(), []string{"serve", "extra"}, &out, &errOut))
	assert.Equal(t, 2, run(context.Background(), []string{"serve", "--nope"}, &out, &errOut))
	assert.Equal(t, 2, run(context.Background(), []string{"ctl"}, &out, &errOut))
	assert.Equal(t, 2, run(context.Background(), []string{"ctl", "--nope"}, &out, &errOut))
	assert.Equal(t, 2, run(context.Background(), []string{"ctl", "--admin", "0.0.0.0:9091", "ping"}, &out, &errOut))
	assert.Equal(t, 1, run(context.Background(), []string{"ctl", "--admin", "127.0.0.1:1", "ping"}, &out, &errOut))
	assert.Equal(t, 2, run(context.Background(), []string{"serve", "--admin", "0.0.0.0:9091"}, &out, &errOut))
	assert.Equal(t, 1, run(context.Background(), []string{"serve", "--alternates", "9", "--admin", "127.0.0.1:0"}, &out, &errOut))
	assert.Equal(t, 1, run(context.Background(), []string{"serve", "--base-url", "http://acme.test.alice", "--admin", "127.0.0.1:0"}, &out, &errOut))
	assert.Equal(t, 1, run(context.Background(), []string{"serve", "--listen", "256.1.1.1:1", "--admin", "127.0.0.1:0"}, &out, &errOut))
}

func TestCheckLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:9091", "[::1]:9091", "127.9.9.9:0"} {
		assert.NoError(t, checkLoopback(ok), ok)
	}
	for _, bad := range []string{"", ":9091", "localhost:9091", "0.0.0.0:9091", "10.0.0.1:9091", "[::ffff:127.0.0.1]:9091", "127.0.0.1", "127.0.0.1:x", "127.0.0.1:99999", "[fe80::1%eth0]:1"} {
		assert.Error(t, checkLoopback(bad), bad)
	}
	assert.Error(t, boundLoopback(&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}))
	assert.NoError(t, boundLoopback(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}))
}

func TestWriteCAReplacesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x", "ca.pem")
	require.NoError(t, writeCA(path, []byte("one")))
	require.NoError(t, writeCA(path, []byte("two")))
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "two", string(b))
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file stays")
	assert.Error(t, writeCA(filepath.Join(path, "sub", "ca.pem"), []byte("x")), "a file is no directory")
}
