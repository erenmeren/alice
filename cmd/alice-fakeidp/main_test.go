package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type running struct {
	issuer, adminAddr string
	stopped           chan error
	cancel            context.CancelFunc
	logs              *bytes.Buffer
}

func start(t *testing.T) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{stopped: make(chan error, 1), cancel: cancel, logs: &bytes.Buffer{}}
	ready := make(chan struct{})
	cfg := serveConfig{Listen: "127.0.0.1:0", Host: "localhost", Admin: "127.0.0.1:0", RedirectPrefix: "https://localhost:", ready: func(i, a string) {
		r.issuer, r.adminAddr = i, a
		close(ready)
	}}
	go func() { r.stopped <- serve(ctx, cfg, slog.New(slog.NewTextHandler(r.logs, nil))) }()
	select {
	case <-ready:
	case err := <-r.stopped:
		t.Fatalf("serve stopped: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not start")
	}
	t.Cleanup(func() { cancel() })
	return r
}

func (r *running) ctl(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"ctl", "--admin", r.adminAddr}, args...), &out, &errb)
	return out.String(), errb.String(), code
}

func (r *running) ctlOK(t *testing.T, args ...string) string {
	t.Helper()
	out, errs, code := r.ctl(t, args...)
	require.Equal(t, 0, code, errs)
	return out
}

// fetch returns the status and the Location header of a GET; the body is closed here.
func fetch(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	require.NoError(t, err)
	res, err := c.Do(req)
	require.NoError(t, err)
	_ = res.Body.Close()
	return res.StatusCode, res.Header.Get("Location")
}

func TestServeRefusesANonLoopbackAdminAddress(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:9091", ":9091", "localhost:9091", "10.0.0.1:9091", "[::ffff:127.0.0.1]:9091", "127.0.0.1", "127.0.0.1:99999"} {
		var errb bytes.Buffer
		code := run(context.Background(), []string{"serve", "--listen", "127.0.0.1:0", "--admin", bad}, io.Discard, &errb)
		assert.Equal(t, 2, code, bad)
		assert.Contains(t, errb.String(), "loopback", bad)
	}
	var errb bytes.Buffer
	assert.Equal(t, 2, run(context.Background(), []string{"ctl", "--admin", "10.0.0.1:9091", "ping"}, io.Discard, &errb))
	assert.Contains(t, errb.String(), "loopback")
}

func TestCtlRoundTrip(t *testing.T) {
	r := start(t)
	assert.Equal(t, "ok\n", r.ctlOK(t, "ping"))

	var creds struct {
		Issuer       string `json:"issuer"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.ctlOK(t, "credentials")), &creds))
	assert.Equal(t, r.issuer, creds.Issuer)
	assert.Regexp(t, `^https://localhost:[0-9]+$`, creds.Issuer)
	assert.Equal(t, "alice", creds.ClientID)
	assert.NotEmpty(t, creds.ClientSecret)

	caPEM := r.ctlOK(t, "ca")
	blk, rest := pem.Decode([]byte(caPEM))
	require.NotNil(t, blk)
	assert.Equal(t, "CERTIFICATE", blk.Type)
	assert.Empty(t, strings.TrimSpace(string(rest)), "exactly one block")
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM([]byte(caPEM)))
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	assert.Equal(t, 200, status(fetch(t, client, creds.Issuer+"/.well-known/openid-configuration")), "the CA verifies the provider")

	assert.JSONEq(t, `{"ok": true}`, r.ctlOK(t, "next-user", "--sub", "e2e-omer", "--username", "omer", "--name", "Ömer Çelik",
		"--email", "omer@example.test", "--groups", "alice-operators,other"))
	verifier := "v-" + strings.Repeat("x", 50)
	sum := sha256.Sum256([]byte(verifier))
	redirect := "https://localhost:9443/api/v1/auth/sso/callback"
	q := url.Values{"response_type": {"code"}, "client_id": {"alice"}, "redirect_uri": {redirect}, "state": {"st"}, "nonce": {"nn"},
		"scope": {"openid"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	st, location := fetch(t, client, creds.Issuer+"/authorize?"+q.Encode())
	require.Equal(t, http.StatusFound, st)
	loc, err := url.Parse(location)
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)
	assert.Equal(t, "st", loc.Query().Get("state"))

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier},
		"client_id": {"alice"}, "client_secret": {creds.ClientSecret}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, creds.Issuer+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tres, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = tres.Body.Close() }()
	var tok struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.NewDecoder(tres.Body).Decode(&tok))
	parts := strings.Split(tok.IDToken, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Sub    string   `json:"sub"`
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	require.NoError(t, json.Unmarshal(raw, &claims))
	assert.Equal(t, "e2e-omer", claims.Sub)
	assert.Equal(t, "omer@example.test", claims.Email)
	assert.Equal(t, []string{"alice-operators", "other"}, claims.Groups)

	// A redirect outside the prefix is refused.
	q.Set("redirect_uri", "https://evil.example/cb")
	assert.Equal(t, http.StatusBadRequest, status(fetch(t, client, creds.Issuer+"/authorize?"+q.Encode())))

	assert.JSONEq(t, `{"ok": true}`, r.ctlOK(t, "down"))
	assert.Equal(t, http.StatusServiceUnavailable, status(fetch(t, client, creds.Issuer+"/.well-known/openid-configuration")))
	assert.Equal(t, "ok\n", r.ctlOK(t, "ping"), "the admin API still answers")
	assert.JSONEq(t, `{"ok": true}`, r.ctlOK(t, "up"))
	assert.Equal(t, 200, status(fetch(t, client, creds.Issuer+"/.well-known/openid-configuration")))

	assert.NotContains(t, r.logs.String(), creds.ClientSecret, "the client secret is never logged")
	r.cancel()
	require.NoError(t, <-r.stopped, "SIGTERM-style cancellation stops cleanly")
	_, err = net.DialTimeout("tcp", strings.TrimPrefix(creds.Issuer, "https://"), time.Second)
	assert.Error(t, err, "the provider stopped listening")
}

func TestCtlErrors(t *testing.T) {
	r := start(t)
	for _, tc := range [][]string{{}, {"nope"}, {"ping", "extra"}, {"next-user"}, {"next-user", "--sub", "x", "extra"}, {"next-user", "--bogus"}} {
		_, errs, code := r.ctl(t, tc...)
		assert.NotEqual(t, 0, code, tc)
		assert.NotEmpty(t, errs, tc)
	}
	resp, err := http.Post("http://"+r.adminAddr+"/ctl/next-user", "application/json", strings.NewReader(`{"sub":"x","extra":1}`)) //nolint:noctx,gosec // G107: loopback test server
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "unknown fields and a missing sub are refused")
	assert.Equal(t, 2, run(context.Background(), nil, io.Discard, io.Discard))
	assert.Equal(t, 2, run(context.Background(), []string{"bogus"}, io.Discard, io.Discard))
	assert.Equal(t, 2, run(context.Background(), []string{"serve", "extra"}, io.Discard, io.Discard))
	assert.Equal(t, 2, run(context.Background(), []string{"serve", "--nope"}, io.Discard, io.Discard))
	assert.Equal(t, 2, run(context.Background(), []string{"ctl", "--nope"}, io.Discard, io.Discard))
	assert.Equal(t, 2, run(context.Background(), []string{"ctl", "--admin", r.adminAddr}, io.Discard, io.Discard))
	var errb bytes.Buffer
	assert.Equal(t, 1, run(context.Background(), []string{"ctl", "--admin", "127.0.0.1:1", "ping"}, io.Discard, &errb))
	assert.Contains(t, errb.String(), "does not answer")
	assert.Equal(t, 1, run(context.Background(), []string{"serve", "--listen", "127.0.0.1:0", "--admin", r.adminAddr}, io.Discard, io.Discard))
}

func status(code int, _ string) int { return code }
