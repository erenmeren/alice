package fakeacme

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

type admin struct {
	t   *testing.T
	srv *httptest.Server
}

func newAdmin(t *testing.T, s *Server) *admin {
	t.Helper()
	srv := httptest.NewServer(s.AdminHandler())
	t.Cleanup(srv.Close)
	return &admin{t: t, srv: srv}
}

func (a *admin) do(method, path string, q url.Values) (int, map[string]any) {
	a.t.Helper()
	req, err := http.NewRequestWithContext(ctx(a.t), method, a.srv.URL+path+"?"+q.Encode(), nil)
	require.NoError(a.t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(a.t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(a.t, err)
	var doc map[string]any
	require.NoError(a.t, json.Unmarshal(b, &doc), string(b))
	return resp.StatusCode, doc
}

func (a *admin) ok(method, path string, kv ...string) map[string]any {
	a.t.Helper()
	q := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	status, doc := a.do(method, path, q)
	require.Equal(a.t, 200, status, "%s %s: %v", method, path, doc)
	return doc
}

func (a *admin) fails(method, path string, kv ...string) {
	a.t.Helper()
	q := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	status, doc := a.do(method, path, q)
	assert.Equal(a.t, 400, status, "%s %s %v", method, path, kv)
	assert.NotEmpty(a.t, doc["error"])
}

func TestAdminControlsTheFake(t *testing.T) {
	s := start(t, Options{})
	a := newAdmin(t, s)
	assert.Equal(t, true, a.ok("GET", "/ping")["ok"])
	cred := a.ok("GET", "/credentials")
	assert.Equal(t, s.Credentials().HookSecret, cred["hook_secret"])
	assert.Equal(t, s.DirectoryURL(), cred["directory_url"])

	// DNS table.
	a.ok("POST", "/dns", "name", "_acme-challenge.X.test.", "value", "v1")
	a.ok("POST", "/dns", "name", "_acme-challenge.x.test", "value", "v2")
	assert.Equal(t, []any{"v1", "v2"}, a.ok("GET", "/dns")["_acme-challenge.x.test"])
	a.ok("POST", "/dns/clear", "name", "_acme-challenge.x.test", "value", "v1")
	assert.Equal(t, []any{"v2"}, a.ok("GET", "/dns")["_acme-challenge.x.test"])
	a.ok("POST", "/dns/clear")
	assert.Empty(t, a.ok("GET", "/dns"))
	a.fails("POST", "/dns", "name", "x.test")

	// HTTP target.
	a.ok("POST", "/http-target", "name", "w.test", "addr", "127.0.0.1:8080")
	assert.Equal(t, "127.0.0.1:8080", s.st.targets["w.test"])
	a.ok("POST", "/http-target", "name", "w.test", "addr", "off")
	assert.Empty(t, s.st.targets)
	a.fails("POST", "/http-target", "addr", "x")

	// Toggles.
	a.ok("POST", "/eab", "required", "true")
	assert.True(t, s.cfg.requireEAB)
	a.fails("POST", "/eab", "required", "maybe")
	a.ok("POST", "/lifetime", "duration", "36h")
	assert.Equal(t, 36*time.Hour, s.cfg.lifetime)
	a.fails("POST", "/lifetime", "duration", "soon")
	a.fails("POST", "/lifetime", "duration", "1s")
	a.ok("POST", "/stuck", "on", "true")
	assert.True(t, s.cfg.stuck)
	a.fails("POST", "/stuck", "on", "x")
	a.ok("POST", "/reject", "identifier", "bad.test")
	a.fails("POST", "/reject")
	assert.Equal(t, []string{"bad.test"}, s.cfg.rejected)
	a.ok("POST", "/reject/clear")
	a.ok("POST", "/validation-fail", "type", "dns-01", "on", "true")
	assert.True(t, s.cfg.failValidation[DNS01])
	a.fails("POST", "/validation-fail", "type", "x", "on", "true")
	a.fails("POST", "/validation-fail", "type", "dns-01", "on", "x")
	a.ok("POST", "/advertise", "field", "newOrder", "url", "http://169.254.169.254/x")
	assert.Equal(t, "http://169.254.169.254/x", s.cfg.overrides["newOrder"])
	a.ok("POST", "/advertise", "field", "newOrder")
	assert.Empty(t, s.cfg.overrides)
	a.fails("POST", "/advertise", "field", "nope")
	a.ok("POST", "/challenges", "types", "dns-01")
	assert.Equal(t, []string{DNS01}, s.cfg.challenges)
	a.fails("POST", "/challenges", "types", "tls-alpn-01")
	a.ok("POST", "/processing-polls", "n", "2")
	assert.Equal(t, 2, s.cfg.processingPolls)
	a.fails("POST", "/processing-polls", "n", "-1")

	// ARI forms.
	a.ok("POST", "/ari", "start", "2030-01-01T00:00:00Z", "end", "2030-01-02T00:00:00Z")
	assert.Equal(t, 2030, s.cfg.ariStart.Year())
	a.ok("POST", "/ari", "before", "48h", "length", "1h")
	assert.Equal(t, 48*time.Hour, s.cfg.ariBefore)
	assert.True(t, s.cfg.ariStart.IsZero())
	a.ok("POST", "/ari", "before", "48h")
	a.ok("POST", "/ari", "default", "true")
	assert.Zero(t, s.cfg.ariBefore)
	a.fails("POST", "/ari")
	a.fails("POST", "/ari", "start", "x", "end", "y")
	a.fails("POST", "/ari", "start", "2030-01-02T00:00:00Z", "end", "2030-01-01T00:00:00Z")
	a.fails("POST", "/ari", "before", "x")
	a.fails("POST", "/ari", "before", "1h", "length", "x")
	a.fails("POST", "/ari", "before", "-1h")

	// Clock.
	a.ok("POST", "/clock", "time", "2031-05-05T05:05:05Z")
	assert.Equal(t, 2031, s.Now().Year())
	a.ok("POST", "/clock", "time", "real")
	a.fails("POST", "/clock", "time", "1999-01-01T00:00:00Z")

	// Faults and counters.
	a.ok("POST", "/fault", "endpoint", "new-order", "kind", "rateLimited", "times", "2", "retry_after", "30")
	assert.Equal(t, 30*time.Second, s.st.faults[0].RetryAfter)
	a.ok("POST", "/fault", "endpoint", "*", "kind", "slow", "delay", "10ms")
	a.fails("POST", "/fault", "endpoint", "x", "kind", "slow", "delay", "10ms")
	a.fails("POST", "/fault", "endpoint", "*", "kind", "slow", "delay", "x")
	a.fails("POST", "/fault", "endpoint", "*", "kind", "badNonce", "times", "x")
	a.fails("POST", "/fault", "endpoint", "*", "kind", "rateLimited", "retry_after", "x")
	a.ok("POST", "/unfault")
	assert.Empty(t, s.st.faults)
	getJSON(t, s, s.DirectoryURL(), nil)
	assert.EqualValues(t, 1, a.ok("GET", "/counters")["directory"])
	assert.Len(t, a.ok("GET", "/requests")["requests"], 1)
	a.ok("POST", "/requests/clear")
	assert.Len(t, a.ok("GET", "/requests")["requests"], 0)

	// Reset returns the credentials.
	assert.Equal(t, cred["eab_kid"], a.ok("POST", "/reset")["eab_kid"])
	assert.False(t, s.cfg.requireEAB)
}

func TestAdminAnswersLoopbackOnly(t *testing.T) {
	s := start(t, Options{})
	h := s.AdminHandler()
	for addr, want := range map[string]int{"127.0.0.1:5000": 200, "[::1]:5000": 200, "10.0.0.5:5000": 403, "garbage": 403} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		req.RemoteAddr = addr
		h.ServeHTTP(rec, req)
		assert.Equal(t, want, rec.Code, addr)
	}
}

func TestSetHTTPTargetFallsBackToPort(t *testing.T) {
	// A bare host in the map keeps the port the URL asks for.
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	s.SetHTTPTarget("Bare.Example.Test", "127.0.0.1")
	o, err := c.AuthorizeOrder(ctx(t), idents("bare.example.test"))
	require.NoError(t, err)
	az, err := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
	require.NoError(t, err)
	for _, ch := range az.Challenges {
		if ch.Type == HTTP01 {
			got, err := c.Accept(ctx(t), ch)
			require.NoError(t, err)
			assert.Equal(t, acme.StatusInvalid, got.Status, "port 80 of 127.0.0.1 has no web server here")
		}
	}
}
