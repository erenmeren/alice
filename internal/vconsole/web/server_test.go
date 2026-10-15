package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

const wantCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// newUnitServer builds a Server without a database: only routes that never reach the pool may be used.
func newUnitServer(t *testing.T) (*Server, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC))
	s, err := New(Config{RPID: "licenses.example.test", Origin: "https://licenses.example.test", Clock: clk})
	require.NoError(t, err)
	return s, clk
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s, _ := newUnitServer(t)
	h := s.Handler()
	for _, path := range []string{"/login", "/enroll", "/static/passkey.js", "/static/app.css", "/static/nope.js", "/static/"} {
		w := serve(h, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, wantCSP, w.Header().Get("Content-Security-Policy"), path)
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"), path)
		assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"), path)
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), path)
	}
	w := serve(h, httptest.NewRequest(http.MethodGet, "/login", nil))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `id="login-button"`)
	assert.Contains(t, body, `role="alert"`)
	assert.Contains(t, body, `<script src="/static/passkey.js"`)
	assert.NotContains(t, body, "<style")
	assert.NotContains(t, body, " style=")
	assert.NotContains(t, body, " onclick=")

	w = serve(h, httptest.NewRequest(http.MethodGet, "/enroll", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `id="enroll-button"`)

	w = serve(h, httptest.NewRequest(http.MethodGet, "/static/passkey.js", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "javascript")

	// No directory listing and no way out of the static directory.
	assert.Equal(t, http.StatusNotFound, serve(h, httptest.NewRequest(http.MethodGet, "/static/", nil)).Code)
	w = serve(h, httptest.NewRequest(http.MethodGet, "/static/../templates/login.html", nil))
	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "{{")
}

func TestCrossSitePostIsRefused(t *testing.T) {
	s, _ := newUnitServer(t)
	h := s.Handler()
	for _, path := range []string{"/logout", "/webauthn/login/begin", "/webauthn/register/begin", "/webauthn/register/finish", "/webauthn/login/finish"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := serve(h, r)
		assert.Equal(t, http.StatusForbidden, w.Code, "Sec-Fetch-Site %s", path)
		assert.Equal(t, wantCSP, w.Header().Get("Content-Security-Policy"))

		r = httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		r.Header.Set("Origin", "https://evil.example")
		assert.Equal(t, http.StatusForbidden, serve(h, r).Code, "Origin %s", path)
	}
	// The configured origin passes even when a proxy rewrote Host.
	r := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", nil)
	r.Header.Set("Origin", "https://licenses.example.test")
	assert.Equal(t, http.StatusOK, serve(h, r).Code)
	// Same-origin per Sec-Fetch-Site passes.
	r = httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	assert.Equal(t, http.StatusOK, serve(h, r).Code)
}

func TestUnauthenticatedPagesRedirectToLogin(t *testing.T) {
	s, _ := newUnitServer(t)
	h := s.Handler()
	for _, path := range []string{"/", "/customers", "/requests/new", "/licenses", "/licenses/x/download", "/anything"} {
		w := serve(h, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, http.StatusSeeOther, w.Code, path)
		assert.Equal(t, "/login", w.Header().Get("Location"), path)
		assert.NotContains(t, w.Body.String(), "BEGIN", path)
	}
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := serve(h, r)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestBeginEndpointsAreRateLimited(t *testing.T) {
	s, clk := newUnitServer(t)
	h := s.Handler()
	post := func(addr string) int {
		r := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", nil)
		r.RemoteAddr = addr
		return serve(h, r).Code
	}
	for i := range 10 {
		require.Equal(t, http.StatusOK, post("192.0.2.1:1234"), "request %d", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, post("192.0.2.1:5678"), "11th from the same address, other port")
	assert.Equal(t, http.StatusOK, post("192.0.2.2:1234"), "another address is unaffected")
	assert.Equal(t, http.StatusOK, post("[2001:db8::1]:443"))
	// register/begin shares the limit for the address.
	r := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", strings.NewReader(`{"code":"x"}`))
	r.RemoteAddr = "192.0.2.1:1"
	assert.Equal(t, http.StatusTooManyRequests, serve(h, r).Code)

	clk.Advance(time.Minute)
	assert.Equal(t, http.StatusOK, post("192.0.2.1:1234"), "a new window starts after a minute")
}

func TestRateLimitIsInjectable(t *testing.T) {
	s, err := New(Config{RPID: "localhost", Origin: "http://localhost:8443", limitN: 2, limitWindow: time.Second})
	require.NoError(t, err)
	h := s.Handler()
	codes := []int{}
	for range 3 {
		r := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", nil)
		codes = append(codes, serve(h, r).Code)
	}
	assert.Equal(t, []int{200, 200, 429}, codes)
}

func TestInsecureOriginIsRefusedExceptLocalhost(t *testing.T) {
	for _, c := range []struct {
		rpid, origin string
		ok           bool
	}{
		{"example.com", "http://example.com", false},
		{"localhost", "http://localhost:8443", true},
		{"127.0.0.1", "http://127.0.0.1:8080", false}, // WebAuthn needs a domain as RP ID
		{"x.example", "https://x.example", true},
		{"x.example", "https://x.example:8443", true},
		{"other.example", "https://x.example", false},
		{"x.example:8443", "https://x.example:8443", false},
		{"x.example", "https://x.example/path", false},
		{"x.example", "https://user@x.example", false},
		{"x.example", "https://x.example?q=1", false},
		{"x.example", "ftp://x.example", false},
		{"", "", false},
	} {
		s, err := New(Config{RPID: c.rpid, Origin: c.origin})
		if c.ok {
			require.NoError(t, err, c.origin)
			require.NotNil(t, s)
		} else {
			assert.Error(t, err, "%s %s", c.rpid, c.origin)
		}
	}
	s, err := New(Config{RPID: "x.example", Origin: "https://x.example"})
	require.NoError(t, err)
	assert.Equal(t, "__Host-vsession", s.cfg.CookieName)
	s, err = New(Config{RPID: "localhost", Origin: "http://localhost:8443"})
	require.NoError(t, err)
	assert.Equal(t, "vsession", s.cfg.CookieName)
}

func TestCeremonyStoreIsSingleUseAndExpires(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC))
	cs := newCeremonies(clk, 3)
	id, err := cs.put(ceremony{kind: kindLogin})
	require.NoError(t, err)
	_, ok := cs.take(id, kindRegister)
	assert.False(t, ok, "wrong kind")
	_, ok = cs.take(id, kindLogin)
	assert.False(t, ok, "a wrong-kind take still consumes it")

	id, err = cs.put(ceremony{kind: kindLogin})
	require.NoError(t, err)
	_, ok = cs.take(id, kindLogin)
	assert.True(t, ok)
	_, ok = cs.take(id, kindLogin)
	assert.False(t, ok, "single use")

	id, err = cs.put(ceremony{kind: kindLogin})
	require.NoError(t, err)
	clk.Advance(ceremonyTTL + time.Second)
	_, ok = cs.take(id, kindLogin)
	assert.False(t, ok, "expired")

	for range 3 {
		_, err = cs.put(ceremony{kind: kindLogin})
		require.NoError(t, err)
	}
	_, err = cs.put(ceremony{kind: kindLogin})
	assert.ErrorIs(t, err, errBusy, "full")
	clk.Advance(ceremonyTTL + time.Second)
	_, err = cs.put(ceremony{kind: kindLogin})
	assert.NoError(t, err, "expired ones are pruned on insert")
	assert.Len(t, cs.m, 1)
}

func TestUserHandleIsEightBigEndianBytes(t *testing.T) {
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 1, 2}, userHandle(258))
	id, ok := userIDFromHandle([]byte{0, 0, 0, 0, 0, 0, 1, 2})
	assert.True(t, ok)
	assert.Equal(t, int64(258), id)
	_, ok = userIDFromHandle([]byte{1, 2})
	assert.False(t, ok)
}
