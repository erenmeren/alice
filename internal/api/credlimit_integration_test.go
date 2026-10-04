//go:build integration

package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AUD-16 with the real auth service and PostgreSQL: a flood of unknown session cookies from one
// address is cut off after 60 lookups, while the people behind that address who hold a valid
// session or token keep working; a stale cookie is deleted; a signed-out cookie is forgotten.
func TestFailedCredentialLimitWithRealSessions(t *testing.T) {
	s, adminBrowser, admin := installed(t)
	const shared = "198.51.100.77"

	token, _ := createToken(t, s, adminBrowser, admin, "read", 1)
	api := s.client(shared)
	api.bearer = token
	requireStatus(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusOK)

	person := s.client(shared)
	s.signIn(person, admin)
	requireStatus(t, person.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	attacker := s.client(shared)
	for i := range 60 {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		attacker.cookies[sessionCookie] = base64.RawURLEncoding.EncodeToString(b) // well-formed, unknown
		rec := attacker.do(http.MethodGet, "/api/v1/version", nil)
		requireError(t, rec, http.StatusUnauthorized, "ALC-AUTH-0001")
		assert.NotContains(t, attacker.cookies, sessionCookie, "request %d: the dead cookie was deleted", i+1)
	}
	attacker.cookies[sessionCookie] = "another-unknown-session-cookie-value-000000"
	rec := attacker.do(http.MethodGet, "/api/v1/version", nil)
	requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))

	for range 5 {
		requireStatus(t, person.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
		requireStatus(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusOK)
	}
	// Sign-in from the blocked address still works (it is limited by the login limiter only).
	other := s.client(shared)
	s.signIn(other, admin)
	requireStatus(t, other.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	// signIn moved the clock 31 s (half the bucket refilled): block the address again.
	for i := 0; ; i++ {
		require.Less(t, i, 61)
		attacker.cookies[sessionCookie] = "refill-unknown-session-cookie-value-" + string(rune('a'+i%26))
		if attacker.do(http.MethodGet, "/api/v1/version", nil).Code == http.StatusTooManyRequests {
			break
		}
	}
	requireStatus(t, person.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	// Signed out: the old cookie is forgotten, so from the blocked address it waits like garbage.
	old := person.cookies[sessionCookie]
	requireStatus(t, person.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)
	replay := s.client(shared)
	replay.cookies[sessionCookie] = old
	requireError(t, replay.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusTooManyRequests, "ALC-SYS-0005")
	// From elsewhere it is looked up and refused as before.
	elsewhere := s.client("198.51.100.78")
	elsewhere.cookies[sessionCookie] = old
	requireError(t, elsewhere.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")

	// Tokens refill: a minute later the address gets lookups again.
	s.clock.Advance(time.Minute)
	attacker.cookies[sessionCookie] = "yet-another-unknown-session-cookie-value-00"
	requireError(t, attacker.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
}

// A session that ended by idling out is deleted from the browser on its next 401, so the browser
// stops sending it (and stops spending the failed-credential bucket).
func TestIdleExpiredSessionCookieIsDeleted(t *testing.T) {
	s, _, admin := installed(t)
	c := s.client("198.51.100.79")
	s.signIn(c, admin)
	require.Contains(t, c.cookies, sessionCookie)
	s.clock.Advance(31 * time.Minute)
	rec := c.do(http.MethodGet, "/api/v1/auth/session", nil)
	requireError(t, rec, http.StatusUnauthorized, "ALC-AUTH-0001")
	var cleared *http.Cookie
	for _, ck := range responseCookies(rec) {
		if ck.Name == sessionCookie {
			cleared = ck
		}
	}
	require.NotNil(t, cleared)
	assert.Negative(t, cleared.MaxAge)
	assert.Equal(t, "/", cleared.Path)
	assert.True(t, cleared.Secure && cleared.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, cleared.SameSite)
	assert.NotContains(t, c.cookies, sessionCookie)
}
