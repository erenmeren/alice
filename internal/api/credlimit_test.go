package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
	"alice/internal/setup"
)

// countingAuth wraps identityAuth: it counts every session and token lookup and lets a test
// add or revoke credentials.
type countingAuth struct {
	*fakeAuth
	mu       sync.Mutex
	sessions map[string]auth.Principal
	tokens   map[string]auth.Principal
	lookups  int
}

func newCountingAuth(d *Deps) *countingAuth {
	base := d.Auth.(*fakeAuth)
	c := &countingAuth{fakeAuth: base, sessions: map[string]auth.Principal{}, tokens: map[string]auth.Principal{}}
	for _, id := range []string{"admin", "operator", "auditor", "pending"} {
		p, err := base.AuthenticateFn(context.Background(), id)
		if err == nil {
			c.sessions[id] = p
		}
	}
	for _, id := range []string{"alice_read_admin", "alice_read_auditor"} {
		p, err := base.AuthenticateTokenFn(context.Background(), id)
		if err == nil {
			c.tokens[id] = p
		}
	}
	base.AuthenticateFn = func(_ context.Context, t string) (auth.Principal, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.lookups++
		if p, ok := c.sessions[t]; ok {
			return p, nil
		}
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	base.AuthenticateTokenFn = func(_ context.Context, b string) (auth.Principal, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.lookups++
		if p, ok := c.tokens[b]; ok {
			return p, nil
		}
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	d.Auth = base
	return c
}

func (c *countingAuth) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lookups
}

func (c *countingAuth) revokeSession(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, id)
}

// floodGarbage sends n requests with never-valid session cookies to target and returns the
// status codes seen.
func floodGarbage(h http.Handler, target string, n int, edit func(*http.Request)) map[int]int {
	codes := map[int]int{}
	for i := range n {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: fmt.Sprintf("garbage-%d", i)})
		if edit != nil {
			edit(req)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes[rec.Code]++
	}
	return codes
}

// clearedCookie returns the Set-Cookie of rec that deletes name, or nil.
func clearedCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.MaxAge < 0 {
			return c
		}
	}
	return nil
}

// AUD-16: garbage credentials buy at most one bucket of lookups per address (60, then one a
// second); after that they are refused with the rate-limit answer before any lookup.
func TestCredentialLookupsAreRateLimitedBeforeTheLookup(t *testing.T) {
	d := testDeps(t, nil)
	var mu sync.Mutex
	sessionLookups, setupLookups := 0, 0
	d.Auth.(*fakeAuth).AuthenticateFn = func(context.Context, string) (auth.Principal, error) {
		mu.Lock()
		defer mu.Unlock()
		sessionLookups++
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	d.Setup = &fakeSetup{AuthenticateFn: func(context.Context, string) error {
		mu.Lock()
		defer mu.Unlock()
		setupLookups++
		return setup.ErrSessionInvalid
	}}
	h := NewHandler(d)
	limited, unauthenticated := 0, 0
	for range 500 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "garbage"})
		req.AddCookie(&http.Cookie{Name: setupCookie, Value: "garbage"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusTooManyRequests:
			limited++
			assert.Equal(t, "ALC-SYS-0005", decodeErr(t, rec).Error.Code)
			assert.Equal(t, "1", rec.Header().Get("Retry-After"), "60 a minute: the next token is a second away")
			assert.Empty(t, rec.Result().Cookies(), "nothing was looked up, so nothing is known to be stale")
		case http.StatusUnauthorized:
			unauthenticated++
		}
	}
	assert.Equal(t, 440, limited)
	assert.Equal(t, 60, unauthenticated)
	assert.Equal(t, 60, sessionLookups)
	assert.Equal(t, 60, setupLookups)
}

// The bucket holds under concurrency too: a token is taken before the lookup, not after.
func TestConcurrentGarbageCannotOverrunTheBucket(t *testing.T) {
	d := testDeps(t, nil)
	c := newCountingAuth(&d)
	h := NewHandler(d)
	var wg sync.WaitGroup
	for g := range 20 {
		wg.Go(func() {
			for i := range 25 {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
				req.AddCookie(&http.Cookie{Name: sessionCookie, Value: fmt.Sprintf("g-%d-%d", g, i)})
				h.ServeHTTP(httptest.NewRecorder(), req)
			}
		})
	}
	wg.Wait()
	assert.Equal(t, 60, c.count())
}

// A valid session never spends the failed-credential bucket: 500 requests meet only the
// per-session limit of 300, and garbage afterwards still gets its 60 lookups.
func TestValidSessionsNeverMeetTheFailedCredentialBucket(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Read, limitDefault)
	codes := map[int]int{}
	for range 500 {
		codes[call(h, http.MethodGet, "/api/v1/probe", "admin", "").Code]++
	}
	assert.Equal(t, map[int]int{http.StatusOK: 300, http.StatusTooManyRequests: 200}, codes)
	assert.Equal(t, map[int]int{http.StatusUnauthorized: 60}, floodGarbage(h, "/api/v1/probe", 60, nil))
	assert.Equal(t, map[int]int{http.StatusTooManyRequests: 1}, floodGarbage(h, "/api/v1/probe", 1, nil))
}

// S2: people with a valid session or token behind the blocked address keep working; the
// remembered credential only skips the block, the lookup still decides (a revoked session is
// refused and forgotten); a cookie this server just issued is remembered at once.
func TestRecentlyValidatedCredentialsPassTheBlock(t *testing.T) {
	d := testDeps(t, nil)
	c := newCountingAuth(&d)
	fa := d.Auth.(*fakeAuth)
	fa.LoginFn = func(context.Context, string, string, auth.Meta) (auth.LoginResult, error) {
		c.mu.Lock()
		c.sessions["fresh"] = auth.Principal{Kind: rbac.PendingSession, UserID: c.sessions["operator"].UserID, SessionHash: []byte("fresh")}
		c.mu.Unlock()
		return auth.LoginResult{Status: "mfa_required", SessionToken: "fresh"}, nil
	}
	fa.LogoutFn = func(context.Context, auth.Principal, auth.Meta) error { return nil }
	activity := 0
	fa.RecordActivityFn = func(context.Context, auth.Principal) error { activity++; return nil }
	h := NewHandler(d)

	require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/version", "operator", "").Code)
	require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/version", "admin", "").Code)
	require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/version", "alice_read_admin", "").Code)
	require.Equal(t, map[int]int{http.StatusUnauthorized: 60}, floodGarbage(h, "/api/v1/version", 60, nil))
	before := c.count()
	require.Equal(t, map[int]int{http.StatusTooManyRequests: 5}, floodGarbage(h, "/api/v1/version", 5, nil))
	assert.Equal(t, before, c.count(), "blocked requests cost no lookup")

	for range 10 {
		assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/version", "operator", "").Code, "a recent session passes")
	}
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/version", "alice_read_admin", "").Code, "a recent token passes")
	before = c.count()
	rec := call(h, http.MethodGet, "/api/v1/version", "auditor", "")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "a valid session this process has not seen for 5 minutes waits like garbage")
	assert.Equal(t, before, c.count())
	assert.Zero(t, activity, "a rate-limited request never slides a session")

	// The sign-in page and sign-in stay reachable; the new session cookie is remembered.
	assert.Equal(t, http.StatusOK, do(h, http.MethodGet, "/login", nil).Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/i18n/locales", "", "").Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/setup/status", "", "").Code)
	rec = call(h, http.MethodPost, "/api/v1/auth/login", "", `{"username":"operator","password":"pw"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	enroll := call(h, http.MethodPost, "/api/v1/auth/mfa/enroll", "fresh", "")
	assert.NotEqual(t, http.StatusTooManyRequests, enroll.Code, "the pending session from sign-in passes the block")

	// Revoked: the lookup runs, refuses, clears the cookie and forgets the credential.
	c.revokeSession("operator")
	before = c.count()
	rec = call(h, http.MethodGet, "/api/v1/version", "operator", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "the remembered credential never authenticates by itself")
	assert.Equal(t, before+1, c.count())
	assert.NotNil(t, clearedCookie(rec, sessionCookie))
	assert.Equal(t, http.StatusTooManyRequests, call(h, http.MethodGet, "/api/v1/version", "operator", "").Code, "forgotten after it failed")

	// Signed out: forgotten at once, even though the fake would still resolve it.
	require.Equal(t, http.StatusNoContent, call(h, http.MethodPost, "/api/v1/auth/logout", "admin", "").Code)
	assert.Equal(t, http.StatusTooManyRequests, call(h, http.MethodGet, "/api/v1/version", "admin", "").Code)
}

// Requests without any credential never meet the failed-credential bucket, and failed
// credentials do not drain the anonymous bucket a neighbour's sign-in uses.
func TestAnonymousRequestsAreNotSubjectToTheBlock(t *testing.T) {
	d := testDeps(t, nil)
	newCountingAuth(&d)
	d.Auth.(*fakeAuth).LoginFn = func(context.Context, string, string, auth.Meta) (auth.LoginResult, error) {
		return auth.LoginResult{}, auth.ErrInvalidCredentials
	}
	h := NewHandler(d)
	require.Equal(t, map[int]int{http.StatusUnauthorized: 60}, floodGarbage(h, "/api/v1/version", 60, nil))
	require.Equal(t, map[int]int{http.StatusTooManyRequests: 100}, floodGarbage(h, "/api/v1/version", 100, nil))
	rec := call(h, http.MethodGet, "/api/v1/version", "", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "no credential: no lookup, no block")
	rec = call(h, http.MethodPost, "/api/v1/auth/login", "", `{"username":"x","password":"y"}`)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "sign-in is limited by the login limiter only")
	assert.Equal(t, "ALC-AUTH-0005", decodeErr(t, rec).Error.Code)
}

// API tokens are counted like cookies; a token request carries no cookie, so nothing is cleared.
func TestFailingTokensAreCountedAndClearNoCookie(t *testing.T) {
	d := testDeps(t, nil)
	c := newCountingAuth(&d)
	h := NewHandler(d)
	bearer := func(i int) func(*http.Request) {
		return func(r *http.Request) {
			r.Header.Del("Cookie")
			r.Header.Set("Authorization", fmt.Sprintf("Bearer alice_wrong%d", i))
		}
	}
	for i := range 60 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
		bearer(i)(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Empty(t, rec.Result().Cookies())
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	bearer(99)(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, 60, c.count())
}

// The bucket is keyed by the same client address as the other limiters: a trusted proxy's
// forwarded address separates clients; without trusted proxies a spoofed header changes nothing;
// IPv6 clients of one /64 share a bucket.
func TestFailedCredentialBucketUsesTheClientAddress(t *testing.T) {
	xff := func(addr string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("X-Forwarded-For", addr) }
	}
	d := testDeps(t, nil)
	newCountingAuth(&d)
	h := NewHandler(d)
	codes := map[int]int{}
	for i := range 61 {
		for code, n := range floodGarbage(h, "/api/v1/version", 1, xff(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}).String())) {
			codes[code] += n
		}
	}
	assert.Equal(t, map[int]int{http.StatusUnauthorized: 60, http.StatusTooManyRequests: 1}, codes, "spoofed X-Forwarded-For is ignored")

	d = testDeps(t, nil)
	newCountingAuth(&d)
	d.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")} // httptest's RemoteAddr is 192.0.2.1
	h = NewHandler(d)
	require.Equal(t, map[int]int{http.StatusUnauthorized: 60, http.StatusTooManyRequests: 1}, floodGarbage(h, "/api/v1/version", 61, xff("203.0.113.7")))
	assert.Equal(t, map[int]int{http.StatusUnauthorized: 1}, floodGarbage(h, "/api/v1/version", 1, xff("203.0.113.8")), "another client behind the proxy")

	d = testDeps(t, nil)
	newCountingAuth(&d)
	h = NewHandler(d)
	v6 := func(addr string) func(*http.Request) {
		return func(r *http.Request) { r.RemoteAddr = "[" + addr + "]:5555" }
	}
	require.Equal(t, map[int]int{http.StatusUnauthorized: 60}, floodGarbage(h, "/api/v1/version", 60, v6("2001:db8:0:1::1")))
	assert.Equal(t, map[int]int{http.StatusTooManyRequests: 1}, floodGarbage(h, "/api/v1/version", 1, v6("2001:db8:0:1:ffff::9")), "same /64")
	assert.Equal(t, map[int]int{http.StatusUnauthorized: 1}, floodGarbage(h, "/api/v1/version", 1, v6("2001:db8:0:2::1")), "another /64")
}

// A session or setup cookie whose lookup failed is deleted with the attributes it was set with,
// so the browser stops sending it; a cookie that resolved is never deleted.
func TestStaleCookiesAreClearedOn401(t *testing.T) {
	d := testDeps(t, nil)
	h := NewHandler(d)

	rec := call(h, http.MethodGet, "/api/v1/version", "expired", "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	c := clearedCookie(rec, sessionCookie)
	require.NotNil(t, c)
	assert.Empty(t, c.Value)
	assert.Equal(t, "/", c.Path)
	assert.True(t, c.Secure)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
	assert.Nil(t, clearedCookie(rec, setupCookie), "no setup cookie was sent")

	rec = call(h, http.MethodGet, "/api/v1/version", "pending", "")
	require.Equal(t, http.StatusUnauthorized, rec.Code, "a pending session is not signed in")
	assert.Empty(t, rec.Result().Cookies(), "but its cookie is valid and stays (the MFA step needs it)")

	req := as(httptest.NewRequest(http.MethodPut, "/api/v1/setup/language", strings.NewReader(`{"language":"en"}`)), "")
	req.AddCookie(&http.Cookie{Name: setupCookie, Value: "setup-stale"})
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "ALC-SET-0003", decodeErr(t, rec).Error.Code)
	assert.NotNil(t, clearedCookie(rec, setupCookie))

	req = as(httptest.NewRequest(http.MethodGet, "/api/v1/version", nil), "stale")
	req.AddCookie(&http.Cookie{Name: setupCookie, Value: "setup-ok"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.NotNil(t, clearedCookie(rec, sessionCookie), "the stale session cookie goes")
	assert.Nil(t, clearedCookie(rec, setupCookie), "the valid setup cookie stays")
}

// AUD-16: /healthz on the public listener has the anonymous per-address limit; the internal
// health listener (container healthcheck, orchestrators) and /livez stay unlimited.
func TestHealthzLimitedOnlyOnThePublicListener(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	for i := range 60 {
		require.Equal(t, http.StatusOK, do(h, http.MethodGet, "/healthz", nil).Code, "request %d", i+1)
	}
	rec := do(h, http.MethodGet, "/healthz", nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusOK, do(h, http.MethodGet, "/livez", nil).Code)

	internal := NewHealthHandler(testDeps(t, nil))
	for range 200 {
		require.Equal(t, http.StatusOK, do(internal, http.MethodGet, "/healthz", nil).Code)
		require.Equal(t, http.StatusOK, do(internal, http.MethodGet, "/livez", nil).Code)
	}
}

func TestResetLimitsClearsTheFailedCredentialBucket(t *testing.T) {
	d := testDeps(t, nil)
	newCountingAuth(&d)
	srv := New(d)
	h := srv.Handler()
	require.Equal(t, map[int]int{http.StatusUnauthorized: 60, http.StatusTooManyRequests: 1}, floodGarbage(h, "/api/v1/version", 61, nil))
	srv.ResetLimits()
	assert.Equal(t, map[int]int{http.StatusUnauthorized: 1}, floodGarbage(h, "/api/v1/version", 1, nil))
}
