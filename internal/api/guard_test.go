package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/rbac"
)

// guardedHandler serves one test route with the given permission and limit;
// the handler echoes the principal's username.
func guardedHandler(t *testing.T, d Deps, perm rbac.Permission, limit limitClass) (http.Handler, *server) {
	t.Helper()
	s := newServer(d)
	h := s.handler([]route{
		{method: http.MethodGet, pattern: "/api/v1/probe", perm: perm, limit: limit, handler: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"user": principalFrom(r.Context()).Username})
		}},
		{method: http.MethodPost, pattern: "/api/v1/probe", perm: perm, limit: limit, lic: license.ClassAlways, handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}},
	})
	return h, s
}

func TestGuardPassesPrincipalToHandler(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Session, limitDefault)
	rec := call(h, http.MethodGet, "/api/v1/probe", "operator", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"user":"operator"}`, rec.Body.String())
}

func TestStateChangeWithoutCSRFTokenIsRejected(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Session, limitDefault)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/probe", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "admin"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "ALC-AUTH-0004", decodeErr(t, rec).Error.Code)

	req.Header.Set("X-CSRF-Token", "csrf-somebody-else")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "a token bound to another session is rejected")

	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, "/api/v1/probe", "admin", "").Code)
}

func TestCrossOriginStateChangeIsRejected(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Session, limitDefault)
	for name, set := range map[string]func(*http.Request){
		"foreign origin":      func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"cross-site fetch":    func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"plain http origin":   func(r *http.Request) { r.Header.Set("Origin", "http://"+r.Host) },
		"same-site subdomain": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") },
	} {
		req := as(httptest.NewRequest(http.MethodPost, "/api/v1/probe", nil), "admin")
		set(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, name)
		assert.Equal(t, "ALC-AUTH-0004", decodeErr(t, rec).Error.Code, name)
	}
}

func TestBearerTokensNeedNoCSRFToken(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Read, limitDefault)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/probe", nil)
	req.Header.Set("Authorization", "Bearer alice_read_admin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestTokenIsNeverAcceptedFromACookie(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Read, limitDefault)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/probe", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "alice_read_admin"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestStepUpRequiredIsDistinctAndAudited(t *testing.T) {
	d := testDeps(t, nil)
	h, _ := guardedHandler(t, d, rbac.UsersManage, limitDefault)
	rec := call(h, http.MethodGet, "/api/v1/probe", "admin", "")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code)
	assert.Equal(t, 1, d.Audit.(*fakeAudit).Count("authz.denied"))

	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "admin-stepup", "").Code)
}

func TestSetupPermissionWithoutSessionSaysSetupExpired(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Setup, limitDefault)
	rec := call(h, http.MethodGet, "/api/v1/probe", "", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "ALC-SET-0003", decodeErr(t, rec).Error.Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "setup", "").Code)
}

func TestRateLimitReturns429WithRetryAfter(t *testing.T) {
	d := testDeps(t, nil)
	fake := d.Clock.(*clock.Fake)
	h, srv := guardedHandler(t, d, rbac.Public, limitLogin)
	for i := range 10 {
		require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "", "").Code, "attempt %d", i+1)
	}
	rec := call(h, http.MethodGet, "/api/v1/probe", "", "")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "ALC-SYS-0005", decodeErr(t, rec).Error.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))

	fake.Advance(7 * time.Second)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "", "").Code, "tokens refill over time")

	for range 20 {
		call(h, http.MethodGet, "/api/v1/probe", "", "")
	}
	(&Server{s: srv}).ResetLimits()
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "", "").Code, "ResetLimits clears buckets")
}

func TestGeneralLimitIsPerIdentity(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Session, limitDefault)
	for range 300 {
		require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "admin", "").Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, call(h, http.MethodGet, "/api/v1/probe", "admin", "").Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "operator", "").Code, "another session has its own bucket")
}

func TestProbesAreNeverRateLimited(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	for range 200 {
		require.Equal(t, http.StatusOK, do(h, http.MethodGet, "/livez", nil).Code)
	}
}

func TestForwardedForIsIgnoredWithoutTrustedProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	assert.Equal(t, "192.0.2.10", clientIP(req, nil).String())

	trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	assert.Equal(t, "203.0.113.9", clientIP(req, trusted).String())

	req.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.9, 192.0.2.11")
	assert.Equal(t, "203.0.113.9", clientIP(req, trusted).String(), "right-most untrusted hop wins")

	req.Header.Set("X-Forwarded-For", "not-an-ip")
	assert.Equal(t, "192.0.2.10", clientIP(req, trusted).String())

	req.RemoteAddr = "[::ffff:192.0.2.10]:5555"
	req.Header.Del("X-Forwarded-For")
	assert.Equal(t, "192.0.2.10", clientIP(req, nil).String(), "IPv4-mapped addresses are unmapped")
}

func TestSpoofedForwardedForCannotEvadeLoginLimit(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Public, limitLogin)
	codes := map[int]int{}
	for i := range 15 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/probe", nil)
		req.Header.Set("X-Forwarded-For", netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}).String())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes[rec.Code]++
	}
	assert.Equal(t, 10, codes[http.StatusOK])
	assert.Equal(t, 5, codes[http.StatusTooManyRequests])
}

func TestUnknownPermissionPanicsAtStartup(t *testing.T) {
	s := newServer(testDeps(t, nil))
	assert.Panics(t, func() {
		s.handler([]route{{method: http.MethodGet, pattern: "/api/v1/x", perm: "nobody.knows", handler: func(http.ResponseWriter, *http.Request) {}}})
	})
}

// IPv6 callers are limited per /64 (ratelimit.IPKey), so rotating through the
// addresses of one network does not escape a per-IP limit.
func TestIPv6ClientsInOneSlash64ShareALimit(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Public, limitLogin)
	from := func(addr string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/probe", nil)
		req.RemoteAddr = "[" + addr + "]:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := range 10 {
		require.Equal(t, http.StatusOK, from(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}).String()), "attempt %d", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, from("2001:db8:0:1:ffff::1"), "same /64, new address")
	assert.Equal(t, http.StatusOK, from("2001:db8:0:2::1"), "another /64 has its own bucket")
}

// API tokens get 300 requests per minute each (SEC-021), independent of other tokens.
func TestGeneralLimitIsPerToken(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Read, limitDefault)
	for range 300 {
		require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "alice_read_admin", "").Code)
	}
	rec := call(h, http.MethodGet, "/api/v1/probe", "alice_read_admin", "")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "alice_read_auditor", "").Code, "another token has its own bucket")
}

// A pending (MFA-incomplete) session is never treated as a signed-in user.
func TestPendingSessionIsNotASignedInUser(t *testing.T) {
	for _, perm := range []rbac.Permission{rbac.Session, rbac.Read, rbac.UsersRead} {
		h, _ := guardedHandler(t, testDeps(t, nil), perm, limitDefault)
		rec := call(h, http.MethodGet, "/api/v1/probe", "pending", "")
		assert.Equal(t, http.StatusUnauthorized, rec.Code, perm)
	}
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.MFAPending, limitDefault)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "pending", "").Code)
}

// Several X-Forwarded-For header lines count as one list: a proxy that adds
// its own line must not let a client-supplied first line pick the address.
func TestForwardedForUsesEveryHeaderLine(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Add("X-Forwarded-For", "198.51.100.66")
	req.Header.Add("X-Forwarded-For", " 203.0.113.9 ")
	trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	assert.Equal(t, "203.0.113.9", clientIP(req, trusted).String())
}

// A failing authentication backend is a 503, never an anonymous 401, and is
// neither passed to the handler nor audited as a denial.
func TestAuthenticationBackendErrorIsUnavailable(t *testing.T) {
	down := errors.New("db down: password=s3cret-pw")
	cases := map[string]struct {
		id  string
		set func(d Deps)
	}{
		"session": {"admin", func(d Deps) {
			d.Auth.(*fakeAuth).AuthenticateFn = func(context.Context, string) (auth.Principal, error) { return auth.Principal{}, down }
		}},
		"token": {"alice_read_admin", func(d Deps) {
			d.Auth.(*fakeAuth).AuthenticateTokenFn = func(context.Context, string) (auth.Principal, error) { return auth.Principal{}, down }
		}},
		"setup": {"setup", func(d Deps) {
			d.Setup.(*fakeSetup).AuthenticateFn = func(context.Context, string) error { return down }
		}},
	}
	for name, tc := range cases {
		for _, perm := range []rbac.Permission{rbac.Read, rbac.Setup} {
			d := testDeps(t, nil)
			tc.set(d)
			called := false
			s := newServer(d)
			h := s.handler([]route{{method: http.MethodGet, pattern: "/api/v1/probe", perm: perm, handler: func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}}})
			rec := call(h, http.MethodGet, "/api/v1/probe", tc.id, "")
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "%s on %s", name, perm)
			b := decodeErr(t, rec)
			assert.Equal(t, "ALC-SYS-0002", b.Error.Code, name)
			assert.True(t, b.Error.Retryable, name)
			assert.Equal(t, "1", rec.Header().Get("Retry-After"), name)
			assert.NotContains(t, rec.Body.String(), "s3cret-pw", name)
			assert.False(t, called, name)
			assert.Empty(t, d.Audit.(*fakeAudit).Events(), name)
		}
	}
}

func TestSetupCookieStateChangeWithoutCSRFTokenIsRejected(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Setup, limitDefault)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/probe", nil)
	req.AddCookie(&http.Cookie{Name: setupCookie, Value: "setup-ok"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "ALC-AUTH-0004", decodeErr(t, rec).Error.Code)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, "/api/v1/probe", "setup", "").Code)
}

func TestPublicStateChangeFromForeignOriginIsRejected(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Public, limitDefault)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/probe", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "ALC-AUTH-0004", decodeErr(t, rec).Error.Code)
}

// A request the client abandoned while authenticating gets no answer and no log noise.
func TestCancelledAuthenticationWritesNothing(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).AuthenticateFn = func(context.Context, string) (auth.Principal, error) {
		return auth.Principal{}, context.Canceled
	}
	h, _ := guardedHandler(t, d, rbac.Session, limitDefault)
	rec := call(h, http.MethodGet, "/api/v1/probe", "admin", "")
	assert.Empty(t, rec.Body.String())
	assert.Empty(t, rec.Header().Get("Content-Type"))
}

func gatedHandler(d Deps, class license.Class) http.Handler {
	s := newServer(d)
	return s.handler([]route{{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.Session, lic: class,
		handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }}})
}

// R9, §9.6: while locked, infrastructure changes are refused with license.locked, audited,
// and never reach the handler; after a renewal they work at once.
func TestLicenseGateRefusesChangesWhileLocked(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	fa := d.Audit.(*fakeAudit)
	h := gatedHandler(d, license.ClassChange)

	fl.set(license.ErrLocked)
	rec := call(h, http.MethodPost, "/api/v1/targets", "admin", `{}`)
	require.Equal(t, http.StatusForbidden, rec.Code)
	body := decodeErr(t, rec)
	assert.Equal(t, "ALC-LIC-0001", body.Error.Code)
	assert.Equal(t, "license.locked", body.Error.Reason)
	assert.Equal(t, 1, fa.Count("request.denied_license"))

	fl.set(nil)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, "/api/v1/targets", "admin", `{}`).Code)
}

func TestLicenseGateOrderAndScope(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	fl.set(license.ErrLocked)

	before := fl.count()
	assert.Equal(t, http.StatusUnauthorized, call(gatedHandler(d, license.ClassChange), http.MethodPost, "/api/v1/targets", "", `{}`).Code,
		"authentication and authorization come first")
	assert.Equal(t, before, fl.count(), "the gate is not consulted for a request that is not allowed anyway")

	assert.Equal(t, http.StatusNoContent, call(gatedHandler(d, license.ClassAlways), http.MethodPost, "/api/v1/targets", "admin", `{}`).Code,
		"ClassAlways routes work in lock")
	assert.Equal(t, before, fl.count(), "and do not consult the gate")

	d.License = nil
	assert.Equal(t, http.StatusForbidden, call(gatedHandler(d, license.ClassChange), http.MethodPost, "/api/v1/targets", "admin", `{}`).Code,
		"no license service: fail closed")
}

// The refusal is audited with the operation and its class, so an administrator can see
// what lock mode stopped (L-26).
func TestLicenseDenialAuditDetails(t *testing.T) {
	d := testDeps(t, nil)
	d.License.(*fakeLicense).set(license.ErrLocked)
	fa := d.Audit.(*fakeAudit)
	call(gatedHandler(d, license.ClassChange), http.MethodPost, "/api/v1/targets", "admin", `{}`)
	var got []audit.Event
	for _, ev := range fa.Events() {
		if ev.Action == "request.denied_license" {
			got = append(got, ev)
		}
	}
	require.Len(t, got, 1)
	assert.Equal(t, audit.Denied, got[0].Result)
	assert.Equal(t, audit.ActorUser, got[0].Actor.Type)
	assert.Equal(t, map[string]string{"method": "POST", "path": "/api/v1/targets", "class": "change"}, got[0].Details)
}

// Default deny (SEC-016): a state-changing route without a license class never starts,
// like a route with an unknown permission.
func TestRegisterRefusesUnclassifiedStateChangingRoute(t *testing.T) {
	s := newServer(testDeps(t, nil))
	noop := func(http.ResponseWriter, *http.Request) {}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		assert.Panics(t, func() {
			s.handler([]route{{method: m, pattern: "/api/v1/x", perm: rbac.Session, handler: noop}})
		}, m)
	}
	assert.NotPanics(t, func() {
		s.handler([]route{{method: http.MethodGet, pattern: "/api/v1/x", perm: rbac.Session, handler: noop}})
	}, "reads need no class")
}

// gated is the single definition of "refused while the license is locked" (R9, §8.6):
// changes to managed systems and recurring read-only work on them.
func TestGatedClasses(t *testing.T) {
	assert.True(t, gated(license.ClassChange))
	assert.True(t, gated(license.ClassReadOnly))
	assert.False(t, gated(license.ClassAlways))
	assert.False(t, gated(license.ClassUnset))
}

// Read-only work on managed systems (discovery, a connection test) is refused in lock exactly
// like a change, audited with its class, and works again after a renewal.
func TestLicenseGateRefusesReadOnlyWorkWhileLocked(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	fa := d.Audit.(*fakeAudit)
	h := gatedHandler(d, license.ClassReadOnly)

	fl.set(license.ErrLocked)
	rec := call(h, http.MethodPost, "/api/v1/targets", "admin", `{}`)
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "license.locked", decodeErr(t, rec).Error.Reason)
	var classes []string
	for _, ev := range fa.Events() {
		if ev.Action == "request.denied_license" {
			classes = append(classes, ev.Details["class"])
		}
	}
	assert.Equal(t, []string{"read_only"}, classes)

	fl.set(nil)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, "/api/v1/targets", "admin", `{}`).Code)
}
