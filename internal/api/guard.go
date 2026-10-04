package api

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/ratelimit"
	"alice/internal/license"
	"alice/internal/rbac"
	"alice/internal/setup"
)

type principalKey struct{}

// principalFrom returns the authenticated principal stored by guard. For
// public routes it is the zero Principal (Kind rbac.Anonymous).
func principalFrom(ctx context.Context) auth.Principal {
	p, _ := ctx.Value(principalKey{}).(auth.Principal)
	return p
}

// guard wraps a route handler with, in order: the query text check (AUD-13), the failed-credential
// limit and authentication (AUD-16; only for routes that are not public), rate limiting,
// the same-origin check, the CSRF check, recording a person's activity on the
// session (AUD-01), the permission decision (SEC-016, SEC-017, SEC-021,
// SEC-024) and the license lock gate (R9). Nothing reaches rt.handler unless
// rbac allows it and, for ClassChange/ClassReadOnly routes, license.Service.Allow does.
func (s *server) guard(rt route) http.HandlerFunc {
	policy, _ := rbac.PolicyFor(rt.perm) // register has checked the permission exists
	return func(w http.ResponseWriter, r *http.Request) {
		if s.refuseUnstorableQuery(w, r) {
			return // AUD-13: query text PostgreSQL cannot store; nothing was looked up or counted
		}
		ipKey := ratelimit.IPKey(clientIP(r, s.deps.TrustedProxies))
		var a authResult
		if !policy.Anonymous {
			var ok bool
			if a, ok = s.authenticateLimited(w, r, ipKey); !ok {
				return
			}
		}
		p, csrfToken := a.p, a.csrf
		if !s.allowRate(w, r, rt.limit, p, ipKey, a.failedCharged) {
			return
		}
		if !safeMethod(r.Method) && !hasBearer(r) {
			if !SameOrigin(r) {
				s.writeError(w, r, ErrCSRF)
				return
			}
			if !policy.Anonymous && csrfToken != "" && !s.deps.Auth.CheckCSRF(csrfToken, r.Header.Get("X-CSRF-Token")) {
				s.writeError(w, r, ErrCSRF)
				return
			}
		}
		if p.Kind == rbac.UserSession && isActivity(r) {
			if err := s.deps.Auth.RecordActivity(r.Context(), p); err != nil {
				s.authUnavailable(w, r, &authError{reason: "session_touch_failed", err: err})
				return
			}
		}
		switch rbac.Decide(rt.perm, p.Subject(s.deps.Clock.Now())) {
		case rbac.Allow:
			if gated(rt.lic) {
				if err := s.licenseGate(rt.lic); err != nil {
					s.auditLicenseDenied(r, rt, p, err)
					s.writeError(w, r, licenseRefusal(err))
					return
				}
			}
			rt.handler(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
		case rbac.DenyUnauthenticated:
			a.clearStaleCookies(w)
			if policy.Setup {
				s.writeError(w, r, ErrSetupSessionExpired)
				return
			}
			s.writeError(w, r, ErrUnauthenticated)
		case rbac.DenyStepUp:
			s.auditDenied(r, rt, p, "stepup")
			s.writeError(w, r, ErrStepUpRequired)
		default:
			s.auditDenied(r, rt, p, "permission")
			s.writeError(w, r, ErrForbidden)
		}
	}
}

// authError is a failure of an authentication backend (not an invalid
// credential). reason is a fixed label that is safe to log.
type authError struct {
	reason string
	err    error
}

func (e *authError) Error() string { return e.reason + ": " + e.err.Error() }
func (e *authError) Unwrap() error { return e.err }

// authResult is what authenticate learned about the caller.
type authResult struct {
	p          auth.Principal
	csrf       string          // the cookie value the CSRF token is bound to ("" for API tokens and anonymous callers)
	credential string          // the credential that resolved to p ("" when none did)
	failed     []presentedCred // credentials whose lookup said unknown, expired or revoked
	// failedCharged: the request's credentials failed and it was charged to the failed-credential
	// bucket, which stands in for the anonymous per-address limit (AUD-16).
	failedCharged bool
}

// presentedCred is a credential a request carries: a cookie (cookie names it) or a bearer token.
type presentedCred struct {
	cookie string // sessionCookie, setupCookie, or "" for a bearer token
	value  string
}

// clearStaleCookies deletes, with the attributes they were set with, the cookies whose lookup
// failed, so a browser stops sending a dead session (AUD-16). A cookie that resolved is kept:
// a pending session refused by a route that needs a signed-in user still needs it for MFA.
func (a authResult) clearStaleCookies(w http.ResponseWriter) {
	for _, c := range a.failed {
		if c.cookie != "" {
			setCookie(w, c.cookie, "", -1)
		}
	}
}

// presentedCredentials lists the credentials authenticate will look up, in its order: a bearer
// token alone (cookies are then not consulted), otherwise the session and the setup cookie.
func presentedCredentials(r *http.Request) []presentedCred {
	if hasBearer(r) {
		return []presentedCred{{value: bearerFrom(r)}}
	}
	var out []presentedCred
	if tok := sessionTokenFrom(r); tok != "" {
		out = append(out, presentedCred{cookie: sessionCookie, value: tok})
	}
	if tok := setupTokenFrom(r); tok != "" {
		out = append(out, presentedCred{cookie: setupCookie, value: tok})
	}
	return out
}

// authenticateLimited is authenticate behind the per-address limit on failing credentials
// (AUD-16). A request without any credential is never limited here. A request whose credential
// this process validated or issued in the last few minutes (s.recent) is not limited either; that
// only skips the limit, as authenticate still looks the credential up and alone decides who the
// caller is. Any other request with a credential takes a token from s.badCreds before the lookup,
// so no more than the bucket allows reaches the database even under concurrency; the token is
// given back when the credential resolves, so only failures count. It writes the 429 or 503
// itself and returns false then.
func (s *server) authenticateLimited(w http.ResponseWriter, r *http.Request, ipKey string) (authResult, bool) {
	creds := presentedCredentials(r)
	reserved := false
	if len(creds) > 0 && !s.anyRecent(creds) {
		ok, retry := s.badCreds.Allow(ipKey)
		if !ok {
			s.writeRateLimited(w, r, retry)
			return authResult{}, false
		}
		reserved = true
	}
	a, err := s.authenticate(r)
	if err != nil {
		if reserved {
			s.badCreds.Refund(ipKey) // the backend failed, not the credential
		}
		s.authUnavailable(w, r, err)
		return authResult{}, false
	}
	for _, c := range a.failed {
		s.recent.Remove(c.value)
	}
	if a.p.Kind != rbac.Anonymous {
		s.recent.Add(a.credential)
		if reserved {
			s.badCreds.Refund(ipKey)
		}
		return a, true
	}
	if len(a.failed) > 0 {
		if !reserved {
			s.badCreds.Allow(ipKey) // a remembered credential failed: it counts like any other
		}
		a.failedCharged = true
	}
	return a, true
}

func (s *server) anyRecent(creds []presentedCred) bool {
	for _, c := range creds {
		if s.recent.Contains(c.value) {
			return true
		}
	}
	return false
}

// authenticate resolves the caller: the principal, the cookie value the CSRF token must be bound
// to, the credential that resolved and the ones that failed. Invalid credentials simply leave the
// caller anonymous; any other backend failure is returned as an *authError.
func (s *server) authenticate(r *http.Request) (authResult, error) {
	ctx := r.Context()
	var a authResult
	if hasBearer(r) {
		bearer := bearerFrom(r)
		p, err := s.deps.Auth.AuthenticateToken(ctx, bearer)
		switch {
		case err == nil:
			return authResult{p: p, credential: bearer}, nil
		case errors.Is(err, auth.ErrUnauthenticated):
			a.failed = append(a.failed, presentedCred{value: bearer})
			return a, nil
		default:
			return authResult{}, &authError{reason: "token_lookup_failed", err: err}
		}
	}
	if tok := sessionTokenFrom(r); tok != "" {
		// Never slides the idle timeout: guard records activity only after the request passed
		// the rate limit and the origin and CSRF checks.
		p, err := s.deps.Auth.AuthenticatePassive(ctx, tok)
		switch {
		case err == nil:
			return authResult{p: p, csrf: tok, credential: tok}, nil
		case !errors.Is(err, auth.ErrUnauthenticated):
			return authResult{}, &authError{reason: "session_lookup_failed", err: err}
		}
		a.failed = append(a.failed, presentedCred{cookie: sessionCookie, value: tok})
	}
	if tok := setupTokenFrom(r); tok != "" {
		err := s.deps.Setup.Authenticate(ctx, tok)
		switch {
		case err == nil:
			a.p, a.csrf, a.credential = auth.Principal{Kind: rbac.SetupSession}, tok, tok
			return a, nil
		case !errors.Is(err, setup.ErrSessionInvalid):
			return authResult{}, &authError{reason: "setup_session_lookup_failed", err: err}
		}
		a.failed = append(a.failed, presentedCred{cookie: setupCookie, value: tok})
	}
	return a, nil
}

// authUnavailable answers a failed authentication backend with a retryable
// 503. Only a fixed reason label is logged: driver text may carry connection
// details. A cancelled request gets no answer, as nobody is waiting for it.
func (s *server) authUnavailable(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	reason := "unknown"
	var ae *authError
	if errors.As(err, &ae) {
		reason = ae.reason
	}
	s.deps.Log.Error("authentication failed", "request_id", RequestID(r.Context()), "reason", reason)
	w.Header().Set("Retry-After", "1")
	s.writeError(w, r, ErrUnavailable)
}

// allowRate applies the route's specific limit and then the general limit.
// ipKey is ratelimit.IPKey of the client address (IPv6 grouped by /64). A request whose
// credentials failed was charged to the failed-credential bucket already (failedCharged), which
// replaces the anonymous limit for it: a neighbour's garbage never drains the bucket that the
// sign-in of others behind the same address uses (AUD-16).
// It writes the 429 response itself and returns false when the caller is over a limit.
func (s *server) allowRate(w http.ResponseWriter, r *http.Request, class limitClass, p auth.Principal, ipKey string, failedCharged bool) bool {
	if class == limitNone {
		return true
	}
	checks := make([]func() (bool, time.Duration), 0, 2)
	switch class {
	case limitLogin:
		checks = append(checks, func() (bool, time.Duration) { return s.login.Allow(ipKey) })
	case limitMFA:
		checks = append(checks, func() (bool, time.Duration) { return s.mfa.Allow(ipKey) })
	}
	switch p.Kind {
	case rbac.UserSession, rbac.PendingSession:
		key := "s:" + hex.EncodeToString(p.SessionHash)
		checks = append(checks, func() (bool, time.Duration) { return s.general.Allow(key) })
	case rbac.APIToken:
		key := "t:" + p.TokenID.String()
		checks = append(checks, func() (bool, time.Duration) { return s.general.Allow(key) })
	default:
		if !failedCharged {
			checks = append(checks, func() (bool, time.Duration) { return s.anon.Allow(ipKey) })
		}
	}
	for _, check := range checks {
		if ok, retry := check(); !ok {
			s.writeRateLimited(w, r, retry)
			return false
		}
	}
	return true
}

// writeRateLimited answers 429 with Retry-After in whole seconds.
func (s *server) writeRateLimited(w http.ResponseWriter, r *http.Request, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retry.Round(time.Second)/time.Second)))
	s.writeError(w, r, ErrRateLimited)
}

// auditDenied records an authorization failure of an authenticated user or
// token (spec §25.1). Failures to write are logged, never shown to the caller.
func (s *server) auditDenied(r *http.Request, rt route, p auth.Principal, reason string) {
	if p.Kind != rbac.UserSession && p.Kind != rbac.APIToken {
		return
	}
	ev := audit.Event{
		Actor:  p.Actor(s.meta(r)),
		Action: "authz.denied",
		Result: audit.Denied,
		Details: map[string]string{
			"permission": string(rt.perm),
			"method":     rt.method,
			"path":       rt.pattern,
			"reason":     reason,
		},
	}
	if err := s.deps.Audit.Write(r.Context(), ev); err != nil {
		s.deps.Log.Error("audit write failed", append([]any{"request_id", RequestID(r.Context()), "action", ev.Action}, errorAttrs(err)...)...)
	}
}

// licenseGate asks the single lock gate (license.Service.Allow). Without a license service the
// answer is no: a misconfigured server fails closed.
func (s *server) licenseGate(c license.Class) error {
	if s.deps.License == nil {
		return license.ErrLocked
	}
	return s.deps.License.Allow(c)
}

// licenseRefusal is the answer to a refusal of the gate: the license could not be verified
// recently (AUD-02, 503 and retryable) or it is locked. Any other refusal (a class the gate does
// not know) is answered as locked: the request is refused either way.
func licenseRefusal(err error) ErrorCode {
	if errors.Is(err, license.ErrUnverified) {
		return ErrLicenseUnverified
	}
	return ErrLicenseLocked
}

// licenseDenialReason is the audit label of a gate refusal: locked, lock_due or unverified.
func licenseDenialReason(err error) string {
	if reason := license.DenialReason(err); reason != "" {
		return reason
	}
	return "locked"
}

// gated reports whether lock mode refuses work of class c: changes to managed systems and
// recurring read-only work on them (R9, §8.6). The guard and the route-table tests share this
// one definition, so a new class cannot be gated in one place and not in the other.
func gated(c license.Class) bool { return c == license.ClassChange || c == license.ClassReadOnly }

// auditLicenseDenied records a request refused by the license gate (L-26): reason "locked",
// "lock_due" (the gate's own clock reached the lock time; no evaluation confirmed it yet) or
// "unverified" (the license could not be checked recently) (AUD-02).
func (s *server) auditLicenseDenied(r *http.Request, rt route, p auth.Principal, cause error) {
	if p.Kind != rbac.UserSession && p.Kind != rbac.APIToken {
		return
	}
	ev := audit.Event{
		Actor:   p.Actor(s.meta(r)),
		Action:  "request.denied_license",
		Result:  audit.Denied,
		Details: map[string]string{"method": rt.method, "path": rt.pattern, "class": rt.lic.String(), "reason": licenseDenialReason(cause)},
	}
	if err := s.deps.Audit.Write(r.Context(), ev); err != nil {
		s.deps.Log.Error("audit write failed", append([]any{"request_id", RequestID(r.Context()), "action", ev.Action}, errorAttrs(err)...)...)
	}
}

func safeMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// activityHeader marks a read of the web UI that follows a person's input (AUD-01, R39).
const activityHeader = "X-Alice-Activity"

// isActivity reports whether r is a person's action for a session's idle timeout (SEC-019 as
// changed by R39): a state-changing request, or a read this origin's web UI marked with
// "X-Alice-Activity: 1". Unmarked reads (polls) never extend a session. guard asks only after a
// state-changing request passed the same-origin and CSRF checks; a marked read must come from
// this origin too, so no other site, a sibling subdomain included, can slide a session. The
// marker is client-sent by design: the only party able to forge it is the client being timed
// out, which could keep its session alive by acting anyway.
func isActivity(r *http.Request) bool {
	if !safeMethod(r.Method) {
		return true
	}
	return r.Header.Get(activityHeader) == "1" && SameOrigin(r)
}

func hasBearer(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// bearerFrom returns the bearer token of r (hasBearer must hold).
func bearerFrom(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

// SameOrigin reports whether a state-changing request may come from this site: it
// rejects cross-site requests (defence in depth next to SameSite=Strict cookies and
// the CSRF token). The e2e build's /test endpoints apply it too.
func SameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	return origin == "" || origin == "https://"+r.Host
}
