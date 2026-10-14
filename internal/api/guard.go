package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

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
		if rt.getOnly && r.Method == http.MethodHead {
			w.Header().Set("Allow", http.MethodGet)
			s.writeError(w, r, ErrMethodNotAllowed)
			return
		}
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
			s.clearStaleCookies(w, a)
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

// clearStaleCookies deletes, with the attributes they were set with, the cookies of a whose lookup
// failed, so a browser stops sending a dead session (AUD-16). A cookie that resolved is kept:
// a pending session refused by a route that needs a signed-in user still needs it for MFA. A
// session cookie that a rotation replaced within the last minute (s.rotated) is kept too: the
// answer to a request sent just before the rotation may arrive after the new cookie, and
// deleting by name would then delete the new one; that request still gets its 401.
func (s *server) clearStaleCookies(w http.ResponseWriter, a authResult) {
	for _, c := range a.failed {
		if c.cookie == "" || (c.cookie == sessionCookie && s.rotated.Contains(c.value)) {
			continue
		}
		setCookie(w, c.cookie, "", -1)
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
// (AUD-16). A request without any credential is never limited here. A request whose first looked-up
// credential this process validated or issued within the session idle timeout (s.recent) is not
// limited either; that only skips the limit, as authenticate still looks the credential up and
// alone decides who the caller is. Any other request with a credential takes a token from
// s.badCreds before the lookup, so no more than the bucket allows reaches the database even under
// concurrency. The token is given back only when the lookup completed and no presented
// credential failed: a lookup that ends in an error (the client went away, the database failed)
// keeps it, so aborted requests cannot buy unlimited lookups. It writes the 429 or 503 itself and
// returns false then.
func (s *server) authenticateLimited(w http.ResponseWriter, r *http.Request, ipKey string) (authResult, bool) {
	creds := presentedCredentials(r)
	reserved := false
	// Only the first credential decides: authenticate looks them up in order, so a remembered
	// second credential must not shield a garbage first one.
	if len(creds) > 0 && !s.recent.Contains(creds[0].value) {
		ok, retry := s.badCreds.Allow(ipKey)
		if !ok {
			s.writeRateLimited(w, r, retry)
			return authResult{}, false
		}
		reserved = true
	}
	a, err := s.authenticate(r)
	if err != nil {
		s.authUnavailable(w, r, err) // the token stays spent
		return authResult{}, false
	}
	for _, c := range a.failed {
		s.recent.Remove(c.value)
	}
	if a.p.Kind != rbac.Anonymous {
		s.recent.Add(a.credential)
	}
	switch {
	case len(a.failed) == 0:
		if reserved {
			s.badCreds.Refund(ipKey)
		}
	case !reserved:
		s.badCreds.Allow(ipKey) // a remembered credential failed: it counts like any other
	}
	a.failedCharged = len(a.failed) > 0 && a.p.Kind == rbac.Anonymous
	return a, true
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
	switch class {
	case limitNone:
		return true
	case limitHealth: // its own per-address bucket: probes never make sign-in wait
		if ok, retry := s.healthz.Allow(ipKey); !ok {
			s.writeRateLimited(w, r, retry)
			return false
		}
		return true
	}
	checks := make([]func() (bool, time.Duration), 0, 2)
	switch class {
	case limitLogin:
		checks = append(checks, func() (bool, time.Duration) { return s.login.Allow(ipKey) })
	case limitMFA:
		checks = append(checks, func() (bool, time.Duration) { return s.mfa.Allow(ipKey) })
	case limitDownload:
		// Per user, and only for a signed-in browser session: the one kind the permission can allow (R41 row 5). A
		// token, a pending sign-in or an anonymous call is refused by the permission check and spends nothing, so
		// none of them can keep an Administrator from downloading (review M1).
		if p.Kind == rbac.UserSession && p.UserID != uuid.Nil {
			key := "u:" + p.UserID.String()
			checks = append(checks, func() (bool, time.Duration) { return s.download.Allow(key) })
		}
	case limitBackupNow, limitHTTPSUpload, limitForwardTest:
		// Per user of a browser session, as the download (the permissions allow nothing else), each in its own bucket.
		if p.Kind == rbac.UserSession && p.UserID != uuid.Nil {
			key, l := "u:"+p.UserID.String(), s.actions[class]
			checks = append(checks, func() (bool, time.Duration) { return l.Allow(key) })
		}
	case limitTestMail:
		// Per user of a browser session, as the download: the permission (settings.manage) allows nothing else.
		if p.Kind == rbac.UserSession && p.UserID != uuid.Nil {
			key := "u:" + p.UserID.String()
			checks = append(checks, func() (bool, time.Duration) { return s.testMails.Allow(key) })
		}
	case limitExport:
		// Per user for a browser session, per token for a token: each identity has its own 10 a minute.
		var key string
		switch {
		case p.Kind == rbac.UserSession && p.UserID != uuid.Nil:
			key = "u:" + p.UserID.String()
		case p.Kind == rbac.APIToken:
			key = "t:" + p.TokenID.String()
		}
		if key != "" {
			checks = append(checks, func() (bool, time.Duration) { return s.export.Allow(key) })
		}
	case limitACME, limitDiscovery, limitDiscoveryResolve:
		// Per user for a browser session, per token for a token, as limitExport (A5): each identity has its own budget
		// in the class's own bucket (ACME and discovery start/cancel 10 a minute, the name resolution check 30).
		var key string
		switch {
		case p.Kind == rbac.UserSession && p.UserID != uuid.Nil:
			key = "u:" + p.UserID.String()
		case p.Kind == rbac.APIToken:
			key = "t:" + p.TokenID.String()
		}
		if key != "" {
			l := s.actions[class]
			checks = append(checks, func() (bool, time.Duration) { return l.Allow(key) })
		}
	case limitOIDCCallback:
		// Per binding cookie (S-11): one browser's retries stop at 10 a minute. The anonymous per-address bucket below
		// (60 a minute) still applies, so fresh cookies cannot buy unlimited callbacks (Task 15 review I-1); it is not
		// the sign-in form's 10 a minute, so the browsers behind one company address still finish their sign-ins.
		if c, err := r.Cookie(oidcCookie); err == nil && c.Value != "" {
			sum := sha256.Sum256([]byte(c.Value))
			key := "b:" + hex.EncodeToString(sum[:])
			checks = append(checks, func() (bool, time.Duration) { return s.oidcCallbacks.Allow(key) })
		}
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

// auditDenied records an authorization failure of an authenticated user or token (spec §25.1,
// SEC-070 as changed by R39): once per subject, permission, reason and route per denialWindow, the
// left-out repeats counted in a later summary row (AUD-06). The row is written on a context the
// client cannot cancel (AUD-15). Failures to write are logged, never shown to the caller.
func (s *server) auditDenied(r *http.Request, rt route, p auth.Principal, reason string) {
	if p.Kind != rbac.UserSession && p.Kind != rbac.APIToken {
		return
	}
	details := map[string]string{"permission": string(rt.perm), "method": rt.method, "path": rt.pattern, "reason": reason}
	ev := audit.Event{Actor: s.denialActor(r, p, details), Action: "authz.denied", Result: audit.Denied, Details: details}
	s.recordDenial(r, denialKey(p, string(rt.perm), reason, rt), ev)
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
// "unverified" (the license could not be checked recently) (AUD-02). Coalesced and written like
// auditDenied (AUD-06, AUD-15).
func (s *server) auditLicenseDenied(r *http.Request, rt route, p auth.Principal, cause error) {
	if p.Kind != rbac.UserSession && p.Kind != rbac.APIToken {
		return
	}
	reason := licenseDenialReason(cause)
	details := map[string]string{"method": rt.method, "path": rt.pattern, "class": rt.lic.String(), "reason": reason}
	ev := audit.Event{Actor: s.denialActor(r, p, details), Action: "request.denied_license", Result: audit.Denied, Details: details}
	s.recordDenial(r, denialKey(p, "license:"+rt.lic.String(), reason, rt), ev)
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

// bearerScheme is the authentication scheme of an API token, with the space that ends it. The scheme name is
// case-insensitive (RFC 9110 §11.1), so "bearer" and "BEARER" are the same scheme (review L-18).
const bearerScheme = "Bearer "

func hasBearer(r *http.Request) bool {
	v := r.Header.Get("Authorization")
	return len(v) >= len(bearerScheme) && strings.EqualFold(v[:len(bearerScheme)], bearerScheme)
}

// bearerFrom returns the bearer token of r (hasBearer must hold).
func bearerFrom(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("Authorization")[len(bearerScheme):])
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
