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

// guard wraps a route handler with, in order: authentication, rate limiting,
// the same-origin check, the CSRF check and the permission decision (SEC-016,
// SEC-017, SEC-021, SEC-024). Nothing reaches rt.handler unless rbac allows it.
func (s *server) guard(rt route) http.HandlerFunc {
	policy, _ := rbac.PolicyFor(rt.perm) // register has checked the permission exists
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, s.deps.TrustedProxies)
		p, csrfToken := auth.Principal{}, ""
		if !policy.Anonymous {
			var err error
			if p, csrfToken, err = s.authenticate(r); err != nil {
				s.authUnavailable(w, r, err)
				return
			}
		}
		if !s.allowRate(w, r, rt.limit, p, ratelimit.IPKey(ip)) {
			return
		}
		if !safeMethod(r.Method) && !hasBearer(r) {
			if !sameOrigin(r) {
				s.writeError(w, r, ErrCSRF)
				return
			}
			if !policy.Anonymous && csrfToken != "" && !s.deps.Auth.CheckCSRF(csrfToken, r.Header.Get("X-CSRF-Token")) {
				s.writeError(w, r, ErrCSRF)
				return
			}
		}
		switch rbac.Decide(rt.perm, p.Subject(s.deps.Clock.Now())) {
		case rbac.Allow:
			rt.handler(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
		case rbac.DenyUnauthenticated:
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

// authenticate resolves the caller. It returns the principal and the cookie
// value that the CSRF token must be bound to ("" for API tokens and anonymous
// callers). Invalid credentials simply leave the caller anonymous; any other
// backend failure is returned as an *authError.
func (s *server) authenticate(r *http.Request) (auth.Principal, string, error) {
	ctx := r.Context()
	if hasBearer(r) {
		bearer := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		p, err := s.deps.Auth.AuthenticateToken(ctx, bearer)
		switch {
		case err == nil:
			return p, "", nil
		case errors.Is(err, auth.ErrUnauthenticated):
			return auth.Principal{}, "", nil
		default:
			return auth.Principal{}, "", &authError{reason: "token_lookup_failed", err: err}
		}
	}
	if tok := sessionTokenFrom(r); tok != "" {
		p, err := s.deps.Auth.Authenticate(ctx, tok)
		switch {
		case err == nil:
			return p, tok, nil
		case !errors.Is(err, auth.ErrUnauthenticated):
			return auth.Principal{}, "", &authError{reason: "session_lookup_failed", err: err}
		}
	}
	if tok := setupTokenFrom(r); tok != "" {
		err := s.deps.Setup.Authenticate(ctx, tok)
		switch {
		case err == nil:
			return auth.Principal{Kind: rbac.SetupSession}, tok, nil
		case !errors.Is(err, setup.ErrSessionInvalid):
			return auth.Principal{}, "", &authError{reason: "setup_session_lookup_failed", err: err}
		}
	}
	return auth.Principal{}, "", nil
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
// ipKey is ratelimit.IPKey of the client address (IPv6 grouped by /64).
// It writes the 429 response itself and returns false when the caller is over a limit.
func (s *server) allowRate(w http.ResponseWriter, r *http.Request, class limitClass, p auth.Principal, ipKey string) bool {
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
		checks = append(checks, func() (bool, time.Duration) { return s.anon.Allow(ipKey) })
	}
	for _, check := range checks {
		if ok, retry := check(); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Round(time.Second)/time.Second)))
			s.writeError(w, r, ErrRateLimited)
			return false
		}
	}
	return true
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

func safeMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

func hasBearer(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// sameOrigin rejects cross-site state-changing requests (defence in depth
// next to SameSite=Strict cookies and the CSRF token).
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	return origin == "" || origin == "https://"+r.Host
}
