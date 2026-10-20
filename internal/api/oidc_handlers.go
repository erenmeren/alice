package api

import (
	"errors"
	"net/http"

	"alice/internal/auth/oidc"
	"alice/internal/auth/oidc/claims"
	"alice/internal/license"
	"alice/internal/rbac"
)

// oidcRoutes are the single sign-on at an identity provider (C13, SEC-010..SEC-015): the sign-in page's list, the
// start (10 a minute per address: each start stores a state row), the provider's redirect back (the only GET that
// writes, R42 row 18; limited per binding cookie, S-11) and an SSO user's step-up.
func (s *server) oidcRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/auth/oidc/providers", scope: scopeNone, perm: rbac.Public, handler: s.oidcProviders},
		{method: http.MethodPost, pattern: "/api/v1/auth/oidc/{id}/start", scope: scopeNone, perm: rbac.Public, limit: limitLogin, lic: license.ClassAlways,
			handler: s.oidcStart},
		{method: http.MethodGet, pattern: "/api/v1/auth/oidc/{id}/callback", scope: scopeNone, perm: rbac.Public, limit: limitOIDCCallback, getOnly: true,
			handler: s.oidcCallback},
		{method: http.MethodPost, pattern: "/api/v1/auth/oidc/stepup", scope: scopeSelf, perm: rbac.Session, limit: limitMFA, lic: license.ClassAlways,
			handler: s.oidcStepUp},
	}
}

// oidcProviders lists the enabled identity providers for the sign-in page: their ID and name only.
func (s *server) oidcProviders(w http.ResponseWriter, r *http.Request) {
	ps, err := s.deps.SSO.PublicProviders(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]publicProviderDTO, 0, len(ps))
	for _, p := range ps {
		out = append(out, publicProviderDTO{ID: p.ID, Name: p.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// oidcStart begins a sign-in at the provider: the browser gets the binding cookie and the provider's authorize URL.
// The body is empty or {"next"} (a path claims.SafeNext keeps).
func (s *server) oidcStart(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		Next string `json:"next"`
	}
	if !s.decodeExactOptional(w, r, &req, maxActionBody, "next") {
		return
	}
	b, err := s.deps.SSO.Begin(r.Context(), oidc.BeginInput{ProviderID: id, Next: req.Next})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setBindingCookie(w, b.Binding)
	writeJSON(w, http.StatusOK, map[string]string{"authorize_url": b.AuthorizeURL})
}

// oidcStepUp begins an SSO user's step-up at their own provider (a fresh sign-in there opens the step-up window of
// this session). A local user is refused with 409 ALC-SSO-0016 and confirms with the authenticator code instead.
func (s *server) oidcStepUp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Next string `json:"next"`
	}
	if !s.decodeExactOptional(w, r, &req, maxActionBody, "next") {
		return
	}
	p := principalFrom(r.Context())
	b, err := s.deps.SSO.Begin(r.Context(), oidc.BeginInput{Next: req.Next, StepUp: true, SessionHash: p.SessionHash, UserID: p.UserID})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setBindingCookie(w, b.Binding)
	writeJSON(w, http.StatusOK, map[string]string{"authorize_url": b.AuthorizeURL})
}

// oidcCallback ends a sign-in or a step-up at the identity provider's redirect (SEC-010..SEC-015). The binding cookie
// is cleared whatever happens; a refusal goes back to the sign-in page (or, for a step-up, to the page that asked) with
// the closed reason, which the page maps to its text. Nothing of the provider's answer is shown, and the answer is
// always a redirect, never a JSON page (the A-06 exception: the only GET that writes).
func (s *server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	clearBindingCookie(w)
	id, ok := pathUUID(r, "id")
	if !ok {
		http.Redirect(w, r, withQuery("/login", "sso_error", ErrSSOLoginInvalid.Reason), http.StatusSeeOther)
		return
	}
	binding := ""
	if c, err := r.Cookie(oidcCookie); err == nil {
		binding = c.Value
	}
	done, err := s.deps.SSO.Complete(r.Context(), id, r.URL.Query(), binding, s.meta(r))
	if err != nil {
		reason, target := ErrSSOLoginInvalid.Reason, "/login"
		var le *oidc.LoginError
		if errors.As(err, &le) {
			reason = loginErrorCode(le).Reason
			if le.StepUp && le.Next != "" {
				target = claims.SafeNext(le.Next)
			}
		} else {
			s.deps.Log.Error("single sign-on failed", append([]any{"request_id", RequestID(r.Context())}, errorAttrs(err)...)...)
		}
		http.Redirect(w, r, withQuery(target, "sso_error", reason), http.StatusSeeOther)
		return
	}
	// A sign-in creates the session; a step-up rotated it (A-04): either way the new token is the cookie now.
	s.issueSessionCookie(w, done.Session.Token)
	http.Redirect(w, r, claims.SafeNext(done.Next), http.StatusSeeOther)
}
