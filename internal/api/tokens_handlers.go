package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"alice/internal/auth"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// tokenRoutes manage personal API tokens (SEC-025, SEC-026). Creating a token
// needs step-up; the secret is returned exactly once.
func (s *server) tokenRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: tokensPattern, scope: scopeSelf, perm: rbac.Session, handler: s.listTokens},
		{method: http.MethodPost, pattern: "/api/v1/tokens", scope: scopeSelf, perm: rbac.SessionStepUp, lic: license.ClassAlways, handler: s.createToken},
		{method: http.MethodDelete, pattern: "/api/v1/tokens/{id}", scope: scopeSelf, perm: rbac.Session, lic: license.ClassAlways, handler: s.revokeToken},
	}
}

type tokenDTO struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scope      string     `json:"scope"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

func tokenJSON(t auth.Token) tokenDTO {
	var last *time.Time
	if t.LastUsedAt != nil {
		u := t.LastUsedAt.UTC()
		last = &u
	}
	return tokenDTO{
		ID:         t.ID.String(),
		UserID:     t.UserID.String(),
		Name:       t.Name,
		Prefix:     t.Prefix,
		Scope:      string(t.Scope),
		ExpiresAt:  t.ExpiresAt.UTC(),
		LastUsedAt: last,
		CreatedAt:  t.CreatedAt.UTC(),
	}
}

// tokensPattern is the token list route; its refusals are coalesced under it (AUD-06).
const tokensPattern = "/api/v1/tokens" //nolint:gosec // G101: a route pattern, not a credential

// listTokens lists the caller's tokens, or another user's when ?user_id= is given. Only an
// administrator may list another user's tokens: anyone else gets 404 like an unknown user (no
// existence check is made), and the refusal is recorded as authz.denied with reason not_owner,
// coalesced per person and route like the guard's refusals, the summary counting the distinct
// user IDs asked for (AUD-06, AUD-15).
func (s *server) listTokens(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	userID := p.UserID
	if raw := r.URL.Query().Get("user_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			var v validate.Errors
			v.Add("user_id", validate.Pattern, nil)
			s.fail(w, r, v)
			return
		}
		userID = id
	}
	if userID != p.UserID && p.Role != rbac.Admin {
		s.auditNotOwner(r, p, route{method: http.MethodGet, pattern: tokensPattern, scope: scopeSelf, perm: rbac.Session}, "user", userID.String())
		s.fail(w, r, auth.ErrNotFound)
		return
	}
	tokens, err := s.deps.Auth.ListTokens(r.Context(), p, s.meta(r), userID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]tokenDTO, 0, len(tokens))
	for _, t := range tokens {
		items = append(items, tokenJSON(t))
	}
	writeJSON(w, http.StatusOK, map[string][]tokenDTO{"items": items})
}

func (s *server) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		Scope         string `json:"scope"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	scope, ok := rbac.ParseScope(req.Scope)
	if !ok {
		var v validate.Errors
		v.Add("scope", validate.OneOf, map[string]string{"values": "read, operate"})
		s.fail(w, r, v)
		return
	}
	secret, t, err := s.deps.Auth.CreateToken(r.Context(), principalFrom(r.Context()), s.meta(r), auth.NewToken{
		Name: req.Name, Scope: scope, ExpiresInDays: req.ExpiresInDays,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.recent.Add(secret) // its first use passes the failed-credential limit (AUD-16)
	writeJSON(w, http.StatusCreated, map[string]any{"token": secret, "item": tokenJSON(t)})
}

func (s *server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.Auth.RevokeToken(r.Context(), principalFrom(r.Context()), s.meta(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}
