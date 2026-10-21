package api

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"alice/internal/auth"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// AutomationService is the part of auth.Service the automation account routes use (R49 Phase 3, R54; design §6.2): a
// non-person that never signs in and only holds API tokens, made and changed by a global Administrator, who also makes
// and revokes its tokens. nil leaves the routes unavailable (503).
type AutomationService interface {
	ListAutomationAccounts(ctx context.Context) ([]auth.AutomationAccount, error)
	CreateAutomationAccount(ctx context.Context, p auth.Principal, m auth.Meta, in auth.NewAutomationAccount) (auth.AutomationAccount, error)
	UpdateAutomationAccount(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID, in auth.AutomationUpdate) (auth.AutomationAccount, error)
	ListAutomationTokens(ctx context.Context, accountID uuid.UUID) ([]auth.Token, error)
	CreateAutomationToken(ctx context.Context, p auth.Principal, m auth.Meta, accountID uuid.UUID, in auth.NewToken) (string, auth.Token, error)
	RevokeAutomationToken(ctx context.Context, p auth.Principal, m auth.Meta, accountID, tokenID uuid.UUID) error
}

var _ AutomationService = (*auth.Service)(nil)

// maxAutomationBody bounds the body of an automation account (a description is at most 500 characters).
const maxAutomationBody = 8 << 10

type automationDTO struct {
	ID          uuid.UUID  `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Description string     `json:"description"`
	Role        *string    `json:"role"` // null: no global role
	Disabled    bool       `json:"disabled"`
	Tokens      int        `json:"tokens"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func automationJSON(a auth.AutomationAccount) automationDTO {
	d := automationDTO{ID: a.ID, Username: a.Username, DisplayName: a.DisplayName, Description: a.Description, Disabled: a.Disabled,
		Tokens: a.Tokens, LastUsedAt: a.LastUsedAt, CreatedAt: a.CreatedAt.UTC(), UpdatedAt: a.UpdatedAt.UTC()}
	if a.Role != auth.NoGlobalRole {
		r := string(a.Role)
		d.Role = &r
	}
	return d
}

// automationReady answers 503 when the automation accounts are not wired (a test build without them).
func (s *server) automationReady(w http.ResponseWriter, r *http.Request) bool {
	if s.deps.Automation == nil {
		s.writeError(w, r, ErrUnavailable)
		return false
	}
	return true
}

func (s *server) listAutomationAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.automationReady(w, r) {
		return
	}
	list, err := s.deps.Automation.ListAutomationAccounts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]automationDTO, 0, len(list))
	for _, a := range list {
		items = append(items, automationJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// roleOrRefuse is the role of an optional role field (null: no global role); an unknown one is written as a validation
// error and ok is false.
func (s *server) roleOrRefuse(w http.ResponseWriter, r *http.Request, o optionalRole) (rbac.Role, bool) {
	role, ok := o.role()
	if !ok {
		var v validate.Errors
		v.Add("role", validate.OneOf, map[string]string{"values": roleValues()})
		s.fail(w, r, v)
	}
	return role, ok
}

func (s *server) createAutomationAccount(w http.ResponseWriter, r *http.Request) {
	if !s.automationReady(w, r) {
		return
	}
	var req struct {
		Username    string       `json:"username"`
		DisplayName string       `json:"display_name"`
		Description string       `json:"description"`
		Role        optionalRole `json:"role"`
	}
	if !s.decodeExact(w, r, &req, maxAutomationBody, "username", "display_name", "description", "role") {
		return
	}
	role, ok := s.roleOrRefuse(w, r, req.Role) // absent and null are both "no global role"
	if !ok {
		return
	}
	a, err := s.deps.Automation.CreateAutomationAccount(r.Context(), principalFrom(r.Context()), s.meta(r), auth.NewAutomationAccount{
		Username: req.Username, DisplayName: req.DisplayName, Description: req.Description, Role: role})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/automation-accounts/"+a.ID.String())
	writeJSON(w, http.StatusCreated, automationJSON(a))
}

func (s *server) updateAutomationAccount(w http.ResponseWriter, r *http.Request) {
	if !s.automationReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		DisplayName *string      `json:"display_name"`
		Description *string      `json:"description"`
		Role        optionalRole `json:"role"`
		Disabled    *bool        `json:"disabled"`
	}
	if !s.decodeExact(w, r, &req, maxAutomationBody, "display_name", "description", "role", "disabled") {
		return
	}
	in := auth.AutomationUpdate{DisplayName: req.DisplayName, Description: req.Description, Disabled: req.Disabled}
	if req.Role.set {
		role, ok := s.roleOrRefuse(w, r, req.Role)
		if !ok {
			return
		}
		in.Role = &role
	}
	a, err := s.deps.Automation.UpdateAutomationAccount(r.Context(), principalFrom(r.Context()), s.meta(r), id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, automationJSON(a))
}

func (s *server) listAutomationTokens(w http.ResponseWriter, r *http.Request) {
	if !s.automationReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	tokens, err := s.deps.Automation.ListAutomationTokens(r.Context(), id)
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

func (s *server) createAutomationToken(w http.ResponseWriter, r *http.Request) {
	if !s.automationReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	in, ok := s.decodeNewToken(w, r)
	if !ok {
		return
	}
	secret, t, err := s.deps.Automation.CreateAutomationToken(r.Context(), principalFrom(r.Context()), s.meta(r), id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.recent.Add(secret) // its first use passes the failed-credential limit (AUD-16)
	writeJSON(w, http.StatusCreated, map[string]any{"token": secret, "item": tokenJSON(t)})
}

func (s *server) revokeAutomationToken(w http.ResponseWriter, r *http.Request) {
	if !s.automationReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	tokenID, ok := pathUUID(r, "token_id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.Automation.RevokeAutomationToken(r.Context(), principalFrom(r.Context()), s.meta(r), id, tokenID); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}
