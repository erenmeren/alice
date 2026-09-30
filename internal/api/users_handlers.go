package api

import (
	"net/http"
	"strings"

	"alice/internal/auth"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// userRoutes are the administrator's user management (spec §9.6, SEC-009:
// every change needs step-up; R10 break-glass is enforced by auth).
func (s *server) userRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/users", perm: rbac.UsersRead, handler: s.listUsers},
		{method: http.MethodPost, pattern: "/api/v1/users", perm: rbac.UsersManage, lic: license.ClassAlways, handler: s.createUser},
		{method: http.MethodGet, pattern: "/api/v1/users/{id}", perm: rbac.UsersRead, handler: s.getUser},
		{method: http.MethodPatch, pattern: "/api/v1/users/{id}", perm: rbac.UsersManage, lic: license.ClassAlways, handler: s.updateUser},
		{method: http.MethodPost, pattern: "/api/v1/users/{id}/actions/reset-mfa", perm: rbac.UsersManage, lic: license.ClassAlways, handler: s.resetUserMFA},
		{method: http.MethodPost, pattern: "/api/v1/users/{id}/actions/reset-password", perm: rbac.UsersManage, lic: license.ClassAlways, handler: s.resetUserPassword},
		{method: http.MethodPost, pattern: "/api/v1/users/{id}/actions/revoke-sessions", perm: rbac.UsersManage, lic: license.ClassAlways, handler: s.revokeUserSessions},
	}
}

// roleValues is the params value for validate.OneOf on role fields.
func roleValues() string {
	names := make([]string, 0, 3)
	for _, r := range rbac.Roles() {
		names = append(names, string(r))
	}
	return strings.Join(names, ", ")
}

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.deps.Auth.ListUsers(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]userDTO, 0, len(users))
	for _, u := range users {
		items = append(items, userJSON(u))
	}
	writeJSON(w, http.StatusOK, map[string][]userDTO{"items": items})
}

func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Role        string `json:"role"`
		Password    string `json:"password"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	role, ok := rbac.ParseRole(req.Role)
	if !ok {
		var v validate.Errors
		v.Add("role", validate.OneOf, map[string]string{"values": roleValues()})
		s.fail(w, r, v)
		return
	}
	u, err := s.deps.Auth.CreateUser(r.Context(), principalFrom(r.Context()), s.meta(r), auth.NewUser{
		Username: req.Username, DisplayName: req.DisplayName, Email: req.Email, Role: role, Password: req.Password,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, userJSON(u))
}

func (s *server) getUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	u, err := s.deps.Auth.GetUser(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userJSON(u))
}

func (s *server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		DisplayName *string `json:"display_name"`
		Email       *string `json:"email"`
		Role        *string `json:"role"`
		Disabled    *bool   `json:"disabled"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	in := auth.UserUpdate{DisplayName: req.DisplayName, Email: req.Email, Disabled: req.Disabled}
	if req.Role != nil {
		role, ok := rbac.ParseRole(*req.Role)
		if !ok {
			var v validate.Errors
			v.Add("role", validate.OneOf, map[string]string{"values": roleValues()})
			s.fail(w, r, v)
			return
		}
		in.Role = &role
	}
	u, err := s.deps.Auth.UpdateUser(r.Context(), principalFrom(r.Context()), s.meta(r), id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userJSON(u))
}

func (s *server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.Auth.ResetMFA(r.Context(), principalFrom(r.Context()), s.meta(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

func (s *server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if err := s.deps.Auth.ResetPassword(r.Context(), principalFrom(r.Context()), s.meta(r), id, req.Password); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

func (s *server) revokeUserSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.Auth.RevokeSessions(r.Context(), principalFrom(r.Context()), s.meta(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}
