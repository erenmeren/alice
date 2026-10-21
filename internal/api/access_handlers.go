package api

import (
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// accessRoutes are the role bindings of people (R49 Phase 2, design §8.1): who holds which role on which service or
// environment, beside the global role of People & access. Reading them is users.read (a global Administrator's, read
// tokens too, as the people list); adding and removing them decides who may reach what: access.manage, a global
// Administrator's browser session with step-up, never a token, in lock too (Alice's own records, ClassAlways).
func (s *server) accessRoutes() []route {
	always := license.ClassAlways
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/role-bindings", scope: scopePlatform, perm: rbac.UsersRead, handler: s.listRoleBindings},
		{method: http.MethodPost, pattern: "/api/v1/role-bindings", scope: scopePlatform, perm: rbac.AccessManage, lic: always, handler: s.createRoleBinding},
		{method: http.MethodDelete, pattern: "/api/v1/role-bindings/{id}", scope: scopePlatform, perm: rbac.AccessManage, lic: always, handler: s.deleteRoleBinding},
		{method: http.MethodGet, pattern: "/api/v1/users/{id}/access", scope: scopePlatform, perm: rbac.UsersRead, handler: s.userAccess},
	}
}

// maxRoleBindingBody bounds the body of a new binding.
const maxRoleBindingBody = 4 << 10

type roleBindingDTO struct {
	ID          uuid.UUID          `json:"id"`
	UserID      *uuid.UUID         `json:"user_id"`
	Username    string             `json:"username,omitempty"`
	DisplayName string             `json:"display_name,omitempty"`
	GroupID     *uuid.UUID         `json:"directory_group_id"`
	Role        string             `json:"role"`
	Service     *serviceRefDTO     `json:"service"`
	Environment *environmentRefDTO `json:"environment"`
	// Services are the services the binding covers now (an environment binding: every service that carries it).
	Services      []serviceRefDTO `json:"services"`
	CreatedBy     *uuid.UUID      `json:"created_by"`
	CreatedByName string          `json:"created_by_name"`
	CreatedAt     time.Time       `json:"created_at"`
}

func roleBindingJSON(b services.Binding) roleBindingDTO {
	d := roleBindingDTO{ID: b.ID, UserID: b.UserID, Username: b.Username, DisplayName: b.DisplayName, GroupID: b.DirectoryGroupID,
		Role: string(b.Role), Environment: environmentRefJSON(b.Environment), Services: make([]serviceRefDTO, 0, len(b.Services)),
		CreatedBy: b.CreatedBy, CreatedByName: b.CreatedByName, CreatedAt: b.CreatedAt.UTC()}
	if b.Service != nil {
		ref := serviceRefJSON(*b.Service)
		d.Service = &ref
	}
	for _, sv := range b.Services {
		d.Services = append(d.Services, serviceRefJSON(sv))
	}
	return d
}

// optionalFilterID reads an optional id query parameter (nil when absent); a malformed one is added to v.
func optionalFilterID(r *http.Request, name string, v *validate.Errors) *uuid.UUID {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return nil
	}
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		v.Add(name, validate.Pattern, nil)
		return nil
	}
	return &id
}

func (s *server) listRoleBindings(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	var v validate.Errors
	f := services.BindingFilter{UserID: optionalFilterID(r, "user_id", &v), DirectoryGroupID: optionalFilterID(r, "directory_group_id", &v),
		ServiceID: optionalFilterID(r, "service_id", &v), EnvironmentID: optionalFilterID(r, "environment_id", &v)}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.deps.Services.Bindings(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]roleBindingDTO, 0, len(list))
	for _, b := range list {
		items = append(items, roleBindingJSON(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createRoleBinding(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	var req struct {
		UserID        uuid.UUID  `json:"user_id"`
		Role          string     `json:"role"`
		ServiceID     *uuid.UUID `json:"service_id"`
		EnvironmentID *uuid.UUID `json:"environment_id"`
	}
	if !s.decodeExact(w, r, &req, maxRoleBindingBody, "user_id", "role", "service_id", "environment_id") {
		return
	}
	b, err := s.deps.Services.CreateBinding(r.Context(), s.serviceActor(r), services.BindingInput{UserID: req.UserID, Role: req.Role,
		ServiceID: req.ServiceID, EnvironmentID: req.EnvironmentID})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/role-bindings/"+b.ID.String())
	writeJSON(w, http.StatusCreated, roleBindingJSON(b))
}

func (s *server) deleteRoleBinding(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.Services.DeleteBinding(r.Context(), s.serviceActor(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// accessGrantDTO is one role as the authorization check sees it: the services it covers now.
type accessGrantDTO struct {
	Role     string          `json:"role"`
	Services []serviceRefDTO `json:"services"`
}

// userAccessDTO explains a person's effective access (design §9 "Explain"): the global role (null: none), every
// binding with what it covers now, the grants they add up to, and whether the "SSO users may be Admin" cap lowers an
// Administrator binding to Operator.
type userAccessDTO struct {
	GlobalRole *string          `json:"global_role"`
	Bindings   []roleBindingDTO `json:"bindings"`
	Grants     []accessGrantDTO `json:"grants"`
	AdminCap   bool             `json:"admin_capped"`
}

func (s *server) userAccess(w http.ResponseWriter, r *http.Request) {
	if !s.servicesReady(w, r) {
		return
	}
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	acc, err := s.deps.Services.Access(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	refs := s.serviceRefs(r)
	out := userAccessDTO{Bindings: make([]roleBindingDTO, 0, len(acc.Bindings)), Grants: make([]accessGrantDTO, 0, len(acc.Grants)),
		AdminCap: acc.AdminCap}
	if acc.GlobalRole != "" {
		g := string(acc.GlobalRole)
		out.GlobalRole = &g
	}
	for _, b := range acc.Bindings {
		out.Bindings = append(out.Bindings, roleBindingJSON(b))
	}
	for _, g := range acc.Grants {
		out.Grants = append(out.Grants, accessGrantDTO{Role: string(g.Role), Services: refList(refs, g.Services)})
	}
	writeJSON(w, http.StatusOK, out)
}

// refList shows services by name (in the order given).
func refList(refs serviceRefs, ids []uuid.UUID) []serviceRefDTO {
	out := make([]serviceRefDTO, 0, len(ids))
	for _, id := range ids {
		if d := refs.of(id); d != nil {
			out = append(out, *d)
		}
	}
	return out
}

// sessionAccessDTO is the access of the signed-in person for the web UI's navigation (design §8.2 GET /auth/session):
// the global role (null: none), each service they hold a role on with those roles, and every permission they hold
// somewhere (a global grant counts everywhere; the step-up window is not considered: the UI asks for it).
type sessionAccessDTO struct {
	GlobalRole          *string             `json:"global_role"`
	Services            []sessionServiceDTO `json:"services"`
	PermissionsAnywhere []string            `json:"permissions_anywhere"`
	// PlatformPermissions are the permissions the person holds with a global grant (the platform pages: people,
	// settings, audit, license, ...).
	PlatformPermissions []string `json:"platform_permissions"`
}

type sessionServiceDTO struct {
	serviceRefDTO
	Roles []string `json:"roles"`
}

// sessionAccess builds the session's access answer from the request's grants.
func (s *server) sessionAccess(r *http.Request) sessionAccessDTO {
	sub := s.subjectOf(r)
	if sub.Kind == rbac.UserSession {
		sub.StepUp = true
	}
	out := sessionAccessDTO{Services: []sessionServiceDTO{}, PermissionsAnywhere: []string{}, PlatformPermissions: []string{}}
	if _, ok := rbac.ParseRole(string(sub.Role)); ok {
		g := string(sub.Role)
		out.GlobalRole = &g
	}
	byService := map[uuid.UUID][]string{}
	var order []uuid.UUID
	for _, g := range sub.Grants {
		for _, sv := range g.Services {
			if _, seen := byService[sv]; !seen {
				order = append(order, sv)
			}
			if !slices.Contains(byService[sv], string(g.Role)) {
				byService[sv] = append(byService[sv], string(g.Role))
			}
		}
	}
	refs := s.serviceRefs(r)
	for _, sv := range order {
		ref := refs.of(sv)
		if ref == nil {
			continue
		}
		out.Services = append(out.Services, sessionServiceDTO{serviceRefDTO: *ref, Roles: byService[sv]})
	}
	for _, p := range rbac.Permissions() {
		if pol, ok := rbac.PolicyFor(p); !ok || pol.Anonymous || pol.Setup || pol.Pending || pol.SignedIn {
			continue
		}
		if rbac.DecideAnywhere(p, sub) == rbac.Allow {
			out.PermissionsAnywhere = append(out.PermissionsAnywhere, string(p))
		}
		if rbac.Decide(p, sub) == rbac.Allow {
			out.PlatformPermissions = append(out.PlatformPermissions, string(p))
		}
	}
	return out
}
