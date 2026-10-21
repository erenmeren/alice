package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/rbac"
)

var errCovCStore = errors.New("store: connection reset")

// covCServices is fakeServices with the methods the access, group and scope tests need answered.
type covCServices struct {
	*fakeServices
	access    services.UserAccess
	accessErr error
	grantsErr error
	groups    []services.DirectoryGroup
	seen      []services.SeenGroup
	groupsErr error
	targetErr error
}

func (f *covCServices) TargetServices(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	if f.targetErr != nil {
		return nil, f.targetErr
	}
	return f.fakeServices.TargetServices(ctx, ids)
}

func (f *covCServices) Access(context.Context, uuid.UUID) (services.UserAccess, error) {
	return f.access, f.accessErr
}

func (f *covCServices) Grants(context.Context, uuid.UUID) ([]rbac.ScopedGrant, error) {
	return nil, f.grantsErr
}

func (f *covCServices) DirectoryGroups(context.Context) ([]services.DirectoryGroup, []services.SeenGroup, error) {
	return f.groups, f.seen, f.groupsErr
}

func covCDeps(t *testing.T) (Deps, *covCServices) {
	t.Helper()
	d, f := servicesDeps(t)
	c := &covCServices{fakeServices: f}
	d.Services = c
	return d, c
}

// covCScoped is a person without a global role: Operator on Payments, Auditor on Default, in a step-up window.
func covCScoped() auth.Principal {
	return auth.Principal{Kind: rbac.UserSession, UserID: uuid.MustParse("0195e000-0000-7000-8000-0000000000c9"), Username: "olga",
		StepUpUntil: testNow.Add(5 * time.Minute), Grants: []rbac.ScopedGrant{
			{Role: rbac.Operator, Services: []uuid.UUID{svcPay}},
			{Role: rbac.Auditor, Services: []uuid.UUID{svcDefault}},
		}}
}

// covCRequest is a request from p with the path parameters given.
func covCRequest(p auth.Principal, params map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	for k, v := range params {
		r.SetPathValue(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}

func covCCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decodeErr(t, rec).Error.Code
}

// checkResource (design §5.4) for a caller with role bindings: the resource must be visible, a write needs the
// permission on its owning service (or on any or every service it is visible from, or on the second resource).
func TestCovCCheckResourceForAScopedCaller(t *testing.T) {
	d, f := covCDeps(t)
	s := newServer(d)
	p := covCScoped()
	write := route{method: http.MethodPost, pattern: "/x/{id}", scope: scopeResource, perm: rbac.CertificatesOperate,
		resolve: by(services.KindCertificate, "id")}
	id := uuid.New()
	params := map[string]string{"id": id.String()}
	resolutions := map[string]services.Resolution{}
	f.ResolveFn = func(kind string, key any) (services.Resolution, error) {
		if res, ok := resolutions[kind+"/"+key.(uuid.UUID).String()]; ok {
			return res, nil
		}
		return services.Resolution{}, services.ErrResourceNotFound
	}
	check := func(rt route, params map[string]string) (*httptest.ResponseRecorder, *http.Request, bool) {
		rec := httptest.NewRecorder()
		r, ok := s.checkResource(rec, covCRequest(p, params), rt, p)
		return rec, r, ok
	}

	// A malformed or nil id names nothing: the handler answers it.
	_, _, ok := check(write, map[string]string{"id": "nope"})
	assert.True(t, ok)
	_, _, ok = check(write, map[string]string{"id": uuid.Nil.String()})
	assert.True(t, ok)

	// Absent and out of sight answer the same 404.
	rec, _, ok := check(write, params)
	assert.False(t, ok)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	resolutions["certificate/"+id.String()] = services.Resolution{Owning: uuid.New(), Visible: []uuid.UUID{uuid.New()}}
	rec, _, ok = check(write, params)
	assert.False(t, ok)
	assert.Equal(t, ErrNotFound.Code, covCCode(t, rec), "visible from no service in the caller's read reach")

	// Visible from Default (Auditor there) but owned by Default: the write is refused with 403.
	resolutions["certificate/"+id.String()] = services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault}}
	rec, _, ok = check(write, params)
	assert.False(t, ok)
	assert.Equal(t, ErrForbidden.Code, covCCode(t, rec))
	// A read route needs it visible only.
	read := write
	read.perm = rbac.Read
	_, r, ok := check(read, params)
	assert.True(t, ok)
	res, stored := pathResource(r.Context())
	require.True(t, stored, "the resolution travels with the request")
	assert.Equal(t, svcDefault, res.Owning)
	// Owned by Payments (Operator there): allowed.
	resolutions["certificate/"+id.String()] = services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}
	_, _, ok = check(write, params)
	assert.True(t, ok)

	// allVisible: the permission on every service it is visible from.
	all := write
	all.resolve = &resolver{kind: services.KindIncident, param: "id", allVisible: true}
	resolutions["incident/"+id.String()] = services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay, svcDefault}}
	rec, _, ok = check(all, params)
	assert.False(t, ok, "Default is visible, but the caller is no Operator there")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	resolutions["incident/"+id.String()] = services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}
	_, _, ok = check(all, params)
	assert.True(t, ok)

	// anyVisible: the permission on one of them suffices.
	anyRt := write
	anyRt.resolve = &resolver{kind: services.KindServiceTrust, param: "id", anyVisible: true}
	resolutions["service_trust/"+id.String()] = services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault, svcPay}}
	_, _, ok = check(anyRt, params)
	assert.True(t, ok)

	// either: the right on the second resource's owning service suffices; an absent second resource adds nothing.
	loc := uuid.New()
	either := write
	either.resolve = byEither(services.KindKVBinding, "id", services.KindLocation, "location_id")
	resolutions["kv_binding/"+id.String()] = services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault}}
	two := map[string]string{"id": id.String(), "location_id": loc.String()}
	rec, _, ok = check(either, two)
	assert.False(t, ok, "the location is absent")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	resolutions["location/"+loc.String()] = services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}
	_, _, ok = check(either, two)
	assert.True(t, ok, "the receiving service detaches its own server")

	// A store failure on either lookup is a 500, never a pass.
	f.ResolveFn = func(kind string, _ any) (services.Resolution, error) {
		if kind == services.KindLocation {
			return services.Resolution{}, errCovCStore
		}
		return services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault}}, nil
	}
	rec, _, ok = check(either, two)
	assert.False(t, ok)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	rec, _, ok = check(write, params)
	assert.False(t, ok, "the owning service is Default: refused before the second look-up")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	f.ResolveFn = func(string, any) (services.Resolution, error) { return services.Resolution{}, errCovCStore }
	rec, _, ok = check(write, params)
	assert.False(t, ok)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// A caller with a global grant and role bindings is looked up (so the handler judges conditional permissions on the
// resource's service) but never refused: an absent resource is the handler's to answer.
func TestCovCCheckResourceForAGlobalGrantWithBindings(t *testing.T) {
	d, f := covCDeps(t)
	s := newServer(d)
	p := covCScoped()
	p.Role = rbac.Operator
	rt := route{method: http.MethodPost, pattern: "/x/{id}", scope: scopeResource, perm: rbac.CertificatesOperate,
		resolve: by(services.KindCertificate, "id")}
	params := map[string]string{"id": uuid.NewString()}
	rec := httptest.NewRecorder()
	_, ok := s.checkResource(rec, covCRequest(p, params), rt, p)
	assert.True(t, ok, "absent: the handler answers its own 404")
	f.ResolveFn = func(string, any) (services.Resolution, error) {
		return services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault}}, nil
	}
	r, ok := s.checkResource(rec, covCRequest(p, params), rt, p)
	assert.True(t, ok)
	_, stored := pathResource(r.Context())
	assert.True(t, stored)
	assert.Equal(t, rbac.Operator, s.roleOn(r), "global Operator; Auditor on Default is weaker")
	assert.Equal(t, rbac.Allow, s.decideOn(r, rbac.CertificatesOperate))
	assert.Equal(t, http.StatusOK, rec.Code, "nothing was written")

	// Without the services module, a global grant passes and scoped grants are refused (never let through).
	d.Services = nil
	s = newServer(d)
	_, ok = s.checkResource(httptest.NewRecorder(), covCRequest(p, params), rt, p)
	assert.True(t, ok)
	scoped := covCScoped()
	rec = httptest.NewRecorder()
	_, ok = s.checkResource(rec, covCRequest(scoped, params), rt, scoped)
	assert.False(t, ok)
	assert.Equal(t, ErrForbidden.Code, covCCode(t, rec))
}

// roleOn and decideOn judge on the owning service of the path's resource; strongestRole picks the most privileged role.
func TestCovCRoleOnTheResourcesService(t *testing.T) {
	d, _ := covCDeps(t)
	s := newServer(d)
	p := covCScoped()
	r := covCRequest(p, nil)
	assert.Equal(t, rbac.Role(""), s.roleOn(r), "no resource: the global role (none)")
	assert.NotEqual(t, rbac.Allow, s.decideOn(r, rbac.CertificatesOperate), "no global grant")
	on := func(svc uuid.UUID) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), resourceKey{}, services.Resolution{Owning: svc}))
	}
	assert.Equal(t, rbac.Operator, s.roleOn(on(svcPay)))
	assert.Equal(t, rbac.Auditor, s.roleOn(on(svcDefault)))
	assert.Equal(t, rbac.Role(""), s.roleOn(on(uuid.New())), "a service no grant covers")
	assert.Equal(t, rbac.Allow, s.decideOn(on(svcPay), rbac.CertificatesOperate))
	assert.NotEqual(t, rbac.Allow, s.decideOn(on(svcDefault), rbac.CertificatesOperate))

	assert.Equal(t, rbac.Admin, strongestRole(rbac.Admin, p.Grants, svcPay))
	assert.Equal(t, rbac.Operator, strongestRole(rbac.Auditor, p.Grants, svcPay))
}

// serviceForCreate (design §4.4): a scoped caller names a service in its reach, or gets the only one it has.
func TestCovCServiceForCreate(t *testing.T) {
	d, _ := covCDeps(t)
	s := newServer(d)
	p := covCScoped()
	rec := httptest.NewRecorder()
	got, ok := s.serviceForCreate(rec, covCRequest(p, nil), rbac.CertificatesOperate, nil)
	assert.True(t, ok)
	assert.Equal(t, svcPay, got, "the only service where the caller may create")
	rec = httptest.NewRecorder()
	_, ok = s.serviceForCreate(rec, covCRequest(p, nil), rbac.CertificatesOperate, &svcDefault)
	assert.False(t, ok)
	assert.Equal(t, ErrSVCNotAllowed.Code, covCCode(t, rec))
	got, ok = s.serviceForCreate(httptest.NewRecorder(), covCRequest(p, nil), rbac.CertificatesOperate, &svcPay)
	assert.True(t, ok)
	assert.Equal(t, svcPay, got)

	// Operator on two services: the body must name one.
	p.Grants[1].Role = rbac.Operator
	rec = httptest.NewRecorder()
	_, ok = s.serviceForCreate(rec, covCRequest(p, nil), rbac.CertificatesOperate, nil)
	assert.False(t, ok)
	assert.Equal(t, ErrSVCRequired.Code, covCCode(t, rec))
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// checkDestinations and checkDestinationsOf (design §5.6 b): every destination in reach; the refusal counts the others.
func TestCovCCheckDestinations(t *testing.T) {
	d, f := covCDeps(t)
	s := newServer(d)
	p := covCScoped()
	r := covCRequest(p, nil)
	assert.True(t, s.checkDestinations(httptest.NewRecorder(), r, rbac.CertificatesOperate, []uuid.UUID{svcPay, svcPay}))
	rec := httptest.NewRecorder()
	other := uuid.New()
	assert.False(t, s.checkDestinations(rec, r, rbac.CertificatesOperate, []uuid.UUID{svcPay, svcDefault, other, other}))
	assert.Equal(t, ErrSVCSpansServices.Code, covCCode(t, rec))
	var body map[string]map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]any{"count": "2"}, body["error"]["params"], "a repeated destination counts once")

	loc1, loc2, gone := uuid.New(), uuid.New(), uuid.New()
	f.ResolveFn = func(_ string, key any) (services.Resolution, error) {
		switch key.(uuid.UUID) {
		case loc1, loc2:
			return services.Resolution{Owning: svcPay}, nil
		case gone:
			return services.Resolution{}, services.ErrResourceNotFound
		}
		return services.Resolution{Owning: svcDefault}, nil
	}
	got, err := s.servicesOf(r.Context(), services.KindLocation, []uuid.UUID{loc1, gone, loc2})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{svcPay}, got, "in order, without repeats, an absent one adds nothing")
	assert.True(t, s.checkDestinationsOf(httptest.NewRecorder(), r, rbac.CertificatesOperate, services.KindLocation, []uuid.UUID{loc1, loc2}))
	rec = httptest.NewRecorder()
	assert.False(t, s.checkDestinationsOf(rec, r, rbac.CertificatesOperate, services.KindLocation, []uuid.UUID{loc1, uuid.New()}))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	f.ResolveFn = func(string, any) (services.Resolution, error) { return services.Resolution{}, errCovCStore }
	rec = httptest.NewRecorder()
	assert.False(t, s.checkDestinationsOf(rec, r, rbac.CertificatesOperate, services.KindLocation, []uuid.UUID{loc1}))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	d.Services = nil
	got, err = newServer(d).servicesOf(r.Context(), services.KindLocation, []uuid.UUID{loc1})
	require.NoError(t, err)
	assert.Nil(t, got, "without the services module nothing is looked up")
}

// targetsSeen and keepSeen (design §5.8): a scoped caller sees the rows on servers in its read reach; the rest are
// counted. Without the services module it sees none.
func TestCovCTargetsSeen(t *testing.T) {
	d, f := covCDeps(t)
	payServer, defServer, foreign, unknown := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	f.targetServices = map[uuid.UUID]uuid.UUID{payServer: svcPay, defServer: svcDefault, foreign: uuid.New()}
	s := newServer(d)
	r := covCRequest(covCScoped(), nil)
	rows := []uuid.UUID{payServer, defServer, foreign, unknown}
	seen, err := s.targetsSeen(r, targetIDsOf(rows, func(id uuid.UUID) uuid.UUID { return id }))
	require.NoError(t, err)
	kept, hidden := keepSeen(rows, func(id uuid.UUID) uuid.UUID { return id }, seen)
	assert.Equal(t, []uuid.UUID{payServer, defServer}, kept)
	assert.Equal(t, 2, hidden)
	f.targetErr = errCovCStore
	_, err = s.targetsSeen(r, rows)
	require.ErrorIs(t, err, errCovCStore)

	d.Services = nil
	seen, err = newServer(d).targetsSeen(r, rows)
	require.NoError(t, err)
	assert.False(t, seen(payServer))
}

// The role binding, access and directory group routes answer 503 without the services module, refuse malformed ids,
// and pass store failures on.
func TestCovCAccessRoutesWithoutTheModuleAndOnFailure(t *testing.T) {
	d, f := covCDeps(t)
	f.BindingsFn = func(services.BindingFilter) ([]services.Binding, error) { return nil, errCovCStore }
	f.accessErr = errCovCStore
	f.groupsErr = errCovCStore
	h := NewHandler(d)
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, "/api/v1/role-bindings", "admin", "").Code)
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, "/api/v1/users/"+uuid.NewString()+"/access", "admin", "").Code)
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, "/api/v1/directory-groups", "admin", "").Code)
	assert.Equal(t, ErrNotFound.Code, covCCode(t, call(h, http.MethodGet, "/api/v1/users/nope/access", "admin", "")))
	assert.Equal(t, ErrNotFound.Code, covCCode(t, call(h, http.MethodDelete, "/api/v1/role-bindings/nope", "admin-stepup", "")))
	assert.Equal(t, ErrACCGroupNotFound.Code, covCCode(t, call(h, http.MethodDelete, "/api/v1/directory-groups/nope", "admin-stepup", "")))
	assert.Equal(t, ErrSVCNotFound.Code, covCCode(t, call(h, http.MethodGet, "/api/v1/services/nope/owners", "admin", "")))
	assert.Equal(t, ErrSVCNotFound.Code, covCCode(t, call(h, http.MethodPut, "/api/v1/services/nope/owners", "admin-stepup",
		`{"version":1,"owners":[]}`)))
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, "/api/v1/services/"+svcPay.String()+"/owners", "admin", "").Code,
		"the owners read failed")

	d.Services = nil
	h = NewHandler(d)
	for _, c := range []struct{ method, path, id, body string }{
		{http.MethodGet, "/api/v1/role-bindings", "admin", ""},
		{http.MethodPost, "/api/v1/role-bindings", "admin-stepup", `{"role":"operator"}`},
		{http.MethodDelete, "/api/v1/role-bindings/" + uuid.NewString(), "admin-stepup", ""},
		{http.MethodGet, "/api/v1/users/" + uuid.NewString() + "/access", "admin", ""},
		{http.MethodGet, "/api/v1/directory-groups", "admin", ""},
		{http.MethodPost, "/api/v1/directory-groups", "admin-stepup", `{"source":"ldap","value":"cn=ops"}`},
		{http.MethodDelete, "/api/v1/directory-groups/" + uuid.NewString(), "admin-stepup", ""},
		{http.MethodGet, "/api/v1/services/" + svcPay.String() + "/owners", "admin", ""},
		{http.MethodPut, "/api/v1/services/" + svcPay.String() + "/owners", "admin-stepup", `{"version":1,"owners":[]}`},
	} {
		rec := call(h, c.method, c.path, c.id, c.body)
		assert.Equalf(t, http.StatusServiceUnavailable, rec.Code, "%s %s: %s", c.method, c.path, rec.Body.String())
	}
}

// A person's access: the global role, bindings, group bindings and grants by service name; bindings list their items.
func TestCovCUserAccessAndBindingsAnswer(t *testing.T) {
	d, f := covCDeps(t)
	pay := authz.ServiceRef{ID: svcPay, Name: "Payments"}
	person, unknown := uuid.New(), uuid.New()
	b := services.Binding{ID: uuid.New(), UserID: &person, Username: "olga", Role: rbac.Operator, Service: &pay, Services: []authz.ServiceRef{pay},
		CreatedAt: testNow}
	f.access = services.UserAccess{GlobalRole: rbac.Auditor, Bindings: []services.Binding{b}, AdminCap: true,
		Grants: []rbac.ScopedGrant{{Role: rbac.Operator, Services: []uuid.UUID{svcPay, uuid.Nil, unknown}}}}
	f.BindingsFn = func(services.BindingFilter) ([]services.Binding, error) { return []services.Binding{b}, nil }
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/users/"+person.String()+"/access", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var out struct {
		GlobalRole    *string          `json:"global_role"`
		Bindings      []map[string]any `json:"bindings"`
		GroupBindings []map[string]any `json:"group_bindings"`
		Grants        []struct {
			Role     string           `json:"role"`
			Services []map[string]any `json:"services"`
		} `json:"grants"`
		AdminCap bool `json:"admin_capped"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.NotNil(t, out.GlobalRole)
	assert.Equal(t, "auditor", *out.GlobalRole)
	require.Len(t, out.Bindings, 1)
	assert.Equal(t, "operator", out.Bindings[0]["role"])
	assert.Empty(t, out.GroupBindings)
	require.Len(t, out.Grants, 1)
	require.Len(t, out.Grants[0].Services, 2, "no service (the nil id) is left out")
	assert.Equal(t, "Payments", out.Grants[0].Services[0]["name"])
	assert.Equal(t, unknown.String(), out.Grants[0].Services[1]["id"], "a service the refs do not know shows its id alone")
	assert.Empty(t, out.Grants[0].Services[1]["name"])
	assert.True(t, out.AdminCap)

	rec = call(h, http.MethodGet, "/api/v1/role-bindings", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list.Items, 1)
	assert.Equal(t, b.ID.String(), list.Items[0]["id"])
}

// The directory groups list shows the declared groups and the values seen at sign-ins.
func TestCovCListDirectoryGroups(t *testing.T) {
	d, f := covCDeps(t)
	dir := uuid.New()
	gid := uuid.New()
	f.groups = []services.DirectoryGroup{{ID: gid, Source: services.SourceLDAP, DirectoryID: &dir, SourceName: "Corp AD", Value: "cn=ops",
		Label: "Ops", Members: 3, CreatedAt: testNow}}
	f.seen = []services.SeenGroup{{Source: services.SourceLDAP, DirectoryID: &dir, SourceName: "Corp AD", Value: "cn=ops", Users: 3, GroupID: &gid},
		{Source: services.SourceLDAP, DirectoryID: &dir, SourceName: "Corp AD", Value: "cn=dev", Users: 1}}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/directory-groups", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var out struct {
		Items []map[string]any `json:"items"`
		Seen  []map[string]any `json:"seen"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Len(t, out.Items, 1)
	assert.Equal(t, "Ops", out.Items[0]["label"])
	require.Len(t, out.Seen, 2)
	assert.Equal(t, gid.String(), out.Seen[0]["directory_group_id"])
	assert.Nil(t, out.Seen[1]["directory_group_id"], "a value no group declares")
	assert.Equal(t, float64(1), out.Seen[1]["users"])
}

// A new session's answer carries its access; when the grants cannot be read the session is still answered, without it.
// A grant naming no service is left out of the navigation.
func TestCovCSessionAnswerAccess(t *testing.T) {
	d, f := covCDeps(t)
	s := newServer(d)
	r := covCRequest(auth.Principal{}, nil)
	si := auth.SessionInfo{User: auth.User{ID: uuid.New(), Username: "olga", Role: rbac.Operator}}
	got := s.sessionAnswer(r, si, nil)
	require.NotNil(t, got.Access)
	require.NotNil(t, got.Access.GlobalRole)
	assert.Equal(t, "operator", *got.Access.GlobalRole)

	f.grantsErr = errCovCStore
	got = s.sessionAnswer(r, si, nil)
	assert.Nil(t, got.Access, "read again by GET /auth/session")

	acc := s.sessionAccessOf(r, rbac.Subject{Kind: rbac.UserSession, Grants: []rbac.ScopedGrant{
		{Role: rbac.Operator, Services: []uuid.UUID{uuid.Nil, svcPay}},
		{Role: rbac.Auditor, Services: []uuid.UUID{svcPay}},
	}})
	assert.Nil(t, acc.GlobalRole)
	require.Len(t, acc.Services, 1, "a grant naming no service (the nil id) is left out")
	assert.Equal(t, svcPay, acc.Services[0].ID)
	assert.Equal(t, []string{"operator", "auditor"}, acc.Services[0].Roles)
	assert.Contains(t, acc.PermissionsAnywhere, string(rbac.CertificatesOperate))
	assert.NotContains(t, acc.PlatformPermissions, string(rbac.CertificatesOperate))
}

// covCAutomation is fakeAutomation with the list, token list and revoke answered.
type covCAutomation struct {
	fakeAutomation
	accounts  []auth.AutomationAccount
	tokens    []auth.Token
	err       error
	revoked   [2]uuid.UUID
	revokeErr error
}

func (f *covCAutomation) ListAutomationAccounts(context.Context) ([]auth.AutomationAccount, error) {
	return f.accounts, f.err
}

func (f *covCAutomation) ListAutomationTokens(context.Context, uuid.UUID) ([]auth.Token, error) {
	return f.tokens, f.err
}

func (f *covCAutomation) RevokeAutomationToken(_ context.Context, _ auth.Principal, _ auth.Meta, id, tokenID uuid.UUID) error {
	f.revoked = [2]uuid.UUID{id, tokenID}
	return f.revokeErr
}

// The automation account routes: lists, the token list and revocation; malformed ids, an unknown role in a PATCH and a
// store failure; 503 without the module.
func TestCovCAutomationRoutes(t *testing.T) {
	d := testDeps(t, nil)
	acct := uuid.MustParse("0190f5a0-0000-7000-8000-0000000000c1")
	tok := uuid.MustParse("0190f5a0-0000-7000-8000-0000000000d1")
	fa := &covCAutomation{accounts: []auth.AutomationAccount{{ID: acct, Username: "ci", DisplayName: "CI"}},
		tokens: []auth.Token{{ID: tok, Name: "deploy", Scope: rbac.ScopeRead, CreatedAt: testNow}}}
	d.Automation = fa
	h := NewHandler(d)
	base := "/api/v1/automation-accounts"

	rec := call(h, http.MethodGet, base, "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"username":"ci"`)
	rec = call(h, http.MethodGet, base+"/"+acct.String()+"/tokens", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), tok.String())
	rec = call(h, http.MethodDelete, base+"/"+acct.String()+"/tokens/"+tok.String(), "admin-stepup", "")
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	assert.Equal(t, [2]uuid.UUID{acct, tok}, fa.revoked)

	for _, c := range []struct{ method, path, body string }{
		{http.MethodPatch, base + "/nope", `{"disabled":true}`},
		{http.MethodGet, base + "/nope/tokens", ""},
		{http.MethodPost, base + "/nope/tokens", `{"name":"x","scope":"read"}`},
		{http.MethodDelete, base + "/nope/tokens/" + tok.String(), ""},
		{http.MethodDelete, base + "/" + acct.String() + "/tokens/nope", ""},
	} {
		assert.Equalf(t, ErrNotFound.Code, covCCode(t, call(h, c.method, c.path, "admin-stepup", c.body)), "%s %s", c.method, c.path)
	}
	rec = call(h, http.MethodPatch, base+"/"+acct.String(), "admin-stepup", `{"role":"root"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"role"`)

	fa.err, fa.revokeErr = errCovCStore, errCovCStore
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, base, "admin", "").Code)
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, base+"/"+acct.String()+"/tokens", "admin", "").Code)
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodDelete, base+"/"+acct.String()+"/tokens/"+tok.String(), "admin-stepup", "").Code)

	d.Automation = nil
	h = NewHandler(d)
	for _, c := range []struct{ method, path, id, body string }{
		{http.MethodGet, base, "admin", ""},
		{http.MethodPost, base, "admin-stepup", `{"username":"ci","display_name":"CI"}`},
		{http.MethodPatch, base + "/" + acct.String(), "admin-stepup", `{"disabled":true}`},
		{http.MethodGet, base + "/" + acct.String() + "/tokens", "admin", ""},
		{http.MethodPost, base + "/" + acct.String() + "/tokens", "admin-stepup", `{"name":"x","scope":"read"}`},
		{http.MethodDelete, base + "/" + acct.String() + "/tokens/" + tok.String(), "admin-stepup", ""},
	} {
		rec := call(h, c.method, c.path, c.id, c.body)
		assert.Equalf(t, http.StatusServiceUnavailable, rec.Code, "%s %s: %s", c.method, c.path, rec.Body.String())
	}
}
