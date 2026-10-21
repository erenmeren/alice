package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// fakeServices is ServicesService for the handler tests: every method answers through its Fn, or errNotConfigured;
// Refs answers the services of refs.
type fakeServices struct {
	refs           map[uuid.UUID]authz.ServiceRef
	lastActor      services.Actor
	targetServices map[uuid.UUID]uuid.UUID // TargetServices' answer

	CreateServiceFn func(in services.ServiceInput) (services.Service, error)
	UpdateServiceFn func(id uuid.UUID, version int, p services.ServicePatch) (services.Service, error)
	DeleteServiceFn func(id uuid.UUID, version int) error
	ServicesFn      func() ([]services.Service, error)
	AssignFn        func(dest uuid.UUID, resources []services.Resource, dryRun bool) (services.AssignResult, error)
	CreateTrustFn   func(source, target uuid.UUID) (services.Trust, error)
	ResolveFn       func(kind string, id any) (services.Resolution, error)
	BindingsFn      func(f services.BindingFilter) ([]services.Binding, error)
	CreateBindingFn func(in services.BindingInput) (services.Binding, error)
	SetPolicyFn     func(id uuid.UUID, version int, body json.RawMessage, global bool) (services.Policy, error)
	OwnersFn        func(id uuid.UUID) (services.Owners, error)
	SetOwnersFn     func(id uuid.UUID, version int, in []services.OwnerInput) (services.Owners, error)
}

var _ ServicesService = (*fakeServices)(nil)

func (f *fakeServices) DirectoryGroups(context.Context) ([]services.DirectoryGroup, []services.SeenGroup, error) {
	return nil, nil, errNotConfigured
}

func (f *fakeServices) CreateDirectoryGroup(context.Context, services.Actor, services.DirectoryGroupInput) (services.DirectoryGroup, error) {
	return services.DirectoryGroup{}, errNotConfigured
}

func (f *fakeServices) DeleteDirectoryGroup(context.Context, services.Actor, uuid.UUID) (services.GroupRemoval, error) {
	return services.GroupRemoval{}, errNotConfigured
}

func (f *fakeServices) Environments(context.Context) ([]services.Environment, error) {
	return nil, errNotConfigured
}
func (f *fakeServices) CreateEnvironment(_ context.Context, a services.Actor, _ services.EnvironmentInput) (services.Environment, error) {
	f.lastActor = a
	return services.Environment{}, errNotConfigured
}
func (f *fakeServices) UpdateEnvironment(_ context.Context, a services.Actor, _ uuid.UUID, _ int, _ services.EnvironmentPatch) (services.Environment, error) {
	f.lastActor = a
	return services.Environment{}, errNotConfigured
}
func (f *fakeServices) DeleteEnvironment(_ context.Context, a services.Actor, _ uuid.UUID, _ int) error {
	f.lastActor = a
	return errNotConfigured
}
func (f *fakeServices) Services(context.Context) ([]services.Service, error) {
	if f.ServicesFn != nil {
		return f.ServicesFn()
	}
	return nil, errNotConfigured
}
func (f *fakeServices) Service(context.Context, uuid.UUID) (services.Service, error) {
	return services.Service{}, services.ErrNotFound
}
func (f *fakeServices) CreateService(_ context.Context, a services.Actor, in services.ServiceInput) (services.Service, error) {
	f.lastActor = a
	if f.CreateServiceFn != nil {
		return f.CreateServiceFn(in)
	}
	return services.Service{}, errNotConfigured
}
func (f *fakeServices) UpdateService(_ context.Context, a services.Actor, id uuid.UUID, version int, p services.ServicePatch) (services.Service, error) {
	f.lastActor = a
	if f.UpdateServiceFn != nil {
		return f.UpdateServiceFn(id, version, p)
	}
	return services.Service{}, errNotConfigured
}
func (f *fakeServices) DeleteService(_ context.Context, a services.Actor, id uuid.UUID, version int) error {
	f.lastActor = a
	if f.DeleteServiceFn != nil {
		return f.DeleteServiceFn(id, version)
	}
	return errNotConfigured
}
func (f *fakeServices) Policy(context.Context, uuid.UUID) (services.Policy, error) {
	return services.Policy{}, errNotConfigured
}
func (f *fakeServices) PolicyVersions(context.Context, uuid.UUID) ([]services.Policy, error) {
	return nil, errNotConfigured
}
func (f *fakeServices) SetPolicy(_ context.Context, a services.Actor, id uuid.UUID, version int, body json.RawMessage, global bool) (services.Policy, error) {
	f.lastActor = a
	if f.SetPolicyFn != nil {
		return f.SetPolicyFn(id, version, body, global)
	}
	return services.Policy{}, errNotConfigured
}
func (f *fakeServices) Owners(_ context.Context, id uuid.UUID) (services.Owners, error) {
	if f.OwnersFn != nil {
		return f.OwnersFn(id)
	}
	return services.Owners{}, errNotConfigured
}
func (f *fakeServices) SetOwners(_ context.Context, a services.Actor, id uuid.UUID, version int, in []services.OwnerInput) (services.Owners, error) {
	f.lastActor = a
	if f.SetOwnersFn != nil {
		return f.SetOwnersFn(id, version, in)
	}
	return services.Owners{}, errNotConfigured
}
func (f *fakeServices) Trusts(context.Context, *uuid.UUID) ([]services.Trust, error) {
	return nil, errNotConfigured
}
func (f *fakeServices) CreateTrust(_ context.Context, a services.Actor, source, target uuid.UUID) (services.Trust, error) {
	f.lastActor = a
	if f.CreateTrustFn != nil {
		return f.CreateTrustFn(source, target)
	}
	return services.Trust{}, errNotConfigured
}
func (f *fakeServices) DeleteTrust(_ context.Context, a services.Actor, _ uuid.UUID) error {
	f.lastActor = a
	return errNotConfigured
}
func (f *fakeServices) Assign(_ context.Context, a services.Actor, dest uuid.UUID, resources []services.Resource, dryRun bool) (services.AssignResult, error) {
	f.lastActor = a
	if f.AssignFn != nil {
		return f.AssignFn(dest, resources, dryRun)
	}
	return services.AssignResult{}, errNotConfigured
}
func (f *fakeServices) Refs(context.Context) (map[uuid.UUID]authz.ServiceRef, error) {
	return f.refs, nil
}
func (f *fakeServices) Resolve(_ context.Context, kind string, id any) (services.Resolution, error) {
	if f.ResolveFn != nil {
		return f.ResolveFn(kind, id)
	}
	return services.Resolution{}, services.ErrResourceNotFound
}
func (f *fakeServices) TargetServices(_ context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	out := map[uuid.UUID]uuid.UUID{}
	for _, id := range ids {
		if svc, ok := f.targetServices[id]; ok {
			out[id] = svc
		}
	}
	return out, nil
}
func (f *fakeServices) Grants(context.Context, uuid.UUID) ([]rbac.ScopedGrant, error) {
	return nil, nil
}
func (f *fakeServices) Bindings(_ context.Context, fl services.BindingFilter) ([]services.Binding, error) {
	if f.BindingsFn != nil {
		return f.BindingsFn(fl)
	}
	return nil, errNotConfigured
}
func (f *fakeServices) Binding(context.Context, uuid.UUID) (services.Binding, error) {
	return services.Binding{}, services.ErrBindingNotFound
}
func (f *fakeServices) CreateBinding(_ context.Context, a services.Actor, in services.BindingInput) (services.Binding, error) {
	f.lastActor = a
	if f.CreateBindingFn != nil {
		return f.CreateBindingFn(in)
	}
	return services.Binding{}, errNotConfigured
}
func (f *fakeServices) DeleteBinding(_ context.Context, a services.Actor, _ uuid.UUID) error {
	f.lastActor = a
	return errNotConfigured
}
func (f *fakeServices) Access(context.Context, uuid.UUID) (services.UserAccess, error) {
	return services.UserAccess{}, errNotConfigured
}

var (
	svcDefault = uuid.MustParse("0195e000-0000-7000-8000-000000000001")
	svcPay     = uuid.MustParse("0195e000-0000-7000-8000-000000000002")
	envProd    = uuid.MustParse("0195e000-0000-7000-8000-0000000000e1")
)

func servicesDeps(t *testing.T) (Deps, *fakeServices) {
	t.Helper()
	d := testDeps(t, nil)
	f := &fakeServices{refs: map[uuid.UUID]authz.ServiceRef{
		svcDefault: {ID: svcDefault, Name: "Default"},
		svcPay:     {ID: svcPay, Name: "Payments", Environment: &authz.EnvironmentRef{ID: envProd, Key: "production", Name: "Production"}},
	}}
	d.Services = f
	return d, f
}

func TestCreateServiceAnswersTheServiceAndTheActor(t *testing.T) {
	d, f := servicesDeps(t)
	var got services.ServiceInput
	f.CreateServiceFn = func(in services.ServiceInput) (services.Service, error) {
		got = in
		return services.Service{ID: svcPay, Name: in.Name, Description: in.Description, Version: 1, PolicyVersion: 1,
			Environment: &authz.EnvironmentRef{ID: envProd, Key: "production", Name: "Production"}, Counts: services.Counts{Servers: 2},
			CreatedAt: testNow, UpdatedAt: testNow}, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/services", "admin-stepup", `{"name":"Payments","description":"Cards","environment_id":"`+envProd.String()+`"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	assert.Equal(t, services.ServiceInput{Name: "Payments", Description: "Cards", EnvironmentID: &envProd}, got)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "Payments", body["name"])
	assert.Equal(t, map[string]any{"id": envProd.String(), "key": "production", "name": "Production"}, body["environment"])
	assert.Equal(t, float64(2), body["counts"].(map[string]any)["servers"])
	assert.NotEqual(t, uuid.Nil, f.lastActor.UserID, "the Administrator is recorded as created_by")

	// Unknown fields are refused; a step-up is needed; a token never may.
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/services", "admin-stepup", `{"name":"x","owner":"y"}`).Code)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/services", "admin", `{"name":"x"}`).Code)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/services", "alice_operate_admin", `{"name":"x"}`).Code)
}

func TestUpdateServiceEnvironmentAbsentNullOrSet(t *testing.T) {
	d, f := servicesDeps(t)
	var got services.ServicePatch
	var version int
	f.UpdateServiceFn = func(_ uuid.UUID, v int, p services.ServicePatch) (services.Service, error) {
		got, version = p, v
		return services.Service{ID: svcPay, Name: "Payments", Version: v + 1}, nil
	}
	h := NewHandler(d)
	patch := func(body string) int {
		req := as(newJSONRequest(http.MethodPatch, "/api/v1/services/"+svcPay.String(), body), "admin-stepup")
		req.Header.Set("If-Match", `"3"`)
		return serve(h, req).Code
	}
	require.Equal(t, http.StatusOK, patch(`{"name":"Pay"}`))
	assert.False(t, got.SetEnvironment, "absent keeps it")
	assert.Equal(t, 3, version)
	require.Equal(t, http.StatusOK, patch(`{"environment_id":null}`))
	assert.True(t, got.SetEnvironment)
	assert.Nil(t, got.EnvironmentID, "null removes it")
	require.Equal(t, http.StatusOK, patch(`{"environment_id":"`+envProd.String()+`"}`))
	assert.Equal(t, &envProd, got.EnvironmentID)
	assert.Equal(t, http.StatusUnprocessableEntity, patch(`{"environment_id":"nope"}`))
	req := as(newJSONRequest(http.MethodPatch, "/api/v1/services/"+svcPay.String(), `{"name":"Pay"}`), "admin-stepup")
	assert.Equal(t, http.StatusPreconditionFailed, serve(h, req).Code, "If-Match is required")
}

func TestServiceErrorsHaveTheirCodes(t *testing.T) {
	d, f := servicesDeps(t)
	h := NewHandler(d)
	del := func() errBody {
		req := as(newJSONRequest(http.MethodDelete, "/api/v1/services/"+svcPay.String(), ""), "admin-stepup")
		req.Header.Set("If-Match", `"1"`)
		return decodeErr(t, serve(h, req))
	}
	for err, code := range map[error]string{
		services.ErrDefaultProtected:                                 "ALC-SVC-0004",
		&services.NotEmptyError{Counts: services.Counts{Servers: 1}}: "ALC-SVC-0003",
		services.ErrNotFound:                                         "ALC-SVC-0001",
		services.ErrVersionMismatch:                                  "ALC-SYS-0008",
	} {
		f.DeleteServiceFn = func(uuid.UUID, int) error { return err }
		assert.Equal(t, code, del().Error.Code, "%v", err)
	}
	f.CreateServiceFn = func(services.ServiceInput) (services.Service, error) {
		return services.Service{}, services.ErrNameTaken
	}
	assert.Equal(t, "ALC-SVC-0002", decodeErr(t, call(h, http.MethodPost, "/api/v1/services", "admin-stepup", `{"name":"x"}`)).Error.Code)
	f.CreateTrustFn = func(uuid.UUID, uuid.UUID) (services.Trust, error) { return services.Trust{}, services.ErrTrustExists }
	assert.Equal(t, "ALC-SVC-0018", decodeErr(t, call(h, http.MethodPost, "/api/v1/service-trusts", "admin-stepup",
		`{"source_service_id":"`+svcDefault.String()+`","target_service_id":"`+svcPay.String()+`"}`)).Error.Code)
}

// A cross-service refusal names both services: the caller sees both (design §5.6).
func TestUntrustedDeploymentNamesBothServices(t *testing.T) {
	d, _ := servicesDeps(t)
	loc := uuid.New()
	d.Inventory.(*fakeInventory).RequestDeploymentFn = func(context.Context, inventory.Actor, inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error) {
		return nil, &inventory.LocationRefusalError{LocationID: loc, Err: &authz.UntrustedError{Source: svcDefault, Target: svcPay}}
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/certificates/"+uuid.NewString()+"/deploy", "operator",
		`{"location_ids":["`+loc.String()+`"]}`)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	var body struct {
		Error struct {
			Code   string            `json:"code"`
			Params map[string]string `json:"params"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ALC-SVC-0007", body.Error.Code)
	assert.Equal(t, map[string]string{"source_service": "Default", "source_service_id": svcDefault.String(), "target_service": "Payments",
		"target_service_id": svcPay.String(), "location_id": loc.String()}, body.Error.Params)
}

func TestAssignReadsDryRunAndTheResources(t *testing.T) {
	d, f := servicesDeps(t)
	var (
		dest   uuid.UUID
		gotRes []services.Resource
		dry    bool
	)
	target := uuid.New()
	f.AssignFn = func(id uuid.UUID, res []services.Resource, dryRun bool) (services.AssignResult, error) {
		dest, gotRes, dry = id, res, dryRun
		return services.AssignResult{DryRun: dryRun, Destination: f.refs[svcPay],
			Moves: []services.Move{{Type: services.KindTarget, ID: target, Name: "web-1", From: f.refs[svcDefault], Changed: true}}}, nil
	}
	h := NewHandler(d)
	body := `{"resources":[{"type":"target","id":"` + target.String() + `"}]}`
	rec := call(h, http.MethodPost, "/api/v1/services/"+svcPay.String()+"/actions/assign?dry_run=true", "admin-stepup", body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, dry)
	assert.Equal(t, svcPay, dest)
	assert.Equal(t, []services.Resource{{Type: "target", ID: target}}, gotRes)
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Equal(t, true, out["dry_run"])
	assert.Equal(t, []any{}, out["untrusted"])
	assert.Equal(t, "Default", out["moves"].([]any)[0].(map[string]any)["from"].(map[string]any)["name"])
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPost, "/api/v1/services/"+svcPay.String()+"/actions/assign?dry_run=maybe",
		"admin-stepup", body).Code)
}

// The list filters (design §5.8): service_id and environment_id, repeatable, as a set of services.
func TestServiceFilter(t *testing.T) {
	d, _ := servicesDeps(t)
	s := newServer(d)
	filter := func(q string) ([]uuid.UUID, validate.Errors) {
		var v validate.Errors
		r := newJSONRequest(http.MethodGet, "/api/v1/targets?"+q, "")
		// A global grant: the filter is not narrowed by a reach (a person without one sees no service's name).
		r = r.WithContext(context.WithValue(r.Context(), principalKey{}, auth.Principal{Kind: rbac.UserSession, Role: rbac.Auditor}))
		got := s.serviceFilter(r, &v)
		return got, v
	}
	got, v := filter("")
	assert.Nil(t, got, "no filter")
	assert.Empty(t, v)
	got, _ = filter("environment_id=" + envProd.String())
	assert.Equal(t, []uuid.UUID{svcPay}, got)
	got, _ = filter("service_id=" + svcDefault.String() + "&service_id=" + svcPay.String() + "&environment_id=" + envProd.String())
	assert.Equal(t, []uuid.UUID{svcPay}, got, "both filters intersect")
	got, _ = filter("service_id=" + uuid.NewString())
	assert.Equal(t, []uuid.UUID{}, got, "an unknown service matches nothing")
	_, v = filter("service_id=x")
	assert.Equal(t, "service_id", v[0].Field)
}

// Rows show their service by name (design §8.2); without the services module only its id.
func TestRowsShowTheirService(t *testing.T) {
	d, _ := servicesDeps(t)
	tg := sampleTarget()
	tg.ServiceID = svcPay
	other := sampleTarget()
	other.ID, other.Name, other.ServiceID = uuid.New(), "web-2", svcDefault
	d.Inventory.(*fakeInventory).ListTargetsFn = func(context.Context) ([]inventory.Target, error) { return []inventory.Target{tg, other}, nil }
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/targets?environment_id="+envProd.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list struct {
		Items []struct {
			Name    string         `json:"name"`
			Service map[string]any `json:"service"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list.Items, 1, "the filter keeps the production service's server")
	assert.Equal(t, "Payments", list.Items[0].Service["name"])
	assert.Equal(t, "production", list.Items[0].Service["environment"].(map[string]any)["key"])
	raw, err := json.Marshal(targetJSON(tg, serviceRefs{}))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"service":{"id":"`+svcPay.String()+`","name":"","environment":null}`)
}

// newJSONRequest is a request with an optional JSON body (no identity yet: as adds one).
func newJSONRequest(method, target, body string) *http.Request {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// R55: the policy is saved with the version read and the whole document; a global Administrator may change the domains;
// every refusal of a policy has its code, params and field.
func TestPutServicePolicy(t *testing.T) {
	d, f := servicesDeps(t)
	var (
		gotVersion int
		gotBody    string
		gotGlobal  bool
	)
	f.SetPolicyFn = func(_ uuid.UUID, version int, body json.RawMessage, global bool) (services.Policy, error) {
		gotVersion, gotBody, gotGlobal = version, string(body), global
		return services.Policy{Version: version + 1, Document: json.RawMessage(`{"schema":1}`), CreatedAt: testNow}, nil
	}
	h := NewHandler(d)
	path := "/api/v1/services/" + svcPay.String() + "/policy"
	rec := call(h, http.MethodPut, path, "admin-stepup", `{"version":4,"body":{"schema":1,"domains":["*.pay.example.com"]}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 4, gotVersion)
	assert.JSONEq(t, `{"schema":1,"domains":["*.pay.example.com"]}`, gotBody)
	assert.True(t, gotGlobal, "a global Administrator may change the domains")
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.EqualValues(t, 5, body["version"])

	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPut, path, "admin-stepup", `{"body":{"schema":1}}`).Code, "no version")
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPut, path, "admin-stepup", `{"version":1}`).Code, "no body")
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPut, path, "admin-stepup", `{"version":1,"body":{},"x":1}`).Code)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPut, path, "admin", `{"version":1,"body":{"schema":1}}`).Code, "step-up")
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPut, path, "operator-stepup", `{"version":1,"body":{"schema":1}}`).Code)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPut, path, "alice_operate_admin", `{"version":1,"body":{"schema":1}}`).Code, "never a token")

	for err, want := range map[error]struct {
		status int
		code   string
		params map[string]any
		field  string
	}{
		services.ErrPolicyVersion:                                 {http.StatusConflict, "ALC-SVC-0010", nil, ""},
		services.ErrDomainsGlobalOnly:                             {http.StatusForbidden, "ALC-SVC-0011", nil, ""},
		authz.ErrPolicyMalformed:                                  {http.StatusBadRequest, "ALC-SYS-0004", nil, ""},
		&authz.FieldUnavailableError{Key: "drift"}:                {http.StatusUnprocessableEntity, "ALC-SVC-0015", map[string]any{"field": "drift"}, "body.drift"},
		&authz.DomainError{Name: "x.example.org", Field: "names"}: {http.StatusUnprocessableEntity, "ALC-SVC-0008", map[string]any{"name": "x.example.org"}, "names"},
		&authz.DomainError{Name: "bad\nname", Field: "names"}:     {http.StatusUnprocessableEntity, "ALC-SVC-0008", map[string]any{}, "names"},
		&authz.SourceError{Source: "uploaded"}:                    {http.StatusUnprocessableEntity, "ALC-SVC-0009", map[string]any{"source": "uploaded"}, ""},
		&authz.ACMEPolicyError{Field: "challenge"}:                {http.StatusUnprocessableEntity, "ALC-SVC-0014", map[string]any{"field": "challenge"}, "challenge"},
		authz.ErrAutoDeployForbidden:                              {http.StatusUnprocessableEntity, "ALC-SVC-0013", nil, ""},
	} {
		f.SetPolicyFn = func(uuid.UUID, int, json.RawMessage, bool) (services.Policy, error) { return services.Policy{}, err }
		rec := call(h, http.MethodPut, path, "admin-stepup", `{"version":1,"body":{"schema":1}}`)
		assert.Equal(t, want.status, rec.Code, "%v", err)
		var e struct {
			Error struct {
				Code    string         `json:"code"`
				Params  map[string]any `json:"params"`
				Details []struct {
					Field string `json:"field"`
				} `json:"details"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &e))
		assert.Equal(t, want.code, e.Error.Code, "%v", err)
		switch {
		case want.params == nil:
		case len(want.params) == 0:
			assert.Empty(t, e.Error.Params, "%v: a name that is not a host name is not repeated", err)
		default:
			assert.Equal(t, want.params, e.Error.Params, "%v", err)
		}
		if want.field != "" {
			require.Len(t, e.Error.Details, 1, "%v", err)
			assert.Equal(t, want.field, e.Error.Details[0].Field)
		}
	}
}

// SR-28 (R56, design §7.1, §8.1): the owner team is read by everyone who sees the service (whether a role reaches the
// service only by a caller who reads people) and replaced by a global Administrator with step-up, never a token.
func TestServiceOwnersRoutes(t *testing.T) {
	d, f := servicesDeps(t)
	olga, group := uuid.New(), uuid.New()
	team := services.Owners{Version: 3, Items: []services.Owner{
		{ID: uuid.New(), UserID: &olga, Username: "olga", DisplayName: "Olga", HasEmail: true, CreatedAt: testNow},
		{ID: uuid.New(), DirectoryGroupID: &group, Group: &services.GroupRef{Source: "oidc", SourceName: "IdP", Value: "pay-ops"}, Members: 4,
			ReachesService: true, CreatedAt: testNow},
	}}
	f.OwnersFn = func(uuid.UUID) (services.Owners, error) { return team, nil }
	var (
		gotVersion int
		gotIn      []services.OwnerInput
	)
	f.SetOwnersFn = func(_ uuid.UUID, version int, in []services.OwnerInput) (services.Owners, error) {
		gotVersion, gotIn = version, in
		return team, nil
	}
	h := NewHandler(d)
	path := "/api/v1/services/" + svcPay.String() + "/owners"

	rec := call(h, http.MethodGet, path, "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"version":3,"items":[
{"id":"`+team.Items[0].ID.String()+`","kind":"person","user_id":"`+olga.String()+`","username":"olga","display_name":"Olga","disabled":false,
 "receives_email":true,"directory_group_id":null,"members":0,"reaches_service":false,"created_at":"`+testNow.Format(time.RFC3339)+`"},
{"id":"`+team.Items[1].ID.String()+`","kind":"group","user_id":null,"disabled":false,"receives_email":false,"directory_group_id":"`+group.String()+`",
 "group":{"source":"oidc","source_name":"IdP","value":"pay-ops","label":""},"members":4,"reaches_service":true,"created_at":"`+testNow.Format(time.RFC3339)+`"}]}`,
		rec.Body.String())
	for _, who := range []string{"operator", "auditor"} {
		rec = call(h, http.MethodGet, path, who, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "reaches_service", "%s: who holds a role is People & access's (users.read)", who)
	}

	rec = call(h, http.MethodPut, path, "admin-stepup", `{"version":3,"owners":[{"user_id":"`+olga.String()+`"},{"directory_group_id":"`+group.String()+`"}]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 3, gotVersion)
	assert.Equal(t, []services.OwnerInput{{UserID: olga}, {DirectoryGroupID: group}}, gotIn)
	assert.Equal(t, "admin", f.lastActor.Audit.Name)

	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPut, path, "admin-stepup", `{"owners":[]}`).Code, "no version")
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPut, path, "admin-stepup", `{"version":3}`).Code, "no owners")
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPut, path, "admin-stepup", `{"version":3,"owners":[{"email":"x@example.com"}]}`).Code)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPut, path, "admin", `{"version":3,"owners":[]}`).Code, "step-up")
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPut, path, "operator-stepup", `{"version":3,"owners":[]}`).Code)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPut, path, "alice_operate_admin", `{"version":3,"owners":[]}`).Code, "never a token")

	for err, want := range map[error]struct {
		status int
		code   string
		field  string
	}{
		services.ErrOwnersVersion: {http.StatusConflict, "ALC-SVC-0010", ""},
		services.ErrNotFound:      {http.StatusNotFound, "ALC-SVC-0001", ""},
		&services.OwnerNotAPersonError{Field: "owners.1.user_id"}: {http.StatusUnprocessableEntity, "ALC-SVC-0019", "owners.1.user_id"},
	} {
		f.SetOwnersFn = func(uuid.UUID, int, []services.OwnerInput) (services.Owners, error) { return services.Owners{}, err }
		rec := call(h, http.MethodPut, path, "admin-stepup", `{"version":3,"owners":[]}`)
		assert.Equal(t, want.status, rec.Code, "%v", err)
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Details []struct {
					Field string `json:"field"`
				} `json:"details"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &e))
		assert.Equal(t, want.code, e.Error.Code, "%v", err)
		if want.field != "" {
			require.Len(t, e.Error.Details, 1)
			assert.Equal(t, want.field, e.Error.Details[0].Field)
		}
	}
}
