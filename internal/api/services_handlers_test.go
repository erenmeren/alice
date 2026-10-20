package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
)

// fakeServices is ServicesService for the handler tests: every method answers through its Fn, or errNotConfigured;
// Refs answers the services of refs.
type fakeServices struct {
	refs      map[uuid.UUID]authz.ServiceRef
	lastActor services.Actor

	CreateServiceFn func(in services.ServiceInput) (services.Service, error)
	UpdateServiceFn func(id uuid.UUID, version int, p services.ServicePatch) (services.Service, error)
	DeleteServiceFn func(id uuid.UUID, version int) error
	ServicesFn      func() ([]services.Service, error)
	AssignFn        func(dest uuid.UUID, resources []services.Resource, dryRun bool) (services.AssignResult, error)
	CreateTrustFn   func(source, target uuid.UUID) (services.Trust, error)
}

var _ ServicesService = (*fakeServices)(nil)

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
		got := s.serviceFilter(newJSONRequest(http.MethodGet, "/api/v1/targets?"+q, ""), &v)
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
	raw, err := json.Marshal(targetJSON(tg, nil))
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
