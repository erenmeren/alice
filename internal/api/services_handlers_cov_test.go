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
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// covAServices is fakeServices with the reads the base fake leaves unconfigured: environments, one service, its policy
// and its versions, and the trusts. A nil Fn keeps the base fake's answer.
type covAServices struct {
	*fakeServices
	refsErr           error
	environmentsFn    func() ([]services.Environment, error)
	createEnvFn       func(in services.EnvironmentInput) (services.Environment, error)
	updateEnvFn       func(id uuid.UUID, version int, p services.EnvironmentPatch) (services.Environment, error)
	serviceFn         func(id uuid.UUID) (services.Service, error)
	policyFn          func(id uuid.UUID) (services.Policy, error)
	policyVersionsFn  func(id uuid.UUID) ([]services.Policy, error)
	trustsFn          func(service *uuid.UUID) ([]services.Trust, error)
	deleteTrustCalled bool
}

var _ ServicesService = (*covAServices)(nil)

func (f *covAServices) Refs(ctx context.Context) (map[uuid.UUID]authz.ServiceRef, error) {
	if f.refsErr != nil {
		return nil, f.refsErr
	}
	// A copy: serviceRefsFor marks the services outside a caller's reach in the map it is given.
	refs, _ := f.fakeServices.Refs(ctx)
	out := make(map[uuid.UUID]authz.ServiceRef, len(refs))
	for k, v := range refs {
		out[k] = v
	}
	return out, nil
}

func (f *covAServices) Environments(ctx context.Context) ([]services.Environment, error) {
	if f.environmentsFn != nil {
		return f.environmentsFn()
	}
	return f.fakeServices.Environments(ctx)
}

func (f *covAServices) CreateEnvironment(ctx context.Context, a services.Actor, in services.EnvironmentInput) (services.Environment, error) {
	if f.createEnvFn != nil {
		f.lastActor = a
		return f.createEnvFn(in)
	}
	return f.fakeServices.CreateEnvironment(ctx, a, in)
}

func (f *covAServices) UpdateEnvironment(ctx context.Context, a services.Actor, id uuid.UUID, version int, p services.EnvironmentPatch) (services.Environment, error) {
	if f.updateEnvFn != nil {
		f.lastActor = a
		return f.updateEnvFn(id, version, p)
	}
	return f.fakeServices.UpdateEnvironment(ctx, a, id, version, p)
}

func (f *covAServices) Service(ctx context.Context, id uuid.UUID) (services.Service, error) {
	if f.serviceFn != nil {
		return f.serviceFn(id)
	}
	return f.fakeServices.Service(ctx, id)
}

func (f *covAServices) Policy(ctx context.Context, id uuid.UUID) (services.Policy, error) {
	if f.policyFn != nil {
		return f.policyFn(id)
	}
	return f.fakeServices.Policy(ctx, id)
}

func (f *covAServices) PolicyVersions(ctx context.Context, id uuid.UUID) ([]services.Policy, error) {
	if f.policyVersionsFn != nil {
		return f.policyVersionsFn(id)
	}
	return f.fakeServices.PolicyVersions(ctx, id)
}

func (f *covAServices) Trusts(ctx context.Context, service *uuid.UUID) ([]services.Trust, error) {
	if f.trustsFn != nil {
		return f.trustsFn(service)
	}
	return f.fakeServices.Trusts(ctx, service)
}

func (f *covAServices) DeleteTrust(ctx context.Context, a services.Actor, id uuid.UUID) error {
	f.deleteTrustCalled = true
	return f.fakeServices.DeleteTrust(ctx, a, id)
}

// covAPayAdmin is a session of a person whose only grant is Administrator of the Payments service (no global role),
// stepped up.
const covAPayAdmin = "covA-pay-admin"

// covADeps are servicesDeps with covAServices and the covAPayAdmin session; the resolver places a service at itself and
// every other resource in Default.
func covADeps(t *testing.T) (Deps, *covAServices) {
	t.Helper()
	d, base := servicesDeps(t)
	f := &covAServices{fakeServices: base}
	base.ResolveFn = func(kind string, id any) (services.Resolution, error) {
		sid, _ := id.(uuid.UUID)
		switch kind {
		case services.KindService:
			if _, ok := base.refs[sid]; !ok {
				return services.Resolution{}, services.ErrResourceNotFound
			}
			return services.Resolution{Owning: sid, Visible: []uuid.UUID{sid}}, nil
		default:
			return services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault}}, nil
		}
	}
	d.Services = f
	fa := identityAuth(testNow)
	next := fa.AuthenticateFn
	fa.AuthenticateFn = func(ctx context.Context, tok string) (auth.Principal, error) {
		if tok == covAPayAdmin {
			uid := uuid.MustParse("0195e000-0000-7000-8000-0000000000a9")
			return auth.Principal{Kind: rbac.UserSession, UserID: uid, Username: "pay", DisplayName: "Pay", Role: auth.NoGlobalRole,
				Locale: "en", SessionHash: []byte(tok), StepUpUntil: testNow.Add(5 * time.Minute),
				Grants: []rbac.ScopedGrant{{Role: rbac.Admin, Services: []uuid.UUID{svcPay}}}}, nil
		}
		return next(ctx, tok)
	}
	d.Auth = fa
	return d, f
}

func covACallIfMatch(h http.Handler, method, target, id, body, version string) *httptest.ResponseRecorder {
	req := as(newJSONRequest(method, target, body), id)
	if version != "" {
		req.Header.Set("If-Match", version)
	}
	return serve(h, req)
}

// A build without the services module answers every service route 503 (ALC-SYS-0002) instead of failing on a nil
// module.
func TestServiceRoutesWithoutTheModuleAreUnavailable(t *testing.T) {
	d := testDeps(t, nil)
	d.Services = nil
	h := NewHandler(d)
	id := svcPay.String()
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/environments", ""},
		{http.MethodPost, "/api/v1/environments", `{"key":"qa","name":"QA"}`},
		{http.MethodPatch, "/api/v1/environments/" + id, `{"name":"QA"}`},
		{http.MethodDelete, "/api/v1/environments/" + id, ""},
		{http.MethodGet, "/api/v1/services", ""},
		{http.MethodPost, "/api/v1/services", `{"name":"x"}`},
		{http.MethodGet, "/api/v1/services/" + id, ""},
		{http.MethodPatch, "/api/v1/services/" + id, `{"name":"x"}`},
		{http.MethodDelete, "/api/v1/services/" + id, ""},
		{http.MethodGet, "/api/v1/services/" + id + "/policy", ""},
		{http.MethodGet, "/api/v1/services/" + id + "/policy/versions", ""},
		{http.MethodPut, "/api/v1/services/" + id + "/policy", `{"version":1,"body":{}}`},
		{http.MethodPost, "/api/v1/services/" + id + "/actions/assign", `{"resources":[]}`},
		{http.MethodGet, "/api/v1/service-trusts", ""},
		{http.MethodPost, "/api/v1/service-trusts", `{"source_service_id":"` + svcDefault.String() + `","target_service_id":"` + id + `"}`},
		{http.MethodDelete, "/api/v1/service-trusts/" + id, ""},
	} {
		rec := covACallIfMatch(h, c.method, c.path, "admin-stepup", c.body, `"1"`)
		require.Equalf(t, http.StatusServiceUnavailable, rec.Code, "%s %s: %s", c.method, c.path, rec.Body.String())
		assert.Equalf(t, "ALC-SYS-0002", decodeErr(t, rec).Error.Code, "%s %s", c.method, c.path)
	}
}

// The environments: listed, created and renamed with their ETag; a store failure is a server error; a malformed id is
// not found and a missing If-Match a failed precondition, before the store is asked.
func TestEnvironmentRoutes(t *testing.T) {
	d, f := covADeps(t)
	h := NewHandler(d)
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.FixedZone("TRT", 3*3600))
	prod := services.Environment{ID: envProd, Key: "production", Name: "Production", Sort: 10, Version: 3, Services: 2, CreatedAt: at, UpdatedAt: at}

	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, "/api/v1/environments", "auditor", "").Code)
	f.environmentsFn = func() ([]services.Environment, error) { return []services.Environment{prod}, nil }
	rec := call(h, http.MethodGet, "/api/v1/environments", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list struct {
		Items []environmentDTO `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list.Items, 1)
	assert.Equal(t, "production", list.Items[0].Key)
	assert.Equal(t, 2, list.Items[0].Services)
	assert.Equal(t, time.UTC, list.Items[0].CreatedAt.Location(), "times are answered in UTC")

	rec = call(h, http.MethodPost, "/api/v1/environments", "admin-stepup", `{"key":"qa","name":"QA"}`)
	assert.Equal(t, http.StatusInternalServerError, rec.Code, "a store failure")
	var gotIn services.EnvironmentInput
	f.createEnvFn = func(in services.EnvironmentInput) (services.Environment, error) {
		gotIn = in
		return services.Environment{ID: uuid.New(), Key: in.Key, Name: in.Name, Sort: in.Sort, Version: 1}, nil
	}
	rec = call(h, http.MethodPost, "/api/v1/environments", "admin-stepup", `{"key":"qa","name":"QA","sort":30}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, services.EnvironmentInput{Key: "qa", Name: "QA", Sort: 30}, gotIn)
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	assert.Equal(t, adminID, f.lastActor.UserID)

	var (
		gotID      uuid.UUID
		gotVersion int
		gotPatch   services.EnvironmentPatch
	)
	f.updateEnvFn = func(id uuid.UUID, version int, p services.EnvironmentPatch) (services.Environment, error) {
		gotID, gotVersion, gotPatch = id, version, p
		e := prod
		e.Name, e.Version = *p.Name, version+1
		return e, nil
	}
	rec = covACallIfMatch(h, http.MethodPatch, "/api/v1/environments/"+envProd.String(), "admin-stepup", `{"name":"Live"}`, `"3"`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, envProd, gotID)
	assert.Equal(t, 3, gotVersion)
	require.NotNil(t, gotPatch.Name)
	assert.Equal(t, "Live", *gotPatch.Name)
	assert.Nil(t, gotPatch.Sort, "an absent field is not changed")
	assert.Equal(t, `"4"`, rec.Header().Get("ETag"))

	f.updateEnvFn = func(uuid.UUID, int, services.EnvironmentPatch) (services.Environment, error) {
		t.Fatal("the store is not asked")
		return services.Environment{}, nil
	}
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		rec = covACallIfMatch(h, method, "/api/v1/environments/not-an-id", "admin-stepup", `{"name":"x"}`, `"1"`)
		assert.Equalf(t, http.StatusNotFound, rec.Code, "%s with a malformed id", method)
		rec = covACallIfMatch(h, method, "/api/v1/environments/"+envProd.String(), "admin-stepup", `{"name":"x"}`, "")
		assert.Equalf(t, http.StatusPreconditionFailed, rec.Code, "%s without If-Match", method)
	}
}

// GET /services: a malformed filter is a validation error, a store failure a server error; a person with role bindings
// sees the services in their reach only.
func TestListServicesFiltersAndReach(t *testing.T) {
	d, f := covADeps(t)
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/services?environment_id=prod", "auditor", "")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"environment_id"`)
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, "/api/v1/services", "auditor", "").Code)

	f.ServicesFn = func() ([]services.Service, error) {
		return []services.Service{{ID: svcDefault, Name: "Default", IsDefault: true, Version: 1},
			{ID: svcPay, Name: "Payments", Version: 2, Environment: f.refs[svcPay].Environment, Counts: services.Counts{Servers: 3}}}, nil
	}
	names := func(id string) []string {
		rec := call(h, http.MethodGet, "/api/v1/services", id, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var list struct {
			Items []serviceDTO `json:"items"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
		out := []string{}
		for _, it := range list.Items {
			out = append(out, it.Name)
		}
		return out
	}
	assert.Equal(t, []string{"Default", "Payments"}, names("auditor"))
	assert.Equal(t, []string{"Payments"}, names(covAPayAdmin), "a person with role bindings sees their services only")
}

// GET /services/{id} answers the service with its ETag, its policy and the policy's versions; a store failure is a
// server error.
func TestGetServiceAndItsPolicy(t *testing.T) {
	d, f := covADeps(t)
	h := NewHandler(d)
	base := "/api/v1/services/" + svcPay.String()

	assert.Equal(t, "ALC-SVC-0001", decodeErr(t, call(h, http.MethodGet, base, "auditor", "")).Error.Code)
	f.serviceFn = func(id uuid.UUID) (services.Service, error) {
		return services.Service{ID: id, Name: "Payments", Description: "card payments", PolicyVersion: 2, Version: 5,
			Environment: f.refs[svcPay].Environment, Counts: services.Counts{Certificates: 4}}, nil
	}
	rec := call(h, http.MethodGet, base, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `"5"`, rec.Header().Get("ETag"))
	var sv serviceDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &sv))
	assert.Equal(t, "card payments", sv.Description)
	assert.Equal(t, 4, sv.Counts.Certificates)
	require.NotNil(t, sv.Environment)
	assert.Equal(t, "production", sv.Environment.Key)

	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, base+"/policy", "auditor", "").Code)
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, base+"/policy/versions", "auditor", "").Code)
	by := uuid.New()
	p1 := services.Policy{Version: 1, Document: json.RawMessage(`{"domains":[]}`), CreatedAt: testNow}
	p2 := services.Policy{Version: 2, Document: json.RawMessage(`{"domains":["pay.example.test"]}`), CreatedBy: &by, CreatedByName: "Ayşe",
		CreatedAt: testNow}
	f.policyFn = func(id uuid.UUID) (services.Policy, error) {
		assert.Equal(t, svcPay, id)
		return p2, nil
	}
	f.policyVersionsFn = func(uuid.UUID) ([]services.Policy, error) { return []services.Policy{p2, p1}, nil }
	rec = call(h, http.MethodGet, base+"/policy", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"version":2,"body":{"domains":["pay.example.test"]},"created_by":"`+by.String()+`","created_by_name":"Ayşe",
		"created_at":"`+testNow.UTC().Format(time.RFC3339Nano)+`"}`, rec.Body.String())
	rec = call(h, http.MethodGet, base+"/policy/versions", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var versions struct {
		Items []servicePolicyDTO `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &versions))
	require.Len(t, versions.Items, 2)
	assert.Equal(t, 2, versions.Items[0].Version)
	assert.Nil(t, versions.Items[1].CreatedBy)
}

// A service id that is not an id is ALC-SVC-0001 and a missing If-Match ALC-SYS precondition, before the store is asked.
func TestServiceRoutesRefuseAMalformedIDOrNoVersion(t *testing.T) {
	d, f := covADeps(t)
	f.UpdateServiceFn = func(uuid.UUID, int, services.ServicePatch) (services.Service, error) {
		t.Fatal("the store is not asked")
		return services.Service{}, nil
	}
	f.DeleteServiceFn = func(uuid.UUID, int) error {
		t.Fatal("the store is not asked")
		return nil
	}
	h := NewHandler(d)
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPatch, "/api/v1/services/x", `{"name":"y"}`},
		{http.MethodDelete, "/api/v1/services/x", ""},
	} {
		rec := covACallIfMatch(h, c.method, c.path, "admin-stepup", c.body, `"1"`)
		require.Equalf(t, http.StatusNotFound, rec.Code, "%s %s", c.method, c.path)
		assert.Equal(t, "ALC-SVC-0001", decodeErr(t, rec).Error.Code)
	}
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		rec := covACallIfMatch(h, method, "/api/v1/services/"+svcPay.String(), "admin-stepup", `{"name":"y"}`, "")
		assert.Equalf(t, http.StatusPreconditionFailed, rec.Code, "%s without If-Match", method)
	}

	f.UpdateServiceFn = func(uuid.UUID, int, services.ServicePatch) (services.Service, error) {
		return services.Service{}, services.ErrNameTaken
	}
	rec := covACallIfMatch(h, http.MethodPatch, "/api/v1/services/"+svcPay.String(), "admin-stepup", `{"name":"Default"}`, `"2"`)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Equal(t, "ALC-SVC-0002", decodeErr(t, rec).Error.Code, "the store's refusal of a rename is answered")
}

// The handlers that read the id themselves refuse a malformed one with the service's not-found (reached directly: the
// router's resolver refuses it first).
func TestServiceHandlersRefuseAMalformedPathID(t *testing.T) {
	d, _ := covADeps(t)
	s := newServer(d)
	for name, handler := range map[string]http.HandlerFunc{
		"getService": s.getService, "getServicePolicy": s.getServicePolicy, "listServicePolicies": s.listServicePolicies,
		"putServicePolicy": s.putServicePolicy, "assignToService": s.assignToService,
	} {
		req := newJSONRequest(http.MethodGet, "/api/v1/services/x", `{}`)
		req.SetPathValue("id", "x")
		rec := httptest.NewRecorder()
		handler(rec, req)
		require.Equalf(t, http.StatusNotFound, rec.Code, "%s", name)
		assert.Equalf(t, "ALC-SVC-0001", decodeErr(t, rec).Error.Code, "%s", name)
	}
	req := newJSONRequest(http.MethodDelete, "/api/v1/service-trusts/x", "")
	req.SetPathValue("id", "x")
	rec := httptest.NewRecorder()
	s.deleteTrust(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// R49 Phase 2 (design §5.6): a person who administers Payments only may not pull a Default resource into Payments: the
// assignment needs services.assign on each resource's current service too. A failure to read where a resource is fails
// the request; a kind the store does not know is left to its refusal.
func TestAssignNeedsTheAssignPermissionOnTheResourcesService(t *testing.T) {
	d, f := covADeps(t)
	assigned := 0
	f.AssignFn = func(dest uuid.UUID, res []services.Resource, dryRun bool) (services.AssignResult, error) {
		assigned++
		return services.AssignResult{DryRun: dryRun, Destination: f.refs[dest],
			Untrusted: []services.UntrustedBinding{{Kind: "key_vault", SourceID: uuid.New(), SourceName: "vault-1", LocationID: uuid.New(),
				TargetID: uuid.New(), TargetName: "web-1", Source: f.refs[svcDefault], Target: f.refs[svcPay]}}}, nil
	}
	h := NewHandler(d)
	path := "/api/v1/services/" + svcPay.String() + "/actions/assign?dry_run=true"
	target := uuid.New()

	rec := call(h, http.MethodPost, path, covAPayAdmin, `{"resources":[{"type":"target","id":"`+target.String()+`"}]}`)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "ALC-SVC-0012", decodeErr(t, rec).Error.Code)
	assert.Zero(t, assigned, "nothing is assigned")

	base := f.ResolveFn
	f.ResolveFn = func(kind string, id any) (services.Resolution, error) {
		if kind == services.KindTarget {
			return services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}, nil // already in Payments
		}
		return base(kind, id)
	}
	rec = call(h, http.MethodPost, path, covAPayAdmin,
		`{"resources":[{"type":"target","id":"`+target.String()+`"},{"type":"planet","id":"`+uuid.NewString()+`"}]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, assigned)
	var out assignResultDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Len(t, out.Untrusted, 1)
	assert.Equal(t, "key_vault", out.Untrusted[0].Kind)
	assert.Equal(t, "Default", out.Untrusted[0].SourceService.Name)
	assert.Equal(t, "Payments", out.Untrusted[0].TargetService.Name)

	f.ResolveFn = func(kind string, id any) (services.Resolution, error) {
		if kind == services.KindTarget {
			return services.Resolution{}, errors.New("database gone")
		}
		return base(kind, id)
	}
	rec = call(h, http.MethodPost, path, covAPayAdmin, `{"resources":[{"type":"target","id":"`+target.String()+`"}]}`)
	assert.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Equal(t, 1, assigned)
}

// GET /service-trusts: service_id must be an id; a store failure is a server error; a person with role bindings sees
// the trusts with a side in their reach, the other side unnamed.
func TestListTrustsNamesOnlyTheSidesInReach(t *testing.T) {
	d, f := covADeps(t)
	h := NewHandler(d)
	other := uuid.MustParse("0195e000-0000-7000-8000-000000000003")
	f.refs[other] = authz.ServiceRef{ID: other, Name: "HR"}

	rec := call(h, http.MethodGet, "/api/v1/service-trusts?service_id=nope", "auditor", "")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"service_id"`)
	assert.Equal(t, http.StatusInternalServerError, call(h, http.MethodGet, "/api/v1/service-trusts", "auditor", "").Code)

	var asked *uuid.UUID
	f.trustsFn = func(service *uuid.UUID) ([]services.Trust, error) {
		asked = service
		return []services.Trust{
			{ID: uuid.New(), Source: f.refs[svcDefault], Target: f.refs[svcPay], CreatedByName: "admin", CreatedAt: testNow},
			{ID: uuid.New(), Source: f.refs[svcDefault], Target: f.refs[other], CreatedAt: testNow},
		}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/service-trusts?service_id="+svcDefault.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, asked)
	assert.Equal(t, svcDefault, *asked)
	var all struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &all))
	require.Len(t, all.Items, 2, "a global grant sees every trust")
	assert.Equal(t, "Default", all.Items[0]["source"].(map[string]any)["name"])

	rec = call(h, http.MethodGet, "/api/v1/service-trusts", covAPayAdmin, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var mine struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &mine))
	require.Len(t, mine.Items, 1, "the HR trust has no side in Payments")
	assert.Equal(t, map[string]any{"outside": true}, mine.Items[0]["source"], "Default is outside the caller's reach: unnamed")
	assert.Equal(t, "Payments", mine.Items[0]["target"].(map[string]any)["name"])
}

// POST /service-trusts answers the trust it created with both services named; DELETE reaches the store.
func TestCreateAndDeleteTrust(t *testing.T) {
	d, f := covADeps(t)
	var gotSource, gotTarget uuid.UUID
	f.CreateTrustFn = func(source, target uuid.UUID) (services.Trust, error) {
		gotSource, gotTarget = source, target
		return services.Trust{ID: uuid.New(), Source: f.refs[source], Target: f.refs[target], CreatedByName: "admin", CreatedAt: testNow}, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/service-trusts", "admin-stepup",
		`{"source_service_id":"`+svcDefault.String()+`","target_service_id":"`+svcPay.String()+`"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, svcDefault, gotSource)
	assert.Equal(t, svcPay, gotTarget)
	var tr serviceTrustDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tr))
	assert.Equal(t, "Default", tr.Source.Name)
	assert.Equal(t, "Payments", tr.Target.Name)
	assert.Equal(t, "production", tr.Target.Environment.Key)
	assert.Equal(t, "admin", tr.CreatedByName)

	f.ResolveFn = func(string, any) (services.Resolution, error) {
		return services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcDefault, svcPay}}, nil
	}
	rec = call(h, http.MethodDelete, "/api/v1/service-trusts/"+uuid.NewString(), "admin-stepup", "")
	assert.True(t, f.deleteTrustCalled)
	assert.Equal(t, http.StatusInternalServerError, rec.Code, "the store's failure is answered: %s", rec.Body.String())
}

// serviceRefs never fails an answer: without the module, or when the services cannot be read (logged), rows show the
// id alone; a service outside the caller's read reach is {"outside": true}.
func TestServiceRefsDegradeAndHideTheServicesOutsideReach(t *testing.T) {
	d, f := covADeps(t)
	auditor := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Auditor}
	req := newJSONRequest(http.MethodGet, "/api/v1/targets", "")

	refs := newServer(d).serviceRefsFor(req, auditor)
	require.NotNil(t, refs.of(svcPay))
	assert.Equal(t, "Payments", refs.of(svcPay).Name)

	scoped := rbac.Subject{Kind: rbac.UserSession, Grants: []rbac.ScopedGrant{{Role: rbac.Auditor, Services: []uuid.UUID{svcPay}}}}
	refs = newServer(d).serviceRefsFor(req, scoped)
	raw, err := json.Marshal(refs.of(svcDefault))
	require.NoError(t, err)
	assert.JSONEq(t, `{"outside":true}`, string(raw), "Default is outside the person's reach")
	assert.Equal(t, "Payments", refs.of(svcPay).Name)
	assert.Nil(t, refs.of(uuid.Nil), "no service")
	stranger := uuid.New()
	assert.Equal(t, &serviceRefDTO{ID: stranger}, refs.of(stranger), "a service the answer did not read shows its id alone")

	f.refsErr = errors.New("database gone")
	refs = newServer(d).serviceRefsFor(req, auditor)
	assert.Nil(t, refs.byID)
	assert.Equal(t, &serviceRefDTO{ID: svcPay}, refs.of(svcPay))

	d.Services = nil
	refs = newServer(d).serviceRefsFor(req, auditor)
	assert.Nil(t, refs.byID)
	assert.Equal(t, auditor, refs.subject)
}

// Without the services module a service_id filter is taken as given (sorted); an environment filter then matches
// nothing.
func TestServiceFilterWithoutTheModule(t *testing.T) {
	d := testDeps(t, nil)
	d.Services = nil
	s := newServer(d)
	filter := func(q string) []uuid.UUID {
		var v validate.Errors
		got := s.serviceFilter(newJSONRequest(http.MethodGet, "/api/v1/targets?"+q, ""), &v)
		require.Empty(t, v)
		return got
	}
	assert.Equal(t, []uuid.UUID{svcDefault, svcPay}, filter("service_id="+svcPay.String()+"&service_id="+svcDefault.String()))
	assert.Equal(t, []uuid.UUID{}, filter("environment_id="+envProd.String()))
}
