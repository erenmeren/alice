package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/rbac"
)

// Role bindings (R49 Phase 2): adding one is a global Administrator's with step-up, never a token; the body names a
// person, a role and a service or an environment, nothing else; the answer shows what the binding covers.
func TestCreateRoleBindingAnswersTheBinding(t *testing.T) {
	d, f := servicesDeps(t)
	person := uuid.MustParse("0195e000-0000-7000-8000-0000000000a1")
	var got services.BindingInput
	f.CreateBindingFn = func(in services.BindingInput) (services.Binding, error) {
		got = in
		pay := authz.ServiceRef{ID: svcPay, Name: "Payments"}
		return services.Binding{ID: uuid.New(), UserID: &person, Username: "olga", Role: rbac.Operator, Service: &pay,
			Services: []authz.ServiceRef{pay}, CreatedAt: testNow}, nil
	}
	h := NewHandler(d)
	body := `{"user_id":"` + person.String() + `","role":"operator","service_id":"` + svcPay.String() + `"}`
	rec := call(h, http.MethodPost, "/api/v1/role-bindings", "admin-stepup", body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, services.BindingInput{UserID: person, Role: "operator", ServiceID: &svcPay}, got)
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Equal(t, "operator", out["role"])
	assert.Equal(t, "Payments", out["service"].(map[string]any)["name"])
	assert.Len(t, out["services"], 1)
	assert.Nil(t, out["environment"])
	assert.NotEqual(t, uuid.Nil, f.lastActor.UserID, "the Administrator is recorded")

	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/role-bindings", "admin-stepup", `{"user_id":"x","owner":"y"}`).Code)
	assert.Equal(t, "auth.stepup_required", decodeErr(t, call(h, http.MethodPost, "/api/v1/role-bindings", "admin", body)).Error.Reason)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/role-bindings", "alice_operate_admin", body).Code, "never a token")
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/role-bindings", "operator-stepup", body).Code)

	f.CreateBindingFn = func(services.BindingInput) (services.Binding, error) { return services.Binding{}, services.ErrBindingDuplicate }
	assert.Equal(t, ErrACCBindingDuplicate.Code, decodeErr(t, call(h, http.MethodPost, "/api/v1/role-bindings", "admin-stepup", body)).Error.Code)
	f.CreateBindingFn = func(services.BindingInput) (services.Binding, error) { return services.Binding{}, services.ErrBindingLimit }
	assert.Equal(t, ErrACCBindingLimit.Code, decodeErr(t, call(h, http.MethodPost, "/api/v1/role-bindings", "admin-stepup", body)).Error.Code)
}

// Listing bindings is users.read (a global Administrator and read tokens); the filters are ids.
func TestListRoleBindingsFilters(t *testing.T) {
	d, f := servicesDeps(t)
	var got services.BindingFilter
	f.BindingsFn = func(fl services.BindingFilter) ([]services.Binding, error) {
		got = fl
		return nil, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/role-bindings?service_id="+svcPay.String(), "alice_read_admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `{"items":[]}`+"\n", rec.Body.String())
	require.NotNil(t, got.ServiceID)
	assert.Equal(t, svcPay, *got.ServiceID)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/role-bindings?user_id=nope", "admin", "").Code)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodGet, "/api/v1/role-bindings", "operator", "").Code)
}

// optionalRole tells an absent role (unchanged), null (no global role) and a role apart.
func TestOptionalRole(t *testing.T) {
	var req struct {
		Role optionalRole `json:"role"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{}`), &req))
	assert.False(t, req.Role.set)
	require.NoError(t, json.Unmarshal([]byte(`{"role":null}`), &req))
	assert.True(t, req.Role.set)
	r, ok := req.Role.role()
	assert.True(t, ok)
	assert.Equal(t, rbac.Role(""), r)
	req.Role = optionalRole{}
	require.NoError(t, json.Unmarshal([]byte(`{"role":"auditor"}`), &req))
	r, ok = req.Role.role()
	assert.True(t, ok)
	assert.Equal(t, rbac.Auditor, r)
	require.NoError(t, json.Unmarshal([]byte(`{"role":"root"}`), &req))
	_, ok = req.Role.role()
	assert.False(t, ok)
}
