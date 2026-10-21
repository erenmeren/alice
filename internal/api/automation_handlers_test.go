package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
)

// fakeAutomation is AutomationService for the handler tests: every method answers through its Fn, or errNotConfigured.
type fakeAutomation struct {
	CreateFn      func(in auth.NewAutomationAccount) (auth.AutomationAccount, error)
	UpdateFn      func(id uuid.UUID, in auth.AutomationUpdate) (auth.AutomationAccount, error)
	CreateTokenFn func(id uuid.UUID, in auth.NewToken) (string, auth.Token, error)
}

var _ AutomationService = (*fakeAutomation)(nil)

func (f *fakeAutomation) ListAutomationAccounts(context.Context) ([]auth.AutomationAccount, error) {
	return nil, errNotConfigured
}

func (f *fakeAutomation) CreateAutomationAccount(_ context.Context, _ auth.Principal, _ auth.Meta, in auth.NewAutomationAccount) (auth.AutomationAccount, error) {
	if f.CreateFn == nil {
		return auth.AutomationAccount{}, errNotConfigured
	}
	return f.CreateFn(in)
}

func (f *fakeAutomation) UpdateAutomationAccount(_ context.Context, _ auth.Principal, _ auth.Meta, id uuid.UUID, in auth.AutomationUpdate) (auth.AutomationAccount, error) {
	if f.UpdateFn == nil {
		return auth.AutomationAccount{}, errNotConfigured
	}
	return f.UpdateFn(id, in)
}

func (f *fakeAutomation) ListAutomationTokens(context.Context, uuid.UUID) ([]auth.Token, error) {
	return nil, errNotConfigured
}

func (f *fakeAutomation) CreateAutomationToken(_ context.Context, _ auth.Principal, _ auth.Meta, id uuid.UUID, in auth.NewToken) (string, auth.Token, error) {
	if f.CreateTokenFn == nil {
		return "", auth.Token{}, errNotConfigured
	}
	return f.CreateTokenFn(id, in)
}

func (f *fakeAutomation) RevokeAutomationToken(context.Context, auth.Principal, auth.Meta, uuid.UUID, uuid.UUID) error {
	return errNotConfigured
}

// The automation account routes (R54): a role of null or absent is "none", admin is ALC-ACC-0002, an unknown role a
// validation error; PATCH tells an absent role from null; a token body takes service_ids; the answer shows a role of
// none as null.
func TestAutomationAccountRoutes(t *testing.T) {
	d := testDeps(t, nil)
	fa := &fakeAutomation{}
	d.Automation = fa
	var created []auth.NewAutomationAccount
	fa.CreateFn = func(in auth.NewAutomationAccount) (auth.AutomationAccount, error) {
		created = append(created, in)
		if in.Role == rbac.Admin {
			return auth.AutomationAccount{}, auth.ErrAutomationAdmin
		}
		return auth.AutomationAccount{ID: uuid.MustParse("0190f5a0-0000-7000-8000-0000000000c1"), Username: in.Username, DisplayName: in.DisplayName,
			Role: in.Role}, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/automation-accounts", "admin-stepup", `{"username":"ci","display_name":"CI"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"role":null`)
	assert.Equal(t, auth.NoGlobalRole, created[0].Role)
	rec = call(h, http.MethodPost, "/api/v1/automation-accounts", "admin-stepup", `{"username":"ci","display_name":"CI","role":"admin"}`)
	assertError(t, rec, http.StatusUnprocessableEntity, "ALC-ACC-0002")
	rec = call(h, http.MethodPost, "/api/v1/automation-accounts", "admin-stepup", `{"username":"ci","display_name":"CI","role":"root"}`)
	assertError(t, rec, http.StatusUnprocessableEntity, ErrValidation.Code)
	rec = call(h, http.MethodPost, "/api/v1/automation-accounts", "admin-stepup", `{"username":"ci","display_name":"CI","password":"x"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "no password field: an automation account never signs in")

	var update auth.AutomationUpdate
	fa.UpdateFn = func(_ uuid.UUID, in auth.AutomationUpdate) (auth.AutomationAccount, error) {
		update = in
		return auth.AutomationAccount{Role: rbac.Operator}, nil
	}
	path := "/api/v1/automation-accounts/0190f5a0-0000-7000-8000-0000000000c1"
	rec = call(h, http.MethodPatch, path, "admin-stepup", `{"disabled":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Nil(t, update.Role, "an absent role is unchanged")
	rec = call(h, http.MethodPatch, path, "admin-stepup", `{"role":null}`)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, update.Role)
	assert.Equal(t, auth.NoGlobalRole, *update.Role, "null removes the global role")

	var token auth.NewToken
	fa.CreateTokenFn = func(_ uuid.UUID, in auth.NewToken) (string, auth.Token, error) {
		token = in
		return "alice_secret", auth.Token{ServiceIDs: in.ServiceIDs}, nil
	}
	rec = call(h, http.MethodPost, path+"/tokens", "admin-stepup",
		`{"name":"ci","scope":"operate","expires_in_days":30,"service_ids":["0190f5a0-0000-7000-8000-0000000000d1"]}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, []uuid.UUID{uuid.MustParse("0190f5a0-0000-7000-8000-0000000000d1")}, token.ServiceIDs)
	assert.Contains(t, rec.Body.String(), `"service_ids":["0190f5a0-0000-7000-8000-0000000000d1"]`)
	rec = call(h, http.MethodPost, path+"/tokens", "admin-stepup", `{"name":"ci","scope":"operate","expires_in_days":30,"service_ids":null}`)
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Nil(t, token.ServiceIDs, "null: no limit")
	rec = call(h, http.MethodPost, path+"/tokens", "admin-stepup", `{"name":"ci","scope":"operate","expires_in_days":30,"service_ids":[]}`)
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.NotNil(t, token.ServiceIDs, "an empty list reaches auth, which refuses it")
	assert.Empty(t, token.ServiceIDs)

	d.Automation = nil
	rec = call(NewHandler(d), http.MethodGet, "/api/v1/automation-accounts", "admin", "")
	assertError(t, rec, http.StatusServiceUnavailable, ErrUnavailable.Code)
}

func assertError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	assert.Equal(t, status, rec.Code, rec.Body.String())
	assert.Equal(t, code, decodeErr(t, rec).Error.Code)
}
