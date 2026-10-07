package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
)

func sampleUser(id uuid.UUID, name string, role rbac.Role) auth.User {
	last := testNow.Add(-time.Hour)
	return auth.User{ID: id, Username: name, DisplayName: "Çağla " + name, Email: name + "@example.com",
		Role: role, Locale: "tr", MFAEnrolled: true, LastLoginAt: &last, CreatedAt: testNow.Add(-24 * time.Hour)}
}

func TestListUsers(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).ListUsersFn = func(context.Context) ([]auth.User, error) {
		return []auth.User{sampleUser(adminID, "admin", rbac.Admin), sampleUser(operatorID, "operator", rbac.Operator)}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/users", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"items":[
	  {"id":"0190f5a0-0000-7000-8000-000000000001","username":"admin","display_name":"Çağla admin","email":"admin@example.com","role":"admin","locale":"tr","disabled":false,"mfa_enrolled":true,"last_login_at":"2026-09-30T11:00:00Z","created_at":"2026-09-29T12:00:00Z","auth_source":"local","sso_provider_id":null},
	  {"id":"0190f5a0-0000-7000-8000-000000000002","username":"operator","display_name":"Çağla operator","email":"operator@example.com","role":"operator","locale":"tr","disabled":false,"mfa_enrolled":true,"last_login_at":"2026-09-30T11:00:00Z","created_at":"2026-09-29T12:00:00Z","auth_source":"local","sso_provider_id":null}]}`, rec.Body.String())
}

func TestListUsersIsEmptyArrayNotNull(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).ListUsersFn = func(context.Context) ([]auth.User, error) { return nil, nil }
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/users", "admin", "")
	assert.JSONEq(t, `{"items":[]}`, rec.Body.String())
}

func TestCreateUser(t *testing.T) {
	d := testDeps(t, nil)
	var got auth.NewUser
	d.Auth.(*fakeAuth).CreateUserFn = func(_ context.Context, p auth.Principal, _ auth.Meta, in auth.NewUser) (auth.User, error) {
		got = in
		assert.Equal(t, adminID, p.UserID)
		return sampleUser(auditorID, in.Username, in.Role), nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/users", "admin-stepup",
		`{"username":"denetci","display_name":"Ömer Işık","email":"","role":"auditor","password":"uzun ve güvenli parola"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, auth.NewUser{Username: "denetci", DisplayName: "Ömer Işık", Role: rbac.Auditor, Password: "uzun ve güvenli parola"}, got)
	assert.Contains(t, rec.Body.String(), `"role":"auditor"`)
	assert.NotContains(t, rec.Body.String(), "uzun ve güvenli parola")

	rec = call(h, http.MethodPost, "/api/v1/users", "admin-stepup",
		`{"username":"x1","display_name":"X","email":"","role":"root","password":"uzun ve güvenli parola"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), `{"field":"role","code":"validation.one_of","params":{"values":"admin, operator, auditor"}}`)
}

func TestCreateUserMapsServiceErrors(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).CreateUserFn = func(context.Context, auth.Principal, auth.Meta, auth.NewUser) (auth.User, error) {
		return auth.User{}, auth.ErrUsernameTaken
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/users", "admin-stepup",
		`{"username":"ADMIN","display_name":"Dup","email":"","role":"operator","password":"uzun ve güvenli parola"}`)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-USR-0001", decodeErr(t, rec).Error.Code)
}

func TestGetUser(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).GetUserFn = func(_ context.Context, id uuid.UUID) (auth.User, error) {
		if id == operatorID {
			return sampleUser(operatorID, "operator", rbac.Operator), nil
		}
		return auth.User{}, auth.ErrNotFound
	}
	h := NewHandler(d)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/users/"+operatorID.String(), "admin", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/users/"+uuid.NewString(), "admin", "").Code)
	rec := call(h, http.MethodGet, "/api/v1/users/not-a-uuid", "admin", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "ALC-SYS-0001", decodeErr(t, rec).Error.Code)
}

func TestUpdateUserPassesOnlyGivenFields(t *testing.T) {
	d := testDeps(t, nil)
	var got auth.UserUpdate
	d.Auth.(*fakeAuth).UpdateUserFn = func(_ context.Context, _ auth.Principal, _ auth.Meta, id uuid.UUID, in auth.UserUpdate) (auth.User, error) {
		got = in
		return sampleUser(id, "operator", rbac.Auditor), nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPatch, "/api/v1/users/"+operatorID.String(), "admin-stepup", `{"role":"auditor","disabled":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, got.Role)
	assert.Equal(t, rbac.Auditor, *got.Role)
	require.NotNil(t, got.Disabled)
	assert.True(t, *got.Disabled)
	assert.Nil(t, got.DisplayName)
	assert.Nil(t, got.Email)

	rec = call(h, http.MethodPatch, "/api/v1/users/"+operatorID.String(), "admin-stepup", `{"role":"superuser"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestUpdateUserLastAdmin(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).UpdateUserFn = func(context.Context, auth.Principal, auth.Meta, uuid.UUID, auth.UserUpdate) (auth.User, error) {
		return auth.User{}, auth.ErrLastAdmin
	}
	rec := call(NewHandler(d), http.MethodPatch, "/api/v1/users/"+adminID.String(), "admin-stepup", `{"disabled":true}`)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-USR-0002", decodeErr(t, rec).Error.Code)
}

func TestUserActions(t *testing.T) {
	d := testDeps(t, nil)
	fa := d.Auth.(*fakeAuth)
	var calls []string
	fa.ResetMFAFn = func(_ context.Context, _ auth.Principal, _ auth.Meta, id uuid.UUID) error {
		calls = append(calls, "mfa:"+id.String())
		return nil
	}
	fa.ResetPasswordFn = func(_ context.Context, _ auth.Principal, _ auth.Meta, id uuid.UUID, pw string) error {
		calls = append(calls, "password:"+pw)
		return nil
	}
	fa.RevokeSessionsFn = func(_ context.Context, _ auth.Principal, _ auth.Meta, id uuid.UUID) error {
		calls = append(calls, "sessions:"+id.String())
		return nil
	}
	h := NewHandler(d)
	base := "/api/v1/users/" + operatorID.String() + "/actions/"
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, base+"reset-mfa", "admin-stepup", "").Code)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, base+"reset-password", "admin-stepup", `{"password":"yeni uzun parola 42"}`).Code)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, base+"revoke-sessions", "admin-stepup", "").Code)
	assert.Equal(t, []string{"mfa:" + operatorID.String(), "password:yeni uzun parola 42", "sessions:" + operatorID.String()}, calls)

	assert.Equal(t, http.StatusNotFound, call(h, http.MethodPost, "/api/v1/users/nope/actions/reset-mfa", "admin-stepup", "").Code)
}
