package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
)

func TestLoginSetsPendingCookie(t *testing.T) {
	d := testDeps(t, nil)
	var user, pass string
	d.Auth.(*fakeAuth).LoginFn = func(_ context.Context, u, p string, _ auth.Meta) (auth.LoginResult, error) {
		user, pass = u, p
		return auth.LoginResult{Status: "mfa_required", SessionToken: "pending-token"}, nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/auth/login", "", `{"username":"Admin","password":"correct horse battery"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"status":"mfa_required","csrf_token":"csrf-pending-token"}`, rec.Body.String())
	assert.Equal(t, "Admin", user)
	assert.Equal(t, "correct horse battery", pass)
	c := cookieNamed(rec, sessionCookie)
	assertStrictCookie(t, c)
	assert.Equal(t, "pending-token", c.Value)
}

func TestLoginFailureIsGenericAndSetsNoCookie(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).LoginFn = func(context.Context, string, string, auth.Meta) (auth.LoginResult, error) {
		return auth.LoginResult{}, auth.ErrInvalidCredentials
	}
	req := `{"username":"nobody","password":"wrong password here"}`
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/auth/login", "", req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	b := decodeErr(t, rec)
	assert.Equal(t, "ALC-AUTH-0005", b.Error.Code)
	assert.Contains(t, b.Error.Message, "Incorrect username or password.")
	assert.NotContains(t, rec.Body.String(), "wrong password here")
	assert.Nil(t, cookieNamed(rec, sessionCookie))
}

func TestLoginRejectsUnknownFieldsAndHugeBodies(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	rec := call(h, http.MethodPost, "/api/v1/auth/login", "", `{"username":"a","password":"b","role":"admin"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "ALC-SYS-0004", decodeErr(t, rec).Error.Code)

	rec = call(h, http.MethodPost, "/api/v1/auth/login", "", `{"username":"a","password":"`+strings.Repeat("x", maxBody)+`"}`)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Equal(t, "ALC-SYS-0007", decodeErr(t, rec).Error.Code)
}

// The OpenAPI limits of the login body (username 64, password 1024 characters) are
// enforced with the standard validation error before any credential is checked.
func TestLoginEnforcesTheSpecLengthLimits(t *testing.T) {
	d := testDeps(t, nil)
	calls := 0
	d.Auth.(*fakeAuth).LoginFn = func(context.Context, string, string, auth.Meta) (auth.LoginResult, error) {
		calls++
		return auth.LoginResult{Status: "mfa_required", SessionToken: "pending-token"}, nil
	}
	h := NewHandler(d)
	body := func(u, p string) string {
		b, err := json.Marshal(map[string]string{"username": u, "password": p})
		require.NoError(t, err)
		return string(b)
	}

	rec := call(h, http.MethodPost, "/api/v1/auth/login", "", body(strings.Repeat("ş", 64), strings.Repeat("ğ", 1024)))
	require.Equal(t, http.StatusOK, rec.Code, "limits count characters, not bytes: %s", rec.Body.String())
	require.Equal(t, 1, calls)

	rec = call(h, http.MethodPost, "/api/v1/auth/login", "", body(strings.Repeat("a", 65), "password"))
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "ALC-SYS-0006", decodeErr(t, rec).Error.Code)
	assert.Contains(t, rec.Body.String(), `"field":"username","code":"validation.too_long","params":{"max":"64"}`)

	long := strings.Repeat("p", 1025)
	rec = call(h, http.MethodPost, "/api/v1/auth/login", "", body("admin", long))
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), `"field":"password","code":"validation.too_long","params":{"max":"1024"}`)
	assert.NotContains(t, rec.Body.String(), long)
	assert.Equal(t, 1, calls, "an over-long request never reaches the credential check")
}

func TestEnrollMFAForPendingSession(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).EnrollMFAFn = func(_ context.Context, p auth.Principal, _ auth.Meta) (auth.TOTPEnrollment, error) {
		assert.Equal(t, rbac.PendingSession, p.Kind)
		return auth.TOTPEnrollment{Secret: "S", URI: "otpauth://totp/Alice:operator?secret=S", QRPNG: []byte("png")}, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/auth/mfa/enroll", "pending", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"secret":"S","otpauth_uri":"otpauth://totp/Alice:operator?secret=S","qr_png":"cG5n"}`, rec.Body.String())

	d.Auth.(*fakeAuth).EnrollMFAFn = func(context.Context, auth.Principal, auth.Meta) (auth.TOTPEnrollment, error) {
		return auth.TOTPEnrollment{}, auth.ErrMFAAlreadyEnrolled
	}
	rec = call(h, http.MethodPost, "/api/v1/auth/mfa/enroll", "pending", "")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-AUTH-0007", decodeErr(t, rec).Error.Code)
}

func TestVerifyMFARotatesCookieAndReturnsRecoveryCodes(t *testing.T) {
	d := testDeps(t, nil)
	var in auth.MFAInput
	d.Auth.(*fakeAuth).VerifyMFAFn = func(_ context.Context, p auth.Principal, got auth.MFAInput, _ auth.Meta) (auth.SessionResult, error) {
		in = got
		assert.Equal(t, rbac.PendingSession, p.Kind)
		return sampleSession("new-full", []string{"AAAA-BBBB-CCCC-DDDD"}), nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/auth/mfa/verify", "pending", `{"code":"123456"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, auth.MFAInput{Code: "123456"}, in)
	c := cookieNamed(rec, sessionCookie)
	assertStrictCookie(t, c)
	assert.Equal(t, "new-full", c.Value)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "csrf-new-full", body["csrf_token"])
	assert.Equal(t, []any{"AAAA-BBBB-CCCC-DDDD"}, body["recovery_codes"])
}

func TestVerifyMFAWithRecoveryCodeAndErrors(t *testing.T) {
	d := testDeps(t, nil)
	var in auth.MFAInput
	d.Auth.(*fakeAuth).VerifyMFAFn = func(_ context.Context, _ auth.Principal, got auth.MFAInput, _ auth.Meta) (auth.SessionResult, error) {
		in = got
		return auth.SessionResult{}, auth.ErrMFAInvalid
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/auth/mfa/verify", "pending", `{"recovery_code":"aaaa-bbbb-cccc-dddd"}`)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "ALC-AUTH-0006", decodeErr(t, rec).Error.Code)
	assert.Equal(t, "aaaa-bbbb-cccc-dddd", in.RecoveryCode)

	rec = call(h, http.MethodPost, "/api/v1/auth/mfa/verify", "pending", `{}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), `"field":"code","code":"validation.required"`)

	rec = call(h, http.MethodPost, "/api/v1/auth/mfa/verify", "admin", `{"code":"123456"}`)
	assert.Equal(t, http.StatusForbidden, rec.Code, "a full session cannot use the MFA step")
}

func TestSessionReturnsUserAndCSRFToken(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).SessionInfoFn = func(_ context.Context, p auth.Principal, tok string) (auth.SessionInfo, error) {
		assert.Equal(t, "operator", tok)
		assert.Equal(t, operatorID, p.UserID)
		info := sampleSession(tok, nil).Info
		info.StepUpUntil = nil
		return info, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/auth/session", "operator", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "csrf-operator", body["csrf_token"])
	assert.Nil(t, body["stepup_until"])
	assert.NotContains(t, body, "recovery_codes")
	assert.Equal(t, "2026-09-30T12:30:00Z", body["idle_expires_at"])

	assert.Equal(t, http.StatusUnauthorized, call(NewHandler(d), http.MethodGet, "/api/v1/auth/session", "expired", "").Code)
}

func TestLogoutClearsCookie(t *testing.T) {
	d := testDeps(t, nil)
	var loggedOut uuid.UUID
	d.Auth.(*fakeAuth).LogoutFn = func(_ context.Context, p auth.Principal, _ auth.Meta) error {
		loggedOut = p.UserID
		return nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/auth/logout", "auditor", "")
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, auditorID, loggedOut)
	c := cookieNamed(rec, sessionCookie)
	assertStrictCookie(t, c)
	assert.Equal(t, -1, c.MaxAge)
}

func TestStepUpRotatesCookie(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).StepUpFn = func(_ context.Context, _ auth.Principal, code string, _ auth.Meta) (auth.SessionResult, error) {
		if code != "654321" {
			return auth.SessionResult{}, auth.ErrMFAInvalid
		}
		return sampleSession("rotated", nil), nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/auth/stepup", "admin", `{"code":"654321"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "rotated", cookieNamed(rec, sessionCookie).Value)
	assert.Contains(t, rec.Body.String(), `"csrf_token":"csrf-rotated"`)

	rec = call(h, http.MethodPost, "/api/v1/auth/stepup", "admin", `{"code":"000000"}`)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Nil(t, cookieNamed(rec, sessionCookie))
}

func TestChangePassword(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).ChangePasswordFn = func(_ context.Context, _ auth.Principal, cur, next string, _ auth.Meta) (auth.SessionResult, error) {
		if cur != "old password 123" {
			return auth.SessionResult{}, auth.ErrCurrentPasswordInvalid
		}
		if next == "qwerty123456" {
			return auth.SessionResult{}, auth.ErrPasswordBreached
		}
		return sampleSession("after-change", nil), nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/auth/password", "operator", `{"current_password":"old password 123","new_password":"a much better passphrase"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "after-change", cookieNamed(rec, sessionCookie).Value)

	rec = call(h, http.MethodPost, "/api/v1/auth/password", "operator", `{"current_password":"nope","new_password":"a much better passphrase"}`)
	assert.Equal(t, "ALC-AUTH-0011", decodeErr(t, rec).Error.Code)
	rec = call(h, http.MethodPost, "/api/v1/auth/password", "operator", `{"current_password":"old password 123","new_password":"qwerty123456"}`)
	assert.Equal(t, "ALC-AUTH-0010", decodeErr(t, rec).Error.Code)
}

func TestRegenerateRecoveryCodesNeedsStepUp(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).RegenerateRecoveryCodesFn = func(context.Context, auth.Principal, auth.Meta) ([]string, error) {
		return []string{"1111-2222-3333-4444"}, nil
	}
	h := NewHandler(d)
	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, call(h, http.MethodPost, "/api/v1/auth/recovery-codes", "auditor", "")).Error.Code)
	rec := call(h, http.MethodPost, "/api/v1/auth/recovery-codes", "auditor-stepup", "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"recovery_codes":["1111-2222-3333-4444"]}`, rec.Body.String())
}

func TestSetLocale(t *testing.T) {
	d := testDeps(t, nil)
	var got string
	d.Auth.(*fakeAuth).SetLocaleFn = func(_ context.Context, _ auth.Principal, l string) error {
		got = l
		return nil
	}
	rec := call(NewHandler(d), http.MethodPut, "/api/v1/auth/locale", "operator", `{"locale":"tr"}`)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "tr", got)
}
