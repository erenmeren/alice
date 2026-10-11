package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/setup"
)

// cookieNamed returns the Set-Cookie with the given name, or nil.
func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func assertStrictCookie(t *testing.T, c *http.Cookie) {
	t.Helper()
	require.NotNil(t, c)
	assert.True(t, strings.HasPrefix(c.Name, "__Host-"))
	assert.True(t, c.Secure)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
	assert.Equal(t, "/", c.Path)
	assert.Empty(t, c.Domain)
}

// sampleSession is a SessionResult as the services return it.
func sampleSession(token string, codes []string) auth.SessionResult {
	stepUp := testNow.Add(5 * time.Minute)
	return auth.SessionResult{
		Token: token,
		Info: auth.SessionInfo{
			User: auth.User{ID: adminID, Username: "admin", DisplayName: "Ayşe Yılmaz", Email: "ayse@example.com",
				Role: rbac.Admin, Locale: "tr", MFAEnrolled: true, CreatedAt: testNow},
			CSRFToken:     "csrf-" + token,
			ExpiresAt:     testNow.Add(12 * time.Hour),
			IdleExpiresAt: testNow.Add(30 * time.Minute),
			StepUpUntil:   &stepUp,
		},
		RecoveryCodes: codes,
	}
}

func TestSetupStatus(t *testing.T) {
	d := testDeps(t, nil)
	d.Setup.(*fakeSetup).StatusFn = func(context.Context) (setup.Status, error) {
		return setup.Status{AdminExists: true, RecoveryPassphraseSet: false, Completed: false, DefaultLocale: "tr"}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/setup/status", "", "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"admin_exists":true,"recovery_passphrase_set":false,"license_chosen":false,"completed":false,"default_locale":"tr","https_chosen":false,"mail_chosen":false,"next_step":""}`, rec.Body.String())
}

func TestSetupSessionSetsStrictCookieAndReturnsCSRFToken(t *testing.T) {
	d := testDeps(t, nil)
	var gotCode string
	d.Setup.(*fakeSetup).StartSessionFn = func(_ context.Context, code string, m auth.Meta) (string, error) {
		gotCode = code
		assert.Equal(t, "192.0.2.1", m.IP.String())
		return "wizard-token", nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/session", "", `{"code":"K7QX2M-9TPD4R-WB5H8N-3VZC6A"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "K7QX2M-9TPD4R-WB5H8N-3VZC6A", gotCode)
	assert.JSONEq(t, `{"csrf_token":"csrf-wizard-token"}`, rec.Body.String())
	c := cookieNamed(rec, setupCookie)
	assertStrictCookie(t, c)
	assert.Equal(t, "wizard-token", c.Value)
}

func TestSetupSessionErrors(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{setup.ErrCodeInvalid, http.StatusUnauthorized, "ALC-SET-0001"},
		{setup.ErrAlreadySetUp, http.StatusNotFound, "ALC-SYS-0001"},
		{&setup.LockedError{RetryAfter: 15 * time.Minute}, http.StatusTooManyRequests, "ALC-SET-0002"},
	}
	for _, tc := range cases {
		d := testDeps(t, nil)
		d.Setup.(*fakeSetup).StartSessionFn = func(context.Context, string, auth.Meta) (string, error) { return "", tc.err }
		rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/session", "", `{"code":"WRONG"}`)
		assert.Equal(t, tc.status, rec.Code, tc.code)
		assert.Equal(t, tc.code, decodeErr(t, rec).Error.Code)
		assert.Nil(t, cookieNamed(rec, setupCookie), tc.code)
		if tc.status == http.StatusTooManyRequests {
			assert.Equal(t, "900", rec.Header().Get("Retry-After"))
		}
	}
}

func TestSetupLanguageUsesTheWizardSession(t *testing.T) {
	d := testDeps(t, nil)
	var token, lang string
	d.Setup.(*fakeSetup).SetLanguageFn = func(_ context.Context, tok, l string) error {
		token, lang = tok, l
		return nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPut, "/api/v1/setup/language", "setup", `{"language":"tr"}`)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "setup-ok", token)
	assert.Equal(t, "tr", lang)

	rec = call(h, http.MethodPut, "/api/v1/setup/language", "", `{"language":"tr"}`)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "ALC-SET-0003", decodeErr(t, rec).Error.Code)
}

func TestSetupEnrollmentReturnsSecretAndQR(t *testing.T) {
	d := testDeps(t, nil)
	var got setup.AdminInput
	d.Setup.(*fakeSetup).BeginAdminEnrollmentFn = func(_ context.Context, _ string, in setup.AdminInput) (auth.TOTPEnrollment, error) {
		got = in
		return auth.TOTPEnrollment{Secret: "JBSWY3DPEHPK3PXP", URI: "otpauth://totp/Alice:admin?secret=JBSWY3DPEHPK3PXP", QRPNG: []byte{0x89, 'P', 'N', 'G'}}, nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/admin/enrollment", "setup",
		`{"username":"admin","display_name":"Ayşe Yılmaz","email":"ayse@example.com","password":"correct horse battery"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, setup.AdminInput{Username: "admin", DisplayName: "Ayşe Yılmaz", Email: "ayse@example.com", Password: "correct horse battery"}, got)
	assert.JSONEq(t, `{"secret":"JBSWY3DPEHPK3PXP","otpauth_uri":"otpauth://totp/Alice:admin?secret=JBSWY3DPEHPK3PXP","qr_png":"iVBORw=="}`, rec.Body.String())
}

func TestSetupEnrollmentValidationErrorsCarryDetails(t *testing.T) {
	d := testDeps(t, nil)
	d.Setup.(*fakeSetup).BeginAdminEnrollmentFn = func(context.Context, string, setup.AdminInput) (auth.TOTPEnrollment, error) {
		var v validate.Errors
		v.Add("username", validate.Pattern, nil)
		return auth.TOTPEnrollment{}, v
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/admin/enrollment", "setup",
		`{"username":"İsmail","display_name":"x","email":"","password":"correct horse battery"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), `"details":[{"field":"username","code":"validation.pattern"}]`)
}

func TestSetupCreateAdminSignsInAndClearsSetupCookie(t *testing.T) {
	d := testDeps(t, nil)
	d.Setup.(*fakeSetup).CreateAdminFn = func(_ context.Context, tok, code string, _ auth.Meta) (auth.SessionResult, error) {
		assert.Equal(t, "setup-ok", tok)
		assert.Equal(t, "123456", code)
		return sampleSession("full-session", []string{"AAAA-BBBB-CCCC-DDDD"}), nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/admin", "setup", `{"code":"123456"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	session := cookieNamed(rec, sessionCookie)
	assertStrictCookie(t, session)
	assert.Equal(t, "full-session", session.Value)
	cleared := cookieNamed(rec, setupCookie)
	assertStrictCookie(t, cleared)
	assert.Equal(t, -1, cleared.MaxAge)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "csrf-full-session", body["csrf_token"])
	assert.Equal(t, []any{"AAAA-BBBB-CCCC-DDDD"}, body["recovery_codes"])
	user := body["user"].(map[string]any)
	assert.Equal(t, "Ayşe Yılmaz", user["display_name"])
	assert.Equal(t, "admin", user["role"])
	assert.Nil(t, user["last_login_at"])
	assert.NotContains(t, rec.Body.String(), `"full-session"`, "the session token itself is never in the body")
}

func TestSetupCreateAdminWrongCodeKeepsSetupCookie(t *testing.T) {
	d := testDeps(t, nil)
	d.Setup.(*fakeSetup).CreateAdminFn = func(context.Context, string, string, auth.Meta) (auth.SessionResult, error) {
		return auth.SessionResult{}, auth.ErrMFAInvalid
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/admin", "setup", `{"code":"000000"}`)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "ALC-AUTH-0006", decodeErr(t, rec).Error.Code)
	assert.Nil(t, cookieNamed(rec, setupCookie))
	assert.Nil(t, cookieNamed(rec, sessionCookie))
}

func TestSetupRecoveryPassphrase(t *testing.T) {
	d := testDeps(t, nil)
	var pass, confirm string
	var who auth.Principal
	d.Setup.(*fakeSetup).SetRecoveryPassphraseFn = func(_ context.Context, p auth.Principal, _ auth.Meta, a, b string) error {
		who, pass, confirm = p, a, b
		if a != b {
			return setup.ErrPassphraseMismatch
		}
		return nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/setup/recovery-passphrase", "admin-stepup",
		`{"passphrase":"kırmızı elma yeşil armut","passphrase_confirm":"kırmızı elma yeşil armut"}`)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "kırmızı elma yeşil armut", pass)
	assert.Equal(t, pass, confirm)
	assert.Equal(t, adminID, who.UserID)

	rec = call(h, http.MethodPost, "/api/v1/setup/recovery-passphrase", "admin-stepup",
		`{"passphrase":"kırmızı elma yeşil armut","passphrase_confirm":"different words entirely"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "ALC-SET-0006", decodeErr(t, rec).Error.Code)

	rec = call(h, http.MethodPost, "/api/v1/setup/recovery-passphrase", "admin", `{"passphrase":"a","passphrase_confirm":"a"}`)
	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, "needs a fresh verification code")
}

func TestSetupComplete(t *testing.T) {
	d := testDeps(t, nil)
	d.Setup.(*fakeSetup).CompleteFn = func(context.Context, auth.Principal, auth.Meta) (setup.Status, error) {
		return setup.Status{AdminExists: true, RecoveryPassphraseSet: true, LicenseChosen: true, Completed: true, DefaultLocale: "en"}, nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/complete", "admin-stepup", "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"admin_exists":true,"recovery_passphrase_set":true,"license_chosen":true,"completed":true,"default_locale":"en","https_chosen":false,"mail_chosen":false,"next_step":""}`, rec.Body.String())

	d.Setup.(*fakeSetup).CompleteFn = func(context.Context, auth.Principal, auth.Meta) (setup.Status, error) {
		return setup.Status{}, setup.ErrIncomplete
	}
	rec = call(NewHandler(d), http.MethodPost, "/api/v1/setup/complete", "admin-stepup", "")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-SET-0008", decodeErr(t, rec).Error.Code)

	// The service repeats the settings.manage check (admin + step-up), so the route does too.
	rec = call(NewHandler(d), http.MethodPost, "/api/v1/setup/complete", "admin", "")
	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, "needs a fresh verification code")

	d.Setup.(*fakeSetup).CompleteFn = func(context.Context, auth.Principal, auth.Meta) (setup.Status, error) {
		return setup.Status{}, setup.ErrForbidden
	}
	rec = call(NewHandler(d), http.MethodPost, "/api/v1/setup/complete", "admin-stepup", "")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "ALC-AUTH-0002", decodeErr(t, rec).Error.Code)
}

// Spec 05 §18.5 rule 2: every wrong setup-code attempt is logged with the
// client address; the code itself never is.
func TestSetupSessionLogsRejectedCodesWithClientIP(t *testing.T) {
	cases := []error{setup.ErrCodeInvalid, &setup.LockedError{RetryAfter: time.Minute}}
	for _, failure := range cases {
		d := testDeps(t, nil)
		var logs bytes.Buffer
		d.Log = slog.New(slog.NewJSONHandler(&logs, nil))
		d.Setup.(*fakeSetup).StartSessionFn = func(context.Context, string, auth.Meta) (string, error) { return "", failure }
		call(NewHandler(d), http.MethodPost, "/api/v1/setup/session", "", `{"code":"GUESS1-GUESS2-GUESS3-GUESS4"}`)
		out := logs.String()
		assert.Contains(t, out, `"msg":"setup code rejected"`, failure.Error())
		assert.Contains(t, out, `"ip":"192.0.2.1"`, failure.Error())
		assert.Contains(t, out, `"request_id":`, failure.Error())
		assert.NotContains(t, out, "GUESS", failure.Error())
	}
}

// An administrator created in the meantime (another wizard session won the
// race) answers like every other wizard route after setup: 404 ALC-SYS-0001.
func TestSetupCreateAdminAfterSetupIsNotFound(t *testing.T) {
	d := testDeps(t, nil)
	d.Setup.(*fakeSetup).CreateAdminFn = func(context.Context, string, string, auth.Meta) (auth.SessionResult, error) {
		return auth.SessionResult{}, setup.ErrAlreadySetUp
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/admin", "setup", `{"code":"123456"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "ALC-SYS-0001", decodeErr(t, rec).Error.Code)
	assert.Nil(t, cookieNamed(rec, sessionCookie))
}

func TestSetupEvaluation(t *testing.T) {
	d := testDeps(t, nil)
	var got auth.Principal
	d.Setup.(*fakeSetup).ChooseEvaluationFn = func(_ context.Context, p auth.Principal, _ auth.Meta) (setup.Status, error) {
		got = p
		return setup.Status{AdminExists: true, RecoveryPassphraseSet: true, LicenseChosen: true, DefaultLocale: "en"}, nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/evaluation", "admin-stepup", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"admin_exists":true,"recovery_passphrase_set":true,"license_chosen":true,"completed":false,"default_locale":"en","https_chosen":false,"mail_chosen":false,"next_step":""}`, rec.Body.String())
	assert.Equal(t, "admin", got.Username)

	rec = call(NewHandler(d), http.MethodPost, "/api/v1/setup/evaluation", "admin", "")
	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, "settings.manage needs step-up")

	d.Setup.(*fakeSetup).CompleteFn = func(context.Context, auth.Principal, auth.Meta) (setup.Status, error) {
		return setup.Status{}, setup.ErrLicenseChoiceMissing
	}
	rec = call(NewHandler(d), http.MethodPost, "/api/v1/setup/complete", "admin-stepup", "")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-SET-0009", decodeErr(t, rec).Error.Code)
}
