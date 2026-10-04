package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/setup"
)

type probeBody struct {
	Name string `json:"name"`
}

// decodeHandler serves POST /api/v1/probe (public) and echoes the decoded name.
func decodeHandler(t *testing.T) http.Handler {
	t.Helper()
	s := newServer(testDeps(t, nil))
	return s.handler([]route{{method: http.MethodPost, pattern: "/api/v1/probe", perm: rbac.Public, lic: license.ClassAlways, handler: func(w http.ResponseWriter, r *http.Request) {
		var b probeBody
		if !s.decode(w, r, &b) {
			return
		}
		writeJSON(w, http.StatusOK, b)
	}}})
}

func TestDecodeAcceptsKnownFields(t *testing.T) {
	rec := call(decodeHandler(t), http.MethodPost, "/api/v1/probe", "", `{"name":"İzmir"}`)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"name":"İzmir"}`, rec.Body.String())
}

func TestDecodeRejectsUnknownFieldsBadJSONAndTrailingData(t *testing.T) {
	for _, body := range []string{`{"name":"a","role":"admin"}`, `{"name":`, `{"name":"a"}{"name":"b"}`, `[]`, ""} {
		rec := call(decodeHandler(t), http.MethodPost, "/api/v1/probe", "", body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, body)
		assert.Equal(t, "ALC-SYS-0004", decodeErr(t, rec).Error.Code, body)
	}
}

func TestDecodeRejectsBodiesOverOneMiB(t *testing.T) {
	big := `{"name":"` + strings.Repeat("a", maxBody) + `"}`
	rec := call(decodeHandler(t), http.MethodPost, "/api/v1/probe", "", big)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Equal(t, "ALC-SYS-0007", decodeErr(t, rec).Error.Code)
}

func TestCookiesUseHostPrefixAndStrictAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	setSessionCookie(rec, "tok")
	setSetupCookie(rec, "stp")
	clearSessionCookie(rec)
	clearSetupCookie(rec)
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 4)
	for _, c := range cookies {
		assert.True(t, strings.HasPrefix(c.Name, "__Host-"), c.Name)
		assert.True(t, c.Secure, c.Name)
		assert.True(t, c.HttpOnly, c.Name)
		assert.Equal(t, http.SameSiteStrictMode, c.SameSite, c.Name)
		assert.Equal(t, "/", c.Path, c.Name)
		assert.Empty(t, c.Domain, c.Name)
	}
	assert.Equal(t, sessionCookie, cookies[0].Name)
	assert.Equal(t, "tok", cookies[0].Value)
	assert.Equal(t, setupCookie, cookies[1].Name)
	assert.Equal(t, -1, cookies[2].MaxAge, "clearing expires the cookie")
	assert.Equal(t, setupCookie, cookies[3].Name)
	assert.Equal(t, -1, cookies[3].MaxAge)
}

func TestPathUUID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetPathValue("id", "0190f5a0-0000-7000-8000-000000000001")
	id, ok := pathUUID(req, "id")
	assert.True(t, ok)
	assert.Equal(t, adminID, id)

	req.SetPathValue("id", "not-a-uuid")
	_, ok = pathUUID(req, "id")
	assert.False(t, ok)
}

// failRecorder runs s.fail for err and returns the response.
func failRecorder(t *testing.T, err error, logs io.Writer) *httptest.ResponseRecorder {
	t.Helper()
	d := testDeps(t, nil)
	if logs != nil {
		d.Log = slog.New(slog.NewJSONHandler(logs, nil))
	}
	s := newServer(d)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	req.Header.Set("Accept-Language", "tr")
	rec := httptest.NewRecorder()
	s.requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.fail(w, r, err) })).ServeHTTP(rec, req)
	return rec
}

func TestFailMapsDomainErrors(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{auth.ErrInvalidCredentials, 401, "ALC-AUTH-0005"},
		{fmt.Errorf("wrapped: %w", auth.ErrMFAInvalid), 401, "ALC-AUTH-0006"},
		{auth.ErrNotFound, 404, "ALC-SYS-0001"},
		{auth.ErrUnauthenticated, 401, "ALC-AUTH-0001"},
		{auth.ErrLastAdmin, 409, "ALC-USR-0002"},
		{auth.ErrUsernameTaken, 409, "ALC-USR-0001"},
		{auth.ErrTokenScopeNotAllowed, 422, "ALC-TOK-0001"},
		{setup.ErrAlreadySetUp, 404, "ALC-SYS-0001"},
		{setup.ErrCodeInvalid, 401, "ALC-SET-0001"},
		{setup.ErrSessionInvalid, 401, "ALC-SET-0003"},
		{setup.ErrIncomplete, 409, "ALC-SET-0008"},
		{setup.ErrLicenseChoiceMissing, 409, "ALC-SET-0009"},
		{setup.ErrForbidden, 403, "ALC-AUTH-0002"},
		{fmt.Errorf("login: %w", auth.ErrTryAgain), 503, "ALC-AUTH-0012"},
		// Carry 2: the bare sentinels (without the typed error that carries the numbers).
		{license.ErrTargetLimit, 409, "ALC-LIC-0008"},
		{fmt.Errorf("add target: %w", license.ErrUnverified), 503, "ALC-LIC-0009"}, // AUD-02: not ALC-LIC-0001
		{license.ErrLocked, 403, "ALC-LIC-0001"},
		{fmt.Errorf("add target: %w", license.ErrWrongInstallation), 422, "ALC-LIC-0003"},
		{inventory.ErrNotFound, 404, "ALC-SYS-0001"},
		{fmt.Errorf("create: %w", inventory.ErrDuplicateTarget), 409, "ALC-TGT-0001"},
		{inventory.ErrVersionMismatch, 412, "ALC-SYS-0008"},
		{inventory.ErrHostKeyUnconfirmed, 409, "ALC-TGT-0002"},
		{inventory.ErrHostKeyStale, 409, "ALC-TGT-0003"},
		{inventory.ErrHostKeyChanged, 409, "ALC-TGT-0004"},
		{inventory.ErrHostKeyState, 409, "ALC-TGT-0005"},
		{inventory.ErrOwnKeyProtected, 409, "ALC-KEY-0001"},
		{inventory.ErrLastRootKey, 409, "ALC-KEY-0002"},
		{inventory.ErrNotRemovable, 409, "ALC-KEY-0003"},
		{inventory.ErrKeysManagedElsewhere, 409, "ALC-SSH-0008"},
		{inventory.ErrNoPlatformKey, 503, "ALC-SYS-0002"},
		{inventory.ErrNoSetupScript, 500, "ALC-SSH-0011"},
		{fmt.Errorf("remove: %w", inventory.ErrSSHDUnreadable), 409, "ALC-KEY-0004"},
		{fmt.Errorf("enqueue: %w", inventory.ErrJobConflict), 409, "ALC-JOB-0005"},
		{jobs.ErrNotFound, 404, "ALC-SYS-0001"},
		{jobs.ErrNotWaiting, 409, "ALC-JOB-0001"},
		{jobs.ErrBadCursor, 400, "ALC-SYS-0004"},
		{fmt.Errorf("%w: %q", jobs.ErrUnknownType, "x"), 500, "ALC-JOB-0004"},
		{fmt.Errorf("job: %w", providers.NewError("ssh.auth_failed", false, nil, nil)), 502, "ALC-SSH-0002"},
		{providers.NewError("ssh.unreachable", true, nil, nil), 502, "ALC-SSH-0001"},
		{providers.NewError("target.host_key_changed", false, nil, nil), 409, "ALC-TGT-0004"},
		{providers.NewError("sshkey.verify_failed", false, nil, nil), 502, "ALC-KEY-0005"},
		{providers.NewError("target.disabled", false, nil, nil), 409, "ALC-TGT-0006"},
		{providers.NewError("no.such_reason", false, nil, nil), 500, "ALC-SYS-0003"},
	}
	for _, tc := range cases {
		rec := failRecorder(t, tc.err, nil)
		assert.Equal(t, tc.status, rec.Code, tc.err.Error())
		assert.Equal(t, tc.code, decodeErr(t, rec).Error.Code, tc.err.Error())
	}
}

func TestFailAddsParamsForLengthErrors(t *testing.T) {
	rec := failRecorder(t, auth.ErrPasswordTooShort, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	var body struct {
		Error struct {
			Params  map[string]string `json:"params"`
			Message string            `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]string{"min": "12"}, body.Error.Params)
	assert.Contains(t, body.Error.Message, "Parola çok kısa.")

	rec = failRecorder(t, setup.ErrPassphraseTooShort, nil)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]string{"min": "16"}, body.Error.Params)
}

func TestFailReturnsValidationDetails(t *testing.T) {
	var v validate.Errors
	v.Add("username", validate.Pattern, nil)
	v.Add("display_name", validate.TooLong, map[string]string{"max": "100"})
	rec := failRecorder(t, fmt.Errorf("create user: %w", v), nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	var body struct {
		Error struct {
			Code    string                `json:"code"`
			Details []validate.FieldError `json:"details"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ALC-SYS-0006", body.Error.Code)
	assert.Equal(t, []validate.FieldError(v), body.Error.Details)
}

func TestFailSetsRetryAfterForSetupLock(t *testing.T) {
	rec := failRecorder(t, &setup.LockedError{RetryAfter: 14*time.Minute + 30*time.Second}, nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "870", rec.Header().Get("Retry-After"))
	assert.Equal(t, "ALC-SET-0002", decodeErr(t, rec).Error.Code)
}

// A credential check that timed out on the account lock is retryable (Task 10 C6 carry-in).
func TestFailMarksTryAgainRetryable(t *testing.T) {
	rec := failRecorder(t, auth.ErrTryAgain, nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
	b := decodeErr(t, rec)
	assert.Equal(t, "ALC-AUTH-0012", b.Error.Code)
	assert.Equal(t, "auth.try_again", b.Error.Reason)
	assert.True(t, b.Error.Retryable)
}

func TestFailHidesUnknownErrorsButLogsThem(t *testing.T) {
	var logs bytes.Buffer
	rec := failRecorder(t, errors.New("pq: relation users does not exist"), &logs)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "relation")
	assert.Equal(t, "ALC-SYS-0003", decodeErr(t, rec).Error.Code)
	// Logged with fixed labels only: the error text may carry column values (TestFailLogsNoErrorText).
	assert.Contains(t, logs.String(), `"msg":"request failed"`)
	assert.Contains(t, logs.String(), `"error_type":"*errors.errorString"`)
	assert.NotContains(t, logs.String(), "relation users does not exist")
	assert.Contains(t, logs.String(), rec.Header().Get("X-Request-Id"))
}

// meta keeps at most maxUserAgent runes of valid UTF-8, like auth.truncateUA.
func TestMetaTruncatesUserAgent(t *testing.T) {
	s := newServer(testDeps(t, nil))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", strings.Repeat("ğ", 300)) // 2 bytes per rune
	m := s.meta(req)
	assert.Equal(t, strings.Repeat("ğ", maxUserAgent), m.UserAgent)
	assert.Equal(t, "192.0.2.1", m.IP.String())

	req.Header.Set("User-Agent", "Mozilla\xff/5.0 \xc4")
	assert.Equal(t, "Mozilla/5.0 ", s.meta(req).UserAgent, "invalid UTF-8 is dropped")
}

// A bare license sentinel has no numbers to show, so the answer carries no params (the typed
// errors keep theirs, see TestLicenseUploadErrors and the target-limit tests).
func TestFailMapsBareLicenseErrorsWithoutParams(t *testing.T) {
	for _, err := range []error{license.ErrTargetLimit, license.ErrWrongInstallation} {
		rec := failRecorder(t, err, nil)
		var raw map[string]map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
		_, hasParams := raw["error"]["params"]
		assert.False(t, hasParams, err.Error())
	}
	rec := failRecorder(t, &license.TargetLimitError{Max: 5, Used: 5}, nil)
	var raw map[string]map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.Equal(t, map[string]any{"used": "5", "max": "5"}, raw["error"]["params"])
}

func TestFailPassesProviderParams(t *testing.T) {
	err := providers.NewError("ssh.helper_refused", false, errors.New("helper said: secret text"), map[string]string{"helper_code": "PATH_NOT_ALLOWED"})
	rec := failRecorder(t, err, nil)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	var body map[string]map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ALC-SSH-0006", body["error"]["code"])
	assert.Equal(t, map[string]any{"helper_code": "PATH_NOT_ALLOWED"}, body["error"]["params"])
	assert.NotContains(t, rec.Body.String(), "secret text", "a provider's cause is never shown")
}

func TestFailLogsUnknownProviderReasons(t *testing.T) {
	var logs bytes.Buffer
	rec := failRecorder(t, providers.NewError("no.such_reason", false, nil, nil), &logs)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, logs.String(), "request failed")
}

func TestCodeForReason(t *testing.T) {
	for _, ec := range AllErrorCodes() {
		assert.Equal(t, ec, codeForReason(ec.Reason), ec.Reason)
	}
	assert.Equal(t, ErrUnexpected, codeForReason("no.such_reason"))
	assert.Equal(t, ErrUnexpected, codeForReason(""))
	assert.Equal(t, ErrLicenseLocked, codeForReason("license.locked"), "jobs cancelled in lock carry this reason")
}

// Only the allowlisted provider params reach the client; any other key is dropped.
func TestFailFiltersProviderParams(t *testing.T) {
	err := providers.NewError("ssh.protocol_error", false, nil, map[string]string{
		"subcommand": "authkeys-read", "exit_code": "3", "helper_code": "IO_ERROR", "stderr": "remote text", "line": "ssh-ed25519 AAAA",
	})
	rec := failRecorder(t, err, nil)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	var body map[string]map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]any{"subcommand": "authkeys-read", "exit_code": "3", "helper_code": "IO_ERROR"}, body["error"]["params"])
	assert.NotContains(t, rec.Body.String(), "remote text")
	assert.NotContains(t, rec.Body.String(), "AAAA")
}

// ssh.helper_outdated names the helper's protocol and the one Alice needs, so the UI can say which
// helper to install.
func TestFailKeepsHelperProtocolParams(t *testing.T) {
	err := providers.NewError("ssh.helper_outdated", false, nil, map[string]string{
		"helper_protocol": "1", "required_protocol": "2", "stderr": "remote text",
	})
	rec := failRecorder(t, err, nil)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	var body map[string]map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ALC-SSH-0005", body["error"]["code"])
	assert.Equal(t, map[string]any{"helper_protocol": "1", "required_protocol": "2"}, body["error"]["params"])
	assert.NotContains(t, rec.Body.String(), "remote text")
}
