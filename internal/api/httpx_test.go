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
	"alice/internal/platform/validate"
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
	return s.handler([]route{{method: http.MethodPost, pattern: "/api/v1/probe", perm: rbac.Public, handler: func(w http.ResponseWriter, r *http.Request) {
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
		{setup.ErrForbidden, 403, "ALC-AUTH-0002"},
		{fmt.Errorf("login: %w", auth.ErrTryAgain), 503, "ALC-AUTH-0012"},
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
