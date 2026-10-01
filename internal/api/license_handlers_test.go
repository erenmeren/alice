package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/license/licensetest"
)

var licenseEnd = time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)

func licenseSnapshot(at time.Time) license.Snapshot {
	p := licensetest.Payload(license.NewInstallationID(), licenseEnd.AddDate(-1, 0, 0), licenseEnd, 10)
	return license.Snapshot{
		InstallationID: p.InstallationID,
		InstalledAt:    licenseEnd.AddDate(-1, 0, 0),
		Eval:           license.Evaluate(at, licenseEnd.AddDate(-1, 0, 0), []license.Installed{{Seq: 1, KeyID: licensetest.KeyID, Payload: p}}),
		Reading:        license.Reading{Wall: at, Trusted: at, Effective: at},
		Ready:          true,
	}
}

type statusBody struct {
	Expired bool    `json:"expired"`
	Phase   *string `json:"phase"`
	Banners []struct {
		Kind     string            `json:"kind"`
		Severity string            `json:"severity"`
		Params   map[string]string `json:"params"`
	} `json:"banners"`
}

func status(t *testing.T, h http.Handler, id string) statusBody {
	t.Helper()
	rec := call(h, http.MethodGet, "/api/v1/license/status", id, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var b statusBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &b))
	return b
}

// L-15: warnings go to Administrators; Operators learn only whether the license expired.
func TestLicenseStatusDependsOnTheRole(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	fl.snap = licenseSnapshot(licenseEnd.Add(-7 * 24 * time.Hour))
	h := NewHandler(d)

	op := status(t, h, "operator")
	assert.False(t, op.Expired)
	assert.Nil(t, op.Phase)
	assert.Empty(t, op.Banners)

	admin := status(t, h, "admin")
	require.NotNil(t, admin.Phase)
	assert.Equal(t, "active", *admin.Phase)
	require.Len(t, admin.Banners, 1)
	assert.Equal(t, "expiry_warning", admin.Banners[0].Kind)
	assert.Equal(t, "caution", admin.Banners[0].Severity)
	assert.Equal(t, "7", admin.Banners[0].Params["days_left"])

	auditor := status(t, h, "auditor")
	require.NotNil(t, auditor.Phase, "Auditors can read the license status (R3)")
	assert.Empty(t, auditor.Banners)
	assert.Len(t, status(t, h, "alice_read_admin").Banners, 1, "a read token of an administrator")

	fl.snap = licenseSnapshot(licenseEnd.Add(2*24*time.Hour + time.Hour))
	op = status(t, h, "operator")
	assert.True(t, op.Expired)
	require.Len(t, op.Banners, 1, "the grace banner is for everyone (§19.3)")
	assert.Equal(t, "grace", op.Banners[0].Kind)
	assert.Equal(t, "3", op.Banners[0].Params["grace_day"])
}

func TestLicenseDetail(t *testing.T) {
	d := testDeps(t, nil)
	snap := licenseSnapshot(licenseEnd.Add(-100 * 24 * time.Hour))
	d.License.(*fakeLicense).DetailFn = func(context.Context) (license.Detail, error) {
		cur := *snap.Eval.Current
		return license.Detail{
			Snapshot: snap,
			Files:    []license.FileInfo{{Seq: 1, Status: "current", UploadedAt: licenseEnd.AddDate(-1, 0, 0), KeyID: licensetest.KeyID, Payload: &cur}, {Seq: 2, Status: "invalid"}},
			History:  []license.HistoryEntry{{At: licenseEnd.AddDate(-1, 0, 0), Event: "installed", LicenseID: cur.LicenseID, FromState: "evaluation", ToState: "active"}},
		}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/license", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, snap.InstallationID, body["installation_id"])
	assert.Equal(t, "active", body["phase"])
	assert.Equal(t, float64(10), body["max_targets"])
	assert.Equal(t, float64(100), body["days_left"])
	assert.Equal(t, "Test Company", body["current"].(map[string]any)["customer"])
	assert.Equal(t, licensetest.KeyID, body["current"].(map[string]any)["key_id"])
	assert.Nil(t, body["pending"])
	files := body["files"].([]any)
	require.Len(t, files, 2)
	assert.Nil(t, files[1].(map[string]any)["license"], "a file that no longer verifies shows no content")
	assert.Nil(t, body["history"].([]any)[0].(map[string]any)["notice"])

	assert.Equal(t, http.StatusForbidden, call(NewHandler(d), http.MethodGet, "/api/v1/license", "operator", "").Code)
}

func TestLicenseUpload(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	var gotRaw []byte
	var gotActor audit.Actor
	var gotBy uuid.UUID
	result := license.UploadResult{Payload: licensetest.Payload(license.NewInstallationID(), licenseEnd.AddDate(-1, 0, 0), licenseEnd, 10),
		KeyID: licensetest.KeyID, Pending: true, Phase: license.PhaseActive}
	fl.PreviewFn = func(_ context.Context, raw []byte) (license.UploadResult, error) { gotRaw = raw; return result, nil }
	fl.InstallFn = func(_ context.Context, raw []byte, a audit.Actor, by uuid.UUID) (license.UploadResult, error) {
		gotRaw, gotActor, gotBy = raw, a, by
		return result, nil
	}
	h := NewHandler(d)

	rec := call(h, http.MethodPost, "/api/v1/license/preview", "admin-stepup", `{"license":"{\"format\":1}"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `{"format":1}`, string(gotRaw))
	var res map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, true, res["pending"])
	assert.Equal(t, "active", res["phase"])
	assert.Equal(t, "Test Company", res["license"].(map[string]any)["customer"])

	rec = call(h, http.MethodPost, "/api/v1/license", "admin-stepup", `{"license":"x"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "admin", gotActor.Name)
	assert.Equal(t, adminID, gotBy)

	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, call(h, http.MethodPost, "/api/v1/license", "admin", `{"license":"x"}`)).Error.Code, "upload needs step-up (§25.1)")
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/license", "auditor-stepup", `{"license":"x"}`).Code)
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/license", "admin-stepup", `{"license":"x","extra":1}`).Code)
}

// The request body is capped at the license size limit before any license parsing:
// a larger body is refused with 413 and never reaches the license service.
func TestLicenseUploadBodyIsCappedAtTheLicenseLimit(t *testing.T) {
	d := testDeps(t, nil)
	reached := 0
	fl := d.License.(*fakeLicense)
	fl.PreviewFn = func(context.Context, []byte) (license.UploadResult, error) {
		reached++
		return license.UploadResult{}, license.ErrInvalid
	}
	fl.InstallFn = func(context.Context, []byte, audit.Actor, uuid.UUID) (license.UploadResult, error) {
		reached++
		return license.UploadResult{}, license.ErrInvalid
	}
	h := NewHandler(d)
	over := `{"license":"` + strings.Repeat("a", license.MaxFileSize) + `"}`
	for _, path := range []string{"/api/v1/license", "/api/v1/license/preview"} {
		rec := call(h, http.MethodPost, path, "admin-stepup", over)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, path)
		assert.Equal(t, "ALC-SYS-0007", decodeErr(t, rec).Error.Code, path)
	}
	assert.Zero(t, reached, "an oversized body never reaches the license service")

	atLimit := `{"license":"` + strings.Repeat("a", license.MaxFileSize-len(`{"license":""}`)) + `"}`
	require.Len(t, atLimit, license.MaxFileSize)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPost, "/api/v1/license", "admin-stepup", atLimit).Code)
	assert.Equal(t, 1, reached, "a body at the limit is handed to the license service")
}

func TestLicenseUploadErrors(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
		params map[string]string
	}{
		{&license.InvalidError{Problem: "signature"}, 422, "ALC-LIC-0002", nil},
		{&license.WrongInstallationError{Expected: "B8TC00", Got: "Q2MXD4"}, 422, "ALC-LIC-0003", map[string]string{"expected": "B8TC00", "got": "Q2MXD4"}},
		{license.ErrUnknownKey, 422, "ALC-LIC-0004", nil},
		{license.ErrRevokedKey, 422, "ALC-LIC-0005", nil},
		{license.ErrUnsupportedFormat, 422, "ALC-LIC-0006", nil},
		{license.ErrOlderThanInstalled, 409, "ALC-LIC-0007", nil},
		{&license.TargetLimitError{Max: 10, Used: 10}, 409, "ALC-LIC-0008", map[string]string{"used": "10", "max": "10"}},
		{license.ErrLocked, 403, "ALC-LIC-0001", nil},
		{license.ErrNoInstallation, 503, "ALC-SYS-0002", nil},
	}
	for _, tc := range cases {
		d := testDeps(t, nil)
		d.License.(*fakeLicense).InstallFn = func(context.Context, []byte, audit.Actor, uuid.UUID) (license.UploadResult, error) {
			return license.UploadResult{}, tc.err
		}
		rec := call(NewHandler(d), http.MethodPost, "/api/v1/license", "admin-stepup", `{"license":"x"}`)
		assert.Equal(t, tc.status, rec.Code, tc.code)
		var body struct {
			Error struct {
				Code   string            `json:"code"`
				Params map[string]string `json:"params"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, tc.code, body.Error.Code)
		if tc.params != nil {
			assert.Equal(t, tc.params, body.Error.Params)
		}
	}
}

// Carry 2: before the first evaluation the snapshot holds no state; answering "not expired"
// would be a guess, so the status is unavailable (retryable) until Start has completed.
func TestLicenseStatusBeforeTheFirstEvaluationIsUnavailable(t *testing.T) {
	d := testDeps(t, nil) // fakeLicense{}: Snapshot().Ready is false
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/license/status", "admin", "")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "ALC-SYS-0002", decodeErr(t, rec).Error.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
	assert.NotContains(t, rec.Body.String(), `"expired"`)

	d.License.(*fakeLicense).snap = licenseSnapshot(licenseEnd.Add(-90 * 24 * time.Hour))
	assert.Equal(t, http.StatusOK, call(NewHandler(d), http.MethodGet, "/api/v1/license/status", "admin", "").Code)
}
