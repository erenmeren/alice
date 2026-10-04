//go:build integration

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

type paramsBody struct {
	Error struct {
		Params map[string]string `json:"params"`
	} `json:"error"`
}

func (s *stack) signedLicense(id string, from, until time.Time, targets int) string {
	p := licensetest.Payload(s.license.Snapshot().InstallationID, from, until, targets)
	p.LicenseID = id
	return string(licensetest.Sign(p))
}

// §19.1 and §25.1: preview, confirm, roles.
func TestLicenseUploadAcrossRoles(t *testing.T) {
	s, admin, adminAcct := installed(t)
	now := s.clock.Now()
	file := s.signedLicense("LIC-A", now, now.AddDate(1, 0, 0), 10)

	s.clock.Advance(6 * time.Minute) // the step-up window of the wizard has closed
	requireError(t, admin.do(http.MethodPost, "/api/v1/license/preview", map[string]string{"license": file}), http.StatusForbidden, "ALC-AUTH-0003")
	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPost, "/api/v1/license/preview", map[string]string{"license": file})
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "Test Company", decodeBody[map[string]any](t, rec)["license"].(map[string]any)["customer"])
	assert.Equal(t, 0, s.count("license_files"), "a preview stores nothing")

	rec = admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": file})
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "active", decodeBody[map[string]any](t, rec)["phase"])
	detail := decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/license", nil))
	assert.Equal(t, "LIC-A", detail["current"].(map[string]any)["license_id"])
	assert.Equal(t, s.license.Snapshot().InstallationID, detail["installation_id"])

	auditor := s.createUser(admin, adminAcct, "audra", "auditor", "auditor-password-2026")
	ac := s.freshClient()
	s.firstSignIn(ac, auditor)
	requireStatus(t, ac.do(http.MethodGet, "/api/v1/license", nil), http.StatusOK)
	requireStatus(t, ac.do(http.MethodPost, "/api/v1/license", map[string]string{"license": file}), http.StatusForbidden)

	operator := s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	oc := s.freshClient()
	s.firstSignIn(oc, operator)
	requireStatus(t, oc.do(http.MethodGet, "/api/v1/license", nil), http.StatusForbidden)
	st := decodeBody[map[string]any](t, oc.do(http.MethodGet, "/api/v1/license/status", nil))
	assert.Equal(t, false, st["expired"])
	assert.NotContains(t, st, "phase", "L-15")
}

// L-40, L-43: refused uploads change nothing and are audited.
func TestLicenseUploadRefusals(t *testing.T) {
	s, admin, adminAcct := installed(t)
	now := s.clock.Now()
	s.stepUp(admin, adminAcct)
	good := s.signedLicense("LIC-A", now, now.AddDate(1, 0, 0), 10)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": good}), http.StatusOK)

	signed := s.signedLicense("LIC-B", now, now.AddDate(1, 0, 0), 10)
	edited := strings.Replace(signed, `"max_targets": 10`, `"max_targets": 1000`, 1)
	require.NotEqual(t, signed, edited, "the edit must change a signed value")
	requireError(t, admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": edited}), http.StatusUnprocessableEntity, "ALC-LIC-0002")
	other := string(licensetest.Sign(licensetest.Payload(license.NewInstallationID(), now, now.AddDate(1, 0, 0), 10)))
	rec := admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": other})
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-LIC-0003")
	body := decodeBody[paramsBody](t, rec)
	assert.Equal(t, license.IDSuffix(s.license.Snapshot().InstallationID), body.Error.Params["expected"])

	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'license.upload.invalid_signature' AND result = 'failure'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'license.upload.wrong_installation'"))
	assert.Equal(t, 1, s.count("license_files"))
	assert.Equal(t, "LIC-A", s.license.Snapshot().Eval.Key())
}

// L-25 (the parts that exist in Phase 2): in lock, sign-in, the license upload, user
// administration and the audit log keep working.
func TestLockKeepsPlatformAdministrationAvailable(t *testing.T) {
	s, admin, adminAcct := installed(t)
	s.clock.Advance(31 * 24 * time.Hour) // the evaluation ends (R1)
	require.NoError(t, s.license.Tick(t.Context()))
	require.True(t, s.license.Snapshot().Eval.Locked())

	s.signIn(admin, adminAcct) // the old session idled out; signing in still works
	st := decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/license/status", nil))
	assert.Equal(t, true, st["expired"])
	assert.Equal(t, "evaluation_expired", st["phase"])

	s.createUser(admin, adminAcct, "nora", "auditor", "auditor-password-2026")
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/audit", nil), http.StatusOK)
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/audit/export?format=json", nil), http.StatusOK)

	now := s.clock.Now()
	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": s.signedLicense("LIC-A", now, now.AddDate(1, 0, 0), 10)})
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "active", decodeBody[map[string]any](t, rec)["phase"], "the renewal works at once (L-30)")
	assert.Equal(t, false, decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/license/status", nil))["expired"])
}

// AUD-02: while no license evaluation succeeds (here a session holds the license row), changes are
// refused with ALC-LIC-0009 after 3 hours and everyone sees the unverified banner; sign-in and
// always-class routes keep working, and a license upload works and its evaluation reopens the gate.
func TestUnverifiedLicenseRefusesChangesAndKeepsUploadsWorking(t *testing.T) {
	s, admin, adminAcct := installed(t)
	tx, err := s.db.App.Begin(t.Context())
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(t.Context(), "SELECT 1 FROM license WHERE id = 1 FOR UPDATE")
	require.NoError(t, err)

	s.clock.Advance(license.MaxEvaluationAge + time.Minute)
	require.Error(t, s.license.Tick(t.Context()), "the evaluation cannot take the license row")
	s.signIn(admin, adminAcct) // the old session idled out; signing in still works

	rec := admin.do(http.MethodPost, "/api/v1/targets", map[string]any{"name": "web-01", "host": "web-01.example.test"})
	requireError(t, rec, http.StatusServiceUnavailable, "ALC-LIC-0009")
	assert.Equal(t, 0, s.count("targets"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'request.denied_license' AND details->>'reason' = 'unverified'"))

	st := decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/license/status", nil))
	var kinds []string
	for _, b := range st["banners"].([]any) {
		kinds = append(kinds, b.(map[string]any)["kind"].(string))
	}
	assert.Contains(t, kinds, "unverified")
	assert.Equal(t, false, st["expired"], "the last evaluated state is still shown")
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/audit/verify", nil), http.StatusOK)

	require.NoError(t, tx.Rollback(t.Context())) // the session ends; the gate stays closed until a check succeeds
	requireError(t, admin.do(http.MethodPost, "/api/v1/targets", map[string]any{"name": "web-01", "host": "web-01.example.test"}),
		http.StatusServiceUnavailable, "ALC-LIC-0009")

	now := s.clock.Now()
	s.stepUp(admin, adminAcct)
	rec = admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": s.signedLicense("LIC-A", now, now.AddDate(1, 0, 0), 10)})
	requireStatus(t, rec, http.StatusOK)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/targets", map[string]any{"name": "web-01", "host": "web-01.example.test"}),
		http.StatusCreated)
}
