package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
)

// The observation model renders its four facts with their own times, the health, the modes and whether a repair is
// available; a value outside its closed list reads as not measured (R52).
func TestObservationJSON(t *testing.T) {
	assert.Nil(t, observationJSON(nil))
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	scan, probe := now.Add(-time.Hour), now.Add(-time.Minute)
	cert, dep := uuid.New(), uuid.New()
	o := &inventory.LocationObservation{Health: inventory.HealthDrifted, Source: inventory.DriftSourceACME, SourceID: &cert,
		Desired:        &inventory.ObservedCertificate{CertificateID: &cert, Fingerprint: "aa", NotAfter: &now},
		LastDeployment: &inventory.DeployedCertificate{DeploymentID: dep, Fingerprint: "aa", At: &scan, Level: providers.LevelTrusted},
		File:           &inventory.FileObservation{ObservedCertificate: inventory.ObservedCertificate{Fingerprint: "bb"}, At: scan},
		TLS: &inventory.TLSObservation{ObservedCertificate: inventory.ObservedCertificate{Fingerprint: "bb"}, At: probe, Probe: inventory.DriftProbeHelper,
			Trust: providers.TrustUntrusted, TrustError: "something"},
		TLSError: "deployment.verify_unreachable", Mode: inventory.DriftModeAuto, DefaultMode: inventory.DriftModeAuto}
	d := observationJSON(o)
	assert.Equal(t, inventory.HealthDrifted, d.Health)
	assert.True(t, d.RepairAvailable)
	assert.Equal(t, inventory.DriftModeDefault, d.ModeSetting, "no stored mode: the default")
	assert.Equal(t, scan, d.File.ObservedAt)
	assert.Equal(t, probe, d.TLS.ObservedAt)
	assert.Equal(t, "helper", d.TLS.Probe)
	assert.Empty(t, d.TLS.TrustError, "an unknown trust error is not shown")
	assert.Equal(t, "ALC-DEP-0005", d.TLSError.Code)
	assert.Equal(t, providers.LevelTrusted, d.LastDeployment.Level)
	raw, err := json.Marshal(d)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"file":{"certificate_id":null,"fingerprint":"bb","not_after":null,"observed_at":"2026-10-21T08:00:00Z"`)
	o.Health = "maybe"
	assert.Equal(t, inventory.HealthStale, observationJSON(o).Health)
}

// PUT /locations/{id}/drift-mode passes the mode and the strength of the session to the inventory (which decides
// automatic repair); the body is {"mode": ...} exactly. POST /locations/{id}/actions/repair answers the deployments.
func TestDriftRoutes(t *testing.T) {
	d, inv := inventoryDeps(t)
	var (
		gotMode   string
		gotStrict bool
	)
	inv.SetDriftModeFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, mode string, strict bool) (inventory.LocationObservation, error) {
		gotMode, gotStrict = mode, strict
		return inventory.LocationObservation{Health: inventory.HealthInSync, Mode: mode}, nil
	}
	dep := uuid.New()
	inv.RepairDriftFn = func(context.Context, inventory.Actor, uuid.UUID, bool) ([]inventory.RequestedDeployment, error) {
		return []inventory.RequestedDeployment{{ID: dep, JobID: uuid.New(), LocationID: locationID}}, nil
	}
	h := NewHandler(d)
	path := "/api/v1/locations/" + locationID.String()
	rec := call(h, http.MethodPut, path+"/drift-mode", "operator", `{"mode":"approve"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "approve", gotMode)
	assert.False(t, gotStrict, "an Operator's session is never strict")
	rec = call(h, http.MethodPut, path+"/drift-mode", "admin-stepup", `{"mode":"auto"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, gotStrict)
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPut, path+"/drift-mode", "admin", `{"mode":"auto","extra":1}`).Code)

	inv.SetDriftModeFn = func(context.Context, inventory.Actor, uuid.UUID, string, bool) (inventory.LocationObservation, error) {
		return inventory.LocationObservation{}, inventory.ErrDriftNotBound
	}
	rec = call(h, http.MethodPut, path+"/drift-mode", "admin", `{"mode":"observe"}`)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-DEP-0029", decodeErr(t, rec).Error.Code)

	rec = call(h, http.MethodPost, path+"/actions/repair", "operator", "")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), dep.String())
	inv.RepairDriftFn = func(context.Context, inventory.Actor, uuid.UUID, bool) ([]inventory.RequestedDeployment, error) {
		return nil, inventory.ErrDriftNotDrifted
	}
	rec = call(h, http.MethodPost, path+"/actions/repair", "operator", "{}")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-DEP-0030", decodeErr(t, rec).Error.Code)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, path+"/actions/repair", "auditor-stepup", "").Code)
}
