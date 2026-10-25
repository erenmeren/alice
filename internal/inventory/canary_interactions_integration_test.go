//go:build integration

package inventory_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/testutil/pki"
)

// incidentOnOld starts a key-compromise incident on the certificate the websites held before the canary (the
// fixture's old leaf, uploaded with its key) with a fresh replacement, and answers its id.
func (w *canaryWorld) incidentOnOld(t *testing.T) inventory.Incident {
	t.Helper()
	h := w.h
	h.installLicense("LIC-CANARY-INCIDENT", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, _, err := h.svc.UploadCertificate(h.ctx, w.admin, pemUpload(w.old))
	require.NoError(t, err)
	old := w.certByFingerprint(t, pki.Fingerprint(w.old.Cert))
	rep := w.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	repCert, _, err := h.svc.UploadCertificate(h.ctx, w.admin, pemUpload(rep))
	require.NoError(t, err)
	i, err := h.svc.StartIncident(h.ctx, w.admin, old.ID, inventory.IncidentInput{})
	require.NoError(t, err)
	i, err = h.svc.ChooseIncidentReplacement(h.ctx, w.admin, i.ID, repCert.ID)
	require.NoError(t, err)
	return i
}

func (w *canaryWorld) advanceIncidents(t *testing.T) {
	t.Helper()
	_, err := w.h.svc.AdvanceIncidents(w.h.ctx)
	require.NoError(t, err)
}

// CAN-28 (design §20.3): an incident at a place a canary holds preempts the rollout: the hold is released, no wave 2,
// and the incident requests its replacement there on its next step.
func TestIncidentPreemptsAHold(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.advance()
	place := w.get(w.hold).LocationID
	i := w.incidentOnOld(t)
	w.advanceIncidents(t)
	d := w.get(w.hold)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status, "released")
	details := w.h.auditDetails("deployment.succeeded")
	require.NotEmpty(t, details)
	assert.Equal(t, inventory.HoldCauseIncident, details[len(details)-1]["hold_cause"])
	r := w.read()
	assert.Equal(t, inventory.RolloutPreempted, r.State)
	assert.Equal(t, inventory.RolloutReasonPreempted, r.Reason)
	assert.Equal(t, 1, w.h.audits("deployment.rollout_preempted"))
	w.advance()
	assert.Empty(t, w.wave2(), "no wave 2")

	w.advanceIncidents(t)
	got, err := w.h.svc.GetIncident(w.h.ctx, i.ID)
	require.NoError(t, err)
	l := incidentLocation(t, got, place)
	assert.Equal(t, inventory.IncidentLocationDeploying, l.Status, "the place proceeds by the incident's rules")
	require.NotNil(t, l.DeploymentID)
	assert.NotEqual(t, w.hold, *l.DeploymentID)
}

// CAN-28: a hold whose deployed certificate is compromised is never released, also under an incident: the incident
// waits on the busy place, the next advance reverts it with canary.certificate_revoked.
func TestIncidentNeverReleasesACompromisedHold(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.advance()
	w.incidentOnOld(t)
	_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE certificates SET compromised_at = now() WHERE id = $1", w.cert.ID)
	require.NoError(t, err)
	w.advanceIncidents(t)
	assert.Equal(t, inventory.DeployStateHolding, w.get(w.hold).State, "not released")
	assert.Equal(t, inventory.RolloutHold, w.read().State)
	w.advance()
	d := w.get(w.hold)
	assert.Equal(t, inventory.DeployStateRecovering, d.State)
	assert.Equal(t, inventory.ReasonCanaryWaveFailed, d.RevertReason)
	r := w.read()
	assert.Equal(t, inventory.RolloutFailed, r.State)
	assert.Equal(t, inventory.RolloutReasonRevoked, r.Reason)
}

// CAN-28: the deployed certificate marked compromised during the hold fails the rollout and reverts wave 1.
func TestDeployedCertificateRevokedDuringTheHold(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.advance()
	_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE certificates SET revoked_at = now(), revocation_reason = 'superseded' WHERE id = $1", w.cert.ID)
	require.NoError(t, err)
	w.advance()
	assert.Equal(t, inventory.RolloutReasonRevoked, w.read().Reason)
	assert.Equal(t, inventory.DeployStateRecovering, w.get(w.hold).State)
	assert.Empty(t, w.wave2())
}

// CAN-28: drift observation, drift repair and the Windows cleanup treat a hold as an unfinished deployment (their
// queries exclude a location or keep a certificate while a deployment is not done; holding is not done).
func TestDriftAndWindowsCleanupSeeAHoldAsUnfinished(t *testing.T) {
	for file, pin := range map[string]string{
		"drift_observe.go":   "AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.location_id = l.id AND d.state <> 'done')",
		"drift_repair.go":    "AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.location_id = o.location_id AND d.state <> 'done')",
		"windows_cleanup.go": "EXISTS (SELECT 1 FROM deployments d WHERE d.target_id = $1 AND d.state <> 'done'",
	} {
		src, err := os.ReadFile(file)
		require.NoError(t, err)
		assert.True(t, strings.Contains(string(src), pin), "%s: %s", file, pin)
	}
	assert.NotEqual(t, inventory.DeployStateDone, inventory.DeployStateHolding)
}

// Final review I (R65): the rollout failed while a wave-1 website was still sending; that website then holds and an
// incident reaches it before the next advance: it is reverted, never recorded a success.
func TestPreemptionRevertsAHoldOfAFailedRollout(t *testing.T) {
	f := newDeployFixture(t)
	id := f.request(f.admin, f.cert.ID, f.loc1)
	rollout := f.asWave(id, 1)
	_, err := f.h.db.Owner.Exec(f.h.ctx, `UPDATE deployment_rollouts SET state = 'failed', reason = 'canary.check_failed', finished_at = $2
WHERE id = $1`, rollout, f.h.clock.Now())
	require.NoError(t, err)
	f.start(id)
	require.NoError(t, f.succeed(id, stringOf('e', 64)))
	require.Equal(t, inventory.DeployStateHolding, f.get(id).State)
	_, err = f.h.svc.PreemptRolloutOf(f.h.ctx, id)
	require.NoError(t, err)
	d := f.get(id)
	assert.Equal(t, inventory.DeployStateRecovering, d.State)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, d.RevertReason)
	assert.NotEqual(t, inventory.DeployStatusSucceeded, d.Status)
}
