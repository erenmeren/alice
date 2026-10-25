//go:build integration

package inventory_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
)

// rolloutOf reads the rollout a deployment belongs to.
func (h *harness) rolloutOf(dep uuid.UUID) inventory.Rollout {
	h.t.Helper()
	d, err := h.svc.Deployment(h.ctx, dep)
	require.NoError(h.t, err)
	require.NotNil(h.t, d.RolloutID, "the deployment is in a rollout")
	r, err := h.svc.Rollout(h.ctx, *d.RolloutID)
	require.NoError(h.t, err)
	return r
}

// forceHold puts a sent wave-1 deployment in holding as the engine does after a verified send (a Key Vault deployment's
// send needs the vault's secret, which these tests do not script).
func (h *harness) forceHold(dep uuid.UUID) {
	h.t.Helper()
	r := h.rolloutOf(dep)
	_, err := h.db.Owner.Exec(h.ctx, `UPDATE deployments SET state = 'holding', status = 'running', operation_id = id, started_at = now(),
    result = 'committed', phase = 'committed', verified = 'remote' WHERE id = $1`, dep)
	require.NoError(h.t, err)
	_, err = h.db.Owner.Exec(h.ctx, "INSERT INTO canary_checks (deployment_id, rollout_id, next_check_at) VALUES ($1, $2, $3)", dep, r.ID, h.clock.Now())
	require.NoError(h.t, err)
}

// failHold advances a holding wave-1 deployment's rollout to its failure: the hold starts, two rounds fail.
func (h *harness) failHold(dep uuid.UUID) {
	h.t.Helper()
	advance := func() {
		_, err := h.svc.AdvanceRollouts(h.ctx)
		require.NoError(h.t, err)
	}
	advance()
	for range 2 {
		require.NoError(h.t, h.svc.RecordCanaryRound(h.ctx, dep, inventory.CanaryRound{Result: inventory.RoundFail, Reason: "canary.http_status",
			TLS: inventory.RoundPass, HTTPStatus: 503}))
	}
	advance()
	require.Equal(h.t, inventory.RolloutFailed, h.rolloutOf(dep).State)
}

// CAN-27 (design §12): an ACME renewal with the canary on rolls out through a rollout; its failure stops the automatic
// deployment of that certificate with the planner's existing notice; a re-armed certificate gets a new rollout.
func TestACMERenewalRollsOutWithACanary(t *testing.T) {
	w := newACMEDeployWorld(t)
	w.h.setPolicy(w.h.defaultService(), canaryTenMinutes)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1, w.loc2, w.loc3onTarget2)
	assert.Equal(t, 1, w.plan().Created, "wave 1 only")
	deps := w.deps(cur)
	require.Len(t, deps, 1)
	r := w.h.rolloutOf(deps[0].ID)
	assert.Equal(t, inventory.RolloutOriginACME, r.Origin)
	require.NotNil(t, r.ACMECertificateID)
	assert.Equal(t, c.ID, *r.ACMECertificateID)
	assert.Len(t, r.Wave2, 2)
	assert.Equal(t, inventory.TriggerACMERenewal, deps[0].Trigger)
	assert.Equal(t, inventory.JobCertificateDeployAuto, w.h.jobType(*w.deployFixture.get(deps[0].ID).JobID))
	assert.Zero(t, w.plan().Created, "nothing else of the certificate while wave 1 runs")

	w.start(deps[0].ID)
	require.NoError(t, w.succeed(deps[0].ID, stringOf('e', 64)))
	w.h.failHold(deps[0].ID)
	var stopped *uuid.UUID
	require.NoError(t, w.h.db.Owner.QueryRow(w.h.ctx, "SELECT deploy_stopped_certificate_id FROM acme_certificates WHERE id = $1", c.ID).Scan(&stopped))
	require.NotNil(t, stopped)
	assert.Equal(t, cur, *stopped)
	details := w.h.auditDetails("acme.auto_deploy.stopped")
	require.Len(t, details, 1)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, details[0]["error_code"])
	assert.Equal(t, 1, w.h.emails(inventory.TemplateACMEAutoDeployStopped))
	assert.Zero(t, w.plan().Created, "stopped")
	assert.Empty(t, w.wave2Of(cur))

	// Re-armed (the stop mark cleared): a new rollout over the free locations; the failed one does not block it.
	_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE acme_certificates SET deploy_stopped_certificate_id = NULL WHERE id = $1", c.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, w.plan().Created)
	assert.Equal(t, 2, w.h.count("SELECT count(*) FROM deployment_rollouts WHERE acme_certificate_id = $1 AND origin = 'acme'", c.ID))
}

func (w *acmeDeployWorld) wave2Of(cert uuid.UUID) []uuid.UUID {
	w.h.t.Helper()
	rows, err := w.h.db.Owner.Query(w.h.ctx, "SELECT id FROM deployments WHERE certificate_id = $1 AND wave = 2", cert)
	require.NoError(w.h.t, err)
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		require.NoError(w.h.t, rows.Scan(&id))
		out = append(out, id)
	}
	return out
}

// CAN-27: a Key Vault renewal with the canary on: a rollout of the binding's version, wave 1 first; its failure stops the
// binding's wave for that version.
func TestKVRenewalRollsOutWithACanary(t *testing.T) {
	f := newAutoFixture(t, true)
	f.h.setPolicy(f.h.defaultService(), canaryTenMinutes)
	f.renew(5, nil)
	assert.Equal(t, 1, f.plan())
	deps := f.deps(ver(5))
	require.Len(t, deps, 1)
	r := f.h.rolloutOf(deps[0].ID)
	assert.Equal(t, inventory.RolloutOriginKeyVault, r.Origin)
	require.NotNil(t, r.BindingID)
	assert.Equal(t, f.bind.ID, *r.BindingID)
	assert.Len(t, r.Wave2, 2)
	assert.Zero(t, f.plan(), "nothing else of the version while wave 1 runs")

	f.h.forceHold(deps[0].ID)
	f.h.failHold(deps[0].ID)
	stopped, _ := f.bindingState()
	assert.Equal(t, ver(5), stopped)
	details := f.h.auditDetails("kv.auto_deploy.stopped")
	require.Len(t, details, 1)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, details[0]["error_code"])
	assert.Zero(t, f.plan())
}

// Design §12 "Reservation": while a person's rollout (an ACME or Key Vault Deploy now) is in wave 1 or hold, the
// planners leave its locations alone; when it fails, the automatic deployment of that certificate stops.
func TestPlannerLeavesAPersonsRolloutAlone(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, false, w.loc1, w.loc2, w.loc3onTarget2)
	w.h.setPolicy(w.h.defaultService(), canaryTenMinutes)
	got, r, err := w.h.svc.DeployACMENowWithRollout(w.h.ctx, w.admin, c.ID, inventory.ACMEDeployInput{})
	require.NoError(t, err)
	require.NotNil(t, r)
	assert.Equal(t, inventory.RolloutOriginManual, r.Origin)
	// The planner now has automatic deployment on for every binding.
	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE acme_bindings SET auto_deploy = true WHERE acme_certificate_id = $1", c.ID)
	require.NoError(t, err)
	assert.Zero(t, w.plan().Created, "the person's rollout holds its wave-2 locations")
	assert.Len(t, w.deps(cur), 1)

	w.start(got[0].ID)
	require.NoError(t, w.succeed(got[0].ID, stringOf('e', 64)))
	w.h.failHold(got[0].ID)
	var stopped *uuid.UUID
	require.NoError(t, w.h.db.Owner.QueryRow(w.h.ctx, "SELECT deploy_stopped_certificate_id FROM acme_certificates WHERE id = $1", c.ID).Scan(&stopped))
	require.NotNil(t, stopped, "TestFailedPersonsRolloutStopsTheAutomaticDeployment: the person's failed rollout stops the planner")
	assert.Equal(t, cur, *stopped)
	assert.Zero(t, w.plan().Created)
	assert.Len(t, w.deps(cur), 1)
}

// The Key Vault variant: a person's Deploy now rollout is left alone by the planner; its failure stops the binding's
// version.
func TestFailedPersonsRolloutStopsTheAutomaticDeployment(t *testing.T) {
	f := newAutoFixture(t, false)
	f.h.setPolicy(f.h.defaultService(), canaryTenMinutes)
	f.renew(5, nil)
	version := f.versionID(f.web, ver(5))
	got, r, err := f.h.svc.RequestKVDeploymentWithRollout(f.h.ctx, f.admin, inventory.KVDeployInput{StrictSession: true, BindingID: f.bind.ID,
		VersionID: version})
	require.NoError(t, err)
	require.NotNil(t, r)
	f.bind = f.setAuto(true)
	assert.Zero(t, f.plan(), "the person's rollout holds its locations")
	f.h.forceHold(got[0].ID)
	f.h.failHold(got[0].ID)
	stopped, _ := f.bindingState()
	assert.Equal(t, ver(5), stopped)
	assert.Zero(t, f.plan())
}
