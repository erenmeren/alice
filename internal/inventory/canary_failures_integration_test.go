//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
)

// failOn makes every statement of kind ("INSERT", "UPDATE") on table raise, as the owner role, until the cleanup.
func (h *harness) failOn(table, kind string) {
	h.t.Helper()
	_, err := h.db.Owner.Exec(h.ctx, `CREATE OR REPLACE FUNCTION alice_test_injected() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'injected failure'; END $$`)
	require.NoError(h.t, err)
	name := "alice_test_fail_" + table + "_" + kind
	_, err = h.db.Owner.Exec(h.ctx, "CREATE TRIGGER "+name+" BEFORE "+kind+" ON "+table+" FOR EACH ROW EXECUTE FUNCTION alice_test_injected()")
	require.NoError(h.t, err)
	h.t.Cleanup(func() { _, _ = h.db.Owner.Exec(h.ctx, "DROP TRIGGER IF EXISTS "+name+" ON "+table) })
}

func (h *harness) stopFailing(table, kind string) {
	h.t.Helper()
	_, err := h.db.Owner.Exec(h.ctx, "DROP TRIGGER alice_test_fail_"+table+"_"+kind+" ON "+table)
	require.NoError(h.t, err)
}

// A database failure in any step of a rollout is an error of that step, with nothing half done: the request makes no
// rollout and no deployment, a hold is not entered, a round is not recorded, and one rollout's failure is reported by
// the advance without stopping it for good (R65).
func TestCanaryStepsFailWhole(t *testing.T) {
	f := newDeployFixture(t)
	f.h.setPolicy(f.h.defaultService(), canaryTenMinutes)
	locs := []uuid.UUID{f.loc1, f.loc2, f.loc3onTarget2}

	f.h.failOn("deployment_rollouts", "INSERT")
	_, _, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: locs})
	require.Error(t, err)
	assert.Zero(t, f.deploymentCount(), "no deployment without its rollout")
	f.h.stopFailing("deployment_rollouts", "INSERT")

	got, r, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: locs})
	require.NoError(t, err)
	require.NotNil(t, r)
	hold := got[0].ID
	f.start(hold)
	f.h.failOn("canary_checks", "INSERT")
	require.Error(t, f.succeed(hold, stringOf('e', 64)))
	assert.NotEqual(t, inventory.DeployStateHolding, f.get(hold).State, "no hold without its observation row")
	f.h.stopFailing("canary_checks", "INSERT")
	require.NoError(t, f.succeed(hold, stringOf('e', 64)))
	require.Equal(t, inventory.DeployStateHolding, f.get(hold).State)

	// The advance: the rollout cannot move; the error is reported and the next advance moves it.
	f.h.failOn("deployment_rollouts", "UPDATE")
	n, err := f.h.svc.AdvanceRollouts(f.h.ctx)
	require.Error(t, err)
	assert.Zero(t, n)
	f.h.stopFailing("deployment_rollouts", "UPDATE")
	f.h.failOn("jobs", "INSERT")
	_, err = f.h.svc.AdvanceRollouts(f.h.ctx)
	require.Error(t, err, "the first round cannot be queued")
	f.h.stopFailing("jobs", "INSERT")
	n, err = f.h.svc.AdvanceRollouts(f.h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	rr, err := f.h.svc.Rollout(f.h.ctx, r.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.RolloutHold, rr.State)

	// A round that cannot be written is an error of the round job.
	f.h.failOn("canary_checks", "UPDATE")
	require.Error(t, f.h.svc.RecordCanaryRound(f.h.ctx, hold, inventory.CanaryRound{Result: inventory.RoundPass, TLS: inventory.RoundPass}))
	f.h.stopFailing("canary_checks", "UPDATE")
	require.Error(t, f.h.svc.RecordCanaryRound(f.h.ctx, hold, inventory.CanaryRound{Result: "maybe"}), "not a round result")

	// The person's actions fail whole too.
	require.NoError(t, f.h.svc.RecordCanaryRound(f.h.ctx, hold, inventory.CanaryRound{Result: inventory.RoundPass, TLS: inventory.RoundPass}))
	f.h.failOn("deployment_rollouts", "UPDATE")
	_, err = f.h.svc.ContinueRollout(f.h.ctx, f.admin, r.ID)
	require.Error(t, err)
	_, err = f.h.svc.AbortRollout(f.h.ctx, f.admin, r.ID)
	require.Error(t, err)
	f.h.stopFailing("deployment_rollouts", "UPDATE")
	assert.Equal(t, inventory.DeployStateHolding, f.get(hold).State, "nothing was half done")
	rr, err = f.h.svc.Rollout(f.h.ctx, r.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.RolloutHold, rr.State)
	assert.False(t, rr.Finished())
}

// Wave 2 checks every website again: one gone and one with another unfinished deployment are skipped with their reasons;
// with nothing left to deploy the rollout completes at the release.
func TestWaveTwoSkipsAGoneAndABusyWebsite(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	// loc3 gets a plain deployment of its own (one website: no canary) that stays queued.
	busy := w.request(w.admin, w.cert.ID, w.loc3onTarget2)
	require.NotEqual(t, uuid.Nil, busy)
	_, err := w.h.db.Owner.Exec(w.h.ctx, "DELETE FROM certificate_locations WHERE id = $1", w.loc2)
	require.NoError(t, err)
	w.passHold()
	w.advance()
	r := w.read()
	assert.Equal(t, inventory.RolloutCompleted, r.State, "nothing left to deploy")
	reasons := map[uuid.UUID]string{}
	for _, s := range r.Skipped {
		reasons[s.LocationID] = s.Reason
	}
	assert.Equal(t, "in_progress", reasons[w.loc3onTarget2])
	assert.Equal(t, "location_not_found", reasons[w.loc2])
	assert.True(t, r.Finished())
	assert.WithinDuration(t, w.h.clock.Now(), *r.FinishedAt, time.Second)
}

// The release, the revert and the audit row of a step fail whole as well: the hold stays until a later advance.
func TestCanaryReleaseAndRevertFailWhole(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.passHold()

	w.h.failOn("deployments", "UPDATE")
	_, err := w.h.svc.AdvanceRollouts(w.h.ctx)
	require.Error(t, err, "the release cannot be written")
	w.h.stopFailing("deployments", "UPDATE")
	assert.Equal(t, inventory.DeployStateHolding, w.get(w.hold).State)

	w.h.failOn("audit_log", "INSERT")
	_, err = w.h.svc.AdvanceRollouts(w.h.ctx)
	require.Error(t, err, "the release cannot be audited")
	_, err = w.h.svc.ContinueRollout(w.h.ctx, w.admin, w.rollout.ID)
	require.Error(t, err, "Continue cannot be audited")
	w.h.stopFailing("audit_log", "INSERT")
	assert.Equal(t, inventory.RolloutHold, w.read().State)

	w.h.failOn("jobs", "INSERT")
	_, err = w.h.svc.AbortRollout(w.h.ctx, w.admin, w.rollout.ID)
	require.Error(t, err, "the revert's recovery job cannot be queued")
	w.h.stopFailing("jobs", "INSERT")
	assert.Equal(t, inventory.DeployStateHolding, w.get(w.hold).State)

	w.advance()
	assert.Equal(t, inventory.RolloutWave2, w.read().State, "a later advance releases it")
}

// Continue's release and Abort's revert fail whole; a round target of an unknown deployment is refused; a planner whose
// rollout cannot be written reports the error and deploys nothing.
func TestCanaryPersonAndPlannerStepsFailWhole(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.advance()
	w.round(inventory.RoundPass, "", 200)
	w.h.failOn("deployments", "UPDATE")
	_, err := w.h.svc.ContinueRollout(w.h.ctx, w.admin, w.rollout.ID)
	require.Error(t, err, "the release cannot be written")
	_, err = w.h.svc.AbortRollout(w.h.ctx, w.admin, w.rollout.ID)
	require.Error(t, err, "the revert cannot be written")
	w.h.stopFailing("deployments", "UPDATE")
	assert.Equal(t, inventory.DeployStateHolding, w.get(w.hold).State)
	_, err = w.h.svc.CanaryRoundTarget(w.h.ctx, uuid.New())
	require.Error(t, err)

	a := newACMEDeployWorld(t)
	a.h.setPolicy(a.h.defaultService(), canaryTenMinutes)
	c, cur := a.issued("www.example.test")
	a.bind(c, true, a.loc1, a.loc2, a.loc3onTarget2)
	require.NoError(t, a.h.lic.Tick(a.h.ctx))
	a.h.failOn("deployment_rollouts", "INSERT")
	_, err = a.h.svc.PlanACMEAutoDeploy(a.h.ctx)
	require.Error(t, err)
	a.h.stopFailing("deployment_rollouts", "INSERT")
	assert.Empty(t, a.deps(cur), "nothing deployed without its rollout")
}

// An incident's preemption of a deployment that does not hold is nothing; one whose release cannot be written fails
// whole and the hold stays.
func TestPreemptionOfNoHoldAndAFailedRelease(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	moved, err := w.h.svc.PreemptRolloutOf(w.h.ctx, uuid.New())
	require.NoError(t, err)
	assert.False(t, moved)
	w.h.failOn("deployments", "UPDATE")
	_, err = w.h.svc.PreemptRolloutOf(w.h.ctx, w.hold)
	require.Error(t, err)
	w.h.stopFailing("deployments", "UPDATE")
	assert.Equal(t, inventory.DeployStateHolding, w.get(w.hold).State)
	moved, err = w.h.svc.PreemptRolloutOf(w.h.ctx, w.hold)
	require.NoError(t, err)
	assert.True(t, moved)
	assert.Equal(t, inventory.RolloutPreempted, w.read().State)
}

// A hold keeps what the verification found (an untrusted chain that was not enforced, the port of a failed check) and
// its release writes it as the success's record.
func TestHoldKeepsTheVerificationsFindings(t *testing.T) {
	f := newDeployFixture(t)
	id := f.request(f.admin, f.cert.ID, f.loc1)
	f.asWave(id, 1)
	f.start(id)
	port := 8443
	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded, Verified: "remote",
		Result: "committed", Phase: "committed", CertFileSHA256: stringOf('e', 64), VerifyFailedPort: &port,
		Trust: providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrors[0], Port: 443}}))
	require.Equal(t, inventory.DeployStateHolding, f.get(id).State)
	moved, err := f.h.svc.PreemptRolloutOf(f.h.ctx, id)
	require.NoError(t, err)
	assert.True(t, moved)
	d := f.get(id)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
}
