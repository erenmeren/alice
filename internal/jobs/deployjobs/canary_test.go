package deployjobs

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/fake"
)

// CAN-11: a deploy job that finds its deployment holding (a re-run after a crash) never sends and never recovers: the
// canary owns the hold.
func TestDeployJobFindingHoldingDoesNothing(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateHolding, time.Minute)
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"deployment_id": f.id.String(), "outcome": "holding"}, res)
	assert.Equal(t, []string{"Deployment"}, f.inv.calls())
	assert.Zero(t, f.prov.Count("DeployCertificate"))
	assert.Zero(t, f.prov.Count("DeploymentStatus"))
}

// CAN-11: a recovery job that finds a hold without a revert reason records nothing.
func TestRecoveryJobFindingHoldingWithoutRevertDoesNothing(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateHolding, time.Minute)
	res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"deployment_id": f.id.String(), "outcome": "holding"}, res)
	assert.Equal(t, []string{"Deployment"}, f.inv.calls())
	assert.Zero(t, f.prov.Count("DeploymentStatus"))
	assert.Zero(t, f.prov.Count("RollbackDeployment"))
}

// A job whose record entered holding when its success was written answers success (resultOf).
func TestResultOfAHoldIsASuccess(t *testing.T) {
	for _, m := range []mode{deployJob, recoveryJob} {
		res, err := resultOf(inventory.Deployment{State: inventory.DeployStateHolding, Verified: "remote"}, m)
		require.NoError(t, err)
		assert.Equal(t, "holding", res["outcome"])
	}
}

// CAN-09 (design §10): the revert rows of the recovery's decision table. Every rollback of a revert carries the revert
// reason as its error code; a committed operation whose new certificate verifies is rolled back all the same; an
// unchanged journal cannot happen for a hold and ends outcome unknown.
func TestRevertDecisions(t *testing.T) {
	reason := inventory.ReasonCanaryCheckFailed
	rolledBack := providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Verified: "remote"}
	for _, tc := range []struct {
		name         string
		phase        string
		verifyOK     bool
		rollback     providers.RollbackOutcome
		status, code string
		sends        int
		verifyReason string
	}{
		{name: "committed, new certificate verified", phase: providers.PhaseCommitted, verifyOK: true, rollback: rolledBack,
			status: inventory.DeployStatusRolledBack, code: reason, sends: 1},
		{name: "committed, verification fails", phase: providers.PhaseCommitted, rollback: rolledBack,
			status: inventory.DeployStatusRolledBack, code: reason, sends: 1, verifyReason: "deployment.verify_failed"},
		{name: "unchanged cannot hold", phase: providers.PhaseUnchanged, verifyOK: true,
			status: inventory.DeployStatusRollbackFailed, code: "deployment.outcome_unknown"},
		{name: "restored (an earlier revert's record lost)", phase: providers.PhaseRestored, rollback: rolledBack,
			status: inventory.DeployStatusRolledBack, code: reason, sends: 1},
		{name: "restoring", phase: providers.PhaseRestoring, rollback: rolledBack, status: inventory.DeployStatusRolledBack, code: reason, sends: 1},
		{name: "restore_failed", phase: providers.PhaseRestoreFailed, rollback: rolledBack, status: inventory.DeployStatusRolledBack, code: reason, sends: 1},
		{name: "the guard refuses", phase: providers.PhaseCommitted, verifyOK: true,
			rollback: providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreForbidden,
				FailedStep: providers.StepNameRestore, Error: "forbidden", Reason: providers.ReasonRollbackForbidden},
			status: inventory.DeployStatusRollbackFailed, code: providers.ReasonRollbackForbidden, sends: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.sent(inventory.DeployStateRecovering, time.Hour)
			f.inv.dep.RevertReason, f.inv.dep.ErrorCode = reason, reason
			f.status = providers.DeploymentState{Phase: tc.phase, NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
			f.prov.Configure(func(c *fake.Config) {
				c.Verify = func(req providers.VerifyRequest) (providers.VerifyResult, error) {
					if tc.verifyOK {
						return providers.VerifyResult{OK: true, Mode: "remote", Served: req.Fingerprint, ServedChainLength: 2}, nil
					}
					return providers.VerifyResult{Mode: "remote", Reason: "deployment.verify_failed", Params: map[string]string{"port": "443"}}, nil
				}
				c.Rollback = func(req providers.RollbackRequest) (providers.RollbackOutcome, error) {
					assert.Equal(t, f.current, req.OldFingerprint, "the recorded previous certificate")
					return tc.rollback, nil
				}
			})
			res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
			require.NoError(t, err)
			require.Len(t, f.inv.outcomes, 1)
			rec := f.inv.outcomes[0].Finish
			assert.Equal(t, tc.status, rec.Status)
			assert.Equal(t, tc.code, rec.ErrorCode)
			assert.Equal(t, tc.status, res["outcome"])
			assert.Equal(t, tc.sends, f.prov.Count("RollbackDeployment"))
			assert.Zero(t, f.prov.Count("DeployCertificate"), "a revert never sends")
			assert.NotContains(t, f.inv.calls(), "DeploymentMaterial(true)", "a revert never needs the private key")
			assert.Equal(t, tc.verifyReason, rec.VerifyFailedReason)
			if tc.sends > 0 {
				assert.Positive(t, f.inv.guardReads, "the rollback guard is read right before the rollback")
			}
		})
	}
}
