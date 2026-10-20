package deployjobs

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/fake"
)

// The rollback guard (R48): no rollback the engine sends or lets the provider send puts a revoked or compromised
// certificate or key back. The engine reads the guard again right before every rollback and hands it to the provider;
// a rollback it cannot read the guard for is never sent.

// forbiddenGuard is the guard of a backup holding a compromised key.
func forbiddenGuard() providers.RollbackGuard {
	return providers.RollbackGuard{ForbiddenSPKI: []string{strings.Repeat("a", 64)}, TargetForbidden: true, Required: true}
}

func rollbackCalls(p *fake.Provider) []providers.RollbackRequest {
	var out []providers.RollbackRequest
	for _, c := range p.Calls() {
		if c.Method == "RollbackDeployment" {
			out = append(out, c.Rollback)
		}
	}
	return out
}

// The acceptance test of the controller path: the old key was marked compromised (here: after the deployment started,
// so only the recovery's own read knows), the new install was interrupted while writing, and the recovery must not put
// the old key back: it sends the guard, the server refuses, and the deployment ends rollback_failed with
// deployment.rollback_forbidden.
func TestRecoveryNeverRestoresAForbiddenBackup(t *testing.T) {
	for _, phase := range []string{providers.PhaseWriting, providers.PhaseRestoring, providers.PhaseRestoreFailed} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t)
			f.sent(inventory.DeployStateRecovering, 0)
			f.status = providers.DeploymentState{Phase: phase, NewCertSHA256: sha(f.nw.FullchainPEM)}
			f.inv.guard = forbiddenGuard()
			restoredOldKey := false
			f.prov.Configure(func(c *fake.Config) {
				c.Rollback = func(req providers.RollbackRequest) (providers.RollbackOutcome, error) {
					if !req.Guard.TargetForbidden {
						restoredOldKey = true // what a server that is not told would do
						return providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}, nil
					}
					return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreForbidden,
						FailedStep: providers.StepNameRestore, Error: providers.DeployErrForbidden, Reason: providers.ReasonRollbackForbidden}, nil
				}
			})
			_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
			require.NoError(t, err)
			assert.False(t, restoredOldKey, "the old key is never put back")
			calls := rollbackCalls(f.prov)
			require.Len(t, calls, 1, "a forbidden restore is not retried")
			assert.Equal(t, forbiddenGuard(), calls[0].Guard, "the guard read right before the rollback")
			assert.Positive(t, f.inv.guardReads)
			fin := f.inv.lastFinish()
			assert.Equal(t, inventory.DeployStatusRollbackFailed, fin.Status)
			assert.Equal(t, providers.ReasonRollbackForbidden, fin.ErrorCode)
			assert.Equal(t, providers.PhaseRestoreForbidden, fin.Phase)
			assert.Equal(t, providers.StepNameRestore, fin.FailedStep)
		})
	}
}

// A guard that cannot be read is no rollback at all: unresolved, nothing sent, nothing recorded.
func TestRecoveryWithoutTheGuardSendsNoRollback(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, 0)
	f.status = providers.DeploymentState{Phase: providers.PhaseWriting, NewCertSHA256: sha(f.nw.FullchainPEM)}
	f.inv.guardErr = errors.New("database down")
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.Error(t, err)
	assert.Equal(t, reasonUnexpected, failureOf(t, err).Reason)
	assert.Empty(t, rollbackCalls(f.prov))
	assert.Empty(t, f.inv.outcomes, "nothing recorded: the next recovery reads the journal again")
}

// The fake honours the guard by default (as a server that checks it): a recovery with the default fake ends
// forbidden, never rolled_back.
func TestRecoveryWithTheDefaultFakeHonoursTheGuard(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, 0)
	f.status = providers.DeploymentState{Phase: providers.PhaseWriting, NewCertSHA256: sha(f.nw.FullchainPEM)}
	f.inv.guard = forbiddenGuard()
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	fin := f.inv.lastFinish()
	assert.Equal(t, inventory.DeployStatusRollbackFailed, fin.Status)
	assert.Equal(t, providers.ReasonRollbackForbidden, fin.ErrorCode)
}

// A rollback the guard allows is sent with the lists (the server checks the backup itself).
func TestRecoveryRollbackCarriesTheLists(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, 0)
	f.status = providers.DeploymentState{Phase: providers.PhaseWriting, NewCertSHA256: sha(f.nw.FullchainPEM)}
	f.inv.guard = providers.RollbackGuard{ForbiddenLeaf: []string{strings.Repeat("b", 64)}}
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	calls := rollbackCalls(f.prov)
	require.Len(t, calls, 1)
	assert.Equal(t, f.inv.guard, calls[0].Guard)
	assert.Equal(t, inventory.DeployStatusRolledBack, f.inv.lastFinish().Status)
}

// The deploy job's one more restore after the helper's restore_failed reads the guard again; without it nothing is
// sent and the outcome is uncertain (the recovery reads the journal).
func TestRollbackAgainReadsTheGuard(t *testing.T) {
	restoreFailed := func(providers.DeployRequest) (providers.DeployOutcome, error) {
		return providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "rollback_reload",
			CauseStep: "reload", Reason: "deployment.rollback_reload_failed"}, nil
	}
	t.Run("forbidden", func(t *testing.T) {
		f := newFixture(t)
		f.prov.Configure(func(c *fake.Config) { c.Deploy = restoreFailed })
		f.inv.guard = forbiddenGuard()
		_, err := f.h.deploy(f.ctx, f.job(), f.steps)
		require.Error(t, err)
		calls := rollbackCalls(f.prov)
		require.Len(t, calls, 1)
		assert.Equal(t, forbiddenGuard(), calls[0].Guard)
		fin := f.inv.lastFinish()
		assert.Equal(t, inventory.DeployStatusRollbackFailed, fin.Status)
		assert.Equal(t, providers.ReasonRollbackForbidden, fin.ErrorCode)
	})
	t.Run("unreadable", func(t *testing.T) {
		f := newFixture(t)
		f.prov.Configure(func(c *fake.Config) { c.Deploy = restoreFailed })
		f.inv.guardErr = errors.New("database down")
		_, err := f.h.deploy(f.ctx, f.job(), f.steps)
		require.Error(t, err)
		assert.Empty(t, rollbackCalls(f.prov), "no restore without the guard")
		require.Len(t, f.inv.outcomes, 1)
		assert.False(t, f.inv.outcomes[0].Terminal, "uncertain: the recovery decides")
	})
}

// The first send carries the guard of the material and a way to read it again before the provider's own rollback.
func TestDeployRequestCarriesTheGuardAndRechecksIt(t *testing.T) {
	f := newFixture(t)
	f.inv.material.Guard = providers.RollbackGuard{ForbiddenSPKI: []string{strings.Repeat("c", 64)}, Required: true}
	f.inv.guard = forbiddenGuard()
	var planned, rechecked providers.RollbackGuard
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(req providers.DeployRequest) (providers.DeployOutcome, error) {
			planned = req.Guard
			require.NotNil(t, req.RecheckGuard)
			g, err := req.RecheckGuard(context.Background())
			require.NoError(t, err)
			rechecked = g
			return providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "remote"}, nil
		}
	})
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, f.inv.material.Guard, planned, "the guard at plan time")
	assert.Equal(t, forbiddenGuard(), rechecked, "read again from inventory")
}

// recoverPending restores an earlier operation: with its owner's guard when Alice knows it, else with this
// deployment's lists and an unknown target (a server that cannot check them restores nothing).
func TestPendingOperationRestoreCarriesItsGuard(t *testing.T) {
	pendingOp := uuid.MustParse("0190f5a0-0000-7000-8000-00000000abcd")
	pending := func(providers.DeployRequest) (providers.DeployOutcome, error) {
		p := map[string]string{"operation_id": pendingOp.String()}
		e := providers.NewError("deployment.recovery_pending", false, nil, p)
		return providers.DeployOutcome{Result: providers.DeployNoChange, Reason: e.Code, Params: maps.Clone(p)}, e
	}
	forbidden := func(providers.RollbackRequest) (providers.RollbackOutcome, error) {
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: providers.StepNameRestore, Error: providers.DeployErrForbidden,
			Reason: providers.ReasonRollbackForbidden}, nil
	}
	t.Run("unknown operation", func(t *testing.T) {
		f := newFixture(t)
		f.prov.Configure(func(c *fake.Config) {
			c.Deploy = pending
			c.Rollback = forbidden
		})
		f.inv.guard = forbiddenGuard()
		_, err := f.h.deploy(f.ctx, f.job(), f.steps)
		require.Error(t, err)
		calls := rollbackCalls(f.prov)
		require.Len(t, calls, 1)
		assert.Equal(t, pendingOp, calls[0].OperationID)
		assert.False(t, calls[0].Guard.TargetForbidden, "the earlier operation's backup is not this deployment's")
		assert.True(t, calls[0].Guard.TargetUnknown)
		assert.Equal(t, forbiddenGuard().ForbiddenSPKI, calls[0].Guard.ForbiddenSPKI)
		fin := f.inv.lastFinish()
		assert.Equal(t, inventory.DeployStatusFailed, fin.Status)
		assert.Equal(t, "deployment.server_operation_pending", fin.ErrorCode, "a refused restore puts nothing back")
		assert.Equal(t, 1, f.prov.Count("DeployCertificate"), "nothing is sent again")
	})
	t.Run("known owner", func(t *testing.T) {
		f := newFixture(t)
		owner := uuid.Must(uuid.NewV7())
		f.inv.ops = map[uuid.UUID]inventory.OperationOwner{pendingOp: {ID: owner, TargetID: f.target, LocationID: f.inv.dep.LocationID,
			State: inventory.DeployStateDone, Status: inventory.DeployStatusRollbackFailed}}
		f.inv.guards = map[uuid.UUID]providers.RollbackGuard{owner: forbiddenGuard()}
		f.prov.Configure(func(c *fake.Config) {
			c.Deploy = pending
			c.Rollback = forbidden
		})
		_, err := f.h.deploy(f.ctx, f.job(), f.steps)
		require.Error(t, err)
		calls := rollbackCalls(f.prov)
		require.Len(t, calls, 1)
		assert.Equal(t, forbiddenGuard(), calls[0].Guard, "the owner's own guard")
	})
	t.Run("unreadable guard", func(t *testing.T) {
		f := newFixture(t)
		f.prov.Configure(func(c *fake.Config) { c.Deploy = pending })
		f.inv.guardErr = errors.New("database down")
		_, err := f.h.deploy(f.ctx, f.job(), f.steps)
		require.Error(t, err)
		assert.Empty(t, rollbackCalls(f.prov), "no restore without the guard")
		assert.Equal(t, "deployment.recovery_pending", f.inv.lastFinish().ErrorCode, "the refusal as it is")
	})
}
