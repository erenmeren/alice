//go:build integration

package deployjobs

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/db"
)

// R65 through the whole stack (the engine, inventory on PostgreSQL, the nginx provider and the emulated helper): a
// wave-1 deployment holds after its verified send; a revert puts the previous certificate back through the recovery
// path with the rollback guard.

// holding requests the new certificate on loc as a wave-1 deployment of a rollout (the owner writes what the request
// transaction writes) and runs it until it holds.
func (e *env) holding(loc uuid.UUID) uuid.UUID {
	e.t.Helper()
	e.evaluate()
	c := e.upload()
	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{loc}})
	require.NoError(e.t, err)
	id := got[0].ID
	rollout := uuid.Must(uuid.NewV7())
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO deployment_rollouts (id, certificate_id, policy_version, settings, origin, state,
wave1_location_ids, wave2_location_ids, created_at) VALUES ($1, $2, 1, '{}', 'manual', 'wave1', $3, $4, now())`,
		rollout, c.ID, []uuid.UUID{loc}, []uuid.UUID{uuid.New()})
	require.NoError(e.t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE deployments SET rollout_id = $2, wave = 1 WHERE id = $1", id, rollout)
	require.NoError(e.t, err)
	e.drain()
	require.Equal(e.t, inventory.DeployStateHolding, e.deployment(id).State)
	return id
}

func (e *env) revert(id uuid.UUID, reason string) {
	e.t.Helper()
	require.NoError(e.t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error { return e.inv.RequestRevert(e.ctx, tx, id, reason) }))
}

// CAN-09: the hold is served by the new certificate; the revert rolls the committed operation back and the previous
// certificate is served again; the deployment ends rolled_back with the canary reason and its failure e-mail.
func TestRevertRollsBackACommittedOperation(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.holding(s.locs[wwwCert])
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw)
	assert.Equal(t, 1, s.emu.DeployCount())
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStatusRunning, d.Status)
	assert.Equal(t, 1, e.audits("deployment.holding"))

	e.revert(id, inventory.ReasonCanaryCheckFailed)
	e.drain()
	d = e.deployment(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, d.ErrorCode)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, d.RevertReason)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
	assert.Equal(t, 1, s.emu.DeployCount(), "never sent again")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'deployment.failed'"))
	assert.Equal(t, 1, e.audits("deployment.rolled_back"))
	assert.Zero(t, e.audits("deployment.succeeded"))
}

// CAN-10: the previous certificate was compromised during the hold: the revert restores nothing (R48 G4).
func TestRevertRespectsTheRollbackGuard(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.holding(s.locs[wwwCert])
	e.compromiseOld()
	e.revert(id, inventory.ReasonCanaryAborted)
	e.drain()
	d := e.settle(id)
	e.assertForbidden(d)
	e.assertOldKeyGone(s)
}

// CAN-11 (Review Focus 3): Alice dies after the revert's restore was sent and before its record; after the restart
// the next recovery reads the journal and records rolled_back once, never succeeded.
func TestRevertSurvivesARestartAfterTheRestoreWasSent(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.holding(s.locs[wwwCert])
	e.revert(id, inventory.ReasonCanaryCheckFailed)
	k := newKiller("session:after:RollbackDeployment")
	e.runDying(k)
	require.Equal(t, "session:after:RollbackDeployment", k.firedAt())
	require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State, "nothing was recorded")
	e.restart()
	d := e.settle(id)
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, d.ErrorCode)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
	assert.Equal(t, 1, e.audits("deployment.rolled_back"), "recorded once")
	assert.Zero(t, e.audits("deployment.succeeded"))
	assert.Equal(t, 1, s.emu.DeployCount())
}
