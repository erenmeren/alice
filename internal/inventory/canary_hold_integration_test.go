//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/db"
	"alice/internal/testutil/pki"
)

// asWave makes deployment id part of a new manual rollout of its certificate in the given wave (the owner writes what
// the request transaction of Task 5 writes at insert).
func (f *deployFixture) asWave(id uuid.UUID, wave int) uuid.UUID {
	f.h.t.Helper()
	d := f.get(id)
	rollout := uuid.Must(uuid.NewV7())
	_, err := f.h.db.Owner.Exec(f.h.ctx, `INSERT INTO deployment_rollouts (id, certificate_id, policy_version, settings, origin, state,
wave1_location_ids, wave2_location_ids, created_at) VALUES ($1, $2, 1, '{}', 'manual', 'wave1', $3, $4, $5)`,
		rollout, d.CertificateID, []uuid.UUID{d.LocationID}, []uuid.UUID{uuid.New()}, f.h.clock.Now())
	require.NoError(f.h.t, err)
	_, err = f.h.db.Owner.Exec(f.h.ctx, "UPDATE deployments SET rollout_id = $2, wave = $3 WHERE id = $1", id, rollout, wave)
	require.NoError(f.h.t, err)
	return rollout
}

// succeed finishes a sent deployment as a verified success writing fileSHA.
func (f *deployFixture) succeed(id uuid.UUID, fileSHA string) error {
	return f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded, Verified: "remote",
		Result: "committed", Phase: "committed", CertFileSHA256: fileSHA})
}

// holding is a wave-1 deployment of nw to loc that entered holding.
func (f *deployFixture) holding(loc uuid.UUID) (uuid.UUID, uuid.UUID) {
	f.h.t.Helper()
	id := f.request(f.admin, f.cert.ID, loc)
	rollout := f.asWave(id, 1)
	f.start(id)
	require.NoError(f.h.t, f.succeed(id, stringOf('e', 64)))
	require.Equal(f.h.t, inventory.DeployStateHolding, f.get(id).State)
	return id, rollout
}

func (f *deployFixture) inTx(fn func(tx pgx.Tx) error) error {
	return db.InTx(f.h.ctx, f.h.db.App, fn)
}

// CAN-06: a wave-1 deployment's verified success holds; nothing a success writes to the location happens yet.
func TestWaveOneSuccessEntersHolding(t *testing.T) {
	f := newDeployFixture(t)
	id := f.request(f.admin, f.cert.ID, f.loc1)
	rollout := f.asWave(id, 1)
	f.start(id)
	before, err := f.h.svc.GetLocation(f.h.ctx, f.loc1)
	require.NoError(t, err)
	require.NoError(t, f.succeed(id, stringOf('e', 64)))

	d := f.get(id)
	assert.Equal(t, inventory.DeployStateHolding, d.State)
	assert.Equal(t, inventory.DeployStatusRunning, d.Status)
	assert.Nil(t, d.FinishedAt)
	require.NotNil(t, d.RolloutID)
	assert.Equal(t, rollout, *d.RolloutID)
	assert.Equal(t, 1, d.Wave)
	assert.Equal(t, "remote", d.Verified)
	assert.Equal(t, "committed", d.Result)
	var held string
	var next time.Time
	require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT held_cert_file_sha256 FROM deployments WHERE id = $1", id).Scan(&held))
	assert.Equal(t, stringOf('e', 64), held)
	require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT next_check_at FROM canary_checks WHERE deployment_id = $1 AND rollout_id = $2",
		id, rollout).Scan(&next))
	assert.WithinDuration(t, f.h.clock.Now(), next, time.Second)
	after, err := f.h.svc.GetLocation(f.h.ctx, f.loc1)
	require.NoError(t, err)
	assert.Equal(t, before.Certificate, after.Certificate, "the location still names the previous certificate")
	assert.Equal(t, before.DeployedFingerprint, after.DeployedFingerprint)
	assert.Equal(t, before.Version, after.Version)
	assert.Equal(t, 1, f.h.audits("deployment.holding"))
	assert.Zero(t, f.h.audits("deployment.succeeded"))
	assert.Empty(t, f.emails())

	// A second finish (a deploy job that runs again) changes nothing.
	require.NoError(t, f.succeed(id, stringOf('f', 64)))
	assert.Equal(t, 1, f.h.audits("deployment.holding"))
	require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT held_cert_file_sha256 FROM deployments WHERE id = $1", id).Scan(&held))
	assert.Equal(t, stringOf('e', 64), held)
}

// CAN-06: an unchanged outcome is not held (nothing was written, nothing can be restored: decision 7).
func TestUnchangedWaveOneFinishesAtOnce(t *testing.T) {
	f := newDeployFixture(t)
	id := f.request(f.admin, f.cert.ID, f.loc1)
	f.asWave(id, 1)
	f.start(id)
	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusUnchanged,
		Verified: "remote", Result: "unchanged", Phase: "unchanged"}))
	d := f.get(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusUnchanged, d.Status)
	assert.Zero(t, f.h.audits("deployment.holding"))
}

// CAN-06: wave 2 and deployments outside a rollout never hold.
func TestWaveTwoAndPlainDeploymentsNeverHold(t *testing.T) {
	f := newDeployFixture(t)
	two := f.request(f.admin, f.cert.ID, f.loc1)
	f.asWave(two, 2)
	f.start(two)
	require.NoError(t, f.succeed(two, stringOf('e', 64)))
	assert.Equal(t, inventory.DeployStatusSucceeded, f.get(two).Status)
	plain := f.deploying(f.loc2)
	require.NoError(t, f.succeed(plain, stringOf('e', 64)))
	assert.Equal(t, inventory.DeployStatusSucceeded, f.get(plain).Status)
	assert.Zero(t, f.h.audits("deployment.holding"))
	var n int
	require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT count(*) FROM canary_checks").Scan(&n))
	assert.Zero(t, n)
}

// CAN-07: the release finishes a hold exactly as a success does, once.
func TestReleaseHoldFinishesAsASuccess(t *testing.T) {
	f := newDeployFixture(t)
	id, _ := f.holding(f.loc1)
	require.NoError(t, f.inTx(func(tx pgx.Tx) error { return f.h.svc.ReleaseHold(f.h.ctx, tx, id, "release") }))
	d := f.get(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	assert.Equal(t, "remote", d.Verified)
	assert.NotNil(t, d.FinishedAt)
	loc, err := f.h.svc.GetLocation(f.h.ctx, f.loc1)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(f.nw.Cert), loc.DeployedFingerprint)
	require.NotNil(t, loc.Certificate)
	assert.Equal(t, f.cert.ID, loc.Certificate.ID)
	var fileSHA string
	require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT cert_file_sha256 FROM certificate_locations WHERE id = $1", f.loc1).Scan(&fileSHA))
	assert.Equal(t, stringOf('e', 64), fileSHA, "the held file hash")
	details := f.h.auditDetails("deployment.succeeded")
	require.Len(t, details, 1)
	assert.Equal(t, "release", details[0]["hold_cause"])

	assert.ErrorIs(t, f.inTx(func(tx pgx.Tx) error { return f.h.svc.ReleaseHold(f.h.ctx, tx, id, "release") }), inventory.ErrDeploymentState)
	assert.ErrorIs(t, f.inTx(func(tx pgx.Tx) error { return f.h.svc.ReleaseHold(f.h.ctx, tx, uuid.New(), "release") }), inventory.ErrNotFound)
	assert.Equal(t, 1, f.h.audits("deployment.succeeded"))
}

// Design §20.3: a hold whose deployed certificate is revoked or compromised is never released (it is reverted).
func TestReleaseHoldRefusesAForbiddenCertificate(t *testing.T) {
	f := newDeployFixture(t)
	id, _ := f.holding(f.loc1)
	_, err := f.h.db.Owner.Exec(f.h.ctx, "UPDATE certificates SET compromised_at = now() WHERE id = $1", f.cert.ID)
	require.NoError(t, err)
	assert.ErrorIs(t, f.inTx(func(tx pgx.Tx) error { return f.h.svc.ReleaseHold(f.h.ctx, tx, id, "release") }), inventory.ErrCertificateCompromised)
	assert.Equal(t, inventory.DeployStateHolding, f.get(id).State)

	g := newDeployFixture(t)
	id, _ = g.holding(g.loc1)
	_, err = g.h.db.Owner.Exec(g.h.ctx, "UPDATE certificates SET revoked_at = now(), revocation_reason = 'superseded' WHERE id = $1", g.cert.ID)
	require.NoError(t, err)
	assert.ErrorIs(t, g.inTx(func(tx pgx.Tx) error { return g.h.svc.ReleaseHold(g.h.ctx, tx, id, "incident") }), inventory.ErrCertificateRevoked)
}

// CAN-07: a revert hands the hold to the recovery path with its reason.
func TestRequestRevertQueuesARecovery(t *testing.T) {
	f := newDeployFixture(t)
	id, _ := f.holding(f.loc1)
	require.NoError(t, f.inTx(func(tx pgx.Tx) error {
		return f.h.svc.RequestRevert(f.h.ctx, tx, id, inventory.ReasonCanaryCheckFailed)
	}))
	d := f.get(id)
	assert.Equal(t, inventory.DeployStateRecovering, d.State)
	assert.Equal(t, inventory.DeployStatusRunning, d.Status)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, d.RevertReason)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, d.ErrorCode)
	assert.Equal(t, []string{"queued"}, f.recoverJobs(id))
	details := f.h.auditDetails("deployment.revert_requested")
	require.Len(t, details, 1)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, details[0]["reason"])

	assert.ErrorIs(t, f.inTx(func(tx pgx.Tx) error {
		return f.h.svc.RequestRevert(f.h.ctx, tx, id, inventory.ReasonCanaryAborted)
	}), inventory.ErrDeploymentState, "only from holding")
	done := f.deploying(f.loc2)
	require.NoError(t, f.succeed(done, stringOf('e', 64)))
	assert.ErrorIs(t, f.inTx(func(tx pgx.Tx) error {
		return f.h.svc.RequestRevert(f.h.ctx, tx, done, inventory.ReasonCanaryAborted)
	}), inventory.ErrDeploymentState)
	assert.ErrorIs(t, f.inTx(func(tx pgx.Tx) error {
		return f.h.svc.RequestRevert(f.h.ctx, tx, uuid.New(), inventory.ReasonCanaryAborted)
	}), inventory.ErrNotFound)
}

// Design §8.1: the engine's own writes cannot move a hold anywhere; only a release or a revert can.
func TestHoldingRefusesTheEngineWrites(t *testing.T) {
	f := newDeployFixture(t)
	id, _ := f.holding(f.loc1)
	assert.ErrorIs(t, f.h.svc.MarkRecovering(f.h.ctx, id, time.Time{}, false), inventory.ErrDeploymentState)
	_, err := f.h.svc.RequestRecovery(f.h.ctx, id)
	assert.ErrorIs(t, err, inventory.ErrDeploymentState)
	assert.ErrorIs(t, f.h.svc.RecordOutcome(f.h.ctx, id, inventory.OutcomeRecord{Finish: inventory.DeploymentFinish{Result: "uncertain",
		ErrorCode: "deployment.interrupted"}}, time.Time{}), inventory.ErrDeploymentState)
	for _, st := range []string{inventory.DeployStatusFailed, inventory.DeployStatusRolledBack, inventory.DeployStatusRollbackFailed} {
		assert.ErrorIs(t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: st, ErrorCode: "deployment.verify_failed",
			NothingWritten: true}), inventory.ErrDeploymentState, st)
	}
	assert.Equal(t, inventory.DeployStateHolding, f.get(id).State)
	assert.Empty(t, f.recoverJobs(id))
}

// CAN-08: the sweep leaves a hold to the canary, whatever its recover_after and its server.
func TestSweepLeavesHoldingAlone(t *testing.T) {
	f := newDeployFixture(t)
	id, _ := f.holding(f.loc1)
	_, err := f.h.db.Owner.Exec(f.h.ctx, "UPDATE deployments SET recover_after = $2 WHERE id = $1", id, f.h.clock.Now().Add(-time.Hour))
	require.NoError(t, err)
	_, err = f.h.db.Owner.Exec(f.h.ctx, "UPDATE targets SET deleted_at = now() WHERE id = $1", f.target1)
	require.NoError(t, err)
	f.h.clock.Advance(48 * time.Hour)
	_, err = f.h.svc.SweepDeployments(f.h.ctx)
	require.NoError(t, err)
	d := f.get(id)
	assert.Equal(t, inventory.DeployStateHolding, d.State)
	assert.Empty(t, f.recoverJobs(id))
}
