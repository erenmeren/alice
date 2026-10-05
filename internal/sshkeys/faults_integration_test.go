//go:build integration

package sshkeys_test

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
)

var errInjected = errors.New("injected failure")

// faults switches failures of the module's dependencies on and off.
type faults struct {
	mail, enqueue, target, locations, added, removed atomic.Bool
}

type faultNotifier struct {
	f    *faults
	next sshkeys.Notifier
}

func (n faultNotifier) NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	if n.f.mail.Load() {
		return errInjected
	}
	return n.next.NotifyAdmins(ctx, tx, template, params)
}

type faultJobs struct {
	f    *faults
	next inventory.Enqueuer
}

func (j faultJobs) EnqueueTx(ctx context.Context, tx pgx.Tx, r inventory.JobRequest) (uuid.UUID, error) {
	if j.f.enqueue.Load() {
		return uuid.Nil, errInjected
	}
	return j.next.EnqueueTx(ctx, tx, r)
}

type faultInventory struct {
	sshkeys.Inventory
	f *faults
}

func (i faultInventory) TargetTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (inventory.Target, error) {
	if i.f.target.Load() {
		return inventory.Target{}, errInjected
	}
	return i.Inventory.TargetTx(ctx, tx, id, lock)
}

func (i faultInventory) KeyLocationsTx(ctx context.Context, tx pgx.Tx, keyID uuid.UUID, lock bool) ([]inventory.KeyLocation, error) {
	if i.f.locations.Load() {
		return nil, errInjected
	}
	return i.Inventory.KeyLocationsTx(ctx, tx, keyID, lock)
}

func (i faultInventory) RecordKeyAddedTx(ctx context.Context, tx pgx.Tx, in inventory.KeyAdded) (uuid.UUID, error) {
	if i.f.added.Load() {
		return uuid.Nil, errInjected
	}
	return i.Inventory.RecordKeyAddedTx(ctx, tx, in)
}

func (i faultInventory) MarkKeyRemoved(ctx context.Context, id uuid.UUID, a audit.Actor, res providers.AuthKeyResult) error {
	if i.f.removed.Load() {
		return errInjected
	}
	return i.Inventory.MarkKeyRemoved(ctx, id, a, res)
}

// withFaults replaces the environment's service by one whose dependencies fail on demand.
func (e *env) withFaults() *faults {
	f := &faults{}
	e.svc = sshkeys.New(sshkeys.Config{HelperBudget: helperproto.HelperBudget, Pool: e.db.App, Keyring: e.keyring, Audit: e.audit,
		Clock: e.tick, License: e.gate, Inventory: faultInventory{Inventory: e.inv, f: f}, Jobs: faultJobs{f: f, next: e.queue},
		Notifier: faultNotifier{f: f, next: e.notifier}, Log: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	return f
}

// A failing dependency fails the step and writes nothing: the run stays where it was.
func TestFailuresWriteNothing(t *testing.T) {
	e := newEnv(t)
	f := e.withFaults()
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)

	f.mail.Store(true)
	_, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	assert.ErrorIs(t, err, errInjected)
	e.clock.Advance(89 * 24 * time.Hour)
	_, err = e.svc.PlanDue(e.ctx)
	assert.ErrorIs(t, err, errInjected)
	assert.Zero(t, e.count("SELECT count(*) FROM rotations"))
	f.mail.Store(false)

	f.locations.Store(true)
	_, err = e.svc.Preview(e.ctx, e.admin, p.ID)
	assert.ErrorIs(t, err, errInjected)
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, "x")
	assert.ErrorIs(t, err, errInjected)
	f.locations.Store(false)

	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	f.enqueue.Store(true)
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	assert.ErrorIs(t, err, errInjected, "the location jobs cannot be queued: the start is rolled back")
	f.enqueue.Store(false)
	failed := e.onlyRun(p.ID)
	assert.Equal(t, "cancelled", failed.Status, "the run Run now created is cancelled (review M3)")
	assert.Equal(t, "rotation.start_failed", failed.ResultCode)
	r, err := e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	require.NoError(t, err)
	loc := r.Locations[0].ID

	f.target.Store(true)
	_, err = e.svc.BeginAdd(e.claimed(), loc)
	assert.ErrorIs(t, err, errInjected)
	f.target.Store(false)
	_, err = e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	f.added.Store(true)
	assert.ErrorIs(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: true, LineNo: 1}), errInjected)
	assert.ErrorIs(t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}), errInjected)
	f.added.Store(false)
	assert.Equal(t, "adding", e.locState(r, "deploy"))
	require.NoError(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: true, LineNo: 1}))
	require.NoError(t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))

	f.mail.Store(true)
	assert.ErrorIs(t, e.svc.Advance(e.ctx, r.ID), errInjected, "the overlap email is part of the transition")
	sum, err := e.svc.Sweep(e.ctx)
	assert.ErrorIs(t, err, errInjected)
	assert.Equal(t, 1, sum.Failed)
	f.mail.Store(false)
	assert.Equal(t, "adding_new", e.run(r.ID).Status)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))

	e.clock.Advance(7 * 24 * time.Hour)
	f.enqueue.Store(true)
	assert.ErrorIs(t, e.svc.Advance(e.ctx, r.ID), errInjected)
	f.enqueue.Store(false)
	assert.Equal(t, "overlap", e.run(r.ID).Status)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))

	// The inventory's record of the removal fails: the removal is still recorded on the run.
	f.removed.Store(true)
	e.removeAt(loc)
	f.removed.Store(false)
	assert.Contains(t, e.logs.String(), "could not record a removal in the inventory")
	f.mail.Store(true)
	assert.ErrorIs(t, e.svc.Advance(e.ctx, r.ID), errInjected)
	f.mail.Store(false)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got := e.run(r.ID)
	assert.Equal(t, "completed", got.Status)
	old, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Nil(t, old.RetiredAt, "the old location is still live in the inventory: not retired")
}

// Pauses and decisions with a failing email: nothing changes.
func TestDecisionsWithAFailingEmail(t *testing.T) {
	e := newEnv(t)
	f := e.withFaults()
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	require.Equal(t, "overlap", r.Status)
	f.mail.Store(true)
	assert.ErrorIs(t, e.svc.FinishNow(e.ctx, e.admin, r.ID), errInjected)
	e.clock.Advance(7 * 24 * time.Hour)
	e.gate.lock()
	assert.ErrorIs(t, e.svc.Advance(e.ctx, r.ID), errInjected, "the pause email is part of the pause")
	assert.False(t, e.run(r.ID).PausedLicense)
	f.mail.Store(false)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	e.gate.unlock()
	f.mail.Store(true)
	assert.ErrorIs(t, e.svc.Continue(e.ctx, e.admin, r.ID), sshkeys.ErrNoticePending, "Continue sends no notice (I2)")
	assert.ErrorIs(t, e.svc.Advance(e.ctx, r.ID), errInjected, "the renewal notice")
	f.mail.Store(false)
	assert.True(t, e.run(r.ID).PausedLicense)
	f.enqueue.Store(true)
	assert.ErrorIs(t, e.svc.Abort(e.ctx, e.admin, r.ID), errInjected)
	f.enqueue.Store(false)
	assert.Equal(t, "overlap", e.run(r.ID).Status)
}

// The sweep's own failures are counted and do not stop it; the undo of every location ends a run
// rolling back in lock (G2: a location pending its undo ends undo_failed when its jobs are exhausted).
func TestSweepBoundsEveryPhase(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	e.addLocation(k.ID, srv, "root")
	r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginRefused})
	require.Equal(t, "rolling_back", r.Status)
	assert.Equal(t, "added", e.locState(r, "root"), "the added location awaits its undo")
	f := e.withFaults()
	f.enqueue.Store(true)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'failed' WHERE type = 'rotation.location' AND payload ? 'phase'")
	require.NoError(t, err)
	sum, err := e.svc.Sweep(e.ctx)
	assert.ErrorIs(t, err, errInjected)
	assert.Equal(t, 1, sum.Failed)
	f.enqueue.Store(false)
	for range sshkeys.MaxLocationJobs + 1 {
		_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'failed' WHERE type = 'rotation.location' AND payload ? 'phase'")
		require.NoError(t, err)
		_, err = e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	got := e.run(r.ID)
	assert.Equal(t, "needs_attention", got.Status)
	assert.Equal(t, "rotation.undo_failed", got.ResultCode)
	for _, l := range got.Locations {
		assert.Equal(t, "undo_failed", l.State, l.OSUser)
		assert.Equal(t, "rotation.retries_exhausted", l.ErrorCode, l.OSUser)
	}
	_ = ids
}

// G1: an added location whose verification never comes ends add_failed when its jobs are exhausted.
func TestSweepEndsAnAddedLocationWithoutVerification(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	e.drive(r.Locations[0].ID, "")
	for range sshkeys.MaxLocationJobs + 1 {
		_, err := e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'failed' WHERE type = 'rotation.location' AND payload ? 'phase'")
		require.NoError(t, err)
		_, err = e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	got := e.run(r.ID)
	assert.Equal(t, "rolling_back", got.Status)
	assert.Equal(t, "add_failed", got.Locations[0].State)
}
