//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/providers"
	"alice/internal/sshkeys"
)

// L-84 at the store: a run paused in lock past the end of its overlap. Continue needs the license;
// the renewal notice is sent before any removal; every removal still needs a fresh re-check.
func TestContinueAfterRenewalRenotifies(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	e.clock.Advance(7 * 24 * time.Hour)
	e.gate.lock()
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	require.True(t, e.run(r.ID).PausedLicense)
	assert.ErrorIs(t, e.svc.Continue(e.ctx, e.admin, r.ID), license.ErrLocked)
	e.gate.unlock()
	require.NoError(t, e.svc.Continue(e.ctx, e.admin, r.ID))
	got := e.run(r.ID)
	assert.False(t, got.PausedLicense)
	assert.Equal(t, "removing_old", got.Status, "Continue advances")
	assert.Len(t, e.mails("rotation.preview_after_license"), 1)
	assert.Equal(t, 1, e.audits("rotation.continued"))
	var by *uuid.UUID
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT continued_by FROM rotations WHERE id = $1", r.ID).Scan(&by))
	assert.Equal(t, e.admin.UserID, *by)
	_, err := e.svc.BeginRemove(e.claimed(), ids["deploy"])
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "a fresh re-check first")
	assert.ErrorIs(t, e.svc.Continue(e.ctx, e.admin, r.ID), sshkeys.ErrNotWaiting, "not paused")
}

func TestFinishNow(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	assert.ErrorIs(t, e.svc.FinishNow(e.ctx, e.admin, r.ID), sshkeys.ErrNotWaiting, "not in the overlap")
	e.drive(r.Locations[0].ID, providers.KeyLoginAccepted)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	e.gate.lock()
	assert.ErrorIs(t, e.svc.FinishNow(e.ctx, e.admin, r.ID), license.ErrLocked)
	e.gate.unlock()
	e.clock.Advance(time.Hour)
	require.NoError(t, e.svc.FinishNow(e.ctx, e.admin, r.ID))
	got := e.run(r.ID)
	assert.Equal(t, "removing_old", got.Status)
	assert.Equal(t, e.clock.Now(), *got.OverlapUntil)
	m := e.mails("rotation.overlap_ending")
	require.Len(t, m, 1, "row 31: the new removal time is mailed")
	assert.Equal(t, "2026-10-05 13:00 UTC", m[0]["overlap_until"])
	assert.Equal(t, 1, e.audits("rotation.finish_requested"))
}

func TestKeepOldNeedsAVerifiedLocation(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	e.addLocation(k.ID, srv, "root")
	r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginUnprovable,
		"root": providers.KeyLoginUnprovable})
	require.Equal(t, "verifying_new", r.Status)
	assert.ErrorIs(t, e.svc.KeepOld(e.ctx, e.admin, r.ID, []uuid.UUID{ids["deploy"], ids["root"]}), sshkeys.ErrNotWaiting,
		"nothing would be rotated")
	assert.Equal(t, "unverifiable", e.locState(r, "deploy"), "nothing changed")

	e2 := newEnv(t)
	srv2 := e2.server("web-01")
	k2 := e2.deployed("ci", srv2, "deploy")
	e2.addLocation(k2.ID, srv2, "root")
	r2, ids2 := e2.runToDecisionWith(k2, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted,
		"root": providers.KeyLoginUnprovable})
	assert.ErrorIs(t, e2.svc.KeepOld(e2.ctx, e2.admin, r2.ID, []uuid.UUID{ids2["deploy"]}), sshkeys.ErrNotWaiting, "only unverifiable ones")
	assert.ErrorIs(t, e2.svc.KeepOld(e2.ctx, e2.admin, r2.ID, nil), sshkeys.ErrNotWaiting)
	require.NoError(t, e2.svc.KeepOld(e2.ctx, e2.admin, r2.ID, []uuid.UUID{ids2["root"]}))
	got := e2.run(r2.ID)
	assert.Equal(t, "overlap", got.Status)
	assert.Equal(t, "kept_old", e2.locState(got, "root"))
	assert.Equal(t, "verified", e2.locState(got, "deploy"))
	assert.Equal(t, "1", e2.lastAuditDetail("rotation.old_kept", "location_count"))
	assert.ErrorIs(t, e2.svc.KeepOld(e2.ctx, e2.admin, r2.ID, []uuid.UUID{ids2["root"]}), sshkeys.ErrNotWaiting, "no longer waiting")
}

func TestAbortStates(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	_, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	previewed := e.openRun(p.ID)
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, previewed))
	got := e.run(previewed)
	assert.Equal(t, "cancelled", got.Status)
	assert.Equal(t, "rotation.stopped", got.ResultCode)
	assert.Equal(t, 1, e.audits("rotation.stop_requested"))

	// In the overlap: every added location is undone, kept_old included.
	e2 := newEnv(t)
	srv2 := e2.server("web-01")
	k2 := e2.deployed("ci", srv2, "deploy")
	e2.addLocation(k2.ID, srv2, "root")
	r2, ids2 := e2.runToDecisionWith(k2, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted,
		"root": providers.KeyLoginUnprovable})
	require.NoError(t, e2.svc.KeepOld(e2.ctx, e2.admin, r2.ID, []uuid.UUID{ids2["root"]}))
	e2.gate.lock()
	assert.ErrorIs(t, e2.svc.Abort(e2.ctx, e2.admin, r2.ID), license.ErrLocked)
	e2.gate.unlock()
	require.NoError(t, e2.svc.Abort(e2.ctx, e2.admin, r2.ID))
	assert.Equal(t, "rolling_back", e2.run(r2.ID).Status)
	assert.Equal(t, 2, e2.jobsOf("undo"))
	e2.undoAt(ids2["deploy"])
	e2.undoAt(ids2["root"])
	require.NoError(t, e2.svc.Advance(e2.ctx, r2.ID))
	assert.Equal(t, "aborted", e2.run(r2.ID).Status)
	assert.Len(t, e2.mails("rotation.aborted"), 1)
	assert.Equal(t, "rotation.stopped", e2.mails("rotation.aborted")[0]["code"])

	// Removing the old key cannot be stopped.
	e3 := newEnv(t)
	id, _ := e3.runInRemoving(e3.deployed("ci", e3.server("web-01"), "deploy"))
	assert.ErrorIs(t, e3.svc.Abort(e3.ctx, e3.admin, id), sshkeys.ErrNotWaiting)
}

// The sweep re-queues a location's job when none is live (dedupe: no second while one is), at most
// MaxLocationJobs times; then the location ends add_failed (rotation.retries_exhausted) and the run
// rolls back.
func TestSweepRequeuesAndBoundsRetries(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	sum, err := e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, sum.Requeued, "the first add job is still live")
	finishJobs := func() {
		_, err := e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'failed' WHERE type = 'rotation.location' AND payload ? 'phase' AND status IN ('queued', 'running')")
		require.NoError(t, err)
	}
	finishJobs()
	sum, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sum.Requeued)
	sum, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, sum.Requeued, "dedupe: one live job")
	for range sshkeys.MaxLocationJobs {
		finishJobs()
		_, err = e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	got := e.run(r.ID)
	assert.Equal(t, "add_failed", got.Locations[0].State)
	assert.Equal(t, "rotation.retries_exhausted", got.Locations[0].ErrorCode)
	assert.Equal(t, "rolling_back", got.Status)
	assert.Equal(t, "rotation.add_failed", got.ResultCode)
}
