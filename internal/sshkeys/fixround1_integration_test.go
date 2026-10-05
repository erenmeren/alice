//go:build integration

package sshkeys_test

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
)

// waitForLockWait blocks until a session of the test database waits on a row lock (a barrier for
// two-connection tests: no sleeps).
func (e *env) waitForLockWait() {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if e.count("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'") > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatal("no session waited on a lock")
}

// C1: on a clock that moves between reads (as a real one does) a scheduled run whose notice was
// delivered starts.
func TestScheduledRunStartsOnARealClock(t *testing.T) {
	e := newEnv(t)
	e.tick.on.Store(true)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	id := e.openRun(p.ID)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE notifications_outbox SET status = 'sent', sent_at = $1 WHERE status = 'pending'", e.clock.Now())
	require.NoError(t, err)
	e.clock.Set(e.run(id).PlannedFor)
	require.NoError(t, e.svc.Advance(e.ctx, id))
	assert.Equal(t, "adding_new", e.run(id).Status, "the delivered notice counts")
}

// I1: after an add without a definite answer, a login that proves nothing (refused on a line with
// from=, or unprovable) does not make the add definite: the undo still waits for the helper's budget.
// A refused login records no inventory location (S4 names accepted and unprovable only).
func TestUndoWaitsAfterAnUnprovenLogin(t *testing.T) {
	for _, outcome := range []providers.KeyLoginOutcome{providers.KeyLoginRefused, providers.KeyLoginUnprovable} {
		t.Run(string(outcome), func(t *testing.T) {
			e := newEnv(t)
			srv := e.server("web-01")
			k := e.generate("ci")
			e.addLocation(k.ID, srv, "deploy")
			_, err := e.db.Owner.Exec(e.ctx, `UPDATE ssh_key_locations SET options = 'from="10.0.0.0/8"' WHERE ssh_key_id = $1`, k.ID)
			require.NoError(t, err)
			r := e.runNow(e.policy(k.ID, 90, 7, 24))
			loc := r.Locations[0].ID
			_, err = e.svc.BeginAdd(e.claimed(), loc)
			require.NoError(t, err)
			sent := e.clock.Now()
			require.NoError(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: false}))
			require.NoError(t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: outcome}))
			got := e.run(r.ID).Locations[0]
			assert.Equal(t, "unverifiable", got.State)
			if outcome == providers.KeyLoginRefused {
				assert.Nil(t, got.NewLocationID, "a refused login proves nothing")
			}
			require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
			e.clock.Set(sent.Add(helperproto.HelperBudget + 30*time.Second - time.Second))
			_, err = e.svc.BeginUndo(e.claimed(), loc)
			assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "a late write may still land")
			e.clock.Advance(time.Second)
			_, err = e.svc.BeginUndo(e.claimed(), loc)
			assert.NoError(t, err)
		})
	}
}

// I2 (S6, L-84): Continue is refused until the sweep queued the renewal notice of this pause, and
// never queues it itself; a second lock before Continue clears it, so the next renewal is announced
// again.
func TestContinueNeedsTheRenewalNotice(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	e.clock.Advance(7 * 24 * time.Hour)
	e.gate.lock()
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	require.True(t, e.run(r.ID).PausedLicense)
	assertErr := func(want error) {
		t.Helper()
		assert.ErrorIs(t, e.svc.Continue(e.ctx, e.admin, r.ID), want)
	}
	assert.ErrorIs(t, e.svc.Continue(e.ctx, e.admin, r.ID), license.ErrLocked)
	e.gate.unlock()
	assertErr(sshkeys.ErrNoticePending)
	assert.NotContains(t, sshkeys.AllowedActions(e.run(r.ID), true), "continue")
	assert.Empty(t, e.mails("rotation.preview_after_license"), "Continue never sends it")
	_, err := e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Len(t, e.mails("rotation.preview_after_license"), 1)
	assert.Equal(t, "overlap", e.run(r.ID).Status, "the sweep that sent the notice changed nothing else")
	assert.Contains(t, sshkeys.AllowedActions(e.run(r.ID), true), "continue")
	// A second lock before Continue: the renewal is announced again.
	e.gate.lock()
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Nil(t, e.run(r.ID).RenotifiedAt)
	e.gate.unlock()
	assertErr(sshkeys.ErrNoticePending)
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Len(t, e.mails("rotation.preview_after_license"), 2)
	require.NoError(t, e.svc.Continue(e.ctx, e.admin, r.ID))
	got := e.run(r.ID)
	assert.False(t, got.PausedLicense)
	assert.Equal(t, "removing_old", got.Status)
	assert.Len(t, e.mails("rotation.preview_after_license"), 2)
	assert.Equal(t, 1, e.audits("rotation.continued"))
	var by *uuid.UUID
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT continued_by FROM rotations WHERE id = $1", r.ID).Scan(&by))
	assert.Equal(t, e.admin.UserID, *by)
	_, err = e.svc.BeginRemove(e.claimed(), ids["deploy"])
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "a fresh re-check first")
	assertErr(sshkeys.ErrNotWaiting)
}

// I3: in rolling_back an adding row whose undo jobs never get through (the server is unreachable)
// is moved to undoing by the sweep after S3's wait and the bound, and then ends undo_failed: the run
// finishes; nothing is re-queued without bound.
func TestUndoOfAnAddingRowIsBounded(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
	e.clock.Advance(helperproto.HelperBudget + 31*time.Second)
	for i := 0; i < 3*sshkeys.MaxLocationJobs; i++ {
		e.failLocationJobs()
		_, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
		assert.LessOrEqual(t, e.count("SELECT job_count FROM rotation_locations WHERE id = $1", loc), sshkeys.MaxLocationJobs)
	}
	got := e.run(r.ID)
	assert.Equal(t, "needs_attention", got.Status)
	assert.Equal(t, "undo_failed", got.Locations[0].State)
	assert.Equal(t, "rotation.retries_exhausted", got.Locations[0].ErrorCode)
}

// failLocationJobs ends every live location job, as when the handler gave up.
func (e *env) failLocationJobs() {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'failed' WHERE type = 'rotation.location' AND payload ? 'phase'
AND status IN ('queued', 'running')`)
	require.NoError(e.t, err)
}

// I4: a licence lock pauses a run with an add or a removal in flight (no planned or verified row left)
// and no retry is consumed meanwhile.
func TestLockWithASendInFlightPauses(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	e.gate.lock()
	for range sshkeys.MaxLocationJobs + 2 {
		e.failLocationJobs()
		_, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	got := e.run(r.ID)
	assert.Equal(t, "adding_new", got.Status)
	assert.True(t, got.PausedLicense)
	assert.Equal(t, "adding", got.Locations[0].State)
	assert.Zero(t, e.count("SELECT job_count FROM rotation_locations WHERE id = $1", loc), "no retry is consumed in lock")

	e2 := newEnv(t)
	id, rl := e2.runInRemoving(e2.deployed("ci", e2.server("web-01"), "deploy"))
	e2.clock.Advance(time.Minute)
	require.NoError(t, e2.svc.RecordReverify(e2.claimed(), rl, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	_, err = e2.svc.BeginRemove(e2.claimed(), rl)
	require.NoError(t, err)
	e2.gate.lock()
	for range sshkeys.MaxLocationJobs + 2 {
		e2.failLocationJobs()
		_, err := e2.svc.Sweep(e2.ctx)
		require.NoError(t, err)
	}
	got = e2.run(id)
	assert.Equal(t, "removing_old", got.Status)
	assert.True(t, got.PausedLicense)
	assert.Equal(t, "removing", got.Locations[0].State)
	assert.Zero(t, e2.count("SELECT job_count FROM rotation_locations WHERE id = $1", rl))
}

// The retry bound of a failed removal is exact: MaxLocationJobs retries, then the run needs attention.
func TestRemovalRetryBoundIsExact(t *testing.T) {
	e := newEnv(t)
	id, loc := e.runInRemoving(e.deployed("ci", e.server("web-01"), "deploy"))
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginRefused}))
	for range sshkeys.MaxLocationJobs {
		e.failLocationJobs()
		_, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	assert.Equal(t, "removing_old", e.run(id).Status)
	assert.Equal(t, sshkeys.MaxLocationJobs, e.count("SELECT count(*) FROM rotation_steps WHERE name = 'remove_retry'"))
	e.failLocationJobs()
	_, err := e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, "needs_attention", e.run(id).Status)
	assert.Equal(t, sshkeys.MaxLocationJobs, e.count("SELECT count(*) FROM rotation_steps WHERE name = 'remove_retry'"))
}

// Review M2, M3: a deploy of the old key queued during the run keeps it from being retired; a key not
// retired at completion is retired by the hourly task once nothing uses it.
func TestOldKeyRetiredOnlyWhenNothingUsesIt(t *testing.T) {
	e := newEnv(t)
	web1, web3 := e.server("web-01"), e.server("web-03")
	k := e.deployed("ci", web1, "deploy")
	id, loc := e.runInRemoving(k)
	_, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: web3, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	require.NoError(t, err)
	e.clock.Advance(time.Minute)
	e.removeAt(loc)
	require.NoError(t, e.svc.Advance(e.ctx, id))
	require.Equal(t, "completed", e.run(id).Status)
	old, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Nil(t, old.RetiredAt, "a deploy of the old key is queued")
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Nil(t, mustKey(e, k.ID).RetiredAt, "still queued")
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'cancelled' WHERE type = 'sshkey.add'")
	require.NoError(t, err)
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.NotNil(t, mustKey(e, k.ID).RetiredAt, "retired by the hourly task")
	assert.Equal(t, 1, e.audits("sshkey.retired"))
}

func mustKey(e *env, id uuid.UUID) sshkeys.ManagedKey {
	e.t.Helper()
	k, err := e.svc.ManagedKey(e.ctx, id)
	require.NoError(e.t, err)
	return k
}

// Review M4 with re-review N1: BeginAdd repeats the connection-account rule at send time and records
// the refusal at once with its own reason.
func TestBeginAddRepeatsTheConnectionAccountRule(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	_, err := e.db.Owner.Exec(e.ctx, `UPDATE targets SET config = jsonb_set(config, '{username}', '"deploy"') WHERE id = $1`, srv)
	require.NoError(t, err)
	_, err = e.svc.BeginAdd(e.claimed(), r.Locations[0].ID)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "the location's user became the connection account")
	got := e.run(r.ID).Locations[0]
	assert.Equal(t, "cancelled", got.State)
	assert.Equal(t, "sshkey.connection_account_file", got.ErrorCode)
	_ = json.Marshal
}

// Review M5: a decision that committed succeeds even when the following Advance fails.
func TestDecisionSucceedsWhenTheFollowingAdvanceFails(t *testing.T) {
	e := newEnv(t)
	f := e.withFaults()
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	f.enqueue.Store(true)
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.FinishNow(e.ctx, e.admin, r.ID), "committed: success")
	assert.Contains(t, e.logs.String(), "could not advance the rotation after a decision")
	assert.Equal(t, "overlap", e.run(r.ID).Status)
	f.enqueue.Store(false)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "removing_old", e.run(r.ID).Status)
}

// Review M9: a definite removal or undo result that arrives after the sweep exhausted the row is
// recorded as a late_result step, the inventory learns the truth, and a scan of the server is queued.
func TestLateResultAfterExhaustionIsRecorded(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	e.drive(loc, providers.KeyLoginRefused) // verify_failed: the run rolls back
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	_, err := e.svc.BeginUndo(e.claimed(), loc)
	require.NoError(t, err)
	for range sshkeys.MaxLocationJobs + 1 {
		e.failLocationJobs()
		_, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	got := e.run(r.ID)
	require.Equal(t, "undo_failed", got.Locations[0].State)
	require.Equal(t, "needs_attention", got.Status)
	newLoc := *got.Locations[0].NewLocationID
	require.NoError(t, e.svc.FinishUndo(e.claimed(), e.jobActor(), loc, sshkeys.UndoRecord{Definite: true,
		Res: providers.AuthKeyResult{Changed: true, Removed: 1}}))
	got = e.run(r.ID)
	assert.Equal(t, "undo_failed", got.Locations[0].State, "the row stays as the guards require")
	last := got.Steps[len(got.Steps)-1]
	assert.Equal(t, "late_result", last.Name)
	assert.Equal(t, "undone", last.Params["result"])
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE id = $1 AND removed_by_alice_at IS NOT NULL", newLoc))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM jobs WHERE type = 'target.discover' AND target_id = $1", srv))
	m := e.mails("rotation.late_result")
	require.Len(t, m, 1, "its own template")
	assert.Equal(t, "web-01", m[0]["server"])
	assert.Equal(t, "undone", m[0]["result"])
}

// Review M11 (R1): a manual run left previewed by a crash between its insert and its start is never
// started by the sweep; after ManualStartGrace it is cancelled.
func TestManualRunLeftPreviewedIsCancelled(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	sshkeys.OnBeforeStart(t, func() { panic("crash") })
	assert.Panics(t, func() { _, _ = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest) })
	sshkeys.OnBeforeStart(t, nil)
	id := e.openRun(p.ID)
	require.NoError(t, e.svc.Advance(e.ctx, id))
	assert.Equal(t, "dry_run_notified", e.run(id).Status, "not started by the sweep")
	e.clock.Advance(sshkeys.ManualStartGrace)
	require.NoError(t, e.svc.Advance(e.ctx, id))
	got := e.run(id)
	assert.Equal(t, "cancelled", got.Status)
	assert.Equal(t, "rotation.start_failed", got.ResultCode)
}

// Review R2: only the time rule maps to clock_behind; the download count and a destroyed key keep
// their own answers.
func TestDownloadClockBehindIsDecidedByTheStore(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "the first download"})
	require.NoError(t, err)
	dl.Body.Zero()
	e.clock.Set(start.Add(-time.Second))
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "with the clock behind"})
	assert.ErrorIs(t, err, sshkeys.ErrClockBehind)
	assert.Zero(t, e.count("SELECT count(*) FROM audit_log WHERE action = 'sshkey.private_key_download.denied'"))
}

// N3 (re-review): an instance that waited on the key's lock sees the audit row the holder wrote:
// one row.
func TestLiveAfterDestructionAfterALockWait(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	e.retireAt(k.ID, e.clock.Now())
	e.clock.Advance(30 * 24 * time.Hour)
	_, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	e.liveLocation(k)
	tx, err := e.db.Owner.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(e.ctx) }()
	_, err = tx.Exec(e.ctx, "SELECT id FROM ssh_keys WHERE id = $1 FOR UPDATE", k.ID)
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := e.svc.DestroyRetiredKeys(e.ctx)
		assert.NoError(t, err)
	}()
	e.waitForLockWait()
	_, err = e.audit.Append(e.ctx, tx, audit.Event{Actor: audit.SystemActor("jobs"), Action: "sshkey.live_after_destruction",
		ObjectType: "ssh_key", ObjectID: k.ID.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": k.ID.String()}})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(e.ctx))
	wg.Wait()
	assert.Equal(t, 1, e.audits("sshkey.live_after_destruction"))
}
