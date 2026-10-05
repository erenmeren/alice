//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
)

// N18: one location whose re-queue the database refuses does not stall the others; it ends in its
// failed state with the reason recorded, and the run reaches needs_attention naming it.
func TestRequeueRefusalOfOneLocationDoesNotStallTheRun(t *testing.T) {
	e := newEnv(t)
	web1, web2 := e.server("web-01"), e.server("web-02")
	k := e.deployed("ci", web1, "deploy")
	e.addLocation(k.ID, web2, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 0, 24))
	locs := map[uuid.UUID]uuid.UUID{}
	for _, l := range r.Locations {
		locs[l.TargetID] = l.ID
		e.drive(l.ID, providers.KeyLoginAccepted)
	}
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	require.Equal(t, "removing_old", e.run(r.ID).Status)
	for _, l := range locs {
		require.NoError(t, e.svc.RecordReverify(e.claimed(), l, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
		_, err := e.svc.BeginRemove(e.claimed(), l)
		require.NoError(t, err)
	}
	// After web-01's send its old location became Alice's connection key: every write of that
	// removing row is refused from now on.
	_, err := e.db.Owner.Exec(e.ctx, `UPDATE ssh_key_locations SET is_alice_connection_key = true WHERE id = (SELECT old_location_id
FROM rotation_locations WHERE id = $1)`, locs[web1])
	require.NoError(t, err)
	e.failLocationJobs()
	sum, err := e.svc.Sweep(e.ctx)
	assert.NoError(t, err, "a handled refusal is not an error of the tick (round 4, A-m3)")
	assert.Equal(t, 1, sum.Requeued, "web-02 got its job")
	got := e.run(r.ID)
	var w1 sshkeys.RotationLocation
	for _, l := range got.Locations {
		if l.ID == locs[web1] {
			w1 = l
		}
	}
	assert.Equal(t, "remove_failed", w1.State)
	assert.Equal(t, "rotation.guard_refused", w1.ErrorCode)
	assert.Contains(t, e.logs.String(), "the database refused a location's re-queue")
	require.NoError(t, e.svc.FinishRemove(e.claimed(), e.jobActor(), locs[web2], sshkeys.RemoveRecord{Definite: true, Removed: 1,
		Res: providers.AuthKeyResult{Removed: 1}}))
	for range 2*sshkeys.MaxLocationJobs + 2 {
		e.failLocationJobs()
		_, _ = e.svc.Sweep(e.ctx)
	}
	got = e.run(r.ID)
	assert.Equal(t, "needs_attention", got.Status)
	m := e.mails("rotation.needs_attention")
	require.Len(t, m, 1)
	assert.Equal(t, "web-01", m[0]["remove_failed_servers"])
}

// M1: BeginUndo on a clock stepped back behind the latest re-send answers the retryable clock refusal.
func TestBeginUndoClockCheckUsesTheLatestSend(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	e.clock.Advance(time.Minute)
	_, err = e.svc.BeginAdd(e.claimed(), loc) // re-send
	require.NoError(t, err)
	resent := e.clock.Now()
	require.NoError(t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
	e.clock.Set(resent.Add(-time.Second))
	_, err = e.svc.BeginUndo(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "retryable, not an unexpected error")
	assert.NotContains(t, e.logs.String(), "the database refused a rotation step", "the store's own check")
	e.clock.Set(resent)
	_, err = e.svc.BeginUndo(e.claimed(), loc)
	assert.NoError(t, err)
}

// M11: a lock shorter than one sweep does not use up a retry: the job that answered ErrPaused gives
// its count back.
func TestShortLockGivesTheRetryBack(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	e.failLocationJobs()
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, e.count("SELECT job_count FROM rotation_locations WHERE id = $1", loc))
	e.gate.lock()
	_, err = e.svc.BeginAdd(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrPaused)
	e.gate.unlock() // before any sweep saw the lock
	assert.Zero(t, e.count("SELECT job_count FROM rotation_locations WHERE id = $1", loc))
	assert.False(t, e.run(r.ID).PausedLicense)
}

// M7: any planner skip reason found at send time ends the location cancelled with that reason at
// once; the others carry on.
func TestSkipFoundAtSendTimeCancelsTheLocation(t *testing.T) {
	e := newEnv(t)
	web1, web2 := e.server("web-01"), e.server("web-02")
	k := e.deployed("ci", web1, "deploy")
	e.addLocation(k.ID, web2, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 0, 24))
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET keys_managed_elsewhere = true WHERE id = $1", web2)
	require.NoError(t, err)
	var w2 uuid.UUID
	for _, l := range r.Locations {
		if l.TargetID == web2 {
			w2 = l.ID
		}
	}
	_, err = e.svc.BeginAdd(e.claimed(), w2)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	for _, l := range e.run(r.ID).Locations {
		if l.ID == w2 {
			assert.Equal(t, "cancelled", l.State)
			assert.Equal(t, "keys_managed_elsewhere", l.SkipReason)
			assert.Equal(t, "rotation.skipped_at_send", l.ErrorCode)
		}
	}
	assert.Zero(t, e.count("SELECT job_count FROM rotation_locations WHERE id = $1", w2))
}

// M2: KeptCount is exact when a late "removed" is followed by a retry that also removes.
func TestKeptCountWithALateRemovalAndARetry(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	web2 := e.server("web-02")
	e.addLocation(k.ID, web2, "app")
	e.setTargetStatus(web2, "unreachable") // skipped: the old key stays there
	id, loc := e.runInRemoving(k)
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
	for range sshkeys.MaxLocationJobs + 1 { // the removing row's bound only
		e.failLocationJobs()
		_, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	require.Equal(t, "remove_failed", e.run(id).Locations[0].State)
	require.NoError(t, e.svc.FinishRemove(e.claimed(), e.jobActor(), loc, sshkeys.RemoveRecord{Definite: true, Removed: 1,
		Res: providers.AuthKeyResult{Removed: 1}})) // late: the first send did remove
	e.clock.Advance(time.Minute)
	e.removeAt(loc) // the retry removes too (nothing left)
	require.NoError(t, e.svc.Advance(e.ctx, id))
	got := e.run(id)
	assert.Equal(t, "completed", got.Status)
	assert.Equal(t, 1, got.KeptCount, "the skipped place only")
}

// M3: while the licence is locked the run's notice state is the licence pause, not "notice pending".
func TestNoticeStateInLock(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	e.clock.Advance(7 * 24 * time.Hour)
	e.gate.lock()
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "rotation.paused_license", e.run(r.ID).NoticeState)
	e.gate.unlock()
	assert.Equal(t, "rotation.notice_pending", e.run(r.ID).NoticeState)
}

// M4: a failing renewal notice records one notice_failed step per pause.
func TestNoticeFailureIsOneStepPerPause(t *testing.T) {
	e := newEnv(t)
	f := e.withFaults()
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	e.clock.Advance(7 * 24 * time.Hour)
	e.gate.lock()
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	e.gate.unlock()
	f.mail.Store(true)
	for range 3 {
		assert.Error(t, e.svc.Advance(e.ctx, r.ID))
	}
	assert.Equal(t, 1, e.count("SELECT count(*) FROM rotation_steps WHERE rotation_id = $1 AND name = 'notice_failed'", r.ID))
}

// M5: re-sends are visible on the run read.
func TestResendsAreVisible(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	e.clock.Advance(time.Second)
	_, err = e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	got := e.run(r.ID).Locations[0]
	assert.Equal(t, 1, got.AddResendCount)
	require.NotNil(t, got.AddResentAt)
	assert.Equal(t, e.clock.Now(), *got.AddResentAt)
}

// M9: the summary's buckets add up to the total.
func TestSummaryBucketsAddUp(t *testing.T) {
	e := newEnv(t)
	web1, web2, web3 := e.server("web-01"), e.server("web-02"), e.server("web-03")
	k := e.deployed("ci", web1, "deploy")
	e.addLocation(k.ID, web2, "deploy")
	e.addLocation(k.ID, web3, "deploy")
	e.setTargetStatus(web3, "unreachable")
	p := e.policy(k.ID, 90, 7, 24)
	r := e.runNow(p)
	for _, l := range r.Locations {
		if l.TargetID == web1 {
			e.drive(l.ID, providers.KeyLoginAccepted)
		}
	}
	list, _, err := e.svc.RotationSummaries(e.ctx, sshkeys.RotationFilter{PolicyID: p.ID})
	require.NoError(t, err)
	c := list[0].Counts
	assert.Equal(t, sshkeys.LocationCounts{Total: 3, Verified: 1, Skipped: 1, InFlight: 1}, c)
	assert.Equal(t, c.Total, c.Verified+c.Removed+c.Kept+c.Failed+c.Skipped+c.Undone+c.Cancelled+c.InFlight)
}

// M6: a scheduled plan in which every location is skipped notifies the Administrators once for that
// interval, and the interval counts as done.
func TestScheduledPlanWithNothingToRotateNotifiesOnce(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	e.setTargetStatus(srv, "unreachable")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	next := *p.NextRunAt
	e.clock.Advance(89 * 24 * time.Hour)
	for range 3 {
		n, err := e.svc.PlanDue(e.ctx)
		require.NoError(t, err)
		assert.Zero(t, n)
	}
	m := e.mails("rotation.nothing_to_rotate")
	require.Len(t, m, 1)
	assert.Equal(t, "ci", m[0]["key_label"])
	assert.Equal(t, "1", m[0]["skip_count"])
	assert.Equal(t, "web-01: target_not_connected", m[0]["skips"])
	assert.Equal(t, next.Add(90*24*time.Hour), *e.reloadPolicy(p.ID).NextRunAt, "the interval counts as done")
}

// Ruling 2: a location already adding when the connection-files refusal is found ends add_failed and
// the run rolls back (its earlier send is undone after S3's wait).
func TestAddingRowRefusedAtResendRollsBack(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	e.setKeyFiles(srv, []providers.UserKeyFiles{{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}, Complete: true}})
	_, err = e.svc.BeginAdd(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	assert.Equal(t, "add_failed", e.run(r.ID).Locations[0].State)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "rolling_back", e.run(r.ID).Status)
	_, err = e.svc.BeginUndo(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "S3: the earlier send may still land")
	e.clock.Advance(helperproto.HelperBudget + 31*time.Second)
	e.undoAt(loc)
}

// G20: a retry of a failed removal is refused by the store's own check until the clock passes the
// stamped failure time (no database refusal is logged).
func TestRemovalRetryWaitsForTheFailureTime(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	id, loc := e.runInRemoving(k)
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.FinishRemove(e.claimed(), e.jobActor(), loc, sshkeys.RemoveRecord{Definite: true, Reason: "ssh.helper_refused"}))
	failedAt := e.clock.Now()
	e.clock.Set(failedAt.Add(-30 * time.Second)) // a clock step back
	assert.ErrorIs(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}), sshkeys.ErrNotYourTurn)
	assert.NotContains(t, e.logs.String(), "the database refused a rotation step")
	e.clock.Set(failedAt.Add(time.Second))
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	assert.Equal(t, "removing", e.locState(e.run(id), "deploy"))
}

// Restored cases of the old connection-account test: unknown files refuse; known again → sent.
func TestBeginAddConnectionFilesUnknownThenKnown(t *testing.T) {
	e := newEnv(t)
	web1, web2 := e.server("web-01"), e.server("web-02")
	k := e.deployed("ci", web1, "deploy")
	e.addLocation(k.ID, web2, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	ids := map[uuid.UUID]uuid.UUID{}
	for _, l := range r.Locations {
		ids[l.TargetID] = l.ID
	}
	e.setKeyFiles(web1, []providers.UserKeyFiles{{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}, Complete: true}})
	_, err := e.svc.BeginAdd(e.claimed(), ids[web1])
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "files unknown")
	e.setKeyFiles(web2, keyFiles) // web-02's list is known
	_, err = e.svc.BeginAdd(e.claimed(), ids[web2])
	assert.NoError(t, err, "known: sent")
}
