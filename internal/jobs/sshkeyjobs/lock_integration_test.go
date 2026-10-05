//go:build integration

package sshkeyjobs_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/providers/fake"
	"alice/internal/sshkeys"
)

// scheduler is the periodic side as cmd/alice runs it: planning, the sweep and the destruction of
// retired private keys, each behind the license gate.
func (e *env) scheduler() *jobs.Scheduler {
	return jobs.NewScheduler(e.tick, e.gate, e.log,
		jobs.Task{Type: jobs.RotationPlan, Every: time.Minute, Run: func(ctx context.Context) error { _, err := e.keys.PlanDue(ctx); return err }},
		jobs.Task{Type: jobs.RotationSweep, Every: time.Minute, Run: func(ctx context.Context) error { _, err := e.keys.Sweep(ctx); return err }},
		jobs.Task{Type: jobs.SSHKeyDestroyRetired, Every: time.Hour, Run: func(ctx context.Context) error {
			_, err := e.keys.DestroyRetiredKeys(ctx)
			return err
		}})
}

// tick runs every task of the scheduler once (a refusal of the gate is the task pausing).
func (e *env) tickAll(s *jobs.Scheduler) {
	e.t.Helper()
	for _, name := range []string{jobs.RotationPlan.Name, jobs.RotationSweep.Name, jobs.SSHKeyDestroyRetired.Name} {
		if err := s.RunNow(e.ctx, name); err != nil {
			require.ErrorIs(e.t, err, license.ErrLocked, name)
		}
	}
}

// overlapRun rotates a key at web-01:deploy with an overlap of days and drains it into the overlap.
func (e *env) overlapRun(days int) (sshkeys.ManagedKey, uuid.UUID, sshkeys.Rotation) {
	e.t.Helper()
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	r := e.runNow(e.policy(k.ID, days))
	e.drain()
	r = e.run(r.ID)
	require.Equal(e.t, sshkeys.StatusOverlap, r.Status)
	return k, web, r
}

// l83 is L-83: a run in overlap with 4 days left; the lock begins; the overlap's end passes and 5 days of
// sweeps and jobs follow: nothing is removed, the run is paused with one email.
func (e *env) l83() (sshkeys.ManagedKey, uuid.UUID, sshkeys.Rotation) {
	e.t.Helper()
	k, web, r := e.overlapRun(7)
	e.clock.Advance(3 * 24 * time.Hour)
	e.gate.lock()
	for range 20 {
		e.clock.Advance(6 * time.Hour)
		e.sweep()
		e.drain()
	}
	return k, web, e.run(r.ID)
}

func TestL83OverlapLockRemovesNothing(t *testing.T) {
	e := newEnv(t)
	_, _, r0 := e.overlapRun(7)
	e.clock.Advance(3 * 24 * time.Hour)
	e.gate.lock()
	e.sweep() // the first sweep in lock pauses the overlap at once (L-83 ruling), with one email
	r0 = e.run(r0.ID)
	assert.True(t, r0.PausedLicense, "paused at the first sweep in lock")
	assert.Len(t, e.mails("rotation.paused_license"), 1)
	e = newEnv(t)
	k, web, r := e.l83()
	assert.Equal(t, sshkeys.StatusOverlap, r.Status)
	assert.True(t, r.PausedLicense)
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	assert.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
	assert.True(t, e.world.Has(web, keyFile("deploy"), r.NewFingerprint))
	assert.Len(t, e.mails("rotation.paused_license"), 1)
}

// L-84: renewal after 20 days of lock. Nothing changes servers until an Administrator chooses Continue;
// Continue is refused until the sweep has sent the renewal notice (S6, Task 9 review I2); every removal
// is preceded by a fresh login with the new key.
func TestL84RenewalAfterTwentyDays(t *testing.T) {
	e := newEnv(t)
	k, web, r := e.l83()
	e.clock.Advance(20 * 24 * time.Hour)
	e.sweep()
	e.drain()
	e.gate.unlock() // the renewal
	require.ErrorIs(t, e.keys.Continue(e.ctx, e.admin, r.ID), sshkeys.ErrNoticePending, "no Continue before the renewal notice")
	assert.Empty(t, e.mails("rotation.preview_after_license"))
	e.sweep()
	e.drain()
	r = e.run(r.ID)
	assert.True(t, r.PausedLicense, "still paused after the renewal (R29)")
	assert.Len(t, e.mails("rotation.preview_after_license"), 1, "the sweep tells the Administrators first")
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	logins := e.countEvents("VerifyKeyLogin")
	remaining := 4 * 24 * time.Hour // the overlap had 4 of its 7 days left when the lock paused it
	require.NoError(t, e.keys.Continue(e.ctx, e.admin, r.ID))
	assert.Len(t, e.mails("rotation.preview_after_license"), 1, "Continue sends no second notice")
	r = e.run(r.ID)
	require.Equal(t, sshkeys.StatusOverlap, r.Status, "the overlap resumes; its end was never reached in lock")
	require.NotNil(t, r.OverlapUntil)
	assert.WithinDuration(t, e.clock.Now().Add(remaining), *r.OverlapUntil, 6*time.Hour+time.Minute,
		"the overlap resumes with the time that remained when the pause began")
	e.clock.Advance(r.OverlapUntil.Sub(e.clock.Now()) - time.Minute)
	e.sweep()
	e.drain()
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"), "nothing before the resumed overlap ends")
	e.clock.Advance(time.Minute)
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusCompleted, r.Status)
	assert.Equal(t, logins+1, e.countEvents("VerifyKeyLogin"), "a fresh login after Continue")
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, r.NewFingerprint)
	assert.False(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
}

// L-85: the lock begins while the first add is in flight: that add completes and is verified; nothing
// more is added, nothing removed; the run is paused while adding.
func TestL85AddInFlightAtLock(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.N == 1 {
			e.gate.lock() // the call itself proceeds
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	first := r.Locations[0]
	e.drain()
	e.sweep()
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, sshkeys.StatusAddingNew, r.Status)
	assert.True(t, r.PausedLicense)
	assert.Equal(t, sshkeys.LocVerified, e.loc(r.ID, first.TargetID, "deploy").State, "the add in flight finished and was verified")
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"), "no further add in lock")
	assert.Equal(t, 1, e.countEvents("VerifyKeyLogin"))
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	assert.Len(t, e.mails("rotation.paused_license"), 1)
}

// L-86: the lock begins inside the first add and its login is refused: the run rolls back in lock, the
// undo removes the new key from that file only, the old key is untouched everywhere.
func TestL86VerifyFailsDuringLock(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch {
		case p.N == 1:
			e.gate.lock()
		case p.Method == "VerifyKeyLogin":
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	first := r.Locations[0]
	r = e.settleRun(r.ID)
	assert.True(t, e.gate.locked.Load(), "all of it in lock")
	assert.Equal(t, sshkeys.StatusAborted, r.Status)
	assert.Equal(t, sshkeys.ReasonVerifyFailed, r.ResultCode)
	removals := e.events("RemoveAuthorizedKey")
	require.Len(t, removals, 1, "the undo removed the new key where this run added it, and nowhere else")
	assert.Equal(t, r.NewFingerprint, removals[0].Fingerprint)
	assert.Equal(t, first.TargetID, removals[0].Target)
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"))
	for _, f := range e.files(k) {
		assert.True(t, e.world.Has(f.target, f.path, k.Fingerprint))
		assert.False(t, e.world.Has(f.target, f.path, r.NewFingerprint))
	}
	assert.GreaterOrEqual(t, e.count("SELECT count(*) FROM audit_log WHERE action = 'rotation.status_changed' AND details->>'rotation_id' = $1",
		r.ID.String()), 3, "adding_new, rolling_back, aborted")
}

// L-88: the lock begins at the instant a scheduled preview is due: the tick does not run (read-only
// work), no run is created, no email; after the renewal the next tick previews.
func TestL88LockAtPreviewTime(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	p := e.policy(k.ID, 7)
	p, err := e.keys.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, true)
	require.NoError(t, err)
	require.NotNil(t, p.NextRunAt)
	e.clock.Set(p.NextRunAt.Add(-24 * time.Hour)) // the preview is due now
	s := e.scheduler()
	e.gate.lock()
	tables := []string{"rotations", "rotation_locations", "rotation_steps", "rotation_policies", "ssh_keys", "managed_private_keys",
		"ssh_key_locations", "notifications_outbox"}
	before := map[string]int{}
	for _, tbl := range tables {
		before[tbl] = e.count("SELECT count(*) FROM " + tbl)
	}
	require.ErrorIs(t, s.RunNow(e.ctx, jobs.RotationPlan.Name), license.ErrLocked, "a read-only tick does not run in lock")
	e.tickAll(s)
	for _, tbl := range tables {
		assert.Equal(t, before[tbl], e.count("SELECT count(*) FROM "+tbl), tbl)
	}
	assert.Empty(t, e.mails("rotation.preview"))
	e.gate.unlock()
	require.NoError(t, s.RunNow(e.ctx, jobs.RotationPlan.Name))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM rotations WHERE policy_id = $1", p.ID))
	assert.Len(t, e.mails("rotation.preview"), 1)
}

// L-29 for rotation: in lock, three days of scheduled planning, sweeps and destruction of retired keys
// send nothing to any server and destroy nothing.
func TestNoRemoteCommandFromScheduledWorkInLock(t *testing.T) {
	e := newEnv(t)
	_, _, r := e.overlapRun(1)
	retired := e.generate("old")
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", retired.ID, e.clock.Now().Add(-40*24*time.Hour))
	require.NoError(t, err)
	envelopes := e.count("SELECT count(*) FROM managed_private_keys WHERE destroyed_at IS NULL")
	calls := e.worldCalls()
	s := e.scheduler()
	e.gate.lock()
	for range 72 {
		e.clock.Advance(time.Hour)
		e.tickAll(s)
		e.drain()
	}
	assert.Equal(t, calls, e.worldCalls(), "no remote command in lock")
	assert.Equal(t, envelopes, e.count("SELECT count(*) FROM managed_private_keys WHERE destroyed_at IS NULL"), "nothing destroyed in lock")
	r = e.run(r.ID)
	assert.Equal(t, sshkeys.StatusOverlap, r.Status)
	assert.True(t, r.PausedLicense, "the sweep flagged the pause at the overlap's end (L-83)")
}

// Task 9 review I4: a lock while an add is in flight in a dead process: the recovered job only verifies
// the line (no send in lock), the run is never rolled back for the lock and nothing else is sent; after
// the renewal it carries on to the end.
func TestLockWithACrashedAddPauses(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	kill := newKiller("session:after:AddAuthorizedKey")
	e.setKiller(kill)
	r := e.runNow(e.policy(k.ID, 1))
	e.drainDying()
	require.Equal(t, "session:after:AddAuthorizedKey", kill.firedAt())
	e.setKiller(nil)
	e.gate.lock()
	e.restart()
	for range 10 {
		e.clock.Advance(time.Minute)
		e.sweep()
		e.drain()
	}
	r = e.run(r.ID)
	assert.NotContains(t, []string{sshkeys.StatusRollingBack, sshkeys.StatusAborted}, r.Status, "never rolled back for the lock")
	assert.Equal(t, sshkeys.LocVerified, r.Locations[0].State, "the add in flight was verified, not sent again")
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"))
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	e.drain()
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"), "nothing removed in lock")
	r = e.run(r.ID)
	assert.Equal(t, sshkeys.StatusAddingNew, r.Status)
	assert.True(t, r.PausedLicense, "a lock with an add in flight pauses the run (review I4)")
	e.gate.unlock()
	e.sweep()
	require.NoError(t, e.keys.Continue(e.ctx, e.admin, r.ID))
	e.drain()
	require.Equal(t, sshkeys.StatusOverlap, e.run(r.ID).Status)
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusCompleted, r.Status)
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, r.NewFingerprint)
}

// S1 on an advancing clock (Task 9 re-review C1): a scheduled run whose notice was delivered starts at
// its planned time and completes; the services' clock moves on every read, as a real one does.
func TestScheduledRunStartsOnAnAdvancingClock(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	p := e.policy(k.ID, 1)
	p, err := e.keys.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, true)
	require.NoError(t, err)
	e.tick.on.Store(true)
	e.clock.Set(p.NextRunAt.Add(-24 * time.Hour))
	s := e.scheduler()
	require.NoError(t, s.RunNow(e.ctx, jobs.RotationPlan.Name))
	var runID uuid.UUID
	var plannedFor time.Time
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT id, planned_for FROM rotations WHERE policy_id = $1", p.ID).Scan(&runID, &plannedFor))
	require.Len(t, e.mails("rotation.preview"), 1)
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE notifications_outbox SET status = 'sent', sent_at = $1 WHERE template_key = 'rotation.preview'`,
		e.clock.Now())
	require.NoError(t, err)
	e.clock.Set(plannedFor)
	require.NoError(t, s.RunNow(e.ctx, jobs.RotationSweep.Name))
	assert.Equal(t, sshkeys.StatusAddingNew, e.run(runID).Status, "a delivered notice lets the scheduled run start")
	e.drain()
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	r := e.settleRun(runID)
	assert.Equal(t, sshkeys.StatusCompleted, r.Status)
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, r.NewFingerprint)
}

// A short lock while a failed removal's retry job runs: the re-check is refused by the gate, nothing is
// sent, and the store gives the retry back (step retry_returned); after the renewal the removal completes.
func TestLockDuringARemovalRetryReturnsTheRetry(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	removes, locked := 0, false
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "RemoveAuthorizedKey" {
			if removes++; removes == 1 {
				return fake.FaultUnreachable
			}
		}
		if p.Method == "VerifyKeyLogin" && removes == 1 && !locked {
			locked = true
			e.gate.lock() // the lock begins while the retry's re-check runs
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	e.drain()
	require.Equal(t, sshkeys.LocRemoveFailed, e.loc(r.ID, web, "deploy").State)
	e.clock.Advance(time.Minute)
	e.sweep()
	e.drain()
	assert.True(t, e.gate.locked.Load())
	assert.Equal(t, 1, removes, "nothing sent in lock")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM rotation_steps WHERE rotation_id = $1 AND name = 'retry_returned'", r.ID))
	assert.Equal(t, sshkeys.LocRemoveFailed, e.loc(r.ID, web, "deploy").State)
	e.gate.unlock()
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusCompleted, r.Status)
	assert.Equal(t, 2, removes)
}
