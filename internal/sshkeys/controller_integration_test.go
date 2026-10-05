//go:build integration

package sshkeys_test

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/sshkeys"
)

// dueScheduledRun plans a scheduled run of the key's enabled policy, delivers its notice and moves
// the clock to its planned start.
func (e *env) dueScheduledRun(k sshkeys.ManagedKey) (sshkeys.Policy, uuid.UUID) {
	e.t.Helper()
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(e.t, err)
	require.Equal(e.t, 1, n)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE notifications_outbox SET status = 'sent', sent_at = $1 WHERE status = 'pending'", e.clock.Now())
	require.NoError(e.t, err)
	e.clock.Advance(24 * time.Hour)
	return p, e.openRun(p.ID)
}

func TestScheduledStartReplansAndRenotifies(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p, id := e.dueScheduledRun(k)
	first := e.run(id)
	e.addLocation(k.ID, e.server("web-02"), "deploy") // a second location appears before the start
	require.NoError(t, e.svc.Advance(e.ctx, id))
	got := e.run(id)
	assert.Equal(t, "cancelled", got.Status)
	assert.Equal(t, "rotation.plan_changed", got.ResultCode)
	assert.Zero(t, e.count("SELECT count(*) FROM ssh_keys WHERE rotated_from = $1", k.ID), "nothing was generated and stored")
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	second := e.run(e.openRun(p.ID))
	assert.NotEqual(t, first.Digest, second.Digest)
	assert.Len(t, e.mails("rotation.preview"), 2)
}

// Two Advance calls at once create exactly one new key and one set of jobs; with every generation
// slot held the run waits, and a later call starts it.
func TestStartIsIdempotentAndBusySafe(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	_, id := e.dueScheduledRun(k)
	release := sshkeys.HoldGenerationSlots(t)
	require.NoError(t, e.svc.Advance(e.ctx, id))
	assert.Equal(t, "dry_run_notified", e.run(id).Status)
	release()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = e.svc.Advance(e.ctx, id)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, "adding_new", e.run(id).Status)
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_keys WHERE rotated_from = $1", k.ID))
	assert.Equal(t, 1, e.jobsOf("add"))
}

// Task 8 review I1: switching the policy off while the planner creates its run (the planner holds the
// policy lock) cancels that run; and a scheduled run of a policy that is off never starts.
func TestPolicySwitchedOffWhilePlanningCancelsTheRun(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	// A second connection holds the policy lock (as PlanDue's transaction does) and creates the run.
	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(e.ctx) }()
	_, err = tx.Exec(e.ctx, "SELECT id FROM rotation_policies WHERE id = $1 FOR UPDATE", p.ID)
	require.NoError(t, err)
	var off error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, off = e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, false)
	}()
	time.Sleep(200 * time.Millisecond) // the switch-off waits for the lock
	runID := uuid.Must(uuid.NewV7())
	_, err = tx.Exec(e.ctx, `INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type,
    overlap_minutes, planned_for, notified_at, created_at, updated_at)
VALUES ($1, $2, $3, 'scheduled', 'dry_run_notified', '{}', repeat('a', 64), 'ed25519', 0, $4, $4, $4, $4)`, runID, p.ID, k.ID, e.clock.Now())
	require.NoError(t, err)
	require.NoError(t, tx.Commit(e.ctx))
	<-done
	require.NoError(t, off)
	got := e.run(runID)
	assert.Equal(t, "cancelled", got.Status)
	assert.Equal(t, "rotation.policy_off", got.ResultCode)

	// Defence in depth: a scheduled run whose policy is off is cancelled at its start.
	e2 := newEnv(t)
	k2 := e2.deployed("ci", e2.server("web-01"), "deploy")
	p2, id2 := e2.dueScheduledRun(k2)
	_, err = e2.db.Owner.Exec(e2.ctx, "UPDATE rotation_policies SET enabled = false, next_run_at = NULL WHERE id = $1", p2.ID)
	require.NoError(t, err)
	require.NoError(t, e2.svc.Advance(e2.ctx, id2))
	assert.Equal(t, "rotation.policy_off", e2.run(id2).ResultCode)
}

// A run that becomes open between the unlocked read and the policy lock makes the policy action start
// over (it then cancels that run).
func TestPolicyActionStartsOverOnAConcurrentRun(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	fired := false
	sshkeys.OnPolicyRead(t, func() {
		if fired {
			return // PlanDue's own policy read
		}
		fired = true
		n, err := e.svc.PlanDue(e.ctx) // on its own connection: creates the run now
		require.NoError(t, err)
		require.Equal(t, 1, n)
	})
	_, err := e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, false)
	require.NoError(t, err)
	assert.Equal(t, "cancelled", e.onlyRun(p.ID).Status)
}

// Every forward step asks the license gate; an undo never does (L-83..L-88).
func TestAdvanceGatesEveryForwardStep(t *testing.T) {
	t.Run("previewed in lock is cancelled", func(t *testing.T) {
		e := newEnv(t)
		k := e.deployed("ci", e.server("web-01"), "deploy")
		_, id := e.dueScheduledRun(k)
		e.gate.lock()
		require.NoError(t, e.svc.Advance(e.ctx, id))
		assert.Equal(t, "rotation.cancelled_license", e.run(id).ResultCode)
		assert.Empty(t, e.mails("rotation.paused_license"))
	})
	t.Run("adding with a planned location pauses once", func(t *testing.T) {
		e := newEnv(t)
		k := e.deployed("ci", e.server("web-01"), "deploy")
		r := e.runNow(e.policy(k.ID, 90, 7, 24))
		e.gate.lock()
		require.NoError(t, e.svc.Advance(e.ctx, r.ID))
		require.NoError(t, e.svc.Advance(e.ctx, r.ID))
		got := e.run(r.ID)
		assert.Equal(t, "adding_new", got.Status)
		assert.True(t, got.PausedLicense)
		assert.Len(t, e.mails("rotation.paused_license"), 1, "one email")
		assert.Equal(t, 1, e.audits("rotation.paused"))
		_, err := e.svc.BeginAdd(e.claimed(), r.Locations[0].ID)
		assert.ErrorIs(t, err, sshkeys.ErrPaused)
		// The sweep queues no add job while paused.
		_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'failed' WHERE type = 'rotation.location' AND payload ? 'phase'")
		require.NoError(t, err)
		sum, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
		assert.Zero(t, sum.Requeued)
	})
	t.Run("overlap ended in lock pauses and removes nothing", func(t *testing.T) {
		e := newEnv(t)
		k := e.deployed("ci", e.server("web-01"), "deploy")
		r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
		e.clock.Advance(7 * 24 * time.Hour)
		e.gate.lock()
		require.NoError(t, e.svc.Advance(e.ctx, r.ID))
		got := e.run(r.ID)
		assert.Equal(t, "overlap", got.Status, "L-83")
		assert.True(t, got.PausedLicense)
		assert.Zero(t, e.jobsOf("remove"))
	})
	t.Run("removing with a verified location left pauses", func(t *testing.T) {
		e := newEnv(t)
		k := e.deployed("ci", e.server("web-01"), "deploy")
		id, loc := e.runInRemoving(k)
		e.gate.lock()
		require.NoError(t, e.svc.Advance(e.ctx, id))
		assert.True(t, e.run(id).PausedLicense)
		e.clock.Advance(time.Minute)
		require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
		e.gate.unlock()
		_, err := e.svc.BeginRemove(e.claimed(), loc)
		assert.ErrorIs(t, err, sshkeys.ErrPaused, "paused until Continue (G5)")
	})
	t.Run("rolling back in lock still undoes", func(t *testing.T) {
		e := newEnv(t)
		k := e.deployed("ci", e.server("web-01"), "deploy")
		r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginRefused})
		require.Equal(t, "rolling_back", r.Status)
		e.gate.lock()
		_, err := e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'failed' WHERE type = 'rotation.location' AND payload ? 'phase'")
		require.NoError(t, err)
		sum, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, sum.Requeued, "undo jobs are queued in lock")
		e.undoAt(ids["deploy"])
		require.NoError(t, e.svc.Advance(e.ctx, r.ID))
		assert.Equal(t, "aborted", e.run(r.ID).Status)
	})
}

func TestDecisionTimeout(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginUnprovable})
	require.Equal(t, "verifying_new", r.Status)
	require.NotNil(t, r.DecisionDueAt)
	assert.Equal(t, e.clock.Now().Add(14*24*time.Hour), *r.DecisionDueAt)
	e.clock.Set(r.DecisionDueAt.Add(-time.Second))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "verifying_new", e.run(r.ID).Status)
	e.clock.Advance(time.Second)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got := e.run(r.ID)
	assert.Equal(t, "rolling_back", got.Status)
	assert.Equal(t, "rotation.decision_timeout", got.ResultCode)
	assert.Equal(t, 1, e.jobsOf("undo"))
}

// S6: verifying_new pauses in lock and its decision timer stops; the first call after the renewal
// sends the notice before Continue is possible; Continue moves the deadline by the paused time.
func TestDecisionDeadlineDoesNotRunInLock(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginUnprovable})
	due := *r.DecisionDueAt
	e.clock.Advance(24 * time.Hour)
	e.gate.lock()
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.True(t, e.run(r.ID).PausedLicense)
	e.clock.Advance(20 * 24 * time.Hour) // past the deadline, in lock
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "verifying_new", e.run(r.ID).Status, "no deadline runs in lock")
	e.gate.unlock()
	_, err := e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Len(t, e.mails("rotation.preview_after_license"), 1, "the notice comes before Continue (L-84)")
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "verifying_new", e.run(r.ID).Status, "still paused after the renewal: no deadline until Continue")
	require.NoError(t, e.svc.Continue(e.ctx, e.admin, r.ID))
	got := e.run(r.ID)
	assert.False(t, got.PausedLicense)
	assert.Equal(t, "verifying_new", got.Status)
	assert.Equal(t, due.Add(20*24*time.Hour), *got.DecisionDueAt, "the deadline moved by the paused time")
	assert.Len(t, e.mails("rotation.preview_after_license"), 1, "Continue does not send it twice")
}

func TestReminderBeforeOverlapEnd(t *testing.T) {
	for _, c := range []struct {
		days  int
		mails int
	}{{3, 1}, {2, 0}} {
		e := newEnv(t)
		k := e.deployed("ci", e.server("web-01"), "deploy")
		r := e.runNow(e.policy(k.ID, 90, c.days, 24))
		e.drive(r.Locations[0].ID, providers.KeyLoginAccepted)
		require.NoError(t, e.svc.Advance(e.ctx, r.ID))
		until := *e.run(r.ID).OverlapUntil
		e.clock.Set(until.Add(-24*time.Hour - time.Second))
		require.NoError(t, e.svc.Advance(e.ctx, r.ID))
		assert.Empty(t, e.mails("rotation.overlap_ending"))
		e.clock.Advance(time.Second)
		require.NoError(t, e.svc.Advance(e.ctx, r.ID))
		require.NoError(t, e.svc.Advance(e.ctx, r.ID))
		assert.Len(t, e.mails("rotation.overlap_ending"), c.mails, "%d days", c.days)
		assert.Equal(t, "overlap", e.run(r.ID).Status)
	}
}

// S11: a location skipped at planning keeps the old key: the run completes, the old key is not
// retired, kept_count says where, and the completion email is the partial one.
func TestCompletionReportsWhereTheOldKeyStays(t *testing.T) {
	e := newEnv(t)
	web1, web2 := e.server("web-01"), e.server("web-02")
	k := e.deployed("ci", web1, "deploy")
	e.addLocation(k.ID, web2, "deploy")
	e.setTargetStatus(web2, "unreachable")
	p := e.policy(k.ID, 90, 0, 24)
	r := e.runNow(p)
	var loc uuid.UUID
	for _, l := range r.Locations {
		if l.State == "planned" {
			loc = l.ID
		}
	}
	e.drive(loc, providers.KeyLoginAccepted)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID)) // overlap of 0 minutes
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	e.removeAt(loc)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got := e.run(r.ID)
	assert.Equal(t, "completed", got.Status)
	assert.Equal(t, 1, got.KeptCount)
	old, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Nil(t, old.RetiredAt, "still live on web-02")
	assert.Equal(t, *got.NewKeyID, e.reloadPolicy(p.ID).SSHKeyID)
	assert.Empty(t, e.mails("rotation.completed"))
	m := e.mails("rotation.completed_partial")
	require.Len(t, m, 1)
	assert.Equal(t, "1", m[0]["kept_count"])
}

// Every status and location change is a step and an audit row with C12's details.
func TestStepsRecorded(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	e.drive(r.Locations[0].ID, providers.KeyLoginAccepted)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got := e.run(r.ID)
	var names []string
	for _, s := range got.Steps {
		names = append(names, s.Name)
	}
	assert.Equal(t, []string{"dry_run_notified", "adding_new", "adding", "added", "verified", "overlap"}, names)
	assert.Equal(t, 2, e.audits("rotation.status_changed"))
	assert.Equal(t, 3, e.audits("rotation.location_changed"))
	var details map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details FROM audit_log WHERE action = 'rotation.location_changed'
ORDER BY seq DESC LIMIT 1`).Scan(&details))
	assert.Equal(t, map[string]string{"rotation_id": r.ID.String(), "location_id": r.Locations[0].ID.String(),
		"target_id": r.Locations[0].TargetID.String(), "os_user": "deploy", "file_path": "/home/deploy/.ssh/authorized_keys",
		"from": "added", "to": "verified", "reason": ""}, details)
}

func TestRotationsList(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	first := e.runNow(p)
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, first.ID))
	assert.Equal(t, "aborted", e.run(first.ID).Status, "nothing was added: aborted at once")
	e.clock.Advance(time.Minute)
	second := e.runNow(p)
	list, next, err := e.svc.Rotations(e.ctx, sshkeys.RotationFilter{PolicyID: p.ID, Limit: 1})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, second.ID, list[0].ID, "newest first")
	assert.Empty(t, list[0].Steps)
	require.NotEmpty(t, next)
	list, next, err = e.svc.Rotations(e.ctx, sshkeys.RotationFilter{KeyID: k.ID, Cursor: next})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, first.ID, list[0].ID)
	assert.Empty(t, next)
	list, _, err = e.svc.Rotations(e.ctx, sshkeys.RotationFilter{KeyID: uuid.New()})
	require.NoError(t, err)
	assert.Empty(t, list)
	_, _, err = e.svc.Rotations(e.ctx, sshkeys.RotationFilter{Cursor: "!"})
	assert.ErrorIs(t, err, sshkeys.ErrBadCursor)
}
