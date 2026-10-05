//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/sshkeys"
)

// endJob ends a job with the status at the clock's time.
func (e *env) endJob(jobID uuid.UUID, status string) {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = $2, finished_at = $3 WHERE id = $1", jobID, status, e.clock.Now())
	require.NoError(e.t, err)
}

func (e *env) outcomeUnknown(jobID uuid.UUID) int {
	return e.count("SELECT count(*) FROM audit_log WHERE action = 'sshkey.add_outcome_unknown' AND request_id = $1", jobID.String())
}

func (e *env) scans(target uuid.UUID) int {
	return e.count("SELECT count(*) FROM jobs WHERE type = 'target.discover' AND target_id = $1", target)
}

// N-I1: no age limit. A deploy that ended with a send right before a 30-day licence lock is reconciled
// after the renewal (the scan it queues is read-only work, which the lock cancels: nothing is
// reconciled in lock, it catches up after).
func TestDeployEndedBeforeALongLockIsReconciledAfter(t *testing.T) {
	e := newEnv(t)
	ctx, jobID, d := e.runningDeploy("web-01")
	_, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	require.NoError(t, err)
	e.endJob(jobID, "dead")
	e.gate.lock()
	e.clock.Advance(2 * time.Hour)
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, e.outcomeUnknown(jobID), "not in lock")
	e.clock.Advance(30 * 24 * time.Hour)
	e.gate.unlock()
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, e.outcomeUnknown(jobID))
	assert.Equal(t, 1, e.scans(d.TargetID))
}

// N-m3: the batch counts unreconciled deploys only: many deploys that finished normally (older than
// the one to reconcile) do not crowd it out, and a reconciled or finished deploy is not read again.
func TestReconcileBatchIsNotCrowdedByFinishedDeploys(t *testing.T) {
	e := newEnv(t)
	sshkeys.SetReconcileBatch(t, 3)
	var finished []uuid.UUID
	for i := range 5 {
		ctx, jobID, d := e.runningDeploy("ok-" + string(rune('a'+i)))
		_, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
		require.NoError(t, err)
		require.NoError(t, e.svc.FinishDeploy(ctx, audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: jobID.String()}, d,
			sshkeys.DeployOutcome{Result: sshkeys.DeployVerified, LineNo: 1}))
		e.endJob(jobID, "succeeded")
		finished = append(finished, jobID)
		e.clock.Advance(time.Second)
	}
	var dead []uuid.UUID
	var targets []uuid.UUID
	for i := range 4 {
		ctx, jobID, d := e.runningDeploy("dead-" + string(rune('a'+i)))
		_, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
		require.NoError(t, err)
		e.endJob(jobID, "dead")
		dead, targets = append(dead, jobID), append(targets, d.TargetID)
		e.clock.Advance(time.Second)
	}
	e.clock.Advance(2 * time.Hour)
	_, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	for i, id := range dead {
		assert.Equal(t, 1, e.outcomeUnknown(id), "dead %d", i)
		assert.Equal(t, 1, e.scans(targets[i]))
	}
	for _, id := range finished {
		assert.Zero(t, e.outcomeUnknown(id))
	}
}

// N-m1: a deploy whose last attempt ended undo_failed or uncertain (sshkey.add_failed with those
// reasons) is reconciled too: one scan once the wait after its latest send is over. Other failures
// count as finished.
func TestDeployEndedUndoFailedGetsItsScanAfterTheWait(t *testing.T) {
	e := newEnv(t)
	type c struct {
		reason string
		want   int
	}
	var ids, targets []uuid.UUID
	cases := []c{{"sshkey.add_undo_failed", 1}, {"sshkey.add_uncertain", 1}, {"ssh.helper_refused", 0}}
	for i, cs := range cases {
		ctx, jobID, d := e.runningDeploy("web-0" + string(rune('1'+i)))
		_, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
		require.NoError(t, err)
		require.NoError(t, e.svc.FinishDeploy(ctx, audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: jobID.String()}, d,
			sshkeys.DeployOutcome{Result: sshkeys.DeployFailed, Reason: cs.reason}))
		e.endJob(jobID, "failed")
		ids, targets = append(ids, jobID), append(targets, d.TargetID)
	}
	_, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	for i := range cases {
		assert.Zero(t, e.scans(targets[i]), "within the wait")
	}
	e.clock.Advance(2 * time.Hour)
	for range 2 {
		_, err = e.svc.DestroyRetiredKeys(e.ctx)
		require.NoError(t, err)
	}
	for i, cs := range cases {
		assert.Equal(t, cs.want, e.scans(targets[i]), cs.reason)
		assert.Equal(t, cs.want, e.outcomeUnknown(ids[i]), cs.reason)
	}
	assert.Equal(t, "sshkey.add_undo_failed", e.count2(`SELECT details->>'last_reason' FROM audit_log
WHERE action = 'sshkey.add_outcome_unknown' AND request_id = $1`, ids[0].String()))
}

// N-m2: a send known to have written nothing does not count for ownership: the same key added by hand
// before the next send is not the job's. The next send's own listing decides instead.
func TestSendKnownNotWrittenDoesNotOwn(t *testing.T) {
	e := newEnv(t)
	ctx, jobID, d := e.runningDeploy("web-01")
	s1, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	require.NoError(t, err)
	require.True(t, s1.Record.Owned())
	rec, err := e.svc.RecordDeployNotWritten(ctx, d, s1)
	require.NoError(t, err)
	assert.Equal(t, 1, rec.NotWritten)
	assert.False(t, rec.Owned(), "nothing was written")
	assert.Equal(t, "not_written", e.lastAuditDetail("sshkey.add_answered", "answer"))
	// The key was added by hand meanwhile: the next send's listing finds it.
	s2, err := e.svc.BeginDeploySendWith(ctx, jobID, d, foundPresent)
	require.NoError(t, err)
	assert.False(t, s2.Record.Owned(), "the first send that may have written found the line")
	assert.False(t, s2.Record.AbsentBefore)
	rec, err = e.svc.DeploySends(ctx, jobID)
	require.NoError(t, err)
	assert.False(t, rec.Owned())
	// Proven absent before a later send that may have written: that send's evidence counts.
	ctx3, job3, d3 := e.runningDeploy("web-02")
	s, err := e.svc.BeginDeploySendWith(ctx3, job3, d3, foundPresent)
	require.NoError(t, err)
	_, err = e.svc.RecordDeployNotWritten(ctx3, d3, s)
	require.NoError(t, err)
	s, err = e.svc.BeginDeploySendWith(ctx3, job3, d3, provenAbsent)
	require.NoError(t, err)
	assert.True(t, s.Record.Owned())
	_, err = e.svc.RecordDeployNotWritten(ctx3, d3, sshkeys.DeploySend{Count: 5})
	assert.ErrorIs(t, err, sshkeys.ErrNoSendOnRecord)
}

// N-m11: a key that is the new key of an unfinished rotation run is not deployed (a rollback of the
// run would remove the deployed line).
func TestDeployOfARunsNewKeyIsRefused(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	newKey := *e.run(r.ID).NewKeyID
	_, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: newKey, TargetID: e.server("web-02"), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, sshkeys.ErrInRotation)
	assert.Equal(t, "sshkey.in_rotation", sshkeys.ReasonInRotation)
	// The run finished: deployable again.
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	require.Equal(t, "aborted", e.run(r.ID).Status)
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: newKey, TargetID: e.server("web-03"), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.NoError(t, err)
}

// N-m10: with a 1-day interval, a run cancelled for an undelivered notice does not skip the next day's run.
func TestNoticeUndeliveredDailyKeepsTheNextDay(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 1, 0, 24)
	first := *p.NextRunAt
	_, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	r := e.onlyRun(p.ID)
	e.clock.Set(r.PlannedFor)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	require.Equal(t, "cancelled", e.run(r.ID).Status)
	assert.Equal(t, first.Add(24*time.Hour), *e.reloadPolicy(p.ID).NextRunAt, "the next day's run")
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the next day's preview goes out")
}

// Item 7: a place that ends because a listing never became complete carries rotation.listing_incomplete,
// recorded by the job as a step; the sweep's bound then ends it with that reason.
func TestListingIncompleteIsTheExhaustedReason(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	e.drive(loc, providers.KeyLoginAccepted)
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
	_, err := e.svc.BeginUndo(e.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.Step(e.claimed(), r.ID, &loc, sshkeys.StepListingIncomplete, providers.StepFailed, nil))
	for range sshkeys.MaxLocationJobs + 1 {
		e.failLocationJobs()
		_, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	got := e.locByID(r.ID, loc)
	assert.Equal(t, "undo_failed", got.State)
	assert.Equal(t, sshkeys.ReasonListingIncomplete, got.ErrorCode)
	assert.Equal(t, "rotation.listing_incomplete", sshkeys.ReasonListingIncomplete)
	// The handler may also end a place with it directly.
	e2 := newEnv(t)
	k2 := e2.deployed("ci", e2.server("web-01"), "deploy")
	r2 := e2.runNow(e2.policy(k2.ID, 90, 7, 24))
	l2 := r2.Locations[0].ID
	e2.drive(l2, providers.KeyLoginAccepted)
	require.NoError(t, e2.svc.Abort(e2.ctx, e2.admin, r2.ID))
	_, err = e2.svc.BeginUndo(e2.claimed(), l2)
	require.NoError(t, err)
	require.NoError(t, e2.svc.FinishUndo(e2.claimed(), e2.jobActor(), l2, sshkeys.UndoRecord{Definite: true, Reason: sshkeys.ReasonListingIncomplete}))
	assert.Equal(t, sshkeys.ReasonListingIncomplete, e2.locByID(r2.ID, l2).ErrorCode)
}

// The walk's edges: a deploy whose wait is not over although its job finished long ago (a clock step)
// holds the cursor until it is; a deploy whose every send is known not written is reconciled with that
// answer; a round-4 send row (evidence only in coverage_before/absent_before) still counts; the cursor's
// and the rotation rule's database failures are errors.
func TestReconcileWalkEdges(t *testing.T) {
	e := newEnv(t)
	ctx, jobID, d := e.runningDeploy("web-01")
	s, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	require.NoError(t, err)
	_, err = e.svc.RecordDeployNotWritten(ctx, d, s)
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'dead', finished_at = $2 WHERE id = $1", jobID, e.clock.Now().Add(-3*time.Hour))
	require.NoError(t, err)
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, e.outcomeUnknown(jobID), "the wait after its send is not over")
	e.clock.Advance(time.Hour)
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, e.outcomeUnknown(jobID))
	assert.Equal(t, "not_written", e.count2(`SELECT details->>'answer' FROM audit_log WHERE action = 'sshkey.add_outcome_unknown'
AND request_id = $1`, jobID.String()))

	// A round-4 first send row.
	ctx2, job2, d2 := e.runningDeploy("web-02")
	require.NoError(t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		_, err := e.audit.Append(e.ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: job2.String()},
			Action: "sshkey.add_sent", ObjectType: "ssh_key", ObjectID: d2.KeyID.String(), Result: audit.Success,
			Details: map[string]string{"job_id": job2.String(), "send_count": "1", "sent_at": e.clock.Now().Format(time.RFC3339Nano),
				"coverage_before": "complete", "absent_before": "true"}})
		return err
	}))
	rec, err := e.svc.DeploySends(ctx2, job2)
	require.NoError(t, err)
	assert.True(t, rec.Owned())

	revoke := func(sql string) {
		_, err := e.db.Owner.Exec(e.ctx, sql)
		require.NoError(t, err)
	}
	revoke("REVOKE SELECT ON settings FROM alice_app")
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	assert.Error(t, err, "the cursor cannot be read")
	revoke("GRANT SELECT ON settings TO alice_app")
	ctx3, job3, d3 := e.runningDeploy("web-03")
	_, err = e.svc.BeginDeploySendWith(ctx3, job3, d3, provenAbsent)
	require.NoError(t, err)
	e.endJob(job3, "dead")
	e.clock.Advance(2 * time.Hour)
	revoke("REVOKE INSERT, UPDATE ON settings FROM alice_app")
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, e.outcomeUnknown(job3), "reconciled although the cursor cannot be stored")
	assert.Contains(t, e.logs.String(), "could not store the reconciliation cursor")
	revoke("GRANT INSERT, UPDATE ON settings TO alice_app")
	kx, web4 := e.generate("x"), e.server("web-04")
	revoke("REVOKE SELECT ON rotations FROM alice_app")
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: kx.ID, TargetID: web4,
		OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.Error(t, err, "the rotation rule's read")
	revoke("GRANT SELECT ON rotations TO alice_app")
}

// T14-D1 / L-83 (controller ruling): a lock during an overlap pauses the run at once (flag and one
// rotation.paused_license mail on the first sweep); the overlap timer stops, so its end is not reached
// in lock; after the renewal the sweep queues the notice, and Continue resumes the overlap with the
// duration that remained when the pause began (and the end reminder goes out again for the new end).
func TestLockDuringOverlapPausesAtOnce(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	require.Equal(t, "overlap", r.Status)
	end := *r.OverlapUntil
	e.clock.Advance(2 * 24 * time.Hour) // 5 days remain
	e.gate.lock()
	_, err := e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	got := e.run(r.ID)
	assert.True(t, got.PausedLicense, "flagged at once")
	assert.Len(t, e.mails("rotation.paused_license"), 1)
	assert.Equal(t, "rotation.paused_license", got.NoticeState)
	for range 3 {
		e.clock.Advance(4 * 24 * time.Hour) // far past the original end
		_, err = e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	got = e.run(r.ID)
	assert.Equal(t, "overlap", got.Status, "the end is not reached in lock")
	assert.Zero(t, e.jobsOf("remove"))
	assert.Len(t, e.mails("rotation.paused_license"), 1, "once per pause")
	assert.Empty(t, e.mails("rotation.overlap_ending"), "no reminder while paused")
	assert.Equal(t, end, *got.OverlapUntil, "unchanged while paused")

	e.gate.unlock()
	assert.ErrorIs(t, e.svc.Continue(e.ctx, e.admin, r.ID), sshkeys.ErrNoticePending, "the notice first")
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Len(t, e.mails("rotation.preview_after_license"), 1)
	require.NoError(t, e.svc.Continue(e.ctx, e.admin, r.ID))
	got = e.run(r.ID)
	assert.False(t, got.PausedLicense)
	assert.Equal(t, e.clock.Now().Add(5*24*time.Hour), *got.OverlapUntil, "the remaining 5 days, from Continue")
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, "overlap", e.run(r.ID).Status)
	e.clock.Advance(4*24*time.Hour + time.Minute) // the reminder for the new end
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Len(t, e.mails("rotation.overlap_ending"), 1)
	e.clock.Advance(24 * time.Hour)
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, "removing_old", e.run(r.ID).Status)
}

// L-83 resume when the reminder was already sent before the pause: Continue clears it, so the
// Administrators are told the new removal time.
func TestOverlapResumeResendsTheReminder(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	e.clock.Advance(6*24*time.Hour + 12*time.Hour) // 12 h remain; the reminder is due
	_, err := e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	require.Len(t, e.mails("rotation.overlap_ending"), 1)
	e.gate.lock()
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	e.clock.Advance(3 * 24 * time.Hour)
	e.gate.unlock()
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	require.NoError(t, e.svc.Continue(e.ctx, e.admin, r.ID))
	got := e.run(r.ID)
	assert.Equal(t, e.clock.Now().Add(12*time.Hour), *got.OverlapUntil)
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	m := e.mails("rotation.overlap_ending")
	require.Len(t, m, 2, "the new removal time")
	assert.Equal(t, "overlap", e.run(r.ID).Status)
}
