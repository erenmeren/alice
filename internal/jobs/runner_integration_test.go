//go:build integration

package jobs

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/platform/logging"
)

func TestRetryBacksOffThenSucceeds(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob, MaxAttempts: 3})
	var runs atomic.Int32
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
		assert.Equal(t, int(runs.Load())+1, j.Attempt)
		if runs.Add(1) < 3 {
			return nil, Retry("ssh.unreachable", map[string]string{"host": "web-01"}, errors.New("refused"))
		}
		return map[string]any{"ok": true}, nil
	})
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ran)
	got := e.row(t, id)
	assert.Equal(t, "queued", got.status)
	assert.Equal(t, "ssh.unreachable", got.lastError)
	assert.Equal(t, queueStart.Add(30*time.Second), got.runAt)
	assert.Empty(t, got.lockedBy)
	v, err := e.q.Get(e.ctx, id)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"host": "web-01"}, v.ErrorParams)

	ran, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.False(t, ran, "not due before its backoff")
	e.fake.Advance(30 * time.Second)
	_, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, queueStart.Add(30*time.Second+time.Minute), e.row(t, id).runAt, "the second wait doubles")
	e.fake.Advance(time.Minute)
	_, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	got = e.row(t, id)
	assert.Equal(t, "succeeded", got.status)
	assert.Equal(t, 3, got.attempts)
	assert.Empty(t, got.lastError)
	assert.Equal(t, 3, e.count(t, `SELECT count(*) FROM job_attempts WHERE job_id = $1 AND finished_at IS NOT NULL`, id))
	assert.Equal(t, 2, e.count(t, `SELECT count(*) FROM job_attempts WHERE job_id = $1 AND error_code = 'ssh.unreachable'`, id))
}

func TestPermanentFailureIsNotRetried(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob, MaxAttempts: 3})
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
		return nil, Fail("ssh.auth_failed", map[string]string{"user": "alice-svc"}, nil)
	})
	_, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	got := e.row(t, id)
	assert.Equal(t, "failed", got.status)
	assert.Equal(t, "ssh.auth_failed", got.lastError)
	assert.Equal(t, 1, got.attempts)
	v, err := e.q.Get(e.ctx, id)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"user": "alice-svc"}, v.ErrorParams)
	assert.NotNil(t, v.FinishedAt)
	e.fake.Advance(time.Hour)
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.False(t, ran)
}

func TestNeedsAttentionIsFlagged(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob})
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, func(_ context.Context, _ Job, s StepRecorder) (map[string]any, error) {
		s.Step("write", "failed", map[string]string{"file_path": "/root/.ssh/authorized_keys"})
		return nil, Attention("ssh.file_changed", nil, nil)
	})
	_, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	v, err := e.q.Get(e.ctx, id)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, v.Status)
	assert.Equal(t, true, v.Result["needs_attention"])
	steps, ok := v.Result["steps"].([]any)
	require.True(t, ok)
	require.Len(t, steps, 1)
	assert.Equal(t, "write", steps[0].(map[string]any)["name"])
}

func TestExhaustedRetriesGoDeadAndAreAudited(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob, MaxAttempts: 2})
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
		return nil, Retry("ssh.timeout", nil, nil)
	})
	_, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, e.audits(t, "job.dead"))
	e.fake.Advance(30 * time.Second)
	_, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	got := e.row(t, id)
	assert.Equal(t, "dead", got.status)
	assert.Equal(t, "ssh.timeout", got.lastError)
	assert.Equal(t, 1, e.audits(t, "job.dead"))
}

func TestPanickingHandlerIsRetriedAndItsValueNeverLogged(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob})
	var logs bytes.Buffer
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Log = logging.New(&logs, slog.LevelDebug) })
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
		panic("CANARY-panic-value")
	})
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ran)
	got := e.row(t, id)
	assert.Equal(t, "queued", got.status)
	assert.Equal(t, "internal.unexpected", got.lastError)
	assert.Contains(t, logs.String(), "job handler panicked")
	assert.NotContains(t, logs.String(), "CANARY")
}

// L-81: a deploy-like external change queued before the lock is not claimed in lock, waits as
// blocked_license, does not run by itself after the renewal and runs once after an
// Administrator confirms it (R29).
func TestLockHoldsChangeJobsUntilAnAdministratorConfirms(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: SSHKeyRemove, Kind: KindUser, TargetID: target, Payload: map[string]string{"location_id": "l1"}})
	var runs atomic.Int32
	r := e.runner(t, "w1")
	r.Handle(SSHKeyRemove, func(context.Context, Job, StepRecorder) (map[string]any, error) { runs.Add(1); return nil, nil })

	e.gate.set(true) // the license locks
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.False(t, ran)
	assert.Zero(t, runs.Load())
	assert.Equal(t, "blocked_license", e.row(t, id).status)
	assert.Equal(t, 1, e.audits(t, "job.blocked_license"))
	assert.ErrorIs(t, e.q.Confirm(e.ctx, admin, admin.ID, id), license.ErrLocked, "confirming is refused while locked")

	e.gate.set(false) // renewal
	ran, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.False(t, ran, "after the renewal the held change does not start on its own")
	assert.Equal(t, "blocked_license", e.row(t, id).status)
	blocked, _, err := e.q.List(e.ctx, ListFilter{Status: StatusBlocked})
	require.NoError(t, err)
	require.Len(t, blocked, 1)
	assert.Equal(t, id, blocked[0].ID)

	require.NoError(t, e.q.Confirm(e.ctx, admin, admin.ID, id))
	assert.Equal(t, 1, e.audits(t, "job.confirmed"))
	ran, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.True(t, ran)
	assert.Equal(t, int32(1), runs.Load())
	assert.Equal(t, "succeeded", e.row(t, id).status)
	assert.ErrorIs(t, e.q.Confirm(e.ctx, admin, admin.ID, id), ErrNotWaiting)
}

func TestLockCancelsQueuedReadOnlyWork(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testReadOnlyJob, Kind: KindScheduled})
	always := e.enqueue(t, Spec{Type: testQueueJob})
	var readOnlyRuns, alwaysRuns atomic.Int32
	r := e.runner(t, "w1")
	r.Handle(testReadOnlyJob, func(context.Context, Job, StepRecorder) (map[string]any, error) { readOnlyRuns.Add(1); return nil, nil })
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) { alwaysRuns.Add(1); return nil, nil })
	e.gate.set(true)
	for {
		ran, err := r.RunOnce(e.ctx)
		require.NoError(t, err)
		if !ran {
			break
		}
	}
	assert.Zero(t, readOnlyRuns.Load())
	assert.Equal(t, int32(1), alwaysRuns.Load(), "always-class work keeps running in lock")
	got := e.row(t, id)
	assert.Equal(t, "cancelled", got.status)
	assert.Equal(t, "license.locked", got.lastError)
	assert.Equal(t, "succeeded", e.row(t, always).status)
	assert.Equal(t, 1, e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'job.cancelled_license' AND object_id = $1
  AND result = 'denied' AND details->>'type' = $2`, id.String(), testReadOnlyJob.Name), "every cancelled job is audited")
}

// A read-only job claimed just before the lock began is cancelled when the gate is asked again,
// and that cancellation is audited like the sweep's.
func TestReadOnlyJobCancelledAfterTheClaimIsAudited(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testReadOnlyJob, Kind: KindScheduled})
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Gate = &flipGate{} })
	r.Handle(testReadOnlyJob, succeed)
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ran)
	assert.Equal(t, "cancelled", e.row(t, id).status)
	assert.Equal(t, 1, e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'job.cancelled_license' AND object_id = $1`, id.String()))
}

// flipGate allows the first question and refuses everything after it: the lock begins
// between the claim and the run. refuse is the refusal (nil = license.ErrLocked).
type flipGate struct {
	asked  atomic.Int32
	refuse error
}

func (g *flipGate) Allow(license.Class) error {
	if g.asked.Add(1) == 1 {
		return nil
	}
	if g.refuse != nil {
		return g.refuse
	}
	return license.ErrLocked
}

// AUD-02, S1: while the license cannot be verified, queued changes and read-only work are neither
// held for a confirmation nor cancelled: they wait queued, always-class work keeps running, and
// the queued work starts by itself once an evaluation succeeds.
func TestUnverifiedPausesQueuedWorkWithoutHoldingIt(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	change := e.enqueue(t, Spec{Type: SSHKeyRemove, Kind: KindUser, TargetID: target, Payload: map[string]string{"location_id": "l1"}})
	readOnly := e.enqueue(t, Spec{Type: testReadOnlyJob, Kind: KindScheduled})
	always := e.enqueue(t, Spec{Type: testQueueJob})
	var changeRuns, readOnlyRuns, alwaysRuns atomic.Int32
	r := e.runner(t, "w1")
	r.Handle(SSHKeyRemove, func(context.Context, Job, StepRecorder) (map[string]any, error) { changeRuns.Add(1); return nil, nil })
	r.Handle(testReadOnlyJob, func(context.Context, Job, StepRecorder) (map[string]any, error) { readOnlyRuns.Add(1); return nil, nil })
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) { alwaysRuns.Add(1); return nil, nil })
	drain := func() {
		t.Helper()
		for {
			ran, err := r.RunOnce(e.ctx)
			require.NoError(t, err)
			if !ran {
				return
			}
		}
	}

	e.gate.setUnverified(true)
	drain()
	assert.Equal(t, int32(1), alwaysRuns.Load(), "always-class work (recovery, rollback) is never paused")
	assert.Zero(t, changeRuns.Load())
	assert.Zero(t, readOnlyRuns.Load())
	assert.Equal(t, "queued", e.row(t, change).status, "not held for an Administrator's confirmation")
	assert.Equal(t, "queued", e.row(t, readOnly).status, "not cancelled")
	assert.Empty(t, e.row(t, readOnly).lastError)
	assert.Zero(t, e.audits(t, "job.blocked_license"))
	assert.Zero(t, e.audits(t, "job.cancelled_license"))
	assert.ErrorIs(t, e.q.Confirm(e.ctx, admin, admin.ID, change), ErrNotWaiting, "nothing waits for a confirmation")

	e.gate.setUnverified(false) // the next evaluation succeeded
	drain()
	assert.Equal(t, int32(1), changeRuns.Load(), "the change resumes by itself")
	assert.Equal(t, int32(1), readOnlyRuns.Load())
	assert.Equal(t, "succeeded", e.row(t, change).status)
	assert.Equal(t, "succeeded", e.row(t, readOnly).status)
	assert.Equal(t, "succeeded", e.row(t, always).status)
}

// AUD-02, S1: a job claimed just before the license became unverified is queued again as it was:
// no attempt is counted, no target lock or attempt row is left, nothing is audited.
func TestUnverifiedAfterTheClaimQueuesTheJobAgain(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: SSHKeyRemove, Kind: KindUser, TargetID: target})
	var runs atomic.Int32
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Gate = &flipGate{refuse: license.ErrUnverified} })
	r.Handle(SSHKeyRemove, func(context.Context, Job, StepRecorder) (map[string]any, error) { runs.Add(1); return nil, nil })
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.True(t, ran, "it was claimed")
	assert.Zero(t, runs.Load(), "but not run")
	got := e.row(t, id)
	assert.Equal(t, "queued", got.status)
	assert.Zero(t, got.attempts, "the refused claim is not an attempt")
	assert.Empty(t, got.lockedBy)
	assert.Zero(t, e.count(t, `SELECT count(*) FROM target_locks`))
	assert.Zero(t, e.count(t, `SELECT count(*) FROM job_attempts WHERE job_id = $1`, id))
	assert.Zero(t, e.count(t, `SELECT count(*) FROM audit_log WHERE object_id = $1`, id.String()))

	r.cfg.Gate = e.gate // the gate opens again
	ran, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ran)
	assert.Equal(t, int32(1), runs.Load())
	got = e.row(t, id)
	assert.Equal(t, "succeeded", got.status)
	assert.Equal(t, 1, got.attempts)
}

func TestGateIsAskedAgainAfterTheClaim(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: SSHKeyRemove, Kind: KindUser, TargetID: target})
	var runs atomic.Int32
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Gate = &flipGate{} })
	r.Handle(SSHKeyRemove, func(context.Context, Job, StepRecorder) (map[string]any, error) { runs.Add(1); return nil, nil })
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.True(t, ran, "it was claimed")
	assert.Zero(t, runs.Load(), "but not run: the lock began in between (§8.6 'right after claim')")
	got := e.row(t, id)
	assert.Equal(t, "blocked_license", got.status)
	assert.Zero(t, got.attempts, "the refused claim is not an attempt")
	assert.Empty(t, got.lockedBy)
	assert.Zero(t, e.count(t, `SELECT count(*) FROM target_locks`))
	assert.Zero(t, e.count(t, `SELECT count(*) FROM job_attempts WHERE job_id = $1`, id), "no attempt row is left behind")

	// After a confirmation the job runs as its first attempt.
	r.cfg.Gate = e.gate
	require.NoError(t, e.q.Confirm(e.ctx, admin, admin.ID, id))
	ran, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ran)
	assert.Equal(t, int32(1), runs.Load())
	got = e.row(t, id)
	assert.Equal(t, "succeeded", got.status)
	assert.Equal(t, 1, got.attempts)
}

func TestDiscard(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: SSHKeyRemove, Kind: KindUser, TargetID: target})
	r := e.runner(t, "w1")
	r.Handle(SSHKeyRemove, succeed)
	e.gate.set(true)
	_, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.Equal(t, "blocked_license", e.row(t, id).status)
	require.NoError(t, e.q.Discard(e.ctx, admin, admin.ID, id), "the queue allows it; the route is gated")
	assert.Equal(t, "cancelled", e.row(t, id).status)
	assert.Equal(t, 1, e.audits(t, "job.discarded"))
	assert.ErrorIs(t, e.q.Discard(e.ctx, admin, admin.ID, id), ErrNotWaiting)
	assert.ErrorIs(t, e.q.Confirm(e.ctx, admin, admin.ID, id), ErrNotWaiting)
}

func TestGetAndListPages(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	var ids []uuid.UUID
	for i := range 3 {
		ids = append(ids, e.enqueue(t, Spec{Type: testQueueJob, TargetID: target}))
		e.fake.Advance(time.Duration(i+1) * time.Second)
	}
	_ = e.enqueue(t, Spec{Type: testQueueJob})
	page, next, err := e.q.List(e.ctx, ListFilter{TargetID: target, Limit: 2})
	require.NoError(t, err)
	require.Len(t, page, 2)
	assert.Equal(t, []uuid.UUID{ids[2], ids[1]}, []uuid.UUID{page[0].ID, page[1].ID}, "newest first")
	require.NotEmpty(t, next)
	rest, next, err := e.q.List(e.ctx, ListFilter{TargetID: target, Limit: 2, Cursor: next})
	require.NoError(t, err)
	require.Len(t, rest, 1)
	assert.Equal(t, ids[0], rest[0].ID)
	assert.Empty(t, next)
	_, _, err = e.q.List(e.ctx, ListFilter{Cursor: "not-a-cursor"})
	assert.ErrorIs(t, err, ErrBadCursor)

	v, err := e.q.Get(e.ctx, ids[0])
	require.NoError(t, err)
	assert.Equal(t, testQueueJob.Name, v.Type)
	assert.Equal(t, StatusQueued, v.Status)
	assert.Equal(t, target, v.TargetID)
	_, err = e.q.Get(e.ctx, uuid.New())
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestReapRequeuesExpiredLeasesOnce(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	live := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target, MaxAttempts: 3})
	last := e.enqueue(t, Spec{Type: testQueueJob, MaxAttempts: 1})
	for _, x := range []struct {
		id       uuid.UUID
		attempts int
	}{{live, 1}, {last, 1}} {
		_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'running', locked_by = 'dead-worker', attempts = $2,
    locked_until = $3 WHERE id = $1`, x.id, x.attempts, queueStart.Add(-time.Second))
		require.NoError(t, err)
	}
	_, err := e.d.Owner.Exec(e.ctx, `INSERT INTO target_locks (target_id, job_id, operation, locked_by, heartbeat_at, lease_until)
VALUES ($1, $2, 'test.queue', 'dead-worker', $3, $3)`, target, live, queueStart.Add(-time.Second))
	require.NoError(t, err)
	r := e.runner(t, "w1")
	n, err := r.Recover(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	got := e.row(t, live)
	assert.Equal(t, "queued", got.status)
	assert.Equal(t, "job.lease_expired", got.lastError)
	assert.Equal(t, 1, got.attempts, "the cut-off attempt counts")
	assert.Equal(t, "dead", e.row(t, last).status, "no attempt left")
	assert.Equal(t, 1, e.audits(t, "job.recovered"))
	assert.Equal(t, 1, e.audits(t, "job.dead"))
	assert.Zero(t, e.count(t, `SELECT count(*) FROM target_locks`))
	n, err = r.Reap(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "a second pass changes nothing")
}

func TestHeartbeatLossStopsTheHandlerAndItsResultIsDropped(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob})
	started, cancelled := make(chan struct{}), make(chan struct{})
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, func(ctx context.Context, _ Job, _ StepRecorder) (map[string]any, error) {
		close(started)
		select {
		case <-ctx.Done():
			close(cancelled)
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
			return map[string]any{"finished": true}, nil
		}
	})
	done := make(chan struct{})
	go func() {
		_, _ = r.RunOnce(e.ctx)
		close(done)
	}()
	<-started
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET locked_by = 'reaper-gave-it-away' WHERE id = $1`, id)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		e.fake.Advance(15 * time.Second)
		select {
		case <-cancelled:
			return true
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond)
	<-done
	got := e.row(t, id)
	assert.Equal(t, "running", got.status, "this worker no longer owns the job, so it writes nothing")
	assert.Equal(t, "reaper-gave-it-away", got.lockedBy)
}

// A database the worker cannot reach (beats fail with errors other than a lost lease) stops the
// handler before its lease ends: another process may reap the job and run it again, so this one
// must not keep working on the server past its lease.
func TestHeartbeatFailuresStopTheHandlerBeforeTheLeaseEnds(t *testing.T) {
	e := newQEnv(t)
	e.enqueue(t, Spec{Type: testQueueJob})
	started, cancelled := make(chan struct{}), make(chan struct{})
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, func(ctx context.Context, _ Job, _ StepRecorder) (map[string]any, error) {
		close(started)
		select {
		case <-ctx.Done():
			close(cancelled)
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
			return map[string]any{"finished": true}, nil
		}
	})
	done := make(chan struct{})
	go func() {
		_, _ = r.RunOnce(e.ctx)
		close(done)
	}()
	<-started
	// Every write to the job row now fails, as during a network partition.
	_, err := e.d.Owner.Exec(e.ctx, `CREATE FUNCTION fail_job_updates() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'partitioned'; END $$`)
	require.NoError(t, err)
	_, err = e.d.Owner.Exec(e.ctx, `CREATE TRIGGER fail_job_updates BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION fail_job_updates()`)
	require.NoError(t, err)
	claimedAt := e.fake.Now()
	require.Eventually(t, func() bool {
		select {
		case <-cancelled:
			return true
		default:
			if e.fake.Now().Sub(claimedAt) < 45*time.Second {
				e.fake.Advance(5 * time.Second)
			}
			return false
		}
	}, 5*time.Second, 20*time.Millisecond)
	assert.Less(t, e.fake.Now().Sub(claimedAt), 45*time.Second, "the handler stops before the lease ends")
	_, err = e.d.Owner.Exec(e.ctx, `DROP TRIGGER fail_job_updates ON jobs`)
	require.NoError(t, err)
	<-done
}
