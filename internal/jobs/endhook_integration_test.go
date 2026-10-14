//go:build integration

package jobs

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/platform/clock"
)

// testEndJob is the job type of the end hook suite: read-only work, so the lock cancels it.
var testEndJob = Register("test.end_hook", license.ClassReadOnly)

// endRecorder is an end hook that records each call with the job's status as the hook's own transaction sees it.
type endRecorder struct {
	mu    sync.Mutex
	ends  []JobEnd
	seen  []Status // the job's status read inside the hook's transaction
	fail  error    // returned after the hook wrote its marker
	panic bool
}

func (h *endRecorder) hook(ctx context.Context, tx pgx.Tx, end JobEnd) error {
	var status Status
	if err := tx.QueryRow(ctx, `SELECT status FROM jobs WHERE id = $1`, end.ID).Scan(&status); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET result = '{"hook": true}'::jsonb WHERE id = $1`, end.ID); err != nil {
		return err
	}
	h.mu.Lock()
	h.ends = append(h.ends, end)
	h.seen = append(h.seen, status)
	h.mu.Unlock()
	if h.panic {
		panic("hook data that must not be logged")
	}
	return h.fail
}

func (h *endRecorder) calls() ([]JobEnd, []Status) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]JobEnd(nil), h.ends...), append([]Status(nil), h.seen...)
}

// hookWrote reports whether the hook's write is in the job row (it committed with the job's end).
func (e *qenv) hookWrote(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	return e.count(t, `SELECT count(*) FROM jobs WHERE id = $1 AND result @> '{"hook": true}'`, id) == 1
}

func drainAll(t *testing.T, e *qenv, r *Runner) {
	t.Helper()
	for range 20 {
		ran, err := r.RunOnce(e.ctx)
		require.NoError(t, err)
		if !ran {
			return
		}
	}
	t.Fatal("jobs did not drain")
}

// A job that ends without success (failed, dead, cancelled) runs its type's end hook inside the transaction that ends
// it: the hook sees the new status and its writes commit with the end. A success, a retry and a re-queue run nothing.
func TestEndHookRunsWhenTheRunnerEndsAJob(t *testing.T) {
	cases := []struct {
		name    string
		max     int
		handler HandlerFunc
		status  Status
		reason  string
	}{
		{"permanent failure", 3, func(context.Context, Job, StepRecorder) (map[string]any, error) {
			return nil, Fail("discovery.scope_not_found", nil, errors.New("gone"))
		}, StatusFailed, "discovery.scope_not_found"},
		{"needs attention", 3, func(context.Context, Job, StepRecorder) (map[string]any, error) {
			return nil, Attention("x.look", nil, errors.New("look"))
		}, StatusFailed, "x.look"},
		{"out of attempts", 1, func(context.Context, Job, StepRecorder) (map[string]any, error) {
			return nil, Retry("db.unavailable", nil, errors.New("down"))
		}, StatusDead, "db.unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newQEnv(t)
			h := &endRecorder{}
			id := e.enqueue(t, Spec{Type: testEndJob, MaxAttempts: tc.max})
			r := e.runner(t, "w1")
			r.Handle(testEndJob, tc.handler)
			r.OnEnd(testEndJob, h.hook)
			drainAll(t, e, r)
			ends, seen := h.calls()
			require.Len(t, ends, 1)
			assert.Equal(t, JobEnd{ID: id, Status: tc.status, Reason: tc.reason}, ends[0])
			assert.Equal(t, []Status{tc.status}, seen, "the hook runs in the transaction that ends the job")
			assert.Equal(t, string(tc.status), e.row(t, id).status)
			assert.True(t, e.hookWrote(t, id), "the hook's write commits with the job's end")
		})
	}

	t.Run("success, retry and other types run nothing", func(t *testing.T) {
		e := newQEnv(t)
		h := &endRecorder{}
		ok := e.enqueue(t, Spec{Type: testEndJob})
		retried := e.enqueue(t, Spec{Type: testEndJob, MaxAttempts: 3})
		other := e.enqueue(t, Spec{Type: testQueueJob, MaxAttempts: 1})
		r := e.runner(t, "w1")
		r.Handle(testEndJob, func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
			if j.ID == retried {
				return nil, Retry("ssh.unreachable", nil, errors.New("refused"))
			}
			return nil, nil
		})
		r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
			return nil, Fail("other.failed", nil, errors.New("x"))
		})
		r.OnEnd(testEndJob, h.hook)
		drainAll(t, e, r)
		ends, _ := h.calls()
		assert.Empty(t, ends)
		assert.Equal(t, "succeeded", e.row(t, ok).status)
		assert.Equal(t, "queued", e.row(t, retried).status)
		assert.Equal(t, "failed", e.row(t, other).status, "a type without a hook ends as before")
	})
}

// The reaper kills a job whose worker died (its lease expired) when it has no attempt left: the hook runs in the
// reaper's transaction. A job with attempts left is re-queued, not ended.
func TestEndHookRunsWhenTheReaperKillsAJob(t *testing.T) {
	e := newQEnv(t)
	h := &endRecorder{}
	dead := e.enqueue(t, Spec{Type: testEndJob, MaxAttempts: 1})
	again := e.enqueue(t, Spec{Type: testEndJob, MaxAttempts: 3})
	for _, id := range []uuid.UUID{dead, again} {
		_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'running', locked_by = 'gone/1', attempts = 1, locked_until = $2
WHERE id = $1`, id, queueStart.Add(time.Minute))
		require.NoError(t, err)
	}
	r := e.runner(t, "w1")
	r.OnEnd(testEndJob, h.hook)
	n, err := r.Reap(e.ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	e.fake.Advance(2 * time.Minute)
	n, err = r.Reap(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	ends, seen := h.calls()
	assert.Equal(t, []JobEnd{{ID: dead, Status: StatusDead, Reason: "job.lease_expired"}}, ends)
	assert.Equal(t, []Status{StatusDead}, seen)
	assert.True(t, e.hookWrote(t, dead))
	assert.Equal(t, "queued", e.row(t, again).status)
}

// A job the runner's own shutdown interrupts on its last attempt is dead (release): the hook runs.
func TestEndHookRunsWhenTheShutdownKillsAJob(t *testing.T) {
	e := newQEnvWith(t, clock.Real{})
	h := &endRecorder{}
	id := e.enqueue(t, Spec{Type: testEndJob, MaxAttempts: 1})
	started := make(chan struct{})
	r := e.runner(t, "w1", func(c *RunnerConfig) {
		c.Workers, c.ShutdownGrace, c.Poll = 1, 200*time.Millisecond, 10*time.Millisecond
	})
	r.Handle(testEndJob, func(ctx context.Context, _ Job, _ StepRecorder) (map[string]any, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	r.OnEnd(testEndJob, h.hook)
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the runner did not stop")
	}
	ends, _ := h.calls()
	assert.Equal(t, []JobEnd{{ID: id, Status: StatusDead, Reason: "job.lease_expired"}}, ends)
	assert.Equal(t, "dead", e.row(t, id).status)
}

// A job whose payload was changed outside Alice is dead without running (terminate): the hook runs.
func TestEndHookRunsForATamperedJob(t *testing.T) {
	e := newQEnv(t)
	h := &endRecorder{}
	id := e.enqueue(t, Spec{Type: testEndJob, Payload: map[string]string{"scan_id": "a"}})
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET payload = '{"scan_id": "b"}' WHERE id = $1`, id)
	require.NoError(t, err)
	r := e.runner(t, "w1")
	r.Handle(testEndJob, succeed)
	r.OnEnd(testEndJob, h.hook)
	drainAll(t, e, r)
	ends, _ := h.calls()
	assert.Equal(t, []JobEnd{{ID: id, Status: StatusDead, Reason: "job.tampered"}}, ends)
}

// The lock cancels read-only work: queued jobs by the lock-mode sweep, a job claimed just before the lock when the
// gate is asked again (revert). Both run the hook with the cancellation's reason.
func TestEndHookRunsWhenTheLockCancelsAJob(t *testing.T) {
	t.Run("sweep", func(t *testing.T) {
		e := newQEnv(t)
		h := &endRecorder{}
		id := e.enqueue(t, Spec{Type: testEndJob, Kind: KindScheduled})
		r := e.runner(t, "w1")
		r.Handle(testEndJob, succeed)
		r.OnEnd(testEndJob, h.hook)
		e.gate.set(true)
		drainAll(t, e, r)
		ends, seen := h.calls()
		assert.Equal(t, []JobEnd{{ID: id, Status: StatusCancelled, Reason: "license.locked"}}, ends)
		assert.Equal(t, []Status{StatusCancelled}, seen)
		assert.True(t, e.hookWrote(t, id))
	})
	t.Run("after the claim", func(t *testing.T) {
		e := newQEnv(t)
		h := &endRecorder{}
		id := e.enqueue(t, Spec{Type: testEndJob, Kind: KindScheduled})
		r := e.runner(t, "w1", func(c *RunnerConfig) { c.Gate = &flipGate{} })
		r.Handle(testEndJob, succeed)
		r.OnEnd(testEndJob, h.hook)
		ran, err := r.RunOnce(e.ctx)
		require.NoError(t, err)
		require.True(t, ran)
		ends, _ := h.calls()
		assert.Equal(t, []JobEnd{{ID: id, Status: StatusCancelled, Reason: "license.locked"}}, ends)
		assert.Equal(t, "cancelled", e.row(t, id).status)
	})
}

// A hook that fails or panics never keeps a job from ending: its savepoint is rolled back (its writes are undone), the
// failure is logged by type only, and the job ends as it would without a hook.
func TestFailingEndHookNeverBlocksTheEnd(t *testing.T) {
	for _, h := range []*endRecorder{{fail: errors.New("hook secret")}, {panic: true}} {
		e := newQEnv(t)
		logs := &syncBuffer{}
		id := e.enqueue(t, Spec{Type: testEndJob, MaxAttempts: 1})
		r := e.runner(t, "w1", func(c *RunnerConfig) { c.Log = slogTo(logs) })
		r.Handle(testEndJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
			return nil, Fail("x.failed", nil, errors.New("x"))
		})
		r.OnEnd(testEndJob, h.hook)
		drainAll(t, e, r)
		ends, _ := h.calls()
		require.Len(t, ends, 1)
		assert.Equal(t, "failed", e.row(t, id).status)
		assert.False(t, e.hookWrote(t, id), "the failed hook's writes were rolled back")
		assert.Contains(t, logs.String(), "job end hook failed")
		assert.NotContains(t, logs.String(), "hook secret")
		assert.NotContains(t, logs.String(), "must not be logged")
		assert.Equal(t, 1, e.count(t, `SELECT count(*) FROM job_attempts WHERE job_id = $1 AND finished_at IS NOT NULL`, id))
	}
}

func TestOnEndRefusesAnUnregisteredTypeANilHookAndASecondHook(t *testing.T) {
	r := NewRunner(RunnerConfig{})
	h := (&endRecorder{}).hook
	assert.Panics(t, func() { r.OnEnd(Type{Name: "test.unregistered", Class: license.ClassAlways}, h) })
	assert.Panics(t, func() { r.OnEnd(Type{Name: testEndJob.Name, Class: license.ClassAlways}, h) }, "another class")
	assert.Panics(t, func() { r.OnEnd(testEndJob, nil) })
	r.OnEnd(testEndJob, h)
	assert.Panics(t, func() { r.OnEnd(testEndJob, h) })
	assert.True(t, strings.HasPrefix(testEndJob.Name, "test."))
}
