//go:build integration

package jobs

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/platform/clock"
)

// syncBuffer is a log sink that may be read while workers still write to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A run whose lease expired and whose job was re-queued and claimed again by the same process
// must not settle the job or free the target lock of the run that replaced it.
func TestStaleRunNeverSettlesOverItsSuccessor(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target, MaxAttempts: 3})
	started := map[int]chan struct{}{1: make(chan struct{}), 2: make(chan struct{})}
	release := map[int]chan struct{}{1: make(chan struct{}), 2: make(chan struct{})}
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Heartbeat = time.Hour }) // run 1 never notices by itself
	r.Handle(testQueueJob, func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
		if j.ID != id {
			return map[string]any{"other": true}, nil
		}
		close(started[j.Attempt])
		<-release[j.Attempt] // ignores its context, like a handler stuck in a slow call
		return map[string]any{"run": j.Attempt}, nil
	})

	done1 := make(chan struct{})
	go func() {
		_, _ = r.RunOnce(e.ctx)
		close(done1)
	}()
	<-started[1]
	e.fake.Advance(46 * time.Second)
	n, err := r.Reap(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	done2 := make(chan struct{})
	go func() {
		_, _ = r.RunOnce(e.ctx)
		close(done2)
	}()
	<-started[2]
	close(release[1])
	<-done1

	got := e.row(t, id)
	assert.Equal(t, "running", got.status, "the stale run did not settle the job")
	assert.Equal(t, 2, got.attempts)
	assert.True(t, strings.HasPrefix(got.lockedBy, "w1/"), "the lease names the claim: %q", got.lockedBy)
	assert.Equal(t, 1, e.count(t, `SELECT count(*) FROM target_locks WHERE job_id = $1`, id), "run 2 still holds the server")

	other := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target})
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.False(t, ran, "no second job starts on the server while run 2 works")

	close(release[2])
	<-done2
	v, err := e.q.Get(e.ctx, id)
	require.NoError(t, err)
	assert.Equal(t, StatusSucceeded, v.Status)
	assert.Equal(t, float64(2), v.Result["run"], "the job ends with run 2's outcome")
	_, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, "succeeded", e.row(t, other).status)
}

// Losing the target lock is losing the lease: the handler is stopped and the job is handed back.
func TestLostTargetLockStopsTheHandler(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target, MaxAttempts: 3})
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
	_, err := e.d.Owner.Exec(e.ctx, `DELETE FROM target_locks WHERE job_id = $1`, id)
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
	assert.Equal(t, "queued", got.status)
	assert.Equal(t, "job.lease_expired", got.lastError)
	assert.Empty(t, got.lockedBy)
}

// §8.1: an expired target lock is taken over only after the reaper re-queued its job.
func TestExpiredTargetLockIsNotTakenWhileItsJobRuns(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	stuck := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target, MaxAttempts: 3})
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'running', locked_by = 'gone/1', attempts = 1, locked_until = $2
WHERE id = $1`, stuck, queueStart.Add(time.Minute))
	require.NoError(t, err)
	_, err = e.d.Owner.Exec(e.ctx, `INSERT INTO target_locks (target_id, job_id, operation, locked_by, heartbeat_at, lease_until)
VALUES ($1, $2, 'test.queue', 'gone/1', $3, $3)`, target, stuck, queueStart.Add(-time.Second))
	require.NoError(t, err)
	next := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target})
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, succeed)
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.False(t, ran, "the job of the expired lock is still running")
	assert.Equal(t, "queued", e.row(t, next).status)

	e.fake.Advance(2 * time.Minute)
	n, err := r.Reap(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	ran, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.True(t, ran)
}

// A job without attempts left that is cut off by the shutdown is dead, not re-queued.
func TestShutdownDoesNotRequeueAJobWithoutAttemptsLeft(t *testing.T) {
	for _, honours := range []bool{true, false} {
		name := "handler stops"
		if !honours {
			name = "handler ignores the cancellation"
		}
		t.Run(name, func(t *testing.T) {
			e := newQEnvWith(t, clock.Real{})
			id := e.enqueue(t, Spec{Type: testQueueJob, MaxAttempts: 1})
			var logs syncBuffer
			r := e.runner(t, "w1", func(c *RunnerConfig) {
				c.Workers, c.Poll, c.ShutdownGrace = 1, 5*time.Millisecond, 100*time.Millisecond
				c.Log = slog.New(slog.NewTextHandler(&logs, nil))
			})
			started, unblock, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			r.Handle(testQueueJob, func(ctx context.Context, _ Job, _ StepRecorder) (map[string]any, error) {
				defer close(returned)
				close(started)
				if honours {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				<-unblock
				return map[string]any{"late": true}, nil
			})
			ctx, cancel := context.WithCancel(e.ctx)
			stopped := make(chan struct{})
			go func() {
				r.Run(ctx)
				close(stopped)
			}()
			<-started
			cancel()
			<-stopped
			close(unblock)
			<-returned
			require.Eventually(t, func() bool { return e.audits(t, "job.dead") == 1 }, 5*time.Second, 10*time.Millisecond)
			if !honours {
				require.Eventually(t, func() bool { return strings.Contains(logs.String(), "job lease lost") }, 5*time.Second, 10*time.Millisecond)
			}
			got := e.row(t, id)
			assert.Equal(t, "dead", got.status)
			assert.Equal(t, "job.lease_expired", got.lastError)
			assert.Equal(t, 1, got.attempts)
		})
	}
}

// J-1: the kind, the creator's role and the attempt budget are covered by the MAC as well.
func TestTamperedJobColumnsAreNeverRun(t *testing.T) {
	for name, sql := range map[string]string{
		"kind":         `UPDATE jobs SET kind = 'user' WHERE id = $1`,
		"role":         `UPDATE jobs SET created_by_role = 'admin' WHERE id = $1`,
		"max attempts": `UPDATE jobs SET max_attempts = 9 WHERE id = $1`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newQEnv(t)
			id := e.enqueue(t, Spec{Type: testQueueJob, CreatedByRole: "operator"})
			_, err := e.d.Owner.Exec(e.ctx, sql, id)
			require.NoError(t, err)
			r := e.runner(t, "w1")
			r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
				t.Error("a tampered job ran")
				return nil, nil
			})
			ran, err := r.RunOnce(e.ctx)
			require.NoError(t, err)
			require.True(t, ran)
			got := e.row(t, id)
			assert.Equal(t, "dead", got.status)
			assert.Equal(t, "job.tampered", got.lastError)
		})
	}
}

type unclassifiedGate struct{}

func (unclassifiedGate) Allow(license.Class) error { return license.ErrUnclassified }

func TestUnexpectedGateErrorIsNotAnUnknownType(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob})
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Gate = unclassifiedGate{} })
	r.Handle(testQueueJob, succeed)
	_, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	got := e.row(t, id)
	assert.Equal(t, "dead", got.status)
	assert.Equal(t, "license.unclassified", got.lastError)
}
