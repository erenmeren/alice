//go:build integration

package jobs

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/clock"
)

func runInBackground(ctx context.Context, r *Runner) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	return done
}

func waitClosed(t *testing.T, ch <-chan struct{}, within time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(within):
		t.Fatalf("%s did not happen within %s", what, within)
	}
}

func TestShutdownLetsShortJobsFinishAndClaimsNothingNew(t *testing.T) {
	e := newQEnvWith(t, clock.Real{})
	first := e.enqueue(t, Spec{Type: testQueueJob, Kind: KindUser})
	second := e.enqueue(t, Spec{Type: testQueueJob})
	started := make(chan struct{}, 2)
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Workers, c.Poll, c.ShutdownGrace = 1, 5*time.Millisecond, 2*time.Second })
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
		started <- struct{}{}
		time.Sleep(50 * time.Millisecond)
		return nil, nil
	})
	ctx, cancel := context.WithCancel(e.ctx)
	done := runInBackground(ctx, r)
	<-started
	cancel()
	waitClosed(t, done, 5*time.Second, "Run returning")
	assert.Equal(t, "succeeded", e.row(t, first).status, "a job that ends within the grace period completes")
	assert.Equal(t, "queued", e.row(t, second).status, "no new job is claimed after the shutdown began")
}

func TestShutdownReleasesInterruptedJobs(t *testing.T) {
	e := newQEnvWith(t, clock.Real{})
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target})
	started := make(chan struct{})
	r := e.runner(t, "w1", func(c *RunnerConfig) {
		c.Workers, c.Poll, c.ShutdownGrace = 1, 5*time.Millisecond, 100*time.Millisecond
	})
	r.Handle(testQueueJob, func(ctx context.Context, _ Job, _ StepRecorder) (map[string]any, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(e.ctx)
	done := runInBackground(ctx, r)
	<-started
	cancel()
	waitClosed(t, done, 5*time.Second, "Run returning")
	got := e.row(t, id)
	assert.Equal(t, "queued", got.status, "an interrupted job resumes after the restart (§8.8), it is not failed")
	assert.Empty(t, got.lockedBy)
	assert.Equal(t, "job.lease_expired", got.lastError)
	assert.Equal(t, 1, got.attempts, "the interrupted attempt counts")
	assert.Zero(t, e.count(t, `SELECT count(*) FROM target_locks`))
	assert.Zero(t, e.count(t, `SELECT count(*) FROM job_attempts WHERE finished_at IS NULL`))
}

func TestShutdownReleasesJobsWhoseHandlerIgnoresCancellation(t *testing.T) {
	e := newQEnvWith(t, clock.Real{})
	id := e.enqueue(t, Spec{Type: testQueueJob})
	started, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	logs := &syncBuffer{}
	r := e.runner(t, "w1", func(c *RunnerConfig) {
		c.Workers, c.Poll, c.ShutdownGrace = 1, 5*time.Millisecond, 100*time.Millisecond
		c.Log = slogTo(logs)
	})
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
		close(started)
		<-release
		defer close(returned)
		return map[string]any{"late": true}, nil
	})
	ctx, cancel := context.WithCancel(e.ctx)
	done := runInBackground(ctx, r)
	<-started
	cancel()
	waitClosed(t, done, 5*time.Second, "Run returning while a handler is stuck")
	assert.Equal(t, "queued", e.row(t, id).status)
	close(release)
	waitClosed(t, returned, 5*time.Second, "the stuck handler returning")
	// The late finish attempt has reached the database and been refused by the fence.
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "job lease lost before the job finished") },
		5*time.Second, 5*time.Millisecond)
	got := e.row(t, id)
	assert.Equal(t, "queued", got.status, "a late result of a released job is not written")
	assert.Empty(t, got.lockedBy)
}

// §8.8: Run recovers jobs whose lease expired before its workers start, so a job of a crashed
// process does not wait for the first reaper tick (an hour here).
func TestRunRecoversExpiredLeasesBeforeItsWorkersStart(t *testing.T) {
	e := newQEnvWith(t, clock.Real{})
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target})
	past := time.Now().UTC().Add(-time.Minute)
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'running', locked_by = 'dead/1', attempts = 1, locked_until = $2 WHERE id = $1`, id, past)
	require.NoError(t, err)
	_, err = e.d.Owner.Exec(e.ctx, `INSERT INTO target_locks (target_id, job_id, operation, locked_by, heartbeat_at, lease_until)
VALUES ($1, $2, 'test.queue', 'dead/1', $3, $3)`, target, id, past)
	require.NoError(t, err)
	var runs atomic.Int32
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Workers, c.Poll, c.ReapEvery = 1, 5*time.Millisecond, time.Hour })
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) { runs.Add(1); return nil, nil })
	ctx, cancel := context.WithCancel(e.ctx)
	done := runInBackground(ctx, r)
	assert.Eventually(t, func() bool { return e.row(t, id).status == "succeeded" }, 10*time.Second, 10*time.Millisecond)
	cancel()
	waitClosed(t, done, 5*time.Second, "Run returning")
	assert.Equal(t, int32(1), runs.Load())
	assert.Equal(t, 1, e.audits(t, "job.recovered"))
}

// A job killed by this process's own shutdown (its last attempt cut off: a connection test has
// one) is audited as dead with shutdown=true but no job.dead email goes out: the Administrators
// restarted Alice themselves. The attempt still counts (R37 item 20). Both shutdown paths are
// covered: a handler that returns on cancellation and one that ignores it.
func TestShutdownKillsALastAttemptWithoutAnEmail(t *testing.T) {
	for _, stuck := range []bool{false, true} {
		e := newQEnvWith(t, clock.Real{})
		e.adminWithEmail(t)
		target := insertTarget(t, e.d)
		id := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target, MaxAttempts: 1})
		started, release := make(chan struct{}), make(chan struct{})
		r := e.runner(t, "w1", func(c *RunnerConfig) {
			c.Workers, c.Poll, c.ShutdownGrace = 1, 5*time.Millisecond, 100*time.Millisecond
			c.Notifier = notify.AdminNotifier{Clock: e.clk}
		})
		r.Handle(testQueueJob, func(ctx context.Context, _ Job, _ StepRecorder) (map[string]any, error) {
			close(started)
			if stuck {
				<-release
				return nil, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		ctx, cancel := context.WithCancel(e.ctx)
		done := runInBackground(ctx, r)
		<-started
		cancel()
		waitClosed(t, done, 5*time.Second, "Run returning")
		close(release)
		got := e.row(t, id)
		assert.Equal(t, "dead", got.status, "stuck=%v", stuck)
		assert.Equal(t, 1, got.attempts, "stuck=%v: the attempt counts", stuck)
		assert.Equal(t, 1, e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'job.dead' AND object_id = $1
  AND details->>'shutdown' = 'true'`, id.String()), "stuck=%v", stuck)
		assert.Empty(t, e.deadEmails(t), "stuck=%v: a restart is not an alert", stuck)
		assert.Zero(t, e.count(t, `SELECT count(*) FROM target_locks`))
	}
}
