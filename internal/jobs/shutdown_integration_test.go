//go:build integration

package jobs

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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
	r := e.runner(t, "w1", func(c *RunnerConfig) {
		c.Workers, c.Poll, c.ShutdownGrace = 1, 5*time.Millisecond, 100*time.Millisecond
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
	time.Sleep(100 * time.Millisecond) // let its finish attempt reach the database
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
	assert.NoError(t, err)
	_, err = e.d.Owner.Exec(e.ctx, `INSERT INTO target_locks (target_id, job_id, operation, locked_by, heartbeat_at, lease_until)
VALUES ($1, $2, 'test.queue', 'dead/1', $3, $3)`, target, id, past)
	assert.NoError(t, err)
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
