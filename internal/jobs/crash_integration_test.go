//go:build integration

package jobs

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
)

const (
	crashChildEnv  = "ALICE_JOBS_CRASH_CHILD"
	crashDBEnv     = "ALICE_JOBS_CRASH_DB"
	crashMarkerEnv = "ALICE_JOBS_CRASH_MARKER"
	// crashChildApp is the application_name of the child's database sessions: the parent waits
	// until PostgreSQL has ended all of them before it looks at the job.
	crashChildApp = "alice-crash-child"
)

var testCrash = Register("test.crash", license.ClassAlways)

// TestCrashChildProcess is the worker process that TestKilledWorkerJobIsRecoveredOnce kills
// while its job runs. It does nothing when run on its own.
func TestCrashChildProcess(t *testing.T) {
	if os.Getenv(crashChildEnv) != "1" {
		t.Skip("runs only as the child process of TestKilledWorkerJobIsRecoveredOnce")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, os.Getenv(crashDBEnv))
	require.NoError(t, err)
	al := audit.New(clock.Real{})
	q := NewQueue(QueueConfig{Pool: pool, Keyring: testKeyring(t), Audit: al, Clock: clock.Real{}, Gate: &fakeGate{}})
	r := NewRunner(RunnerConfig{Pool: pool, Queue: q, Gate: &fakeGate{}, Audit: al, Clock: clock.Real{}, Log: quiet,
		WorkerID: "crash-child", Lease: time.Second, Heartbeat: 200 * time.Millisecond})
	r.Handle(testCrash, func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
		require.NoError(t, os.WriteFile(os.Getenv(crashMarkerEnv), []byte(j.ID.String()), 0o600))
		time.Sleep(time.Hour) // the parent kills this process here
		return nil, nil
	})
	_, err = r.RunOnce(ctx)
	t.Fatalf("the child must be killed while its job runs (RunOnce returned %v)", err)
}

// withApplicationName tags the sessions of a database URL.
func withApplicationName(t *testing.T, raw, name string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	q := u.Query()
	q.Set("application_name", name)
	u.RawQuery = q.Encode()
	return u.String()
}

// F-66 (framework part): a worker process killed with SIGKILL in the middle of a job. Its
// lease expires, the reaper re-queues the job once (job.lease_expired, audit job.recovered),
// the target lock is released, and the job then runs exactly once more to success.
//
// Determinism: the child runs on the real clock; the parent's runner runs on a fake clock that
// is set from the lease the child left behind, after PostgreSQL has ended every session of the
// child (so no late heartbeat can move the lease). Every wait is bounded.
func TestKilledWorkerJobIsRecoveredOnce(t *testing.T) {
	e := newQEnvWith(t, clock.Real{})
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: testCrash, TargetID: target})
	marker := filepath.Join(t.TempDir(), "claimed")

	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChildProcess$", "-test.count=1", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), crashChildEnv+"=1", crashDBEnv+"="+withApplicationName(t, e.d.AppURL, crashChildApp),
		crashMarkerEnv+"="+marker)
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(marker)
		return err == nil && string(b) == id.String()
	}, time.Minute, 20*time.Millisecond, "the child never claimed the job; its output: %s", out)
	got := e.row(t, id)
	require.Equal(t, "running", got.status)
	require.Regexp(t, `^crash-child/`, got.lockedBy, "the claim token starts with the worker id")
	require.Equal(t, 1, e.count(t, `SELECT count(*) FROM target_locks WHERE target_id = $1`, target))

	require.NoError(t, cmd.Process.Kill())
	_ = cmd.Wait()
	require.Eventually(t, func() bool {
		var n int
		err := e.d.Owner.QueryRow(e.ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name = $1`, crashChildApp).Scan(&n)
		return err == nil && n == 0
	}, 30*time.Second, 20*time.Millisecond, "PostgreSQL kept the killed child's sessions")

	var leaseEnd time.Time
	require.NoError(t, e.d.Owner.QueryRow(e.ctx, `SELECT locked_until FROM jobs WHERE id = $1`, id).Scan(&leaseEnd))
	clk := clock.NewFake(leaseEnd.UTC())
	var runs atomic.Int32
	r := e.runner(t, "parent", func(c *RunnerConfig) { c.Clock, c.Lease = clk, time.Second })
	r.Handle(testCrash, func(context.Context, Job, StepRecorder) (map[string]any, error) { runs.Add(1); return nil, nil })
	n, err := r.Reap(e.ctx)
	require.NoError(t, err)
	require.Zero(t, n, "a lease that has not expired is never taken")
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.False(t, ran, "the dead worker's job is not claimed while its lease lasts")

	clk.Advance(time.Millisecond)
	n, err = r.Reap(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	got = e.row(t, id)
	assert.Equal(t, "queued", got.status)
	assert.Equal(t, "job.lease_expired", got.lastError)
	assert.Equal(t, 1, got.attempts, "the killed attempt counts")
	assert.Equal(t, 1, e.audits(t, "job.recovered"))
	assert.Zero(t, e.count(t, `SELECT count(*) FROM target_locks`))
	assert.Zero(t, e.count(t, `SELECT count(*) FROM job_attempts WHERE finished_at IS NULL`), "the killed attempt is closed")

	ran, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ran)
	assert.Equal(t, int32(1), runs.Load())
	got = e.row(t, id)
	assert.Equal(t, "succeeded", got.status)
	assert.Equal(t, 2, got.attempts)
	ran, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.False(t, ran, "nothing runs twice")
	clk.Advance(time.Hour)
	n, err = r.Reap(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Equal(t, 1, e.audits(t, "job.recovered"), "recovered exactly once")
	assert.Equal(t, int32(1), runs.Load())
}
