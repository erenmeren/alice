//go:build integration

package jobs

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) {
	if os.Getenv(crashChildEnv) == "1" {
		// The child of TestKilledWorkerJobIsRecoveredOnce uses its parent's database.
		os.Exit(m.Run())
	}
	os.Exit(pgtest.Main(m))
}

// Test job types of the queue suites.
var (
	testQueueJob    = Register("test.queue", license.ClassAlways)
	testReadOnlyJob = Register("test.queue_readonly", license.ClassReadOnly)
)

var queueStart = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

type qenv struct {
	ctx   context.Context
	d     *pgtest.DB
	clk   clock.Clock
	fake  *clock.Fake // nil with a real clock
	gate  *fakeGate
	audit *audit.Log
	q     *Queue
}

func testKeyring(t testing.TB) *secrets.Keyring {
	t.Helper()
	kr, err := secrets.NewKeyring(1, bytes.Repeat([]byte{9}, 32))
	require.NoError(t, err)
	return kr
}

func newQEnvWith(t *testing.T, clk clock.Clock) *qenv {
	t.Helper()
	d := pgtest.New(t)
	gate := &fakeGate{}
	al := audit.New(clk)
	e := &qenv{ctx: context.Background(), d: d, clk: clk, gate: gate, audit: al,
		q: NewQueue(QueueConfig{Pool: d.App, Keyring: testKeyring(t), Audit: al, Clock: clk, Gate: gate})}
	e.fake, _ = clk.(*clock.Fake)
	// Confirm and Discard record the Administrator in jobs.confirmed_by, a reference to users.
	_, err := d.Owner.Exec(e.ctx, `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'admin', 'Admin', 'x', 'admin', $2, $2)`, admin.ID, queueStart)
	require.NoError(t, err)
	return e
}

func newQEnv(t *testing.T) *qenv { return newQEnvWith(t, clock.NewFake(queueStart)) }

func (e *qenv) runner(t *testing.T, worker string, opts ...func(*RunnerConfig)) *Runner {
	t.Helper()
	c := RunnerConfig{Pool: e.d.App, Queue: e.q, Gate: e.gate, Audit: e.audit, Clock: e.clk, Log: quiet,
		WorkerID: worker, Jitter: func() float64 { return 0 }}
	for _, o := range opts {
		o(&c)
	}
	return NewRunner(c)
}

// insertTarget creates a target row (and the platform credential it needs) as the owner role.
func insertTarget(t *testing.T, d *pgtest.DB) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	_, err := d.Owner.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', $2, $3, $2, 1, $4)
ON CONFLICT (purpose) WHERE purpose = 'platform_ssh' DO NOTHING`, uuid.New(), []byte{1}, make([]byte, 12), queueStart)
	require.NoError(t, err)
	var cred uuid.UUID
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT id FROM credentials WHERE purpose = 'platform_ssh'`).Scan(&cred))
	id := uuid.New()
	_, err = d.Owner.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, $2, 'linux', $3::jsonb, $4, 'ok', $5, $5)`, id, "target-"+id.String(),
		`{"host":"h-`+id.String()+`.example.com","port":22,"username":"alice-svc"}`, cred, queueStart)
	require.NoError(t, err)
	return id
}

type jobRow struct {
	status, lastError, lockedBy string
	attempts                    int
	runAt                       time.Time
}

func (e *qenv) row(t *testing.T, id uuid.UUID) jobRow {
	t.Helper()
	var r jobRow
	var lockedBy *string
	require.NoError(t, e.d.App.QueryRow(e.ctx, `SELECT status, last_error_code, locked_by, attempts, run_at FROM jobs WHERE id = $1`, id).
		Scan(&r.status, &r.lastError, &lockedBy, &r.attempts, &r.runAt))
	if lockedBy != nil {
		r.lockedBy = *lockedBy
	}
	r.runAt = r.runAt.UTC()
	return r
}

func (e *qenv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, e.d.App.QueryRow(e.ctx, sql, args...).Scan(&n))
	return n
}

func (e *qenv) audits(t *testing.T, action string) int {
	return e.count(t, `SELECT count(*) FROM audit_log WHERE action = $1`, action)
}

func (e *qenv) enqueue(t *testing.T, s Spec) uuid.UUID {
	t.Helper()
	if s.Kind == "" {
		s.Kind = KindSystem
	}
	id, dup, err := e.q.Enqueue(e.ctx, s)
	require.NoError(t, err)
	require.False(t, dup)
	return id
}

func succeed(context.Context, Job, StepRecorder) (map[string]any, error) {
	return map[string]any{"done": true}, nil
}

var admin = audit.Actor{Type: audit.ActorUser, ID: uuid.MustParse("0190f5a0-0000-7000-8000-000000000001"), Name: "admin"}

func TestEnqueueDedupesLiveJobsOnly(t *testing.T) {
	e := newQEnv(t)
	first, dup, err := e.q.Enqueue(e.ctx, Spec{Type: testQueueJob, Kind: KindScheduled, DedupeKey: "test.queue:1"})
	require.NoError(t, err)
	assert.False(t, dup)
	again, dup, err := e.q.Enqueue(e.ctx, Spec{Type: testQueueJob, Kind: KindScheduled, DedupeKey: "test.queue:1"})
	require.NoError(t, err)
	assert.True(t, dup)
	assert.Equal(t, first, again)
	assert.Equal(t, 1, e.count(t, `SELECT count(*) FROM jobs`))

	r := e.runner(t, "w1")
	r.Handle(testQueueJob, succeed)
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ran)
	later, dup, err := e.q.Enqueue(e.ctx, Spec{Type: testQueueJob, Kind: KindScheduled, DedupeKey: "test.queue:1"})
	require.NoError(t, err)
	assert.False(t, dup, "a finished job no longer holds its dedupe key")
	assert.NotEqual(t, first, later)
}

func TestEnqueueRefusesUnknownTypesAndKinds(t *testing.T) {
	e := newQEnv(t)
	_, _, err := e.q.Enqueue(e.ctx, Spec{Type: Type{Name: "test.never", Class: license.ClassAlways}, Kind: KindUser})
	assert.ErrorIs(t, err, ErrUnknownType)
	_, _, err = e.q.Enqueue(e.ctx, Spec{Type: Type{Name: testQueueJob.Name, Class: license.ClassChange}, Kind: KindUser})
	assert.ErrorIs(t, err, ErrUnknownType, "the class must be the registered one")
	_, _, err = e.q.Enqueue(e.ctx, Spec{Type: testQueueJob, Kind: "robot"})
	assert.Error(t, err)
	assert.Zero(t, e.count(t, `SELECT count(*) FROM jobs`))
}

func TestEnqueueDefaults(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	id := e.enqueue(t, Spec{Type: SSHKeyRemove, Kind: KindUser, TargetID: target, Payload: map[string]string{"location_id": "x"}})
	var (
		class, kind string
		priority    int
		maxAttempts int
	)
	require.NoError(t, e.d.App.QueryRow(e.ctx, `SELECT class, kind, priority, max_attempts FROM jobs WHERE id = $1`, id).
		Scan(&class, &kind, &priority, &maxAttempts))
	assert.Equal(t, "change", class)
	assert.Equal(t, "user", kind)
	assert.Equal(t, 1, priority, "user jobs overtake scheduled ones (§8.5)")
	assert.Equal(t, 3, maxAttempts)
	assert.Equal(t, queueStart, e.row(t, id).runAt)
}

func TestTamperedPayloadIsNeverRun(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob, Payload: map[string]string{"location_id": "good"}})
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET payload = '{"location_id":"evil"}' WHERE id = $1`, id)
	require.NoError(t, err)
	var runs atomic.Int32
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) { runs.Add(1); return nil, nil })
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.True(t, ran)
	assert.Zero(t, runs.Load(), "a job whose payload changed in the database never runs (J-1)")
	got := e.row(t, id)
	assert.Equal(t, "dead", got.status)
	assert.Equal(t, "job.tampered", got.lastError)
	assert.Equal(t, 1, e.audits(t, "job.tampered"))

	// Control: an untouched job runs.
	other := e.enqueue(t, Spec{Type: testQueueJob, Payload: map[string]string{"location_id": "good"}})
	_, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), runs.Load())
	assert.Equal(t, "succeeded", e.row(t, other).status)
}

func TestClaimOrderFollowsPriorityThenRunAt(t *testing.T) {
	e := newQEnv(t)
	oldScheduled := e.enqueue(t, Spec{Type: testQueueJob, Kind: KindScheduled, RunAt: queueStart.Add(-3 * time.Minute)})
	newScheduled := e.enqueue(t, Spec{Type: testQueueJob, Kind: KindScheduled, RunAt: queueStart.Add(-2 * time.Minute)})
	user := e.enqueue(t, Spec{Type: testQueueJob, Kind: KindUser, RunAt: queueStart.Add(-time.Minute)})
	future := e.enqueue(t, Spec{Type: testQueueJob, Kind: KindUser, RunAt: queueStart.Add(time.Minute)})
	var order []uuid.UUID
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
		order = append(order, j.ID)
		return nil, nil
	})
	for {
		ran, err := r.RunOnce(e.ctx)
		require.NoError(t, err)
		if !ran {
			break
		}
	}
	assert.Equal(t, []uuid.UUID{user, oldScheduled, newScheduled}, order)
	assert.Equal(t, "queued", e.row(t, future).status, "a job is never claimed before its run_at")
}

func TestSameTargetJobsNeverOverlap(t *testing.T) {
	e := newQEnv(t)
	targets := []uuid.UUID{insertTarget(t, e.d), insertTarget(t, e.d), insertTarget(t, e.d)}
	for i := range 60 {
		e.enqueue(t, Spec{Type: testQueueJob, TargetID: targets[i%3]})
	}
	var (
		mu        sync.Mutex
		perTarget = map[uuid.UUID]int{}
		maxPer    int
		inFlight  atomic.Int32
		maxGlobal atomic.Int32
	)
	r := e.runner(t, "w1")
	r.Handle(testQueueJob, func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
		mu.Lock()
		perTarget[j.TargetID]++
		maxPer = max(maxPer, perTarget[j.TargetID])
		mu.Unlock()
		n := inFlight.Add(1)
		for {
			m := maxGlobal.Load()
			if n <= m || maxGlobal.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(3 * time.Millisecond)
		inFlight.Add(-1)
		mu.Lock()
		perTarget[j.TargetID]--
		mu.Unlock()
		return nil, nil
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e.count(t, `SELECT count(*) FROM jobs WHERE status IN ('queued', 'running')`) > 0 {
				if ran, err := r.RunOnce(e.ctx); err != nil {
					t.Error(err)
					return
				} else if !ran {
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, maxPer, "one running job per target (§8.5, §12.5)")
	assert.GreaterOrEqual(t, maxGlobal.Load(), int32(2), "different targets did run in parallel (the test is not serial)")
	assert.Equal(t, 60, e.count(t, `SELECT count(*) FROM jobs WHERE status = 'succeeded'`))
	assert.Zero(t, e.count(t, `SELECT count(*) FROM target_locks`))
}

// F-69: SKIP LOCKED proven with 20 workers in two runners (two processes' worth) and 1000 jobs.
func TestTwentyWorkersRunThousandJobsExactlyOnce(t *testing.T) {
	e := newQEnvWith(t, clock.Real{})
	ids := make([]uuid.UUID, 0, 1000)
	for range 1000 {
		ids = append(ids, e.enqueue(t, Spec{Type: testQueueJob}))
	}
	var counts sync.Map
	// One handler for both runners: slog's text handler serialises its writes.
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	handler := func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
		n, _ := counts.LoadOrStore(j.ID, new(atomic.Int32))
		n.(*atomic.Int32).Add(1)
		return nil, nil
	}
	ctx, cancel := context.WithCancel(e.ctx)
	var wg sync.WaitGroup
	for _, name := range []string{"process-a", "process-b"} {
		r := e.runner(t, name, func(c *RunnerConfig) { c.Workers, c.Poll, c.Log = 10, 5*time.Millisecond, log })
		r.Handle(testQueueJob, handler)
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Run(ctx)
		}()
	}
	require.Eventually(t, func() bool {
		return e.count(t, `SELECT count(*) FROM jobs WHERE status = 'succeeded'`) == 1000
	}, 2*time.Minute, 50*time.Millisecond)
	cancel()
	wg.Wait()
	assert.NotContains(t, logs.String(), "claiming a job failed", "no two workers ever claimed the same row (they would collide on job_attempts)")
	for _, id := range ids {
		n, ok := counts.Load(id)
		require.True(t, ok, "job %s never ran", id)
		assert.Equal(t, int32(1), n.(*atomic.Int32).Load(), "job %s ran more than once", id)
	}
	assert.Equal(t, 1000, e.count(t, `SELECT count(*) FROM job_attempts`))
	assert.Equal(t, 1000, e.count(t, `SELECT count(*) FROM jobs WHERE attempts = 1`))
}

func TestPruneDeletesOnlyOldFinishedJobs(t *testing.T) {
	e := newQEnv(t)
	old := map[string]uuid.UUID{}
	for _, status := range []string{"succeeded", "failed", "cancelled", "dead"} {
		id := e.enqueue(t, Spec{Type: testQueueJob})
		_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = $2, finished_at = $3 WHERE id = $1`,
			id, status, queueStart.Add(-91*24*time.Hour))
		require.NoError(t, err)
		_, err = e.d.Owner.Exec(e.ctx, `INSERT INTO job_attempts (id, job_id, attempt, worker_id, started_at) VALUES ($1, $2, 1, 'w', $3)`,
			uuid.New(), id, queueStart.Add(-91*24*time.Hour))
		require.NoError(t, err)
		old[status] = id
	}
	recent := e.enqueue(t, Spec{Type: testQueueJob})
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'succeeded', finished_at = $2 WHERE id = $1`, recent, queueStart.Add(-89*24*time.Hour))
	require.NoError(t, err)
	queued := e.enqueue(t, Spec{Type: testQueueJob, RunAt: queueStart.Add(-100 * 24 * time.Hour)})

	n, err := e.q.Prune(e.ctx, 90*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	for status, id := range old {
		_, err := e.q.Get(e.ctx, id)
		assert.ErrorIs(t, err, ErrNotFound, status)
	}
	_, err = e.q.Get(e.ctx, recent)
	assert.NoError(t, err, "finished less than 90 days ago")
	_, err = e.q.Get(e.ctx, queued)
	assert.NoError(t, err, "unfinished jobs are never pruned")
	assert.Zero(t, e.count(t, `SELECT count(*) FROM job_attempts`), "attempts go with their job")
}

// Prune deletes in batches (no long lock on a large jobs table) and repeats until done.
func TestPruneDeletesInBatchesUntilDone(t *testing.T) {
	e := newQEnv(t)
	old := pruneBatch
	pruneBatch = 2
	t.Cleanup(func() { pruneBatch = old })
	for i := range 5 {
		id := e.enqueue(t, Spec{Type: testQueueJob})
		_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'succeeded', finished_at = $2 WHERE id = $1`,
			id, queueStart.Add(-time.Duration(91+i)*24*time.Hour))
		require.NoError(t, err)
	}
	n, err := e.q.Prune(e.ctx, 90*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Zero(t, e.count(t, `SELECT count(*) FROM jobs`))
}
