//go:build integration

package netdiscojobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery"
	"alice/internal/jobs"
)

// netdisco.scan is a registered type with a handler: a scan queued like the API queues it (StartTx: the scan row and
// its job in one transaction) is claimed by the real runner and run by the real scanner to its end.
func TestAQueuedScanRunsThroughTheRealQueue(t *testing.T) {
	names := map[string]bool{}
	for _, typ := range jobs.Types() {
		names[typ.Name] = true
	}
	require.True(t, names["netdisco.scan"], "jobs.Types() lists netdisco.scan")

	w := newWorld(t)
	require.True(t, w.runner.Handles(jobs.NetdiscoScan))
	scope := w.scope("lab", scopeOpts{})
	scan, job, err := w.start(scope, TriggerManual)
	require.NoError(t, err)

	j := w.job(job)
	assert.Equal(t, "queued", j.status)
	assert.Equal(t, map[string]string{"scan_id": scan.String()}, j.payload, "the payload is the scan id only: no scope contents, no secrets")
	assert.Equal(t, jobs.NetdiscoScanDedupeKey(scope), j.dedupe)
	assert.Equal(t, "user", j.kind)
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM jobs WHERE id = $1 AND created_by = $2 AND created_by_role = 'operator' AND max_attempts = 1
  AND class = 'read_only'`, job, w.user))
	assert.Equal(t, scanRow{state: "queued", trigger: "manual"}, w.scan(scan))
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM discovery_scans WHERE id = $1 AND requested_by = $2 AND queued_at = $3`, scan, w.user, t0))

	w.drain()
	got := w.scan(scan)
	assert.Equal(t, "done", got.state)
	assert.Equal(t, 4, got.total)
	assert.Equal(t, 4, got.excluded, "the test policy refuses every address: nothing is dialed")
	j = w.job(job)
	assert.Equal(t, "succeeded", j.status)
	assert.Equal(t, scan.String(), j.result["scan_id"])
	assert.Equal(t, "done", j.result["state"])
	assert.EqualValues(t, 4, j.result["endpoints_excluded"])
	assert.NotContains(t, j.result, "error_code")

	// The scope is free again: a second scan can be started.
	_, _, err = w.start(scope, TriggerManual)
	require.NoError(t, err)
}

// StartTx writes both rows or neither: a scope with a scan queued or running is ALC-DSC-0004, a deleted or unknown
// scope ALC-DSC-0008, and a refused start leaves no job behind. A scheduled start is a scheduled job with no creator.
func TestStartQueuesTheScanAndItsJobTogether(t *testing.T) {
	w := newWorld(t)
	scope := w.scope("lab", scopeOpts{})
	scan, job, err := w.start(scope, TriggerSchedule)
	require.NoError(t, err)
	assert.Equal(t, "schedule", w.scan(scan).trigger)
	assert.Equal(t, "scheduled", w.job(job).kind)
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM jobs WHERE id = $1 AND created_by IS NULL`, job))

	_, _, err = w.start(scope, TriggerManual)
	require.ErrorIs(t, err, discovery.ErrScanRunning)
	_, _, err = w.start(w.scope("gone", scopeOpts{deleted: true}), TriggerManual)
	require.ErrorIs(t, err, discovery.ErrScopeNotFound)
	_, _, err = w.start(uuid.New(), TriggerManual)
	require.ErrorIs(t, err, discovery.ErrScopeNotFound)
	_, _, err = w.start(scope, "sometimes")
	require.Error(t, err)
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM jobs`), "no job without its scan")
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM discovery_scans`), "no scan without its job")

	// A live job that already holds the scope's dedupe key (a scan row that was ended by hand, outside Alice): the start is
	// refused as running and rolls its scan row back.
	w.exec(`UPDATE discovery_scans SET state = 'failed', error_code = 'discovery.scan_interrupted', finished_at = $2 WHERE id = $1`, scan, t0)
	_, _, err = w.start(scope, TriggerManual)
	require.ErrorIs(t, err, discovery.ErrScanRunning)
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM discovery_scans`))
}

// The handler maps the scanner's outcomes onto the job: a finished, cancelled or timed-out scan is a succeeded job whose
// result names the scan's state and code; a failed scan is a failed job with the scan's code (permanent: a scan is not
// retried by the queue); a job whose scan does not exist fails as not found.
func TestScanOutcomesBecomeJobResults(t *testing.T) {
	t.Run("refused rules fail the job with the scan's code", func(t *testing.T) {
		w := newWorld(t)
		w.exec(`DELETE FROM settings WHERE key = 'discovery.allowed_networks'`)
		scan, job, err := w.start(w.scope("lab", scopeOpts{}), TriggerManual)
		require.NoError(t, err)
		w.drain()
		assert.Equal(t, scanRow{state: "failed", code: discovery.ReasonEntryNotAllowed, trigger: "manual"}, w.scan(scan))
		j := w.job(job)
		assert.Equal(t, "failed", j.status)
		assert.Equal(t, discovery.ReasonEntryNotAllowed, j.code)
	})
	t.Run("a scope switched off cancels the scan", func(t *testing.T) {
		w := newWorld(t)
		scope := w.scope("lab", scopeOpts{})
		scan, job, err := w.start(scope, TriggerManual)
		require.NoError(t, err)
		w.exec(`UPDATE discovery_scopes SET enabled = false WHERE id = $1`, scope)
		w.drain()
		assert.Equal(t, "cancelled", w.scan(scan).state)
		j := w.job(job)
		assert.Equal(t, "succeeded", j.status)
		assert.Equal(t, "cancelled", j.result["state"])
		assert.Equal(t, discovery.ReasonCancelled, j.result["error_code"])
	})
	t.Run("a payload without a scan", func(t *testing.T) {
		w := newWorld(t)
		for _, payload := range []map[string]string{{"scan_id": "not-a-uuid"}, {"scan_id": uuid.NewString()}} {
			id, _, err := w.queue.Enqueue(w.ctx, jobs.Spec{Type: jobs.NetdiscoScan, Kind: jobs.KindSystem, Payload: payload})
			require.NoError(t, err)
			w.drain()
			j := w.job(id)
			assert.Equal(t, "failed", j.status)
			assert.Equal(t, "system.not_found", j.code)
		}
	})
}

// A database failure inside the scanner is an unexpected job failure (the one attempt is spent: dead, with the dead-job
// e-mail), and the runner's end hook ends a scan the handler could not end as failed with ALC-DSC-0012.
func TestAScanErrorEndsTheScanThroughTheHook(t *testing.T) {
	w := newWorld(t)
	h := scanHandler(w)
	h.run = func(ctx context.Context, d discovery.Deps, id uuid.UUID) error {
		_, err := d.Store.BeginScan(ctx, id, w.clock.Now(), d.Lease)
		require.NoError(t, err)
		return errors.New("database gone")
	}
	scope := w.scope("lab", scopeOpts{})
	scan, job, err := w.start(scope, TriggerManual)
	require.NoError(t, err)
	w.drain()
	assert.Equal(t, scanRow{state: "failed", code: discovery.ReasonInterrupted, trigger: "manual"}, w.scan(scan))
	j := w.job(job)
	assert.Equal(t, "dead", j.status)
	assert.Equal(t, "internal.unexpected", j.code)
	_, _, err = w.start(scope, TriggerManual)
	require.NoError(t, err, "the scope can start a new scan")
}

// CARRY (max_attempts 1): a worker that loses its lease in the middle of a scan never runs again, so the scanner's own
// crash recovery (BeginScan) never sees the scan. The reaper kills the job (no attempt left) and the end hook ends the
// scan as failed with ALC-DSC-0012 in the same transaction; the stale run that wakes up later changes nothing, and the
// scope can start a new scan at once.
func TestALostLeaseMidScanEndsTheScan(t *testing.T) {
	w := newWorld(t)
	h := scanHandler(w)
	started, release := make(chan struct{}), make(chan struct{})
	h.run = func(ctx context.Context, d discovery.Deps, id uuid.UUID) error {
		st, err := d.Store.BeginScan(context.WithoutCancel(ctx), id, w.clock.Now(), d.Lease)
		require.NoError(t, err)
		require.True(t, st.Run)
		close(started)
		<-release // stuck in a slow probe, deaf to its context, like a worker whose process stopped
		return d.Store.FinishScan(context.WithoutCancel(ctx), discovery.Finish{ScanID: id, ScopeID: st.ScopeID, Now: w.clock.Now(),
			State: discovery.ScanDone})
	}
	scope := w.scope("lab", scopeOpts{})
	scan, job, err := w.start(scope, TriggerManual)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = w.runner.RunOnce(w.ctx)
	}()
	<-started
	assert.Equal(t, "running", w.scan(scan).state)

	w.clock.Advance(46 * time.Second) // the lease (45 s) is over; the stuck run's heartbeat is not due before
	n, err := w.runner.Reap(w.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	assert.Equal(t, "dead", w.job(job).status)
	assert.Equal(t, scanRow{state: "failed", code: discovery.ReasonInterrupted, trigger: "manual"}, w.scan(scan),
		"the scan ended with the job, in the reaper's transaction")

	next, _, err := w.start(scope, TriggerManual)
	require.NoError(t, err, "the scope can start a new scan")

	close(release)
	<-done
	assert.Equal(t, "failed", w.scan(scan).state, "the stale run's finish changes nothing")
	assert.Equal(t, "dead", w.job(job).status)
	assert.Equal(t, "queued", w.scan(next).state)
}

// The lock cancels queued read-only work: a queued scan's job is cancelled by the runner's lock sweep and its scan is
// cancelled with the license reason in the same transaction (not left queued, blocking its scope).
func TestTheLockCancelsAQueuedScan(t *testing.T) {
	w := newWorld(t)
	scope := w.scope("lab", scopeOpts{})
	scan, job, err := w.start(scope, TriggerManual)
	require.NoError(t, err)
	w.gate.locked.Store(true)
	w.drain()
	assert.Equal(t, "cancelled", w.job(job).status)
	assert.Equal(t, scanRow{state: "cancelled", code: "license.locked", trigger: "manual"}, w.scan(scan))
	w.gate.locked.Store(false)
	_, _, err = w.start(scope, TriggerManual)
	require.NoError(t, err)
}

// The backstop of the hook: a scan whose job is no longer queued or running (a hook that failed, a job ended outside
// the runner) is ended as failed with ALC-DSC-0012 by the next schedule tick or retention run (on the leader). A scan
// whose job is live is left alone.
func TestOrphanScansAreEndedByTheSweep(t *testing.T) {
	for _, task := range []string{jobs.NetdiscoSchedule.Name, jobs.NetdiscoRetention.Name} {
		t.Run(task, func(t *testing.T) {
			w := newWorld(t)
			scope, live := w.scope("lab", scopeOpts{}), w.scope("live", scopeOpts{})
			orphan, job, err := w.start(scope, TriggerManual)
			require.NoError(t, err)
			alive, _, err := w.start(live, TriggerManual)
			require.NoError(t, err)
			w.exec(`UPDATE discovery_scans SET state = 'running', started_at = $2 WHERE id = $1`, orphan, t0)
			w.exec(`UPDATE jobs SET status = 'dead', last_error_code = 'job.lease_expired', finished_at = $2 WHERE id = $1`, job, t0)
			w.clock.Advance(time.Minute)
			require.NoError(t, w.sched.RunNow(w.ctx, task))
			assert.Equal(t, scanRow{state: "failed", code: discovery.ReasonInterrupted, trigger: "manual"}, w.scan(orphan))
			assert.Equal(t, 1, w.count(`SELECT count(*) FROM discovery_scans WHERE id = $1 AND finished_at = $2`, orphan, t0.Add(time.Minute)))
			assert.Equal(t, "queued", w.scan(alive).state, "a scan whose job is queued is not an orphan")
			_, _, err = w.start(scope, TriggerManual)
			require.NoError(t, err)
		})
	}
}

// scanHandler is the world's scan handler, so a test can replace its scanner.
func scanHandler(w *world) *handlers {
	w.t.Helper()
	h := newHandlers(w.deps)
	w.runner = jobs.NewRunner(jobs.RunnerConfig{Pool: w.db.App, Queue: w.queue, Gate: w.gate, Audit: w.audit, Clock: w.clock,
		Log: w.deps.Log, Workers: 1, WorkerID: "netdisco-seam", Jitter: func() float64 { return 0 },
		Heartbeat: time.Hour}) // the stuck run never extends its lease by itself
	h.install(w.runner)
	return h
}
