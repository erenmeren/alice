//go:build integration

package netdiscojobs

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery"
	"alice/internal/jobs"
)

// failingQueue refuses every job.
type failingQueue struct{}

func (failingQueue) Add(context.Context, pgx.Tx, jobs.Spec) (uuid.UUID, bool, error) {
	return uuid.Nil, false, errors.New("queue down")
}

// closedPool is a pool of the world's database that is already closed: every call fails.
func (w *world) closedPool() *pgxpool.Pool {
	w.t.Helper()
	p, err := pgxpool.New(w.ctx, w.db.AppURL)
	require.NoError(w.t, err)
	p.Close()
	return p
}

// Every database failure of a tick is logged by type and reported, and the next tick starts over; nothing is half done.
func TestDatabaseFailuresAreReported(t *testing.T) {
	w := newWorld(t)
	scope := w.scope("lab", scopeOpts{hours: 1})
	broken := w.deps
	broken.Pool = w.closedPool()
	tk := newTasks(broken)
	assert.ErrorIs(t, tk.schedule(w.ctx), errScheduleFailed)
	assert.ErrorIs(t, tk.retain(w.ctx), errRetentionFailed)
	_, err := EndOrphanScans(w.ctx, broken.Pool, w.audit, t0)
	assert.Error(t, err)
	_, err = tk.startScheduled(w.ctx, candidate{id: scope}, t0)
	assert.Error(t, err)
	assert.Contains(t, w.logs.String(), "ending discovery scans whose job ended failed")
	assert.Contains(t, w.logs.String(), "reading the discovery scopes to schedule failed")
	assert.Contains(t, w.logs.String(), "the discovery retention failed")

	// A queue that refuses the job: the scope's scan and its last_scheduled_at roll back with it.
	noQueue := w.deps
	noQueue.Queue = failingQueue{}
	assert.ErrorIs(t, newTasks(noQueue).schedule(w.ctx), errScheduleFailed)
	assert.Contains(t, w.logs.String(), "queueing a scheduled discovery scan failed")
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_scans`))
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_scopes WHERE last_scheduled_at IS NOT NULL`))
	assert.NotContains(t, w.logs.String(), "queue down", "error texts are never logged")
}

// The handler's read of the scan's outcome fails: an unexpected failure (the end hook then ends the scan).
func TestOutcomeReadFailureIsUnexpected(t *testing.T) {
	w := newWorld(t)
	d := w.deps
	d.Pool = w.closedPool()
	h := newHandlers(d)
	h.run = func(context.Context, discovery.Deps, uuid.UUID) error { return nil }
	_, err := h.scan(w.ctx, jobs.Job{Payload: map[string]string{PayloadScanID: uuid.NewString()}}, nil)
	var f *jobs.Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, jobs.Retryable, f.Class)
	assert.Equal(t, "internal.unexpected", f.Reason)
}

// A scan whose row is still queued or running after its run (it cannot be, but the job never claims success for it)
// fails as interrupted.
func TestAScanStillInFlightAfterItsRunFails(t *testing.T) {
	w := newWorld(t)
	h := newHandlers(w.deps)
	h.run = func(context.Context, discovery.Deps, uuid.UUID) error { return nil }
	scan, _, err := w.start(w.scope("lab", scopeOpts{}), TriggerManual)
	require.NoError(t, err)
	_, err = h.scan(w.ctx, jobs.Job{Payload: map[string]string{PayloadScanID: scan.String()}}, nil)
	var f *jobs.Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, jobs.Permanent, f.Class)
	assert.Equal(t, discovery.ReasonInterrupted, f.Reason)
}

// The end hook reports a statement that fails (the runner then rolls its savepoint back and logs it).
func TestEndHookReportsItsFailure(t *testing.T) {
	w := newWorld(t)
	tx, err := w.db.App.Begin(w.ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(w.ctx))
	err = newHandlers(w.deps).ended(w.ctx, tx, jobs.JobEnd{ID: uuid.New(), Status: jobs.StatusDead, Reason: "job.lease_expired"})
	assert.Error(t, err)
}
