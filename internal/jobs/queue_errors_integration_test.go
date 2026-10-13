//go:build integration

package jobs

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
)

// Confirm and Discard of a job that does not exist answer ErrNotFound (the route's 404), never
// ErrNotWaiting, and write no audit entry.
func TestConfirmAndDiscardOfAMissingJobAreNotFound(t *testing.T) {
	e := newQEnv(t)
	missing := uuid.Must(uuid.NewV7())
	assert.ErrorIs(t, e.q.Confirm(e.ctx, admin, admin.ID, missing), ErrNotFound)
	assert.ErrorIs(t, e.q.Discard(e.ctx, admin, admin.ID, missing), ErrNotFound)
	assert.Zero(t, e.audits(t, "job.confirmed"))
	assert.Zero(t, e.audits(t, "job.discarded"))
}

// holdJob enqueues a job and moves it to blocked_license as the owner role, optionally renaming its
// type (a job written by a build that registered a type this build no longer has).
func (e *qenv) holdJob(t *testing.T, typ string) uuid.UUID {
	t.Helper()
	id := e.enqueue(t, Spec{Type: testQueueJob})
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'blocked_license', type = $2 WHERE id = $1`, id, typ)
	require.NoError(t, err)
	return id
}

// A held job of a type this build does not know is never released to the queue: Confirm answers
// ErrUnknownType and the job stays held, without an audit entry.
func TestConfirmRefusesAHeldJobOfAnUnknownType(t *testing.T) {
	e := newQEnv(t)
	id := e.holdJob(t, "test.no_longer_registered")
	assert.ErrorIs(t, e.q.Confirm(e.ctx, admin, admin.ID, id), ErrUnknownType)
	assert.Equal(t, "blocked_license", e.row(t, id).status)
	assert.Zero(t, e.audits(t, "job.confirmed"))
}

// A queue built without a license gate fails closed: Confirm answers license.ErrLocked and the job
// stays held.
func TestConfirmWithoutAGateFailsClosed(t *testing.T) {
	e := newQEnv(t)
	id := e.holdJob(t, testQueueJob.Name)
	q := NewQueue(QueueConfig{Pool: e.d.App, Keyring: testKeyring(t), Audit: e.audit, Clock: e.clk})
	assert.ErrorIs(t, q.Confirm(e.ctx, admin, admin.ID, id), license.ErrLocked)
	assert.Equal(t, "blocked_license", e.row(t, id).status)
	assert.Zero(t, e.audits(t, "job.confirmed"))

	require.NoError(t, e.q.Confirm(e.ctx, admin, admin.ID, id), "the same job is confirmed through a gated queue")
	assert.Equal(t, "queued", e.row(t, id).status)
}

// EnqueueTx refuses a request of an unregistered type before it touches the transaction.
func TestEnqueueTxRefusesAnUnknownType(t *testing.T) {
	q := NewQueue(QueueConfig{Keyring: testKeyring(t)})
	id, err := q.EnqueueTx(context.Background(), nil, inventory.JobRequest{Type: "test.never_registered", Kind: string(KindUser)})
	assert.ErrorIs(t, err, ErrUnknownType)
	assert.Equal(t, uuid.Nil, id)
}

// A cursor that does not decode is ErrBadCursor from List (the route's 400), never a database error.
func TestListRefusesABadCursor(t *testing.T) {
	e := newQEnv(t)
	e.enqueue(t, Spec{Type: testQueueJob})
	views, next, err := e.q.List(e.ctx, ListFilter{Cursor: "not a cursor"})
	assert.ErrorIs(t, err, ErrBadCursor)
	assert.Nil(t, views)
	assert.Empty(t, next)
}

// A job row whose result is not a JSON object is reported as an error by Get and List instead of
// being shown with an empty or partial result.
func TestGetAndListReportACorruptResult(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob})
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET result = '[1, 2]'::jsonb WHERE id = $1`, id)
	require.NoError(t, err)

	_, err = e.q.Get(e.ctx, id)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
	assert.Contains(t, err.Error(), "decode result")

	views, next, err := e.q.List(e.ctx, ListFilter{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jobs: list")
	assert.Nil(t, views)
	assert.Empty(t, next)
}

// When the database cannot be reached (here: the request is already cancelled) Get, List and Prune
// return a wrapped error; Get never turns it into ErrNotFound and Prune reports nothing deleted.
func TestQueueReadsReportDatabaseErrors(t *testing.T) {
	e := newQEnv(t)
	id := e.enqueue(t, Spec{Type: testQueueJob})
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()

	_, err := e.q.Get(ctx, id)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
	assert.ErrorIs(t, err, context.Canceled)

	_, _, err = e.q.List(ctx, ListFilter{})
	assert.ErrorIs(t, err, context.Canceled)

	n, err := e.q.Prune(ctx, 0)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, n)

	v, err := e.q.Get(e.ctx, id)
	require.NoError(t, err, "the job is still there")
	assert.Equal(t, StatusQueued, v.Status)
}
