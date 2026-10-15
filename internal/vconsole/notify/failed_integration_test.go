//go:build integration

package notify_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/vpgtest"
)

// markFailed puts a seeded row in the state SendPending leaves after giving up.
func markFailed(t *testing.T, d *vpgtest.DB, id int64, at time.Time) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(),
		`UPDATE mail_outbox SET attempts = $2, last_error = 'smtp: 550 mailbox unavailable', failed_at = $3 WHERE id = $1`,
		id, notify.MaxAttempts, at)
	require.NoError(t, err)
}

func TestListFailedShowsOnlyFailedUnsentRows(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	now := testNow()
	failed := seed(t, d, []string{"a@example.com"}, "failed one", now)
	markFailed(t, d, failed, now)
	_ = seed(t, d, []string{"a@example.com"}, "pending one", now)
	sent := seed(t, d, []string{"a@example.com"}, "sent one", now)
	_, err := d.Owner.Exec(ctx, `UPDATE mail_outbox SET sent_at = $2 WHERE id = $1`, sent, now)
	require.NoError(t, err)

	for _, p := range []audit.Q{d.As(t, "vendor_owner", "lf_owner"), notifier(t, d, "lf_notifier")} {
		rows, err := notify.ListFailed(ctx, p, 10)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		r := rows[0]
		assert.Equal(t, failed, r.ID)
		assert.Equal(t, "test", r.Kind)
		assert.Equal(t, "failed one", r.Subject)
		assert.Equal(t, notify.MaxAttempts, r.Attempts)
		assert.Contains(t, r.LastError, "550")
		assert.True(t, r.FailedAt.Equal(now))
	}

	_, err = notify.ListFailed(ctx, d.As(t, "vendor_sales", "lf_sales"), 10)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "42501", pe.Code)
}

func TestListFailedHonoursTheLimit(t *testing.T) {
	d := vpgtest.New(t)
	now := testNow()
	for range 3 {
		id := seed(t, d, []string{"a@example.com"}, "x", now)
		markFailed(t, d, id, now)
	}
	rows, err := notify.ListFailed(context.Background(), d.Owner, 2)
	require.NoError(t, err)
	assert.Len(t, rows, 2)
	_, err = notify.ListFailed(context.Background(), d.Owner, 0)
	assert.Error(t, err)
}

func TestRetryFailedMakesTheRowDueAgainAndIsAudited(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	now := testNow()
	id := seed(t, d, []string{"a@example.com"}, "retry me", now.Add(-time.Hour))
	markFailed(t, d, id, now.Add(-time.Hour))
	nt := notifier(t, d, "rf_notifier")

	later := now.Add(time.Minute)
	require.NoError(t, notify.RetryFailed(ctx, nt, id, later))
	r := load(t, d.Owner, id)
	assert.Nil(t, r.FailedAt)
	assert.Nil(t, r.SentAt)
	assert.Equal(t, 0, r.Attempts)
	assert.Empty(t, r.LastError)
	assert.True(t, r.NextAttemptAt.Equal(later))

	var actor, subject string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT actor, subject FROM audit WHERE action = 'mail.retry'`).Scan(&actor, &subject))
	assert.Equal(t, "rf_notifier", actor)
	assert.Equal(t, strconv.FormatInt(id, 10), subject)

	// The next send picks it up.
	s := &fakeSender{}
	res, err := notify.SendPending(ctx, d.Owner, s, "", later)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Sent)

	// Now sent: a second retry is refused and changes nothing.
	before := load(t, d.Owner, id)
	err = notify.RetryFailed(ctx, nt, id, later.Add(time.Hour))
	assert.ErrorIs(t, err, notify.ErrNotFailed)
	assert.Equal(t, before, load(t, d.Owner, id))
}

func TestRetryFailedRefusesPendingAndUnknownRows(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	now := testNow()
	due := now.Add(30 * time.Minute)
	id := seed(t, d, []string{"a@example.com"}, "pending", due)
	_, err := d.Owner.Exec(ctx, `UPDATE mail_outbox SET attempts = 3, last_error = 'busy' WHERE id = $1`, id)
	require.NoError(t, err)
	nt := notifier(t, d, "rp_notifier")
	before := load(t, d.Owner, id)

	assert.ErrorIs(t, notify.RetryFailed(ctx, nt, id, now), notify.ErrNotFailed)
	assert.Equal(t, before, load(t, d.Owner, id), "a pending row keeps its attempts and backoff")
	assert.ErrorIs(t, notify.RetryFailed(ctx, nt, id+1000, now), notify.ErrNotFailed)

	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action = 'mail.retry'`).Scan(&n))
	assert.Zero(t, n)
}

func TestOnlyTheNotifierRetries(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	now := testNow()
	id := seed(t, d, []string{"a@example.com"}, "x", now)
	markFailed(t, d, id, now)
	before := load(t, d.Owner, id)
	for _, p := range []audit.Q{d.As(t, "vendor_owner", "ro_owner"), d.As(t, "vendor_sales", "ro_sales")} {
		err := notify.RetryFailed(ctx, p, id, now)
		var pe *pgconn.PgError
		require.True(t, errors.As(err, &pe), "%v", err)
		assert.Equal(t, "42501", pe.Code)
	}
	assert.Equal(t, before, load(t, d.Owner, id))
}
