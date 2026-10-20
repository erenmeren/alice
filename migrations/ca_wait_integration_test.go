//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// 00022 keeps the CA's earliest retry time apart (R47): a rate limit recorded before takes its next_attempt_at as
// ca_not_before; the application writes the column; the ledger takes the kind acme_renewal_ca_wait; the Down puts the
// CA's wait back into next_attempt_at (capped at 24 hours, as before) and removes the notices of the new kind.
func TestMigration00022CANotBefore(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	w := seedAcme(t, d)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 21)
	require.NoError(t, err)

	require.NoError(t, exec(t, d.Owner, `UPDATE acme_certificates SET failures = 1, state = 'failing', last_error_code = 'acme.ca_rate_limited',
    next_attempt_at = now() + interval '20 hours' WHERE id = $1`, w.acmeCert))
	_, err = p.UpTo(ctx, 22)
	require.NoError(t, err)
	var next, ca *time.Time
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT next_attempt_at, ca_not_before FROM acme_certificates WHERE id = $1", w.acmeCert).Scan(&next, &ca))
	require.NotNil(t, ca, "the earlier rate limit is the CA's time")
	assert.True(t, ca.Equal(*next))

	// The application writes the column; a CA wait of three days is kept.
	require.NoError(t, exec(t, d.App, "UPDATE acme_certificates SET ca_not_before = now() + interval '3 days', next_attempt_at = now() WHERE id = $1",
		w.acmeCert))
	add := func() error {
		return exec(t, d.App, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, 'acme_renewal_ca_wait', $2, 'www.example.com', '2026-11-01T00:00:00Z', 4, false, true, now())`, uuid.New(), w.acmeCert)
	}
	require.NoError(t, add())
	assert.Equal(t, uniqueViolation, sqlState(add()), "once per certificate, expiry instant and days left")

	_, err = p.DownTo(ctx, 21)
	require.NoError(t, err, "the Down removes the notices of the new kind first")
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT count(*) FROM alerts").Scan(&n))
	assert.Zero(t, n)
	var back time.Time
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT next_attempt_at FROM acme_certificates WHERE id = $1", w.acmeCert).Scan(&back))
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), back, time.Minute, "the CA's wait back in next_attempt_at, capped as before")
	_, err = p.Up(ctx)
	require.NoError(t, err)
}
