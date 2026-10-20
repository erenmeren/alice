//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// 00020 classifies the failures of ACME renewals (owner decision 2026-10-20): a series from before takes the class of
// its last code (outages transient, everything else permanent, with every failure counted as that class); the ledger of
// expiry notices takes the kind acme_renewal_expiry; the Down drops both again.
func TestMigration00020ClassifiesRenewalFailures(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	w := seedAcme(t, d)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 19)
	require.NoError(t, err)

	require.NoError(t, exec(t, d.Owner, `UPDATE acme_certificates SET failures = 5, state = 'stopped', last_error_code = 'acme.provider_unreachable'
WHERE id = $1`, w.acmeCert))
	_, err = p.UpTo(ctx, 20)
	require.NoError(t, err)
	class, permanent := classOfCert(t, d, w.acmeCert)
	assert.Equal(t, "transient", class, "five outages: recovered by itself")
	assert.Equal(t, 0, permanent)

	_, err = p.DownTo(ctx, 19)
	require.NoError(t, err)
	require.NoError(t, exec(t, d.Owner, "UPDATE acme_certificates SET last_error_code = 'acme.validation_failed_dns' WHERE id = $1", w.acmeCert))
	_, err = p.UpTo(ctx, 20)
	require.NoError(t, err)
	class, permanent = classOfCert(t, d, w.acmeCert)
	assert.Equal(t, "permanent", class, "five refusals stay stopped")
	assert.Equal(t, 5, permanent)

	// The application writes both columns, within their checks.
	require.NoError(t, exec(t, d.App, "UPDATE acme_certificates SET last_failure_class = '', permanent_failures = 0 WHERE id = $1", w.acmeCert))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE acme_certificates SET last_failure_class = 'flaky' WHERE id = $1", w.acmeCert)))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE acme_certificates SET permanent_failures = -1 WHERE id = $1", w.acmeCert)))

	// The ledger takes the new kind (once per certificate, expiry instant and threshold).
	add := func() error {
		return exec(t, d.App, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, 'acme_renewal_expiry', $2, 'www.example.com', '2026-11-01T00:00:00Z', 7, false, true, now())`, uuid.New(), w.acmeCert)
	}
	require.NoError(t, add())
	assert.Equal(t, uniqueViolation, sqlState(add()))

	_, err = p.DownTo(ctx, 19)
	require.NoError(t, err, "the Down removes the notices of the new kind first")
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT count(*) FROM alerts").Scan(&n))
	assert.Zero(t, n)
	_, err = p.Up(ctx)
	require.NoError(t, err)
}

func classOfCert(t *testing.T, d *pgtest.DB, id any) (string, int) {
	t.Helper()
	var class string
	var permanent int
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT last_failure_class, permanent_failures FROM acme_certificates WHERE id = $1", id).
		Scan(&class, &permanent))
	return class, permanent
}
