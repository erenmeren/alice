//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// 00027 (R52): a location records when a scan last read its file, a bound location has one observation row (the TLS
// observation, the drift episode, the repair mode and its back-off) written by the application, a repair is a
// deployment of its own trigger, and the drift notices have their ledger kinds; the Down keeps a finished repair's
// history as a retry.
func TestMigration00027CertificateDrift(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	w := seedWorld(t, d)

	require.NoError(t, exec(t, d.App, "UPDATE certificate_locations SET file_observed_at = now() WHERE id = $1", w.loc))
	require.NoError(t, exec(t, d.App, `INSERT INTO location_observations (location_id, drift_mode, tls_attempted_at, tls_observed_at,
    tls_fingerprint, tls_probe, tls_level, tls_trust, tls_trust_error, updated_at)
VALUES ($1, 'auto', now(), now(), $2, 'helper', 3, 'untrusted', 'wrong_intermediate', now())`, w.loc, hex64("c")))
	require.NoError(t, exec(t, d.App, `UPDATE location_observations SET drift_since = now(), drift_fingerprint = $2, drift_source = 'tls',
    backoff_reason = 'flapping', backed_off_at = now(), in_sync_fingerprint = $2, in_sync_at = now(), tls_error = 'deployment.verify_unreachable'
WHERE location_id = $1`, w.loc, hex64("d")))
	require.NoError(t, exec(t, d.App, "UPDATE location_observations SET drift_mode = NULL WHERE location_id = $1", w.loc))
	for _, bad := range []string{
		"UPDATE location_observations SET drift_mode = 'repair' WHERE location_id = $1",
		"UPDATE location_observations SET tls_probe = 'outside' WHERE location_id = $1",
		"UPDATE location_observations SET tls_level = 5 WHERE location_id = $1",
		"UPDATE location_observations SET tls_fingerprint = 'abc' WHERE location_id = $1",
		"UPDATE location_observations SET tls_trust = 'trusted' WHERE location_id = $1", // a trust error without untrusted
		"UPDATE location_observations SET drift_source = '' WHERE location_id = $1",     // a drift without its source
		"UPDATE location_observations SET backed_off_at = NULL WHERE location_id = $1",  // a back-off reason without its time
		"UPDATE location_observations SET backoff_reason = 'tired' WHERE location_id = $1",
		"UPDATE location_observations SET in_sync_at = NULL WHERE location_id = $1",
		"UPDATE location_observations SET tls_error = 'Not A Code' WHERE location_id = $1",
	} {
		assert.Equal(t, checkViolation, sqlState(exec(t, d.App, bad, w.loc)), bad)
	}
	require.NoError(t, exec(t, d.App, "DELETE FROM location_observations WHERE location_id = $1", w.loc), "the application prunes a row")
	require.NoError(t, exec(t, d.App, "INSERT INTO location_observations (location_id, updated_at) VALUES ($1, now())", w.loc))

	repair := with(deploymentRow(w), map[string]any{"trigger": "drift_repair", "state": "done", "status": "succeeded", "finished_at": time.Now(),
		"verified": "remote"})
	require.NoError(t, insertRow(t, d.App, "deployments", repair))
	require.NoError(t, exec(t, d.App, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES (gen_random_uuid(), 'location_drift', $1, 'www', now(), 0, false, true, now())`, w.loc))

	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 25)
	require.NoError(t, err, "a finished repair does not stop the Down")
	assert.False(t, hasColumn(t, d, "certificate_locations", "file_observed_at"))
	var trigger string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT trigger FROM deployments WHERE id = $1", repair["id"]).Scan(&trigger))
	assert.Equal(t, "retry", trigger, "history is kept")
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.True(t, hasColumn(t, d, "certificate_locations", "file_observed_at"))
}

// 00027 (R52): the bindings that exist when the migration runs observe and report only; a location found later has no
// row until it is bound.
func TestMigration00027ExistingBindingsObserve(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 25)
	require.NoError(t, err)
	w := seedAcme(t, d) // the location is bound with automatic deployment on
	_, err = p.Up(ctx)
	require.NoError(t, err)
	var mode string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT drift_mode FROM location_observations WHERE location_id = $1", w.loc).Scan(&mode))
	assert.Equal(t, "observe", mode)
	var observed *time.Time
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT file_observed_at FROM certificate_locations WHERE id = $1", w.loc).Scan(&observed))
	assert.NotNil(t, observed, "a location holding a certificate read it at its last scan")
}
