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

// 00034 (R64, D5): an installation with a user before the migration gets the revocation check switched off, a new one
// none (on); the reasons an authority can give are accepted; how a revocation was seen is frozen with it (Z1022); the
// Down refuses while a certificate carries what it cannot represent.
func TestMigration00034(t *testing.T) {
	ctx := context.Background()
	setting := func(d *pgtest.DB) string {
		var v string
		err := d.Owner.QueryRow(ctx, "SELECT coalesce((SELECT value::text FROM settings WHERE key = 'revocation.check'), '')").Scan(&v)
		require.NoError(t, err)
		return v
	}
	provider := func(d *pgtest.DB) *goose.Provider {
		p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
		require.NoError(t, err)
		return p
	}

	fresh := pgtest.New(t)
	assert.Empty(t, setting(fresh), "a new installation has no row: the check is on")

	d := pgtest.New(t)
	p := provider(d)
	_, err := p.DownTo(ctx, 33)
	require.NoError(t, err)
	var constraint string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT conname FROM pg_constraint WHERE conrelid = 'certificates'::regclass
AND pg_get_constraintdef(oid) LIKE '%revocation_reason%' AND pg_get_constraintdef(oid) LIKE '%cessationOfOperation%'`).Scan(&constraint))
	assert.Equal(t, "certificates_revocation_reason_check", constraint, "the constraint 00034 replaces")
	require.NoError(t, exec(t, d.Owner, `INSERT INTO users (id, username, display_name, auth_source, password_hash, role, created_at, updated_at)
VALUES ($1, 'ada', 'Ada', 'local', 'x', 'admin', now(), now())`, uuid.New()))
	_, err = p.UpTo(ctx, 34)
	require.NoError(t, err)
	assert.JSONEq(t, `{"enabled": false, "version": 0}`, setting(d), "an updated installation keeps the check off")

	_, cert, _ := seedCertWorld(t, d)
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE certificates SET revocation_seen = 'ocsp' WHERE id = $1", cert)),
		"seen only with a revocation")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `UPDATE certificates SET revoked_at = now(), revocation_reason = 'certificateHold'
WHERE id = $1`, cert)), "a hold is never a certificate's revocation")
	require.NoError(t, exec(t, d.App, `UPDATE certificates SET revoked_at = now(), revocation_reason = 'cACompromise', revocation_seen = 'crl'
WHERE id = $1`, cert))
	assert.Equal(t, "Z1022", sqlState(exec(t, d.App, "UPDATE certificates SET revocation_seen = 'ocsp' WHERE id = $1", cert)), "frozen")
	assert.Equal(t, "Z1022", sqlState(exec(t, d.App, "UPDATE certificates SET revocation_seen = '' WHERE id = $1", cert)), "frozen")

	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	require.NoError(t, exec(t, d.App, `INSERT INTO revocation_checks (fingerprint_sha256, status, method, revoked_at, reason, checked_at, next_check_at)
VALUES ($1, 'on_hold', 'ocsp', now(), 'certificateHold', now(), now())`, fp))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `INSERT INTO revocation_checks (fingerprint_sha256, status, checked_at, next_check_at)
VALUES ($1, 'unavailable', now(), now())`, "1"+fp[1:])), "unavailable names its code")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `INSERT INTO revocation_checks (fingerprint_sha256, status, checked_at, next_check_at)
VALUES ($1, 'revoked', now(), now())`, "2"+fp[1:])), "revoked names when")
	require.NoError(t, exec(t, d.App, "DELETE FROM revocation_checks"))

	_, err = p.DownTo(ctx, 33)
	require.Error(t, err, "the Down refuses while a certificate carries a reported revocation")
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(34), version)

	d2 := pgtest.New(t)
	p2 := provider(d2)
	_, err = p2.DownTo(ctx, 33)
	require.NoError(t, err, "nothing to lose: the Down runs")
	var exists bool
	require.NoError(t, d2.Owner.QueryRow(ctx, "SELECT to_regclass('revocation_checks') IS NOT NULL").Scan(&exists))
	assert.False(t, exists)
	_, err = p2.Up(ctx)
	require.NoError(t, err)
}
