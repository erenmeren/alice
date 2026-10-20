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

// 00023 (R48): a deployment records the certificate the replaced file held (its leaf and public key hash, hex or ''),
// written by the application; the phase restore_forbidden is a phase; the Down keeps a finished deployment's phase.
func TestMigration00023RollbackGuard(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	w := seedWorld(t, d)
	row := deploymentRow(w)
	require.NoError(t, insertRow(t, d.App, "deployments", row))
	id := row["id"]

	require.NoError(t, exec(t, d.App, "UPDATE deployments SET rollback_leaf_sha256 = $2, rollback_spki_sha256 = $3 WHERE id = $1", id, hex64("1"), hex64("2")))
	require.NoError(t, exec(t, d.App, "UPDATE deployments SET rollback_leaf_sha256 = '', rollback_spki_sha256 = '' WHERE id = $1", id), "unknown")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE deployments SET rollback_leaf_sha256 = 'abc' WHERE id = $1", id)))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE deployments SET rollback_spki_sha256 = upper($2) WHERE id = $1", id, hex64("a"))))

	done := with(deploymentRow(w), map[string]any{"state": "done", "status": "rollback_failed", "finished_at": time.Now(), "phase": "restore_forbidden",
		"error_code": "deployment.rollback_forbidden", "failed_step": "restore", "helper_error": "forbidden"})
	require.NoError(t, insertRow(t, d.App, "deployments", done))
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"state": "done",
		"status": "failed", "finished_at": time.Now(), "phase": "forbidden"}))))

	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 21)
	require.NoError(t, err, "a finished restore_forbidden deployment does not stop the Down")
	assert.False(t, hasColumn(t, d, "deployments", "rollback_leaf_sha256"))
	var phase string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT phase FROM deployments WHERE id = $1", done["id"]).Scan(&phase))
	assert.Equal(t, "restore_forbidden", phase, "history is kept")
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.True(t, hasColumn(t, d, "deployments", "rollback_leaf_sha256"))
}
