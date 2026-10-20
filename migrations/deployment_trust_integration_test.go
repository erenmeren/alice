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

// 00025 (R51): a deployment records what its verification found about the served chains (status, reason, port,
// store, whether the anchor was known), written by the application; a reason goes with untrusted only; the Down keeps
// a finished deployment's other history.
func TestMigration00025DeploymentTrust(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	w := seedWorld(t, d)
	row := deploymentRow(w)
	require.NoError(t, insertRow(t, d.App, "deployments", row))
	id := row["id"]

	require.NoError(t, exec(t, d.App, `UPDATE deployments SET trust_status = 'untrusted', trust_error = 'wrong_intermediate', trust_port = 443,
    trust_store = 'acme_bundle', trust_enforced = true WHERE id = $1`, id))
	require.NoError(t, exec(t, d.App, "UPDATE deployments SET trust_status = 'trusted', trust_error = '', trust_port = NULL WHERE id = $1", id))
	require.NoError(t, exec(t, d.App, "UPDATE deployments SET trust_status = 'unchecked', trust_store = 'uploaded_root' WHERE id = $1", id))
	for _, bad := range []string{
		"UPDATE deployments SET trust_status = 'maybe' WHERE id = $1",
		"UPDATE deployments SET trust_status = 'untrusted' WHERE id = $1", // no reason
		"UPDATE deployments SET trust_status = 'trusted', trust_error = 'expired' WHERE id = $1",
		"UPDATE deployments SET trust_status = 'untrusted', trust_error = 'something' WHERE id = $1",
		"UPDATE deployments SET trust_store = 'mine' WHERE id = $1",
		"UPDATE deployments SET trust_port = 0 WHERE id = $1",
	} {
		assert.Equal(t, checkViolation, sqlState(exec(t, d.App, bad, id)), bad)
	}

	done := with(deploymentRow(w), map[string]any{"state": "done", "status": "rolled_back", "finished_at": time.Now(),
		"error_code": "deployment.verify_untrusted", "failed_step": "verify", "trust_status": "untrusted", "trust_error": "incomplete_chain",
		"trust_port": 8443, "trust_store": "system", "trust_enforced": true})
	require.NoError(t, insertRow(t, d.App, "deployments", done))

	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 23)
	require.NoError(t, err, "a finished deployment does not stop the Down")
	assert.False(t, hasColumn(t, d, "deployments", "trust_status"))
	var code string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT error_code FROM deployments WHERE id = $1", done["id"]).Scan(&code))
	assert.Equal(t, "deployment.verify_untrusted", code, "history is kept")
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.True(t, hasColumn(t, d, "deployments", "trust_status"))
}
