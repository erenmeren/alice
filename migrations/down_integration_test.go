//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

func appColumnPrivilege(t *testing.T, d *pgtest.DB, column, priv string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		"SELECT has_column_privilege('alice_app', 'license', $1, $2)", column, priv).Scan(&ok))
	return ok
}

// Carry 4b: migrating below 00004 (an emergency downgrade) must not give the application back
// table-wide UPDATE on the installation row: the ID and the timestamp stay read-only.
func TestDownBelowTheSealKeepsTheInstallationReadOnly(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 3)
	require.NoError(t, err)
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(3), version)

	var tableUpdate bool
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT has_table_privilege('alice_app', 'license', 'UPDATE')").Scan(&tableUpdate))
	assert.False(t, tableUpdate, "no table-wide UPDATE after the Down")
	assert.False(t, appColumnPrivilege(t, d, "installed_at", "UPDATE"))
	assert.False(t, appColumnPrivilege(t, d, "installation_id", "UPDATE"))
	for _, col := range []string{"state", "clock_jump", "updated_at"} {
		assert.True(t, appColumnPrivilege(t, d, col, "UPDATE"), col)
	}
	_, err = d.App.Exec(ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at)
VALUES (1, 'ALICE-TEST', now(), 'evaluation', now())`)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, "UPDATE license SET installed_at = now() - interval '1 day'")
	require.Error(t, err, "the application cannot move the installation time after a downgrade")

	_, err = p.Up(ctx)
	require.NoError(t, err, "the schema migrates up again")
}
