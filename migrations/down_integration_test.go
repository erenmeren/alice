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
	assert.False(t, appColumnPrivilege(t, d, "installation_seal", "UPDATE"), "the seal stays read-only (00007, AUD-18)")
	assert.False(t, appColumnPrivilege(t, d, "installed_at", "UPDATE"))
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT has_table_privilege('alice_app', 'license', 'UPDATE')").Scan(&tableUpdate))
	assert.False(t, tableUpdate, "no table-wide UPDATE after migrating up again")
}

func tableExists(t *testing.T, d *pgtest.DB, name string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT to_regclass('public.' || $1) IS NOT NULL", name).Scan(&ok))
	return ok
}

var phase4Tables = []string{"managed_private_keys", "certificates", "csr_requests", "certificate_locations", "deployments", "deployment_steps"}

// 00006 goes up over a database that holds Phase 3 data, goes down to 00005 with that data intact
// and goes up again (Phase 4 is unreleased, so a Down is an emergency tool: it drops the Phase 4
// tables and nothing else).
func TestMigration00006UpAndDownKeepPhase3Data(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)

	_, err = p.DownTo(ctx, 5)
	require.NoError(t, err)
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(5), version)
	for _, tbl := range phase4Tables {
		assert.False(t, tableExists(t, d, tbl), tbl)
	}
	// Below 00007 the application holds UPDATE on the installation seal again (00004); the
	// grant check describes the current schema, so that is the one difference it reports.
	// The guard describes the current schema: below 00008 targets lacks the Phase 5 column grants
	// (credential_id, poll_failures), so it reports targets as well.
	assert.ElementsMatch(t, []string{"public.license", "public.targets"}, grantProblems(t, d), "no Phase 4 grant is left behind")
	target := seedTarget(t, d, "web-01", "web-01.example.com")
	job, err := seedJob(t, d, nil, "succeeded")
	require.NoError(t, err)

	count := func() (targets, jobs, credentials int) {
		require.NoError(t, d.Owner.QueryRow(ctx, "SELECT (SELECT count(*) FROM targets), (SELECT count(*) FROM jobs), (SELECT count(*) FROM credentials)").Scan(&targets, &jobs, &credentials))
		return
	}
	for round := 0; round < 2; round++ {
		_, err = p.Up(ctx)
		require.NoError(t, err)
		for _, tbl := range phase4Tables {
			assert.True(t, tableExists(t, d, tbl), tbl)
		}
		assert.Empty(t, grantProblems(t, d))
		targets, jobs, creds := count()
		assert.Equal(t, [3]int{1, 1, 1}, [3]int{targets, jobs, creds}, "Phase 3 data survives the Up")
		var name string
		require.NoError(t, d.App.QueryRow(ctx, "SELECT name FROM targets WHERE id = $1", target).Scan(&name))
		require.NoError(t, d.App.QueryRow(ctx, "SELECT id::text FROM jobs WHERE id = $1", job).Scan(&name))

		if round == 0 {
			_, err = p.DownTo(ctx, 5)
			require.NoError(t, err)
			for _, tbl := range phase4Tables {
				assert.False(t, tableExists(t, d, tbl), tbl)
			}
			var fn bool
			require.NoError(t, d.Owner.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname IN ('certificates_check_key', 'deployments_protect_done', 'deployment_steps_check_open', 'certificate_location_path_hash'))").Scan(&fn))
			assert.False(t, fn, "the Down drops the trigger and index functions")
			targets, jobs, creds = count()
			assert.Equal(t, [3]int{1, 1, 1}, [3]int{targets, jobs, creds}, "Phase 3 data survives the Down")
		}
	}
}

// 00007 (AUD-18) takes UPDATE on the installation seal from the application; its Down gives it
// back (symmetric), and the Up again takes it.
func TestMigration00007SealIsReadOnly(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	assert.False(t, appColumnPrivilege(t, d, "installation_seal", "UPDATE"))
	_, err = p.DownTo(ctx, 6)
	require.NoError(t, err)
	assert.True(t, appColumnPrivilege(t, d, "installation_seal", "UPDATE"), "the Down restores the 00004 grant")
	for _, col := range []string{"state", "clock_jump", "updated_at"} {
		assert.True(t, appColumnPrivilege(t, d, col, "UPDATE"), col)
	}
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.False(t, appColumnPrivilege(t, d, "installation_seal", "UPDATE"))
	assert.Empty(t, grantProblems(t, d))
}
