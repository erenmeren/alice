//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"os"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

// grants returns table -> sorted privileges held by alice_app in the public schema.
func grants(t *testing.T, d *pgtest.DB) map[string][]string {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), `
SELECT table_name, privilege_type FROM information_schema.role_table_grants
WHERE grantee = 'alice_app' AND table_schema = 'public'`)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var table, priv string
		require.NoError(t, rows.Scan(&table, &priv))
		out[table] = append(out[table], priv)
	}
	require.NoError(t, rows.Err())
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func TestAppRoleGrants(t *testing.T) {
	d := pgtest.New(t)
	g := grants(t, d)

	assert.Equal(t, []string{"INSERT", "SELECT"}, g["audit_log"], "audit_log is append-only for the app (R33, SEC-071)")
	assert.Equal(t, []string{"INSERT", "SELECT"}, g["master_key_versions"])
	assert.Equal(t, []string{"SELECT"}, g["goose_db_version"])

	rows, err := d.Owner.Query(context.Background(),
		"SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
	require.NoError(t, err)
	defer rows.Close()
	full := []string{"DELETE", "INSERT", "SELECT", "UPDATE"}
	for rows.Next() {
		var table string
		require.NoError(t, rows.Scan(&table))
		switch table {
		case "audit_log", "master_key_versions", "goose_db_version":
			continue
		}
		assert.Equal(t, full, g[table], "table %s needs grants for alice_app (add them in its migration)", table)
	}
	require.NoError(t, rows.Err())
}

func TestAppRoleIsNotSuperuser(t *testing.T) {
	d := pgtest.New(t)
	var super, createRole bool
	require.NoError(t, d.App.QueryRow(context.Background(),
		"SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user").Scan(&super, &createRole))
	assert.False(t, super)
	assert.False(t, createRole)
}

const insertAudit = `INSERT INTO audit_log (seq, at, actor_type, actor_name, action, result, prev_hash, hash)
VALUES (1, now(), 'system', 'test', 'test.event', 'success', '\x00', '\x01')`

func TestAppRoleCannotRewriteAuditLog(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	_, err := d.App.Exec(ctx, insertAudit)
	require.NoError(t, err, "the app may append")

	for _, stmt := range []string{
		"UPDATE audit_log SET action = 'forged'",
		"DELETE FROM audit_log",
		"TRUNCATE audit_log",
	} {
		_, err := d.App.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), stmt)
		assert.Equal(t, "42501", pgErr.Code, "%s must be denied by privileges (F-94)", stmt)
	}
}

func TestTriggersBlockOwnerRewrites(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	_, err := d.Owner.Exec(ctx, insertAudit)
	require.NoError(t, err)

	for _, stmt := range []string{
		"UPDATE audit_log SET action = 'forged'",
		"DELETE FROM audit_log",
		"TRUNCATE audit_log",
	} {
		_, err := d.Owner.Exec(ctx, stmt)
		require.Error(t, err, stmt)
		assert.Contains(t, err.Error(), "audit_log is append-only", stmt)
	}
	var action string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT action FROM audit_log WHERE seq = 1").Scan(&action))
	assert.Equal(t, "test.event", action)
}

func TestDatabasesAreIsolated(t *testing.T) {
	a, b := pgtest.New(t), pgtest.New(t)
	ctx := context.Background()
	_, err := a.App.Exec(ctx, "INSERT INTO settings (key, value) VALUES ('only-in-a', '1')")
	require.NoError(t, err)
	var n int
	require.NoError(t, b.App.QueryRow(ctx, "SELECT count(*) FROM settings").Scan(&n))
	assert.Equal(t, 0, n)
}
