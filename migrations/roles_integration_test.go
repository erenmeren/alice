//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"sort"
	"strings"
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

	assert.Empty(t, grantProblems(t, d), "every relation alice_app can reach needs an explicit grant set")
}

// A later migration that adds a table without grants, grants too much, adds a view or a
// granted sequence, opens another schema to alice_app, or adds a column-level grant fails TestAppRoleGrants.
func TestGrantGuardCatchesUnlistedRelations(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"CREATE TABLE phase_x_no_grants (id int)",
		"CREATE TABLE phase_x_too_much (id int)",
		"GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON phase_x_too_much TO alice_app",
		"CREATE TABLE phase_x_columns_only (id int, note text)",
		"GRANT SELECT (id) ON phase_x_columns_only TO alice_app",
		"CREATE VIEW phase_x_view AS SELECT id FROM users",
		"GRANT SELECT ON phase_x_view TO alice_app",
		"CREATE SEQUENCE phase_x_seq",
		"GRANT USAGE ON SEQUENCE phase_x_seq TO alice_app",
		"CREATE SCHEMA phase_x",
		"GRANT USAGE ON SCHEMA phase_x TO alice_app",
		"CREATE TABLE phase_x.hidden (id int)",
		// Column-level grants on relations whose table-level grants are correct.
		"GRANT UPDATE (action) ON audit_log TO alice_app",
		"GRANT REFERENCES (key) ON settings TO alice_app",
	} {
		_, err := d.Owner.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	problems := grantProblems(t, d)
	for _, rel := range []string{"public.phase_x_no_grants", "public.phase_x_too_much", "public.phase_x_columns_only",
		"public.phase_x_view", "public.phase_x_seq", "schema phase_x", "phase_x.hidden",
		"public.audit_log", "public.settings"} {
		assert.Contains(t, problems, rel)
	}
	assert.Len(t, problems, 9, "%v", problems)
}

// Explicit grant sets of alice_app. A normal table in public gets appTableGrants unless it
// is listed here; every other relation it can reach (views, sequences with a privilege,
// tables in another schema) must be listed.
var explicitGrants = map[string][]string{
	"public.audit_log":           {"INSERT", "SELECT"},
	"public.master_key_versions": {"INSERT", "SELECT"},
	"public.goose_db_version":    {"SELECT"},
}

var appTableGrants = []string{"DELETE", "INSERT", "SELECT", "UPDATE"}

// grantProblems returns every schema or relation whose effective alice_app privileges
// (direct, through PUBLIC or role membership) differ from the explicit sets above.
func grantProblems(t *testing.T, d *pgtest.DB) []string {
	t.Helper()
	ctx := context.Background()
	var problems []string

	rows, err := d.Owner.Query(ctx, `SELECT nspname FROM pg_namespace
WHERE has_schema_privilege('alice_app', oid, 'USAGE')
  AND nspname NOT IN ('pg_catalog', 'information_schema') AND nspname NOT LIKE 'pg\_toast%' AND nspname NOT LIKE 'pg\_temp%'`)
	require.NoError(t, err)
	var schemas []string
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		schemas = append(schemas, n)
		if n != "public" {
			problems = append(problems, "schema "+n)
		}
	}
	require.NoError(t, rows.Err())

	rows, err = d.Owner.Query(ctx, `
SELECT n.nspname || '.' || c.relname, c.relkind::text,
       array_remove(CASE WHEN c.relkind = 'S' THEN ARRAY[
         CASE WHEN has_sequence_privilege('alice_app', c.oid, 'USAGE') THEN 'USAGE' END,
         CASE WHEN has_sequence_privilege('alice_app', c.oid, 'SELECT') THEN 'SELECT' END,
         CASE WHEN has_sequence_privilege('alice_app', c.oid, 'UPDATE') THEN 'UPDATE' END]
       ELSE ARRAY[
         CASE WHEN has_table_privilege('alice_app', c.oid, 'SELECT') THEN 'SELECT' END,
         CASE WHEN has_table_privilege('alice_app', c.oid, 'INSERT') THEN 'INSERT' END,
         CASE WHEN has_table_privilege('alice_app', c.oid, 'UPDATE') THEN 'UPDATE' END,
         CASE WHEN has_table_privilege('alice_app', c.oid, 'DELETE') THEN 'DELETE' END,
         CASE WHEN has_table_privilege('alice_app', c.oid, 'TRUNCATE') THEN 'TRUNCATE' END,
         CASE WHEN has_table_privilege('alice_app', c.oid, 'REFERENCES') THEN 'REFERENCES' END,
         CASE WHEN has_table_privilege('alice_app', c.oid, 'TRIGGER') THEN 'TRIGGER' END] END, NULL),
       CASE WHEN c.relkind = 'S' THEN false ELSE
         (has_any_column_privilege('alice_app', c.oid, 'SELECT') AND NOT has_table_privilege('alice_app', c.oid, 'SELECT'))
         OR (has_any_column_privilege('alice_app', c.oid, 'INSERT') AND NOT has_table_privilege('alice_app', c.oid, 'INSERT'))
         OR (has_any_column_privilege('alice_app', c.oid, 'UPDATE') AND NOT has_table_privilege('alice_app', c.oid, 'UPDATE'))
         OR (has_any_column_privilege('alice_app', c.oid, 'REFERENCES') AND NOT has_table_privilege('alice_app', c.oid, 'REFERENCES'))
       END
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')`, schemas)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var (
			name, kind string
			privs      []string
			columnOnly bool
		)
		require.NoError(t, rows.Scan(&name, &kind, &privs, &columnOnly))
		sort.Strings(privs)
		want, listed := explicitGrants[name]
		switch {
		case listed:
		case kind == "S" && len(privs) == 0:
			continue // a sequence alice_app cannot use is not reachable
		case (kind == "r" || kind == "p") && strings.HasPrefix(name, "public."):
			want = appTableGrants
		default:
			problems = append(problems, name) // views, granted sequences, other schemas: list them explicitly
			continue
		}
		// A column-level privilege without the table-level one is a hidden extra grant
		// (for example UPDATE on one audit_log column), even when the table-level set matches.
		if !slices.Equal(want, privs) || columnOnly {
			problems = append(problems, name)
		}
	}
	require.NoError(t, rows.Err())
	return problems
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
