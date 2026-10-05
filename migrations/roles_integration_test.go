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
		// One column more than the listed column-level set.
		"GRANT UPDATE (installed_at) ON license TO alice_app",
	} {
		_, err := d.Owner.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	problems := grantProblems(t, d)
	for _, rel := range []string{"public.phase_x_no_grants", "public.phase_x_too_much", "public.phase_x_columns_only",
		"public.phase_x_view", "public.phase_x_seq", "schema phase_x", "phase_x.hidden",
		"public.audit_log", "public.settings", "public.license"} {
		assert.Contains(t, problems, rel)
	}
	assert.Len(t, problems, 10, "%v", problems)
}

// Explicit grant sets of alice_app. A normal table in public gets appTableGrants unless it
// is listed here; every other relation it can reach (views, sequences with a privilege,
// tables in another schema) must be listed.
var explicitGrants = map[string][]string{
	"public.audit_log":           {"INSERT", "SELECT"},
	"public.master_key_versions": {"INSERT", "SELECT"},
	"public.goose_db_version":    {"SELECT"},
	// License data: uploaded files and their history are append-only for the application,
	// so a compromised application cannot rewrite which licenses were installed (spec §16).
	// The installation row's ID and timestamp are never updated (UPDATE is column-level, below).
	"public.license":         {"INSERT", "SELECT"},
	"public.license_files":   {"INSERT", "SELECT"},
	"public.license_history": {"INSERT", "SELECT"},
	// Phase 3 (R37): credentials are append-only for the application; inventory rows are never
	// deleted (soft delete, missing_since) so their history stays.
	"public.credentials":       {"INSERT", "SELECT"},
	"public.targets":           {"INSERT", "SELECT"},
	"public.host_keys":         {"INSERT", "SELECT"},
	"public.ssh_keys":          {"INSERT", "SELECT"},
	"public.ssh_key_locations": {"INSERT", "SELECT"},
	// Phase 4: private keys and step events are append-only for the application; certificates,
	// locations, signing requests and deployments are history and are never deleted.
	"public.managed_private_keys":  {"INSERT", "SELECT"},
	"public.certificates":          {"INSERT", "SELECT"},
	"public.csr_requests":          {"INSERT", "SELECT"},
	"public.certificate_locations": {"INSERT", "SELECT"},
	"public.deployments":           {"INSERT", "SELECT"},
	"public.deployment_steps":      {"INSERT", "SELECT"},
	// Phase 5 (R40): vault inventory, bindings and imports are never deleted (rows are marked
	// missing, bindings soft-deleted, imports finished); only the listed columns change.
	"public.kv_certificates":         {"INSERT", "SELECT"},
	"public.kv_certificate_versions": {"INSERT", "SELECT"},
	"public.kv_keys":                 {"INSERT", "SELECT"},
	"public.kv_secrets":              {"INSERT", "SELECT"},
	"public.bindings":                {"INSERT", "SELECT"},
	"public.kv_imports":              {"INSERT", "SELECT"},
	// Phase 6 (R41): policies, runs, their locations and steps are history and are never deleted; the steps
	// are append-only (no UPDATE at all).
	"public.rotation_policies":  {"INSERT", "SELECT"},
	"public.rotations":          {"INSERT", "SELECT"},
	"public.rotation_locations": {"INSERT", "SELECT"},
	"public.rotation_steps":     {"INSERT", "SELECT"},
}

// Column-level grants of alice_app (a privilege it holds on some columns but not on the
// table). Every other column-level grant is a problem.
var explicitColumnGrants = map[string]map[string][]string{
	// The cached state and a held clock jump; never installation_id or installed_at (B1, spec
	// §16.1), and never the seal, which is written only when the row is created (00007, AUD-18).
	"public.license": {"UPDATE": {"clock_jump", "state", "updated_at"}},
	// Phase 3: only the columns the services write; identity columns (key material, fingerprints,
	// target and credential references, the host key bytes) are never updated.
	// Phase 5 adds credential_id (a vault's credential moves to its replacement; a trigger refuses it
	// for any other kind of target) and poll_failures (it delays the next poll).
	"public.targets": {"UPDATE": {"credential_id", "deleted_at", "discovery_interval_seconds", "facts", "keys_managed_elsewhere",
		"last_discovery_at", "last_error_code", "last_scheduled_at", "last_success_at", "name", "poll_failures", "status", "updated_at", "version"}},
	"public.host_keys": {"UPDATE": {"confirmed_at", "confirmed_by", "observed_at", "status", "superseded_at"}},
	// Phase 6 adds retired_at (a rotation retires its old key; a key found live again is un-retired).
	"public.ssh_keys": {"UPDATE": {"is_platform_key", "retired_at", "weak"}},
	"public.ssh_key_locations": {"UPDATE": {"comment", "flags", "is_alice_connection_key", "last_seen_at", "line_no",
		"missing_since", "options", "removed_by_alice_at"}},
	// Phase 4: identity columns (fingerprints, public key hashes, paths of a location or a
	// deployment, the certificate, location and target of a deployment, every envelope column) are
	// never updated; the lists are the columns the inventory and deployment services write.
	"public.certificates": {"UPDATE": {"chain_complete", "label", "last_seen_at", "pem_chain", "private_key_id", "source"}},
	"public.csr_requests": {"UPDATE": {"certificate_id", "finished_at", "status"}},
	"public.certificate_locations": {"UPDATE": {"binding_id", "cert_file_sha256", "certificate_id", "changed_outside_at", "custom_location",
		"deployed_fingerprint", "inherited", "key_exists", "key_group", "key_mode", "key_owner", "key_path", "key_problem", "key_type",
		"last_seen_at", "missing_since", "problem", "resolved_cert_path", "servers", "skip_verify", "supported", "symlinked",
		"unsupported_reason", "verify_port", "verify_sni", "version", "warnings"}},
	"public.deployments": {"UPDATE": {"cause_step", "error_code", "error_params", "expect_cert_sha256", "failed_step", "finished_at",
		"helper_error", "job_id", "new_chain_length", "operation_id", "phase", "previous_chain_length", "previous_fingerprint",
		"recover_after", "recovery_attempts", "result", "rollback_info", "started_at", "state", "status", "verified",
		"verify_failed_port", "verify_failed_reason"}},
	// Phase 5: a location joins or leaves a binding; everything that names a vault object, a
	// version, a thumbprint, a binding's certificate or an import's request is fixed at INSERT.
	"public.kv_certificates": {"UPDATE": {"auto_renew", "content_type", "current_thumbprint", "current_version", "details_pending",
		"enabled", "expires", "exportable", "issuer_name", "key_size", "key_type", "kv_created_at", "kv_updated_at", "last_seen_at",
		"listed_thumbprint", "listed_updated_at", "missing_since", "not_before", "removed_notified_at"}},
	"public.kv_certificate_versions": {"UPDATE": {"certificate_id", "chain_incomplete", "content_type", "enabled", "expires", "exportable", "held",
		"held_reason", "key_type", "not_before", "notified_at", "skipped_notified_at"}},
	"public.kv_keys": {"UPDATE": {"curve", "details_problem", "details_updated_at", "enabled", "expires", "hsm", "key_size", "key_type",
		"kv_created_at", "kv_updated_at", "last_seen_at", "managed", "missing_since", "not_before", "version"}},
	"public.kv_secrets": {"UPDATE": {"content_type", "enabled", "expires", "kv_created_at", "kv_updated_at", "last_seen_at", "managed",
		"missing_since", "not_before"}},
	"public.bindings":   {"UPDATE": {"auto_deploy", "auto_since", "deleted_at", "stopped_version", "version"}},
	"public.kv_imports": {"UPDATE": {"error_code", "error_params", "finished_at", "job_id", "sent_at", "state", "version"}},
	// Phase 6: a download counts, a retired key's envelope is destroyed (the envelope columns may only go
	// to NULL together with destroyed_at: managed_private_keys_guard). A rotation's plan, digest, key type,
	// overlap, planning and notice times are fixed at INSERT, as are a location's identity columns.
	"public.managed_private_keys": {"UPDATE": {"ciphertext", "destroyed_at", "download_count", "key_version", "last_downloaded_at", "nonce", "wrapped_dek"}},
	"public.rotation_policies": {"UPDATE": {"deleted_at", "enabled", "interval_days", "name", "new_key_type", "next_run_at", "notify_before_hours",
		"overlap_minutes", "preview_mailed_at", "ssh_key_id", "updated_at", "version"}},
	"public.rotations": {"UPDATE": {"awaiting_decision", "continued_at", "continued_by", "decision_due_at", "finished_at", "kept_count",
		"new_ssh_key_id", "overlap_until", "paused_at", "paused_license", "reminder_sent_at", "removal_allowed", "renotified_at", "result_code",
		"started_at", "status", "updated_at", "verified_at", "version"}},
	"public.rotation_locations": {"UPDATE": {"add_op_id", "add_sent_at", "added_line_no", "backup", "error_code", "job_count", "new_location_id",
		"remove_op_id", "remove_sent_at", "remove_verified_at", "removed_at", "reverified_at", "skip_reason", "state", "undo_op_id",
		"undo_sent_at", "updated_at", "verified_at", "verify_note"}},
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
         CASE WHEN has_table_privilege('alice_app', c.oid, 'TRIGGER') THEN 'TRIGGER' END] END, NULL)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')`, schemas)
	require.NoError(t, err)
	defer rows.Close()
	columns := columnGrants(t, d, schemas)
	for rows.Next() {
		var (
			name, kind string
			privs      []string
		)
		require.NoError(t, rows.Scan(&name, &kind, &privs))
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
		// (for example UPDATE on one audit_log column) unless it is listed exactly.
		if !slices.Equal(want, privs) || !equalColumnGrants(explicitColumnGrants[name], columns[name]) {
			problems = append(problems, name)
		}
	}
	require.NoError(t, rows.Err())
	return problems
}

// columnGrants returns relation -> privilege -> sorted columns on which alice_app holds the
// privilege without holding it on the whole relation.
func columnGrants(t *testing.T, d *pgtest.DB, schemas []string) map[string]map[string][]string {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), `
SELECT n.nspname || '.' || c.relname, p.priv, a.attname::text
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p(priv)
WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND has_column_privilege('alice_app', c.oid, a.attnum, p.priv)
  AND NOT has_table_privilege('alice_app', c.oid, p.priv)`, schemas)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]map[string][]string{}
	for rows.Next() {
		var rel, priv, col string
		require.NoError(t, rows.Scan(&rel, &priv, &col))
		if out[rel] == nil {
			out[rel] = map[string][]string{}
		}
		out[rel][priv] = append(out[rel][priv], col)
	}
	require.NoError(t, rows.Err())
	for _, byPriv := range out {
		for p := range byPriv {
			sort.Strings(byPriv[p])
		}
	}
	return out
}

func equalColumnGrants(want, got map[string][]string) bool {
	if len(want) != len(got) {
		return false
	}
	for p, cols := range want {
		if !slices.Equal(cols, got[p]) {
			return false
		}
	}
	return true
}

func TestLicenseTablesAreAppendOnlyForTheApp(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	g := grants(t, d)
	assert.Equal(t, []string{"INSERT", "SELECT"}, g["license"], "UPDATE on license is column-level only")
	assert.Equal(t, []string{"INSERT", "SELECT"}, g["license_files"])
	assert.Equal(t, []string{"INSERT", "SELECT"}, g["license_history"])
	assert.Equal(t, []string{"DELETE", "INSERT", "SELECT", "UPDATE"}, g["notifications_outbox"])

	_, err := d.App.Exec(ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at)
		VALUES (1, 'ALICE-TEST', now(), 'evaluation', now())`)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at)
		VALUES (2, 'ALICE-TWO', now(), 'evaluation', now())`)
	require.Error(t, err, "the license row is a singleton")
	_, err = d.App.Exec(ctx, `UPDATE license SET state = 'active', clock_jump = NULL, updated_at = now()`)
	require.NoError(t, err, "the cached state and the clock jump stay writable")
	_, err = d.App.Exec(ctx, `UPDATE license SET installation_seal = decode(repeat('01', 32), 'hex')`)
	require.ErrorContains(t, err, "permission denied", "the seal is written only with the row (00007, AUD-18)")
	_, err = d.App.Exec(ctx, `SELECT 1 FROM license WHERE id = 1 FOR UPDATE`)
	require.NoError(t, err, "the license row lock needs UPDATE on some column")
	_, err = d.App.Exec(ctx, `INSERT INTO license_files (id, seq, sha256, raw_file, uploaded_at)
		VALUES (gen_random_uuid(), 1, '\x01', '{}', now())`)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `INSERT INTO license_history (id, at, event, notice) VALUES (gen_random_uuid(), now(), 'notice', 'expiry:30')`)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `INSERT INTO license_history (id, at, event, notice) VALUES (gen_random_uuid(), now(), 'notice', 'expiry:30')`)
	require.Error(t, err, "a notice is recorded once per license")
	_, err = d.App.Exec(ctx, `INSERT INTO license_history (id, at, event, notice) VALUES (gen_random_uuid(), now(), 'state_change', 'x')`)
	require.Error(t, err, "only notices carry a notice key")

	for _, stmt := range []string{
		"UPDATE license_files SET raw_file = '{\"x\":1}'",
		"DELETE FROM license_files",
		"UPDATE license_history SET event = 'renewed'",
		"DELETE FROM license_history",
		"DELETE FROM license",
		// The installation ID and timestamp are fixed once written (B1, spec §16.1).
		"UPDATE license SET installed_at = now()",
		"UPDATE license SET installation_id = 'ALICE-OTHER'",
	} {
		_, err := d.App.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), stmt)
		assert.Equal(t, "42501", pgErr.Code, "%s must be denied by privileges", stmt)
	}
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
