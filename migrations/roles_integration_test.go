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
	// Phase 7 (R42): the notice ledger is append-only; sign-in states are inserted and deleted, never changed.
	"public.alerts":            {"INSERT", "SELECT"},
	"public.oidc_login_states": {"DELETE", "INSERT", "SELECT"},
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
	// Every operation id a rotation location used (G23): append-only, written by the location guard.
	"public.rotation_op_ids": {"INSERT", "SELECT"},
	// ACME (00013): authorities, accounts, hooks, certificates and orders are never deleted (soft delete, history); a
	// binding is added and removed; an account row is deleted only while it is a pending rollover key (trigger, Z1018), and
	// its state only moves forward (Z1019), so no row becomes deletable by an UPDATE.
	"public.acme_providers":    {"INSERT", "SELECT"},
	"public.acme_accounts":     {"DELETE", "INSERT", "SELECT"},
	"public.acme_hooks":        {"INSERT", "SELECT"},
	"public.acme_certificates": {"INSERT", "SELECT"},
	"public.acme_orders":       {"INSERT", "SELECT"},
	"public.acme_bindings":     {"DELETE", "INSERT", "SELECT"},
	// Network discovery (00014): a scope is soft-deleted (its scans keep it); the last 30 scans per scope are kept and a
	// finished scan is history (Z1020); certificates and endpoints are found, updated and removed by retention.
	"public.discovery_scopes":       {"INSERT", "SELECT"},
	"public.discovery_scans":        {"DELETE", "INSERT", "SELECT"},
	"public.discovery_certificates": {"DELETE", "INSERT", "SELECT"},
	"public.discovery_endpoints":    {"DELETE", "INSERT", "SELECT"},
	// Key-compromise incidents (00021): history, never deleted; a finished incident is frozen (Z1023).
	"public.certificate_incidents":          {"INSERT", "SELECT"},
	"public.certificate_incident_locations": {"INSERT", "SELECT"},
	// Services (00026, R49): a service's policy history is append-only.
	"public.service_policies": {"INSERT", "SELECT"},
}

// Column-level grants of alice_app (a privilege it holds on some columns but not on the
// table). Every other column-level grant is a problem.
var explicitColumnGrants = map[string]map[string][]string{
	// The cached state and a held clock jump; never installation_id or installed_at (B1, spec
	// §16.1), and never the seal, which is written only when the row is created (00007, AUD-18).
	"public.license": {"UPDATE": {"clock_jump", "state", "updated_at"}},
	// Phase 3: only the columns the services write; identity columns (key material, fingerprints,
	// target and credential references, the host key bytes) are never updated.
	// 00017 adds capabilities (the startup sync, spec §8.1).
	// Phase 5 adds credential_id (a vault's credential moves to its replacement; a trigger refuses it
	// for any other kind of target) and poll_failures (it delays the next poll).
	// 00026 adds service_id here and on the other owned tables (moving a resource to another service, R49).
	"public.targets": {"UPDATE": {"capabilities", "credential_id", "deleted_at", "discovery_interval_seconds", "facts", "keys_managed_elsewhere",
		"last_discovery_at", "last_error_code", "last_scheduled_at", "last_success_at", "name", "poll_failures", "service_id", "status", "updated_at", "version"}},
	"public.host_keys": {"UPDATE": {"confirmed_at", "confirmed_by", "observed_at", "status", "superseded_at"}},
	// Phase 6 adds retired_at (a rotation retires its old key; a key found live again is un-retired).
	"public.ssh_keys": {"UPDATE": {"is_platform_key", "retired_at", "service_id", "weak"}},
	"public.ssh_key_locations": {"UPDATE": {"comment", "flags", "is_alice_connection_key", "last_seen_at", "line_no",
		"missing_since", "options", "removed_by_alice_at"}},
	// Phase 4: identity columns (fingerprints, public key hashes, paths of a location or a
	// deployment, the certificate, location and target of a deployment, every envelope column) are
	// never updated; the lists are the columns the inventory and deployment services write.
	// 00021 adds the revocation and compromise marks (final once set: Z1022).
	"public.certificates": {"UPDATE": {"chain_complete", "compromised_at", "compromised_by", "label", "last_seen_at", "pem_chain", "private_key_id",
		"revocation_reason", "revoked_at", "revoked_by", "service_id", "source"}},
	"public.csr_requests": {"UPDATE": {"certificate_id", "finished_at", "service_id", "status"}},
	// 00026 adds the binding attention mark (a website whose service does not accept the vault's keys, R49).
	"public.certificate_locations": {"UPDATE": {"binding_attention_at", "binding_attention_code", "binding_id", "cert_file_sha256", "certificate_id", "changed_outside_at", "custom_location",
		"deployed_fingerprint", "inherited", "key_exists", "key_group", "key_mode", "key_owner", "key_path", "key_problem", "key_type",
		"last_seen_at", "missing_since", "problem", "resolved_cert_path", "servers", "skip_verify", "supported", "symlinked",
		"unsupported_reason", "verify_port", "verify_sni", "version", "warnings"}},
	"public.deployments": {"UPDATE": {"cause_step", "error_code", "error_params", "expect_cert_sha256", "failed_step", "finished_at",
		"helper_error", "job_id", "new_chain_length", "operation_id", "phase", "previous_chain_length", "previous_fingerprint",
		"recover_after", "recovery_attempts", "result", "rollback_info", "rollback_leaf_sha256", "rollback_spki_sha256", "started_at", "state",
		"status", "verified", "verify_failed_port", "verify_failed_reason"}},
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
	"public.rotation_policies": {"UPDATE": {"approved_service_ids", "deleted_at", "enabled", "interval_days", "name", "new_key_type", "next_run_at", "notify_before_hours",
		"overlap_minutes", "preview_mailed_at", "ssh_key_id", "updated_at", "version"}},
	"public.rotations": {"UPDATE": {"awaiting_decision", "continued_at", "continued_by", "decision_due_at", "finished_at", "kept_count",
		"new_ssh_key_id", "overlap_until", "paused_at", "paused_license", "reminder_sent_at", "removal_allowed", "renotified_at", "result_code",
		"started_at", "status", "updated_at", "verified_at", "version"}},
	"public.rotation_locations": {"UPDATE": {"add_op_id", "add_resend_count", "add_resent_at", "add_sent_at", "added_line_no", "backup", "error_code", "job_count", "new_location_id",
		"remove_op_id", "remove_sent_at", "remove_verified_at", "removed_at", "reverified_at", "skip_reason", "state", "undo_op_id",
		"undo_sent_at", "updated_at", "verified_at", "verify_note"}},
	// ACME (00013): the sealed account key and every identity column (provider, ids, kind, started_at) are fixed at INSERT; the
	// pending key of an order is deletable (A8) and its challenge records are cleared by the cleanup job (A12).
	"public.acme_providers": {"UPDATE": {"allowed_suffixes", "ca_bundle_pem", "deleted_at", "directory_url", "eab_hmac_ct", "eab_hmac_key_version",
		"eab_hmac_nonce", "eab_hmac_wrapped_dek", "eab_kid", "name", "preset", "updated_at"}},
	"public.acme_accounts": {"UPDATE": {"account_url", "contact_email", "state", "tos_accepted_at", "tos_accepted_by", "tos_url", "updated_at"}},
	"public.acme_hooks": {"UPDATE": {"allowed_suffixes", "ca_bundle_pem", "deleted_at", "name", "poll_timeout_seconds",
		"propagation_wait_seconds", "secret_ct", "secret_key_version", "secret_nonce", "secret_wrapped_dek", "updated_at", "url"}},
	"public.acme_certificates": {"UPDATE": {"account_id", "ari_checked_at", "ari_next_check_at", "ari_renew_at", "ari_window_end", "ari_window_start", "auto_deploy",
		"auto_renew",
		"ca_not_before", "challenge", "current_certificate_id", "deleted_at", "deploy_held_certificate_id", "deploy_held_reason",
		"deploy_released_certificate_id", "deploy_stopped_certificate_id", "failure_notified_at", "failures", "hook_id",
		"http_target_id", "key_type", "last_attempt_at", "last_error_code", "last_failure_class", "names", "next_attempt_at",
		"permanent_failures", "provider_id", "rate_limited_since", "renew_before_days", "service_id", "state", "updated_at"}},
	"public.acme_orders": {"UPDATE": {"account_url", "certificate_id", "cleanup_at", "cleanup_error_code", "error_code", "finished_at", "order_url",
		"pending_key_ct", "pending_key_nonce", "pending_key_version", "pending_key_wrapped_dek", "presented", "replaces", "replaces_outcome", "state"}},
	"public.acme_bindings": {"UPDATE": {"attention_at", "attention_code", "auto_deploy"}},
	// Network discovery (00014): ids, a scope's creator and creation time, a scan's scope, trigger, requester and queue
	// time, a certificate's body and parsed fields, an endpoint's key (scope, address, port, SNI), host and first sighting
	// are fixed at INSERT.
	"public.discovery_scopes": {"UPDATE": {"alert_on_expiry", "concurrency", "deleted_at", "enabled", "entries", "exclusions",
		"last_scheduled_at", "name", "ports", "rate_per_sec", "schedule_hours", "service_id", "sni_names", "updated_at", "version", "window_end",
		"window_start", "window_tz"}},
	"public.discovery_scans": {"UPDATE": {"cancel_requested", "cert_churn", "certificates_new", "endpoints_answered", "endpoints_excluded",
		"endpoints_failed", "endpoints_total", "error_code", "finished_at", "started_at", "state"}},
	"public.discovery_certificates": {"UPDATE": {"is_leaf", "last_seen", "public_key_sha256"}},
	"public.discovery_endpoints": {"UPDATE": {"chain_fingerprints", "chain_sha256", "cipher", "fingerprint_sha256", "gone_since",
		"last_error_code", "last_scan_id", "last_scanned_at", "last_seen", "missed_scans", "previous_fingerprints", "state", "tls_version"}},
	// Key-compromise incidents (00021): the certificate, its key, the ACME certificate, the starter and the creation time
	// are fixed at INSERT, as are a location row's incident and location.
	"public.certificate_incidents": {"UPDATE": {"attention_code", "closed_by", "finished_at", "next_attempt_at", "order_id", "replacement_certificate_id",
		"revocation", "revoke_attempts", "revoke_mode", "revoked_at", "state", "updated_at"}},
	"public.certificate_incident_locations": {"UPDATE": {"attempts", "deployment_id", "error_code", "status", "updated_at"}},
}

var appTableGrants = []string{"DELETE", "INSERT", "SELECT", "UPDATE"}

// serviceColumnTables are the relations whose service columns (00026) the application may update.
var serviceColumnTables = []string{"public.targets", "public.certificates", "public.csr_requests", "public.ssh_keys", "public.acme_certificates",
	"public.discovery_scopes", "public.rotation_policies", "public.certificate_locations"}

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
	apache := hasApacheType(t, d)
	recovery := hasColumn(t, d, "acme_certificates", "last_failure_class")
	revocation := hasColumn(t, d, "certificates", "revoked_at")
	caWait := hasColumn(t, d, "acme_certificates", "ca_not_before")
	guard := hasColumn(t, d, "deployments", "rollback_leaf_sha256")
	ari := hasColumn(t, d, "acme_certificates", "ari_renew_at")
	services := hasColumn(t, d, "targets", "service_id")
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
		wantColumns := explicitColumnGrants[name]
		if name == "public.targets" && !apache {
			// Below 00017 alice_app cannot update targets.capabilities. The guard describes the current schema, so a test that
			// goes down further does not have to list it.
			wantColumns = map[string][]string{"UPDATE": slices.DeleteFunc(slices.Clone(wantColumns["UPDATE"]),
				func(c string) bool { return c == "capabilities" })}
		}
		if name == "public.acme_certificates" && !recovery {
			// Below 00020 the failure class columns do not exist.
			wantColumns = map[string][]string{"UPDATE": slices.DeleteFunc(slices.Clone(wantColumns["UPDATE"]),
				func(c string) bool { return c == "last_failure_class" || c == "permanent_failures" })}
		}
		if name == "public.acme_certificates" && !caWait {
			// Below 00022 the CA's earliest retry time does not exist.
			wantColumns = map[string][]string{"UPDATE": slices.DeleteFunc(slices.Clone(wantColumns["UPDATE"]),
				func(c string) bool { return c == "ca_not_before" })}
		}
		if !ari && (name == "public.acme_certificates" || name == "public.acme_orders") {
			// Below 00024 the chosen renewal time and the replaces columns do not exist.
			wantColumns = map[string][]string{"UPDATE": slices.DeleteFunc(slices.Clone(wantColumns["UPDATE"]), func(c string) bool {
				return slices.Contains([]string{"ari_renew_at", "account_url", "replaces", "replaces_outcome"}, c)
			})}
		}
		if !revocation && (name == "public.certificates" || name == "public.discovery_certificates") {
			// Below 00021 the revocation, compromise and public key columns do not exist.
			wantColumns = map[string][]string{"UPDATE": slices.DeleteFunc(slices.Clone(wantColumns["UPDATE"]), func(c string) bool {
				return slices.Contains([]string{"compromised_at", "compromised_by", "revocation_reason", "revoked_at", "revoked_by", "public_key_sha256"}, c)
			})}
		}
		if name == "public.deployments" && !guard {
			// Below 00023 the rollback target columns do not exist.
			wantColumns = map[string][]string{"UPDATE": slices.DeleteFunc(slices.Clone(wantColumns["UPDATE"]), func(c string) bool {
				return c == "rollback_leaf_sha256" || c == "rollback_spki_sha256"
			})}
		}
		if !services && slices.Contains(serviceColumnTables, name) {
			// Below 00026 there is no owning service to move and no approval to record.
			wantColumns = map[string][]string{"UPDATE": slices.DeleteFunc(slices.Clone(wantColumns["UPDATE"]), func(c string) bool {
				return c == "service_id" || c == "approved_service_ids" || strings.HasPrefix(c, "binding_attention_")
			})}
		}
		if !slices.Equal(want, privs) || !equalColumnGrants(wantColumns, columns[name]) {
			problems = append(problems, name)
		}
	}
	require.NoError(t, rows.Err())
	return problems
}

// hasApacheType: whether migration 00017 is applied (the targets.type check knows apache).
// The LIKE matches the quoted word 'apache' only: it is true from 00017 on, and 00018's 'haproxy' does not change it.
func hasApacheType(t *testing.T, d *pgtest.DB) bool {
	t.Helper()
	var has bool
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		"SELECT coalesce(bool_or(pg_get_constraintdef(oid) LIKE '%''apache''%'), false) FROM pg_constraint WHERE conname = 'targets_type_check'").Scan(&has))
	return has
}

// hasColumn: whether table (schema public) has column (a migration that added it is applied).
func hasColumn(t *testing.T, d *pgtest.DB, table, column string) bool {
	t.Helper()
	var has bool
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2)`, table, column).Scan(&has))
	return has
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
