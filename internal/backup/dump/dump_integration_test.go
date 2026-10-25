//go:build integration

package dump_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/backup/dump"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var ctx = context.Background()

// dumpDB dumps d through the app pool in one REPEATABLE READ READ ONLY transaction and returns the payload (M, the
// tables, Q, Z) and the counts read at the start of the transaction.
func dumpDB(t *testing.T, pool *pgxpool.Pool) ([]byte, map[string]int64) {
	t.Helper()
	var b bytes.Buffer
	counts := dumpTo(t, pool, &b)
	return b.Bytes(), counts
}

func dumpTo(t *testing.T, pool *pgxpool.Pool, w io.Writer) map[string]int64 {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	tables, err := dump.Tables(ctx, tx)
	require.NoError(t, err)
	counts, err := dump.Counts(ctx, tx, tables)
	require.NoError(t, err)
	enc := dump.NewEncoder(w)
	require.NoError(t, enc.JSON(dump.Manifest, "manifest.json", map[string]any{"tables": counts}))
	st, err := dump.Dump(ctx, tx, enc, tables)
	require.NoError(t, err)
	assert.Equal(t, len(tables), st.Tables)
	assert.Equal(t, counts, st.Rows)
	require.NoError(t, enc.JSON(dump.End, "end", map[string]int{"tables": st.Tables, "files": 0}))
	require.NoError(t, enc.Flush())
	require.NoError(t, tx.Commit(ctx))
	return counts
}

// load loads payload into the database of pool as the owner under session_replication_role = replica, inside one
// transaction that commits only when commit is true and Load succeeded.
func load(t *testing.T, pool *pgxpool.Pool, payload []byte, commit bool) (dump.Stats, error) {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "SET LOCAL session_replication_role = replica")
	require.NoError(t, err)
	dec := dump.NewDecoder(bytes.NewReader(payload))
	m, err := dec.Next()
	require.NoError(t, err)
	require.Equal(t, dump.Manifest, m.Kind)
	first, err := dec.Next()
	if err != nil {
		return dump.Stats{}, err
	}
	st, err := dump.Load(ctx, tx.Conn(), dec, first)
	if err != nil {
		return st, err
	}
	if commit {
		require.NoError(t, tx.Commit(ctx))
	}
	return st, nil
}

// rewrite decodes payload and re-encodes it with every frame replaced by what fn returns.
func rewrite(t *testing.T, payload []byte, fn func(f dump.Frame) []dump.Frame) []byte {
	t.Helper()
	dec := dump.NewDecoder(bytes.NewReader(payload))
	var out bytes.Buffer
	enc := dump.NewEncoder(&out)
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		for _, g := range fn(f) {
			require.NoError(t, enc.Frame(g.Kind, g.Name, g.Data))
		}
	}
	require.NoError(t, enc.Flush())
	return out.Bytes()
}

func tableNames(t *testing.T, q db.Querier) []string {
	t.Helper()
	tables, err := dump.Tables(ctx, q)
	require.NoError(t, err)
	names := make([]string, len(tables))
	for i, tb := range tables {
		names[i] = tb.Name
	}
	return names
}

func rowCounts(t *testing.T, q db.Querier) map[string]int64 {
	t.Helper()
	tables, err := dump.Tables(ctx, q)
	require.NoError(t, err)
	c, err := dump.Counts(ctx, q, tables)
	require.NoError(t, err)
	return c
}

// migrationSeeds are the rows a freshly migrated database holds: 00026's environments, Default service and its first
// policy (Load replaces them with the backup's).
var migrationSeeds = map[string]int64{"environments": 4, "services": 1, "service_policies": 1}

// requireEmpty checks that the database holds nothing but what the migrations seed.
func requireEmpty(t *testing.T, d *pgtest.DB) {
	t.Helper()
	for name, n := range rowCounts(t, d.Owner) {
		require.Equalf(t, migrationSeeds[name], n, "table %s of the fresh database has rows", name)
	}
}

// tableDigest is the md5 of every row of table as text, in text order.
func tableDigest(t *testing.T, q db.Querier, table string) string {
	t.Helper()
	var sum string
	//nolint:gosec // G202: the table name comes from pg_catalog and is quoted by pgx.Identifier
	require.NoError(t, q.QueryRow(ctx, "SELECT md5(coalesce(string_agg(t::text, ',' ORDER BY t::text), '')) FROM "+
		pgx.Identifier{"public", table}.Sanitize()+" t").Scan(&sum))
	return sum
}

func TestTablesListsEveryOrdinaryTable(t *testing.T) {
	d := pgtest.New(t)
	_, err := d.Owner.Exec(ctx, `CREATE TABLE public.with_generated (a int, dropped int, b int GENERATED ALWAYS AS (a * 2) STORED, c text);
ALTER TABLE public.with_generated DROP COLUMN dropped;
CREATE VIEW public.a_view AS SELECT 1 AS x;
CREATE SCHEMA other; CREATE TABLE other.hidden (x int);`)
	require.NoError(t, err)

	got, err := dump.Tables(ctx, d.App)
	require.NoError(t, err)

	rows, err := d.Owner.Query(ctx, `SELECT c.table_name::text, array_agg(c.column_name::text ORDER BY c.ordinal_position)
FROM information_schema.columns c JOIN information_schema.tables t USING (table_schema, table_name)
WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE' AND c.table_name <> 'goose_db_version' AND c.is_generated = 'NEVER'
GROUP BY c.table_name`)
	require.NoError(t, err)
	var want []dump.Table
	for rows.Next() {
		var tb dump.Table
		require.NoError(t, rows.Scan(&tb.Name, &tb.Columns))
		want = append(want, tb)
	}
	require.NoError(t, rows.Err())
	sort.Slice(want, func(i, j int) bool { return want[i].Name < want[j].Name })
	assert.Equal(t, want, got)
	assert.Contains(t, got, dump.Table{Name: "with_generated", Columns: []string{"a", "c"}})
	assert.Greater(t, len(got), 30, "every table of the schema")
}

// fill puts at least one row into every table the setup and seed helpers can fill.
func fill(t *testing.T, d *pgtest.DB) {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	kr, err := secrets.LoadOrCreateMasterKey(ctx, d.App, t.TempDir(), clk.Now())
	require.NoError(t, err)
	h := auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	log := audit.New(clk)
	a := auth.NewService(auth.Config{Pool: d.App, Keyring: kr, Audit: log, Clock: clk, Hasher: h, RecoveryHasher: h})
	s := setup.New(setup.Config{Pool: d.App, Auth: a, Keyring: kr, Audit: log, Clock: clk, Hasher: h,
		BackupKDF: secrets.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}})
	code, err := s.ResetToken(ctx)
	require.NoError(t, err)
	meta := auth.Meta{RequestID: "fill"}
	token, err := s.StartSession(ctx, code, meta)
	require.NoError(t, err)
	enr, err := s.BeginAdminEnrollment(ctx, token, setup.AdminInput{Username: "admin", DisplayName: "Ayşe", Password: "correct horse battery staple"})
	require.NoError(t, err)
	totpCode, err := totp.GenerateCode(enr.Secret, clk.Now())
	require.NoError(t, err)
	res, err := s.CreateAdmin(ctx, token, totpCode, meta)
	require.NoError(t, err)
	p, err := a.Authenticate(ctx, res.Token)
	require.NoError(t, err)
	require.NoError(t, s.SetRecoveryPassphrase(ctx, p, meta, "a long and safe recovery passphrase", "a long and safe recovery passphrase"))
	_, err = seed.Dashboard(ctx, d.Owner, clk.Now())
	require.NoError(t, err)
	vault, err := seed.Target(ctx, d.Owner, "vault1", "azure_key_vault", "ok", nil)
	require.NoError(t, err)
	_, _, err = seed.KeyVault(ctx, d.Owner, vault, "cert1", clk.Now().Add(90*24*time.Hour), nil, "key1", clk.Now().Add(90*24*time.Hour))
	require.NoError(t, err)
	insertJob(t, d.App)
	appendAudit(t, d.App, log, "fill.done")
}

func insertJob(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO jobs (id, type, class, kind, payload, payload_mac, status, run_at, max_attempts, created_at)
VALUES ($1, 'test.job', 'always', 'system', '{"x":1}', $2, 'queued', now(), 3, now())`, uuid.New(), bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
}

func appendAudit(t *testing.T, pool *pgxpool.Pool, log *audit.Log, action string) {
	t.Helper()
	require.NoError(t, db.InTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := log.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("test"), Action: action, Result: audit.Success})
		return err
	}))
}

// emptyOnPurpose lists the tables the round trip leaves empty, each with the reason. There are none today.
var emptyOnPurpose = map[string]string{}

// fillRest puts one row into every table fill leaves empty, referring to fill's rows (an Administrator, targets, certificates, a Key
// Vault certificate, a deployment and a job).
func fillRest(t *testing.T, d *pgtest.DB) {
	t.Helper()
	var cert, target uuid.UUID
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT certificate_id, target_id FROM certificate_locations LIMIT 1").Scan(&cert, &target))
	_, err := seed.Deployment(ctx, d.Owner, cert, target, "needs_attention", "", time.Now())
	require.NoError(t, err, "an unfinished deployment, which may get steps")
	_, err = d.Owner.Exec(ctx, `
INSERT INTO license (id, installation_id, installed_at, state, updated_at)
VALUES (1, 'ALICE-ABCD-EFGH-JKLM-NPQR', now(), 'evaluation', now()) ON CONFLICT (id) DO NOTHING;
INSERT INTO location_observations (location_id, drift_mode, tls_observed_at, tls_fingerprint, tls_probe, tls_level,
    drift_since, drift_fingerprint, drift_source, updated_at)
SELECT id, 'approve', now(), repeat('c', 64), 'alice', 2, now(), repeat('c', 64), 'tls', now() FROM certificate_locations LIMIT 1;
INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
SELECT gen_random_uuid(), 'certificate_expiry', id, 'alert subject', now() + interval '30 days', 30, false, false, now() FROM certificates LIMIT 1;
INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at, created_at)
SELECT gen_random_uuid(), id, 'token', '\x0102', 'alc_', '{read}', now() + interval '1 day', now() FROM users LIMIT 1;
INSERT INTO bindings (id, kv_certificate_id, kv_target_id, auto_deploy, created_by, created_at)
SELECT gen_random_uuid(), k.id, k.target_id, false, (SELECT id FROM users LIMIT 1), now() FROM kv_certificates k LIMIT 1;
INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ('a0000000-0000-4000-8000-000000000001', 'csr', 'ecdsa', 256, repeat('a', 64), '\x01', '\x000000000000000000000000', '\x01', 1, now()),
       ('a0000000-0000-4000-8000-000000000002', 'ssh_key', 'ed25519', 256, repeat('b', 64), '\x02', '\x000000000000000000000001', '\x02', 1, now());
INSERT INTO csr_requests (id, private_key_id, common_name, csr_pem, status, created_at)
VALUES (gen_random_uuid(), 'a0000000-0000-4000-8000-000000000001', 'csr.example.test', 'pem', 'pending', now());
INSERT INTO deployment_steps (id, deployment_id, n, name, status, at) SELECT gen_random_uuid(), id, 1, 'connect', 'ok', now() FROM deployments WHERE state <> 'done' LIMIT 1;
INSERT INTO host_keys (id, target_id, key_type, public_key, fingerprint_sha256, status, observed_at)
SELECT gen_random_uuid(), id, 'ssh-ed25519', '\x01', 'SHA256:' || repeat('A', 43), 'observed', now() FROM targets LIMIT 1;
INSERT INTO job_attempts (id, job_id, attempt, worker_id, started_at) SELECT gen_random_uuid(), id, 1, 'worker', now() FROM jobs LIMIT 1;
INSERT INTO kv_imports (id, certificate_id, target_id, name, new_version, state, thumbprint, created_at)
SELECT gen_random_uuid(), (SELECT id FROM certificates LIMIT 1), id, 'import1', true, 'queued', repeat('a', 40), now() FROM targets LIMIT 1;
INSERT INTO kv_secrets (id, target_id, name, enabled, first_seen_at, last_seen_at)
SELECT gen_random_uuid(), target_id, 'secret1', true, now(), now() FROM kv_certificates LIMIT 1;
INSERT INTO license_files (id, seq, sha256, raw_file, uploaded_at) VALUES (gen_random_uuid(), 1, '\x0a0b', '\x01', now());
INSERT INTO license_history (id, at, event) VALUES (gen_random_uuid(), now(), 'installed');
INSERT INTO notifications_outbox (id, kind, to_address, template_key, locale, status, next_attempt_at, created_at)
VALUES (gen_random_uuid(), 'email', 'ayse@example.com', 'notify.test', 'en', 'pending', now(), now());
INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim, authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at)
VALUES ('b0000000-0000-4000-8000-000000000001', 'IdP', 'https://idp.example.test', 'client', '{openid}', 'groups',
        'https://idp.example.test/a', 'https://idp.example.test/t', 'https://idp.example.test/j', true, now(), now());
INSERT INTO oidc_group_mappings (id, provider_id, group_claim_value, role, created_at)
VALUES (gen_random_uuid(), 'b0000000-0000-4000-8000-000000000001', 'admins', 'admin', now());
INSERT INTO ldap_directories (id, name, addresses, user_base_dn, user_filter, login_attribute, unique_id_attribute, display_name_attribute,
        email_attribute, bind_dn, group_base_dn, group_filter, group_name_attribute, created_by, created_at, updated_at)
VALUES ('b1000000-0000-4000-8000-000000000001', 'Corp AD', '{ldaps://dc1.example.test:636,ldaps://dc2.example.test}', 'dc=example,dc=test',
        '(sAMAccountName={login})', 'sAMAccountName', 'objectGUID', 'displayName', 'mail', 'cn=alice,dc=example,dc=test', 'dc=example,dc=test',
        '(member:1.2.840.113556.1.4.1941:={dn})', 'cn', (SELECT id FROM users LIMIT 1), now(), now());
INSERT INTO ldap_group_mappings (id, directory_id, group_value, role, created_at)
VALUES (gen_random_uuid(), 'b1000000-0000-4000-8000-000000000001', 'CN=Alice Ops,DC=example,DC=test', 'operator', now());
INSERT INTO users (id, username, display_name, email, auth_source, role, role_source, ldap_directory_id, ldap_unique_id, ldap_login, created_at, updated_at)
VALUES ('b1000000-0000-4000-8000-000000000002', 'cigdem', 'Çiğdem', 'cigdem@example.test', 'ldap', 'operator', 'ldap_mapping',
        'b1000000-0000-4000-8000-000000000001', '00112233445566778899aabbccddeeff', 'Çiğdem', now(), now());
INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
VALUES ('ldap.directory.b1000000-0000-4000-8000-000000000001.bind_password', '\x01', '\x000000000000000000000005', '\x01', 1, now());
INSERT INTO oidc_login_states (state_hash, provider_id, binding_hash, nonce, code_verifier, purpose, next_path, created_at, expires_at)
VALUES (sha256('state'), 'b0000000-0000-4000-8000-000000000001', sha256('binding'), repeat('n', 43), repeat('v', 43), 'login', '/', now(), now() + interval '5 minutes');
INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES ('c0000000-0000-4000-8000-000000000001', 'SHA256:' || repeat('B', 43), 'ssh-ed25519', 'ssh-ed25519 AAAA', now(), now());
INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, managed, private_key_id, first_seen_at, created_at)
VALUES ('c0000000-0000-4000-8000-000000000002', 'SHA256:' || repeat('C', 43), 'ssh-ed25519', 'ssh-ed25519 BBBB', true,
        'a0000000-0000-4000-8000-000000000002', now(), now());
INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at)
SELECT 'e0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000002', id, 'root', '/root/.ssh/authorized_keys', 1, now(), now()
FROM targets LIMIT 1;
INSERT INTO rotation_policies (id, ssh_key_id, name, enabled, interval_days, created_at, updated_at)
VALUES ('f0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000002', 'policy', false, 30, now(), now());
INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type, overlap_minutes, planned_for, notified_at, created_at, updated_at)
VALUES ('f1000000-0000-4000-8000-000000000001', 'f0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000002',
        'manual', 'dry_run_notified', '{}', repeat('d', 64), 'ed25519', 0, now(), now(), now(), now());
INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state, updated_at)
SELECT 'f2000000-0000-4000-8000-000000000001', 'f1000000-0000-4000-8000-000000000001', 1, id, target_id, os_user, file_path, 'planned', now()
FROM ssh_key_locations WHERE id = 'e0000000-0000-4000-8000-000000000001';
INSERT INTO rotation_op_ids (op_id, location_id, kind) VALUES (gen_random_uuid(), 'f2000000-0000-4000-8000-000000000001', 'add');
INSERT INTO rotation_steps (id, rotation_id, n, location_id, name, status, at)
VALUES (gen_random_uuid(), 'f1000000-0000-4000-8000-000000000001', 1, 'f2000000-0000-4000-8000-000000000001', 'plan', 'ok', now());
INSERT INTO acme_providers (id, name, directory_url, preset, created_at, updated_at)
VALUES ('d1000000-0000-4000-8000-000000000001', 'CA', 'https://ca.example.test/directory', 'custom', now(), now());
INSERT INTO acme_accounts (id, provider_id, key_ct, key_nonce, key_wrapped_dek, key_version, state, created_at, updated_at)
VALUES ('d2000000-0000-4000-8000-000000000001', 'd1000000-0000-4000-8000-000000000001', '\x01', '\x000000000000000000000002', '\x01', 1, 'active', now(), now());
INSERT INTO acme_hooks (id, name, url, secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version, created_at, updated_at)
VALUES ('d3000000-0000-4000-8000-000000000001', 'hook', 'https://dns.example.test/hook', '\x01', '\x000000000000000000000003', '\x01', 1, now(), now());
INSERT INTO acme_hooks (id, name, kind, url, settings, secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version, created_at, updated_at)
VALUES ('d3000000-0000-4000-8000-000000000002', 'route 53', 'route53', '', '{"access_key_id": "TESTACCESSKEYID0001", "role_arn": ""}', '\x01',
        '\x000000000000000000000013', '\x01', 1, now(), now());
INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, created_at, updated_at)
VALUES ('d4000000-0000-4000-8000-000000000001', 'd1000000-0000-4000-8000-000000000001', 'd2000000-0000-4000-8000-000000000001',
        '{www.example.test}', 'ecdsa_p256', 'dns01', 'd3000000-0000-4000-8000-000000000001', now(), now());
INSERT INTO acme_orders (id, acme_certificate_id, kind, started_at, pending_key_ct, pending_key_nonce, pending_key_wrapped_dek, pending_key_version, presented)
VALUES ('d5000000-0000-4000-8000-000000000001', 'd4000000-0000-4000-8000-000000000001', 'issue', now(), '\x01', '\x000000000000000000000004', '\x01', 1,
        '[{"kind":"dns","name":"_acme-challenge.www.example.test"}]');
INSERT INTO acme_bindings (acme_certificate_id, location_id, auto_deploy, created_at)
SELECT 'd4000000-0000-4000-8000-000000000001', id, false, now() FROM certificate_locations LIMIT 1;
INSERT INTO discovery_scopes (id, name, entries, ports, sni_names, exclusions, schedule_hours, window_start, window_end, window_tz, created_at, updated_at)
VALUES ('d6000000-0000-4000-8000-000000000001', 'LAN', '["10.0.0.0/30", "www.example.test"]', '{443,8443}', '{www.example.test}', '["10.0.0.3"]',
        24, '22:00', '04:30', 'Europe/Istanbul', now(), now());
INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, endpoints_total, endpoints_answered)
VALUES ('d7000000-0000-4000-8000-000000000001', 'd6000000-0000-4000-8000-000000000001', 'manual', 'running', now(), now(), 8, 1);
INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before, not_after, key_algorithm, pem, first_seen, last_seen)
VALUES (repeat('e', 64), true, 'www.example.test', '{www.example.test}', 'CA', now(), now() + interval '30 days', 'ecdsa',
        '-----BEGIN CERTIFICATE-----' || chr(10) || 'MIIB' || chr(10) || '-----END CERTIFICATE-----' || chr(10), now(), now());
INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, host, fingerprint_sha256, previous_fingerprints, tls_version, cipher, state, first_seen,
        last_seen, last_scanned_at, last_scan_id)
VALUES ('d8000000-0000-4000-8000-000000000001', 'd6000000-0000-4000-8000-000000000001', '2001:db8::5', 443, 'www.example.test', 'www.example.test',
        repeat('e', 64), ARRAY[repeat('f', 64)], 'TLS 1.3', 'TLS_AES_128_GCM_SHA256', 'present', now(), now(), now(), 'd7000000-0000-4000-8000-000000000001');
INSERT INTO saved_views (id, user_id, page, name, query, created_at) SELECT gen_random_uuid(), id, 'certificates', 'view', '{}', now() FROM users LIMIT 1;
INSERT INTO setup_sessions (id_hash, created_at, idle_expires_at) VALUES (sha256('setup'), now(), now() + interval '1 hour');
INSERT INTO target_locks (target_id, job_id, operation, locked_by, heartbeat_at, lease_until)
SELECT (SELECT id FROM targets LIMIT 1), id, 'deploy', 'worker', now(), now() + interval '1 minute' FROM jobs LIMIT 1;
INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, state, revocation, created_at, updated_at)
SELECT 'e1000000-0000-4000-8000-000000000001', id, public_key_sha256, 'awaiting_replacement', 'not_possible', now(), now()
FROM certificates WHERE public_key_sha256 ~ '^[0-9a-f]{64}$' LIMIT 1;
INSERT INTO certificate_incident_locations (incident_id, location_id, status, updated_at)
SELECT 'e1000000-0000-4000-8000-000000000001', id, 'pending', now() FROM certificate_locations LIMIT 1;
INSERT INTO incident_notices (incident_id, notice, created_at)
VALUES ('e1000000-0000-4000-8000-000000000001', 'windows.compromised_in_store:' || repeat('a', 40), now());
INSERT INTO revocation_checks (fingerprint_sha256, status, method, error_code, failures, checked_at, next_check_at)
VALUES (repeat('e', 64), 'unavailable', '', 'certificate.revocation_unreachable', 2, now(), now() + interval '2 hours');
INSERT INTO deployment_rollouts (id, certificate_id, policy_version, settings, origin, state, wave1_location_ids, wave2_location_ids,
        hold_started_at, hold_until, created_at)
SELECT 'e3000000-0000-4000-8000-000000000001', certificate_id, 1, '{"hold":"10m"}', 'manual', 'hold', ARRAY[id],
       ARRAY['e3000000-0000-4000-8000-000000000002'::uuid], now(), now() + interval '10 minutes', now() FROM certificate_locations LIMIT 1;
INSERT INTO canary_checks (deployment_id, rollout_id, rounds, passes, next_check_at, last_at, last_result, last_tls, last_http_status, last_latency_ms)
SELECT id, 'e3000000-0000-4000-8000-000000000001', 1, 1, now() + interval '30 seconds', now(), 'pass', 'pass', 200, 12
FROM deployments WHERE state <> 'done' LIMIT 1;
INSERT INTO services (id, name, environment_id, created_at, updated_at)
VALUES ('e2000000-0000-4000-8000-000000000001', 'Payments', (SELECT id FROM environments WHERE key = 'production'), now(), now());
INSERT INTO service_trusts (id, source_service_id, target_service_id, created_at)
SELECT 'e2000000-0000-4000-8000-000000000002', id, 'e2000000-0000-4000-8000-000000000001', now() FROM services WHERE is_default;
INSERT INTO directory_groups (id, source, ldap_directory_id, value, created_at)
VALUES ('e2000000-0000-4000-8000-000000000003', 'ldap', 'b1000000-0000-4000-8000-000000000001', 'CN=Payments,DC=example,DC=test', now());
INSERT INTO user_directory_groups (user_id, value, seen_at)
VALUES ('b1000000-0000-4000-8000-000000000002', 'CN=Payments,DC=example,DC=test', now());
INSERT INTO role_bindings (id, directory_group_id, role, service_id, created_at)
VALUES ('e2000000-0000-4000-8000-000000000004', 'e2000000-0000-4000-8000-000000000003', 'operator', 'e2000000-0000-4000-8000-000000000001', now());
INSERT INTO role_bindings (id, user_id, role, environment_id, created_at)
VALUES ('e2000000-0000-4000-8000-000000000006', 'b1000000-0000-4000-8000-000000000002', 'auditor', (SELECT id FROM environments WHERE key = 'staging'), now());
INSERT INTO service_owners (id, service_id, directory_group_id, created_at)
VALUES ('e2000000-0000-4000-8000-000000000005', 'e2000000-0000-4000-8000-000000000001', 'e2000000-0000-4000-8000-000000000003', now());
INSERT INTO users (id, username, display_name, auth_source, role, description, created_at, updated_at)
VALUES ('e2000000-0000-4000-8000-000000000007', 'ci-deployer', 'CI deployer', 'automation', NULL, 'Deploys from the pipeline', now(), now());
INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, service_ids, expires_at, created_at)
VALUES ('e2000000-0000-4000-8000-000000000008', 'e2000000-0000-4000-8000-000000000007', 'pipeline', sha256('automation token'), 'alice_autom1',
        '{operate}', '{e2000000-0000-4000-8000-000000000001}', now() + interval '30 days', now());
INSERT INTO deployment_backups (deployment_id, location_id, leaf_sha256, spki_sha256, ciphertext, nonce, wrapped_dek, key_version, created_at)
SELECT id, location_id, repeat('a', 64), repeat('b', 64), '\x01', '\x000000000000000000000006', '\x01', 1, now() FROM deployments WHERE state <> 'done' LIMIT 1;
INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ('e3000000-0000-4000-8000-000000000001', 'kubernetes_cluster', 'k8s_token', '{"api_url":"https://k8s.example.test:6443"}', '\x01',
        '\x000000000000000000000007', '\x01', 1, now(), 'e3000000-0000-4000-8000-000000000002');
INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ('e3000000-0000-4000-8000-000000000002', 'cluster-1', 'kubernetes', '{"host":"k8s.example.test","port":6443}',
        'e3000000-0000-4000-8000-000000000001', 'ok', now(), now());
INSERT INTO certificate_locations (id, target_id, kind, cert_path, locator, details, verify_address, supported, first_seen_at, last_seen_at)
VALUES ('e3000000-0000-4000-8000-000000000003', 'e3000000-0000-4000-8000-000000000002', 'k8s_tls_secret', 'shop/shop-tls',
        '{"namespace":"shop","name":"shop-tls"}', '{"resource_version":"12","immutable":false}', '10.0.0.9', true, now(), now());`)
	require.NoError(t, err)
}

func TestDumpLoadRoundTripsEveryTable(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	fillRest(t, a)
	countsA := rowCounts(t, a.Owner)
	// Every table of the catalog has rows, so a new table fails here until fillRest (or emptyOnPurpose) covers it.
	for _, name := range tableNames(t, a.Owner) {
		if why, ok := emptyOnPurpose[name]; ok {
			require.Zerof(t, countsA[name], "table %s is listed as empty: %s", name, why)
			continue
		}
		require.Positivef(t, countsA[name], "table %s has no row: fill it in fillRest or list it in emptyOnPurpose with the reason", name)
	}
	payload, counts := dumpDB(t, a.App)
	assert.Equal(t, countsA, counts)

	b := pgtest.New(t)
	requireEmpty(t, b) // migrations seed only migrationSeeds, which Load replaces; TRUNCATE is refused by audit_log_no_truncate (M-26)
	st, err := load(t, b.Owner, payload, true)
	require.NoError(t, err)
	assert.Equal(t, dump.End, st.Next.Kind, "Load returns at the first frame after Q")
	assert.Equal(t, len(countsA), st.Tables)
	assert.Equal(t, countsA, st.Rows)

	for _, name := range tableNames(t, a.Owner) {
		assert.Equalf(t, tableDigest(t, a.Owner, name), tableDigest(t, b.Owner, name), "table %s", name)
	}
	seqs := func(q db.Querier) map[string]*int64 {
		rows, err := q.Query(ctx, "SELECT sequencename::text, last_value FROM pg_sequences WHERE schemaname = 'public'")
		require.NoError(t, err)
		m := map[string]*int64{}
		for rows.Next() {
			var n string
			var v *int64
			require.NoError(t, rows.Scan(&n, &v))
			m[n] = v
		}
		require.NoError(t, rows.Err())
		return m
	}
	sa, sb := seqs(a.App), seqs(b.App)
	assert.Len(t, sb, len(sa))
	for n, v := range sa {
		if v != nil {
			assert.Equalf(t, *v, *sb[n], "sequence %s", n)
		}
	}

	ra, err := audit.Verify(ctx, a.App)
	require.NoError(t, err)
	rb, err := audit.Verify(ctx, b.App)
	require.NoError(t, err)
	assert.True(t, rb.Intact)
	assert.Equal(t, ra.HeadSeq, rb.HeadSeq)
	assert.Equal(t, ra.HeadHash, rb.HeadHash)
}

// TestF86ConsistentSnapshot: rows committed while the dump runs are not in the payload.
func TestF86ConsistentSnapshot(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	// A first table large enough that its copy blocks on the pipe while the writers commit.
	_, err := a.Owner.Exec(ctx, `CREATE TABLE public.aaa_big (id int PRIMARY KEY, pad text NOT NULL);
INSERT INTO public.aaa_big SELECT g, repeat('x', 200) FROM generate_series(1, 20000) g;
GRANT SELECT ON public.aaa_big TO alice_app`)
	require.NoError(t, err)
	log := audit.New(clock.NewFake(time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)))

	pr, pw := io.Pipe()
	var payload bytes.Buffer
	var counts map[string]int64
	dumped := make(chan struct{})
	go func() {
		defer close(dumped)
		counts = dumpTo(t, a.App, pw)
		_ = pw.Close()
	}()
	// Read the first bytes: the dump is inside the first table now, and blocks on the pipe.
	first := make([]byte, 64<<10)
	n, err := io.ReadFull(pr, first)
	require.NoError(t, err)
	payload.Write(first[:n])

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			appendAudit(t, a.App, log, "concurrent.append")
			insertJob(t, a.App)
		})
	}
	wg.Wait()
	_, err = io.Copy(&payload, pr)
	require.NoError(t, err)
	<-dumped

	after := rowCounts(t, a.Owner)
	assert.Equal(t, counts["audit_log"]+50, after["audit_log"], "the writers committed while the dump ran")
	assert.Equal(t, counts["jobs"]+50, after["jobs"])

	rows := map[string]int64{}
	dec := dump.NewDecoder(bytes.NewReader(payload.Bytes()))
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if f.Kind == dump.TableEnd {
			var e struct{ Rows int64 }
			require.NoError(t, json.Unmarshal(f.Data, &e))
			rows[f.Name] = e.Rows
		}
	}
	assert.Equal(t, counts, rows, "the payload holds exactly the snapshot taken at the start")

	b := pgtest.New(t)
	_, err = b.Owner.Exec(ctx, `CREATE TABLE public.aaa_big (id int PRIMARY KEY, pad text NOT NULL)`)
	require.NoError(t, err)
	_, err = load(t, b.Owner, payload.Bytes(), true)
	require.NoError(t, err)
	rep, err := audit.Verify(ctx, b.App)
	require.NoError(t, err)
	assert.True(t, rep.Intact, "no half-appended chain")
	assert.Equal(t, counts["audit_log"], rep.Checked)
}

// tableJSON is the data of a T frame.
type tableJSON struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

func TestLoadRefusesASchemaMismatch(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	payload, _ := dumpDB(t, a.App)
	for name, change := range map[string]func([]string) []string{
		"unknown column": func(c []string) []string { return append(c, "extra") },
		"missing column": func(c []string) []string { return c[:len(c)-1] },
		"other order":    func(c []string) []string { return append([]string{c[len(c)-1]}, c[:len(c)-1]...) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := rewrite(t, payload, func(f dump.Frame) []dump.Frame {
				if f.Kind == dump.TableStart && f.Name == "settings" {
					var tj tableJSON
					require.NoError(t, json.Unmarshal(f.Data, &tj))
					tj.Columns = change(tj.Columns)
					f.Data, _ = json.Marshal(tj)
				}
				return []dump.Frame{f}
			})
			b := pgtest.New(t)
			_, err := load(t, b.Owner, bad, true)
			require.ErrorIs(t, err, dump.ErrSchemaMismatch)
			requireEmpty(t, b)
		})
	}
	t.Run("name differs from the frame", func(t *testing.T) {
		bad := rewrite(t, payload, func(f dump.Frame) []dump.Frame {
			if f.Kind == dump.TableStart && f.Name == "settings" {
				f.Data = []byte(`{"name":"users","columns":["key"]}`)
			}
			return []dump.Frame{f}
		})
		b := pgtest.New(t)
		_, err := load(t, b.Owner, bad, true)
		require.ErrorIs(t, err, dump.ErrPayload)
		requireEmpty(t, b)
	})
	t.Run("row count differs from the end frame", func(t *testing.T) {
		bad := rewrite(t, payload, func(f dump.Frame) []dump.Frame {
			if f.Kind == dump.TableEnd && f.Name == "users" {
				f.Data = []byte(`{"rows":99}`)
			}
			return []dump.Frame{f}
		})
		b := pgtest.New(t)
		_, err := load(t, b.Owner, bad, true)
		require.ErrorIs(t, err, dump.ErrPayload)
		requireEmpty(t, b)
	})
	t.Run("damaged copy data", func(t *testing.T) {
		bad := rewrite(t, payload, func(f dump.Frame) []dump.Frame {
			if f.Kind == dump.Data && len(f.Data) > 30 {
				f.Data = f.Data[:len(f.Data)-7]
			}
			return []dump.Frame{f}
		})
		b := pgtest.New(t)
		_, err := load(t, b.Owner, bad, true)
		require.Error(t, err)
		requireEmpty(t, b)
	})
}

func TestLoadRefusesMissingDuplicateOrUnorderedTables(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	payload, _ := dumpDB(t, a.App)
	// Collect each table's frames, so the cases can drop, repeat or swap whole tables.
	var head, tail []dump.Frame
	var tables [][]dump.Frame
	dec := dump.NewDecoder(bytes.NewReader(payload))
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		switch f.Kind {
		case dump.Manifest:
			head = append(head, f)
		case dump.TableStart:
			tables = append(tables, []dump.Frame{f})
		case dump.Data, dump.TableEnd:
			tables[len(tables)-1] = append(tables[len(tables)-1], f)
		default:
			tail = append(tail, f)
		}
	}
	build := func(ts [][]dump.Frame) []byte {
		var out bytes.Buffer
		enc := dump.NewEncoder(&out)
		for _, f := range head {
			require.NoError(t, enc.Frame(f.Kind, f.Name, f.Data))
		}
		for _, tb := range ts {
			for _, f := range tb {
				require.NoError(t, enc.Frame(f.Kind, f.Name, f.Data))
			}
		}
		for _, f := range tail {
			require.NoError(t, enc.Frame(f.Kind, f.Name, f.Data))
		}
		require.NoError(t, enc.Flush())
		return out.Bytes()
	}
	n := len(tables)
	cases := map[string]struct {
		tables [][]dump.Frame
		err    error
	}{
		"first missing":  {tables[1:], dump.ErrSchemaMismatch},
		"middle missing": {append(append([][]dump.Frame{}, tables[:n/2]...), tables[n/2+1:]...), dump.ErrSchemaMismatch},
		"last missing":   {tables[:n-1], dump.ErrSchemaMismatch},
		"repeated":       {append(append([][]dump.Frame{}, tables[:2]...), tables[1:]...), dump.ErrPayload},
		"unordered":      {append([][]dump.Frame{tables[1], tables[0]}, tables[2:]...), dump.ErrSchemaMismatch},
		"unknown table": {append(append([][]dump.Frame{}, tables...), []dump.Frame{
			{Kind: dump.TableStart, Name: "zzz_unknown", Data: []byte(`{"name":"zzz_unknown","columns":["a"]}`)},
			{Kind: dump.TableEnd, Name: "zzz_unknown", Data: []byte(`{"rows":0}`)}}), dump.ErrSchemaMismatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := pgtest.New(t)
			_, err := load(t, b.Owner, build(c.tables), true)
			require.ErrorIs(t, err, c.err)
			requireEmpty(t, b)
		})
	}
	t.Run("control", func(t *testing.T) {
		b := pgtest.New(t)
		_, err := load(t, b.Owner, build(tables), true)
		require.NoError(t, err)
	})
}

func TestLoadRefusesMissingSequences(t *testing.T) {
	const ddl = `CREATE SEQUENCE public.extra_seq; GRANT USAGE, SELECT ON SEQUENCE public.extra_seq TO alice_app`
	a := pgtest.New(t)
	_, err := a.Owner.Exec(ctx, ddl)
	require.NoError(t, err)
	_, err = a.Owner.Exec(ctx, "SELECT setval('public.extra_seq', 41)")
	require.NoError(t, err)
	payload, _ := dumpDB(t, a.App)

	var q map[string]*int64
	_ = rewrite(t, payload, func(f dump.Frame) []dump.Frame {
		if f.Kind == dump.Sequences {
			require.NoError(t, json.Unmarshal(f.Data, &q))
		}
		return []dump.Frame{f}
	})
	require.NotNil(t, q["public.extra_seq"])
	assert.Equal(t, int64(41), *q["public.extra_seq"])

	withQ := func(m map[string]*int64) []byte {
		return rewrite(t, payload, func(f dump.Frame) []dump.Frame {
			if f.Kind == dump.Sequences {
				f.Data, _ = json.Marshal(m)
			}
			return []dump.Frame{f}
		})
	}
	without := map[string]*int64{}
	for k, v := range q {
		if k != "public.extra_seq" {
			without[k] = v
		}
	}
	ghost := map[string]*int64{"public.ghost_seq": nil}
	for k, v := range q {
		ghost[k] = v
	}
	noPrefix := map[string]*int64{}
	for k, v := range q {
		noPrefix[k] = v
	}
	delete(noPrefix, "public.extra_seq")
	noPrefix["extra_seq"] = nil

	for name, stream := range map[string][]byte{"lacks one": withQ(without), "names an unknown one": withQ(ghost),
		"without schema": withQ(noPrefix)} {
		t.Run(name, func(t *testing.T) {
			b := pgtest.New(t)
			_, err := b.Owner.Exec(ctx, ddl)
			require.NoError(t, err)
			_, err = load(t, b.Owner, stream, true)
			require.ErrorIs(t, err, dump.ErrSchemaMismatch)
		})
	}
	t.Run("control", func(t *testing.T) {
		b := pgtest.New(t)
		_, err := b.Owner.Exec(ctx, ddl)
		require.NoError(t, err)
		_, err = load(t, b.Owner, payload, true)
		require.NoError(t, err)
		var v int64
		require.NoError(t, b.Owner.QueryRow(ctx, "SELECT last_value FROM public.extra_seq").Scan(&v))
		assert.Equal(t, int64(41), v)
	})
	t.Run("a sequence the target lacks", func(t *testing.T) {
		b := pgtest.New(t)
		_, err := load(t, b.Owner, payload, true)
		require.ErrorIs(t, err, dump.ErrSchemaMismatch)
	})
}

func TestCopyStatementsQuoteIdentifiers(t *testing.T) {
	const ddl = `CREATE TABLE public."odd ""table"" name" ("col ""x""" text)`
	odd := dump.Table{Name: `odd "table" name`, Columns: []string{`col "x"`}}
	assert.Equal(t, `COPY "public"."odd ""table"" name" ("col ""x""") TO STDOUT (FORMAT binary)`, dump.CopyOut(odd))
	assert.Equal(t, `COPY "public"."odd ""table"" name" ("col ""x""") FROM STDIN (FORMAT binary)`, dump.CopyIn(odd))

	a := pgtest.New(t)
	_, err := a.Owner.Exec(ctx, ddl+`; INSERT INTO public."odd ""table"" name" VALUES ('it''s "quoted"');
GRANT SELECT ON public."odd ""table"" name" TO alice_app`)
	require.NoError(t, err)
	payload, counts := dumpDB(t, a.App)
	assert.Equal(t, int64(1), counts[odd.Name])

	b := pgtest.New(t)
	_, err = b.Owner.Exec(ctx, ddl)
	require.NoError(t, err)
	_, err = load(t, b.Owner, payload, true)
	require.NoError(t, err)
	assert.Equal(t, tableDigest(t, a.Owner, odd.Name), tableDigest(t, b.Owner, odd.Name))
	var v string
	require.NoError(t, b.Owner.QueryRow(ctx, `SELECT "col ""x""" FROM public."odd ""table"" name"`).Scan(&v))
	assert.Equal(t, `it's "quoted"`, v)
}

// failAfter fails every write after n bytes.
type failAfter struct{ n int }

func (w *failAfter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		return 0, errors.New("no space left on device")
	}
	w.n -= len(p)
	return len(p), nil
}

func TestDumpReportsWriteErrors(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	_, err := a.Owner.Exec(ctx, `CREATE TABLE public.aaa_big (id int PRIMARY KEY, pad text NOT NULL);
INSERT INTO public.aaa_big SELECT g, repeat('x', 200) FROM generate_series(1, 20000) g;
GRANT SELECT ON public.aaa_big TO alice_app`)
	require.NoError(t, err)
	for _, limit := range []int{0, 100 << 10, 2 << 20} {
		tx, err := a.App.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		tables, err := dump.Tables(ctx, tx)
		require.NoError(t, err)
		enc := dump.NewEncoder(&failAfter{n: limit})
		_, err = dump.Dump(ctx, tx, enc, tables)
		if err == nil {
			err = enc.Flush()
		}
		require.ErrorContainsf(t, err, "no space left on device", "limit %d", limit)
		_ = tx.Rollback(ctx)
	}
}

func TestCatalogErrorsAreReported(t *testing.T) {
	a := pgtest.New(t)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := dump.Tables(cancelled, a.App)
	require.Error(t, err)
	_, err = dump.Counts(cancelled, a.App, []dump.Table{{Name: "users"}})
	require.Error(t, err)
	_, err = dump.Counts(ctx, a.App, []dump.Table{{Name: "no_such_table"}})
	require.Error(t, err)
}
