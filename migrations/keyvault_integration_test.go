//go:build integration

package migrations_test

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// vaultFixture is one vault added the way the inventory service adds it: the vault's credential
// and the vault target in one transaction (the credential's foreign key to the target is deferred).
type vaultFixture struct {
	target, credential string
}

const insertVaultCredential = `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, 'azure_vault', $2, '{"tenant_id": "00000000-0000-0000-0000-000000000001"}', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), $3)`

const insertVaultTarget = `INSERT INTO targets (id, name, type, config, credential_id, status, discovery_interval_seconds, created_at, updated_at)
VALUES ($1, $2, 'azure_key_vault', jsonb_build_object('vault_url', $3::text, 'host', $4::text, 'port', 443), $5, 'ok', 900, now(), now())`

func vaultConfigHost(name string) string { return name + ".vault.azure.net" }

// addVault inserts a vault target with its credential through the application role.
func addVault(t *testing.T, d *pgtest.DB, name string) vaultFixture {
	t.Helper()
	ctx := context.Background()
	f := vaultFixture{}
	require.NoError(t, d.App.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&f.target))
	require.NoError(t, d.App.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&f.credential))
	tx, err := d.App.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, insertVaultCredential, f.credential, "azure_sp_secret", f.target)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, insertVaultTarget, f.target, "vault "+name, "https://"+vaultConfigHost(name), vaultConfigHost(name), f.credential)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return f
}

func scanID(t *testing.T, d *pgtest.DB, sql string, args ...any) string {
	t.Helper()
	var id string
	require.NoError(t, d.App.QueryRow(context.Background(), sql, args...).Scan(&id))
	return id
}

func insertKVCertificate(t *testing.T, d *pgtest.DB, vault, name string) string {
	t.Helper()
	return scanID(t, d, `INSERT INTO kv_certificates (id, target_id, name, listed_thumbprint, enabled, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, $2, repeat('a', 40), true, now(), now()) RETURNING id::text`, vault, name)
}

const insertVersionSQL = `INSERT INTO kv_certificate_versions (id, kv_certificate_id, version, thumbprint, enabled, detected_at)
VALUES (gen_random_uuid(), $1, $2, $3, true, now()) RETURNING id::text`

func insertKVVersion(t *testing.T, d *pgtest.DB, cert, version string) string {
	t.Helper()
	return scanID(t, d, insertVersionSQL, cert, version, strings.Repeat("b", 40))
}

func insertCertificate(t *testing.T, d *pgtest.DB) string {
	t.Helper()
	return scanID(t, d, `INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
VALUES (gen_random_uuid(), encode(sha256(gen_random_uuid()::text::bytea), 'hex'), now() - interval '1 day', now() + interval '90 days', 'rsa', repeat('c', 64), 'pem', 'azure_kv', now(), now(), now())
RETURNING id::text`)
}

func insertLocation(t *testing.T, d *pgtest.DB, target string) string {
	t.Helper()
	return scanID(t, d, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, supported, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, 'nginx_file', '/etc/ssl/' || gen_random_uuid()::text || '.pem', true, now(), now()) RETURNING id::text`, target)
}

func insertBinding(t *testing.T, d *pgtest.DB, cert, vault string) error {
	t.Helper()
	return exec(t, d.App, `INSERT INTO bindings (id, kv_certificate_id, kv_target_id, created_at) VALUES (gen_random_uuid(), $1, $2, now())`, cert, vault)
}

func TestPhase3ConstraintNamesAreTheDefaults(t *testing.T) {
	d := pgtest.New(t)
	rows, err := d.Owner.Query(context.Background(), `SELECT conname FROM pg_constraint WHERE conrelid IN ('credentials'::regclass, 'targets'::regclass)`)
	require.NoError(t, err)
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		names = append(names, n)
	}
	require.NoError(t, rows.Err())
	for _, want := range []string{"credentials_purpose_check", "targets_status_check", "targets_discovery_interval_seconds_check"} {
		assert.Contains(t, names, want, "00008 drops and re-adds the constraint by this name")
	}
}

func TestVaultTargetAndItsCredentialCommitTogether(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	v := addVault(t, d, "kv1")
	var tid string
	require.NoError(t, d.App.QueryRow(ctx, "SELECT credential_id::text FROM targets WHERE id = $1", v.target).Scan(&tid))
	assert.Equal(t, v.credential, tid)

	// The credential alone: the deferred foreign key refuses the commit.
	tx, err := d.App.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, insertVaultCredential, "00000000-0000-0000-0000-0000000000aa", "azure_sp_secret", "00000000-0000-0000-0000-0000000000bb")
	require.NoError(t, err, "the statement itself passes: the check is deferred")
	assert.Equal(t, "23503", sqlState(tx.Commit(ctx)), "a credential whose vault does not exist cannot commit")

	cols := `(id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)`
	for name, stmt := range map[string]string{
		"platform_ssh credential with a target":     `INSERT INTO credentials ` + cols + ` SELECT gen_random_uuid(), 'platform_ssh', 'ssh_private_key', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), id FROM targets LIMIT 1`,
		"azure_vault credential without a target":   `INSERT INTO credentials ` + cols + ` VALUES (gen_random_uuid(), 'azure_vault', 'azure_sp_secret', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), NULL)`,
		"azure kind on the platform purpose":        `INSERT INTO credentials ` + cols + ` VALUES (gen_random_uuid(), 'platform_ssh', 'azure_sp_secret', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), NULL)`,
		"ssh kind on the vault purpose":             `INSERT INTO credentials ` + cols + ` SELECT gen_random_uuid(), 'azure_vault', 'ssh_private_key', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), id FROM targets LIMIT 1`,
		"unknown purpose":                           `INSERT INTO credentials ` + cols + ` VALUES (gen_random_uuid(), 'other', 'azure_sp_secret', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), NULL)`,
		"password kind that is not a vault purpose": `INSERT INTO credentials ` + cols + ` VALUES (gen_random_uuid(), 'platform_ssh', 'ssh_password_unused', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), NULL)`,
	} {
		assert.Equal(t, "23514", sqlState(exec(t, d.App, stmt)), name)
	}
	// Every sign-in kind is accepted for a vault.
	for _, kind := range []string{"azure_sp_cert", "azure_managed_identity"} {
		target := scanID(t, d, "SELECT gen_random_uuid()::text")
		cred := scanID(t, d, "SELECT gen_random_uuid()::text")
		host := "kv-" + strings.ReplaceAll(kind, "_", "") // lower case letters and digits only
		tx, err := d.App.Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, insertVaultCredential, cred, kind, target)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, insertVaultTarget, target, host, "https://"+vaultConfigHost(host), vaultConfigHost(host), cred)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx), kind)
	}
}

func TestVaultConfigAndIntervalChecks(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	v := addVault(t, d, "kv1")
	seed := seedTarget(t, d, "web-01", "web-01.example.com")

	ins := func(typ, cfg string, interval int, status string) error {
		tx, err := d.App.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		cred := scanID(t, d, "SELECT gen_random_uuid()::text")
		id := scanID(t, d, "SELECT gen_random_uuid()::text")
		if typ == "azure_key_vault" {
			if _, err := tx.Exec(ctx, insertVaultCredential, cred, "azure_sp_secret", id); err != nil {
				return err
			}
		} else if err := d.App.QueryRow(ctx, "SELECT credential_id::text FROM targets WHERE id = $1", seed).Scan(&cred); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, discovery_interval_seconds, created_at, updated_at)
VALUES ($1, gen_random_uuid()::text, $2, $3::jsonb, $4, $5, $6, now(), now())`, id, typ, cfg, cred, status, interval); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	good := func(host string) string {
		return fmt.Sprintf(`{"vault_url": "https://%s", "host": "%s", "port": 443}`, host, host)
	}
	for name, cfg := range map[string]string{
		"suffix host":            good("kv2.vault.azure.net.evil.test"),
		"port 8443":              `{"vault_url": "https://kv2.vault.azure.net", "host": "kv2.vault.azure.net", "port": 8443}`,
		"port as string":         `{"vault_url": "https://kv2.vault.azure.net", "host": "kv2.vault.azure.net", "port": "443"}`,
		"url with the port":      `{"vault_url": "https://kv2.vault.azure.net:443", "host": "kv2.vault.azure.net", "port": 443}`,
		"http url":               `{"vault_url": "http://kv2.vault.azure.net", "host": "kv2.vault.azure.net", "port": 443}`,
		"url of another vault":   `{"vault_url": "https://kv3.vault.azure.net", "host": "kv2.vault.azure.net", "port": 443}`,
		"url with a path":        `{"vault_url": "https://kv2.vault.azure.net/", "host": "kv2.vault.azure.net", "port": 443}`,
		"missing host":           `{"vault_url": "https://kv2.vault.azure.net", "port": 443}`,
		"missing url":            `{"host": "kv2.vault.azure.net", "port": 443}`,
		"missing port":           `{"vault_url": "https://kv2.vault.azure.net", "host": "kv2.vault.azure.net"}`,
		"upper case host":        good("KV2.vault.azure.net"),
		"two characters":         good("k2.vault.azure.net"),
		"leading digit":          good("2kv.vault.azure.net"),
		"trailing hyphen":        good("kv2-.vault.azure.net"),
		"double hyphen":          good("kv--2.vault.azure.net"),
		"25 characters":          good(strings.Repeat("a", 25) + ".vault.azure.net"),
		"other cloud":            good("kv2.vault.usgovcloudapi.net"),
		"host of another domain": good("kv2.example.com"),
		"old placeholder shape":  `{"vault": "v"}`,
	} {
		assert.Equal(t, "23514", sqlState(ins("azure_key_vault", cfg, 900, "ok")), name)
	}
	require.NoError(t, ins("azure_key_vault", good(strings.Repeat("a", 24)+".vault.azure.net"), 900, "ok"), "24 characters is the longest vault name")
	require.NoError(t, ins("azure_key_vault", good("kv3.vault.azure.net"), 300, "degraded"))
	require.NoError(t, ins("azure_key_vault", good("kv4.vault.azure.net"), 86400, "degraded"))
	assert.Equal(t, "23514", sqlState(ins("azure_key_vault", good("kv5.vault.azure.net"), 299, "ok")), "vault interval below 5 minutes")
	assert.Equal(t, "23514", sqlState(ins("azure_key_vault", good("kv5.vault.azure.net"), 86401, "ok")), "vault interval above 24 hours")
	assert.Equal(t, "23514", sqlState(ins("azure_key_vault", good("kv5.vault.azure.net"), 900, "unknown")), "status stays a closed list")
	assert.Equal(t, "23505", sqlState(ins("azure_key_vault", good("kv1.vault.azure.net"), 900, "ok")), "one live vault per address (targets_endpoint_live)")

	linux := func(host string, interval int, status string) error {
		return exec(t, d.App, `INSERT INTO targets (id, name, type, config, credential_id, status, discovery_interval_seconds, created_at, updated_at)
SELECT gen_random_uuid(), gen_random_uuid()::text, 'linux', jsonb_build_object('host', $1::text, 'port', 22), credential_id, $3, $2, now(), now() FROM targets WHERE id = $4`, host, interval, status, seed)
	}
	assert.Equal(t, "23514", sqlState(linux("a.example.com", 1800, "ok")), "servers keep the hour minimum")
	assert.Equal(t, "23514", sqlState(linux("a.example.com", 2592001, "ok")))
	require.NoError(t, linux("b.example.com", 3600, "ok"))
	require.NoError(t, linux("c.example.com", 2592000, "degraded"), "degraded is a status of both kinds")

	require.NoError(t, exec(t, d.App, "UPDATE targets SET poll_failures = 3 WHERE id = $1", v.target))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE targets SET poll_failures = -1 WHERE id = $1", v.target)))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE targets SET poll_failures = 1000001 WHERE id = $1", v.target)))
	require.NoError(t, exec(t, d.App, "UPDATE targets SET deleted_at = now() WHERE id = $1", v.target), "a vault is soft-deleted like a server")
	addVault(t, d, "kv1") // and frees its address
}

// S6(e): the application may move a vault's credential (a replacement is a new credential row),
// but not the credential of any other kind of target; the owner role keeps what it could do.
func TestCredentialReplacementIsNarrowedToVaults(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	v := addVault(t, d, "kv1")
	server := seedTarget(t, d, "web-01", "web-01.example.com")
	var platform string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT credential_id::text FROM targets WHERE id = $1", server).Scan(&platform))

	// A replacement credential for the vault, inserted in the same transaction as the move.
	next := scanID(t, d, "SELECT gen_random_uuid()::text")
	tx, err := d.App.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, insertVaultCredential, next, "azure_sp_cert", v.target)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "UPDATE targets SET credential_id = $2 WHERE id = $1", v.target, next)
	require.NoError(t, err, "the application replaces a vault's credential")
	require.NoError(t, tx.Commit(ctx))

	// Not a server's.
	assert.Equal(t, "Z1005", sqlState(exec(t, d.App, "UPDATE targets SET credential_id = $2 WHERE id = $1", server, platform)), "any statement that sets a server's credential is refused")
	assert.Equal(t, "Z1005", sqlState(exec(t, d.App, "UPDATE targets SET credential_id = $2 WHERE id = $1", server, v.credential)), "a server cannot be pointed at a vault credential")
	var after string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT credential_id::text FROM targets WHERE id = $1", server).Scan(&after))
	assert.Equal(t, platform, after, "the refused change left the server alone")

	// Only a credential that belongs to that vault.
	second := addVault(t, d, "kv2")
	assert.Equal(t, "Z1006", sqlState(exec(t, d.App, "UPDATE targets SET credential_id = $2 WHERE id = $1", v.target, second.credential)), "another vault's credential")
	assert.Equal(t, "Z1006", sqlState(exec(t, d.Owner, "UPDATE targets SET credential_id = $2 WHERE id = $1", v.target, platform)), "a platform key is never a vault's credential, whoever asks")

	// The owner role is not narrowed beyond that: it can still rewrite a server's credential.
	require.NoError(t, exec(t, d.Owner, "UPDATE targets SET credential_id = credential_id WHERE id = $1", server))
	assert.Equal(t, "42501", sqlState(exec(t, d.App, "UPDATE targets SET config = '{}' WHERE id = $1", v.target)), "no other target column opens up")
	assert.Equal(t, "42501", sqlState(exec(t, d.App, "UPDATE targets SET type = 'linux' WHERE id = $1", v.target)))

	// A new vault target must name a credential of its own; a server one that is a vault's is refused.
	tx, err = d.App.Begin(ctx)
	require.NoError(t, err)
	id := scanID(t, d, "SELECT gen_random_uuid()::text")
	_, err = tx.Exec(ctx, insertVaultTarget, id, "vault kv9", "https://"+vaultConfigHost("kv9"), vaultConfigHost("kv9"), platform)
	assert.Equal(t, "Z1006", sqlState(err), "a vault created with the platform key")
	_ = tx.Rollback(ctx)
	assert.Equal(t, "Z1006", sqlState(exec(t, d.App, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES (gen_random_uuid(), 'web-09', 'linux', '{"host": "web-09.example.com", "port": 22}', $1, 'ok', now(), now())`, v.credential)), "a server created with a vault credential")
}

// The trigger runs as the invoking role: the application can create temporary tables, which must
// not shadow credentials.
func TestCredentialTriggerIgnoresShadowingTempTables(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	v := addVault(t, d, "kv1")
	second := addVault(t, d, "kv2")
	conn, err := d.App.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	defer func() { _, _ = conn.Exec(ctx, "DROP TABLE IF EXISTS pg_temp.credentials") }()
	_, err = conn.Exec(ctx, "CREATE TEMP TABLE credentials (id uuid, purpose text, target_id uuid)")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "INSERT INTO pg_temp.credentials SELECT $1::uuid, 'azure_vault', $2::uuid", second.credential, v.target)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "UPDATE targets SET credential_id = $2 WHERE id = $1", v.target, second.credential)
	assert.Equal(t, "Z1006", sqlState(err), "the temporary table must not vouch for another vault's credential")
}

func TestKeyVaultNamesAreCaseInsensitive(t *testing.T) {
	d := pgtest.New(t)
	v := addVault(t, d, "kv1")
	w := addVault(t, d, "kv2")
	insert := func(table, vault, name string) error {
		switch table {
		case "kv_certificates":
			return exec(t, d.App, `INSERT INTO kv_certificates (id, target_id, name, listed_thumbprint, enabled, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, $2, repeat('a', 40), true, now(), now())`, vault, name)
		case "kv_keys":
			return exec(t, d.App, `INSERT INTO kv_keys (id, target_id, name, enabled, first_seen_at, last_seen_at) VALUES (gen_random_uuid(), $1, $2, true, now(), now())`, vault, name)
		default:
			return exec(t, d.App, `INSERT INTO kv_secrets (id, target_id, name, enabled, first_seen_at, last_seen_at) VALUES (gen_random_uuid(), $1, $2, true, now(), now())`, vault, name)
		}
	}
	for _, table := range []string{"kv_certificates", "kv_keys", "kv_secrets"} {
		require.NoError(t, insert(table, v.target, "Web-Cert"), table)
		assert.Equal(t, "23505", sqlState(insert(table, v.target, "web-cert")), table+": names compare case-insensitively")
		assert.Equal(t, "23505", sqlState(insert(table, v.target, "WEB-CERT")), table)
		require.NoError(t, insert(table, w.target, "web-cert"), table+": another vault has its own names")
		require.NoError(t, insert(table, v.target, "web-cert2"), table)
		for _, bad := range []string{"web_cert", "", "web.cert", "web cert", strings.Repeat("a", 128)} {
			assert.Equal(t, "23514", sqlState(insert(table, v.target, bad)), "%s name %q", table, bad)
		}
	}
	// The exact upsert key the application writes: ON CONFLICT (target_id, lower(name COLLATE "C")).
	require.NoError(t, exec(t, d.App, `INSERT INTO kv_certificates (id, target_id, name, listed_thumbprint, enabled, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, 'WEB-CERT', repeat('d', 40), false, now(), now())
ON CONFLICT (target_id, lower(name COLLATE "C")) DO UPDATE SET enabled = EXCLUDED.enabled, listed_thumbprint = EXCLUDED.listed_thumbprint`, v.target))
}

func TestKeyVaultInventoryChecks(t *testing.T) {
	d := pgtest.New(t)
	v := addVault(t, d, "kv1")
	cert := insertKVCertificate(t, d, v.target, "web-cert")

	// kv_certificates: closed vocabularies and shapes.
	upd := func(set string, args ...any) string {
		return sqlState(exec(t, d.App, "UPDATE kv_certificates SET "+set+" WHERE id = '"+cert+"'", args...))
	}
	assert.Equal(t, "", upd("current_version = ''"))
	assert.Equal(t, "", upd("current_version = repeat('a', 32), current_thumbprint = repeat('b', 40)"))
	assert.Equal(t, "23514", upd("current_version = 'ABC'"))
	assert.Equal(t, "23514", upd("current_version = repeat('A', 32)"))
	assert.Equal(t, "23514", upd("current_thumbprint = repeat('B', 40)"))
	assert.Equal(t, "23514", upd("current_thumbprint = repeat('b', 39)"))
	assert.Equal(t, "23514", upd("listed_thumbprint = ''"))
	assert.Equal(t, "23514", upd("key_type = 'dsa'"))
	assert.Equal(t, "", upd("key_type = 'ecdsa'"))
	assert.Equal(t, "23514", upd("content_type = 'jks'"))
	assert.Equal(t, "", upd("content_type = 'pem'"))
	assert.Equal(t, "23514", upd("key_size = 16385"))
	assert.Equal(t, "23514", upd("issuer_name = repeat('x', 128)"))

	// kv_certificate_versions.
	ver := strings.Repeat("a", 32)
	insertKVVersion(t, d, cert, ver)
	_, err := d.App.Exec(context.Background(), insertVersionSQL, cert, ver, strings.Repeat("c", 40))
	assert.Equal(t, "23505", sqlState(err), "one row per certificate and version")
	for _, bad := range [][2]string{{strings.Repeat("A", 32), strings.Repeat("c", 40)}, {strings.Repeat("a", 31), strings.Repeat("c", 40)}, {strings.Repeat("e", 32), strings.Repeat("C", 40)}, {strings.Repeat("e", 32), strings.Repeat("c", 41)}, {"", strings.Repeat("c", 40)}} {
		_, err := d.App.Exec(context.Background(), insertVersionSQL, cert, bad[0], bad[1])
		assert.Equal(t, "23514", sqlState(err), "%q %q", bad[0], bad[1])
	}
	other := insertKVCertificate(t, d, v.target, "other-cert")
	_, err = d.App.Exec(context.Background(), insertVersionSQL, other, ver, strings.Repeat("c", 40))
	assert.NoError(t, err, "the same version id under another certificate")

	// keys and secrets: closed vocabularies.
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO kv_keys (id, target_id, name, key_type, enabled, first_seen_at, last_seen_at) VALUES (gen_random_uuid(), $1, 'k1', 'dsa', true, now(), now())`, v.target)))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO kv_keys (id, target_id, name, curve, enabled, first_seen_at, last_seen_at) VALUES (gen_random_uuid(), $1, 'k2', 'P-999', true, now(), now())`, v.target)))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO kv_keys (id, target_id, name, details_problem, enabled, first_seen_at, last_seen_at) VALUES (gen_random_uuid(), $1, 'k3', 'broken', true, now(), now())`, v.target)))
	require.NoError(t, exec(t, d.App, `INSERT INTO kv_keys (id, target_id, name, key_type, curve, details_problem, enabled, first_seen_at, last_seen_at) VALUES (gen_random_uuid(), $1, 'k4', 'ec', 'P-384', 'forbidden', true, now(), now())`, v.target))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO kv_secrets (id, target_id, name, content_type, enabled, first_seen_at, last_seen_at) VALUES (gen_random_uuid(), $1, 's1', repeat('x', 256), true, now(), now())`, v.target)))

	// bindings: kv_target_id is the vault of the certificate (composite foreign key).
	w := addVault(t, d, "kv2")
	server := seedTarget(t, d, "web-01", "web-01.example.com")
	assert.Equal(t, "23503", sqlState(insertBinding(t, d, cert, w.target)), "a binding naming another vault than its certificate's")
	assert.Equal(t, "23503", sqlState(insertBinding(t, d, cert, server)), "a binding naming a server")

	// bindings: one live binding per vault certificate; automatic deployment needs its start time.
	require.NoError(t, insertBinding(t, d, cert, v.target))
	assert.Equal(t, "23505", sqlState(insertBinding(t, d, cert, v.target)), "two live bindings of one vault certificate")
	require.NoError(t, exec(t, d.App, "UPDATE bindings SET deleted_at = now() WHERE kv_certificate_id = $1", cert))
	require.NoError(t, insertBinding(t, d, cert, v.target), "a second one after the first was deleted")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE bindings SET auto_deploy = true WHERE kv_certificate_id = $1 AND deleted_at IS NULL", cert)), "auto_deploy without auto_since")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE bindings SET auto_since = now() WHERE kv_certificate_id = $1 AND deleted_at IS NULL", cert)), "auto_since without auto_deploy")
	require.NoError(t, exec(t, d.App, "UPDATE bindings SET auto_deploy = true, auto_since = now() WHERE kv_certificate_id = $1 AND deleted_at IS NULL", cert))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE bindings SET stopped_version = 'XYZ' WHERE kv_certificate_id = $1 AND deleted_at IS NULL", cert)))
	require.NoError(t, exec(t, d.App, "UPDATE bindings SET stopped_version = $2, version = version + 1 WHERE kv_certificate_id = $1 AND deleted_at IS NULL", cert, ver))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE bindings SET version = 0 WHERE kv_certificate_id = $1 AND deleted_at IS NULL", cert)))
}

func TestKeyVaultDeploymentSource(t *testing.T) {
	d := pgtest.New(t)
	v := addVault(t, d, "kv1")
	server := seedTarget(t, d, "web-01", "web-01.example.com")
	loc := insertLocation(t, d, server)
	leaf := insertCertificate(t, d)
	cert := insertKVCertificate(t, d, v.target, "web-cert")
	version := insertKVVersion(t, d, cert, strings.Repeat("a", 32))
	require.NoError(t, insertBinding(t, d, cert, v.target))
	binding := scanID(t, d, "SELECT id::text FROM bindings WHERE kv_certificate_id = $1", cert)

	require.NoError(t, exec(t, d.App, "UPDATE certificate_locations SET binding_id = $2 WHERE id = $1", loc, binding), "a location joins a binding")
	assert.Equal(t, "23503", sqlState(exec(t, d.App, "UPDATE certificate_locations SET binding_id = gen_random_uuid() WHERE id = $1", loc)))

	ins := func(trigger string, binding, version any) error {
		return exec(t, d.App, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint, cert_path, key_path, created_at, binding_id, kv_version_id)
VALUES (gen_random_uuid(), $1, $2, $3, $4, 'queued', 'pending', repeat('e', 64), '/etc/ssl/a.pem', '/etc/ssl/a.key', now(), $5, $6)`, leaf, loc, server, trigger, binding, version)
	}
	assert.Equal(t, "23514", sqlState(ins("manual", binding, nil)), "a binding without a vault version")
	assert.Equal(t, "23514", sqlState(ins("manual", nil, version)), "a vault version without a binding")
	assert.Equal(t, "23503", sqlState(ins("manual", binding, "00000000-0000-0000-0000-000000000000")))
	require.NoError(t, ins("kv_renewal", binding, version))
	require.NoError(t, exec(t, d.App, "UPDATE deployments SET state = 'done', status = 'succeeded', finished_at = now() WHERE binding_id = $1", binding))
	require.NoError(t, ins("manual", nil, nil), "a Phase 4 deployment keeps working")
}

func TestKeyVaultImportChecks(t *testing.T) {
	d := pgtest.New(t)
	v := addVault(t, d, "kv1")
	leaf := insertCertificate(t, d)
	thumb := strings.Repeat("f", 40)
	// insert writes an import row; cols and vals add columns (with $6.. as their bind parameters).
	insert := func(name, state, cols, vals string, args ...any) error {
		sql := `INSERT INTO kv_imports (id, certificate_id, target_id, name, new_version, state, thumbprint, created_at` + cols + `)
VALUES (gen_random_uuid(), $1, $2, $3, false, $4, $5, now()` + vals + `)`
		return exec(t, d.App, sql, append([]any{leaf, v.target, name, state, thumb}, args...)...)
	}
	require.NoError(t, insert("web-cert", "queued", "", ""))
	assert.Equal(t, "23505", sqlState(insert("web-cert", "queued", "", "")), "two queued imports of one vault and name")
	assert.Equal(t, "23505", sqlState(insert("WEB-cert", "queued", "", "")), "names compare case-insensitively")
	assert.Equal(t, "23505", sqlState(insert("Web-Cert", "running", ", sent_at", ", now()")), "a running one blocks too")
	require.NoError(t, exec(t, d.App, "UPDATE kv_imports SET state = 'uncertain', sent_at = now() WHERE lower(name) = 'web-cert'"))
	assert.Equal(t, "23505", sqlState(insert("web-cert", "queued", "", "")), "an uncertain import blocks the name")
	require.NoError(t, insert("other-cert", "queued", "", ""), "another name")
	require.NoError(t, exec(t, d.App, "UPDATE kv_imports SET state = 'failed', finished_at = now(), error_code = 'azure.forbidden' WHERE lower(name) = 'web-cert'"))
	require.NoError(t, insert("web-cert", "queued", "", ""), "a finished import frees the name")
	require.NoError(t, insert("web-cert", "failed", ", finished_at", ", now()"), "any number of finished ones")

	assert.Equal(t, "23514", sqlState(insert("x_y", "queued", "", "")), "name shape")
	assert.Equal(t, "23514", sqlState(insert("n1", "paused", "", "")), "state is a closed list")
	assert.Equal(t, "23514", sqlState(insert("n2", "queued", ", version", ", $6", strings.Repeat("A", 32))), "version shape")
	assert.Equal(t, "23514", sqlState(insert("n3", "succeeded", ", finished_at, sent_at", ", now(), now()")), "succeeded without a version")
	assert.Equal(t, "23514", sqlState(insert("n4", "succeeded", ", version, sent_at", ", $6, now()", strings.Repeat("a", 32))), "succeeded without finished_at")
	assert.Equal(t, "23514", sqlState(insert("n5", "failed", "", "")), "failed without finished_at")
	assert.Equal(t, "23514", sqlState(insert("n6", "queued", ", finished_at", ", now()")), "queued with finished_at")
	assert.Equal(t, "23514", sqlState(insert("n7", "running", "", "")), "running without sent_at: an import that reached the vault was sent")
	assert.Equal(t, "23514", sqlState(insert("n8", "uncertain", "", "")), "uncertain without sent_at")
	assert.Equal(t, "23514", sqlState(insert("n9", "queued", ", sent_at", ", now()")), "queued with sent_at")
	require.NoError(t, insert("n10", "succeeded", ", version, finished_at, sent_at", ", $6, now(), now()", strings.Repeat("a", 32)))

	var bad = []string{"error_code = 'a b'", "error_params = '[]'", "error_params = '\"x\"'"}
	for _, set := range bad {
		assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE kv_imports SET "+set+" WHERE name = 'other-cert'")), set)
	}
	assert.Equal(t, "42501", sqlState(exec(t, d.App, "UPDATE kv_imports SET thumbprint = repeat('a', 40)")), "the thumbprint a poll recognises an import by is fixed")
}

func TestHeldVersionsAndNotificationColumns(t *testing.T) {
	d := pgtest.New(t)
	v := addVault(t, d, "kv1")
	cert := insertKVCertificate(t, d, v.target, "web-cert")
	version := insertKVVersion(t, d, cert, strings.Repeat("a", 32))
	set := func(s string) string {
		return sqlState(exec(t, d.App, "UPDATE kv_certificate_versions SET "+s+" WHERE id = $1", version))
	}
	assert.Equal(t, "", set("held = true, held_reason = 'license'"))
	assert.Equal(t, "", set("held = true, held_reason = 'incomplete_chain'"))
	assert.Equal(t, "23514", set("held = true, held_reason = 'whim'"), "reason is a closed list")
	assert.Equal(t, "23514", set("held = true, held_reason = ''"), "a held version says why")
	assert.Equal(t, "23514", set("held = false, held_reason = 'license'"), "a reason without a hold")
	assert.Equal(t, "", set("held = false, held_reason = ''"))
	assert.Equal(t, "", set("notified_at = now(), skipped_notified_at = now()"), "the new-version and the skipped email are separate marks (D25)")
	assert.Equal(t, "42501", set("thumbprint = repeat('a', 40)"))
	assert.Equal(t, "42501", set("detected_at = now()"))
	assert.Equal(t, "42501", set("kv_certificate_id = kv_certificate_id"))
	assert.Equal(t, "42501", set("version = repeat('b', 32)"))
}

func TestAppRoleCannotRewriteKeyVaultHistory(t *testing.T) {
	d := pgtest.New(t)
	v := addVault(t, d, "kv1")
	server := seedTarget(t, d, "web-01", "web-01.example.com")
	loc := insertLocation(t, d, server)
	leaf := insertCertificate(t, d)
	cert := insertKVCertificate(t, d, v.target, "web-cert")
	version := insertKVVersion(t, d, cert, strings.Repeat("a", 32))
	require.NoError(t, insertBinding(t, d, cert, v.target))
	require.NoError(t, exec(t, d.App, `INSERT INTO kv_keys (id, target_id, name, enabled, first_seen_at, last_seen_at) VALUES (gen_random_uuid(), $1, 'k', true, now(), now())`, v.target))
	require.NoError(t, exec(t, d.App, `INSERT INTO kv_secrets (id, target_id, name, enabled, first_seen_at, last_seen_at) VALUES (gen_random_uuid(), $1, 's', true, now(), now())`, v.target))
	require.NoError(t, exec(t, d.App, `INSERT INTO kv_imports (id, certificate_id, target_id, name, new_version, state, thumbprint, created_at)
VALUES (gen_random_uuid(), $1, $2, 'web-cert', false, 'queued', repeat('f', 40), now())`, leaf, v.target))
	require.NoError(t, exec(t, d.App, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint, cert_path, key_path, created_at, binding_id, kv_version_id)
SELECT gen_random_uuid(), $1, $2, $3, 'manual', 'queued', 'pending', repeat('e', 64), '/etc/ssl/a.pem', '/etc/ssl/a.key', now(), b.id, $4 FROM bindings b`, leaf, loc, server, version))

	for _, stmt := range []string{
		"UPDATE kv_certificates SET name = 'x'",
		"UPDATE kv_certificates SET target_id = target_id",
		"UPDATE kv_certificates SET first_seen_at = now()",
		"UPDATE kv_certificate_versions SET thumbprint = repeat('a', 40)",
		"UPDATE kv_certificate_versions SET version = repeat('a', 32)",
		"UPDATE kv_certificate_versions SET kv_created_at = now()",
		"UPDATE kv_keys SET name = 'x'",
		"UPDATE kv_keys SET target_id = target_id",
		"UPDATE kv_secrets SET name = 'x'",
		"UPDATE kv_secrets SET target_id = target_id",
		"UPDATE bindings SET kv_certificate_id = kv_certificate_id",
		"UPDATE bindings SET kv_target_id = kv_target_id",
		"UPDATE bindings SET created_at = now()",
		"UPDATE deployments SET binding_id = NULL",
		"UPDATE deployments SET kv_version_id = NULL",
		"UPDATE credentials SET target_id = NULL",
		"UPDATE credentials SET ciphertext = '\\x03'",
		"UPDATE kv_imports SET certificate_id = certificate_id",
		"UPDATE kv_imports SET target_id = target_id",
		"UPDATE kv_imports SET name = 'x'",
		"UPDATE kv_imports SET new_version = true",
		"UPDATE kv_imports SET thumbprint = repeat('a', 40)",
		"UPDATE kv_imports SET created_at = now()",
		"DELETE FROM kv_certificates",
		"DELETE FROM kv_certificate_versions",
		"DELETE FROM kv_keys",
		"DELETE FROM kv_secrets",
		"DELETE FROM bindings",
		"DELETE FROM kv_imports",
		"TRUNCATE kv_certificates CASCADE",
		"UPDATE targets SET poll_failures = 0, type = type",
	} {
		assert.Equal(t, "42501", sqlState(exec(t, d.App, stmt)), "%s must be refused for alice_app", stmt)
	}
	// What the services write stays possible.
	for _, stmt := range []string{
		"UPDATE kv_certificates SET enabled = false, last_seen_at = now(), missing_since = now(), details_pending = true",
		"UPDATE kv_certificate_versions SET held = false, notified_at = now()",
		"UPDATE kv_keys SET last_seen_at = now(), missing_since = now(), hsm = true",
		"UPDATE kv_secrets SET last_seen_at = now(), missing_since = now()",
		"UPDATE bindings SET auto_deploy = false, deleted_at = now()",
		"UPDATE kv_imports SET state = 'failed', finished_at = now(), error_code = 'x'",
		"UPDATE targets SET poll_failures = 2",
	} {
		require.NoError(t, exec(t, d.App, stmt), stmt)
	}
}

// No new column can hold a client secret, a private key, a token, a PFX or a vault secret's value:
// credentials stay in the Phase 3 envelope and the vault inventory holds metadata only.
func TestNoKeyVaultColumnCanHoldSecretMaterial(t *testing.T) {
	d := pgtest.New(t)
	rows, err := d.Owner.Query(context.Background(), `
SELECT table_name, column_name, data_type FROM information_schema.columns
WHERE table_schema = 'public' AND table_name IN ('kv_certificates', 'kv_certificate_versions', 'kv_keys', 'kv_secrets', 'bindings', 'kv_imports')
ORDER BY 1, 2`)
	require.NoError(t, err)
	defer rows.Close()
	words := regexp.MustCompile(`(^|_)(secret|password|passphrase|private|token|pfx|pkcs12|pem|value|ciphertext|payload|body|blob)(_|$)`)
	for rows.Next() {
		var table, col, typ string
		require.NoError(t, rows.Scan(&table, &col, &typ))
		assert.False(t, words.MatchString(col), "%s.%s", table, col)
		assert.NotEqual(t, "bytea", typ, "%s.%s: no binary column", table, col)
	}
	require.NoError(t, rows.Err())
}

// Vault inventory tables and the new columns that point at them, listed so a later change to
// the schema is noticed here as well as in the grant guard.
func TestKeyVaultSchemaHasTheColumnsTheServicesNeed(t *testing.T) {
	d := pgtest.New(t)
	rows, err := d.Owner.Query(context.Background(), `
SELECT table_name || '.' || column_name || ':' || data_type || ':' || is_nullable FROM information_schema.columns
WHERE table_schema = 'public' AND (
  table_name IN ('kv_certificates', 'kv_certificate_versions', 'kv_keys', 'kv_secrets', 'bindings', 'kv_imports')
  OR (table_name = 'targets' AND column_name = 'poll_failures')
  OR (table_name = 'credentials' AND column_name = 'target_id')
  OR (table_name = 'certificate_locations' AND column_name = 'binding_id')
  OR (table_name = 'deployments' AND column_name IN ('binding_id', 'kv_version_id')))`)
	require.NoError(t, err)
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		have[s] = true
	}
	require.NoError(t, rows.Err())
	want := []string{
		"targets.poll_failures:integer:NO", "credentials.target_id:uuid:YES", "certificate_locations.binding_id:uuid:YES",
		"deployments.binding_id:uuid:YES", "deployments.kv_version_id:uuid:YES",
		"kv_certificates.id:uuid:NO", "kv_certificates.target_id:uuid:NO", "kv_certificates.name:text:NO", "kv_certificates.current_version:text:NO",
		"kv_certificates.current_thumbprint:text:NO", "kv_certificates.kv_updated_at:timestamp with time zone:YES",
		"kv_certificates.listed_thumbprint:text:NO", "kv_certificates.listed_updated_at:timestamp with time zone:YES",
		"kv_certificates.enabled:boolean:NO", "kv_certificates.not_before:timestamp with time zone:YES", "kv_certificates.expires:timestamp with time zone:YES",
		"kv_certificates.kv_created_at:timestamp with time zone:YES", "kv_certificates.exportable:boolean:YES", "kv_certificates.key_type:text:NO",
		"kv_certificates.key_size:integer:NO", "kv_certificates.content_type:text:NO", "kv_certificates.issuer_name:text:NO",
		"kv_certificates.auto_renew:boolean:NO", "kv_certificates.details_pending:boolean:NO", "kv_certificates.first_seen_at:timestamp with time zone:NO",
		"kv_certificates.last_seen_at:timestamp with time zone:NO", "kv_certificates.missing_since:timestamp with time zone:YES",
		"kv_certificates.removed_notified_at:timestamp with time zone:YES",
		"kv_certificate_versions.id:uuid:NO", "kv_certificate_versions.kv_certificate_id:uuid:NO", "kv_certificate_versions.version:text:NO",
		"kv_certificate_versions.thumbprint:text:NO", "kv_certificate_versions.certificate_id:uuid:YES", "kv_certificate_versions.enabled:boolean:NO",
		"kv_certificate_versions.not_before:timestamp with time zone:YES", "kv_certificate_versions.expires:timestamp with time zone:YES",
		"kv_certificate_versions.kv_created_at:timestamp with time zone:YES", "kv_certificate_versions.exportable:boolean:YES",
		"kv_certificate_versions.key_type:text:NO", "kv_certificate_versions.content_type:text:NO",
		"kv_certificate_versions.detected_at:timestamp with time zone:NO", "kv_certificate_versions.held:boolean:NO",
		"kv_certificate_versions.held_reason:text:NO", "kv_certificate_versions.notified_at:timestamp with time zone:YES",
		"kv_certificate_versions.skipped_notified_at:timestamp with time zone:YES",
		"kv_keys.id:uuid:NO", "kv_keys.target_id:uuid:NO", "kv_keys.name:text:NO", "kv_keys.version:text:NO", "kv_keys.key_type:text:NO",
		"kv_keys.hsm:boolean:NO", "kv_keys.key_size:integer:NO", "kv_keys.curve:text:NO", "kv_keys.details_updated_at:timestamp with time zone:YES",
		"kv_keys.details_problem:text:NO", "kv_keys.enabled:boolean:NO", "kv_keys.managed:boolean:NO",
		"kv_keys.first_seen_at:timestamp with time zone:NO", "kv_keys.last_seen_at:timestamp with time zone:NO", "kv_keys.missing_since:timestamp with time zone:YES",
		"kv_secrets.id:uuid:NO", "kv_secrets.target_id:uuid:NO", "kv_secrets.name:text:NO", "kv_secrets.content_type:text:NO",
		"kv_secrets.enabled:boolean:NO", "kv_secrets.managed:boolean:NO", "kv_secrets.last_seen_at:timestamp with time zone:NO",
		"bindings.id:uuid:NO", "bindings.kv_certificate_id:uuid:NO", "bindings.kv_target_id:uuid:NO", "bindings.auto_deploy:boolean:NO",
		"bindings.auto_since:timestamp with time zone:YES", "bindings.stopped_version:text:NO", "bindings.created_by:uuid:YES",
		"bindings.created_at:timestamp with time zone:NO", "bindings.deleted_at:timestamp with time zone:YES", "bindings.version:integer:NO",
		"kv_imports.id:uuid:NO", "kv_imports.certificate_id:uuid:NO", "kv_imports.target_id:uuid:NO", "kv_imports.name:text:NO",
		"kv_imports.new_version:boolean:NO", "kv_imports.state:text:NO", "kv_imports.thumbprint:text:NO", "kv_imports.version:text:NO",
		"kv_imports.error_code:text:NO", "kv_imports.error_params:jsonb:NO", "kv_imports.job_id:uuid:YES", "kv_imports.requested_by:uuid:YES",
		"kv_imports.created_at:timestamp with time zone:NO", "kv_imports.sent_at:timestamp with time zone:YES", "kv_imports.finished_at:timestamp with time zone:YES",
	}
	var missing []string
	for _, w := range want {
		if !have[w] {
			missing = append(missing, w)
		}
	}
	sort.Strings(missing)
	assert.Empty(t, missing)
}

// Migration 00008 goes up over a database that holds Phase 3 and Phase 4 data, goes down to 00007
// with that data intact (which restores the previous schema exactly) and goes up again. A Down over
// a database that holds a vault is refused whole: nothing is half-dropped.
func TestMigration00008UpAndDownKeepEarlierData(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)

	_, err = p.DownTo(ctx, 7)
	require.NoError(t, err)
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(7), version)
	for _, tbl := range phase5Tables {
		assert.False(t, tableExists(t, d, tbl), tbl)
	}
	// The guard describes the current schema, so below 00008 it reports the two tables whose
	// column-level grants lost the Phase 5 columns (and nothing else: no kv_* or bindings grant remains).
	assert.ElementsMatch(t, []string{"public.targets", "public.certificate_locations", "public.ssh_keys", "public.managed_private_keys"}, grantProblems(t, d),
		"no Phase 5 grant is left behind (and, below 00010, the guard also lists the two tables whose Phase 6 column grants are gone)")
	var fn bool
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'targets_check_credential')").Scan(&fn))
	assert.False(t, fn, "the Down drops the trigger function")
	// Previous schema: the three constraints are back to their 00005 shapes.
	assert.Equal(t, "23514", sqlState(exec(t, d.Owner, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES (gen_random_uuid(), 'azure_vault', 'azure_sp_secret', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`)))
	assert.Equal(t, "23514", sqlState(exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
SELECT gen_random_uuid(), 'deg', 'linux', '{"host": "deg.example.com", "port": 22}', credential_id, 'degraded', now(), now() FROM (SELECT gen_random_uuid() AS credential_id) x`)), "degraded is not a status below 00008")
	var cols int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND
((table_name = 'targets' AND column_name = 'poll_failures') OR (table_name = 'credentials' AND column_name = 'target_id')
 OR (table_name = 'certificate_locations' AND column_name = 'binding_id') OR (table_name = 'deployments' AND column_name IN ('binding_id', 'kv_version_id')))`).Scan(&cols))
	assert.Equal(t, 0, cols)

	// Phase 3 and Phase 4 data.
	server := seedTarget(t, d, "web-01", "web-01.example.com")
	loc := insertLocation(t, d, server)
	leaf := insertCertificate(t, d)
	require.NoError(t, exec(t, d.App, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint, cert_path, key_path, created_at)
VALUES (gen_random_uuid(), $1, $2, $3, 'manual', 'queued', 'pending', repeat('e', 64), '/etc/ssl/a.pem', '/etc/ssl/a.key', now())`, leaf, loc, server))
	count := func() (n [5]int) {
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM targets), (SELECT count(*) FROM credentials), (SELECT count(*) FROM certificates),
(SELECT count(*) FROM certificate_locations), (SELECT count(*) FROM deployments)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]))
		return
	}
	want := [5]int{1, 1, 1, 1, 1}
	require.Equal(t, want, count())

	_, err = p.Up(ctx)
	require.NoError(t, err, "00008 applies over Phase 4 data")
	for _, tbl := range phase5Tables {
		assert.True(t, tableExists(t, d, tbl), tbl)
	}
	assert.Empty(t, grantProblems(t, d))
	assert.Equal(t, want, count(), "earlier data survives the Up")
	var n int
	require.NoError(t, d.App.QueryRow(ctx, "SELECT count(*) FROM deployments WHERE binding_id IS NULL AND kv_version_id IS NULL").Scan(&n))
	assert.Equal(t, 1, n, "an existing deployment is a Phase 4 one")

	_, err = p.DownTo(ctx, 7)
	require.NoError(t, err)
	assert.Equal(t, want, count(), "earlier data survives the Down")
	assert.Equal(t, "42501", sqlState(exec(t, d.App, "UPDATE targets SET credential_id = credential_id")),
		"the Down takes UPDATE (credential_id) back from the application")
	_, err = p.Up(ctx)
	require.NoError(t, err)

	// A vault makes the Down impossible, and the refusal changes nothing.
	addVault(t, d, "kv1")
	_, err = p.DownTo(ctx, 7)
	require.Error(t, err, "a Down over vault data is refused")
	assert.Equal(t, "Z1008", sqlState(err), "by the Down's own first statement, not by whichever restored CHECK fails first")
	assert.ErrorContains(t, err, "Key Vault data exists")
	version, err = p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(8), version)
	for _, tbl := range phase5Tables {
		assert.True(t, tableExists(t, d, tbl), tbl+" is still there after a refused Down")
	}
	assert.Equal(t, 1, scanInt(t, d, "SELECT count(*) FROM targets WHERE type = 'azure_key_vault'"))
	// goose runs each Down in its own transaction: 00009's went through before 00008's refused, so only the chain
	// column's grant is missing until the next Up.
	assert.ElementsMatch(t, []string{"public.kv_certificate_versions", "public.ssh_keys", "public.managed_private_keys"}, grantProblems(t, d))
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.Empty(t, grantProblems(t, d))
}

// Migration 00009 adds what a secret read found about a version's chain, with its column grant, and takes both
// away again over vault data (nothing else depends on it).
func TestMigration00009ChainIncomplete(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	column := func() int {
		return scanInt(t, d, `SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'kv_certificate_versions'
AND column_name = 'chain_incomplete'`)
	}
	require.Equal(t, 1, column())
	assert.Empty(t, grantProblems(t, d))
	v := addVault(t, d, "kv1")
	cert := insertKVCertificate(t, d, v.target, "web-cert")
	_, err = p.DownTo(ctx, 8)
	require.NoError(t, err, "00009 goes down over vault data")
	assert.Equal(t, 0, column())
	assert.ElementsMatch(t, []string{"public.kv_certificate_versions", "public.ssh_keys", "public.managed_private_keys"}, grantProblems(t, d), "only the chain column's grant is gone (and the two Phase 6 column grants, below 00010)")
	// Versions stored before the column existed: one held for its chain (a read found it incomplete), one held
	// for the license, one not held.
	chainHeld := insertKVVersion(t, d, cert, strings.Repeat("a", 32))
	licenseHeld := insertKVVersion(t, d, cert, strings.Repeat("b", 32))
	insertKVVersion(t, d, cert, strings.Repeat("c", 32))
	require.NoError(t, exec(t, d.App, "UPDATE kv_certificate_versions SET held = true, held_reason = 'incomplete_chain' WHERE id = $1", chainHeld))
	require.NoError(t, exec(t, d.App, "UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE id = $1", licenseHeld))
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, column())
	assert.Empty(t, grantProblems(t, d))
	var marked []string
	rows, err := d.Owner.Query(ctx, "SELECT id::text FROM kv_certificate_versions WHERE chain_incomplete")
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		marked = append(marked, id)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{chainHeld}, marked, "a version held for its chain is known incomplete; the others are unknown until a read")
}

var phase5Tables = []string{"kv_certificates", "kv_certificate_versions", "kv_keys", "kv_secrets", "bindings", "kv_imports"}

func scanInt(t *testing.T, d *pgtest.DB, sql string) int {
	t.Helper()
	var n int
	require.NoError(t, d.Owner.QueryRow(context.Background(), sql).Scan(&n))
	return n
}

// The Down refuses explicitly and for exactly two reasons: Key Vault data exists (a vault target,
// soft-deleted or not, or a vault credential), or a server has the status degraded (00008 added it
// and the restored check would refuse it). Both leave the schema at 00008; without them it goes down.
func TestMigration00008DownRefusals(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	refused := func(contains string) {
		t.Helper()
		_, err := p.DownTo(ctx, 7)
		require.Error(t, err)
		assert.Equal(t, "Z1008", sqlState(err), contains)
		assert.ErrorContains(t, err, contains)
		version, err := p.GetDBVersion(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(8), version)
		assert.True(t, tableExists(t, d, "kv_certificates"))
	}

	server := seedTarget(t, d, "web-01", "web-01.example.com")
	require.NoError(t, exec(t, d.App, "UPDATE targets SET status = 'degraded' WHERE id = $1", server))
	refused("degraded")
	require.NoError(t, exec(t, d.App, "UPDATE targets SET status = 'ok' WHERE id = $1", server))

	v := addVault(t, d, "kv1")
	require.NoError(t, exec(t, d.App, "UPDATE targets SET deleted_at = now() WHERE id = $1", v.target))
	refused("Key Vault data exists") // a soft-deleted vault is still vault data

	// No vault data and no degraded server: the Down goes through.
	d2 := pgtest.New(t)
	p2, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d2.Owner), migrations.FS)
	require.NoError(t, err)
	seedTarget(t, d2, "web-01", "web-01.example.com")
	_, err = p2.DownTo(ctx, 7)
	require.NoError(t, err, "no vault data and no degraded server: the Down goes through")
	assert.False(t, tableExists(t, d2, "kv_certificates"))
}

// Imports are history. A finished import (succeeded or failed) changes only in job_id going to NULL
// (a pruned job); sent_at, once set, never changes; state never returns to queued; an uncertain
// import is settled (succeeded, failed) or stays uncertain, it is not re-run. SQLSTATE Z1007.
func TestFinishedImportsAreFrozen(t *testing.T) {
	d := pgtest.New(t)
	v := addVault(t, d, "kv1")
	leaf := insertCertificate(t, d)
	n := 0
	newImport := func() string {
		n++
		return scanID(t, d, `INSERT INTO kv_imports (id, certificate_id, target_id, name, new_version, state, thumbprint, created_at)
VALUES (gen_random_uuid(), $1, $2, $3, false, 'queued', repeat('f', 40), now()) RETURNING id::text`, leaf, v.target, fmt.Sprintf("imp-%d", n))
	}
	up := func(id, set string, args ...any) string {
		return sqlState(exec(t, d.App, "UPDATE kv_imports SET "+set+" WHERE id = '"+id+"'", args...))
	}
	version := strings.Repeat("a", 32)
	sent := func(id string) { require.Equal(t, "", up(id, "state = 'running', sent_at = now()")) }

	// Legal paths.
	ok := newImport()
	require.Equal(t, "", up(ok, "job_id = NULL, error_code = 'x'"), "queued rows change freely")
	sent(ok)
	require.Equal(t, "", up(ok, "state = 'succeeded', version = $1, finished_at = now()", version), "running -> succeeded")
	refusedQueued := newImport()
	require.Equal(t, "", up(refusedQueued, "state = 'failed', finished_at = now(), error_code = 'azure.forbidden'"), "queued -> failed: refused before any send")
	lost := newImport()
	sent(lost)
	require.Equal(t, "", up(lost, "state = 'uncertain'"), "running -> uncertain")
	require.Equal(t, "", up(lost, "state = 'uncertain', error_code = 'azure.unreachable'"), "an uncertain import may be annotated")
	require.Equal(t, "", up(lost, "state = 'succeeded', version = $1, finished_at = now()", version), "uncertain -> succeeded (a poll saw it)")
	timeout := newImport()
	sent(timeout)
	require.Equal(t, "", up(timeout, "state = 'uncertain'"))
	require.Equal(t, "", up(timeout, "state = 'failed', finished_at = now(), error_code = 'kv.import_outcome_unknown'"), "uncertain -> failed (24 hours)")
	failedSent := newImport()
	sent(failedSent)
	require.Equal(t, "", up(failedSent, "state = 'failed', finished_at = now(), error_code = 'azure.forbidden'"), "running -> failed")

	// Finished rows: nothing reopens or changes.
	for name, id := range map[string]string{"succeeded": ok, "failed before the send": refusedQueued, "failed": failedSent, "settled from uncertain": lost, "timed out": timeout} {
		assert.Equal(t, "Z1007", up(id, "state = 'queued', finished_at = NULL, sent_at = NULL"), name+": reopened")
		assert.Equal(t, "Z1007", up(id, "state = 'running', finished_at = NULL"), name+": reopened as running")
		assert.Equal(t, "Z1007", up(id, "state = 'uncertain', finished_at = NULL"), name+": reopened as uncertain")
		if id != refusedQueued { // never sent: its sent_at is NULL already
			assert.Equal(t, "Z1007", up(id, "sent_at = NULL"), name+": sent_at cleared")
		}
		assert.Equal(t, "Z1007", up(id, "sent_at = now() + interval '1 hour'"), name+": sent_at changed")
		assert.Equal(t, "Z1007", up(id, "error_code = 'other'"), name+": error rewritten")
		assert.Equal(t, "Z1007", up(id, "version = repeat('b', 32)"), name+": version rewritten")
		assert.Equal(t, "Z1007", up(id, "finished_at = now() + interval '1 day'"), name+": finish time moved")
	}
	assert.Equal(t, "Z1007", up(ok, "state = 'failed', error_code = 'x'"), "succeeded cannot become failed")
	assert.Equal(t, "Z1007", up(failedSent, "state = 'succeeded', version = repeat('a', 32)"), "failed cannot become succeeded")

	// Unfinished rows: sent_at is fixed once set, state never goes back to queued, uncertain is not re-run.
	run := newImport()
	sent(run)
	assert.Equal(t, "Z1007", up(run, "sent_at = NULL"), "running: sent_at cleared")
	assert.Equal(t, "Z1007", up(run, "sent_at = now() + interval '1 minute'"), "running: sent_at changed")
	assert.Equal(t, "Z1007", up(run, "state = 'queued', sent_at = NULL"), "running -> queued")
	assert.Equal(t, "", up(run, "sent_at = sent_at, error_code = 'retrying'"), "an unchanged sent_at is fine")
	assert.Equal(t, "", up(run, "state = 'uncertain'"))
	assert.Equal(t, "Z1007", up(run, "state = 'running'"), "uncertain -> running: an uncertain import is never sent again")
	assert.Equal(t, "Z1007", up(run, "state = 'queued', sent_at = NULL"), "uncertain -> queued")
	assert.Equal(t, "Z1007", up(run, "sent_at = NULL"), "uncertain: sent_at cleared")

	// A finished import loses its pruned job, whoever prunes it; it never gains or swaps one.
	jobID, err := seedJob(t, d, nil, "succeeded")
	require.NoError(t, err)
	withJob := newImport()
	require.Equal(t, "", up(withJob, "job_id = $1", jobID))
	require.Equal(t, "", up(withJob, "state = 'failed', finished_at = now(), error_code = 'x'"))
	other, err := seedJob(t, d, nil, "succeeded")
	require.NoError(t, err)
	assert.Equal(t, "Z1007", up(withJob, "job_id = $1", other), "a finished import's job is not swapped")
	require.NoError(t, exec(t, d.App, "DELETE FROM jobs WHERE id = $1", jobID), "pruning the job of a finished import works (ON DELETE SET NULL)")
	var jobNull bool
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT job_id IS NULL FROM kv_imports WHERE id = $1", withJob).Scan(&jobNull))
	assert.True(t, jobNull)
	assert.Equal(t, "", up(withJob, "job_id = NULL"), "clearing the job by hand is the same legal change")
	assert.Equal(t, "Z1007", up(ok, "job_id = $1", other), "a finished import never gains a job")
	assert.Equal(t, "Z1007", sqlState(exec(t, d.Owner, "UPDATE kv_imports SET state = 'queued', finished_at = NULL, sent_at = NULL WHERE id = $1", ok)), "the owner role too")
}

// Names compare by an ASCII fold that does not depend on the database's locale: under a Turkish
// collation lower('WEB-I') is 'web-ı', while Go folds ASCII. The four name indexes use
// lower(name COLLATE "C"), and so must every conflict target.
func TestKeyVaultNameIndexesAreLocaleIndependent(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	for _, idx := range []string{"kv_certificates_name", "kv_keys_name", "kv_secrets_name", "kv_imports_one_active"} {
		var def string
		require.NoError(t, d.Owner.QueryRow(ctx, "SELECT indexdef FROM pg_indexes WHERE indexname = $1", idx).Scan(&def))
		assert.Contains(t, def, `lower((name COLLATE "C"))`, idx)
	}

	// The upsert forms the application writes, run as alice_app, including the partial index of imports.
	v := addVault(t, d, "kv1")
	leaf := insertCertificate(t, d)
	for i := 0; i < 2; i++ {
		require.NoError(t, exec(t, d.App, `INSERT INTO kv_certificates (id, target_id, name, listed_thumbprint, enabled, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, 'WEB-I', repeat('a', 40), true, now(), now())
ON CONFLICT (target_id, lower(name COLLATE "C")) DO UPDATE SET enabled = EXCLUDED.enabled`, v.target))
	}
	require.NoError(t, exec(t, d.App, `INSERT INTO kv_imports (id, certificate_id, target_id, name, new_version, state, thumbprint, created_at)
VALUES (gen_random_uuid(), $1, $2, 'WEB-I', false, 'queued', repeat('f', 40), now())
ON CONFLICT (target_id, lower(name COLLATE "C")) WHERE state IN ('queued', 'running', 'uncertain') DO NOTHING`, leaf, v.target))
	require.NoError(t, exec(t, d.App, `INSERT INTO kv_imports (id, certificate_id, target_id, name, new_version, state, thumbprint, created_at)
VALUES (gen_random_uuid(), $1, $2, 'web-i', false, 'queued', repeat('f', 40), now())
ON CONFLICT (target_id, lower(name COLLATE "C")) WHERE state IN ('queued', 'running', 'uncertain') DO NOTHING`, leaf, v.target))
	assert.Equal(t, 1, scanInt(t, d, "SELECT count(*) FROM kv_imports"))
	assert.Equal(t, 1, scanInt(t, d, "SELECT count(*) FROM kv_certificates"))

	// A database whose default collation is Turkish: lower() there folds I to a dotless i, so an
	// index on lower(name) would let WEB-I and web-i live side by side. Skipped without ICU.
	var turkish string
	if err := d.Owner.QueryRow(ctx, `SELECT lower('WEB-I' COLLATE "tr-TR-x-icu")`).Scan(&turkish); err != nil || turkish == "web-i" {
		t.Skipf("no Turkish ICU collation here (%v, %q): the index definitions above are the check", err, turkish)
	}
	own, err := url.Parse(d.OwnerURL)
	require.NoError(t, err)
	name := "tr_" + strings.TrimPrefix(strings.TrimPrefix(own.Path, "/"), "test_")
	_, err = d.Owner.Exec(ctx, "CREATE DATABASE "+name+" TEMPLATE template0 LOCALE_PROVIDER icu ICU_LOCALE 'tr-TR' LOCALE 'C' ENCODING 'UTF8'")
	if err != nil {
		t.Skipf("cannot create a Turkish database: %v", err)
	}
	own.Path = "/" + name
	pool, err := db.Open(ctx, own.String())
	require.NoError(t, err)
	defer pool.Close()
	require.NoError(t, db.Migrate(ctx, pool, migrations.FS))
	var lowered string
	require.NoError(t, pool.QueryRow(ctx, "SELECT lower('WEB-I')").Scan(&lowered))
	require.NotEqual(t, "web-i", lowered, "this database really folds the Turkish way")
	var target, cred = "00000000-0000-0000-0000-0000000000e1", "00000000-0000-0000-0000-0000000000e2"
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, insertVaultCredential, cred, "azure_sp_secret", target)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, insertVaultTarget, target, "vault tr", "https://kv-tr.vault.azure.net", "kv-tr.vault.azure.net", cred)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	ins := func(name string) error {
		_, err := pool.Exec(ctx, `INSERT INTO kv_certificates (id, target_id, name, listed_thumbprint, enabled, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, $2, repeat('a', 40), true, now(), now())`, target, name)
		return err
	}
	require.NoError(t, ins("WEB-I"))
	assert.Equal(t, "23505", sqlState(ins("web-i")), "WEB-I and web-i collide even in a Turkish database")
}
