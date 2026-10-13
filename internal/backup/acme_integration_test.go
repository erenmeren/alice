//go:build integration

package backup_test

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup"
	"alice/internal/secrets"
)

// acmeSeed is the ACME rows of TestACMEBackupCycle and what they hold.
type acmeSeed struct {
	account uuid.UUID
	key     []byte // the plaintext account key
}

// seedACME inserts a provider (with a sealed EAB key), an active account whose key is really sealed under the master key,
// a hook, an issued certificate (a managed key, a certificates row with source acme), an ACME certificate with
// auto_renew on, a finished order, a binding to a location, and an acme_renewal deployment.
func seedACME(e *env) acmeSeed {
	e.t.Helper()
	seal := func(table string, id uuid.UUID, column string, plain []byte) secrets.Envelope {
		env, err := e.keyring.Seal(secrets.Location{Table: table, RowID: id.String(), Column: column}, plain)
		require.NoError(e.t, err)
		return env
	}
	exec := func(sql string, args ...any) {
		e.t.Helper()
		_, err := e.db.Owner.Exec(e.ctx, sql, args...)
		require.NoError(e.t, err, sql)
	}
	s := acmeSeed{account: uuid.New(), key: []byte("account-key-canary-0123456789abcdef")}
	provider, hook, acmeCert, order, cert, mkey := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	cred, target, loc := uuid.New(), uuid.New(), uuid.New()
	now := e.clk.Now()

	eab := seal("acme_providers", provider, "eab_hmac", []byte("eab-hmac-secret"))
	exec(`INSERT INTO acme_providers (id, name, directory_url, preset, eab_kid, eab_hmac_ct, eab_hmac_nonce, eab_hmac_wrapped_dek, eab_hmac_key_version,
created_at, updated_at) VALUES ($1, 'Corp CA', 'https://ca.corp.example/directory', 'custom', 'kid-1', $2, $3, $4, $5, $6, $6)`,
		provider, eab.Ciphertext, eab.Nonce, eab.WrappedDEK, eab.KeyVersion, now)
	key := seal("acme_accounts", s.account, "key", s.key)
	exec(`INSERT INTO acme_accounts (id, provider_id, contact_email, account_url, tos_url, tos_accepted_at, key_ct, key_nonce, key_wrapped_dek, key_version,
state, created_at, updated_at) VALUES ($1, $2, 'ops@corp.example', 'https://ca.corp.example/acct/1', 'https://ca.corp.example/tos', $3, $4, $5, $6, $7,
'active', $3, $3)`, s.account, provider, now, key.Ciphertext, key.Nonce, key.WrappedDEK, key.KeyVersion)
	sec := seal("acme_hooks", hook, "secret", []byte("hook-bearer"))
	exec(`INSERT INTO acme_hooks (id, name, url, secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version, created_at, updated_at)
VALUES ($1, 'dns-hook', 'https://dns.corp.example/hook', $2, $3, $4, $5, $6, $6)`, hook, sec.Ciphertext, sec.Nonce, sec.WrappedDEK, sec.KeyVersion, now)

	pub := strings.Repeat("c", 64)
	mk := seal("managed_private_keys", mkey, "ciphertext", []byte("leaf-key"))
	exec(`INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'certificate', 'ecdsa', 256, $2, $3, $4, $5, $6, $7)`, mkey, pub, mk.Ciphertext, mk.Nonce, mk.WrappedDEK, mk.KeyVersion, now)
	exec(`INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256, pem_chain, source, private_key_id,
first_seen_at, last_seen_at, created_at) VALUES ($1, $2, $3::timestamptz, $3::timestamptz + interval '90 days', 'ecdsa', $4, '', 'acme', $5, $3, $3, $3)`,
		cert, hex.EncodeToString(make([]byte, 32)), now, pub, mkey)
	exec(`INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, auto_renew, auto_deploy, state,
current_certificate_id, created_at, updated_at) VALUES ($1, $2, $3, '{www.corp.example}', 'ecdsa_p256', 'dns01', $4, true, true, 'active', $5, $6, $6)`,
		acmeCert, provider, s.account, hook, cert, now)
	exec(`INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, finished_at, certificate_id, order_url)
VALUES ($1, $2, 'issue', 'succeeded', $3, $3, $4, 'https://ca.corp.example/order/1')`, order, acmeCert, now, cert)
	exec(`INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`, cred, now)
	exec(`INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'web-01', 'nginx', '{"host":"10.0.0.1","port":22,"username":"alice-svc"}', $2, 'ok', $3, $3)`, target, cred, now)
	exec(`INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported, first_seen_at, last_seen_at)
VALUES ($1, $2, 'nginx_file', '/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', $3, true, $4, $4)`, loc, target, cert, now)
	exec(`INSERT INTO acme_bindings (acme_certificate_id, location_id, auto_deploy, created_at) VALUES ($1, $2, true, $3)`, acmeCert, loc, now)
	exec(`INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint, cert_path, key_path, created_at, finished_at)
VALUES ($1, $2, $3, $4, 'acme_renewal', 'done', 'succeeded', $5, '/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', $6, $6)`,
		uuid.New(), cert, loc, target, hex.EncodeToString(make([]byte, 32)), now)
	return s
}

// The ACME tables travel in the backup: Create counts them in the manifest, VerifyDeep reads them back, a Restore brings
// them into a database that lost them, the sealed account key opens under the restored master key, and a restored clone
// does not renew certificates on its own until an Administrator confirms (A11).
func TestACMEBackupCycle(t *testing.T) {
	e := newRestoreEnv(t)
	s := seedACME(e)
	info := e.create(backup.KindManual)

	m, err := e.svc.VerifyDeep(e.ctx, info.Path, []byte(passphrase))
	require.NoError(t, err)
	for table, want := range map[string]int64{"acme_providers": 1, "acme_accounts": 1, "acme_hooks": 1, "acme_certificates": 1, "acme_orders": 1, "acme_bindings": 1} {
		assert.Equal(t, want, m.Tables[table], table)
	}

	// The installation loses its ACME data after the backup (TRUNCATE: an account row other than a pending rollover
	// key refuses a DELETE, Z1018).
	_, err = e.db.Owner.Exec(e.ctx, "TRUNCATE acme_bindings, acme_orders, acme_certificates, acme_hooks, acme_accounts, acme_providers")
	require.NoError(t, err)
	require.Zero(t, e.count("SELECT count(*) FROM acme_accounts"))

	res, err := e.restore(info.Path, nil)
	require.NoError(t, err)
	e.reload()
	for table, want := range map[string]int{"acme_providers": 1, "acme_accounts": 1, "acme_hooks": 1, "acme_certificates": 1, "acme_orders": 1, "acme_bindings": 1} {
		assert.Equal(t, want, e.count("SELECT count(*) FROM "+table), table)
	}
	assert.Equal(t, 1, e.count("SELECT count(*) FROM certificates WHERE source = 'acme'"))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM deployments WHERE trigger = 'acme_renewal'"))

	// The sealed account key opens under the restored master key, at its own location only.
	var env secrets.Envelope
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT key_ct, key_nonce, key_wrapped_dek, key_version FROM acme_accounts WHERE id = $1", s.account).
		Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion))
	pt, err := e.keyring.Open(secrets.Location{Table: "acme_accounts", RowID: s.account.String(), Column: "key"}, env)
	require.NoError(t, err)
	assert.Equal(t, s.key, pt.Bytes())
	_, err = e.keyring.Open(secrets.Location{Table: "acme_accounts", RowID: uuid.NewString(), Column: "key"}, env)
	assert.Error(t, err)

	// A11: auto-renew is off after a restore; auto_deploy and every other setting is as it was.
	assert.Zero(t, e.count("SELECT count(*) FROM acme_certificates WHERE auto_renew"), "auto-renew stays off until an Administrator confirms")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM acme_certificates WHERE auto_deploy AND state = 'active'"))
	assert.True(t, slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "renew") }), res.Warnings)

	// A backup of the restored installation verifies too.
	e.clk.Advance(time.Hour)
	again := e.create(backup.KindManual)
	m, err = e.svc.VerifyDeep(e.ctx, again.Path, []byte(passphrase))
	require.NoError(t, err)
	assert.Equal(t, int64(1), m.Tables["acme_accounts"])
}
