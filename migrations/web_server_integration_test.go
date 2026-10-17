//go:build integration

package migrations_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// nginxCapabilities is what an Nginx target stored before 00016 (the provider's set when it was added).
var nginxCapabilities = []string{"authorized_keys", "deploy_certificate", "discover_certificates", "discover_ssh_keys",
	"key_login", "test_connection", "verify_deployment"}

const oldNginxFacts = `{"version":"1.24.0","conf_path":"/etc/nginx/nginx.conf","config_valid":true,"config_error":"",` +
	`"config_error_reason":"","config_error_file":"","found":true}`

// targetFacts reads a target's facts as a generic JSON object.
func targetFacts(t *testing.T, d *pgtest.DB, id uuid.UUID) map[string]any {
	t.Helper()
	var raw []byte
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT facts FROM targets WHERE id = $1", id).Scan(&raw))
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func targetCapabilities(t *testing.T, d *pgtest.DB, id uuid.UUID) []string {
	t.Helper()
	var caps []string
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT capabilities FROM targets WHERE id = $1", id).Scan(&caps))
	return caps
}

func warningCodes(t *testing.T, facts map[string]any) []string {
	t.Helper()
	list, ok := facts["warnings"].([]any)
	require.True(t, ok, "warnings is an array: %v", facts["warnings"])
	codes := make([]string, 0, len(list))
	for _, w := range list {
		m := w.(map[string]any)
		assert.Equal(t, map[string]any{}, m["Params"], "params are kept")
		codes = append(codes, m["Code"].(string))
	}
	return codes
}

func jsonObject(t *testing.T, s string) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(s), &out))
	return out
}

// 00016: facts.nginx becomes facts.web_server with its software, the scan's nginx_* warning codes become web_server_*,
// Nginx targets gain http01_challenge in byte order and locations of kind nginx_file become server_file; the Down
// restores the 00015 shape and the Up goes through again.
func TestMigration00016RewritesWebServerDataAndDownRestoresIt(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 15)
	require.NoError(t, err)

	cred, a, b, c, cert, loc := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	aFacts := `{"os":{"id":"debian","version_id":"12"},"nginx":` + oldNginxFacts +
		`,"warnings":[{"Code":"nginx_profile_missing","Params":{}},{"Code":"stream_tls","Params":{}}]}`
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, []any{cred}},
		{`INSERT INTO targets (id, name, type, config, credential_id, status, facts, capabilities, created_at, updated_at)
VALUES ($1, 'web-a', 'nginx', '{"host":"10.0.0.1","port":22,"username":"alice-svc"}', $2, 'ok', $3::jsonb, $4, now(), now())`,
			[]any{a, cred, aFacts, nginxCapabilities}},
		{`INSERT INTO targets (id, name, type, config, credential_id, status, facts, created_at, updated_at)
VALUES ($1, 'web-b', 'nginx', '{"host":"10.0.0.2","port":22,"username":"alice-svc"}', $2, 'ok', '{"nginx":null,"warnings":"x"}', now(), now())`,
			[]any{b, cred}},
		{`INSERT INTO targets (id, name, type, config, credential_id, status, facts, created_at, updated_at)
VALUES ($1, 'host-c', 'linux', '{"host":"10.0.0.3","port":22,"username":"alice-svc"}', $2, 'ok',
'{"warnings":[{"Code":"keys_managed_elsewhere","Params":{}}]}', now(), now())`, []any{c, cred}},
		{`INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256, pem_chain, source,
first_seen_at, last_seen_at, created_at) VALUES ($1, $2, now(), now() + interval '90 days', 'ecdsa', $3, '', 'discovered', now(), now(), now())`,
			[]any{cert, hex64("a"), hex64("b")}},
		{`INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported, first_seen_at, last_seen_at)
VALUES ($1, $2, 'nginx_file', '/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', $3, true, now(), now())`, []any{loc, a, cert}},
	} {
		_, err := d.Owner.Exec(ctx, q.sql, q.args...)
		require.NoError(t, err)
	}
	cFactsBefore := targetFacts(t, d, c)
	kind := func() string {
		var k string
		require.NoError(t, d.Owner.QueryRow(ctx, "SELECT kind FROM certificate_locations WHERE id = $1", loc).Scan(&k))
		return k
	}
	insertLocation := func(kind string) error {
		_, err := d.Owner.Exec(ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, supported, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, $2, '/etc/nginx/ssl/' || gen_random_uuid()::text || '.crt', true, now(), now())`, a, kind)
		return err
	}

	_, err = p.Up(ctx)
	require.NoError(t, err)
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(16), version)

	fa := targetFacts(t, d, a)
	assert.NotContains(t, fa, "nginx")
	want := jsonObject(t, oldNginxFacts)
	want["software"] = "nginx"
	assert.Equal(t, want, fa["web_server"])
	assert.Equal(t, []string{"web_server_profile_missing", "stream_tls"}, warningCodes(t, fa), "codes renamed, order kept")
	assert.Equal(t, map[string]any{"id": "debian", "version_id": "12"}, fa["os"])
	assert.Equal(t, []string{"authorized_keys", "deploy_certificate", "discover_certificates", "discover_ssh_keys", "http01_challenge",
		"key_login", "test_connection", "verify_deployment"}, targetCapabilities(t, d, a))

	fb := targetFacts(t, d, b)
	assert.NotContains(t, fb, "nginx", "a JSON null is dropped")
	assert.NotContains(t, fb, "web_server")
	assert.Equal(t, "x", fb["warnings"], "a non-array warnings value is left alone")

	assert.Equal(t, cFactsBefore, targetFacts(t, d, c), "a Linux target's facts are unchanged")
	assert.Empty(t, targetCapabilities(t, d, c), "a Linux target gains no capability")

	assert.Equal(t, "server_file", kind())
	assert.Equal(t, checkViolation, sqlState(insertLocation("nginx_file")), "nginx_file is no longer a kind")
	require.NoError(t, insertLocation("server_file"))

	_, err = p.DownTo(ctx, 15)
	require.NoError(t, err)
	fa = targetFacts(t, d, a)
	assert.NotContains(t, fa, "web_server")
	assert.Equal(t, jsonObject(t, oldNginxFacts), fa["nginx"], "the software is dropped again")
	assert.Equal(t, []string{"nginx_profile_missing", "stream_tls"}, warningCodes(t, fa))
	assert.Equal(t, nginxCapabilities, targetCapabilities(t, d, a))
	assert.Equal(t, "nginx_file", kind())
	assert.Equal(t, checkViolation, sqlState(insertLocation("server_file")), "the 00015 CHECK is back")

	_, err = p.Up(ctx)
	require.NoError(t, err)
	n := 0
	for _, capability := range targetCapabilities(t, d, a) {
		if capability == "http01_challenge" {
			n++
		}
	}
	assert.Equal(t, 1, n, "http01_challenge appears exactly once after a second Up")
}
