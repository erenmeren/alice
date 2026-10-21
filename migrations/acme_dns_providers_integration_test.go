//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// 00030 (R57): a DNS publisher has a kind; only a hook has a URL and a CA bundle, only a provider has settings; the
// application may change the settings but never the kind; the Down refuses while a provider exists (Z1030).
func TestMigration00030DNSProviders(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	insert := `INSERT INTO acme_hooks (id, name, kind, url, ca_bundle_pem, settings, secret_ct, secret_nonce, secret_wrapped_dek,
secret_key_version, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, 'x', '123456789012', 'x', 1, now(), now())`
	hook, cf := uuid.New(), uuid.New()
	require.NoError(t, exec(t, d.App, insert, hook, "hook", "webhook", "https://hook.example/x", "", `{}`))
	require.NoError(t, exec(t, d.App, insert, cf, "cloudflare", "cloudflare", "", "", `{}`))
	require.NoError(t, exec(t, d.App, insert, uuid.New(), "azure", "azure_dns", "", "", `{"auth":"managed_identity"}`))
	require.NoError(t, exec(t, d.App, insert, uuid.New(), "route53", "route53", "", "", `{"access_key_id":"X"}`))

	var kind string
	require.NoError(t, d.App.QueryRow(ctx, `INSERT INTO acme_hooks (id, name, url, secret_ct, secret_nonce, secret_wrapped_dek,
secret_key_version, created_at, updated_at) VALUES (gen_random_uuid(), 'old', 'https://h.example', 'x', '123456789012', 'x', 1, now(), now())
RETURNING kind`).Scan(&kind))
	assert.Equal(t, "webhook", kind, "a hook stored the old way is a webhook")

	refused := map[string][]any{
		"unknown kind":           {uuid.New(), "a", "bind", "", "", `{}`},
		"provider with a URL":    {uuid.New(), "b", "cloudflare", "https://x.example", "", `{}`},
		"provider with a bundle": {uuid.New(), "c", "route53", "", "-----BEGIN CERTIFICATE-----", `{}`},
		"hook without a URL":     {uuid.New(), "d", "webhook", "", "", `{}`},
		"hook with settings":     {uuid.New(), "e", "webhook", "https://x.example", "", `{"a":1}`},
		"settings not an object": {uuid.New(), "f", "cloudflare", "", "", `[]`},
	}
	for name, args := range refused {
		assert.Equal(t, checkViolation, sqlState(exec(t, d.App, insert, args...)), name)
	}
	require.NoError(t, exec(t, d.App, `UPDATE acme_hooks SET settings = '{"x":"y"}' WHERE id = $1`, cf), "settings change")
	assert.Equal(t, "42501", sqlState(exec(t, d.App, `UPDATE acme_hooks SET kind = 'route53' WHERE id = $1`, cf)), "the kind never changes")

	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 29)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Z1030")
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(30), version, "nothing changed")

	_, err = d.Owner.Exec(ctx, "DELETE FROM acme_hooks WHERE kind <> 'webhook'")
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 29)
	require.NoError(t, err)
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `INSERT INTO acme_hooks (id, name, url, secret_ct, secret_nonce, secret_wrapped_dek,
secret_key_version, created_at, updated_at) VALUES (gen_random_uuid(), 'nourl', '', 'x', '123456789012', 'x', 1, now(), now())`)),
		"the hook's URL rule is back")
	_, err = p.Up(ctx)
	require.NoError(t, err)
}
