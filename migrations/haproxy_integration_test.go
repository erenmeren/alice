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

// 00018 adds the haproxy target type. The Down refuses while a HAProxy target exists (deleted ones included) and
// otherwise restores the 00017 CHECK (which still knows apache and keeps the capabilities grant).
func TestMigration00018AddsHAProxy(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 17)
	require.NoError(t, err)
	_, err = p.UpTo(ctx, 18)
	require.NoError(t, err)

	cred, ha := uuid.New(), uuid.New()
	require.NoError(t, exec(t, d.Owner, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, cred))
	insert := func(id uuid.UUID, typ string) error {
		return exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, facts, created_at, updated_at)
VALUES ($1, $5, $2, '{"host":"10.0.0.1","port":22,"username":"alice-svc"}', $3, 'ok', $4::jsonb, now(), now())`,
			id, typ, cred, `{"web_server":{"software":"haproxy"},"warnings":[{"Code":"web_server_not_found","Params":{"software":"haproxy"}}]}`, id.String())
	}
	require.NoError(t, insert(ha, "haproxy"), "a haproxy target inserts, with warning Params in its facts")

	_, err = p.DownTo(ctx, 17)
	require.Error(t, err)
	assert.Equal(t, "Z1008", sqlState(err), "the Down refuses while a HAProxy target exists")
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(18), version, "nothing changed")

	require.NoError(t, exec(t, d.Owner, "UPDATE targets SET deleted_at = now() WHERE id = $1", ha))
	_, err = p.DownTo(ctx, 17)
	require.Error(t, err)
	assert.Equal(t, "Z1008", sqlState(err), "a deleted HAProxy target counts: targets are never hard-deleted")

	// Without a haproxy row the Down goes through (the row is removed as the owner, which a deployment never does).
	require.NoError(t, exec(t, d.Owner, "DELETE FROM targets WHERE id = $1", ha))
	_, err = p.DownTo(ctx, 17)
	require.NoError(t, err)
	assert.Equal(t, checkViolation, sqlState(insert(uuid.New(), "haproxy")), "haproxy is no longer a type")
	require.NoError(t, insert(uuid.New(), "apache"), "apache still is")
	assert.Empty(t, grantProblems(t, d), "00017's capabilities grant stays")

	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.Empty(t, grantProblems(t, d))
	require.NoError(t, insert(uuid.New(), "haproxy"))
}
