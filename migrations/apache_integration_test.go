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

const insufficientPrivilege = "42501"

// 00017 adds the apache target type and lets alice_app rewrite targets.capabilities (the startup sync, spec §8.1).
// The Down refuses while an Apache target exists (deleted ones included) and otherwise restores the 00016 CHECK and grant.
func TestMigration00017AddsApacheAndTheCapabilitiesGrant(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 16)
	require.NoError(t, err)
	_, err = p.UpTo(ctx, 17)
	require.NoError(t, err)

	cred, apache := uuid.New(), uuid.New()
	require.NoError(t, exec(t, d.Owner, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, cred))
	insert := func(id uuid.UUID, typ string) error {
		return exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, facts, created_at, updated_at)
VALUES ($1, $5, $2, '{"host":"10.0.0.1","port":22,"username":"alice-svc"}', $3, 'ok', $4::jsonb, now(), now())`,
			id, typ, cred, `{"web_server":{"software":"apache"},"warnings":[{"Code":"web_server_not_found","Params":{"software":"apache"}}]}`, id.String())
	}
	require.NoError(t, insert(apache, "apache"), "an apache target inserts")
	require.NoError(t, exec(t, d.App, "UPDATE targets SET capabilities = $2 WHERE id = $1", apache, []string{"test_connection"}),
		"alice_app updates capabilities")

	_, err = p.DownTo(ctx, 16)
	require.Error(t, err)
	assert.Equal(t, "Z1008", sqlState(err), "the Down refuses while an Apache target exists")
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(17), version, "nothing changed")

	require.NoError(t, exec(t, d.Owner, "UPDATE targets SET deleted_at = now() WHERE id = $1", apache))
	_, err = p.DownTo(ctx, 16)
	require.Error(t, err)
	assert.Equal(t, "Z1008", sqlState(err), "a deleted Apache target counts: targets are never hard-deleted")

	// Without an apache row the Down goes through (the row is removed as the owner, which a deployment never does).
	require.NoError(t, exec(t, d.Owner, "DELETE FROM targets WHERE id = $1", apache))
	_, err = p.DownTo(ctx, 16)
	require.NoError(t, err)
	assert.Equal(t, checkViolation, sqlState(insert(uuid.New(), "apache")), "apache is no longer a type")
	assert.Equal(t, insufficientPrivilege, sqlState(exec(t, d.App, "UPDATE targets SET capabilities = '{}'")),
		"alice_app can no longer update capabilities")
	assert.Empty(t, grantProblems(t, d), "the guard expects no capabilities grant below 00017")

	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.Empty(t, grantProblems(t, d))
	require.NoError(t, insert(uuid.New(), "apache"))
}
