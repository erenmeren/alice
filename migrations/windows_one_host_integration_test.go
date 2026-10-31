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

// oneHostUpRefused is the SQLSTATE of 00039's Up while two live Windows servers share a host.
const oneHostUpRefused = "Z1037"

// 00039 (R72 Rulings 4-5, WIN-77): one live Windows server per lower(host), any port, either transport. The Up refuses
// while a pair exists and changes nothing then; the Down drops the index.
func TestMigration00039(t *testing.T) {
	ctx := context.Background()
	d := pgtest.New(t)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 38)
	require.NoError(t, err)
	cred := platformCredential(t, d, seedWorld(t, d))
	add := func(name, host string, port int, transport string) (uuid.UUID, error) {
		id := uuid.New()
		cfg := map[string]any{"host": host, "port": port}
		if transport != "" {
			cfg["transport"] = transport
		}
		return id, exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, $2, 'windows', $3, $4, 'ok', now(), now())`, id, name, cfg, cred)
	}
	first, err := add("iis-01", "iis-01.corp.example", 22, "")
	require.NoError(t, err)
	_, err = add("iis-01-winrm", "IIS-01.corp.example", 5986, "winrm")
	require.NoError(t, err, "00038 allows the pair")

	_, err = p.Up(ctx)
	require.Error(t, err, "a pair exists")
	assert.Equal(t, oneHostUpRefused, sqlState(err), "a pair exists: %v", err)
	assert.Contains(t, err.Error(), "two Windows servers share a host")
	v, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(38), v, "nothing changed")

	require.NoError(t, exec(t, d.Owner, "UPDATE targets SET deleted_at = now() WHERE id = $1", first), "a removed server is no pair")
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, indexCount(t, d))
	_, err = add("iis-01-again", "iis-01.corp.example", 2222, "")
	assert.Equal(t, uniqueViolation, sqlState(err), "the same host, another port and transport")
	require.NoError(t, exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'web-on-iis-01', 'nginx', '{"host":"iis-01.corp.example","port":22}', $2, 'ok', now(), now())`, uuid.New(), cred),
		"another type on the host")
	_, err = add("iis-02", "iis-02.corp.example", 22, "")
	require.NoError(t, err, "another host")

	_, err = p.DownTo(ctx, 38)
	require.NoError(t, err)
	assert.Zero(t, indexCount(t, d), "the Down drops the index")
	_, err = p.Up(ctx)
	require.NoError(t, err)
}

func indexCount(t *testing.T, d *pgtest.DB) int {
	t.Helper()
	var n int
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT count(*) FROM pg_indexes WHERE indexname = 'targets_windows_host_live'").Scan(&n))
	return n
}
