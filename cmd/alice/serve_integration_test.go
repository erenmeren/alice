//go:build integration

package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/config"
	"alice/internal/platform/logging"
	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// runServe starts serve on cfg until it reports ready and returns its log and a stop function
// that waits for a clean exit.
func runServe(t *testing.T, cfg config.Config) (*lockedBuffer, func()) {
	t.Helper()
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, logging.New(logs, slog.LevelInfo)) }()
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "alice is ready") },
		30*time.Second, 20*time.Millisecond, "serve did not start: %s", logs.String())
	return logs, func() {
		t.Helper()
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(30 * time.Second):
			t.Fatal("serve did not stop")
		}
	}
}

// An installation upgraded from Phase 3 starts: serve applies migration 00006 over the Phase 3
// schema and its data (the installation, the platform key, the audit chain), and the Phase 4
// wiring needs no Nginx server to exist.
func TestServeStartsOnAPhase3Database(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL": d.AppURL, "ALICE_MIGRATE_DATABASE_URL": d.OwnerURL,
		"ALICE_LISTEN_ADDR": "127.0.0.1:0", "ALICE_HEALTH_ADDR": "127.0.0.1:0",
		"ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": t.TempDir(),
	}))
	require.NoError(t, err)
	_, stop := runServe(t, cfg)
	stop()
	installation := countRows(t, d, "SELECT count(*) FROM license")
	require.Equal(t, 1, installation)

	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 5)
	require.NoError(t, err)
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(5), version, "a Phase 3 schema")

	logs, stop := runServe(t, cfg)
	version, err = p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(6), version, "serve applied 00006")
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM license"), "the same installation")
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM credentials WHERE purpose = 'platform_ssh'"), "the same platform key")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM targets"), "no Nginx server is needed")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM deployments"))
	assert.NotContains(t, logs.String(), "not completely wired")
	stop()
	code, out, errOut := runCLI(t, cliEnv(t, d), "audit", "verify")
	assert.Equal(t, 0, code, "the audit chain is intact across the upgrade: %s %s", out, errOut)
}
