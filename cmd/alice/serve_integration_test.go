//go:build integration

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/config"
	"alice/internal/platform/db"
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

// An installation upgraded from Phase 3 starts: serve applies migrations 00006 to 00012 over the Phase 3
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
	assert.Equal(t, int64(12), version, "serve applied 00006 to 00012")
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM license"), "the same installation")
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM credentials WHERE purpose = 'platform_ssh'"), "the same platform key")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM targets"), "no Nginx server is needed")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM deployments"))
	assert.NotContains(t, logs.String(), "not completely wired")
	stop()
	code, out, errOut := runCLI(t, cliEnv(t, d), "audit", "verify")
	assert.Equal(t, 0, code, "the audit chain is intact across the upgrade: %s %s", out, errOut)
}

// freeAddr returns a loopback address with a port nothing listens on right now.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// externalConfig is the production alice container's configuration (C3): the app role only, and
// migrations left to the migrate service. The owner URL is not in it at all.
func externalConfig(t *testing.T, d *pgtest.DB, healthAddr string) config.Config {
	t.Helper()
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL": d.AppURL, "ALICE_MIGRATE": "external",
		"ALICE_LISTEN_ADDR": "127.0.0.1:0", "ALICE_HEALTH_ADDR": healthAddr,
		"ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": t.TempDir(),
	}))
	require.NoError(t, err)
	require.Empty(t, cfg.MigrateDatabaseURL)
	return cfg
}

// P1-01: with ALICE_MIGRATE=external, serve never migrates; a schema older than the binary stops the
// start with a message naming both versions and the command that fixes it.
func TestServeRefusesAStaleSchemaWhenMigrationsAreExternal(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	latest, err := db.LatestVersion(migrations.FS)
	require.NoError(t, err)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, latest-1)
	require.NoError(t, err)

	cfg := externalConfig(t, d, "127.0.0.1:0")
	logs := &lockedBuffer{}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = serve(runCtx, cfg, logging.New(logs, slog.LevelInfo))
	require.Error(t, err)
	assert.Equal(t, fmt.Sprintf("database schema is at version %d but this Alice needs %d: run the migrate service first "+
		"(docker compose run --rm migrate)", latest-1, latest), err.Error())
	assert.NotContains(t, logs.String(), "alice is ready")

	v, err := db.SchemaVersion(ctx, d.Owner)
	require.NoError(t, err)
	assert.Equal(t, latest-1, v, "serve applied nothing")

	// The same through the command line: exit 1, the message in the log.
	code, _, errOut := runCLI(t, env(map[string]string{
		"ALICE_DATABASE_URL": d.AppURL, "ALICE_MIGRATE": "external",
		"ALICE_LISTEN_ADDR": "127.0.0.1:0", "ALICE_HEALTH_ADDR": "127.0.0.1:0",
		"ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": t.TempDir(),
	}), "serve")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "run the migrate service first")

	// A schema newer than the binary (an older Alice started on a migrated database) is refused too.
	_, err = p.UpTo(ctx, latest)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, "INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)", latest+1)
	require.NoError(t, err)
	err = serve(runCtx, externalConfig(t, d, "127.0.0.1:0"), logging.New(logs, slog.LevelInfo))
	require.Error(t, err)
	assert.Equal(t, fmt.Sprintf("database schema is at version %d, newer than this Alice (%d): run the Alice version that "+
		"migrated it, or restore a backup made by this version", latest+1, latest), err.Error())
}

// A current schema starts with external migrations, without the single-role warning: the owner
// role exists, it is just not this container's business.
func TestServeWithExternalMigrationsStartsOnACurrentSchema(t *testing.T) {
	d := pgtest.New(t)
	health := freeAddr(t)
	logs, stop := runServe(t, externalConfig(t, d, health))
	defer stop()

	resp, err := http.Get("http://" + health + "/healthz") //nolint:noctx // a test against loopback
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotContains(t, logs.String(), "ALICE_MIGRATE_DATABASE_URL is not set")
	assert.NotContains(t, logs.String(), "share one database role")
}

// S-37: the migrate service gets the owner URL only; migrate needs no application credential.
func TestMigrateCommandNeedsOnlyTheOwnerURL(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	latest, err := db.LatestVersion(migrations.FS)
	require.NoError(t, err)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, latest-1)
	require.NoError(t, err)

	code, out, errOut := runCLI(t, env(map[string]string{"ALICE_MIGRATE_DATABASE_URL": d.OwnerURL}), "migrate")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "database is up to date")
	v, err := db.SchemaVersion(ctx, d.Owner)
	require.NoError(t, err)
	assert.Equal(t, latest, v)

	code, _, errOut = runCLI(t, env(nil), "migrate")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "ALICE_DATABASE_URL")
}

// A database that cannot be read stops the version check (it never counts as current).
func TestRequireCurrentSchemaFailsClosed(t *testing.T) {
	d := pgtest.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, d.AppURL)
	require.NoError(t, err)
	require.NoError(t, requireCurrentSchema(ctx, pool))
	pool.Close()
	require.Error(t, requireCurrentSchema(ctx, pool))
}
