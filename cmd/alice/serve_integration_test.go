//go:build integration

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	"alice/internal/platform/settings"
	"alice/internal/platform/tlscert"
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

// stageRestore writes a staging directory as a restore stopped after its swap point leaves it (C1, S-1): the staged
// files, FILES and RESTORE_ID.
func stageRestore(t *testing.T, dir, id string, files map[string][]byte) {
	t.Helper()
	s := filepath.Join(dir, ".restore-staging")
	require.NoError(t, os.Mkdir(s, 0o700))
	var names []string
	for name, b := range files {
		mode := os.FileMode(0o400)
		if name == "tls.crt" {
			mode = 0o644
		}
		require.NoError(t, os.WriteFile(filepath.Join(s, name), b, mode))
		names = append(names, name)
	}
	require.NoError(t, os.WriteFile(filepath.Join(s, "FILES"), []byte(strings.Join(names, "\n")+"\n"), 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(s, "RESTORE_ID"), []byte(id+"\n"), 0o400))
}

func readFiles(t *testing.T, dir string, names ...string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		require.NoError(t, err)
		out[n] = b
	}
	return out
}

// S-1: serve applies staged files before it loads the master key, but only when the live database's restore ID is the
// staging's; any other staging is stale and removed, the live files untouched.
func TestServeFinishesAnInterruptedRestore(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	other := t.TempDir()
	_, err := tlscert.EnsureSelfSigned(other, []string{"restored.example.test"}, time.Now())
	require.NoError(t, err)
	staged := readFiles(t, other, "tls.crt", "tls.key")

	t.Run("the restore ID matches", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		_, err := tlscert.EnsureSelfSigned(i.keys, []string{"localhost"}, time.Now())
		require.NoError(t, err)
		files := readFiles(t, i.keys, "master.key")
		files["tls.crt"], files["tls.key"] = staged["tls.crt"], staged["tls.key"]
		stageRestore(t, i.keys, id, files)
		stageRestore(t, i.state, id, map[string][]byte{})
		require.NoError(t, settings.Set(i.ctx, i.d.Owner, "backup.restore_id", id, time.Now()))

		stop := i.serve()
		defer stop()
		assert.Equal(t, staged, readFiles(t, i.keys, "tls.crt", "tls.key"), "the staged pair is live")
		assert.NoDirExists(t, filepath.Join(i.keys, ".restore-staging"))
		assert.NoDirExists(t, filepath.Join(i.state, ".restore-staging"))
		code, out, errOut := i.run("", "selfcheck")
		requireHealthy(t, code, out, errOut)
	})
	t.Run("another restore ID", func(t *testing.T) {
		i := newCLIInstall(t)
		i.listening()
		_, err := tlscert.EnsureSelfSigned(i.keys, []string{"localhost"}, time.Now())
		require.NoError(t, err)
		live := readFiles(t, i.keys, "master.key", "tls.crt", "tls.key")
		// A master key that would make the start fail if it were applied.
		files := map[string][]byte{"master.key": []byte(base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")}
		files["tls.crt"], files["tls.key"] = staged["tls.crt"], staged["tls.key"]
		stageRestore(t, i.keys, id, files)
		require.NoError(t, settings.Set(i.ctx, i.d.Owner, "backup.restore_id", "ffffffffffffffffffffffffffffffff", time.Now()))

		stop := i.serve()
		defer stop()
		assert.Equal(t, live, readFiles(t, i.keys, "master.key", "tls.crt", "tls.key"), "the live files are byte-equal")
		assert.NoDirExists(t, filepath.Join(i.keys, ".restore-staging"), "the stale staging is removed")
	})
}

// S-13: an interrupted certificate installation that the store finishes at the start is audited
// https.certificate_recovered.
func TestServeAuditsARecoveredCertificate(t *testing.T) {
	i := newCLIInstall(t)
	i.listening()
	_, err := tlscert.EnsureSelfSigned(i.keys, []string{"localhost"}, time.Now())
	require.NoError(t, err)
	other := t.TempDir()
	_, err = tlscert.EnsureSelfSigned(other, []string{"new.example.test"}, time.Now())
	require.NoError(t, err)
	next := readFiles(t, other, "tls.crt", "tls.key")
	// The key was renamed into place, the certificate was not: tls.crt.new is left.
	require.NoError(t, os.Remove(filepath.Join(i.keys, "tls.key")))
	require.NoError(t, os.WriteFile(filepath.Join(i.keys, "tls.key"), next["tls.key"], 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(i.keys, "tls.crt.new"), next["tls.crt"], 0o644))

	stop := i.serve()
	defer stop()
	assert.Equal(t, next["tls.crt"], readFiles(t, i.keys, "tls.crt")["tls.crt"])
	assert.NoFileExists(t, filepath.Join(i.keys, "tls.crt.new"))
	rows, err := i.d.Owner.Query(i.ctx, `SELECT actor_name, details->>'reason', details->>'fingerprint', details->>'temporary'
		FROM audit_log WHERE action = 'https.certificate_recovered'`)
	require.NoError(t, err)
	type row struct{ actor, reason, fp, temporary string }
	var got []row
	for rows.Next() {
		var r row
		require.NoError(t, rows.Scan(&r.actor, &r.reason, &r.fp, &r.temporary))
		got = append(got, r)
	}
	require.NoError(t, rows.Err())
	require.Len(t, got, 1)
	assert.Equal(t, "startup", got[0].actor)
	assert.Equal(t, "finished", got[0].reason)
	assert.Regexp(t, `^[0-9a-f]{64}$`, got[0].fp)
	code, out, errOut := i.run("", "selfcheck")
	requireHealthy(t, code, out, errOut)
}
