//go:build integration

package db_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"alice/internal/platform/db"
	"alice/migrations"
)

// adminURL points at the package-wide container; each test gets its own database.
var adminURL string

var dbCounter atomic.Int64

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
		postgres.WithDatabase("alice"),
		postgres.WithUsername("alice"),
		postgres.WithPassword("s3cret-pw"),
		postgres.BasicWaitStrategies(),
	)
	if ctr != nil {
		defer func() { _ = testcontainers.TerminateContainer(ctr) }()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "start postgres container:", err)
		return 1
	}
	adminURL, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, "connection string:", err)
		return 1
	}
	return m.Run()
}

// freshDatabaseURL creates an empty database and returns its connection URL.
func freshDatabaseURL(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := db.Open(ctx, adminURL)
	require.NoError(t, err)
	defer admin.Close()

	name := fmt.Sprintf("test_%d_%d", os.Getpid(), dbCounter.Add(1))
	_, err = admin.Exec(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)

	u, err := url.Parse(adminURL)
	require.NoError(t, err)
	u.Path = "/" + name
	return u.String()
}

func TestMigrateAndHealth(t *testing.T) {
	url := freshDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	hc, err := db.NewHealthChecker(pool, migrations.FS)
	require.NoError(t, err)
	assert.True(t, errors.Is(hc.Check(ctx), db.ErrMigrationsPending), "fresh database must report pending migrations")

	var exists bool
	require.NoError(t, pool.QueryRow(ctx, "SELECT to_regclass('goose_db_version') IS NOT NULL").Scan(&exists))
	assert.False(t, exists, "Check must be read-only and not create the goose table")

	require.NoError(t, db.Migrate(ctx, pool, migrations.FS))
	require.NoError(t, db.Migrate(ctx, pool, migrations.FS), "migrate must be idempotent")
	assert.NoError(t, hc.Check(ctx))

	var n int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM settings").Scan(&n))
	assert.Equal(t, 0, n)

	_, err = pool.Exec(ctx, "INSERT INTO settings (key, value) VALUES ('k', '1')")
	require.NoError(t, err)
	var secret bool
	require.NoError(t, pool.QueryRow(ctx, "SELECT secret FROM settings WHERE key = 'k'").Scan(&secret))
	assert.False(t, secret, "settings.secret defaults to false")
}

func TestHealthReportsPendingWhenNewerMigrationExists(t *testing.T) {
	url := freshDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()
	require.NoError(t, db.Migrate(ctx, pool, migrations.FS))

	// Every shipped migration plus one newer than any real one.
	newer := fstest.MapFS{
		"99999_more.sql": &fstest.MapFile{Data: []byte("-- +goose Up\nCREATE TABLE more (id int);\n-- +goose Down\nDROP TABLE more;\n")},
	}
	entries, err := migrations.FS.ReadDir(".")
	require.NoError(t, err)
	for _, e := range entries {
		newer[e.Name()] = &fstest.MapFile{Data: mustRead(t, e.Name())}
	}
	hc, err := db.NewHealthChecker(pool, newer)
	require.NoError(t, err)
	assert.True(t, errors.Is(hc.Check(ctx), db.ErrMigrationsPending))

	require.NoError(t, db.Migrate(ctx, pool, newer))
	assert.NoError(t, hc.Check(ctx))
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := migrations.FS.ReadFile(name)
	require.NoError(t, err)
	return b
}

func TestConcurrentMigrateIsSerialized(t *testing.T) {
	url := freshDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	errs := make(chan error, 3)
	for range 3 {
		go func() { errs <- db.Migrate(ctx, pool, migrations.FS) }()
	}
	for range 3 {
		assert.NoError(t, <-errs)
	}
}

func TestHealthReportsUnreachableAfterPoolClosed(t *testing.T) {
	url := freshDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, url)
	require.NoError(t, err)
	require.NoError(t, db.Migrate(ctx, pool, migrations.FS))
	hc, err := db.NewHealthChecker(pool, migrations.FS)
	require.NoError(t, err)

	pool.Close()
	assert.True(t, errors.Is(hc.Check(ctx), db.ErrUnreachable))
}

func TestOpenFailsFastOnWrongPassword(t *testing.T) {
	u, err := url.Parse(adminURL)
	require.NoError(t, err)
	u.User = url.UserPassword("alice", "wrong-pw-9f3a")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	pool, err := db.Open(ctx, u.String())
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.True(t, errors.Is(err, db.ErrAuthFailed), err.Error())
	assert.False(t, errors.Is(err, db.ErrUnreachable))
	assert.NotContains(t, err.Error(), "wrong-pw-9f3a")
	assert.NotContains(t, err.Error(), "s3cret-pw")
	assert.Contains(t, err.Error(), "rejected the user name or password")
	assert.Less(t, time.Since(start), 5*time.Second, "a rejected password must not be retried")
}

func TestOpenFailsFastOnMissingDatabase(t *testing.T) {
	u, err := url.Parse(adminURL)
	require.NoError(t, err)
	u.Path = "/no_such_database"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err = db.Open(ctx, u.String())
	require.Error(t, err)
	assert.True(t, errors.Is(err, db.ErrDatabaseMissing), err.Error())
	assert.NotContains(t, err.Error(), "s3cret-pw")
	assert.Contains(t, err.Error(), "does not exist")
	assert.Less(t, time.Since(start), 5*time.Second, "a missing database must not be retried")
}
