package db_test

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
)

func TestOpenGivesUpWhenDatabaseUnreachableWithoutLeakingPassword(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	pool, err := db.Open(ctx, "postgres://alice:s3cret-pw@127.0.0.1:1/alice?sslmode=disable")
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.True(t, errors.Is(err, db.ErrUnreachable))
	assert.NotContains(t, err.Error(), "s3cret-pw")
	assert.Contains(t, err.Error(), "127.0.0.1:1")
	assert.Less(t, time.Since(start), 4*time.Second)
}

func TestOpenRejectsInvalidURLWithoutEchoingIt(t *testing.T) {
	_, err := db.Open(context.Background(), "postgres://alice:s3cret-pw@host:notaport/alice")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cret-pw")
	assert.Contains(t, err.Error(), "ALICE_DATABASE_URL")
}

// LatestVersion is the highest NNNNN_*.sql in the migration set; other files are not migrations,
// and a .sql file without a version prefix is refused rather than silently skipped.
func TestLatestVersionReadsFileNames(t *testing.T) {
	v, err := db.LatestVersion(fstest.MapFS{
		"00001_a.sql": {Data: []byte("-- a")},
		"00012_b.sql": {Data: []byte("-- b")},
		"00003_c.sql": {Data: []byte("-- c")},
		"README.md":   {Data: []byte("not a migration")},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(12), v)

	for _, bad := range []string{"0001x_a.sql", "a_00002.sql", "00002.sql", "_a.sql"} {
		_, err := db.LatestVersion(fstest.MapFS{"00001_a.sql": {}, bad: {}})
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), bad)
	}
	_, err = db.LatestVersion(fstest.MapFS{"README.md": {}})
	require.Error(t, err, "a set without migrations")
	_, err = db.LatestVersion(fstest.MapFS{"99999999999999999999_huge.sql": {}})
	require.Error(t, err, "a version beyond int64")
	_, err = db.LatestVersion(fstest.MapFS{"00000_zero.sql": {}})
	require.Error(t, err, "goose versions start at 1")
	_, err = db.LatestVersion(brokenFS{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read the migrations")
}

// brokenFS cannot list its root.
type brokenFS struct{}

func (brokenFS) Open(string) (fs.File, error) { return nil, fs.ErrPermission }
