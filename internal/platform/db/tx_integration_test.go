//go:build integration

package db_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/migrations"
)

// migratedPool returns a pool on a fresh, fully migrated database.
func migratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, freshDatabaseURL(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, db.Migrate(ctx, pool, migrations.FS))
	return pool
}

func countSettings(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), "SELECT count(*) FROM settings").Scan(&n))
	return n
}

func TestInTxCommitsOnSuccess(t *testing.T) {
	pool := migratedPool(t)
	err := db.InTx(context.Background(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "INSERT INTO settings (key, value) VALUES ('a', '1')")
		return err
	})
	require.NoError(t, err)
	assert.Equal(t, 1, countSettings(t, pool))
}

func TestInTxRollsBackOnError(t *testing.T) {
	pool := migratedPool(t)
	boom := errors.New("boom")
	err := db.InTx(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), "INSERT INTO settings (key, value) VALUES ('a', '1')"); err != nil {
			return err
		}
		return boom
	})
	assert.ErrorIs(t, err, boom)
	assert.Equal(t, 0, countSettings(t, pool))
}

func TestInTxRollsBackAndRepanicsOnPanic(t *testing.T) {
	pool := migratedPool(t)
	assert.PanicsWithValue(t, "kaboom", func() {
		_ = db.InTx(context.Background(), pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), "INSERT INTO settings (key, value) VALUES ('a', '1')")
			require.NoError(t, err)
			panic("kaboom")
		})
	})
	assert.Equal(t, 0, countSettings(t, pool))
}

func TestUniqueViolationIsDetected(t *testing.T) {
	pool := migratedPool(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, "INSERT INTO settings (key, value) VALUES ('dup', '1')")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO settings (key, value) VALUES ('dup', '2')")
	assert.True(t, db.IsUniqueViolation(err))
}

type checkpoint struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

func TestSettingsRoundTrip(t *testing.T) {
	pool := migratedPool(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	var missing string
	found, err := settings.Get(ctx, pool, "locale.default", &missing)
	require.NoError(t, err)
	assert.False(t, found)

	require.NoError(t, settings.Set(ctx, pool, "locale.default", "tr", now))
	var lang string
	found, err = settings.Get(ctx, pool, "locale.default", &lang)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "tr", lang)

	require.NoError(t, settings.Set(ctx, pool, "audit.checkpoint", checkpoint{Seq: 7, Hash: "ab"}, now))
	require.NoError(t, settings.Set(ctx, pool, "audit.checkpoint", checkpoint{Seq: 9, Hash: "İzmir"}, now.Add(time.Hour)))
	var cp checkpoint
	found, err = settings.Get(ctx, pool, "audit.checkpoint", &cp)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, checkpoint{Seq: 9, Hash: "İzmir"}, cp)

	var updated time.Time
	require.NoError(t, pool.QueryRow(ctx, "SELECT updated_at FROM settings WHERE key = 'audit.checkpoint'").Scan(&updated))
	assert.True(t, updated.UTC().Equal(now.Add(time.Hour)))

	require.NoError(t, settings.Delete(ctx, pool, "audit.checkpoint"))
	found, err = settings.Get(ctx, pool, "audit.checkpoint", &cp)
	require.NoError(t, err)
	assert.False(t, found)
	require.NoError(t, settings.Delete(ctx, pool, "audit.checkpoint"), "deleting a missing key is not an error")
}

func TestSettingsWorkInsideTransaction(t *testing.T) {
	pool := migratedPool(t)
	ctx := context.Background()
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		if err := settings.Set(ctx, tx, "k", map[string]int{"n": 1}, time.Now().UTC()); err != nil {
			return err
		}
		return errors.New("roll back")
	})
	require.Error(t, err)
	var v map[string]int
	found, err := settings.Get(ctx, pool, "k", &v)
	require.NoError(t, err)
	assert.False(t, found)
}

func TestInTxRollsBackOnGoexit(t *testing.T) {
	pool := migratedPool(t)
	baseline := pool.Stat().AcquiredConns()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = db.InTx(context.Background(), pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), "INSERT INTO settings (key, value) VALUES ('a', '1')")
			require.NoError(t, err)
			runtime.Goexit()
			return nil
		})
	}()
	<-done
	assert.Equal(t, baseline, pool.Stat().AcquiredConns(), "connection must be released")
	assert.Equal(t, 0, countSettings(t, pool))
}

func TestInTxSurfacesCommitError(t *testing.T) {
	pool := migratedPool(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `CREATE TABLE deferred_uniq (n int, CONSTRAINT n_uniq UNIQUE (n) DEFERRABLE INITIALLY DEFERRED)`)
	require.NoError(t, err)

	err = db.InTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO deferred_uniq (n) VALUES (1), (1)")
		return err // succeeds now; the unique check runs at commit
	})
	require.Error(t, err)
	assert.True(t, db.IsUniqueViolation(err))
	assert.Contains(t, err.Error(), "commit transaction")
	var n int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM deferred_uniq").Scan(&n))
	assert.Equal(t, 0, n)
}
