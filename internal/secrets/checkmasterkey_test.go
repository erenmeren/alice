package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyCheckDB is a db.Querier holding at most one master_key_versions row; any write fails the test.
type keyCheckDB struct {
	t     *testing.T
	check []byte
	err   error
}

func (q *keyCheckDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	q.t.Fatal("CheckMasterKey must never write")
	return pgconn.CommandTag{}, nil
}

func (q *keyCheckDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	q.t.Fatal("unexpected Query")
	return nil, nil
}

func (q *keyCheckDB) QueryRow(context.Context, string, ...any) pgx.Row { return keyCheckRow{q} }

type keyCheckRow struct{ q *keyCheckDB }

func (r keyCheckRow) Scan(dest ...any) error {
	switch {
	case r.q.err != nil:
		return r.q.err
	case r.q.check == nil:
		return pgx.ErrNoRows
	}
	*(dest[0].(*[]byte)) = r.q.check
	return nil
}

func writeKeyFile(t *testing.T, dir string, key []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, MasterKeyFile), []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o400))
}

func keyCheckFor(t *testing.T, key []byte) []byte {
	t.Helper()
	k, err := NewKeyring(masterKeyVersion, key)
	require.NoError(t, err)
	check, err := k.KeyCheck()
	require.NoError(t, err)
	return check
}

func TestCheckMasterKeyNeverCreates(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, KeySize)
	key[0] = 1
	other := make([]byte, KeySize)
	other[0] = 2

	t.Run("no row and no file", func(t *testing.T) {
		dir := t.TempDir()
		err := CheckMasterKey(ctx, &keyCheckDB{t: t}, dir)
		require.Error(t, err)
		_, statErr := os.Lstat(filepath.Join(dir, MasterKeyFile))
		assert.True(t, errors.Is(statErr, os.ErrNotExist), "no key file is created")
	})
	t.Run("a file but no row", func(t *testing.T) {
		dir := t.TempDir()
		writeKeyFile(t, dir, key)
		require.ErrorIs(t, CheckMasterKey(ctx, &keyCheckDB{t: t}, dir), ErrMasterKeyNotRecorded)
	})
	t.Run("a row but no file", func(t *testing.T) {
		dir := t.TempDir()
		require.ErrorIs(t, CheckMasterKey(ctx, &keyCheckDB{t: t, check: keyCheckFor(t, key)}, dir), ErrMasterKeyMissing)
		_, statErr := os.Lstat(filepath.Join(dir, MasterKeyFile))
		assert.True(t, errors.Is(statErr, os.ErrNotExist), "no key file is created")
	})
	t.Run("the matching file", func(t *testing.T) {
		dir := t.TempDir()
		writeKeyFile(t, dir, key)
		require.NoError(t, CheckMasterKey(ctx, &keyCheckDB{t: t, check: keyCheckFor(t, key)}, dir))
	})
	t.Run("another file", func(t *testing.T) {
		dir := t.TempDir()
		writeKeyFile(t, dir, other)
		require.ErrorIs(t, CheckMasterKey(ctx, &keyCheckDB{t: t, check: keyCheckFor(t, key)}, dir), ErrMasterKeyMismatch)
	})
	t.Run("the database cannot be read", func(t *testing.T) {
		dir := t.TempDir()
		writeKeyFile(t, dir, key)
		boom := errors.New("connection refused")
		require.ErrorIs(t, CheckMasterKey(ctx, &keyCheckDB{t: t, err: boom}, dir), boom)
	})
}
