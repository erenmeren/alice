package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AUD-20: the new key file's directory is synced (and the parent of a directory that was created).
func TestCreateKeyFileSyncsItsDirectory(t *testing.T) {
	var synced []string
	old := syncDir
	syncDir = func(dir string) error { synced = append(synced, dir); return syncDirectory(dir) }
	defer func() { syncDir = old }()
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	path := filepath.Join(dir, MasterKeyFile)
	require.NoError(t, createKeyFile(dir, path))
	assert.Equal(t, []string{dir, base}, synced)

	synced = nil
	require.NoError(t, createKeyFile(dir, path), "an existing key file is left alone")
	assert.Equal(t, []string{dir}, synced, "the winner's entry may not be durable yet: the loser syncs the directory too")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o400), info.Mode().Perm())
}

func TestCreateKeyFileSyncsOnlyTheDirectoryOfAnExistingDirectory(t *testing.T) {
	var synced []string
	old := syncDir
	syncDir = func(dir string) error { synced = append(synced, dir); return nil }
	defer func() { syncDir = old }()
	dir := t.TempDir()
	require.NoError(t, createKeyFile(dir, filepath.Join(dir, MasterKeyFile)))
	assert.Equal(t, []string{dir}, synced)
}

func TestCreateKeyFileFailsWhenTheDirectorySyncFails(t *testing.T) {
	boom := errors.New("sync failed")
	old := syncDir
	syncDir = func(string) error { return boom }
	defer func() { syncDir = old }()
	dir := t.TempDir()
	path := filepath.Join(dir, MasterKeyFile)
	err := createKeyFile(dir, path)
	require.ErrorIs(t, err, boom)
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr, "the file stays: another starting process may already use it")

	// The retry adopts the file and must still sync the directory.
	var synced []string
	syncDir = func(d string) error { synced = append(synced, d); return nil }
	require.NoError(t, createKeyFile(dir, path))
	assert.Equal(t, []string{dir}, synced)
}

// A start that loses the O_EXCL race adopts the winner's file, and fails when it cannot make that
// file's directory entry durable either.
func TestCreateKeyFileLoserFailsWhenTheDirectorySyncFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, MasterKeyFile)
	require.NoError(t, createKeyFile(dir, path))
	boom := errors.New("sync failed")
	restore := SetSyncDirForTest(func(string) error { return boom })
	defer restore()
	err := createKeyFile(dir, path)
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "sync keys directory")
}

// When the keys directory was created by this start, its parent is synced too; a failure there
// fails the start and names the parent, and the key file stays for the next start to adopt.
func TestCreateKeyFileFailsWhenTheParentSyncFails(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	path := filepath.Join(dir, MasterKeyFile)
	boom := errors.New("parent sync failed")
	restore := SetSyncDirForTest(func(d string) error {
		if d == base {
			return boom
		}
		return nil
	})
	defer restore()
	err := createKeyFile(dir, path)
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "sync parent of keys directory")
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr)
}

// syncDirectory itself: a directory is synced; a missing one is an error, never ignored.
func TestSyncDirectory(t *testing.T) {
	require.NoError(t, syncDirectory(t.TempDir()))
	require.ErrorIs(t, syncDirectory(filepath.Join(t.TempDir(), "missing")), os.ErrNotExist)
}
