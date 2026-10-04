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
	assert.Empty(t, synced, "nothing new, nothing to sync")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o400), info.Mode().Perm())
}

func TestCreateKeyFileSyncsOnlyTheDirectoryOfAnExistingOne(t *testing.T) {
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
	assert.ErrorIs(t, statErr, os.ErrNotExist, "an unsynced key file is not left behind")
}
