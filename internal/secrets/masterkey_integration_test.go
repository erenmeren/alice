//go:build integration

package secrets_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func versionRows(t *testing.T, d *pgtest.DB) int {
	t.Helper()
	var n int
	require.NoError(t, d.App.QueryRow(context.Background(), "SELECT count(*) FROM master_key_versions").Scan(&n))
	return n
}

func TestFirstStartCreatesKeyFileAndVersion(t *testing.T) {
	d := pgtest.New(t)
	dir := filepath.Join(t.TempDir(), "keys")
	ctx := context.Background()

	k, err := secrets.LoadOrCreateMasterKey(ctx, d.App, dir, now)
	require.NoError(t, err)
	assert.Equal(t, 1, k.Version())

	info, err := os.Stat(filepath.Join(dir, secrets.MasterKeyFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o400), info.Mode().Perm())
	dinfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dinfo.Mode().Perm())
	assert.Equal(t, 1, versionRows(t, d))

	// A second start reuses the same key: data sealed before decrypts after.
	env, err := k.Seal(loc, []byte("persisted"))
	require.NoError(t, err)
	again, err := secrets.LoadOrCreateMasterKey(ctx, d.App, dir, now.Add(time.Hour))
	require.NoError(t, err)
	pt, err := again.Open(loc, env)
	require.NoError(t, err)
	assert.Equal(t, "persisted", string(pt.Bytes()))
	assert.Equal(t, 1, versionRows(t, d))
}

func TestInstallerProvidedKeyFileIsAdopted(t *testing.T) {
	d := pgtest.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, secrets.MasterKeyFile)
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(testKey(5))+"\n"), 0o400))

	k, err := secrets.LoadOrCreateMasterKey(context.Background(), d.App, dir, now)
	require.NoError(t, err)
	want, err := secrets.NewKeyring(1, testKey(5))
	require.NoError(t, err)
	// Compare by behaviour, never by printing keyrings.
	assert.Equal(t, want.Version(), k.Version())
	check, err := want.KeyCheck()
	require.NoError(t, err)
	assert.NoError(t, k.VerifyKeyCheck(check))
	assert.Equal(t, want.Derive(secrets.LabelCSRF), k.Derive(secrets.LabelCSRF))
	assert.Equal(t, 1, versionRows(t, d))
}

// Review Focus #4: a new empty keys volume must never replace the key of existing data.
func TestMissingKeyFileWithExistingDataRefusesAndCreatesNothing(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	_, err := secrets.LoadOrCreateMasterKey(ctx, d.App, t.TempDir(), now)
	require.NoError(t, err)

	emptyVolume := t.TempDir()
	_, err = secrets.LoadOrCreateMasterKey(ctx, d.App, emptyVolume, now)
	require.ErrorIs(t, err, secrets.ErrMasterKeyMissing)
	assert.Contains(t, err.Error(), filepath.Join(emptyVolume, secrets.MasterKeyFile))
	_, statErr := os.Stat(filepath.Join(emptyVolume, secrets.MasterKeyFile))
	assert.True(t, os.IsNotExist(statErr), "no new key file may be created")
}

func TestDifferentKeyFileIsRejected(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	_, err := secrets.LoadOrCreateMasterKey(ctx, d.App, t.TempDir(), now)
	require.NoError(t, err)

	other := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(other, secrets.MasterKeyFile),
		[]byte(base64.StdEncoding.EncodeToString(testKey(6))), 0o400))
	_, err = secrets.LoadOrCreateMasterKey(ctx, d.App, other, now)
	assert.ErrorIs(t, err, secrets.ErrMasterKeyMismatch)
}

func TestKeyFilePermissionsAndFormat(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()

	open := t.TempDir()
	path := filepath.Join(open, secrets.MasterKeyFile)
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(testKey(4))), 0o644))
	_, err := secrets.LoadOrCreateMasterKey(ctx, d.App, open, now)
	require.ErrorIs(t, err, secrets.ErrMasterKeyPermissions)
	assert.Contains(t, err.Error(), "chmod 0400")
	assert.Equal(t, 0, versionRows(t, d), "nothing recorded for a rejected file")

	bad := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bad, secrets.MasterKeyFile), []byte("not base64 at all"), 0o400))
	_, err = secrets.LoadOrCreateMasterKey(ctx, d.App, bad, now)
	assert.ErrorIs(t, err, secrets.ErrMasterKeyInvalid)

	short := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(short, secrets.MasterKeyFile),
		[]byte(base64.StdEncoding.EncodeToString([]byte("sixteen byte key"))), 0o400))
	_, err = secrets.LoadOrCreateMasterKey(ctx, d.App, short, now)
	assert.ErrorIs(t, err, secrets.ErrMasterKeyInvalid)
}

// C10: the key file must be a regular file we own, never a symlink or special file.
func TestKeyFileSymlinkIsRefused(t *testing.T) {
	d := pgtest.New(t)
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "real.key")
	require.NoError(t, os.WriteFile(target, []byte(base64.StdEncoding.EncodeToString(testKey(7))), 0o400))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, secrets.MasterKeyFile)))

	_, err := secrets.LoadOrCreateMasterKey(context.Background(), d.App, dir, now)
	require.ErrorIs(t, err, secrets.ErrMasterKeyInvalid)
	assert.Contains(t, err.Error(), "symlink")
	assert.Equal(t, 0, versionRows(t, d))
}

func TestKeyFileNonRegularIsRefused(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()

	asDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(asDir, secrets.MasterKeyFile), 0o700))
	_, err := secrets.LoadOrCreateMasterKey(ctx, d.App, asDir, now)
	require.ErrorIs(t, err, secrets.ErrMasterKeyInvalid)
	assert.Contains(t, err.Error(), "regular file")

	asFifo := t.TempDir()
	require.NoError(t, syscall.Mkfifo(filepath.Join(asFifo, secrets.MasterKeyFile), 0o400))
	_, err = secrets.LoadOrCreateMasterKey(ctx, d.App, asFifo, now) // must not block on open
	require.ErrorIs(t, err, secrets.ErrMasterKeyInvalid)
	assert.Equal(t, 0, versionRows(t, d))
}

func TestKeyFileWithWrongOwnerIsRefused(t *testing.T) {
	d := pgtest.New(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, secrets.MasterKeyFile),
		[]byte(base64.StdEncoding.EncodeToString(testKey(8))), 0o400))

	restore := secrets.SetGeteuidForTest(func() int { return os.Geteuid() + 1 })
	defer restore()
	_, err := secrets.LoadOrCreateMasterKey(context.Background(), d.App, dir, now)
	require.ErrorIs(t, err, secrets.ErrMasterKeyPermissions)
	assert.Contains(t, err.Error(), "owned by")
	assert.Equal(t, 0, versionRows(t, d))
}

// AUD-20: a key file found without a version row (an installer's file, or one a failed first start
// left behind) is adopted only after its directory entry is durable; when the sync fails, the
// start fails and records nothing, and the next start syncs and adopts the same file.
func TestAdoptedKeyFileIsRecordedOnlyAfterItsDirectorySync(t *testing.T) {
	d := pgtest.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, secrets.MasterKeyFile)
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(testKey(6))+"\n"), 0o400))

	var synced []string
	restore := secrets.SetSyncDirForTest(func(d string) error {
		synced = append(synced, d)
		return syscall.EINVAL
	})
	_, err := secrets.LoadOrCreateMasterKey(context.Background(), d.App, dir, now)
	restore()
	require.ErrorIs(t, err, syscall.EINVAL)
	assert.Contains(t, err.Error(), "sync keys directory")
	assert.Equal(t, []string{dir}, synced)
	assert.Equal(t, 0, versionRows(t, d), "nothing is recorded before the directory is synced")

	k, err := secrets.LoadOrCreateMasterKey(context.Background(), d.App, dir, now)
	require.NoError(t, err)
	want, err := secrets.NewKeyring(1, testKey(6))
	require.NoError(t, err)
	check, err := want.KeyCheck()
	require.NoError(t, err)
	assert.NoError(t, k.VerifyKeyCheck(check))
	assert.Equal(t, 1, versionRows(t, d))
}
