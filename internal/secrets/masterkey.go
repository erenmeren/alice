package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// MasterKeyFile is the file name of the current master key inside the keys
// directory. Content: base64 (standard encoding) of 32 random bytes plus "\n".
const MasterKeyFile = "master.key"

var (
	// ErrMasterKeyMissing: the database holds encrypted data but the key file is gone.
	ErrMasterKeyMissing = errors.New("the master key file is missing but this database already holds encrypted data")
	// ErrMasterKeyPermissions: the key file is readable or writable by more than its owner, or owned by someone else (SEC-042).
	ErrMasterKeyPermissions = errors.New("the master key file permissions are too open")
	// ErrMasterKeyInvalid: the key file is not a regular file or does not contain a base64-encoded 32-byte key.
	ErrMasterKeyInvalid = errors.New("the master key file is not valid")
)

const masterKeyVersion = 1

// geteuid is the effective-UID lookup for the owner check; tests replace it.
var geteuid = os.Geteuid

// LoadOrCreateMasterKey returns the keyring for the master key in dir.
//
//   - No master_key_versions row and no file: a first start. A new key is
//     written with mode 0400 (never over an existing file) and version 1 is recorded.
//   - No row but a file (created by an installer): the file is adopted.
//   - A row but no file: ErrMasterKeyMissing. A new key is never generated,
//     because it could not decrypt the existing data (F-71).
//   - A row and a file: the file must be a regular file (not a symlink) owned
//     by the running user with mode 0400 or stricter, and the key must match
//     the stored key check (ErrMasterKeyMismatch otherwise).
func LoadOrCreateMasterKey(ctx context.Context, q db.Querier, dir string, now time.Time) (*Keyring, error) {
	path := filepath.Join(dir, MasterKeyFile)
	check, found, err := currentKeyCheck(ctx, q)
	if err != nil {
		return nil, err
	}
	_, statErr := os.Lstat(path)
	fileExists := statErr == nil
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return nil, fmt.Errorf("read master key file %s: %w", path, statErr)
	}

	switch {
	case found && !fileExists:
		return nil, fmt.Errorf("%w: expected %s. Restore the key file from your backup; Alice will not create a new key because it could not decrypt existing data", ErrMasterKeyMissing, path)
	case found:
		k, err := loadKeyFile(path)
		if err != nil {
			return nil, err
		}
		if err := k.VerifyKeyCheck(check); err != nil {
			return nil, fmt.Errorf("%w: %s belongs to another installation or was replaced", ErrMasterKeyMismatch, path)
		}
		return k, nil
	case !fileExists:
		if err := createKeyFile(dir, path); err != nil {
			return nil, err
		}
	default:
		// An adopted file (an installer's, or one a failed first start left behind): its directory entry
		// may never have been synced, and the database is about to start depending on it (AUD-20).
		if err := syncDir(dir); err != nil {
			return nil, fmt.Errorf("sync keys directory %s: %w", dir, err)
		}
	}
	k, err := loadKeyFile(path)
	if err != nil {
		return nil, err
	}
	return k, recordVersion(ctx, q, k, now)
}

func currentKeyCheck(ctx context.Context, q db.Querier) ([]byte, bool, error) {
	var check []byte
	err := q.QueryRow(ctx,
		"SELECT key_check FROM master_key_versions WHERE version = $1", masterKeyVersion).Scan(&check)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read master key versions: %w", err)
	}
	return check, true, nil
}

// recordVersion inserts the key check. When another process won the race,
// its row is verified against our key instead.
func recordVersion(ctx context.Context, q db.Querier, k *Keyring, now time.Time) error {
	check, err := k.KeyCheck()
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx,
		"INSERT INTO master_key_versions (version, key_check, created_at) VALUES ($1, $2, $3) ON CONFLICT (version) DO NOTHING",
		masterKeyVersion, check, now.UTC()); err != nil {
		return fmt.Errorf("record master key version: %w", err)
	}
	stored, _, err := currentKeyCheck(ctx, q)
	if err != nil {
		return err
	}
	if err := k.VerifyKeyCheck(stored); err != nil {
		return fmt.Errorf("%w: another process recorded a different key", ErrMasterKeyMismatch)
	}
	return nil
}

// syncDir makes a new directory entry durable; tests replace it (AUD-20).
var syncDir = syncDirectory

func syncDirectory(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the keys directory from configuration, or its parent
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

func createKeyFile(dir, path string) error {
	_, statErr := os.Stat(dir)
	dirCreated := errors.Is(statErr, fs.ErrNotExist)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create keys directory %s: %w", dir, err)
	}
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate master key: %w", err)
	}
	defer clear(key)
	enc := []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	defer clear(enc)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o400) //nolint:gosec // G304: path is dir from configuration + fixed file name
	if errors.Is(err, fs.ErrExist) {
		// Another process created it first; it is loaded and verified next. Its directory entry may not
		// be durable yet, so this start syncs it too.
		if err := syncDir(dir); err != nil {
			return fmt.Errorf("sync keys directory %s: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("create master key file %s: %w", path, err)
	}
	if _, err := f.Write(enc); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write master key file %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync master key file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close master key file %s: %w", path, err)
	}
	// AUD-20: the file's own sync does not make its directory entry durable. Without this a power loss
	// right after the first start can lose the file while rows encrypted under it exist. An unsynced
	// file is left in place (another starting process may already use it): startup fails, and the
	// next start adopts the file and syncs the directory before recording it.
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync keys directory %s: %w", dir, err)
	}
	if dirCreated {
		if err := syncDir(filepath.Dir(dir)); err != nil {
			return fmt.Errorf("sync parent of keys directory %s: %w", dir, err)
		}
	}
	return nil
}

// checkKeyFileInfo enforces C10: a regular file (not a symlink), owned by the
// running user, with mode 0400 or stricter.
func checkKeyFileInfo(path string, info fs.FileInfo) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink; the key file must be a regular file", ErrMasterKeyInvalid, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrMasterKeyInvalid, path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not the running user (uid %d); run: chown %d %s", ErrMasterKeyPermissions, path, st.Uid, geteuid(), geteuid(), path)
	}
	if perm := info.Mode().Perm(); perm&^0o400 != 0 {
		return fmt.Errorf("%w: %s has mode %04o; run: chmod 0400 %s", ErrMasterKeyPermissions, path, perm, path)
	}
	return nil
}

func loadKeyFile(path string) (*Keyring, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read master key file %s: %w", path, err)
	}
	if err := checkKeyFileInfo(path, pathInfo); err != nil {
		return nil, err
	}
	// O_NOFOLLOW and O_NONBLOCK guard against the path being swapped after the Lstat.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: path is dir from configuration + fixed file name
	if err != nil {
		return nil, fmt.Errorf("read master key file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	openInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read master key file %s: %w", path, err)
	}
	if !os.SameFile(pathInfo, openInfo) {
		return nil, fmt.Errorf("%w: %s changed while it was being read", ErrMasterKeyInvalid, path)
	}
	if err := checkKeyFileInfo(path, openInfo); err != nil {
		return nil, err
	}
	raw := make([]byte, 1024) // a valid file is 45 bytes; anything larger is rejected below
	n, err := f.Read(raw)
	defer clear(raw)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("%w: %s is empty or unreadable", ErrMasterKeyInvalid, path)
	}
	raw = raw[:n]
	key := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	defer clear(key)
	dn, err := base64.StdEncoding.Decode(key, bytes.TrimSpace(raw))
	if err != nil || dn != KeySize {
		return nil, fmt.Errorf("%w: %s must contain a base64-encoded 32-byte key", ErrMasterKeyInvalid, path)
	}
	return NewKeyring(masterKeyVersion, key[:dn])
}
