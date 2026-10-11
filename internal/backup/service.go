// Package backup makes, lists, verifies and prunes Alice's encrypted backups (R4, SEC-048; C7, C8) and runs the daily
// schedule with its failure e-mail and 48-hour alarm (F-70, F-86..F-88). A backup is one streamed file: the container
// of internal/backup/format around a gzip of the frame stream of internal/backup/dump, written as .<name>.partial,
// synced, re-hashed and only then renamed. No plaintext of the payload ever reaches the disk.
package backup

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/backup/dump"
	"alice/internal/backup/format"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/secrets"
)

// Kind is the kind of a backup: "auto", "manual", "pre-restore" or "pre-upgrade-<version>".
type Kind string

// The fixed kinds.
const (
	KindAuto       Kind = "auto"
	KindManual     Kind = "manual"
	KindPreRestore Kind = "pre-restore"
)

// Errors of the backup service (C8).
var (
	ErrRunning       = errors.New("backup: another backup is running")            // ALC-BAK-0001
	ErrNotConfigured = errors.New("backup: no recovery passphrase has been set")  // ALC-BAK-0002
	ErrNotFound      = errors.New("backup: no such backup")                       // ALC-BAK-0003
	ErrWrite         = errors.New("backup: the backup file could not be written") // ALC-BAK-0004
	ErrVersion       = errors.New("backup: the schedule was changed meanwhile")   // ALC-SYS-0008
)

// Error codes recorded in backup.state.last_error_code and in backup.failed.
const (
	codeDiskFull      = "disk_full"
	codeNotConfigured = "not_configured"
	codeDatabase      = "database"
	codeIO            = "io"
	codeFileTooLarge  = "file_too_large"
)

// Settings keys.
const (
	keyBackupKey   = "backup.key"
	keySender      = "backup.sender"
	keyCompletedAt = "setup.completed_at"
)

// lockName is the advisory lock that allows one backup at a time per installation (R43 row 11).
const lockName = "alice.backup"

// minFreeExtra is added to twice the newest backup's size for the free-space check (R43 row 46).
const minFreeExtra = 1 << 30

// maxReasonRunes bounds the free-text reason of a backup.
const maxReasonRunes = 200

// gzipLevel is C7's compression level.
const gzipLevel = 6

// writeFile is a file Create writes: the partial backup or its partial checksum file.
type writeFile interface {
	io.Writer
	Sync() error
	Close() error
}

// Config holds the service's dependencies (C8).
type Config struct {
	Pool     *pgxpool.Pool // app role: dumps and state
	Audit    *audit.Log
	Notifier notify.AdminNotifier
	Clock    clock.Clock
	Dir      string // ALICE_BACKUP_DIR
	KeysDir  string
	StateDir string
	Version  string // the binary's version
	Hostname func() (string, error)
	Log      *slog.Logger
	Keyring  *secrets.Keyring // opens the sender key backup.sender (R43 row 41)
	// Zone is the schedule's default zone (ALICE_TZ, R43 row 10); nil = UTC.
	Zone   *time.Location
	create func(path string) (writeFile, error) // tests: disk-full injection (export_test.go)
	statfs func(dir string) (free uint64, err error)
}

// Service makes and manages backups.
type Service struct {
	c      Config
	inDump func() // tests: runs inside the snapshot, after the manifest (export_test.go)
}

// New builds the service.
func New(c Config) *Service {
	if c.Hostname == nil {
		c.Hostname = os.Hostname
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.Notifier.Clock == nil {
		c.Notifier.Clock = c.Clock
	}
	if c.Zone == nil {
		c.Zone = time.UTC
	}
	if c.create == nil {
		c.create = createFile
	}
	if c.statfs == nil {
		c.statfs = freeSpace
	}
	return &Service{c: c}
}

func createFile(path string) (writeFile, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: a name checked by ValidName in Dir
}

func freeSpace(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("backup: free space of %s: %w", dir, err)
	}
	return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // G115: the block size is positive
}

// Info describes a backup file.
type Info struct {
	Name, Path   string
	Kind         Kind
	Size         int64
	CreatedAt    time.Time
	AliceVersion string
	Check        string // "ok", "missing checksum", "checksum mismatch", "unreadable header"
}

// The values of Info.Check.
const (
	CheckOK               = "ok"
	CheckMissingChecksum  = "missing checksum"
	CheckChecksumMismatch = "checksum mismatch"
	CheckUnreadableHeader = "unreadable header"
)

// CreateInput is one backup to make. Out is a file name for --out ("" = the standard name).
type CreateInput struct {
	Kind   Kind
	Reason string
	Out    string
	Actor  audit.Actor
}

// failure is an error of Create with the code it records.
type failure struct {
	code string
	err  error
}

func (f *failure) Error() string { return f.err.Error() }
func (f *failure) Unwrap() error { return f.err }

func fail(code string, err error) error { return &failure{code: code, err: err} }

// writeFailure classifies an error of a file operation: ENOSPC is disk_full, anything else io.
func writeFailure(err error) error {
	code := codeIO
	if errors.Is(err, syscall.ENOSPC) {
		code = codeDiskFull
	}
	return fail(code, fmt.Errorf("%w: %w", ErrWrite, err))
}

func checkInput(in CreateInput) error {
	switch {
	case !ValidKind(in.Kind):
		return fmt.Errorf("%w: kind", errName)
	case in.Out != "" && !ValidName(in.Out):
		return errName
	case utf8.RuneCountInString(in.Reason) > maxReasonRunes || !utf8.ValidString(in.Reason) ||
		strings.ContainsFunc(in.Reason, unicode.IsControl):
		return errors.New("backup: the reason must be one line of at most 200 characters")
	}
	return nil
}

// Create makes one backup (C8's sequence): one at a time (ErrRunning), only with a version 2 backup key and its
// sender key (ErrNotConfigured), only with enough free space, streamed into .<name>.partial, synced, re-hashed,
// renamed, with its checksum file beside it; audited backup.created and recorded in backup.state, and for an auto
// backup followed by pruning. Any failure removes the partial files, is audited backup.failed and recorded in
// backup.state (with the failure e-mail for a scheduled backup) and returns ErrNotConfigured or ErrWrite.
func (s *Service) Create(ctx context.Context, in CreateInput) (Info, error) {
	if err := checkInput(in); err != nil {
		return Info{}, err
	}
	conn, err := s.c.Pool.Acquire(ctx)
	if err != nil {
		return Info{}, fmt.Errorf("backup: database connection: %w", err)
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext($1))", lockName).Scan(&locked); err != nil {
		return Info{}, fmt.Errorf("backup: take the backup lock: %w", err)
	}
	if !locked {
		return Info{}, ErrRunning
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock(hashtext($1))", lockName); err != nil {
			_ = conn.Conn().Close(context.WithoutCancel(ctx)) // a closed session releases its locks
		}
	}()

	info, err := s.write(ctx, in)
	if err != nil {
		code := codeDatabase
		var f *failure
		if errors.As(err, &f) {
			code = f.code
		} else {
			err = fmt.Errorf("%w: %w", ErrWrite, err)
		}
		s.c.Log.Error("backup failed", "event", "backup.failed", "kind", string(in.Kind), "reason", code,
			"error_type", fmt.Sprintf("%T", errors.Unwrap(err)))
		if rerr := s.recordFailure(ctx, in, code); rerr != nil {
			s.c.Log.Error("could not record a failed backup", "error_type", fmt.Sprintf("%T", rerr))
		}
		return Info{}, err
	}
	if err := s.recordSuccess(ctx, in, info); err != nil {
		return info, err
	}
	if in.Kind == KindAuto {
		sch, err := s.Schedule(ctx)
		if err == nil {
			_, err = s.Prune(ctx, sch.Retention, in.Actor)
		}
		if err != nil {
			s.c.Log.Error("could not prune old backups", "error_type", fmt.Sprintf("%T", err))
		}
	}
	return info, nil
}

// keys returns the backup key and the sender private key. Any missing or mismatched part is ErrNotConfigured.
func (s *Service) keys(ctx context.Context) (format.WrappedKey, *ecdh.PrivateKey, error) {
	var w format.WrappedKey
	found, err := settings.Get(ctx, s.c.Pool, keyBackupKey, &w)
	if err != nil {
		return w, nil, fail(codeDatabase, err)
	}
	notConfigured := func(why string) error {
		return fail(codeNotConfigured, fmt.Errorf("%w (%s)", ErrNotConfigured, why))
	}
	if !found {
		return w, nil, notConfigured("no backup key")
	}
	if w.Version != secrets.BackupKeyVersion {
		return w, nil, notConfigured("the backup key is of version " + strconv.Itoa(w.Version) + "; run the setup wizard again")
	}
	pt, ok, err := s.c.Keyring.GetSetting(ctx, s.c.Pool, keySender)
	if err != nil {
		if errors.Is(err, secrets.ErrDecrypt) {
			return w, nil, notConfigured("the sender key does not open")
		}
		return w, nil, fail(codeDatabase, err)
	}
	if !ok {
		return w, nil, notConfigured("no sender key")
	}
	defer pt.Zero()
	sender, err := ecdh.X25519().NewPrivateKey(pt.Bytes())
	if err != nil || !bytes.Equal(sender.PublicKey().Bytes(), w.SenderPublicKey) {
		return w, nil, notConfigured("the sender key does not belong to the backup key")
	}
	return w, sender, nil
}

func (s *Service) installationID(ctx context.Context, q db.Querier) (string, error) {
	var id string
	if err := q.QueryRow(ctx, "SELECT installation_id FROM license WHERE id = 1").Scan(&id); err != nil {
		return "", fail(codeDatabase, fmt.Errorf("backup: read the installation ID: %w", err))
	}
	return id, nil
}

// errWriter remembers the first write error of the file, so a failed dump can tell a full disk from a database
// error.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	n, err := e.w.Write(p)
	if err != nil && e.err == nil {
		e.err = err
	}
	return n, err
}

// write makes the file and its checksum file; on any error it leaves nothing behind.
func (s *Service) write(ctx context.Context, in CreateInput) (Info, error) {
	wrapped, sender, err := s.keys(ctx)
	if err != nil {
		return Info{}, err
	}
	now := s.c.Clock.Now().UTC().Truncate(time.Second)
	id, err := s.installationID(ctx, s.c.Pool)
	if err != nil {
		return Info{}, err
	}
	name := in.Out
	if name == "" {
		if name, err = FileName(id, now, in.Kind); err != nil {
			return Info{}, fail(codeDatabase, err)
		}
	}
	final := filepath.Join(s.c.Dir, name)
	if _, err := os.Lstat(final); err == nil {
		return Info{}, fail(codeIO, fmt.Errorf("%w: %s already exists", ErrWrite, name))
	}
	if err := s.checkFreeSpace(); err != nil {
		return Info{}, err
	}
	files, err := s.readFiles()
	if err != nil {
		return Info{}, err
	}
	defer func() {
		for _, f := range files {
			clear(f.data)
		}
	}()

	partial := filepath.Join(s.c.Dir, "."+name+".partial")
	sum, err := s.writePartial(ctx, partial, wrapped, sender, format.Meta{AliceVersion: s.c.Version, CreatedAt: now, Kind: string(in.Kind)},
		func(enc *dump.Encoder) error { return s.payload(ctx, enc, in, now, id, files) })
	if err != nil {
		_ = os.Remove(partial)
		return Info{}, err
	}
	if err := os.Rename(partial, final); err != nil {
		_ = os.Remove(partial)
		return Info{}, writeFailure(err)
	}
	if err := s.writeChecksum(name, sum); err != nil {
		_ = os.Remove(final)
		return Info{}, err
	}
	if err := syncDir(s.c.Dir); err != nil {
		_ = os.Remove(final + ChecksumExt)
		_ = os.Remove(final)
		return Info{}, writeFailure(err)
	}
	fi, err := os.Stat(final)
	if err != nil {
		return Info{}, writeFailure(err)
	}
	return Info{Name: name, Path: final, Kind: in.Kind, Size: fi.Size(), CreatedAt: now, AliceVersion: s.c.Version, Check: CheckOK}, nil
}

// writePartial streams the backup into path and returns the SHA-256 it computed while writing, after it re-read the
// synced file and found the same hash.
func (s *Service) writePartial(ctx context.Context, path string, wrapped format.WrappedKey, sender *ecdh.PrivateKey, meta format.Meta,
	payload func(*dump.Encoder) error) ([]byte, error) {
	f, err := s.c.create(path)
	if err != nil {
		return nil, writeFailure(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	h := sha256.New()
	ew := &errWriter{w: f}
	fw, err := format.NewWriter(io.MultiWriter(ew, h), wrapped, sender, meta)
	if err != nil {
		if ew.err != nil {
			return nil, writeFailure(ew.err)
		}
		return nil, fail(codeIO, fmt.Errorf("%w: %w", ErrWrite, err))
	}
	gz, err := gzip.NewWriterLevel(fw, gzipLevel)
	if err != nil {
		return nil, fail(codeIO, err)
	}
	enc := dump.NewEncoder(gz)
	err = payload(enc)
	if err == nil {
		err = enc.Flush()
	}
	if err == nil {
		err = gz.Close()
	}
	if err == nil {
		err = fw.Close()
	}
	if err == nil {
		err = f.Sync()
	}
	if ew.err != nil {
		return nil, writeFailure(ew.err)
	}
	if err != nil {
		var fl *failure
		if errors.As(err, &fl) {
			return nil, err
		}
		if errors.Is(err, syscall.ENOSPC) {
			return nil, writeFailure(err)
		}
		return nil, fail(codeDatabase, fmt.Errorf("%w: %w", ErrWrite, err))
	}
	closed = true
	if err := f.Close(); err != nil {
		return nil, writeFailure(err)
	}
	sum := h.Sum(nil)
	again, err := hashFile(path)
	if err != nil {
		return nil, writeFailure(err)
	}
	if !bytes.Equal(sum, again) {
		return nil, fail(codeIO, fmt.Errorf("%w: the written file does not read back", ErrWrite))
	}
	return sum, nil
}

// payload writes the manifest, the dump, the files and the end frame, all from one REPEATABLE READ snapshot (F-86).
func (s *Service) payload(ctx context.Context, enc *dump.Encoder, in CreateInput, now time.Time, id string, files []fileData) error {
	tx, err := s.c.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fail(codeDatabase, err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	m, tables, err := s.manifest(ctx, tx, in, now, id, files)
	if err != nil {
		return err
	}
	if err := enc.JSON(dump.Manifest, "manifest.json", m); err != nil {
		return err
	}
	if s.inDump != nil {
		s.inDump()
	}
	st, err := dump.Dump(ctx, tx, enc, tables)
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := enc.Frame(dump.File, f.name, f.data); err != nil {
			return err
		}
	}
	return enc.JSON(dump.End, "end", endFrame{Tables: st.Tables, Files: len(files)})
}

func (s *Service) manifest(ctx context.Context, tx pgx.Tx, in CreateInput, now time.Time, id string, files []fileData) (Manifest, []dump.Table, error) {
	version, err := db.SchemaVersion(ctx, tx)
	if err != nil {
		return Manifest{}, nil, fail(codeDatabase, err)
	}
	tables, err := dump.Tables(ctx, tx)
	if err != nil {
		return Manifest{}, nil, fail(codeDatabase, err)
	}
	counts, err := dump.Counts(ctx, tx, tables)
	if err != nil {
		return Manifest{}, nil, fail(codeDatabase, err)
	}
	var head AuditHead
	var headHash []byte
	err = tx.QueryRow(ctx, "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&head.Seq, &headHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Manifest{}, nil, fail(codeDatabase, err)
	}
	head.Hash = hex.EncodeToString(headHash)
	host, err := s.c.Hostname()
	if err != nil {
		host = ""
	}
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f.name
	}
	return Manifest{Format: ManifestFormat, AliceVersion: s.c.Version, SchemaVersion: version, CreatedAt: now, Kind: in.Kind,
		Reason: in.Reason, InstallationID: id, Hostname: host, Tables: counts, AuditHead: head, Files: names}, tables, nil
}

// fileData is one file read for the payload.
type fileData struct {
	name string
	data []byte
}

// tlsTries is how often the TLS pair is re-read when the key does not match the certificate (a renewal may be
// replacing both files at that moment; S-14).
const tlsTries = 3

// readFiles reads the payload files of the fixed table: master.key must exist; tls.crt and tls.key are taken only as
// a matching pair; hwm.dat when present. Each is at most dump.MaxData bytes (else file_too_large).
func (s *Service) readFiles() ([]fileData, error) {
	var out []fileData
	for _, p := range payloadFiles {
		if p.File == "tls.crt" || p.File == "tls.key" {
			continue
		}
		dir := s.c.StateDir
		if p.InKeys {
			dir = s.c.KeysDir
		}
		b, err := readSmall(filepath.Join(dir, p.File))
		switch {
		case errors.Is(err, os.ErrNotExist) && p.Optional:
			continue
		case err != nil:
			for _, f := range out {
				clear(f.data)
			}
			return nil, err
		}
		out = append(out, fileData{name: p.Name, data: b})
		if p.File == "master.key" {
			pair, err := s.readTLSPair()
			if err != nil {
				clear(b)
				return nil, err
			}
			out = append(out, pair...)
		}
	}
	return out, nil
}

func (s *Service) readTLSPair() ([]fileData, error) {
	for range tlsTries {
		crt, err := readSmall(filepath.Join(s.c.KeysDir, "tls.crt"))
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		key, err := readSmall(filepath.Join(s.c.KeysDir, "tls.key"))
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if _, err := tls.X509KeyPair(crt, key); err == nil {
			return []fileData{{name: "keys/tls.crt", data: crt}, {name: "keys/tls.key", data: key}}, nil
		}
		clear(key)
	}
	s.c.Log.Warn("the HTTPS certificate and key do not match; the backup leaves both out", "event", "backup.tls_pair_skipped")
	return nil, nil
}

// readSmall reads a file of at most dump.MaxData bytes without following a symbolic link.
func readSmall(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a fixed file name in a configured directory
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fail(codeIO, fmt.Errorf("%w: read %s: %w", ErrWrite, filepath.Base(path), err))
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, dump.MaxData+1))
	if err != nil {
		return nil, fail(codeIO, fmt.Errorf("%w: read %s: %w", ErrWrite, filepath.Base(path), err))
	}
	if len(b) > dump.MaxData {
		clear(b)
		return nil, fail(codeFileTooLarge, fmt.Errorf("%w: %s is larger than 1 MiB", ErrWrite, filepath.Base(path)))
	}
	return b, nil
}

// checkFreeSpace refuses a backup when Dir has less than twice the newest backup plus 1 GiB free (R43 row 46).
func (s *Service) checkFreeSpace() error {
	free, err := s.c.statfs(s.c.Dir)
	if err != nil {
		return fail(codeIO, fmt.Errorf("%w: %w", ErrWrite, err))
	}
	var newest int64
	var newestAt time.Time
	entries, err := os.ReadDir(s.c.Dir)
	if err != nil {
		return writeFailure(err)
	}
	for _, en := range entries {
		if !en.Type().IsRegular() || !ValidName(en.Name()) {
			continue
		}
		fi, err := en.Info()
		if err != nil {
			continue
		}
		if fi.ModTime().After(newestAt) {
			newest, newestAt = fi.Size(), fi.ModTime()
		}
	}
	need := 2*uint64(newest) + minFreeExtra //nolint:gosec // G115: a file size is not negative
	if free < need {
		return fail(codeDiskFull, fmt.Errorf("%w: %d bytes free, %d needed", ErrWrite, free, need))
	}
	return nil
}

// FreeBytes returns the free space of the backups directory (Backups tab, S-21).
func (s *Service) FreeBytes() (uint64, error) { return s.c.statfs(s.c.Dir) }

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a backup path in Dir
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// writeChecksum writes <name>.sha256 (the partial-then-rename rule of the backup itself).
func (s *Service) writeChecksum(name string, sum []byte) error {
	final := filepath.Join(s.c.Dir, name+ChecksumExt)
	partial := filepath.Join(s.c.Dir, "."+name+ChecksumExt+".partial")
	f, err := s.c.create(partial)
	if err != nil {
		return writeFailure(err)
	}
	_, err = io.WriteString(f, hex.EncodeToString(sum)+"  "+name+"\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(partial, final)
	}
	if err != nil {
		_ = os.Remove(partial)
		return writeFailure(err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the configured backups directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Verify is the shallow check without the passphrase (R43 row 4): the header parses within the bounds, the size fits
// the chunk framing, and the .sha256 file matches. Only a missing file is an error (ErrNotFound); every other finding
// is in Info.Check.
func (s *Service) Verify(_ context.Context, path string) (Info, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the path of a backup the operator named
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Info{}, ErrNotFound
		}
		return Info{}, fmt.Errorf("backup: open %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return Info{}, fmt.Errorf("backup: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Info{}, ErrNotFound
	}
	info := Info{Name: filepath.Base(path), Path: path, Size: fi.Size(), CreatedAt: fi.ModTime().UTC(), Check: CheckUnreadableHeader}
	cr := &countingReader{r: f}
	h, err := format.ReadHeader(cr)
	if err != nil {
		return info, nil
	}
	info.Kind, info.CreatedAt, info.AliceVersion = Kind(h.Kind), h.CreatedAt.UTC(), h.AliceVersion
	if rest := fi.Size() - cr.n; rest%int64(format.ChunkSize+16) < 16 {
		return info, nil // a final chunk always has its 16-byte tag and less than a full chunk
	}
	want, err := readChecksum(path, info.Name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		info.Check = CheckMissingChecksum
		return info, nil
	case err != nil:
		info.Check = CheckChecksumMismatch
		return info, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Info{}, fmt.Errorf("backup: %w", err)
	}
	hs := sha256.New()
	if _, err := io.Copy(hs, f); err != nil {
		return Info{}, fmt.Errorf("backup: read %s: %w", info.Name, err)
	}
	info.Check = CheckChecksumMismatch
	if bytes.Equal(hs.Sum(nil), want) {
		info.Check = CheckOK
	}
	return info, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// readChecksum reads <path>.sha256: "<64 hex>  <name>\n".
func readChecksum(path, name string) ([]byte, error) {
	b, err := readSmall(path + ChecksumExt)
	if err != nil {
		return nil, err
	}
	line, ok := strings.CutSuffix(string(b), "\n")
	sumHex, file, found := strings.Cut(line, "  ")
	if !ok || !found || file != name || len(sumHex) != 2*sha256.Size {
		return nil, errors.New("backup: the checksum file is malformed")
	}
	return hex.DecodeString(sumHex)
}

// VerifyDeep decrypts the whole file with the passphrase and checks the payload against its manifest. A wrong
// passphrase or any damage is ErrDamaged (wrapping the cause); a file that is not a backup is format.ErrNotBackup and
// a newer format format.ErrNewerFormat.
func (s *Service) VerifyDeep(_ context.Context, path string, passphrase []byte) (Manifest, error) {
	return readPayload(path, passphrase, nil)
}

// List returns every backup in Dir, newest first, each with its shallow check.
func (s *Service) List(ctx context.Context) ([]Info, error) {
	entries, err := os.ReadDir(s.c.Dir)
	if err != nil {
		return nil, fmt.Errorf("backup: read the backups directory: %w", err)
	}
	var out []Info
	for _, en := range entries {
		if !en.Type().IsRegular() || !ValidName(en.Name()) {
			continue
		}
		info, err := s.Verify(ctx, filepath.Join(s.c.Dir, en.Name()))
		if errors.Is(err, ErrNotFound) {
			continue // removed meanwhile
		}
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	slices.SortStableFunc(out, func(a, b Info) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.Name, a.Name)
	})
	return out, nil
}

// Open opens a backup of Dir for the download. A name that fails ValidName, a missing file, a symbolic link or
// anything but a regular file is ErrNotFound; nothing outside Dir is ever opened.
func (s *Service) Open(ctx context.Context, name string) (*os.File, Info, error) {
	if !ValidName(name) {
		return nil, Info{}, ErrNotFound
	}
	root, err := os.OpenRoot(s.c.Dir)
	if err != nil {
		return nil, Info{}, fmt.Errorf("backup: open the backups directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	if fi, err := root.Lstat(name); err != nil || !fi.Mode().IsRegular() {
		return nil, Info{}, ErrNotFound
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, Info{}, ErrNotFound
	}
	info, err := s.Verify(ctx, filepath.Join(s.c.Dir, name))
	if err != nil {
		_ = f.Close()
		return nil, Info{}, err
	}
	return f, info, nil
}

// Prune keeps the newest keep automatic backups whose checksum matches and deletes the older ones with their
// checksum files, each deletion audited backup.deleted. Other kinds and unverified files are never deleted.
func (s *Service) Prune(ctx context.Context, keep int, actor audit.Actor) (int, error) {
	if keep < 1 {
		return 0, errors.New("backup: retention must keep at least one backup")
	}
	list, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	kept, deleted := 0, 0
	for _, info := range list {
		if info.Kind != KindAuto || info.Check != CheckOK || !standardName.MatchString(info.Name) {
			continue
		}
		if kept < keep {
			kept++
			continue
		}
		if err := os.Remove(info.Path); err != nil {
			return deleted, fmt.Errorf("backup: delete %s: %w", info.Name, err)
		}
		if err := os.Remove(info.Path + ChecksumExt); err != nil && !errors.Is(err, os.ErrNotExist) {
			return deleted, fmt.Errorf("backup: delete %s: %w", info.Name+ChecksumExt, err)
		}
		deleted++
		err := db.InTx(ctx, s.c.Pool, func(tx pgx.Tx) error {
			_, err := s.c.Audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "backup.deleted", ObjectType: "backup",
				ObjectID: info.Name, Result: audit.Success,
				Details: map[string]string{"name": info.Name, "kind": string(info.Kind), "deleted_count": "1"}})
			return err
		})
		if err != nil {
			return deleted, err
		}
	}
	if deleted > 0 {
		if err := syncDir(s.c.Dir); err != nil {
			return deleted, fmt.Errorf("backup: sync the backups directory: %w", err)
		}
	}
	return deleted, nil
}
