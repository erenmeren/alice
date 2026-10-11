package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/backup/format"
	"alice/internal/platform/db"
)

// The codes of Info.Code for a file whose Check is CheckUnreadable.
const (
	codePermissionDenied = "permission_denied"
	codeUnreadableIO     = "io"
)

// maxCached bounds the shallow-check cache; a directory with more backups than this still lists correctly, only
// with more hashing.
const maxCached = 512

// fileSig is what a cached shallow check depends on: the backup file and its checksum file, each by size, mtime,
// ctime and inode. Any write, rename over, touch or chmod of either changes it.
type fileSig struct {
	size, mtime, ctime int64
	dev, ino           uint64
	sum                bool // the checksum file exists
	sumSize, sumMtime  int64
	sumCtime           int64
	sumIno             uint64
}

func statSig(fi os.FileInfo) (size, mtime, ctime int64, dev, ino uint64) {
	size, mtime = fi.Size(), fi.ModTime().UnixNano()
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		ctime = st.Ctim.Sec*int64(time.Second) + st.Ctim.Nsec
		dev, ino = st.Dev, st.Ino
	}
	return size, mtime, ctime, dev, ino
}

// signature describes the open backup fi and the checksum file beside path as they are now.
func signature(fi os.FileInfo, path string) fileSig {
	var sig fileSig
	sig.size, sig.mtime, sig.ctime, sig.dev, sig.ino = statSig(fi)
	if sfi, err := os.Lstat(path + ChecksumExt); err == nil {
		sig.sum = true
		sig.sumSize, sig.sumMtime, sig.sumCtime, _, sig.sumIno = statSig(sfi)
	}
	return sig
}

// checkCache holds the shallow check of the backups of Dir, so List, Prune and the Backups tab do not re-read every
// byte of every backup on every call (review I-1). An entry is used only while the file and its checksum file are
// exactly as they were when it was computed.
type checkCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry // by path
}

type cacheEntry struct {
	sig  fileSig
	info Info
}

func (c *checkCache) get(path string, sig fileSig) (Info, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[path]
	if !ok || e.sig != sig {
		return Info{}, false
	}
	return e.info, true
}

func (c *checkCache) put(path string, sig fileSig, info Info) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]cacheEntry{}
	}
	if _, ok := c.entries[path]; !ok && len(c.entries) >= maxCached {
		clear(c.entries)
	}
	c.entries[path] = cacheEntry{sig: sig, info: info}
}

// retain drops the entries of files that are no longer listed.
func (c *checkCache) retain(paths map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p := range c.entries {
		if !paths[p] {
			delete(c.entries, p)
		}
	}
}

// The cache modes of verify.
const (
	cacheNone  = iota // Verify: an explicit check always hashes and leaves the cache alone
	cacheStore        // Open: always hashes, and refreshes the cache
	cacheUse          // List: uses a matching entry, else hashes and stores
)

// Verify is the shallow check without the passphrase (R43 row 4): the header parses within the bounds, the size fits
// the chunk framing, and the .sha256 file matches. It always reads the whole file. Only a missing file is an error
// (ErrNotFound); every other finding is in Info.Check, and an error to read the file is returned as such.
func (s *Service) Verify(_ context.Context, path string) (Info, error) {
	return s.verify(path, cacheNone)
}

func (s *Service) verify(path string, mode int) (Info, error) {
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
	sig := signature(fi, path)
	if mode == cacheUse {
		if info, ok := s.cache.get(path, sig); ok {
			return info, nil
		}
	}
	info, err := s.check(f, fi, path)
	if err != nil {
		return Info{}, err
	}
	if mode != cacheNone {
		// Stored only when nothing changed while the file was read.
		if after, err := f.Stat(); err == nil && signature(after, path) == sig {
			s.cache.put(path, sig, info)
		}
	}
	return info, nil
}

// check is the shallow check of the open file f.
func (s *Service) check(f *os.File, fi os.FileInfo, path string) (Info, error) {
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
	if s.hashed != nil {
		s.hashed(info.Name)
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

// unreadable is the entry of a backup List could not read: its name, size and time from the directory, Check
// CheckUnreadable and a code, never the error text (review I-2).
func unreadable(path string, fi os.FileInfo, err error) Info {
	code := codeUnreadableIO
	if errors.Is(err, fs.ErrPermission) {
		code = codePermissionDenied
	}
	info := Info{Name: filepath.Base(path), Path: path, Check: CheckUnreadable, Code: code}
	if fi != nil {
		info.Size, info.CreatedAt = fi.Size(), fi.ModTime().UTC()
	}
	return info
}

// List returns every backup in Dir, newest first, each with its shallow check (cached while the file and its checksum
// file do not change). A file that cannot be read is listed with Check CheckUnreadable; it never fails the list.
func (s *Service) List(_ context.Context) ([]Info, error) {
	entries, err := os.ReadDir(s.c.Dir)
	if err != nil {
		return nil, fmt.Errorf("backup: read the backups directory: %w", err)
	}
	var out []Info
	seen := map[string]bool{}
	for _, en := range entries {
		if !en.Type().IsRegular() || !ValidName(en.Name()) {
			continue
		}
		path := filepath.Join(s.c.Dir, en.Name())
		info, err := s.verify(path, cacheUse)
		if errors.Is(err, ErrNotFound) {
			continue // removed meanwhile
		}
		if err != nil {
			fi, _ := en.Info()
			info = unreadable(path, fi, err)
			s.c.Log.Warn("a backup file cannot be read", "event", "backup.unreadable", "name", info.Name, "code", info.Code)
		}
		seen[path] = true
		out = append(out, info)
	}
	s.cache.retain(seen)
	slices.SortStableFunc(out, func(a, b Info) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.Name, a.Name)
	})
	return out, nil
}

// Open opens a backup of Dir for the download, with a full shallow check of that file. A name that fails ValidName, a
// missing file, a symbolic link or anything but a regular file is ErrNotFound; nothing outside Dir is ever opened.
func (s *Service) Open(_ context.Context, name string) (*os.File, Info, error) {
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
	info, err := s.verify(filepath.Join(s.c.Dir, name), cacheStore)
	if err != nil {
		_ = f.Close()
		return nil, Info{}, err
	}
	return f, info, nil
}

// Prune keeps the newest keep automatic backups whose checksum matches and deletes the older ones with their
// checksum files, each deletion audited backup.deleted. Other kinds, unverified and unreadable files are never
// deleted and never counted as kept.
func (s *Service) Prune(ctx context.Context, keep int, actor audit.Actor) (int, error) {
	return s.prune(ctx, keep, actor, "")
}

// prune is Prune that never deletes the backup named made (the one just created) and counts it as kept, so a clock
// set backwards, which sorts the new backup below older ones stamped "in the future", cannot delete it. The newest
// verified backup by its header is kept as well.
func (s *Service) prune(ctx context.Context, keep int, actor audit.Actor, made string) (int, error) {
	if keep < 1 {
		return 0, errors.New("backup: retention must keep at least one backup")
	}
	list, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	var candidates []Info
	for _, info := range list {
		if info.Kind == KindAuto && info.Check == CheckOK && standardName.MatchString(info.Name) {
			candidates = append(candidates, info)
		}
	}
	protected := map[string]bool{}
	if len(candidates) > 0 {
		protected[candidates[0].Name] = true
	}
	for _, c := range candidates {
		if c.Name == made {
			protected[made] = true
		}
	}
	kept, deleted := len(protected), 0
	var errs []error
	for _, info := range candidates {
		if protected[info.Name] {
			continue
		}
		if kept < keep {
			kept++
			continue
		}
		if err := s.deleteBackup(ctx, info, actor); err != nil {
			errs = append(errs, err)
			continue
		}
		deleted++
	}
	if deleted > 0 {
		if err := syncDir(s.c.Dir); err != nil {
			errs = append(errs, fmt.Errorf("backup: sync the backups directory: %w", err))
		}
	}
	return deleted, errors.Join(errs...)
}

// deleteBackup removes a backup and its checksum file, then audits backup.deleted. The file goes first: an audit row
// is never written for a deletion that did not happen, at the cost of a deletion without its row when the audit append
// fails afterwards (review minor 11).
func (s *Service) deleteBackup(ctx context.Context, info Info, actor audit.Actor) error {
	if err := os.Remove(info.Path); err != nil {
		return fmt.Errorf("backup: delete %s: %w", info.Name, err)
	}
	if err := os.Remove(info.Path + ChecksumExt); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("backup: delete %s: %w", info.Name+ChecksumExt, err)
	}
	return db.InTx(ctx, s.c.Pool, func(tx pgx.Tx) error {
		_, err := s.c.Audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "backup.deleted", ObjectType: "backup",
			ObjectID: info.Name, Result: audit.Success,
			Details: map[string]string{"name": info.Name, "kind": string(info.Kind), "deleted_count": "1"}})
		return err
	})
}

// partialMaxAge is how old a partial file must be before a scheduled run removes it: far longer than any backup
// takes, so a running backup's partial file is never touched.
const partialMaxAge = 24 * time.Hour

// sweepPartials removes the .<name>.partial and .<name>.sha256.partial files older than partialMaxAge, which a
// process killed mid-backup leaves behind (review minor 1).
func (s *Service) sweepPartials() {
	entries, err := os.ReadDir(s.c.Dir)
	if err != nil {
		return
	}
	cutoff := s.c.Clock.Now().Add(-partialMaxAge)
	removed := 0
	for _, en := range entries {
		if !en.Type().IsRegular() || !partialName(en.Name()) {
			continue
		}
		fi, err := en.Info()
		if err != nil || !fi.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(s.c.Dir, en.Name())); err == nil {
			removed++
		}
	}
	if removed > 0 {
		s.c.Log.Info("removed partial backup files left by an interrupted backup", "event", "backup.partials_removed",
			"count", strconv.Itoa(removed))
	}
}

// partialName reports whether name is ".<backup name>.partial" or ".<backup name>.sha256.partial".
func partialName(name string) bool {
	base, ok := strings.CutPrefix(name, ".")
	if !ok {
		return false
	}
	if base, ok = strings.CutSuffix(base, ".partial"); !ok {
		return false
	}
	return ValidName(strings.TrimSuffix(base, ChecksumExt))
}
