//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

// backupRetention is the helper's hard cap for backups (spec §12.6 step 8).
const backupRetention = 30 * 24 * time.Hour

// cmdCleanup removes the backups of one operation. An Nginx operation (a directory with a
// journal) is removed under the Nginx lock, and never while its journal says writing or
// restoring: those backups are what nginx-restore needs (S3).
func cmdCleanup(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 2 || args[0] != "--op" {
		return nil, refused(helperproto.CodeUsage, "usage: cleanup --op <operation id>")
	}
	op := args[1]
	if !helperproto.ValidOpID(op) {
		return nil, refused(helperproto.CodeInvalidArgument, "the operation id is not allowed")
	}
	s.syslog(helperproto.SubCleanup, helperproto.BackupRoot+"/"+op)
	root, err := s.openBackupRoot(false)
	if errors.Is(err, unix.ENOENT) {
		return helperproto.CleanupResponse{OK: true}, nil
	}
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backups cannot be opened")
	}
	defer func() { _ = root.Close() }()
	var st unix.Stat_t
	err = unix.Fstatat(int(root.Fd()), op, &st, unix.AT_SYMLINK_NOFOLLOW) //nolint:gosec // G115: a descriptor fits an int
	if errors.Is(err, unix.ENOENT) {
		return helperproto.CleanupResponse{OK: true}, nil
	}
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backups cannot be checked")
	}
	// An authorized_keys operation (only <n>.bak / <n>.json) and an empty directory are removed
	// without the Nginx lock, as before Phase 4 (an empty directory is removed only while it is
	// empty: a deployment that created it and has not written its journal yet then simply fails
	// its first write, nothing changed). Anything else is or could be an Nginx operation: it is
	// decided under the Nginx lock, the journal read under it.
	if err := unix.Unlinkat(int(root.Fd()), op, unix.AT_REMOVEDIR); err == nil { //nolint:gosec // G115: a descriptor fits an int
		_ = root.Sync()
		return helperproto.CleanupResponse{OK: true, Removed: 1}, nil
	}
	if !s.nginxOperation(root, op) && removeAuthKeysOp(root, op) {
		return helperproto.CleanupResponse{OK: true, Removed: 1}, nil
	}
	lock, err := s.nginxLock(ctx)
	if err != nil {
		return nil, failed(helperproto.CodeBusy, "a certificate change is running on this server")
	}
	defer func() { _ = lock.Close() }()
	if j, ok := s.nginxJournal(root, op); ok {
		if s.keepForRecovery(j, true) {
			return nil, failed(helperproto.CodeBusy, "the deployment is not finished; restore it before its backups are removed")
		}
		if !s.releaseRecord(j) {
			return nil, failed(helperproto.CodeIOError, "the record of the latest deployment cannot be updated")
		}
		s.cleanStaged(j)
	}
	if err := removeAt(root, op); err != nil {
		return nil, failed(helperproto.CodeIOError, "the backups cannot be removed")
	}
	return helperproto.CleanupResponse{OK: true, Removed: 1}, nil
}

// authKeysEntry matches the files authkeys-write keeps in an operation directory.
var authKeysEntry = regexp.MustCompile(`^[0-9]+\.(bak|json)$`)

// removeAuthKeysOp removes an authorized_keys operation directory without the Nginx lock: only
// <n>.bak and <n>.json are unlinked, then the directory is removed only if that left it empty.
// Anything else (an Nginx deployment that reused the id and wrote meanwhile) stays, and false
// sends the caller to the locked path.
func removeAuthKeysOp(root *os.File, name string) bool {
	dir, err := subdir(root, name, false)
	if err != nil {
		return false
	}
	names, err := dir.Readdirnames(-1)
	if err == nil {
		for _, n := range names {
			if authKeysEntry.MatchString(n) {
				_ = unix.Unlinkat(int(dir.Fd()), n, 0) //nolint:gosec // G115: a descriptor fits an int
			}
		}
	}
	_ = dir.Close()
	if unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR) != nil { //nolint:gosec // G115: a descriptor fits an int
		return false
	}
	_ = root.Sync()
	return true
}

// nginxOperation reports a directory that holds a name only an Nginx operation writes (or that
// cannot be listed: then it is treated as one).
func (s *sys) nginxOperation(root *os.File, name string) bool {
	dir, err := subdir(root, name, false)
	if err != nil {
		return true
	}
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(names, func(n string) bool { return slices.Contains(nginxEntries, n) })
}

// nginxJournal reads the journal of the operation directory name below root (ok false when it has
// none or it cannot be read).
func (s *sys) nginxJournal(root *os.File, name string) (journal, bool) {
	dir, err := subdir(root, name, false)
	if err != nil {
		return journal{}, false
	}
	defer func() { _ = dir.Close() }()
	j, found, err := readJournal(dir, name)
	return j, found && err == nil
}

// keepForRecovery reports an Nginx operation whose backups nginx-restore may still need: one
// interrupted (writing, restoring) and not superseded, or a restore_failed one nginx-restore could
// still act on (restorable). readKeys false (the sweep) decides the key file by fstatat only.
func (s *sys) keepForRecovery(j journal, readKeys bool) bool {
	switch j.Phase {
	case helperproto.PhaseWriting, helperproto.PhaseRestoring:
		sup, err := s.superseded(j)
		return err != nil || !sup
	case helperproto.PhaseRestoreFailed:
		return s.restorable(j, readKeys)
	}
	return false
}

// nginxEntries are the names only an Nginx operation directory holds.
var nginxEntries = []string{journalName, journalTmp, certBackup, keyBackup}

// sweepBackups removes old operation backup directories. It runs before every privileged
// subcommand; failures are ignored (they never block the call).
//
// A directory without a journal (authkeys-write backups) is removed after backupRetention. A
// directory with a journal is an Nginx operation, decided under the Nginx lock (skipped while
// another helper holds it): committed, unchanged, restored and prepared operations are removed
// after helperproto.NginxBackupKeep, restore_failed and unreadable journals after backupRetention,
// and an operation that keepForRecovery keeps (writing, restoring, a failed rollback whose pair
// still holds deployed content) is never removed, whatever its age (S3): its backups are the only
// way back to a consistent pair. Everything is decided under the Nginx lock (skipped while another
// helper holds it). The staged files an operation left next to its pair are removed with it (S2).
func (s *sys) sweepBackups() {
	root, err := s.openBackupRoot(false)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	names, err := root.Readdirnames(-1)
	if err != nil {
		return
	}
	var lock *os.File
	locked := false
	defer func() {
		if lock != nil {
			_ = lock.Close()
		}
	}()
	rfd := int(root.Fd()) //nolint:gosec // G115: a descriptor fits an int
	for _, name := range names {
		if !helperproto.ValidOpID(name) {
			continue
		}
		var st unix.Stat_t
		if unix.Fstatat(rfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		age := s.now().Sub(time.Unix(st.Mtim.Unix()))
		if age <= helperproto.NginxBackupKeep {
			continue
		}
		if !locked {
			lock, locked = s.tryNginxLock(), true
		}
		if lock == nil {
			return
		}
		if unix.Fstatat(rfd, name+"/"+journalName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
			if age > backupRetention {
				_ = removeAt(root, name)
			}
			continue
		}
		j, ok := s.nginxJournal(root, name)
		switch {
		case ok && s.keepForRecovery(j, false):
			continue
		case !ok, j.Phase == helperproto.PhaseRestoreFailed, j.Phase == helperproto.PhaseWriting, j.Phase == helperproto.PhaseRestoring:
			if age <= backupRetention {
				continue
			}
		}
		if ok {
			if !s.releaseRecord(j) {
				continue
			}
			s.cleanStaged(j)
		}
		_ = removeAt(root, name)
	}
}

// lockDirName is the directory of the key directory locks, next to the backups.
const lockDirName = "locks"

// lockName matches the lock files lockKeyDir creates (<dev>-<ino>.lock).
var lockName = regexp.MustCompile(`^[0-9]+-[0-9]+\.lock$`)

// sweepLocks removes lock files that no write used for backupRetention (their times are set on
// every use). A lock file is removed only while the sweep holds its flock, so it never pulls the
// lock away from a writer; a writer that waited for a removed file locks again (lockKeyDir).
// Failures are ignored, as for the backups.
func (s *sys) sweepLocks() {
	locks, err := s.openStateDir(lockDirName, false)
	if err != nil {
		return
	}
	defer func() { _ = locks.Close() }()
	ldfd := int(locks.Fd()) //nolint:gosec // G115: a descriptor fits an int
	names, err := locks.Readdirnames(-1)
	if err != nil {
		return
	}
	for _, name := range names {
		if !lockName.MatchString(name) {
			continue
		}
		var st unix.Stat_t
		if unix.Fstatat(ldfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG ||
			s.now().Sub(time.Unix(st.Mtim.Unix())) <= backupRetention {
			continue
		}
		f, err := openLockFile(ldfd, name, false)
		if err != nil {
			continue
		}
		var mine, now unix.Stat_t
		if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil && unix.Fstat(int(f.Fd()), &mine) == nil && //nolint:gosec // G115: a descriptor fits an int
			unix.Fstatat(ldfd, name, &now, unix.AT_SYMLINK_NOFOLLOW) == nil && sameFile(mine, now) &&
			s.now().Sub(time.Unix(now.Mtim.Unix())) > backupRetention {
			_ = unix.Unlinkat(ldfd, name, 0)
		}
		_ = f.Close()
	}
}

// openBackupRoot opens BackupRoot (with create: making it when missing).
func (s *sys) openBackupRoot(create bool) (*os.File, error) {
	return s.openStateDir(filepath.Base(helperproto.BackupRoot), create)
}

// openStateDir opens <state>/name, where <state> is the directory of BackupRoot
// (/var/lib/alice-helper), one component at a time below /var/lib, never following a symlink.
// With create, both helper-owned levels are created 0700 when missing. Both must belong to the
// helper's user (root).
func (s *sys) openStateDir(name string, create bool) (*os.File, error) {
	state := filepath.Dir(helperproto.BackupRoot)
	cur, err := os.OpenFile(s.host(filepath.Dir(state)), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, n := range []string{filepath.Base(state), name} {
		next, err := subdir(cur, n, create)
		_ = cur.Close()
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// subdir opens (with create: makes, when missing) a helper-owned 0700 directory below parent.
func subdir(parent *os.File, name string, create bool) (*os.File, error) {
	pfd := int(parent.Fd()) //nolint:gosec // G115: a descriptor fits an int
	if create {
		switch err := unix.Mkdirat(pfd, name, 0o700); {
		case err == nil:
			if err := parent.Sync(); err != nil { // the new entry survives a power loss
				return nil, err
			}
		case !errors.Is(err, unix.EEXIST):
			return nil, err
		}
	}
	fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || int(st.Uid) != unix.Geteuid() {
		_ = f.Close()
		return nil, errUnsafe
	}
	if create {
		if err := unix.Fchmod(fd, 0o700); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}

// removeAt removes name below dir: a file or symlink is unlinked (a symlink is never followed),
// a directory is emptied first (one level: operation directories hold only files).
func removeAt(dir *os.File, name string) error {
	dfd := int(dir.Fd()) //nolint:gosec // G115: a descriptor fits an int
	err := unix.Unlinkat(dfd, name, 0)
	if err == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if !errors.Is(err, unix.EISDIR) {
		return err
	}
	sub, err := subdir(dir, name, false)
	if err != nil {
		return err
	}
	names, err := sub.Readdirnames(-1)
	if err == nil {
		for _, n := range names {
			if err = unix.Unlinkat(int(sub.Fd()), n, 0); err != nil && !errors.Is(err, unix.ENOENT) { //nolint:gosec // G115: a descriptor fits an int
				break
			}
			err = nil
		}
	}
	_ = sub.Close()
	if err != nil {
		return err
	}
	return unix.Unlinkat(dfd, name, unix.AT_REMOVEDIR)
}
