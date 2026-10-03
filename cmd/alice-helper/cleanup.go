//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

// backupRetention is the helper's hard cap for backups (spec §12.6 step 8).
const backupRetention = 30 * 24 * time.Hour

// cmdCleanup removes the backups of one operation.
func cmdCleanup(_ context.Context, s *sys, args []string) (any, error) {
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
	if err := removeAt(root, op); err != nil {
		return nil, failed(helperproto.CodeIOError, "the backups cannot be removed")
	}
	return helperproto.CleanupResponse{OK: true, Removed: 1}, nil
}

// sweepBackups removes operation backup directories older than backupRetention. It runs before
// every privileged subcommand; failures are ignored (they never block the call).
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
	for _, name := range names {
		if !helperproto.ValidOpID(name) {
			continue
		}
		var st unix.Stat_t
		if unix.Fstatat(int(root.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR { //nolint:gosec // G115: a descriptor fits an int
			continue
		}
		if s.now().Sub(time.Unix(st.Mtim.Unix())) > backupRetention {
			_ = removeAt(root, name)
		}
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
		if err := unix.Mkdirat(pfd, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
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
