//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

// selinuxXattr is the extended attribute that holds a file's SELinux label.
const selinuxXattr = "security.selinux"

// maxDirDepth bounds the StrictModes walk from the key directory up to "/".
const maxDirDepth = 256

// errInsecure means a file or directory sshd's StrictModes would reject: writable by group or
// others, or owned by neither the user nor root.
var errInsecure = errors.New("insecure permissions")

// lockWait bounds the wait for the key directory lock: a user can hold a flock on their own .ssh
// forever, and the helper must answer within Alice's budget (tests shorten it).
var lockWait = 45 * time.Second

// cmdAuthKeysWrite replaces one candidate authorized_keys file with stdin, but only when its
// current content still has the hash Alice read (spec §13.4 step 4).
func cmdAuthKeysWrite(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 5 || args[1] != "--expect-sha256" || args[3] != "--op" {
		return nil, refused(helperproto.CodeUsage, "usage: authkeys-write <path> --expect-sha256 <sha256|absent> --op <operation id>")
	}
	path, expect, op := args[0], args[2], args[4]
	if !helperproto.ValidPath(path) || !helperproto.ValidSHA256(expect) || !helperproto.ValidOpID(op) {
		return nil, refused(helperproto.CodeInvalidArgument, "an argument is not allowed")
	}
	content, err := io.ReadAll(io.LimitReader(s.stdin, helperproto.MaxAuthorizedKeysSize+1))
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the new content cannot be read")
	}
	if len(content) > helperproto.MaxAuthorizedKeysSize {
		return nil, refused(helperproto.CodeTooLarge, "the new content is too large")
	}
	s.syslog(helperproto.SubAuthKeysWrite, path)
	r, err := s.scan(ctx)
	if err != nil {
		return nil, err
	}
	c, ok := r.find(path)
	if !ok {
		return nil, refused(helperproto.CodePathNotAllowed, "the path is not an authorized_keys file of a listed user")
	}
	if err := r.writable(c); err != nil {
		return nil, err
	}
	return s.writeCandidate(ctx, c, expect, op, content)
}

// writable refuses users whose key files are not known to be the whole truth: sshd -T failed for
// them (the files come from defaults), or sshd takes their keys from an AuthorizedKeysCommand.
func (r scanResult) writable(c candidate) error {
	for _, u := range r.users {
		if u.acct.name != c.acct.name {
			continue
		}
		if u.unreadable {
			return precondition(helperproto.CodeSSHDFailed, "the sshd configuration of this user cannot be read")
		}
		if u.command != "" && u.command != "none" {
			return refused(helperproto.CodeAuthorizedKeysCommand, "sshd takes this user's keys from an AuthorizedKeysCommand")
		}
		return nil
	}
	return refused(helperproto.CodePathNotAllowed, "the path is not an authorized_keys file of a listed user")
}

// writeError turns an error of the write path into its answer.
func writeError(err error) error {
	var he *helperError
	switch {
	case errors.As(err, &he):
		return err
	case errors.Is(err, fs.ErrNotExist):
		return precondition(helperproto.CodeNotFound, "the key directory does not exist")
	case errors.Is(err, errTooLarge):
		return refused(helperproto.CodeTooLarge, "the file is too large")
	case errors.Is(err, errEscaped):
		return refused(helperproto.CodePathNotAllowed, "the path leaves its allowed directory")
	case errors.Is(err, errUnsafe):
		return refused(helperproto.CodeUnsafeFile, "the file is hard-linked or owned by another user")
	case errors.Is(err, errInsecure):
		return refused(helperproto.CodeInsecurePermissions, "the file or a directory above it is writable by others or owned by another user")
	case errors.Is(err, errNotRegular), errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return refused(helperproto.CodeNotRegularFile, "the path is not a regular file")
	}
	return failed(helperproto.CodeIOError, "the file cannot be written")
}

// keyDir is the opened directory of a candidate file. Every later step (lock, read, stage,
// rename, cleanup) is relative to fd, so a path component swapped after it was opened can never
// redirect the write.
type keyDir struct {
	allowed int    // the allowed directory (the home, or the directory of an absolute pattern)
	fd      int    // the directory that holds the file, opened for reading
	base    string // the file name in fd
}

func (d keyDir) close() {
	_ = unix.Close(d.fd)
	_ = unix.Close(d.allowed)
}

// writeCandidate is the locked compare, backup and atomic replace.
func (s *sys) writeCandidate(ctx context.Context, c candidate, expect, op string, content []byte) (any, error) {
	home, ok := s.resolveNearest(c.acct.home)
	inHome := ok && c.dir == home
	d, err := s.openKeyDir(c, inHome)
	if err != nil {
		return nil, writeError(err)
	}
	defer d.close()
	if err := lockDir(ctx, d.fd); err != nil {
		return nil, failed(helperproto.CodeIOError, "the key directory is locked by another process")
	}
	if err := s.secureDirs(d, c.acct.uid, inHome); err != nil {
		return nil, writeError(err)
	}
	cur, err := readCurrent(d, c.acct)
	if err != nil {
		return nil, writeError(err)
	}
	defer cur.close()
	if cur.sha256() != expect {
		return nil, precondition(helperproto.CodeHashMismatch, "the file changed since it was read")
	}
	backup, err := s.backup(op, c.path, cur)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backup cannot be written")
	}
	if err := s.replace(c, d, cur, content); err != nil {
		return nil, err
	}
	return helperproto.AuthKeysWriteResponse{OK: true, SHA256: hexSHA(content), Backup: backup}, nil
}

// openKeyDir opens the allowed directory and, beneath it, the directory of the file. A missing
// <home>/.ssh is created (spec §13.4 step 4); no other missing directory ever is.
func (s *sys) openKeyDir(c candidate, inHome bool) (keyDir, error) {
	dirRel, base, err := splitCandidate(c)
	if err != nil {
		return keyDir{}, err
	}
	allowed, err := s.openAllowed(c)
	if err != nil {
		return keyDir{}, err
	}
	pfd, err := openBeneath(allowed, dirRel)
	if errors.Is(err, fs.ErrNotExist) && inHome && dirRel == ".ssh" {
		if err = s.makeSSHDir(allowed, c.acct); err == nil {
			pfd, err = openBeneath(allowed, dirRel)
		}
	}
	if err != nil {
		_ = unix.Close(allowed)
		return keyDir{}, err
	}
	// The beneath-resolution gives an O_PATH descriptor; reopen it for flock and fsync.
	fd, err := unix.Openat(pfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	_ = unix.Close(pfd)
	if err != nil {
		_ = unix.Close(allowed)
		return keyDir{}, err
	}
	return keyDir{allowed: allowed, fd: fd, base: base}, nil
}

// makeSSHDir creates .ssh in the home (0700, owned by the user). An existing entry is left alone:
// it is then opened and checked like any other directory.
func (s *sys) makeSSHDir(home int, acct account) error {
	if err := unix.Mkdirat(home, ".ssh", 0o700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return err
	}
	fd, err := unix.Openat(home, ".ssh", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), ".ssh")
	defer func() { _ = f.Close() }()
	if err := s.chown(f, acct.uid, acct.gid); err != nil {
		return failed(helperproto.CodeIOError, "the key directory owner cannot be set")
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return failed(helperproto.CodeIOError, "the key directory mode cannot be set")
	}
	return nil
}

// lockDir takes an exclusive flock on the key directory, giving up after lockWait.
func lockDir(ctx context.Context, fd int) error {
	ctx, cancel := context.WithTimeout(ctx, lockWait)
	defer cancel()
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// secureDirs mirrors sshd's StrictModes on descriptors: the key directory and every directory
// above it, up to the home for a file in the home or up to "/" otherwise, is owned by the user or
// root and not writable by group or others. The walk follows ".." from the opened directory, so
// it checks the directories the write really goes through.
func (s *sys) secureDirs(d keyDir, uid int, inHome bool) error {
	var stop, root unix.Stat_t
	if err := unix.Fstat(d.allowed, &stop); err != nil {
		return err
	}
	if err := unix.Stat(s.host("/"), &root); err != nil {
		return err
	}
	cur, err := unix.Openat(d.fd, ".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(cur) }()
	var prev unix.Stat_t
	for i := 0; i < maxDirDepth; i++ {
		var st unix.Stat_t
		if err := unix.Fstat(cur, &st); err != nil {
			return err
		}
		if i > 0 && sameFile(st, prev) {
			return nil // ".." of the real root is the root
		}
		if !modesOK(st, uid) {
			return errInsecure
		}
		if (inHome && sameFile(st, stop)) || sameFile(st, root) {
			return nil
		}
		next, err := unix.Openat(cur, "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		_ = unix.Close(cur)
		cur, prev = next, st
	}
	return errInsecure
}

// modesOK is sshd's StrictModes rule for one file or directory.
func modesOK(st unix.Stat_t, uid int) bool {
	return (int(st.Uid) == uid || st.Uid == 0) && st.Mode&0o022 == 0
}

func sameFile(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

// current is the file as found under the lock, with the descriptor it was read from.
type current struct {
	f      *os.File // nil when absent
	st     *syscall.Stat_t
	absent bool
	data   []byte
}

func (c current) sha256() string {
	if c.absent {
		return helperproto.AbsentSHA256
	}
	return hexSHA(c.data)
}

func (c current) close() {
	if c.f != nil {
		_ = c.f.Close()
	}
}

// readCurrent opens and reads the file under the lock. The last element is opened with
// O_NOFOLLOW: a symlink, dangling or not, is refused, never followed and never taken for a
// missing file. The file must be regular, have one link, have a credible owner (fileOK) and pass
// StrictModes.
func readCurrent(d keyDir, acct account) (current, error) {
	fd, err := unix.Openat(d.fd, d.base, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return current{absent: true}, nil
	}
	if err != nil {
		return current{}, err
	}
	cur := current{f: os.NewFile(uintptr(fd), d.base)}
	data, err := cur.check(d, acct)
	if err != nil {
		cur.close()
		return current{}, err
	}
	cur.data = data
	return cur, nil
}

func (c *current) check(d keyDir, acct account) ([]byte, error) {
	var parent unix.Stat_t
	if err := unix.Fstat(d.fd, &parent); err != nil {
		return nil, err
	}
	st, err := c.f.Stat()
	if err != nil {
		return nil, err
	}
	if err := fileOK(st, parent, acct); err != nil {
		return nil, err
	}
	c.st, _ = st.Sys().(*syscall.Stat_t) // fileOK checked the type
	if st.Mode().Perm()&0o022 != 0 {
		return nil, errInsecure
	}
	if st.Size() > helperproto.MaxAuthorizedKeysSize {
		return nil, errTooLarge
	}
	return c.content()
}

// content reads the whole file from its descriptor (from offset 0, whatever was read before).
func (c current) content() ([]byte, error) {
	data, err := io.ReadAll(io.NewSectionReader(c.f, 0, helperproto.MaxAuthorizedKeysSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > helperproto.MaxAuthorizedKeysSize {
		return nil, errTooLarge
	}
	return data, nil
}

// unchanged reports, right before the rename, that the name still refers to the inode that was
// read (or still to nothing) and that the inode still holds the bytes that were hashed.
func (c current) unchanged(d keyDir) bool {
	var now unix.Stat_t
	err := unix.Fstatat(d.fd, d.base, &now, unix.AT_SYMLINK_NOFOLLOW)
	if c.absent {
		return errors.Is(err, unix.ENOENT)
	}
	if err != nil || now.Dev != c.st.Dev || now.Ino != c.st.Ino {
		return false
	}
	data, err := c.content()
	return err == nil && bytes.Equal(data, c.data)
}

// backupMeta is written next to each backup.
type backupMeta struct {
	Path   string `json:"path"`
	Absent bool   `json:"absent"`
	Mode   string `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	SHA256 string `json:"sha256"`
}

// backup stores the old content as <BackupRoot>/<op>/<n>.bak with metadata in <n>.json, both 0600
// in 0700 root-only directories. It returns the guest path of the .bak file.
func (s *sys) backup(op, path string, cur current) (string, error) {
	root, err := s.openBackupRoot(true)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	dir, err := subdir(root, op, true)
	if err != nil {
		return "", err
	}
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return "", err
	}
	n := 1
	for _, name := range names {
		if strings.HasSuffix(name, ".bak") {
			n++
		}
	}
	meta := backupMeta{Path: path, Absent: cur.absent, SHA256: cur.sha256()}
	if !cur.absent {
		meta.Mode, meta.UID, meta.GID = fmt.Sprintf("%04o", cur.st.Mode&0o777), int(cur.st.Uid), int(cur.st.Gid)
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}
	name := strconv.Itoa(n)
	if err := writeNewAt(dir, name+".bak", cur.data); err != nil {
		return "", err
	}
	if err := writeNewAt(dir, name+".json", raw); err != nil {
		return "", err
	}
	if err := dir.Sync(); err != nil {
		return "", err
	}
	return helperproto.BackupRoot + "/" + op + "/" + name + ".bak", nil
}

// writeNewAt creates a new 0600 file in dir (never over an existing one or through a symlink)
// and syncs it.
func writeNewAt(dir *os.File, name string, data []byte) error {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600) //nolint:gosec // G115: a descriptor fits an int
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// replace stages content next to the real file, copies owner, mode and SELinux label, syncs, and
// renames it over the real file; then it syncs the directory. Before the rename any failure
// removes the staging file, so the real file is always the old or the new version. Everything
// happens through d.fd and the staging file's descriptor.
func (s *sys) replace(c candidate, d keyDir, cur current, content []byte) error {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := ".authorized_keys.alice-" + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(d.fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return failed(helperproto.CodeIOError, "the staging file cannot be created")
	}
	f := os.NewFile(uintptr(fd), tmp)
	renamed := false
	defer func() {
		_ = f.Close()
		if !renamed {
			_ = unix.Unlinkat(d.fd, tmp, 0)
		}
	}()
	uid, gid, mode := c.acct.uid, c.acct.gid, uint32(0o600)
	if !cur.absent {
		uid, gid, mode = int(cur.st.Uid), int(cur.st.Gid), cur.st.Mode&0o777
	}
	if _, err := f.Write(content); err != nil {
		return failed(helperproto.CodeIOError, "the staging file cannot be written")
	}
	if err := s.chown(f, uid, gid); err != nil {
		return failed(helperproto.CodeIOError, "the owner cannot be set")
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return failed(helperproto.CodeIOError, "the mode cannot be set")
	}
	if !cur.absent {
		copySELinux(int(cur.f.Fd()), fd) //nolint:gosec // G115: a descriptor fits an int
	}
	if err := f.Sync(); err != nil {
		return failed(helperproto.CodeIOError, "the staging file cannot be synced")
	}
	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			return failed(helperproto.CodeIOError, "the file cannot be replaced")
		}
	}
	if !cur.unchanged(d) {
		return precondition(helperproto.CodeHashMismatch, "the file changed since it was read")
	}
	if err := renameInto(d, tmp, cur.absent); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return precondition(helperproto.CodeHashMismatch, "the file changed since it was read")
		}
		return failed(helperproto.CodeIOError, "the file cannot be replaced")
	}
	renamed = true
	if err := unix.Fsync(d.fd); err != nil {
		return failed(helperproto.CodeIOError, "the directory cannot be synced")
	}
	return nil
}

// renameInto moves the staging file over the real one. When the file was absent it must still be
// absent: RENAME_NOREPLACE never clobbers a file that appeared meanwhile (a file system without
// renameat2 support falls back to a plain rename after the unchanged check).
func renameInto(d keyDir, tmp string, absent bool) error {
	if !absent {
		return unix.Renameat(d.fd, tmp, d.fd, d.base)
	}
	err := unix.Renameat2(d.fd, tmp, d.fd, d.base, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		return unix.Renameat(d.fd, tmp, d.fd, d.base)
	}
	return err
}

// copySELinux copies the SELinux label of src to dst (spec §13.4 step 4), best effort: a system
// without SELinux has no label (ENODATA, ENOTSUP), and a new file inherits its directory's label.
func copySELinux(src, dst int) {
	buf := make([]byte, 4096)
	n, err := unix.Fgetxattr(src, selinuxXattr, buf)
	if err != nil || n <= 0 {
		return
	}
	_ = unix.Fsetxattr(dst, selinuxXattr, buf[:n], 0)
}
