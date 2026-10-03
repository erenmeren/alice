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
	"runtime"
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

// errHomeNotWritable means a missing .ssh cannot be created because the user may not write the
// home (.ssh is created with the user's filesystem credentials).
var errHomeNotWritable = errors.New("home not writable for its user")

// lockWait bounds the wait for the key directory lock: a user can hold a flock on their own .ssh
// forever, and the helper must answer within Alice's budget. It is well below commandBudget, which
// also bounds it, so the scan before it keeps time too (tests shorten it).
var lockWait = 30 * time.Second

// cmdAuthKeysWrite replaces one candidate authorized_keys file with stdin, but only when its
// current content still has the hash Alice read (spec §13.4 step 4) and stdin has the hash Alice
// computed for the new content (protocol 3): EOF on stdin is not proof that all of it arrived (a
// dropped connection ends it early), so a prefix is never written.
func cmdAuthKeysWrite(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 7 || args[1] != "--expect-sha256" || args[3] != "--content-sha256" || args[5] != "--op" {
		return nil, refused(helperproto.CodeUsage, "usage: authkeys-write <path> --expect-sha256 <sha256|absent> --content-sha256 <sha256> --op <operation id>")
	}
	path, expect, want, op := args[0], args[2], args[4], args[6]
	if !helperproto.ValidPath(path) || !helperproto.ValidSHA256(expect) || want == helperproto.AbsentSHA256 ||
		!helperproto.ValidSHA256(want) || !helperproto.ValidOpID(op) {
		return nil, refused(helperproto.CodeInvalidArgument, "an argument is not allowed")
	}
	content, err := io.ReadAll(io.LimitReader(s.stdin, helperproto.MaxAuthorizedKeysSize+1))
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the new content cannot be read")
	}
	if len(content) > helperproto.MaxAuthorizedKeysSize {
		return nil, refused(helperproto.CodeTooLarge, "the new content is too large")
	}
	if hexSHA(content) != want {
		return nil, precondition(helperproto.CodeContentMismatch, "the new content arrived incomplete")
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
	case errors.Is(err, errHomeNotWritable):
		return precondition(helperproto.CodeHomeNotWritable, "the user cannot create .ssh in the home directory")
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
	d, err := s.openKeyDir(c)
	if err != nil {
		return nil, writeError(err)
	}
	defer d.close()
	lock, err := s.lockKeyDir(ctx, d)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the key directory is locked by another process")
	}
	defer func() { _ = lock.Close() }()
	if err := s.secureDirs(d, c.acct.uid, c.inHome); err != nil {
		return nil, writeError(err)
	}
	if err := writeThroughOK(c, d); err != nil {
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
	b, err := s.backup(op, c.path, cur)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backup cannot be written")
	}
	defer b.close()
	if replaced, err := s.replace(ctx, c, d, cur, content); err != nil {
		if !replaced {
			b.discard() // the file is unchanged: the backup describes nothing
		}
		return nil, err
	}
	return helperproto.AuthKeysWriteResponse{OK: true, SHA256: hexSHA(content), Backup: b.path(), Owner: c.acct.name}, nil
}

// writeThroughOK is throughOK for the opened key directory: a file reached through a symlink must
// sit in a directory of its user (root excepted).
func writeThroughOK(c candidate, d keyDir) error {
	var parent unix.Stat_t
	if err := unix.Fstat(d.fd, &parent); err != nil {
		return err
	}
	return throughOK(c, parent)
}

// openKeyDir opens the allowed directory and, beneath it, the directory of the file. A missing
// <home>/.ssh is created (spec §13.4 step 4); no other missing directory ever is.
func (s *sys) openKeyDir(c candidate) (keyDir, error) {
	dirRel, base, err := splitCandidate(c)
	if err != nil {
		return keyDir{}, err
	}
	allowed, err := s.openAllowed(c)
	if err != nil {
		return keyDir{}, err
	}
	pfd, err := openBeneath(allowed, dirRel, !c.through)
	if errors.Is(err, fs.ErrNotExist) && c.inHome && dirRel == ".ssh" {
		if err = s.makeSSHDir(allowed, c.acct); err == nil {
			pfd, err = openBeneath(allowed, dirRel, !c.through)
		} else if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
			err = errHomeNotWritable
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

// makeSSHDir creates .ssh in the home, owned by the user and 0700. The directory is made with
// the user's filesystem credentials, so it is born theirs and root never chowns a name the user
// could have swapped in the meantime; it is then opened without following symlinks and must be a
// directory owned by the user before its mode is set. An existing entry is left alone: it is
// opened and checked like any other directory.
func (s *sys) makeSSHDir(home int, acct account) error {
	err := mkdirAs(home, ".ssh", acct.uid, acct.gid)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.afterMkdirSSH != nil {
		s.afterMkdirSSH()
	}
	fd, err := unix.Openat(home, ".ssh", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != acct.uid {
		return errUnsafe
	}
	return unix.Fchmod(fd, 0o700)
}

// errCredentials means the thread's filesystem credentials could not be switched or restored.
var errCredentials = errors.New("filesystem credentials not switched")

// mkdirAs runs mkdirat with the filesystem uid and gid of a user on a dedicated, locked OS thread
// (setfsuid and setfsgid are per thread). When the original credentials cannot be restored the
// goroutine exits with the thread still locked, so the runtime discards that thread.
func mkdirAs(dirfd int, name string, uid, gid int) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		origUID, _ := unix.SetfsuidRetUid(-1) // an invalid id changes nothing and returns the current one
		origGID, _ := unix.SetfsgidRetGid(-1)
		_, _ = unix.SetfsgidRetGid(gid)
		_, _ = unix.SetfsuidRetUid(uid)
		err := errCredentials
		if fsUID, _ := unix.SetfsuidRetUid(-1); fsUID == uid {
			if fsGID, _ := unix.SetfsgidRetGid(-1); fsGID == gid {
				err = unix.Mkdirat(dirfd, name, 0o700)
			}
		}
		_, _ = unix.SetfsuidRetUid(origUID)
		_, _ = unix.SetfsgidRetGid(origGID)
		fsUID, _ := unix.SetfsuidRetUid(-1)
		fsGID, _ := unix.SetfsgidRetGid(-1)
		if fsUID != origUID || fsGID != origGID {
			done <- errCredentials
			return // still locked: the thread dies with the goroutine
		}
		runtime.UnlockOSThread()
		done <- err
	}()
	return <-done
}

// lockKeyDir serializes helper writers of one key directory. The lock is a root-private file
// <state>/locks/<dev>-<ino>.lock, never the key directory itself: any user who can open a 0755
// directory could hold a flock on it and block every write there. The wait is bounded by
// lockWait. Closing the returned file releases the lock.
//
// The backup sweep removes lock files nobody used for a long time (sweepLocks), but only while it
// holds their flock. A writer that waited for such a file holds the flock of a removed inode, which
// no longer excludes anyone: after locking, it checks that the name still refers to its file and
// otherwise locks again. A held lock is marked as used (its times are set to the helper's clock).
func (s *sys) lockKeyDir(ctx context.Context, d keyDir) (*os.File, error) {
	var st unix.Stat_t
	if err := unix.Fstat(d.fd, &st); err != nil {
		return nil, err
	}
	locks, err := s.openStateDir(lockDirName, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = locks.Close() }()
	ldfd := int(locks.Fd()) //nolint:gosec // G115: a descriptor fits an int
	name := fmt.Sprintf("%d-%d.lock", st.Dev, st.Ino)
	ctx, cancel := context.WithTimeout(ctx, lockWait)
	defer cancel()
	for {
		f, err := openLockFile(ldfd, name, true)
		if err != nil {
			return nil, err
		}
		if err := flockWait(ctx, int(f.Fd())); err != nil { //nolint:gosec // G115: a descriptor fits an int
			_ = f.Close()
			return nil, err
		}
		var mine, now unix.Stat_t
		if unix.Fstat(int(f.Fd()), &mine) == nil && unix.Fstatat(ldfd, name, &now, unix.AT_SYMLINK_NOFOLLOW) == nil && sameFile(mine, now) { //nolint:gosec // G115: a descriptor fits an int
			ts := unix.NsecToTimespec(s.now().UnixNano())
			_ = unix.UtimesNanoAt(ldfd, name, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW)
			return f, nil
		}
		_ = f.Close() // the sweep removed it while this writer waited: lock the current file
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

// openLockFile opens (with create: creating it when missing) a lock file below the locks
// directory: a regular file of the helper's user with one link, never through a symlink.
func openLockFile(ldfd int, name string, create bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Openat(ldfd, name, flags, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var lst unix.Stat_t
	if err := unix.Fstat(fd, &lst); err != nil || lst.Mode&unix.S_IFMT != unix.S_IFREG || int(lst.Uid) != unix.Geteuid() || lst.Nlink != 1 {
		_ = f.Close()
		return nil, errUnsafe
	}
	return f, nil
}

// flockWait takes an exclusive flock, giving up when ctx ends (lockKeyDir bounds it by lockWait).
func flockWait(ctx context.Context, fd int) error {
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

// maxBackupTries bounds the search for a free backup number (concurrent writers of one operation
// on different key directories race for the same number).
const maxBackupTries = 64

// savedBackup is one backup written for a write: <BackupRoot>/<op>/<n>.bak and <n>.json.
type savedBackup struct {
	dir *os.File // the operation directory
	op  string
	n   string
}

func (b savedBackup) path() string { return helperproto.BackupRoot + "/" + b.op + "/" + b.n + ".bak" }

func (b savedBackup) close() { _ = b.dir.Close() }

// discard removes the backup again (the file was not replaced).
func (b savedBackup) discard() {
	dfd := int(b.dir.Fd()) //nolint:gosec // G115: a descriptor fits an int
	_ = unix.Unlinkat(dfd, b.n+".bak", 0)
	_ = unix.Unlinkat(dfd, b.n+".json", 0)
	_ = b.dir.Sync()
}

// backup stores the old content as <BackupRoot>/<op>/<n>.bak with metadata in <n>.json, both 0600
// in 0700 root-only directories. The caller closes it.
func (s *sys) backup(op, path string, cur current) (savedBackup, error) {
	root, err := s.openBackupRoot(true)
	if err != nil {
		return savedBackup{}, err
	}
	defer func() { _ = root.Close() }()
	dir, err := subdir(root, op, true)
	if err != nil {
		return savedBackup{}, err
	}
	b, err := writeBackup(dir, op, path, cur)
	if err != nil {
		_ = dir.Close()
		return savedBackup{}, err
	}
	return b, nil
}

func writeBackup(dir *os.File, op, path string, cur current) (savedBackup, error) {
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return savedBackup{}, err
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
		return savedBackup{}, err
	}
	b := savedBackup{dir: dir, op: op}
	for i := 0; ; i++ {
		b.n = strconv.Itoa(n + i)
		err = writeNewAt(dir, b.n+".bak", cur.data)
		if !errors.Is(err, unix.EEXIST) || i == maxBackupTries {
			break
		}
	}
	if err != nil {
		return savedBackup{}, err
	}
	if err := writeNewAt(dir, b.n+".json", raw); err != nil {
		b.discard()
		return savedBackup{}, err
	}
	if err := dir.Sync(); err != nil {
		b.discard()
		return savedBackup{}, err
	}
	return b, nil
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
// removes the staging file, so the real file is always the old or the new version. It reports
// whether the rename happened. Everything
// happens through d.fd and the staging file's descriptor. Once ctx (the helper's budget) has
// ended, the rename does not happen: Alice is about to report ssh.timeout and must be able to rely
// on the file being unchanged.
func (s *sys) replace(ctx context.Context, c candidate, d keyDir, cur current, content []byte) (bool, error) {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := ".authorized_keys.alice-" + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(d.fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return false, failed(helperproto.CodeIOError, "the staging file cannot be created")
	}
	f := os.NewFile(uintptr(fd), tmp)
	renamed := false
	defer func() {
		_ = f.Close()
		if !renamed {
			_ = unix.Unlinkat(d.fd, tmp, 0)
		}
	}()
	uid, gid, mode, err := newOwner(c, d, cur)
	if err != nil {
		return false, failed(helperproto.CodeIOError, "the directory cannot be checked")
	}
	if _, err := f.Write(content); err != nil {
		return false, failed(helperproto.CodeIOError, "the staging file cannot be written")
	}
	if err := s.chown(f, uid, gid); err != nil {
		return false, failed(helperproto.CodeIOError, "the owner cannot be set")
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return false, failed(helperproto.CodeIOError, "the mode cannot be set")
	}
	if !cur.absent {
		copySELinux(int(cur.f.Fd()), fd) //nolint:gosec // G115: a descriptor fits an int
	}
	if err := f.Sync(); err != nil {
		return false, failed(helperproto.CodeIOError, "the staging file cannot be synced")
	}
	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			return false, failed(helperproto.CodeIOError, "the file cannot be replaced")
		}
	}
	if !cur.unchanged(d) {
		return false, precondition(helperproto.CodeHashMismatch, "the file changed since it was read")
	}
	if ctx.Err() != nil {
		return false, failed(helperproto.CodeIOError, "the time budget ended before the file was replaced")
	}
	if err := renameInto(d, tmp, cur.absent); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return false, precondition(helperproto.CodeHashMismatch, "the file changed since it was read")
		}
		return false, failed(helperproto.CodeIOError, "the file cannot be replaced")
	}
	renamed = true
	if err := unix.Fsync(d.fd); err != nil {
		return true, failed(helperproto.CodeIOError, "the directory cannot be synced")
	}
	return true, nil
}

// newOwner is the owner and mode of the replacement: an existing file keeps its own; a new file
// belongs to the user (0600), except in a root-owned directory (an administrator-managed key
// directory such as /etc/ssh/keys or a root-owned .ssh), where it is root's (0644).
func newOwner(c candidate, d keyDir, cur current) (uid, gid int, mode uint32, err error) {
	if !cur.absent {
		return int(cur.st.Uid), int(cur.st.Gid), cur.st.Mode & 0o777, nil
	}
	var parent unix.Stat_t
	if err := unix.Fstat(d.fd, &parent); err != nil {
		return 0, 0, 0, err
	}
	if parent.Uid == 0 && c.acct.uid != 0 {
		return 0, 0, 0o644, nil
	}
	return c.acct.uid, c.acct.gid, 0o600, nil
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
