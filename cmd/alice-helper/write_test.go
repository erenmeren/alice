//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

const (
	keysPath = "/home/deploy/.ssh/authorized_keys"
	op1      = "0190f5a0-0000-7000-8000-0000000000a1"
	op2      = "0190f5a0-0000-7000-8000-0000000000a2"
)

type chownCall struct {
	name     string
	uid, gid int
}

// newWriteFixture is newFixture with a chown that records instead of changing owners (the tests
// do not run as root).
func newWriteFixture(t *testing.T) (*fixture, func() []chownCall) {
	t.Helper()
	skipOddUID(t)
	f := newFixture(t)
	var mu sync.Mutex
	var calls []chownCall
	f.s.chown = func(file *os.File, uid, gid int) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, chownCall{name: filepath.Base(file.Name()), uid: uid, gid: gid})
		return nil
	}
	return f, func() []chownCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]chownCall(nil), calls...)
	}
}

func (f *fixture) runWith(stdin string, args ...string) (int, map[string]any) {
	f.t.Helper()
	f.s.stdin = strings.NewReader(stdin)
	return f.run(args...)
}

func writeArgs(path, expect, op string) []string {
	return []string{"authkeys-write", path, "--expect-sha256", expect, "--op", op}
}

// sshDirEntries lists the names in the deploy .ssh directory (no staging file may remain).
func (f *fixture) sshDirEntries() []string {
	f.t.Helper()
	return f.dirEntries("/home/deploy/.ssh")
}

func (f *fixture) dirEntries(guest string) []string {
	f.t.Helper()
	entries, err := os.ReadDir(f.host(guest))
	require.NoError(f.t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// asUser gives the paths to the deploy user when the tests run as root (the fixture's files are
// then root's); as a normal user they already belong to deploy.
func (f *fixture) asUser(guests ...string) {
	f.t.Helper()
	if os.Getuid() != 0 {
		return
	}
	for _, g := range guests {
		require.NoError(f.t, os.Lchown(f.host(g), f.uid, f.uid))
	}
}

// lockFile is the root-private lock of a key directory.
func (f *fixture) lockFile(keyDir string) string {
	f.t.Helper()
	var st unix.Stat_t
	require.NoError(f.t, unix.Stat(f.host(keyDir), &st))
	return fmt.Sprintf("/var/lib/alice-helper/locks/%d-%d.lock", st.Dev, st.Ino)
}

func (f *fixture) exists(guest string) bool {
	_, err := os.Lstat(f.host(guest))
	return err == nil
}

func TestWriteReplacesWithCompareAndSwap(t *testing.T) {
	f, chowns := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o640)
	st, err := os.Stat(f.host(keysPath))
	require.NoError(t, err)
	uid, gid := owner(st)

	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, map[string]any{"ok": true, "sha256": hexOf("new\n"),
		"backup": "/var/lib/alice-helper/backups/" + op1 + "/1.bak", "owner": "deploy"}, m)
	assert.Equal(t, "new\n", f.read(keysPath))
	st, err = os.Stat(f.host(keysPath))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), st.Mode().Perm(), "the original mode is kept")
	require.Len(t, chowns(), 1)
	assert.Equal(t, uid, chowns()[0].uid, "the original owner is kept")
	assert.Equal(t, gid, chowns()[0].gid)
	assert.True(t, strings.HasPrefix(chowns()[0].name, ".authorized_keys.alice-"), "the staging file is chowned before the rename")
	assert.Equal(t, []string{"authorized_keys"}, f.sshDirEntries(), "no staging file remains")

	backupDir := "/var/lib/alice-helper/backups/" + op1
	assert.Equal(t, "old\n", f.read(backupDir+"/1.bak"))
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(f.read(backupDir+"/1.json")), &meta))
	assert.Equal(t, map[string]any{"path": keysPath, "absent": false, "mode": "0640", "uid": float64(uid), "gid": float64(gid),
		"sha256": hexOf("old\n")}, meta)
	for _, p := range []string{"/var/lib/alice-helper", "/var/lib/alice-helper/backups", backupDir} {
		dst, err := os.Stat(f.host(p))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), dst.Mode().Perm(), p)
	}
	for _, p := range []string{backupDir + "/1.bak", backupDir + "/1.json"} {
		bst, err := os.Stat(f.host(p))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), bst.Mode().Perm(), p)
	}
	assert.Contains(t, f.loggedLines(), "authkeys-write "+keysPath)

	// A second write in the same operation gets the next backup number.
	code, m = f.runWith("newer\n", writeArgs(keysPath, hexOf("new\n"), op1)...)
	require.Equal(t, 0, code)
	assert.Equal(t, "/var/lib/alice-helper/backups/"+op1+"/2.bak", m["backup"])
	assert.Equal(t, "new\n", f.read(backupDir+"/2.bak"))
}

// F-38: a file changed since Alice read it is refused and left as it is.
func TestWriteRefusesAStaleHash(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "changed by someone\n", 0o600)
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("what alice read\n"), op1)...)
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeHashMismatch, m["code"])
	assert.Equal(t, "changed by someone\n", f.read(keysPath))
	assert.False(t, f.exists(helperproto.BackupRoot+"/"+op1), "nothing is backed up for a refused write")

	code, m = f.runWith("new\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
	assert.Equal(t, helperproto.ExitPrecondition, code, "absent expected but the file exists")
	assert.Equal(t, helperproto.CodeHashMismatch, m["code"])

	require.NoError(t, os.Remove(f.host(keysPath)))
	code, m = f.runWith("new\n", writeArgs(keysPath, hexOf("changed by someone\n"), op1)...)
	assert.Equal(t, helperproto.ExitPrecondition, code, "a file expected but it is absent")
	assert.Equal(t, helperproto.CodeHashMismatch, m["code"])
	assert.False(t, f.exists(keysPath))
}

func TestWriteCreatesAMissingFileAndSSHDirectory(t *testing.T) {
	f, chowns := newWriteFixture(t)
	f.asUser("/home/deploy")
	require.NoError(t, os.RemoveAll(f.host("/home/deploy/.ssh")))
	code, m := f.runWith("ssh-ed25519 AAAA new\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "ssh-ed25519 AAAA new\n", f.read(keysPath))

	dst, err := os.Stat(f.host("/home/deploy/.ssh"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dst.Mode().Perm())
	dirUID, dirGID := owner(dst)
	assert.Equal(t, []int{f.uid, f.uid}, []int{dirUID, dirGID}, "the new .ssh is made with the user's credentials")
	fst, err := os.Stat(f.host(keysPath))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fst.Mode().Perm())
	calls := chowns()
	require.Len(t, calls, 1, "root never chowns the new .ssh")
	assert.Equal(t, f.uid, calls[0].uid, "the new file belongs to the user")
	assert.Equal(t, f.uid, calls[0].gid)

	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(f.read(helperproto.BackupRoot+"/"+op1+"/1.json")), &meta))
	assert.Equal(t, true, meta["absent"])
	assert.Equal(t, helperproto.AbsentSHA256, meta["sha256"])
	assert.Equal(t, "", f.read(helperproto.BackupRoot+"/"+op1+"/1.bak"))
}

func TestWriteOutsideTheHomeNeedsAnExistingDirectory(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.perUser[deployCtx] = "authorizedkeysfile /etc/ssh/keys/%u\n"
	code, m := f.runWith("x\n", writeArgs("/etc/ssh/keys/deploy", helperproto.AbsentSHA256, op1)...)
	assert.Equal(t, helperproto.ExitPrecondition, code, "only <home>/.ssh is ever created")
	assert.Equal(t, helperproto.CodeNotFound, m["code"])
	assert.False(t, f.exists("/etc/ssh/keys"))

	// A missing directory below the home other than .ssh is never created either.
	f.perUser[deployCtx] = "authorizedkeysfile .config/ssh/keys\n"
	code, m = f.runWith("x\n", writeArgs("/home/deploy/.config/ssh/keys", helperproto.AbsentSHA256, op1)...)
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeNotFound, m["code"])
	assert.False(t, f.exists("/home/deploy/.config"))
}

// An absolute pattern writes into its existing directory; StrictModes is checked up to "/" there.
func TestWriteAbsolutePattern(t *testing.T) {
	f, chowns := newWriteFixture(t)
	f.perUser[deployCtx] = "authorizedkeysfile /etc/ssh/keys/%u\n"
	f.mkdir("/etc/ssh/keys", 0o755)
	code, m := f.runWith("x\n", writeArgs("/etc/ssh/keys/deploy", helperproto.AbsentSHA256, op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "x\n", f.read("/etc/ssh/keys/deploy"))
	require.Len(t, chowns(), 1)
	wantUID, wantMode := f.uid, os.FileMode(0o600)
	if os.Getuid() == 0 {
		wantUID, wantMode = 0, 0o644 // a new file in a root-owned key directory stays root's
	}
	assert.Equal(t, wantUID, chowns()[0].uid)
	st, err := os.Stat(f.host("/etc/ssh/keys/deploy"))
	require.NoError(t, err)
	assert.Equal(t, wantMode, st.Mode().Perm())

	require.NoError(t, os.Chmod(f.host("/etc"), 0o777))
	code, m = f.runWith("y\n", writeArgs("/etc/ssh/keys/deploy", hexOf("x\n"), op1)...)
	assert.Equal(t, helperproto.ExitRefused, code, "a world-writable directory above an absolute pattern")
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"], "refused by the scan already (A-1: rootControlled)")
	assert.Equal(t, "x\n", f.read("/etc/ssh/keys/deploy"))
}

// Review Focus 3: an interruption before the rename leaves the old file and no staging file.
func TestWriteIsAtomicWhenInterrupted(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o600)
	f.s.beforeRename = func() error { return errors.New("connection dropped") }
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
	assert.Equal(t, "old\n", f.read(keysPath))
	assert.Equal(t, []string{"authorized_keys"}, f.sshDirEntries())
	assert.Empty(t, f.dirEntries(helperproto.BackupRoot+"/"+op1), "the backup of a write that did not happen is removed")
}

// Two writers that read the same content: the directory lock serializes them, exactly one wins
// and the other sees the changed hash.
func TestConcurrentWritersSerialize(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "base\n", 0o600)
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i, content := range []string{"first\n", "second\n"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := *f.s
			var out strings.Builder
			s.stdout = &out
			s.stdin = strings.NewReader(content)
			codes[i] = run(writeArgs(keysPath, hexOf("base\n"), []string{op1, op2}[i]), &s)
		}()
	}
	wg.Wait()
	assert.ElementsMatch(t, []int{0, helperproto.ExitPrecondition}, codes)
	assert.Contains(t, []string{"first\n", "second\n"}, f.read(keysPath))
}

// A flock any user can take on the key directory itself no longer blocks the write: the helper
// locks a root-private file instead.
func TestWriteIgnoresAFlockOnTheKeyDirectory(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o600)
	orig := lockWait
	lockWait = 200 * time.Millisecond
	t.Cleanup(func() { lockWait = orig })
	d, err := os.Open(f.host("/home/deploy/.ssh"))
	require.NoError(t, err)
	defer func() { _ = d.Close() }()
	require.NoError(t, unix.Flock(int(d.Fd()), unix.LOCK_EX))
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "new\n", f.read(keysPath))
	st, err := os.Stat(f.host(f.lockFile("/home/deploy/.ssh")))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	dst, err := os.Stat(f.host("/var/lib/alice-helper/locks"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dst.Mode().Perm())
}

// A helper lock that is never released makes the write fail after lockWait instead of hanging.
func TestWriteGivesUpOnAHeldLock(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o600)
	orig := lockWait
	lockWait = 50 * time.Millisecond
	t.Cleanup(func() { lockWait = orig })
	f.mkdir("/var/lib/alice-helper/locks", 0o700)
	lock := f.lockFile("/home/deploy/.ssh")
	f.write(lock, "", 0o600)
	l, err := os.Open(f.host(lock))
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	require.NoError(t, unix.Flock(int(l.Fd()), unix.LOCK_EX))
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
	assert.Equal(t, "old\n", f.read(keysPath))
}

// A lock file planted as a symlink is refused, never followed.
func TestWriteRefusesASymlinkedLockFile(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o600)
	f.mkdir("/var/lib/alice-helper/locks", 0o700)
	f.write("/etc/target", "keep\n", 0o600)
	require.NoError(t, os.Symlink(f.host("/etc/target"), f.host(f.lockFile("/home/deploy/.ssh"))))
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
	assert.Equal(t, "keep\n", f.read("/etc/target"))
	assert.Equal(t, "old\n", f.read(keysPath))
}

// Writers of one operation on different key directories (not serialized by a lock) each get
// their own backup number.
func TestConcurrentWritersOfOneOperationGetDistinctBackups(t *testing.T) {
	f, _ := newWriteFixture(t)
	if os.Getuid() == 0 {
		f.s.chown = productionSys().chown // later rounds need the replacements to stay the user's
	}
	const n = 6
	var patterns []string
	for i := range n {
		dir := fmt.Sprintf("/home/deploy/k%d", i)
		f.mkdir(dir, 0o700)
		f.write(dir+"/keys", fmt.Sprintf("old %d\n", i), 0o600)
		f.asUser(dir, dir+"/keys")
		patterns = append(patterns, fmt.Sprintf("k%d/keys", i))
	}
	f.perUser[deployCtx] = "authorizedkeysfile " + strings.Join(patterns, " ") + "\n"
	for round := range 5 {
		op := fmt.Sprintf("0190f5a0-0000-7000-8000-%012d", round)
		codes := make([]int, n)
		outs := make([]strings.Builder, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s := *f.s
				s.stdout = &outs[i]
				s.stdin = strings.NewReader(fmt.Sprintf("round %d\n", round))
				path := fmt.Sprintf("/home/deploy/k%d/keys", i)
				prev := fmt.Sprintf("old %d\n", i)
				if round > 0 {
					prev = fmt.Sprintf("round %d\n", round-1)
				}
				codes[i] = run(writeArgs(path, hexOf(prev), op), &s)
			}()
		}
		wg.Wait()
		for i := range n {
			require.Equal(t, 0, codes[i], "round %d writer %d: %s", round, i, outs[i].String())
		}
		var baks []string
		for _, e := range f.dirEntries(helperproto.BackupRoot + "/" + op) {
			if strings.HasSuffix(e, ".bak") {
				baks = append(baks, e)
			}
		}
		assert.Len(t, baks, n, "round %d", round)
	}
}

func TestWriteRefusesBadRequests(t *testing.T) {
	f, chowns := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o600)
	f.write("/etc/shadow", "root:HASH:1::::::\n", 0o600)
	good := hexOf("old\n")
	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
		exit  int
		code  string
	}{
		{"not a candidate", writeArgs("/etc/shadow", hexOf("root:HASH:1::::::\n"), op1), "x", helperproto.ExitRefused, helperproto.CodePathNotAllowed},
		{"another user's home", writeArgs("/home/nologin/.ssh/authorized_keys", helperproto.AbsentSHA256, op1), "x", helperproto.ExitRefused, helperproto.CodePathNotAllowed},
		{"injection in the path", writeArgs(keysPath+";id", good, op1), "x", helperproto.ExitRefused, helperproto.CodeInvalidArgument},
		{"newline in the path", writeArgs(keysPath+"\n/etc/shadow", good, op1), "x", helperproto.ExitRefused, helperproto.CodeInvalidArgument},
		{"upper-case hash", writeArgs(keysPath, strings.Repeat("A", 64), op1), "x", helperproto.ExitRefused, helperproto.CodeInvalidArgument},
		{"traversal in the op id", writeArgs(keysPath, good, "../../../../etc/cron.d/x"), "x", helperproto.ExitRefused, helperproto.CodeInvalidArgument},
		{"flags swapped", []string{"authkeys-write", keysPath, "--op", op1, "--expect-sha256", good}, "x", helperproto.ExitRefused, helperproto.CodeUsage},
		{"missing flags", []string{"authkeys-write", keysPath}, "x", helperproto.ExitRefused, helperproto.CodeUsage},
		{"content too large", writeArgs(keysPath, good, op1), strings.Repeat("#", helperproto.MaxAuthorizedKeysSize+1), helperproto.ExitRefused, helperproto.CodeTooLarge},
	} {
		code, m := f.runWith(tc.stdin, tc.args...)
		assert.Equal(t, tc.exit, code, tc.name)
		assert.Equal(t, tc.code, m["code"], tc.name)
	}
	assert.Equal(t, "old\n", f.read(keysPath))
	assert.Equal(t, "root:HASH:1::::::\n", f.read("/etc/shadow"))
	assert.Empty(t, chowns())
	assert.False(t, f.exists(helperproto.BackupRoot), "no refused request creates backups")
}

func TestWriteRefusesHardLinkedAndNonRegularFiles(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write("/home/deploy/elsewhere", "x\n", 0o600)
	require.NoError(t, os.Link(f.host("/home/deploy/elsewhere"), f.host(keysPath)))
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("x\n"), op1)...)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeUnsafeFile, m["code"], "the same code authkeys-read uses for a hard link")
	assert.Equal(t, "x\n", f.read("/home/deploy/elsewhere"))

	f.mkdir("/home/deploy/.ssh/authorized_keys2", 0o700)
	code, m = f.runWith("new\n", writeArgs("/home/deploy/.ssh/authorized_keys2", helperproto.AbsentSHA256, op1)...)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeNotRegularFile, m["code"])

	require.NoError(t, os.RemoveAll(f.host("/home/deploy/.ssh/authorized_keys2")))
	f.write("/home/deploy/.ssh/authorized_keys2", strings.Repeat("#", helperproto.MaxAuthorizedKeysSize+1), 0o600)
	code, m = f.runWith("new\n", writeArgs("/home/deploy/.ssh/authorized_keys2", helperproto.AbsentSHA256, op1)...)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeTooLarge, m["code"])
}

// A symlink inside the home (an operator's convenience link) resolved by the scan is written
// through: the target file is replaced and the link stays a link.
func TestWriteThroughSymlinkReplacesTheTarget(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o600)
	f.asUser("/home/deploy/.ssh", keysPath)
	require.NoError(t, os.Symlink("authorized_keys", f.host("/home/deploy/.ssh/authorized_keys2")))
	code, _ := f.runWith("new\n", writeArgs("/home/deploy/.ssh/authorized_keys2", hexOf("old\n"), op1)...)
	require.Equal(t, 0, code)
	assert.Equal(t, "new\n", f.read(keysPath))
	lst, err := os.Lstat(f.host("/home/deploy/.ssh/authorized_keys2"))
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, lst.Mode()&os.ModeSymlink)
}

// I-2: keys of a user whose sshd configuration is unknown, or whose keys come from an
// AuthorizedKeysCommand, are never written.
func TestWriteRefusesUsersWithUnknownOrExternalKeys(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o600)
	f.cFails = true
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeSSHDFailed, m["code"])

	f.cFails, f.sshdFails = false, true
	code, m = f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	assert.Equal(t, helperproto.ExitPrecondition, code, "the global sshd -T failed: the defaults may be wrong")
	assert.Equal(t, helperproto.CodeSSHDFailed, m["code"])

	f.sshdFails = false
	f.perUser[deployCtx] = "authorizedkeysfile .ssh/authorized_keys\nauthorizedkeyscommand /usr/bin/x %u\n"
	code, m = f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeAuthorizedKeysCommand, m["code"])

	assert.Equal(t, "old\n", f.read(keysPath))
	assert.False(t, f.exists(helperproto.BackupRoot))
}

// StrictModes on the write side: a file or directory sshd would ignore is not written.
func TestWriteRefusesInsecurePermissions(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		mode os.FileMode
	}{
		{"group-writable .ssh", "/home/deploy/.ssh", 0o770},
		{"world-writable .ssh", "/home/deploy/.ssh", 0o707},
		{"group-writable home", "/home/deploy", 0o775},
		{"group-writable file", keysPath, 0o660},
		{"world-writable file", keysPath, 0o606},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, chowns := newWriteFixture(t)
			f.write(keysPath, "old\n", 0o600)
			require.NoError(t, os.Chmod(f.host(tc.path), tc.mode))
			code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
			assert.Equal(t, helperproto.ExitRefused, code)
			assert.Equal(t, helperproto.CodeInsecurePermissions, m["code"])
			assert.Equal(t, "old\n", f.read(keysPath))
			assert.Empty(t, chowns())
			assert.False(t, f.exists(helperproto.BackupRoot))
		})
	}
	// Directories above the home are not checked for a file in the home (as sshd).
	f, _ := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o600)
	require.NoError(t, os.Chmod(f.host("/home"), 0o777))
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	assert.Equal(t, 0, code, "%v", m)
}

// C-1 for writes: after the scan resolved ~/.ssh/authorized_keys, ~/.ssh becomes a symlink to a
// directory outside the home. Both openat2 and the fallback walk refuse; nothing outside is touched.
func TestAttackWriteSwapRaceAfterScan(t *testing.T) {
	for _, tc := range []struct {
		name    string
		openat2 bool
		target  func(f *fixture) string
	}{
		{"openat2 absolute", true, func(f *fixture) string { return f.host("/etc/evil") }},
		{"openat2 relative", true, func(*fixture) string { return "../../etc/evil" }},
		{"fallback absolute", false, func(f *fixture) string { return f.host("/etc/evil") }},
		{"fallback relative", false, func(*fixture) string { return "../../etc/evil" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useOpenat2 = tc.openat2
			t.Cleanup(func() { useOpenat2 = true })
			f, chowns := newWriteFixture(t)
			f.addZed()
			f.write(keysPath, "mine\n", 0o600)
			f.mkdir("/etc/evil", 0o755)
			f.write("/etc/evil/authorized_keys", "root-only\n", 0o600)
			swapped := false
			f.onSSHD = func(args []string) {
				if len(args) == 3 && strings.HasPrefix(args[2], "user=zed") && !swapped {
					swapped = true
					require.NoError(t, os.Rename(f.host("/home/deploy/.ssh"), f.host("/home/deploy/.ssh.orig")))
					require.NoError(t, os.Symlink(tc.target(f), f.host("/home/deploy/.ssh")))
				}
			}
			code, m := f.runWith("attacker-chosen\n", writeArgs(keysPath, hexOf("root-only\n"), op1)...)
			require.True(t, swapped, "the swap happened between scan and write")
			assert.Equal(t, helperproto.ExitRefused, code)
			assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
			assert.Equal(t, "root-only\n", f.read("/etc/evil/authorized_keys"))
			assert.Equal(t, []string{"authorized_keys"}, f.dirEntries("/etc/evil"))
			assert.Empty(t, chowns())
		})
	}
}

// The swap happens after the helper opened the key directory, just before the rename: every
// later operation is relative to the opened descriptor, so the write lands in the original
// directory and the symlink target is never touched.
func TestAttackWriteSwapRaceBeforeRename(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "old\n", 0o600)
	f.mkdir("/etc/evil", 0o755)
	f.write("/etc/evil/authorized_keys", "root-only\n", 0o600)
	f.s.beforeRename = func() error {
		require.NoError(t, os.Rename(f.host("/home/deploy/.ssh"), f.host("/home/deploy/.ssh.orig")))
		require.NoError(t, os.Symlink(f.host("/etc/evil"), f.host("/home/deploy/.ssh")))
		return nil
	}
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "root-only\n", f.read("/etc/evil/authorized_keys"))
	assert.Equal(t, []string{"authorized_keys"}, f.dirEntries("/etc/evil"), "no staging file leaked outside")
	assert.Equal(t, "new\n", f.read("/home/deploy/.ssh.orig/authorized_keys"))
}

// The file is replaced by another inode (or changed in place) after the compare and before the
// rename: the write is refused as a hash mismatch and the other content survives.
func TestAttackWriteFileChangedBeforeRename(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f *fixture)
	}{
		{"replaced by another inode", func(f *fixture) {
			f.write("/home/deploy/.ssh/other", "old\n", 0o600)
			require.NoError(f.t, os.Rename(f.host("/home/deploy/.ssh/other"), f.host(keysPath)))
		}},
		{"changed in place", func(f *fixture) {
			require.NoError(f.t, os.WriteFile(f.host(keysPath), []byte("in place\n"), 0o600))
		}},
		{"removed", func(f *fixture) { require.NoError(f.t, os.Remove(f.host(keysPath))) }},
		{"replaced by a symlink", func(f *fixture) {
			require.NoError(f.t, os.Remove(f.host(keysPath)))
			require.NoError(f.t, os.Symlink(f.host("/etc/shadow"), f.host(keysPath)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newWriteFixture(t)
			f.write("/etc/shadow", "root:SECRET:1::::::\n", 0o600)
			f.write(keysPath, "old\n", 0o600)
			f.s.beforeRename = func() error { tc.change(f); return nil }
			code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
			assert.Equal(t, helperproto.ExitPrecondition, code)
			assert.Equal(t, helperproto.CodeHashMismatch, m["code"])
			assert.Equal(t, "root:SECRET:1::::::\n", f.read("/etc/shadow"))
			for _, n := range f.sshDirEntries() {
				assert.False(t, strings.HasPrefix(n, ".authorized_keys.alice-"), "staging file removed")
			}
			assert.Empty(t, f.dirEntries(helperproto.BackupRoot+"/"+op1), "the late mismatch removes its backup")
		})
	}

	// A file appears where none was expected: RENAME_NOREPLACE refuses to clobber it.
	f, _ := newWriteFixture(t)
	f.s.beforeRename = func() error { f.write(keysPath, "appeared\n", 0o600); return nil }
	code, m := f.runWith("new\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeHashMismatch, m["code"])
	assert.Equal(t, "appeared\n", f.read(keysPath))
}

// The last element is a symlink (the scan saw a regular file, or the link dangles): it is
// refused, never written through and never treated as a missing file to create.
func TestAttackWriteSymlinkedTarget(t *testing.T) {
	t.Run("swapped after the scan", func(t *testing.T) {
		f, _ := newWriteFixture(t)
		f.addZed()
		f.write("/etc/shadow", "root:SECRET:1::::::\n", 0o600)
		f.write(keysPath, "old\n", 0o600)
		f.onSSHD = func(args []string) {
			if len(args) == 3 && strings.HasPrefix(args[2], "user=zed") && !f.exists(keysPath+".gone") {
				require.NoError(t, os.Rename(f.host(keysPath), f.host(keysPath+".gone")))
				require.NoError(t, os.Symlink(f.host("/etc/shadow"), f.host(keysPath)))
			}
		}
		code, m := f.runWith("pwned\n", writeArgs(keysPath, hexOf("root:SECRET:1::::::\n"), op1)...)
		assert.Equal(t, helperproto.ExitRefused, code)
		assert.Equal(t, helperproto.CodeNotRegularFile, m["code"])
		assert.Equal(t, "root:SECRET:1::::::\n", f.read("/etc/shadow"))
		assert.NotContains(t, f.out.String(), "SECRET")
	})
	for _, target := range []string{"missing-in-ssh", "../../../etc/cron.d/evil"} {
		t.Run("dangling "+target, func(t *testing.T) {
			f, chowns := newWriteFixture(t)
			f.mkdir("/etc/cron.d", 0o755)
			require.NoError(t, os.Symlink(target, f.host(keysPath)))
			code, m := f.runWith("* * * * * root id\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
			assert.Equal(t, helperproto.ExitRefused, code)
			assert.Contains(t, []any{helperproto.CodeNotRegularFile, helperproto.CodePathNotAllowed}, m["code"])
			assert.False(t, f.exists("/home/deploy/.ssh/missing-in-ssh"))
			assert.False(t, f.exists("/etc/cron.d/evil"))
			lst, err := os.Lstat(f.host(keysPath))
			require.NoError(t, err)
			assert.Equal(t, os.ModeSymlink, lst.Mode()&os.ModeSymlink, "the link is left alone")
			assert.Empty(t, chowns())
		})
	}
}

// I-1 for writes: a hard link to a root file is never replaced or chowned.
func TestAttackWriteHardLink(t *testing.T) {
	f, chowns := newWriteFixture(t)
	f.write("/etc/shadow", "root:SECRET:1::::::\n", 0o600)
	require.NoError(t, os.Link(f.host("/etc/shadow"), f.host(keysPath)))
	code, m := f.runWith("pwned\n", writeArgs(keysPath, hexOf("root:SECRET:1::::::\n"), op1)...)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeUnsafeFile, m["code"])
	assert.Equal(t, "root:SECRET:1::::::\n", f.read("/etc/shadow"))
	assert.Empty(t, chowns())
	assert.False(t, f.exists(helperproto.BackupRoot))
}

// The .ssh directory is created, but the user swaps in a symlink before the helper opens it.
func TestAttackSSHDirCreationRace(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.asUser("/home/deploy")
	require.NoError(t, os.RemoveAll(f.host("/home/deploy/.ssh")))
	f.mkdir("/etc/evil", 0o755)
	f.s.afterMkdirSSH = func() {
		require.NoError(t, os.Rename(f.host("/home/deploy/.ssh"), f.host("/home/deploy/.ssh.orig")))
		require.NoError(t, os.Symlink(f.host("/etc/evil"), f.host("/home/deploy/.ssh")))
	}
	code, m := f.runWith("x\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodeNotRegularFile, m["code"])
	assert.Empty(t, f.dirEntries("/etc/evil"))
	st, err := os.Stat(f.host("/etc/evil"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), st.Mode().Perm(), "the symlink target is never chmodded")
}

// I-1 (root only): the user swaps a root-owned directory of their home in as .ssh between the
// helper's mkdir and its open. The helper must refuse, not chown or chmod root's directory.
func TestAttackSSHDirSwappedForARootDirectory(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root: the swapped-in directory must belong to root")
	}
	f, _ := newWriteFixture(t)
	f.asUser("/home/deploy")
	require.NoError(t, os.RemoveAll(f.host("/home/deploy/.ssh")))
	f.mkdir("/home/deploy/rootdir", 0o755) // root-owned, inside the user's home
	f.s.afterMkdirSSH = func() {
		require.NoError(t, os.Rename(f.host("/home/deploy/.ssh"), f.host("/home/deploy/x")))
		require.NoError(t, os.Rename(f.host("/home/deploy/rootdir"), f.host("/home/deploy/.ssh")))
	}
	code, m := f.runWith("x\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodeUnsafeFile, m["code"])
	st, err := os.Stat(f.host("/home/deploy/.ssh"))
	require.NoError(t, err)
	uid, gid := owner(st)
	assert.Equal(t, []int{0, 0}, []int{uid, gid}, "root's directory keeps its owner")
	assert.Equal(t, os.FileMode(0o755), st.Mode().Perm(), "and its mode")
	assert.False(t, f.exists(keysPath))
}

func TestWriteFailurePaths(t *testing.T) {
	t.Run("stdin", func(t *testing.T) {
		f, _ := newWriteFixture(t)
		f.s.stdin = errReader{}
		code, m := f.run(writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
	})
	t.Run("passwd unreadable", func(t *testing.T) {
		f, _ := newWriteFixture(t)
		require.NoError(t, os.Remove(f.host("/etc/passwd")))
		code, m := f.runWith("x\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
	})
	t.Run("chown of the staging file", func(t *testing.T) {
		f, _ := newWriteFixture(t)
		f.write(keysPath, "old\n", 0o600)
		f.s.chown = func(*os.File, int, int) error { return errors.New("EPERM") }
		code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		assert.Equal(t, "old\n", f.read(keysPath))
		assert.Equal(t, []string{"authorized_keys"}, f.sshDirEntries())
	})
	t.Run(".ssh is a file", func(t *testing.T) {
		f, _ := newWriteFixture(t)
		require.NoError(t, os.RemoveAll(f.host("/home/deploy/.ssh")))
		f.write("/home/deploy/.ssh", "", 0o600)
		code, m := f.runWith("new\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
		assert.Equal(t, helperproto.ExitRefused, code)
		assert.Contains(t, []any{helperproto.CodeNotRegularFile, helperproto.CodePathNotAllowed}, m["code"])
	})
	t.Run("backup directory not creatable", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		f, _ := newWriteFixture(t)
		f.write(keysPath, "old\n", 0o600)
		require.NoError(t, os.Chmod(f.host("/var/lib"), 0o555))
		t.Cleanup(func() { _ = os.Chmod(f.host("/var/lib"), 0o755) })
		code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		assert.Equal(t, "old\n", f.read(keysPath))
	})
	t.Run("backup root is a symlink", func(t *testing.T) {
		f, _ := newWriteFixture(t)
		f.write(keysPath, "old\n", 0o600)
		f.mkdir("/tmp/elsewhere", 0o700)
		require.NoError(t, os.Symlink(f.host("/tmp/elsewhere"), f.host("/var/lib/alice-helper")))
		code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		assert.Empty(t, f.dirEntries("/tmp/elsewhere"))
		assert.Equal(t, "old\n", f.read(keysPath))
	})
	t.Run("backup file already exists", func(t *testing.T) {
		f, _ := newWriteFixture(t)
		f.write(keysPath, "old\n", 0o600)
		f.mkdir(helperproto.BackupRoot+"/"+op1, 0o700)
		f.write(helperproto.BackupRoot+"/"+op1+"/1.json", "{}", 0o600)
		code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		assert.Equal(t, "old\n", f.read(keysPath))
	})
	t.Run("staging file cannot be created", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		f, _ := newWriteFixture(t)
		f.write(keysPath, "old\n", 0o600)
		require.NoError(t, os.Chmod(f.host("/home/deploy/.ssh"), 0o500))
		t.Cleanup(func() { _ = os.Chmod(f.host("/home/deploy/.ssh"), 0o700) })
		code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		assert.Equal(t, "old\n", f.read(keysPath))
	})
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

// Root only: real owners are set through the descriptors and the ownership rules hold.
func TestWriteAsRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to chown")
	}
	const user = 1000
	setup := func(t *testing.T) *fixture {
		f := newFixture(t)
		require.Equal(t, user, f.uid)
		f.s.chown = productionSys().chown
		require.NoError(t, os.Chown(f.host("/home/deploy"), user, user))
		require.NoError(t, os.Chown(f.host("/home/deploy/.ssh"), user, user))
		return f
	}
	statOf := func(t *testing.T, f *fixture, guest string) (uint32, uint32, os.FileMode) {
		st, err := os.Lstat(f.host(guest))
		require.NoError(t, err)
		sys := st.Sys().(*syscall.Stat_t)
		return sys.Uid, sys.Gid, st.Mode().Perm()
	}

	t.Run("an existing file keeps its owner and mode", func(t *testing.T) {
		f := setup(t)
		f.write(keysPath, "old\n", 0o640)
		require.NoError(t, os.Chown(f.host(keysPath), user, 1234))
		code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
		require.Equal(t, 0, code, "%v", m)
		uid, gid, mode := statOf(t, f, keysPath)
		assert.Equal(t, []any{uint32(user), uint32(1234), os.FileMode(0o640)}, []any{uid, gid, mode})
		uid, _, mode = statOf(t, f, helperproto.BackupRoot+"/"+op1+"/1.bak")
		assert.Equal(t, uint32(0), uid, "backups belong to root")
		assert.Equal(t, os.FileMode(0o600), mode)
	})
	t.Run("a new .ssh and file belong to the user", func(t *testing.T) {
		f := setup(t)
		require.NoError(t, os.RemoveAll(f.host("/home/deploy/.ssh")))
		code, m := f.runWith("new\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
		require.Equal(t, 0, code, "%v", m)
		uid, gid, mode := statOf(t, f, "/home/deploy/.ssh")
		assert.Equal(t, []any{uint32(user), uint32(user), os.FileMode(0o700)}, []any{uid, gid, mode})
		uid, gid, mode = statOf(t, f, keysPath)
		assert.Equal(t, []any{uint32(user), uint32(user), os.FileMode(0o600)}, []any{uid, gid, mode})
	})
	t.Run("a stale root inode in the user's directory is refused", func(t *testing.T) {
		f := setup(t)
		f.write(keysPath, "stale\n", 0o600) // root-owned
		code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("stale\n"), op1)...)
		assert.Equal(t, helperproto.ExitRefused, code)
		assert.Equal(t, helperproto.CodeUnsafeFile, m["code"])
	})
	t.Run("another user's file is refused", func(t *testing.T) {
		f := setup(t)
		f.write(keysPath, "x\n", 0o600)
		require.NoError(t, os.Chown(f.host(keysPath), 2000, 2000))
		code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("x\n"), op1)...)
		assert.Equal(t, helperproto.ExitRefused, code)
		assert.Equal(t, helperproto.CodeUnsafeFile, m["code"])
	})
	t.Run("a directory owned by another user is refused", func(t *testing.T) {
		f := setup(t)
		f.write(keysPath, "x\n", 0o600)
		require.NoError(t, os.Chown(f.host(keysPath), user, user))
		require.NoError(t, os.Chown(f.host("/home/deploy"), 2000, 2000))
		code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("x\n"), op1)...)
		assert.Equal(t, helperproto.ExitRefused, code)
		assert.Equal(t, helperproto.CodeInsecurePermissions, m["code"])
		assert.Equal(t, "x\n", f.read(keysPath))
	})
	t.Run("a symlink in the home is not written through into a root directory", func(t *testing.T) {
		f := setup(t)
		f.mkdir("/home/deploy/rootdir", 0o755) // root's directory inside the home
		f.write("/home/deploy/rootdir/keys", "admin\n", 0o644)
		require.NoError(t, os.Symlink("../rootdir/keys", f.host("/home/deploy/.ssh/authorized_keys2")))
		code, m := f.runWith("pwned\n", writeArgs("/home/deploy/.ssh/authorized_keys2", hexOf("admin\n"), op1)...)
		assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
		assert.Equal(t, helperproto.CodeUnsafeFile, m["code"])
		assert.Equal(t, "admin\n", f.read("/home/deploy/rootdir/keys"))
	})
	t.Run("a new file in a root-owned .ssh is root's", func(t *testing.T) {
		f := setup(t)
		require.NoError(t, os.Chown(f.host("/home/deploy/.ssh"), 0, 0))
		code, m := f.runWith("x\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
		require.Equal(t, 0, code, "%v", m)
		uid, gid, mode := statOf(t, f, keysPath)
		assert.Equal(t, []any{uint32(0), uint32(0), os.FileMode(0o644)}, []any{uid, gid, mode})
	})
	t.Run("a new file in a root key directory is root's", func(t *testing.T) {
		f := setup(t)
		f.perUser[deployCtx] = "authorizedkeysfile /etc/ssh/keys/%u\n"
		f.mkdir("/etc/ssh/keys", 0o755)
		code, m := f.runWith("x\n", writeArgs("/etc/ssh/keys/deploy", helperproto.AbsentSHA256, op1)...)
		require.Equal(t, 0, code, "%v", m)
		uid, gid, mode := statOf(t, f, "/etc/ssh/keys/deploy")
		assert.Equal(t, []any{uint32(0), uint32(0), os.FileMode(0o644)}, []any{uid, gid, mode})
	})
	t.Run("a root file in a root directory stays root's", func(t *testing.T) {
		f := setup(t)
		f.perUser[deployCtx] = "authorizedkeysfile /etc/ssh/keys/%u\n"
		f.mkdir("/etc/ssh/keys", 0o755)
		f.write("/etc/ssh/keys/deploy", "x\n", 0o644)
		code, m := f.runWith("y\n", writeArgs("/etc/ssh/keys/deploy", hexOf("x\n"), op1)...)
		require.Equal(t, 0, code, "%v", m)
		uid, _, mode := statOf(t, f, "/etc/ssh/keys/deploy")
		assert.Equal(t, uint32(0), uid)
		assert.Equal(t, os.FileMode(0o644), mode)
	})
}

func TestCleanupAndBackupRetention(t *testing.T) {
	f, _ := newWriteFixture(t)
	old := "0190f5a0-0000-7000-8000-0000000000b1"
	f.mkdir(helperproto.BackupRoot+"/"+old, 0o700)
	f.write(helperproto.BackupRoot+"/"+old+"/1.bak", "x", 0o600)
	f.mkdir(helperproto.BackupRoot+"/"+op1, 0o700)
	f.mkdir(helperproto.BackupRoot+"/"+op2, 0o700)
	f.write(helperproto.BackupRoot+"/"+op2+"/1.bak", "x", 0o600)
	f.write(helperproto.BackupRoot+"/"+op2+"/1.json", "{}", 0o600)
	f.mkdir(helperproto.BackupRoot+"/notes", 0o700)
	for p, age := range map[string]time.Duration{old: 31 * 24 * time.Hour, op1: 29 * 24 * time.Hour, op2: time.Hour, "notes": 400 * 24 * time.Hour} {
		at := testNow.Add(-age)
		require.NoError(t, os.Chtimes(f.host(helperproto.BackupRoot+"/"+p), at, at))
	}
	exists := func(name string) bool { return f.exists(helperproto.BackupRoot + "/" + name) }

	code, m := f.run("version")
	require.Equal(t, 0, code, "%v", m)
	assert.True(t, exists(old), "an unprivileged call does not sweep")

	code, m = f.run("cleanup", "--op", op2)
	require.Equal(t, 0, code)
	assert.Equal(t, map[string]any{"ok": true, "removed": float64(1)}, m)
	assert.False(t, exists(op2), "cleanup removes the operation's backups")
	assert.False(t, exists(old), "every privileged call removes backups older than 30 days")
	assert.True(t, exists(op1), "29 days old: kept")
	assert.True(t, exists("notes"), "only operation directories are swept")
	assert.Contains(t, f.loggedLines(), "cleanup "+helperproto.BackupRoot+"/"+op2)

	code, m = f.run("cleanup", "--op", op2)
	require.Equal(t, 0, code)
	assert.Equal(t, float64(0), m["removed"])

	for _, args := range [][]string{{"cleanup"}, {"cleanup", "--op"}, {"cleanup", "--op", "../.."}, {"cleanup", "--op", "0190F5A0-0000-7000-8000-0000000000A1"}} {
		code, m = f.run(args...)
		assert.Equal(t, helperproto.ExitRefused, code, "%v", args)
		assert.Contains(t, []any{helperproto.CodeUsage, helperproto.CodeInvalidArgument}, m["code"], "%v", args)
	}
	assert.True(t, exists(op1))
}

func TestCleanupWithoutBackups(t *testing.T) {
	f, _ := newWriteFixture(t)
	code, m := f.run("cleanup", "--op", op1)
	require.Equal(t, 0, code)
	assert.Equal(t, map[string]any{"ok": true, "removed": float64(0)}, m)
}

// A symlink planted as an operation directory is removed itself; its target is not followed.
func TestCleanupDoesNotFollowSymlinks(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.mkdir(helperproto.BackupRoot, 0o700)
	f.mkdir("/etc/keep", 0o755)
	f.write("/etc/keep/file", "x", 0o600)
	require.NoError(t, os.Symlink(f.host("/etc/keep"), f.host(helperproto.BackupRoot+"/"+op1)))
	code, m := f.run("cleanup", "--op", op1)
	require.Equal(t, 0, code, "%v", m)
	assert.False(t, f.exists(helperproto.BackupRoot+"/"+op1))
	assert.Equal(t, "x", f.read("/etc/keep/file"))

	require.NoError(t, os.Remove(f.host(helperproto.BackupRoot)))
	require.NoError(t, os.Symlink(f.host("/etc/keep"), f.host(helperproto.BackupRoot)))
	code, m = f.run("cleanup", "--op", op1)
	assert.Equal(t, helperproto.ExitFailed, code, "%v", m)
	assert.Equal(t, "x", f.read("/etc/keep/file"))
}

func TestCleanupFailsWhenTheDirectoryCannotBeRemoved(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f, _ := newWriteFixture(t)
	f.mkdir(helperproto.BackupRoot+"/"+op1, 0o700)
	f.write(helperproto.BackupRoot+"/"+op1+"/1.bak", "x", 0o600)
	require.NoError(t, os.Chmod(f.host(helperproto.BackupRoot+"/"+op1), 0o500))
	t.Cleanup(func() { _ = os.Chmod(f.host(helperproto.BackupRoot+"/"+op1), 0o700) })
	code, m := f.run("cleanup", "--op", op1)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
}

func TestPrivilegedReadsAlsoSweep(t *testing.T) {
	f, _ := newWriteFixture(t)
	old := "0190f5a0-0000-7000-8000-0000000000b1"
	f.mkdir(helperproto.BackupRoot+"/"+old, 0o700)
	at := testNow.Add(-31 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(f.host(helperproto.BackupRoot+"/"+old), at, at))
	code, _ := f.run("sshd-dump")
	require.Equal(t, 0, code)
	assert.False(t, f.exists(helperproto.BackupRoot+"/"+old))
}

// .ssh appears between the failed open and the mkdir (another process created it): it is used as
// found, checked like any existing directory, and not chowned.
func TestWriteUsesAConcurrentlyCreatedSSHDir(t *testing.T) {
	orig := openat2
	t.Cleanup(func() { openat2 = orig })
	calls := 0
	openat2 = func(dirfd int, path string, how *unix.OpenHow) (int, error) {
		calls++
		if calls == 1 {
			return -1, unix.ENOENT
		}
		return orig(dirfd, path, how)
	}
	f, chowns := newWriteFixture(t)
	code, m := f.runWith("x\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "x\n", f.read(keysPath))
	require.Len(t, chowns(), 1, "only the new file is chowned")
	assert.NotEqual(t, ".ssh", chowns()[0].name)
}

// .ssh is made with the user's credentials: a home the user cannot write gets no .ssh (also as
// root, where the fixture's home belongs to root).
func TestWriteFailsWhenSSHDirCannotBeCreated(t *testing.T) {
	f, _ := newWriteFixture(t)
	require.NoError(t, os.RemoveAll(f.host("/home/deploy/.ssh")))
	require.NoError(t, os.Chmod(f.host("/home/deploy"), 0o555))
	t.Cleanup(func() { _ = os.Chmod(f.host("/home/deploy"), 0o755) })
	code, m := f.runWith("x\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
	assert.False(t, f.exists("/home/deploy/.ssh"))
}

// The sweep only removes directories named like an operation; a file with such a name stays,
// and a sweep without a backup root does nothing.
func TestSweepSkipsNonDirectories(t *testing.T) {
	f, _ := newWriteFixture(t)
	code, _ := f.run("sshd-dump")
	require.Equal(t, 0, code, "no backup root yet")
	f.mkdir(helperproto.BackupRoot, 0o700)
	f.write(helperproto.BackupRoot+"/"+op1, "x", 0o600)
	at := testNow.Add(-40 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(f.host(helperproto.BackupRoot+"/"+op1), at, at))
	code, _ = f.run("sshd-dump")
	require.Equal(t, 0, code)
	assert.True(t, f.exists(helperproto.BackupRoot+"/"+op1))

	// cleanup removes whatever entry has the operation's name, without following it.
	code, m := f.run("cleanup", "--op", op1)
	require.Equal(t, 0, code)
	assert.Equal(t, float64(1), m["removed"])
	assert.False(t, f.exists(helperproto.BackupRoot+"/"+op1))
}
