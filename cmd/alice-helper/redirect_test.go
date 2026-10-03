//go:build linux

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
)

// absoluteHomePattern is an absolute AuthorizedKeysFile pattern that names a file in the home.
const absoluteHomePattern = "authorizedkeysfile /home/%u/.ssh/authorized_keys\n"

// A-1 (final review PoC): with an absolute pattern that points into the home, a user replaces
// ~/.ssh with a symlink to /root/.ssh. Root's file must never be read, listed with a hash or
// rewritten as "deploy's" file.
func TestAttackAbsolutePatternRedirectsToRoot(t *testing.T) {
	for _, target := range []string{"abs", "../../root/.ssh"} {
		t.Run(target, func(t *testing.T) {
			f, chowns := newWriteFixture(t)
			f.perUser[deployCtx] = absoluteHomePattern
			f.mkdir("/root/.ssh", 0o700)
			f.write("/root/.ssh/authorized_keys", "ssh-ed25519 ROOTKEY root@admin\n", 0o600)
			require.NoError(t, os.RemoveAll(f.host("/home/deploy/.ssh")))
			link := target
			if link == "abs" {
				link = f.host("/root/.ssh")
			}
			require.NoError(t, os.Symlink(link, f.host("/home/deploy/.ssh")))
			f.asUser("/home/deploy", "/home/deploy/.ssh")

			code, m := f.run("authkeys-read", keysPath)
			assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
			assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
			assert.NotContains(t, f.out.String(), "ROOTKEY")

			_, m = f.run("authkeys-list")
			fi := filesOf(listUser(t, m, "deploy"))[0]
			assert.Equal(t, keysPath, fi["path"])
			assert.Equal(t, true, fi["unsupported"])
			assert.Equal(t, "", fi["sha256"])
			assert.Equal(t, "", fi["owner"])

			code, m = f.runWith("ssh-ed25519 ATTACKER deploy@evil\n",
				writeArgs(keysPath, hexOf("ssh-ed25519 ROOTKEY root@admin\n"), op1)...)
			assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
			assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
			assert.Equal(t, "ssh-ed25519 ROOTKEY root@admin\n", f.read("/root/.ssh/authorized_keys"))
			assert.Empty(t, chowns())
			assert.False(t, f.exists(helperproto.BackupRoot+"/"+op1))
		})
	}
}

// A-1: an absolute pattern inside the home is handled like a home-relative one: a symlink that
// stays in the home is still followed, as for ".ssh/authorized_keys".
func TestAbsolutePatternInsideTheHomeBehavesLikeARelativeOne(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.perUser[deployCtx] = absoluteHomePattern
	f.write(keysPath, "mine\n", 0o600)
	f.asUser("/home/deploy/.ssh", keysPath)
	code, m := f.run("authkeys-read", keysPath)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "deploy", m["owner"])

	// A missing .ssh is created, as for a relative pattern.
	require.NoError(t, os.RemoveAll(f.host("/home/deploy/.ssh")))
	f.asUser("/home/deploy")
	code, m = f.runWith("x\n", writeArgs(keysPath, helperproto.AbsentSHA256, op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "x\n", f.read(keysPath))
}

// A-1: the directory of an absolute pattern outside the home must be the directory itself, not a
// symlink to another one.
func TestAbsolutePatternDirectoryMustNotBeASymlink(t *testing.T) {
	f, chowns := newWriteFixture(t)
	f.perUser[deployCtx] = "authorizedkeysfile /etc/ssh/keys/%u\n"
	f.mkdir("/srv/keys", 0o755)
	f.write("/srv/keys/deploy", "admin\n", 0o644)
	require.NoError(t, os.Symlink("../../srv/keys", f.host("/etc/ssh/keys")))

	code, m := f.run("authkeys-read", "/etc/ssh/keys/deploy")
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	_, m = f.run("authkeys-list")
	assert.Equal(t, true, filesOf(listUser(t, m, "deploy"))[0]["unsupported"])
	code, m = f.runWith("y\n", writeArgs("/etc/ssh/keys/deploy", hexOf("admin\n"), op1)...)
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	assert.Equal(t, "admin\n", f.read("/srv/keys/deploy"))
	assert.Empty(t, chowns())
}

// A-1: every existing directory of an absolute pattern outside the home must be root's and not
// writable by group or others; otherwise the file is not a candidate (it is listed, flagged).
func TestAbsolutePatternDirectoryChainMustBeRootControlled(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.perUser[deployCtx] = "authorizedkeysfile /etc/ssh/keys/%u\n"
	f.mkdir("/etc/ssh/keys", 0o755)
	f.write("/etc/ssh/keys/deploy", "x\n", 0o644)
	code, _ := f.run("authkeys-read", "/etc/ssh/keys/deploy")
	require.Equal(t, 0, code)

	for _, dir := range []string{"/etc/ssh/keys", "/etc", "/"} {
		st, err := os.Stat(f.host(dir))
		require.NoError(t, err)
		require.NoError(t, os.Chmod(f.host(dir), 0o775))
		code, m := f.run("authkeys-read", "/etc/ssh/keys/deploy")
		assert.Equal(t, helperproto.ExitRefused, code, dir)
		assert.Equal(t, helperproto.CodePathNotAllowed, m["code"], dir)
		require.NoError(t, os.Chmod(f.host(dir), st.Mode().Perm()))
	}

	if os.Getuid() != 0 {
		return // ownership needs root: the fixture's directories belong to the test user
	}
	require.NoError(t, os.Chown(f.host("/etc/ssh/keys"), f.uid, f.uid))
	code, m := f.run("authkeys-read", "/etc/ssh/keys/deploy")
	assert.Equal(t, helperproto.ExitRefused, code, "a key directory the user owns")
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	require.NoError(t, os.Chown(f.host("/etc/ssh/keys"), 0, 0))
	require.NoError(t, os.Chown(f.host("/etc"), f.uid, f.uid))
	code, m = f.run("authkeys-read", "/etc/ssh/keys/deploy")
	assert.Equal(t, helperproto.ExitRefused, code, "a directory above it that the user owns")
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
}

// A-1 (root only): a symlink in the home that leads into a root-owned directory of the home is
// refused for reads too, not only for writes.
func TestReadThroughSymlinkIntoARootDirectoryIsRefused(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root: the directory the link leads to must belong to root")
	}
	f := newFixture(t)
	require.NoError(t, os.Chown(f.host("/home/deploy"), f.uid, f.uid))
	require.NoError(t, os.Chown(f.host("/home/deploy/.ssh"), f.uid, f.uid))
	f.mkdir("/home/deploy/rootdir", 0o755)
	f.write("/home/deploy/rootdir/keys", "ssh-ed25519 ADMINKEY admin\n", 0o644)
	require.NoError(t, os.Symlink("../rootdir/keys", f.host("/home/deploy/.ssh/authorized_keys2")))

	code, m := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys2")
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodeUnsafeFile, m["code"])
	assert.NotContains(t, f.out.String(), "ADMINKEY")
	_, m = f.run("authkeys-list")
	fi := filesOf(listUser(t, m, "deploy"))[1]
	assert.Equal(t, true, fi["unsupported"])
	assert.Equal(t, "", fi["sha256"])
}

// A-1 (root only, Task 7 parked item): when the home itself is a symlink (/home/deploy ->
// /data/deploy), a root-owned .ssh below it is not "reached through a symlink": the path is
// compared with the listed one rebased on the resolved home.
func TestWriteWhenTheHomeIsASymlink(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root: the .ssh directory must belong to root")
	}
	f := newFixture(t)
	f.s.chown = productionSys().chown
	f.mkdir("/data", 0o755)
	require.NoError(t, os.Rename(f.host("/home/deploy"), f.host("/data/deploy")))
	require.NoError(t, os.Symlink("../data/deploy", f.host("/home/deploy")))
	require.NoError(t, os.Chown(f.host("/data/deploy"), f.uid, f.uid)) // the resolved home is the user's
	f.write("/data/deploy/.ssh/authorized_keys", "old\n", 0o644)       // root:root in a root .ssh
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "new\n", f.read("/data/deploy/.ssh/authorized_keys"))
}

// addSvc adds the account svc (uid 1500) whose home /srv/homes/svc sits below /srv/homes.
func (f *fixture) addSvc() {
	f.t.Helper()
	f.mkdir("/srv", 0o755)
	f.mkdir("/srv/homes", 0o755)
	f.write("/etc/passwd", f.read("/etc/passwd")+"svc:x:1500:1500::/srv/homes/svc:/bin/bash\n", 0o644)
}

// Re-review item 1: another user can write the directory that holds svc's home and replaces the
// home with a symlink to /root. Root's keys must never be read, hashed or rewritten as svc's.
func TestAttackHomeReplacedBySymlinkToRoot(t *testing.T) {
	f, chowns := newWriteFixture(t)
	f.addSvc()
	f.mkdir("/root/.ssh", 0o700)
	f.write("/root/.ssh/authorized_keys", "ssh-ed25519 ROOTKEY root@admin\n", 0o600)
	require.NoError(t, os.Chmod(f.host("/srv/homes"), 0o777)) // eve may write it
	require.NoError(t, os.Symlink(f.host("/root"), f.host("/srv/homes/svc")))
	if os.Getuid() == 0 {
		require.NoError(t, os.Chmod(f.host("/srv/homes"), 0o755))
		require.NoError(t, os.Chown(f.host("/srv/homes"), 3000, 3000)) // owned by eve
	}
	const svcKeys = "/srv/homes/svc/.ssh/authorized_keys"

	code, m := f.run("authkeys-read", svcKeys)
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	assert.NotContains(t, f.out.String(), "ROOTKEY")

	_, m = f.run("authkeys-list") // root's own entry may show its hash; svc's entries never do
	for _, fi := range filesOf(listUser(t, m, "svc")) {
		assert.Equal(t, true, fi["unsupported"], "%v", fi)
		assert.Equal(t, "", fi["sha256"])
	}

	code, m = f.runWith("ssh-ed25519 ATTACKER eve@evil\n", writeArgs(svcKeys, hexOf("ssh-ed25519 ROOTKEY root@admin\n"), op1)...)
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	assert.Equal(t, "ssh-ed25519 ROOTKEY root@admin\n", f.read("/root/.ssh/authorized_keys"))
	assert.Empty(t, chowns())
}

// Re-review item 1: a real home below a directory others can write could be swapped between the
// scan and the open, so it is not a candidate either; a root-controlled parent chain is required
// for every home.
func TestHomeBelowAWritableDirectoryIsNotACandidate(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write(keysPath, "mine\n", 0o600)
	f.asUser("/home/deploy", "/home/deploy/.ssh", keysPath)
	code, m := f.run("authkeys-read", keysPath)
	require.Equal(t, 0, code, "a root-controlled parent chain: %v", m)

	for _, dir := range []string{"/home", "/"} {
		st, err := os.Stat(f.host(dir))
		require.NoError(t, err)
		require.NoError(t, os.Chmod(f.host(dir), 0o777))
		code, m := f.run("authkeys-read", keysPath)
		assert.Equal(t, helperproto.ExitRefused, code, dir)
		assert.Equal(t, helperproto.CodePathNotAllowed, m["code"], dir)
		_, m = f.run("authkeys-list")
		assert.Equal(t, true, filesOf(listUser(t, m, "deploy"))[0]["unsupported"], dir)
		require.NoError(t, os.Chmod(f.host(dir), st.Mode().Perm()))
	}
	if os.Getuid() != 0 {
		return
	}
	require.NoError(t, os.Chown(f.host("/home"), 3000, 3000))
	code, m = f.run("authkeys-read", keysPath)
	assert.Equal(t, helperproto.ExitRefused, code, "a parent owned by another user")
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
}

// Re-review item 1 (root only): a symlinked home is accepted only when the resolved home belongs
// to the account (or the account is root) and its own parent chain is root-controlled.
func TestSymlinkedHomeMustBelongToTheAccount(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root: the resolved home must belong to another account")
	}
	f := newFixture(t)
	f.mkdir("/data", 0o755)
	require.NoError(t, os.Rename(f.host("/home/deploy"), f.host("/data/deploy")))
	require.NoError(t, os.Symlink("../data/deploy", f.host("/home/deploy")))
	f.write("/data/deploy/.ssh/authorized_keys", "x\n", 0o644)
	require.NoError(t, os.Chown(f.host("/data/deploy"), 2000, 2000)) // someone else's directory
	code, m := f.run("authkeys-read", keysPath)
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	require.NoError(t, os.Chown(f.host("/data/deploy"), f.uid, f.uid))
	code, m = f.run("authkeys-read", keysPath)
	assert.Equal(t, 0, code, "%v", m)
	require.NoError(t, os.Chmod(f.host("/data"), 0o777))
	code, m = f.run("authkeys-read", keysPath)
	assert.Equal(t, helperproto.ExitRefused, code, "the resolved home sits in a writable directory: %v", m)
}

// Re-review item 1, without root: a symlinked home is followed when the resolved home is the
// account's and sits in a root-controlled directory; another account's directory, or one in a
// writable directory, is refused.
func TestSymlinkedHomeRules(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.mkdir("/data", 0o755)
	require.NoError(t, os.Rename(f.host("/home/deploy"), f.host("/data/deploy")))
	require.NoError(t, os.Symlink("../data/deploy", f.host("/home/deploy")))
	f.write("/data/deploy/.ssh/authorized_keys", "mine\n", 0o600)
	f.asUser("/data/deploy", "/data/deploy/.ssh", "/data/deploy/.ssh/authorized_keys")
	code, m := f.run("authkeys-read", keysPath)
	require.Equal(t, 0, code, "%v", m)

	require.NoError(t, os.Chmod(f.host("/data"), 0o777))
	code, m = f.run("authkeys-read", keysPath)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"], "the resolved home sits in a writable directory: %d", code)
	require.NoError(t, os.Chmod(f.host("/data"), 0o755))

	// alice-svc (uid 998) whose home is linked to deploy's directory: not its own.
	require.NoError(t, os.RemoveAll(f.host("/var/lib/alice-svc")))
	require.NoError(t, os.Symlink("../../data/deploy", f.host("/var/lib/alice-svc")))
	code, m = f.run("authkeys-read", "/var/lib/alice-svc/.ssh/authorized_keys")
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"], "another account's directory: %d", code)
}

// moveHomeBehindALink makes /home a symlink to /data/home (homes moved to a larger volume, or
// Fedora Silverblue's /home -> var/home): root's link in root's directory.
func (f *fixture) moveHomeBehindALink() {
	f.t.Helper()
	f.mkdir("/data", 0o755)
	require.NoError(f.t, os.Rename(f.host("/home"), f.host("/data/home")))
	require.NoError(f.t, os.Symlink("data/home", f.host("/home")))
	f.asUser("/data/home/deploy", "/data/home/deploy/.ssh")
}

// Round 3 item 1: a root-owned symlink among the directories above the home, whose target chain is
// root-controlled too, is as safe as a directory: accounts below it work (read, list, write).
func TestHomeBehindARootOwnedSymlinkWorks(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.moveHomeBehindALink()
	f.write("/data/home/deploy/.ssh/authorized_keys", "old\n", 0o600)
	f.asUser("/data/home/deploy/.ssh/authorized_keys")
	code, m := f.run("authkeys-read", keysPath)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "deploy", m["owner"])
	_, m = f.run("authkeys-list")
	fi := filesOf(listUser(t, m, "deploy"))[0]
	assert.Equal(t, false, fi["unsupported"])
	assert.Equal(t, hexOf("old\n"), fi["sha256"])
	if os.Getuid() == 0 {
		f.s.chown = productionSys().chown
	}
	code, m = f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "new\n", f.read("/data/home/deploy/.ssh/authorized_keys"))
}

// Round 3 item 1: the target chain of the link must be root-controlled too, and a link loop is
// refused (not followed forever).
func TestHomeBehindASymlinkIntoAWritableChainIsUnsupported(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.moveHomeBehindALink()
	f.write("/data/home/deploy/.ssh/authorized_keys", "old\n", 0o600)
	f.asUser("/data/home/deploy/.ssh/authorized_keys")
	require.NoError(t, os.Chmod(f.host("/data"), 0o777))
	code, m := f.run("authkeys-read", keysPath)
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	_, m = f.run("authkeys-list")
	assert.Equal(t, true, filesOf(listUser(t, m, "deploy"))[0]["unsupported"])
	code, m = f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"], "%d", code)
	assert.Equal(t, "old\n", f.read("/data/home/deploy/.ssh/authorized_keys"))
	require.NoError(t, os.Chmod(f.host("/data"), 0o755))

	assert.True(t, f.s.rootControlled("/loop/x"), "missing components are allowed")
	require.NoError(t, os.Symlink("loop2", f.host("/loop")))
	require.NoError(t, os.Symlink("loop", f.host("/loop2")))
	assert.False(t, f.s.rootControlled("/loop/x"), "a symlink loop is refused")
}

// Round 3 item 1 (root only): a link owned by another user is refused, even into a
// root-controlled chain.
func TestHomeBehindASymlinkOwnedByAnotherUserIsUnsupported(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root: the link must belong to another user")
	}
	f, _ := newWriteFixture(t)
	f.moveHomeBehindALink()
	f.write("/data/home/deploy/.ssh/authorized_keys", "old\n", 0o600)
	f.asUser("/data/home/deploy/.ssh/authorized_keys")
	require.NoError(t, os.Lchown(f.host("/home"), 3000, 3000))
	code, m := f.run("authkeys-read", keysPath)
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	require.NoError(t, os.Lchown(f.host("/home"), 0, 0))
	require.NoError(t, os.Chown(f.host("/data/home"), 3000, 3000))
	code, m = f.run("authkeys-read", keysPath)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"], "the target is another user's directory: %d", code)
}

// Round 4 item 1 (the reviewer's PoC): a link target with ".." was cleaned as text before the
// symlink before it was followed, so the check looked at another path than the kernel opens.
// /a -> evil/sub and /home -> a/../real/home (both root's) really lead to /evil/real/home, below
// a world-writable /evil. Such a target is refused: the account is unsupported.
func TestHomeBehindALinkWithDotDotIsUnsupported(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.mkdir("/evil", 0o777)
	f.mkdir("/evil/sub", 0o755)
	f.mkdir("/evil/real", 0o755)
	require.NoError(t, os.Rename(f.host("/home"), f.host("/evil/real/home")))
	require.NoError(t, os.Symlink("evil/sub", f.host("/a")))
	require.NoError(t, os.Symlink("a/../real/home", f.host("/home")))
	f.write("/evil/real/home/deploy/.ssh/authorized_keys", "old\n", 0o600)
	f.asUser("/evil/real/home/deploy", "/evil/real/home/deploy/.ssh", "/evil/real/home/deploy/.ssh/authorized_keys")

	assert.False(t, f.s.rootControlled("/home"))
	code, m := f.run("authkeys-read", keysPath)
	assert.Equal(t, helperproto.ExitRefused, code, "%v", m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	_, m = f.run("authkeys-list")
	assert.Equal(t, true, filesOf(listUser(t, m, "deploy"))[0]["unsupported"])
	code, m = f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"], "%d", code)
	assert.Equal(t, "old\n", f.read("/evil/real/home/deploy/.ssh/authorized_keys"))

	// A plain ".." target without an earlier link is refused too (no legitimate layout needs one).
	require.NoError(t, os.Remove(f.host("/home")))
	require.NoError(t, os.Symlink("evil/../evil/real/home", f.host("/home")))
	assert.False(t, f.s.rootControlled("/home"))
}
