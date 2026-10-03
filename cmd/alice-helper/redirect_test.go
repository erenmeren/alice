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
	f.write("/data/deploy/.ssh/authorized_keys", "old\n", 0o644) // root:root in a root .ssh
	code, m := f.runWith("new\n", writeArgs(keysPath, hexOf("old\n"), op1)...)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "new\n", f.read("/data/deploy/.ssh/authorized_keys"))
}
