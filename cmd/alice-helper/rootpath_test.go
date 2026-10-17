//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/haproxyconf"
)

func (f *fixture) symlink(target, guest string) {
	f.t.Helper()
	require.NoError(f.t, os.Symlink(target, f.host(guest)))
}

func TestResolveRootPlainFile(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/etc/nginx/ssl", 0o755)
	f.write("/etc/nginx/ssl/www.crt", "x", 0o644)
	rf, err := f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	require.NoError(t, err)
	defer rf.close()
	assert.Equal(t, "/etc/nginx/ssl/www.crt", rf.resolved)
	assert.Equal(t, "www.crt", rf.name)
	assert.False(t, rf.symlinked)
	file, st, err := rf.open()
	require.NoError(t, err)
	defer func() { _ = file.Close() }()
	assert.Equal(t, int64(1), st.Size)
}

// Review Focus 1: certbot's live/ links lead into ../../archive.
func TestResolveRootFollowsRootOwnedLetsEncryptLinks(t *testing.T) {
	f := newFixture(t)
	letsEncrypt(f)
	rf, err := f.s.resolveRoot("/etc/letsencrypt/live/shop.example.test/fullchain.pem")
	require.NoError(t, err)
	defer rf.close()
	assert.Equal(t, "/etc/letsencrypt/archive/shop.example.test/fullchain3.pem", rf.resolved)
	assert.True(t, rf.symlinked)
	file, _, err := rf.open()
	require.NoError(t, err)
	_ = file.Close()
}

// letsEncrypt builds certbot's layout: live/<name>/fullchain.pem -> ../../archive/<name>/fullchain3.pem.
func letsEncrypt(f *fixture) {
	f.t.Helper()
	for _, d := range []string{"/etc", "/etc/letsencrypt", "/etc/letsencrypt/live", "/etc/letsencrypt/live/shop.example.test",
		"/etc/letsencrypt/archive", "/etc/letsencrypt/archive/shop.example.test"} {
		f.mkdir(d, 0o755)
	}
	f.write("/etc/letsencrypt/archive/shop.example.test/fullchain3.pem", "x", 0o644)
	f.write("/etc/letsencrypt/archive/shop.example.test/privkey3.pem", "k", 0o600)
	f.symlink("../../archive/shop.example.test/fullchain3.pem", "/etc/letsencrypt/live/shop.example.test/fullchain.pem")
	f.symlink("../../archive/shop.example.test/privkey3.pem", "/etc/letsencrypt/live/shop.example.test/privkey.pem")
}

// A ".." after a link to a directory steps back from where the link led, as the kernel does
// (never a textual join): the walk and the kernel agree on the file.
func TestResolveRootDotDotFollowsTheKernel(t *testing.T) {
	f := newFixture(t)
	for _, d := range []string{"/etc/nginx", "/srv", "/srv/a", "/srv/a/b"} {
		f.mkdir(d, 0o755)
	}
	f.write("/srv/a/x.crt", "kernel", 0o644)
	f.write("/etc/x.crt", "textual", 0o644)
	f.symlink("../../srv/a/b", "/etc/nginx/cur")
	f.symlink("cur/../x.crt", "/etc/nginx/l.crt")
	rf, err := f.s.resolveRoot("/etc/nginx/l.crt")
	require.NoError(t, err)
	defer rf.close()
	assert.Equal(t, "/srv/a/x.crt", rf.resolved)
	real, err := filepath.EvalSymlinks(f.host("/etc/nginx/l.crt"))
	require.NoError(t, err)
	assert.Equal(t, f.host("/srv/a/x.crt"), real, "the kernel agrees")
	file, _, err := rf.open()
	require.NoError(t, err)
	defer func() { _ = file.Close() }()
	b := make([]byte, 16)
	n, _ := file.Read(b)
	assert.Equal(t, "kernel", string(b[:n]))
}

func TestResolveRootAbsoluteLinkStaysInTheRoot(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/srv", 0o755)
	f.write("/srv/x.crt", "x", 0o644)
	f.symlink("/srv/x.crt", "/etc/nginx/x.crt")
	f.symlink("../../../../../../srv/x.crt", "/etc/nginx/y.crt")
	for _, p := range []string{"/etc/nginx/x.crt", "/etc/nginx/y.crt"} {
		rf, err := f.s.resolveRoot(p)
		require.NoError(t, err, p)
		assert.Equal(t, "/srv/x.crt", rf.resolved, "an absolute link and too many .. both stay inside the guest root")
		rf.close()
	}
}

func TestResolveRootRefusals(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/etc/nginx/ssl", 0o755)
	f.mkdir("/etc/nginx/dir.crt", 0o755)
	f.symlink("b.crt", "/etc/nginx/a.crt")
	f.symlink("a.crt", "/etc/nginx/b.crt")
	f.symlink("ssl/.", "/etc/nginx/dot.crt")
	f.write("/etc/nginx/file", "x", 0o644)
	for _, tc := range []struct {
		path string
		want error
	}{
		{"/etc/nginx/a.crt", errTooManyLinks},
		{"/etc/nginx/dir.crt", errNotRegular},
		{"/etc/nginx/dot.crt", errEscaped},
		{"/etc/nginx/file/x.crt", unix.ENOTDIR},
		{"/etc/nginx/nothere/x.crt", unix.ENOENT},
		{"relative/x.crt", errEscaped},
		{"/etc/nginx/../x.crt", errEscaped},
		{"/etc/nginx//x.crt", errEscaped},
		{"/", errEscaped},
	} {
		_, err := f.s.resolveRoot(tc.path)
		assert.True(t, errors.Is(err, tc.want), "%s: %v", tc.path, err)
	}
	rf, err := f.s.resolveRoot("/etc/nginx/ssl/missing.crt")
	require.NoError(t, err, "a missing last element is resolved; opening it reports ENOENT")
	_, _, err = rf.open()
	assert.True(t, errors.Is(err, unix.ENOENT))
	rf.close()
}

// Review Focus 2: a directory others can write is never trusted.
func TestAttackUserWritableDirectoryOnThePath(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/etc/nginx/ssl", 0o777)
	f.write("/etc/nginx/ssl/www.crt", "x", 0o644)
	_, err := f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	assert.ErrorIs(t, err, errNotRootControlled)
	require.NoError(t, os.Chmod(f.host("/etc/nginx/ssl"), 0o775))
	_, err = f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	assert.ErrorIs(t, err, errNotRootControlled, "group-writable is refused too")
	require.NoError(t, os.Chmod(f.host("/etc/nginx/ssl"), 0o1777))
	_, err = f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	assert.ErrorIs(t, err, errNotRootControlled, "a sticky world-writable directory such as /tmp is refused")
	require.NoError(t, os.Chmod(f.host("/etc/nginx/ssl"), 0o755))
	require.NoError(t, os.Chmod(f.host("/"), 0o777))
	t.Cleanup(func() { _ = os.Chmod(f.host("/"), 0o755) })
	_, err = f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	assert.ErrorIs(t, err, errNotRootControlled, "the root directory itself is checked")
}

// A link's target chain is held to the same rule: Let's Encrypt's archive must be root's too.
func TestAttackWritableDirectoryBehindALink(t *testing.T) {
	f := newFixture(t)
	letsEncrypt(f)
	require.NoError(t, os.Chmod(f.host("/etc/letsencrypt/archive/shop.example.test"), 0o777))
	_, err := f.s.resolveRoot("/etc/letsencrypt/live/shop.example.test/fullchain.pem")
	assert.ErrorIs(t, err, errNotRootControlled)
	require.NoError(t, os.Chmod(f.host("/etc/letsencrypt/archive/shop.example.test"), 0o755))
	require.NoError(t, os.Chmod(f.host("/etc/letsencrypt/archive"), 0o775))
	_, err = f.s.resolveRoot("/etc/letsencrypt/live/shop.example.test/fullchain.pem")
	assert.ErrorIs(t, err, errNotRootControlled, "a writable directory that the link's .. passes through")
}

func TestAttackHardLinkIsRefused(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.write("/etc/nginx/www.crt", "x", 0o644)
	require.NoError(t, os.Link(f.host("/etc/nginx/www.crt"), f.host("/etc/nginx/other.crt")))
	rf, err := f.s.resolveRoot("/etc/nginx/www.crt")
	require.NoError(t, err)
	defer rf.close()
	_, _, err = rf.open()
	assert.ErrorIs(t, err, errUnsafe)
}

// A FIFO (or a device) is refused before it is opened: opening a device can have side effects.
func TestAttackFIFOIsNeverOpened(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	require.NoError(t, unix.Mkfifo(f.host("/etc/nginx/www.crt"), 0o644))
	// A writer blocks in open until a reader opens the FIFO: if the helper opened it, it returns.
	opened := make(chan struct{})
	go func() {
		w, err := os.OpenFile(f.host("/etc/nginx/www.crt"), os.O_WRONLY, 0)
		if err == nil {
			_ = w.Close()
		}
		close(opened)
	}()
	time.Sleep(100 * time.Millisecond) // the writer is blocked in open
	rf, err := f.s.resolveRoot("/etc/nginx/www.crt")
	require.NoError(t, err)
	defer rf.close()
	_, _, err = rf.open()
	assert.ErrorIs(t, err, errNotRegular)
	select {
	case <-opened:
		t.Fatal("the helper opened the FIFO")
	case <-time.After(200 * time.Millisecond):
	}
	r, err := os.OpenFile(f.host("/etc/nginx/www.crt"), os.O_RDONLY, 0) // release the writer
	require.NoError(t, err)
	<-opened
	_ = r.Close()
}

// The last element swapped for a link after the walk: the open follows no link.
func TestAttackLastElementSwappedForALink(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.write("/etc/nginx/www.crt", "x", 0o644)
	f.write("/etc/shadow", "root:SECRET-HASH:19000::::::\n", 0o600)
	rf, err := f.s.resolveRoot("/etc/nginx/www.crt")
	require.NoError(t, err)
	defer rf.close()
	require.NoError(t, os.Remove(f.host("/etc/nginx/www.crt")))
	f.symlink("/etc/shadow", "/etc/nginx/www.crt")
	_, _, err = rf.open()
	assert.Error(t, err)
	assert.Equal(t, "not_regular", problemOf(err))
}

// A directory of the path swapped between its check and its open: a link is never followed and
// another directory is detected (same device and inode as checked).
func TestAttackDirectorySwappedDuringTheWalk(t *testing.T) {
	for _, tc := range []struct {
		name string
		swap func(f *fixture)
	}{
		{"for a link", func(f *fixture) {
			require.NoError(t, os.Rename(f.host("/etc/nginx/ssl"), f.host("/etc/nginx/ssl.orig")))
			f.symlink("/etc/secret", "/etc/nginx/ssl")
		}},
		{"for another directory", func(f *fixture) {
			require.NoError(t, os.Rename(f.host("/etc/nginx/ssl"), f.host("/etc/nginx/ssl.orig")))
			require.NoError(t, os.Rename(f.host("/etc/secret"), f.host("/etc/nginx/ssl")))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.mkdir("/etc/nginx", 0o755)
			f.mkdir("/etc/nginx/ssl", 0o755)
			f.write("/etc/nginx/ssl/www.crt", "x", 0o644)
			f.mkdir("/etc/secret", 0o755)
			f.write("/etc/secret/www.crt", "SECRET", 0o644)
			swapped := false
			f.s.walkHook = func(name string) {
				if name == "ssl" && !swapped {
					swapped = true
					tc.swap(f)
				}
			}
			_, err := f.s.resolveRoot("/etc/nginx/ssl/www.crt")
			require.True(t, swapped)
			assert.Error(t, err)
			assert.Equal(t, "not_root_controlled", problemOf(err))
		})
	}
}

// Root only: a link or a directory owned by another user on the path is refused.
func TestAttackUserOwnedLinkAndDirectoryAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (lchown)")
	}
	f := newFixture(t)
	f.s.rootUID = 0
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/etc/nginx/ssl", 0o755)
	f.write("/etc/nginx/ssl/www.crt", "x", 0o644)
	f.symlink("ssl/www.crt", "/etc/nginx/link.crt")
	require.NoError(t, os.Lchown(f.host("/etc/nginx/link.crt"), 1000, 1000))
	_, err := f.s.resolveRoot("/etc/nginx/link.crt")
	assert.ErrorIs(t, err, errNotRootControlled, "a user's link")
	require.NoError(t, os.Chown(f.host("/etc/nginx/ssl"), 1000, 1000))
	_, err = f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	assert.ErrorIs(t, err, errNotRootControlled, "a user's directory, even 0755")
	_, err = f.s.resolveRoot("/etc/nginx/ok.crt")
	assert.NoError(t, err, "root's own directory still resolves")
}

// Root only: a Let's Encrypt layout whose link or archive belongs to a user is refused; root's works.
func TestAttackUserOwnedLetsEncryptChainAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (lchown)")
	}
	f := newFixture(t)
	f.s.rootUID = 0
	letsEncrypt(f)
	const live = "/etc/letsencrypt/live/shop.example.test/fullchain.pem"
	rf, err := f.s.resolveRoot(live)
	require.NoError(t, err)
	rf.close()
	require.NoError(t, os.Lchown(f.host(live), 1000, 1000))
	_, err = f.s.resolveRoot(live)
	assert.ErrorIs(t, err, errNotRootControlled, "a user's live link")
	require.NoError(t, os.Lchown(f.host(live), 0, 0))
	require.NoError(t, os.Chown(f.host("/etc/letsencrypt/archive/shop.example.test"), 1000, 1000))
	_, err = f.s.resolveRoot(live)
	assert.ErrorIs(t, err, errNotRootControlled, "a user's archive directory")
}

func TestCertName(t *testing.T) {
	for name, want := range map[string]bool{"www.crt": true, "fullchain1.pem": true, "a.key": true, "a.cer": true, "a.cert": true,
		"a.chained": true, "a.fullchain": true, "shadow": false, "a.crt.bak": false, "a.conf": false, "": false, ".pem": false} {
		assert.Equal(t, want, certName(name), name)
	}
}

func TestProblemOf(t *testing.T) {
	for err, want := range map[error]string{
		unix.ENOENT: "missing", errNotRootControlled: "not_root_controlled", errEscaped: "not_root_controlled",
		errTooManyLinks: "not_regular", errUnsafe: "hard_linked", errNotRegular: "not_regular",
		unix.ENOTDIR: "not_regular", unix.ELOOP: "not_regular", errTooLarge: "too_large", unix.EIO: "unreadable",
		errSpecialFS: "special_filesystem",
	} {
		assert.Equal(t, want, problemOf(err), "%v", err)
	}
}

// The production file system check sees the real /proc as special and the test directory as not.
func TestProductionFSMagic(t *testing.T) {
	s := productionSys()
	fd, err := unix.Open("/proc/self", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skip("no /proc")
	}
	defer func() { _ = unix.Close(fd) }()
	assert.ErrorIs(t, s.normalFS(fd), errSpecialFS)
	tmp, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	defer func() { _ = unix.Close(tmp) }()
	assert.NoError(t, s.normalFS(tmp))
	assert.ErrorIs(t, (&sys{fsMagic: func(int) (int64, error) { return 0, unix.EBADF }}).normalFS(tmp), errSpecialFS,
		"an unreadable file system type is refused")
}

// C9: listRootDir walks to the directory as walkRoot walks to a file, checks the directory itself
// and lists only regular entries and links that walk to a regular file.
func TestListRootDir(t *testing.T) {
	setup := func(t *testing.T) *fixture {
		f := newFixture(t)
		for _, d := range []string{"/etc/haproxy", "/etc/haproxy/certs", "/etc/haproxy/certs/sub", "/srv"} {
			f.mkdir(d, 0o755)
		}
		f.write("/etc/haproxy/certs/a.pem", "a", 0o644)
		f.symlink("a.pem", "/etc/haproxy/certs/link.pem")
		require.NoError(t, unix.Mkfifo(f.host("/etc/haproxy/certs/fifo"), 0o644))
		return f
	}
	f := setup(t)
	names, isDir, err := f.s.listRootDir("/etc/haproxy/certs")
	require.NoError(t, err)
	assert.True(t, isDir)
	assert.Equal(t, []string{"a.pem", "link.pem"}, names)

	for name, tc := range map[string]struct {
		change func(f *fixture)
		dir    string
	}{
		"a file":                    {func(*fixture) {}, "/etc/haproxy/certs/a.pem"},
		"a link to a file":          {func(*fixture) {}, "/etc/haproxy/certs/link.pem"},
		"missing":                   {func(*fixture) {}, "/etc/haproxy/none"},
		"below a file":              {func(*fixture) {}, "/etc/haproxy/certs/a.pem/x"},
		"a FIFO":                    {func(*fixture) {}, "/etc/haproxy/certs/fifo"},
		"not a helper path":         {func(*fixture) {}, "/etc/haproxy/../haproxy/certs"},
		"the root":                  {func(*fixture) {}, "/"},
		"a 0777 directory":          {func(f *fixture) { require.NoError(t, os.Chmod(f.host("/etc/haproxy/certs"), 0o777)) }, "/etc/haproxy/certs"},
		"a 1777 directory":          {func(f *fixture) { require.NoError(t, os.Chmod(f.host("/etc/haproxy/certs"), 0o1777)) }, "/etc/haproxy/certs"},
		"a 0775 directory":          {func(f *fixture) { require.NoError(t, os.Chmod(f.host("/etc/haproxy/certs"), 0o775)) }, "/etc/haproxy/certs"},
		"a group-writable parent":   {func(f *fixture) { require.NoError(t, os.Chmod(f.host("/etc/haproxy"), 0o775)) }, "/etc/haproxy/certs"},
		"a link loop":               {func(f *fixture) { f.symlink("loop", "/etc/haproxy/loop") }, "/etc/haproxy/loop"},
		"a link to a 1777 dir":      {func(f *fixture) { f.mkdir("/srv/tmp", 0o1777); f.symlink("/srv/tmp", "/etc/haproxy/t") }, "/etc/haproxy/t"},
		"a link to a missing dir":   {func(f *fixture) { f.symlink("/srv/none", "/etc/haproxy/t") }, "/etc/haproxy/t"},
		"a link to the root (dot)":  {func(f *fixture) { f.symlink("/.", "/etc/haproxy/t") }, "/etc/haproxy/t"},
		"a link escaping by dotdot": {func(f *fixture) { f.symlink("../../..", "/etc/haproxy/t") }, "/etc/haproxy/t"},
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			tc.change(f)
			names, isDir, err := f.s.listRootDir(tc.dir)
			require.NoError(t, err)
			assert.False(t, isDir)
			assert.Nil(t, names)
		})
	}

	// Concern 5: the directory's own dirOK is checked before it is opened, so a directory that is
	// not root-controlled is never opened (walkHook runs just before the open, fsMagic after it).
	t.Run("an unsafe directory is never opened", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o777, 0o1777, 0o775} {
			f := setup(t)
			require.NoError(t, os.Chmod(f.host("/etc/haproxy/certs"), mode))
			certs, opened, checked := f.host("/etc/haproxy/certs"), 0, 0
			f.s.walkHook = func(name string) {
				if name == "certs" {
					opened++
				}
			}
			f.s.fsMagic = func(fd int) (int64, error) {
				if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil && p == certs {
					checked++
				}
				return unix.EXT4_SUPER_MAGIC, nil
			}
			_, isDir, err := f.s.listRootDir("/etc/haproxy/certs")
			require.NoError(t, err)
			assert.False(t, isDir)
			assert.Zero(t, opened, "mode %o: refused before the open", mode)
			assert.Zero(t, checked, "mode %o", mode)
		}
	})
	t.Run("a link to a directory", func(t *testing.T) {
		for _, target := range []string{"certs", "/etc/haproxy/certs", "certs/", "certs/.", "/etc/haproxy/certs/sub/.."} {
			f := setup(t)
			f.symlink(target, "/etc/haproxy/live")
			names, isDir, err := f.s.listRootDir("/etc/haproxy/live")
			require.NoError(t, err, target)
			assert.True(t, isDir, target)
			assert.Equal(t, []string{"a.pem", "link.pem"}, names, target)
		}
	})
	t.Run("links inside", func(t *testing.T) {
		f := setup(t)
		f.mkdir("/srv/open", 0o777)
		f.write("/srv/open/u.pem", "u", 0o644)
		f.write("/srv/r.pem", "r", 0o644)
		f.symlink("sub", "/etc/haproxy/certs/dir.pem")            // a directory: not followed
		f.symlink("/srv/open/u.pem", "/etc/haproxy/certs/u.pem")  // through a 0777 directory
		f.symlink("/srv/r.pem", "/etc/haproxy/certs/r.pem")       // elsewhere, root-controlled
		f.symlink("/srv/gone.pem", "/etc/haproxy/certs/gone.pem") // dangling
		f.symlink("/proc/self/x", "/etc/haproxy/certs/proc.pem")  // missing under the root
		names, isDir, err := f.s.listRootDir("/etc/haproxy/certs")
		require.NoError(t, err)
		assert.True(t, isDir)
		assert.Equal(t, []string{"a.pem", "link.pem", "r.pem"}, names)
	})
	t.Run("special file system", func(t *testing.T) {
		f := setup(t)
		certs := f.host("/etc/haproxy/certs")
		f.s.fsMagic = func(fd int) (int64, error) {
			if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil && p == certs {
				return unix.FUSE_SUPER_MAGIC, nil
			}
			return unix.EXT4_SUPER_MAGIC, nil
		}
		_, isDir, err := f.s.listRootDir("/etc/haproxy/certs")
		require.NoError(t, err)
		assert.False(t, isDir)
	})
	t.Run("swapped for a link before the open", func(t *testing.T) {
		f := setup(t)
		f.mkdir("/srv/evil", 0o755)
		f.s.walkHook = func(name string) {
			if name == "certs" {
				require.NoError(t, os.Rename(f.host("/etc/haproxy/certs"), f.host("/etc/haproxy/old")))
				f.symlink("/srv/evil", "/etc/haproxy/certs")
			}
		}
		_, isDir, err := f.s.listRootDir("/etc/haproxy/certs")
		require.NoError(t, err)
		assert.False(t, isDir)
	})
	t.Run("too many entries", func(t *testing.T) {
		f := setup(t)
		for i := range haproxyconf.MaxDirEntries - 3 { // a.pem, link.pem, fifo and sub are already there: 4097
			f.write(fmt.Sprintf("/etc/haproxy/certs/%04d.pem", i), "", 0o644)
		}
		names, isDir, err := f.s.listRootDir("/etc/haproxy/certs")
		assert.ErrorIs(t, err, errTooManyEntries)
		assert.True(t, isDir)
		assert.Nil(t, names)
		require.NoError(t, os.Remove(f.host("/etc/haproxy/certs/0000.pem")))
		names, _, err = f.s.listRootDir("/etc/haproxy/certs")
		require.NoError(t, err)
		assert.Len(t, names, haproxyconf.MaxDirEntries-2)
	})
}
