//go:build linux

package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// programFixture is a fixture with /usr/sbin and /usr/lib (root's, 0755) for the web-server
// programs; rootUID is the test's uid (newFixture).
func programFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	for _, d := range []string{"/usr", "/usr/sbin", "/usr/lib"} {
		f.mkdir(d, 0o755)
	}
	return f
}

// script writes a #!/bin/sh program at guest that appends its name and arguments to marker (a
// guest path, "" for none) and prints "ok".
func (f *fixture) script(guest, marker string, mode os.FileMode) {
	f.t.Helper()
	body := "#!/bin/sh\n"
	if marker != "" {
		body += "echo \"$0 $*\" >> '" + f.host(marker) + "'\n"
	}
	f.write(guest, body+"echo ok\n", mode)
}

func needSh(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
}

// untrustedPath is the path a programError names (errProgramUntrusted through errors.As).
func untrustedPath(t *testing.T, err error) string {
	t.Helper()
	require.ErrorIs(t, err, errProgramUntrusted)
	var pe *programError
	require.True(t, errors.As(err, &pe), "%v", err)
	return pe.path
}

// Ruling 15: each program path that exists must walk (every directory and link root's) and be a
// regular file owned by root with no group or other write bit; a missing path passes.
func TestTrustedProgram(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(f *fixture)
		path    string
		trusted bool
	}{
		{"a 0755 file in 0755 directories", func(f *fixture) { f.write("/usr/sbin/nginx", "x", 0o755) }, "/usr/sbin/nginx", true},
		{"a 0700 file", func(f *fixture) { f.write("/usr/sbin/nginx", "x", 0o700) }, "/usr/sbin/nginx", true},
		{"a missing path", func(*fixture) {}, "/usr/sbin/nginx", true},
		{"a missing parent directory", func(*fixture) {}, "/etc/apache2/envvars", true},
		{"a parent that is a file", func(f *fixture) { f.write("/usr/sbin/apache2", "x", 0o755) }, "/usr/sbin/apache2/x", true},
		{"a root-owned link to a 0755 file", func(f *fixture) {
			f.mkdir("/usr/lib/apache2", 0o755)
			f.write("/usr/lib/apache2/apache2", "x", 0o755)
			require.NoError(t, os.Symlink("../lib/apache2/apache2", f.host("/usr/sbin/apache2")))
		}, "/usr/sbin/apache2", true},
		{"a root-owned link to a missing file", func(f *fixture) {
			require.NoError(t, os.Symlink("/opt/gone/nginx", f.host("/usr/sbin/nginx")))
		}, "/usr/sbin/nginx", true},
		{"a hard link", func(f *fixture) {
			f.write("/usr/sbin/nginx", "x", 0o755)
			require.NoError(t, os.Link(f.host("/usr/sbin/nginx"), f.host("/usr/lib/nginx")))
		}, "/usr/sbin/nginx", true},

		{"a 0775 file", func(f *fixture) { f.write("/usr/sbin/nginx", "x", 0o775) }, "/usr/sbin/nginx", false},
		{"a 0757 file", func(f *fixture) { f.write("/usr/sbin/nginx", "x", 0o757) }, "/usr/sbin/nginx", false},
		{"a 0666 envvars", func(f *fixture) {
			f.mkdir("/etc/apache2", 0o755)
			f.write("/etc/apache2/envvars", "x", 0o666)
		}, "/etc/apache2/envvars", false},
		{"a file in a 0777 directory", func(f *fixture) {
			require.NoError(t, os.Chmod(f.host("/usr/sbin"), 0o777))
			f.write("/usr/sbin/nginx", "x", 0o755)
		}, "/usr/sbin/nginx", false},
		{"a missing file in a 0777 directory", func(f *fixture) {
			require.NoError(t, os.Chmod(f.host("/usr/sbin"), 0o777))
		}, "/usr/sbin/nginx", false},
		{"a link into a 0777 directory", func(f *fixture) {
			f.mkdir("/opt", 0o777)
			f.write("/opt/nginx", "x", 0o755)
			require.NoError(t, os.Symlink("/opt/nginx", f.host("/usr/sbin/nginx")))
		}, "/usr/sbin/nginx", false},
		{"a FIFO", func(f *fixture) { require.NoError(t, unix.Mkfifo(f.host("/usr/sbin/nginx"), 0o755)) }, "/usr/sbin/nginx", false},
		{"a directory", func(f *fixture) { f.mkdir("/usr/sbin/nginx", 0o755) }, "/usr/sbin/nginx", false},
		{"a file on FUSE", func(f *fixture) {
			f.write("/usr/sbin/nginx", "x", 0o755)
			(&nginxWorld{f: f}).magicAt("/usr/sbin/nginx", unix.FUSE_SUPER_MAGIC)
		}, "/usr/sbin/nginx", false},
		{"a relative path", func(*fixture) {}, "usr/sbin/nginx", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := programFixture(t)
			tc.setup(f)
			err := f.s.trustedProgram(tc.path)
			if tc.trusted {
				assert.NoError(t, err)
				return
			}
			assert.Equal(t, tc.path, untrustedPath(t, err))
		})
	}
}

// The owner check needs a file another user owns, which only root can make.
func TestTrustedProgramOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("chown to another user needs root (the root-only suite)")
	}
	f := programFixture(t)
	f.write("/usr/sbin/nginx", "x", 0o755)
	require.NoError(t, os.Chown(f.host("/usr/sbin/nginx"), 65534, 0))
	assert.Equal(t, "/usr/sbin/nginx", untrustedPath(t, f.s.trustedProgram("/usr/sbin/nginx")))
	require.NoError(t, os.Chown(f.host("/usr/sbin/nginx"), 0, 0))
	require.NoError(t, os.Symlink("nginx", f.host("/usr/sbin/nginx-link")))
	require.NoError(t, os.Lchown(f.host("/usr/sbin/nginx-link"), 65534, 0))
	assert.Equal(t, "/usr/sbin/nginx-link", untrustedPath(t, f.s.trustedProgram("/usr/sbin/nginx-link")), "a link another user owns")
}

// Every path is checked, in order, and the first untrusted one is named.
func TestTrustedProgramNamesTheFirstUntrustedPath(t *testing.T) {
	f := programFixture(t)
	f.write("/usr/sbin/a", "x", 0o755)
	f.write("/usr/sbin/b", "x", 0o775)
	f.write("/usr/sbin/c", "x", 0o757)
	assert.NoError(t, f.s.trustedProgram())
	assert.NoError(t, f.s.trustedProgram("/usr/sbin/a", "/usr/sbin/missing"))
	assert.Equal(t, "/usr/sbin/b", untrustedPath(t, f.s.trustedProgram("/usr/sbin/a", "/usr/sbin/b", "/usr/sbin/c")))
	assert.Equal(t, "/usr/sbin/b: "+errProgramUntrusted.Error(), (&programError{path: "/usr/sbin/b"}).Error())
}

func TestRunGuardedRunsATrustedProgram(t *testing.T) {
	needSh(t)
	f := programFixture(t)
	const prog, marker = "/usr/sbin/prog", "/marker"
	f.script(prog, marker, 0o755)

	out, _, err := f.s.runGuarded(context.Background(), prog, nil, 1<<10, "-t")
	require.NoError(t, err)
	assert.Equal(t, "ok\n", string(out))
	assert.Equal(t, f.host(prog)+" -t\n", f.read(marker), "the program under the root ran, with the arguments")
	require.NoError(t, os.Remove(f.host(marker)))

	require.NoError(t, os.Chmod(f.host(prog), 0o775))
	out, _, err = f.s.runGuarded(context.Background(), prog, nil, 1<<10, "-t")
	assert.Equal(t, prog, untrustedPath(t, err))
	assert.Nil(t, out)
	assert.NoFileExists(t, f.host(marker), "the program never ran")

	require.NoError(t, os.Chmod(f.host(prog), 0o755))
	f.write("/usr/lib/loaded", "x", 0o666)
	_, _, err = f.s.runGuarded(context.Background(), prog, []string{"/usr/lib/missing", "/usr/lib/loaded"}, 1<<10)
	assert.Equal(t, "/usr/lib/loaded", untrustedPath(t, err), "a file it loads")
	assert.NoFileExists(t, f.host(marker))

	_, _, err = f.s.runGuarded(context.Background(), "/usr/sbin/missing", nil, 1<<10)
	assert.True(t, missingProgram(err), "a missing program is still not found: %v", err)
}

// apache2ctl sources /etc/apache2/envvars and runs /usr/sbin/apache2: all three are checked.
// httpd (RHEL family) loads neither.
func TestApacheCtlGuardsEnvvarsAndBinary(t *testing.T) {
	needSh(t)
	f := programFixture(t)
	f.mkdir("/etc/apache2", 0o755)
	f.script(apache2ctlPath, "/marker", 0o755)
	f.write("/etc/apache2/envvars", "export APACHE_RUN_USER=www-data\n", 0o666)
	_, _, err := f.s.runApacheCtl(context.Background(), "-V")
	assert.Equal(t, "/etc/apache2/envvars", untrustedPath(t, err))
	assert.NoFileExists(t, f.host("/marker"))

	require.NoError(t, os.Chmod(f.host("/etc/apache2/envvars"), 0o644))
	f.write("/usr/sbin/apache2", "x", 0o775)
	_, _, err = f.s.runApacheCtl(context.Background(), "-V")
	assert.Equal(t, "/usr/sbin/apache2", untrustedPath(t, err))
	assert.NoFileExists(t, f.host("/marker"))

	require.NoError(t, os.Chmod(f.host("/usr/sbin/apache2"), 0o755))
	out, _, err := f.s.runApacheCtl(context.Background(), "-V")
	require.NoError(t, err)
	assert.Equal(t, "ok\n", string(out))

	require.NoError(t, os.Chmod(f.host(apache2ctlPath), 0o775))
	_, _, err = f.s.runApacheCtl(context.Background(), "-V")
	assert.Equal(t, apache2ctlPath, untrustedPath(t, err), "the control program itself")

	// httpd only: envvars and apache2 are not checked.
	require.NoError(t, os.Remove(f.host(apache2ctlPath)))
	require.NoError(t, os.Chmod(f.host("/etc/apache2/envvars"), 0o666))
	require.NoError(t, os.Chmod(f.host("/usr/sbin/apache2"), 0o777))
	f.script(httpdPath, "", 0o755)
	out, _, err = f.s.runApacheCtl(context.Background(), "-V")
	require.NoError(t, err)
	assert.Equal(t, "ok\n", string(out))
	require.NoError(t, os.Chmod(f.host(httpdPath), 0o757))
	_, _, err = f.s.runApacheCtl(context.Background(), "-V")
	assert.Equal(t, httpdPath, untrustedPath(t, err))
}

// C5: the runners productionSys wires go through the pre-check (the only production path of the
// security change): under a test root, a group-writable program is never run.
func TestProductionRunnersAreGuarded(t *testing.T) {
	needSh(t)
	for _, tc := range []struct {
		name, path string
		run        func(s *sys) ([]byte, []byte, error)
	}{
		{"nginx", nginxPath, func(s *sys) ([]byte, []byte, error) { return s.runNginx(context.Background(), "-t") }},
		{"apache2ctl", apache2ctlPath, func(s *sys) ([]byte, []byte, error) { return s.runApache(context.Background(), "-V") }},
		{"httpd", httpdPath, func(s *sys) ([]byte, []byte, error) { return s.runApache(context.Background(), "-V") }},
		{"haproxy", haproxyPath, func(s *sys) ([]byte, []byte, error) { return s.runHAProxy(context.Background(), "-v") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := programFixture(t)
			s := productionSys()
			s.root, s.rootUID, s.rootGID = f.root, f.s.rootUID, f.s.rootGID

			_, _, err := tc.run(s)
			assert.True(t, missingProgram(err), "not installed: %v", err)

			f.script(tc.path, "/marker", 0o755)
			out, _, err := tc.run(s)
			require.NoError(t, err)
			assert.Equal(t, "ok\n", string(out))
			require.FileExists(t, f.host("/marker"))
			require.NoError(t, os.Remove(f.host("/marker")))

			require.NoError(t, os.Chmod(f.host(tc.path), 0o775))
			_, _, err = tc.run(s)
			assert.Equal(t, tc.path, untrustedPath(t, err))
			assert.NoFileExists(t, f.host("/marker"), "the group-writable program never ran")
		})
	}
}

// The control-program choice is made under the root: apache2ctl when it exists, else httpd;
// apachectl (Rocky's refuses extra arguments) is never run.
func TestApacheCtlChoice(t *testing.T) {
	assert.Equal(t, []string{"/usr/sbin/apache2ctl", "/usr/sbin/httpd"}, apacheCtlPaths)
	assert.NotContains(t, apacheCtlPaths, "/usr/sbin/apachectl", "Rocky's apachectl refuses extra arguments")
	needSh(t)
	f := programFixture(t)
	named := func(guest string) {
		f.write(guest, "#!/bin/sh\necho "+filepath.Base(guest)+" \"$@\"\n", 0o755)
	}

	named("/usr/sbin/apachectl")
	_, _, err := f.s.runApacheCtl(context.Background(), "-V")
	assert.ErrorIs(t, err, fs.ErrNotExist, "neither present: apachectl is never used")
	assert.True(t, missingProgram(err))

	named(httpdPath)
	out, _, err := f.s.runApacheCtl(context.Background(), "-D", "DUMP_INCLUDES", "-t")
	require.NoError(t, err)
	assert.Equal(t, "httpd -D DUMP_INCLUDES -t\n", string(out))

	named(apache2ctlPath)
	out, _, err = f.s.runApacheCtl(context.Background(), "-V")
	require.NoError(t, err)
	assert.Equal(t, "apache2ctl -V\n", string(out), "apache2ctl when both exist")
}

// An lstat error other than "does not exist" is not "not installed": it is returned as is.
func TestApacheCtlLstatError(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/usr", 0o755)
	f.write("/usr/sbin", "a file, not a directory", 0o644)
	_, _, err := f.s.runApacheCtl(context.Background(), "-V")
	require.Error(t, err)
	assert.False(t, missingProgram(err), "%v", err)
	assert.NotErrorIs(t, err, errProgramUntrusted)
}
