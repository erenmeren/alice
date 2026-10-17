//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/apacheconf"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// apacheV is "apache2ctl -V" as Debian 12 prints it on stdout (trimmed).
const apacheV = `Server version: Apache/2.4.68 (Debian)
Server built:   2026-06-12T05:08:45
Server MPM:     event
Server compiled with....
 -D HTTPD_ROOT="/etc/apache2"
 -D SUEXEC_BIN="/usr/lib/apache2/suexec"
 -D SERVER_CONFIG_FILE="apache2.conf"
`

const (
	apacheConfPath = "/etc/apache2/apache2.conf"
	apacheSite     = "/etc/apache2/sites-enabled/alice.conf"
	apacheMainConf = `ServerRoot "/etc/apache2"
Listen 443
IncludeOptional sites-enabled/*.conf
`
	apacheSiteConf = `<VirtualHost *:443>
    ServerName www.example.test
    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/www.crt
    SSLCertificateKeyFile /etc/apache2/ssl/www.key
</VirtualHost>
<VirtualHost *:443>
    ServerName api.example.test
    ServerAlias alt.example.test
    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/api.crt
    SSLCertificateKeyFile /etc/apache2/ssl/api.key
</VirtualHost>
`
	apacheIncludes = "Included configuration files:\n  (*) /etc/apache2/apache2.conf\n    (3) /etc/apache2/sites-enabled/alice.conf\n"
	apacheModules  = "Loaded Modules:\n core_module (static)\n so_module (static)\n http_module (static)\n ssl_module (shared)\n"
	apacheRunCfg   = "ServerRoot: \"/etc/apache2\"\nMain DocumentRoot: \"/var/www/html\"\nDefine: DUMP_RUN_CFG\n"
	// apacheNotice is what apache2ctl prints on stderr on most hosts: never part of the answer.
	apacheNotice = "AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.17.0.2\n"
)

var (
	argsV        = "-V"
	argsIncludes = "-D DUMP_INCLUDES -t"
	argsModules  = "-D DUMP_MODULES -t"
	argsRunCfg   = "-D DUMP_RUN_CFG -t"
)

// apacheAnswer is what one run of the control program gives.
type apacheAnswer struct {
	out, errOut string
	err         error
}

// apacheWorld is a Debian server with Apache: the configuration files exist on disk and the
// control program answers from a table keyed by its arguments.
type apacheWorld struct {
	f        *fixture
	answers  map[string]apacheAnswer
	calls    []string
	www, api pki.Leaf
}

func newApacheWorld(t *testing.T) *apacheWorld {
	f := newFixture(t)
	for _, d := range []string{"/etc/apache2", "/etc/apache2/sites-enabled", "/etc/apache2/ssl"} {
		f.mkdir(d, 0o755)
	}
	ca := pki.NewCA("Helper Apache Test", pki.ECDSA256, testNow)
	w := &apacheWorld{f: f, www: ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow),
		api: ca.Issue(pki.Opts{CommonName: "api.example.test"}, testNow)}
	f.write(apacheConfPath, apacheMainConf, 0o644)
	f.write(apacheSite, apacheSiteConf, 0o644)
	f.write("/etc/apache2/ssl/www.crt", string(w.www.FullchainPEM), 0o644)
	f.write("/etc/apache2/ssl/www.key", string(w.www.KeyPEM), 0o600)
	f.write("/etc/apache2/ssl/api.crt", string(w.api.FullchainPEM), 0o644)
	f.write("/etc/apache2/ssl/api.key", string(w.api.KeyPEM), 0o600)
	w.answers = map[string]apacheAnswer{
		argsV:        {out: apacheV},
		argsIncludes: {out: apacheIncludes, errOut: apacheNotice},
		argsModules:  {out: apacheModules, errOut: apacheNotice},
		argsRunCfg:   {out: apacheRunCfg, errOut: apacheNotice},
	}
	f.s.runApache = func(_ context.Context, args ...string) ([]byte, []byte, error) {
		key := strings.Join(args, " ")
		w.calls = append(w.calls, key)
		a, ok := w.answers[key]
		if !ok {
			return nil, nil, errors.New("unexpected arguments")
		}
		return []byte(a.out), []byte(a.errOut), a.err
	}
	return w
}

func (w *apacheWorld) set(args string, a apacheAnswer) { w.answers[args] = a }

// includes makes DUMP_INCLUDES print the root and these lines (each "(<n>) <path>" at depth 1).
func (w *apacheWorld) includes(children ...string) {
	b := "Included configuration files:\n  (*) /etc/apache2/apache2.conf\n"
	for _, c := range children {
		b += "    " + c + "\n"
	}
	w.set(argsIncludes, apacheAnswer{out: b})
}

func (w *apacheWorld) dump(t *testing.T) (int, map[string]any) {
	t.Helper()
	w.calls = nil
	return w.f.run(helperproto.SubApacheDump)
}

func TestApacheDumpRunsTheFourCommandsInOrder(t *testing.T) {
	w := newApacheWorld(t)
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, []string{"-V", "-D DUMP_INCLUDES -t", "-D DUMP_MODULES -t", "-D DUMP_RUN_CFG -t"}, w.calls)
}

func TestApacheDumpListsTwoSites(t *testing.T) {
	w := newApacheWorld(t)
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, true, m["ok"])
	assert.Equal(t, "2.4.68", m["version"])
	assert.Equal(t, apacheConfPath, m["conf_path"])
	assert.Equal(t, true, m["config_valid"])
	assert.Equal(t, "", m["config_error"])
	assert.Equal(t, "", m["config_error_reason"])
	assert.Equal(t, "", m["config_error_file"])
	assert.Equal(t, []any{}, m["warnings"])
	assert.Equal(t, []any{}, m["writable"])

	servers := m["servers"].([]any)
	require.Len(t, servers, 2)
	www, api := servers[0].(map[string]any), servers[1].(map[string]any)
	assert.Equal(t, apacheSite, www["file"])
	assert.Equal(t, float64(1), www["line"])
	assert.Equal(t, []any{"www.example.test"}, www["names"])
	assert.Equal(t, []any{map[string]any{"addr": "", "port": float64(443), "default_server": true}}, www["listens"])
	assert.Equal(t, []any{map[string]any{"cert": "/etc/apache2/ssl/www.crt", "key": "/etc/apache2/ssl/www.key",
		"inherited": false, "unsupported": "", "raw": ""}}, www["pairs"])
	assert.Equal(t, false, www["stream"])
	assert.Equal(t, float64(7), api["line"])
	assert.Equal(t, []any{"api.example.test", "alt.example.test"}, api["names"])
	assert.Equal(t, []any{map[string]any{"addr": "", "port": float64(443), "default_server": false}}, api["listens"])

	files := m["files"].([]any)
	require.Len(t, files, 4)
	for i, want := range []struct {
		kind, path string
		leaf       pki.Leaf
	}{{"cert", "/etc/apache2/ssl/www.crt", w.www}, {"cert", "/etc/apache2/ssl/api.crt", w.api},
		{"key", "/etc/apache2/ssl/www.key", w.www}, {"key", "/etc/apache2/ssl/api.key", w.api}} {
		fi := files[i].(map[string]any)
		assert.Equal(t, want.kind, fi["kind"])
		assert.Equal(t, want.path, fi["path"])
		assert.Equal(t, want.path, fi["resolved"])
		assert.Equal(t, true, fi["exists"])
		assert.Equal(t, "", fi["problem"])
		if want.kind == "cert" {
			assert.Equal(t, "0644", fi["mode"])
			assert.Equal(t, string(want.leaf.FullchainPEM), fi["pem"])
			assert.Equal(t, hexOf(string(want.leaf.FullchainPEM)), fi["sha256"])
		} else {
			assert.Equal(t, "0600", fi["mode"])
			assert.Equal(t, float64(len(want.leaf.KeyPEM)), fi["size"])
			assert.Equal(t, "", fi["pem"], "a key file is never read")
			assert.Equal(t, "", fi["sha256"])
		}
	}
	out := w.f.out.String()
	assert.NotContains(t, out, privateKeyMarker)
	assert.NotContains(t, out, string(w.www.KeyPEM[30:70]))
	assert.NotContains(t, out, "AH00558", "stderr is never part of the answer")
	assert.Contains(t, w.f.loggedLines(), "apache-dump ")
}

// A file listed twice in the tree is read and parsed twice, as Apache does (Ruling 7).
func TestApacheDumpFileListedTwice(t *testing.T) {
	w := newApacheWorld(t)
	w.f.write(apacheConfPath, apacheMainConf+"IncludeOptional sites-enabled/*.conf\n", 0o644)
	w.includes("(3) "+apacheSite, "(4) "+apacheSite)
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, true, m["config_valid"], "%v", m)
	assert.Len(t, m["servers"].([]any), 4)
	assert.Len(t, m["files"].([]any), 4, "each distinct file is described once")
}

func TestApacheDumpNotInstalled(t *testing.T) {
	for name, a := range map[string]apacheAnswer{
		"no program":             {err: &fs.PathError{Op: "fork/exec", Path: apache2ctlPath, Err: fs.ErrNotExist}},
		"no Server version line": {out: " -D SERVER_CONFIG_FILE=\"apache2.conf\"\n"},
		"not Apache":             {out: "Server version: nginx/1.22.1\n"},
		"bad version":            {out: "Server version: Apache/2.4.68;rm (Debian)\n"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newApacheWorld(t)
			w.set(argsV, a)
			code, m := w.dump(t)
			assert.Equal(t, helperproto.ExitPrecondition, code)
			assert.Equal(t, false, m["ok"])
			assert.Equal(t, helperproto.CodeSoftwareNotFound, m["code"])
			assert.Equal(t, []string{"-V"}, w.calls)
		})
	}
	t.Run("removed between the runs", func(t *testing.T) {
		w := newApacheWorld(t)
		w.set(argsModules, apacheAnswer{err: &fs.PathError{Op: "fork/exec", Path: httpdPath, Err: fs.ErrNotExist}})
		code, m := w.dump(t)
		assert.Equal(t, helperproto.ExitPrecondition, code)
		assert.Equal(t, helperproto.CodeSoftwareNotFound, m["code"])
	})
}

func TestApacheDumpInvalidConfiguration(t *testing.T) {
	secret := "AH00526: Syntax error on line 3 of /etc/apache2/secret-site.conf: Invalid command 'hunter2'\n"
	check := func(t *testing.T, w *apacheWorld, calls int) {
		t.Helper()
		code, m := w.dump(t)
		require.Equal(t, 0, code, "%v", m)
		assert.Equal(t, true, m["ok"])
		assert.Equal(t, false, m["config_valid"])
		assert.Equal(t, helperproto.ConfigErrSyntax, m["config_error"])
		assert.Equal(t, "", m["config_error_reason"])
		assert.Equal(t, "", m["config_error_file"])
		assert.Equal(t, []any{}, m["servers"])
		assert.Equal(t, []any{}, m["files"])
		assert.Equal(t, []any{}, m["writable"])
		assert.Equal(t, "2.4.68", m["version"])
		assert.Len(t, w.calls, calls)
		for _, s := range []string{"AH00526", "secret-site", "hunter2"} {
			assert.NotContains(t, w.f.out.String(), s)
		}
	}
	t.Run("DUMP_INCLUDES fails", func(t *testing.T) {
		w := newApacheWorld(t)
		w.set(argsIncludes, apacheAnswer{out: "Included configuration files:\n", errOut: secret, err: errors.New("exit status 1")})
		check(t, w, 2)
	})
	t.Run("a later run fails: the configuration changed", func(t *testing.T) {
		w := newApacheWorld(t)
		w.set(argsRunCfg, apacheAnswer{errOut: secret, err: errors.New("exit status 1")})
		check(t, w, 4)
	})
	t.Run("modules run fails", func(t *testing.T) {
		w := newApacheWorld(t)
		w.set(argsModules, apacheAnswer{errOut: secret, err: errors.New("exit status 1")})
		check(t, w, 3)
	})
}

func TestApacheDumpKilledIsIOError(t *testing.T) {
	for _, args := range []string{argsV, argsIncludes, argsModules, argsRunCfg} {
		t.Run(args, func(t *testing.T) {
			w := newApacheWorld(t)
			w.set(args, apacheAnswer{err: fmt.Errorf("%w: %w", errProgramKilled, context.DeadlineExceeded)})
			code, m := w.dump(t)
			assert.Equal(t, helperproto.ExitFailed, code)
			assert.Equal(t, helperproto.CodeIOError, m["code"])
		})
	}
	t.Run("-V exits non-zero", func(t *testing.T) {
		w := newApacheWorld(t)
		w.set(argsV, apacheAnswer{out: apacheV, err: errors.New("exit status 1")})
		code, m := w.dump(t)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
	})
}

// refusal runs a dump and returns its class, reason and file; the answer is empty, never partial.
func (w *apacheWorld) refusal(t *testing.T) (class, reason, file string) {
	t.Helper()
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	require.Equal(t, false, m["config_valid"], "%v", m)
	assert.Equal(t, []any{}, m["servers"])
	assert.Equal(t, []any{}, m["files"])
	assert.Equal(t, []any{}, m["writable"])
	assert.Equal(t, []any{}, m["warnings"])
	return m["config_error"].(string), m["config_error_reason"].(string), m["config_error_file"].(string)
}

func TestApacheDumpUntrustedFiles(t *testing.T) {
	const (
		untrustedC   = helperproto.ConfigErrUntrusted
		unsupportedC = helperproto.ConfigErrUnsupported
	)
	for name, tc := range map[string]struct {
		setup               func(w *apacheWorld)
		class, reason, file string
	}{
		"tree root is not the -V configuration file": {func(w *apacheWorld) {
			w.f.write("/etc/apache2/other.conf", apacheMainConf, 0o644)
			w.set(argsIncludes, apacheAnswer{out: "Included configuration files:\n  (*) /etc/apache2/other.conf\n    (3) " + apacheSite + "\n"})
		}, untrustedC, helperproto.ConfigReasonWrongFirstFile, "/etc/apache2/other.conf"},
		"-V names no valid configuration file": {func(w *apacheWorld) {
			w.set(argsV, apacheAnswer{out: "Server version: Apache/2.4.68 (Debian)\n -D SERVER_CONFIG_FILE=\"a b.conf\"\n"})
		}, unsupportedC, helperproto.ConfigReasonNoConfPath, ""},
		"file in a group-writable directory": {func(w *apacheWorld) {
			require.NoError(t, os.Chmod(w.f.host("/etc/apache2/sites-enabled"), 0o775))
		}, untrustedC, helperproto.ConfigReasonNotRootControlled, apacheSite},
		"file missing": {func(w *apacheWorld) {
			require.NoError(t, os.Remove(w.f.host(apacheSite)))
		}, untrustedC, helperproto.ConfigReasonMissing, apacheSite},
		"not a regular file": {func(w *apacheWorld) {
			require.NoError(t, os.Remove(w.f.host(apacheSite)))
			w.f.mkdir(apacheSite, 0o755)
		}, untrustedC, helperproto.ConfigReasonNotRegular, apacheSite},
		"tree name with a space": {func(w *apacheWorld) {
			w.includes("(3) /etc/apache2/sites-enabled/my site.conf")
		}, unsupportedC, helperproto.ConfigReasonNameNotAllowed, ""},
		"include mismatch": {func(w *apacheWorld) {
			w.includes("(2) " + apacheSite)
		}, untrustedC, helperproto.ConfigReasonChanged, ""},
		"tool output in an unexpected format": {func(w *apacheWorld) {
			w.set(argsModules, apacheAnswer{out: "Loaded Modules:\nAH00558: forged\n"})
		}, untrustedC, helperproto.ConfigReasonUnexpectedText, ""},
		"DUMP_INCLUDES larger than the cap": {func(w *apacheWorld) {
			w.set(argsIncludes, apacheAnswer{err: errTooLarge})
		}, unsupportedC, helperproto.ConfigReasonTooLarge, ""},
		"files over the read budget": {func(w *apacheWorld) {
			apacheReadBudget = len(apacheMainConf) + len(apacheSiteConf) - 1
		}, unsupportedC, helperproto.ConfigReasonTooLarge, ""},
		"a line over the parser's limit": {func(w *apacheWorld) {
			w.f.write(apacheSite, "# "+strings.Repeat("a", apacheconf.MaxLine)+"\n"+apacheSiteConf, 0o644)
		}, unsupportedC, helperproto.ConfigReasonTooLarge, ""},
		"sections nested too deep": {func(w *apacheWorld) {
			w.f.write(apacheSite, strings.Repeat("<Directory />\n", apacheconf.MaxDepth+1)+strings.Repeat("</Directory>\n", apacheconf.MaxDepth+1), 0o644)
		}, unsupportedC, helperproto.ConfigReasonTooComplex, ""},
		"too many modules": {func(w *apacheWorld) {
			w.set(argsModules, apacheAnswer{out: "Loaded Modules:\n" + strings.Repeat(" x_module (shared)\n", apacheconf.MaxModules+1)})
		}, unsupportedC, helperproto.ConfigReasonTooComplex, ""},
		"NUL byte": {func(w *apacheWorld) {
			w.f.write(apacheSite, "\x00"+apacheSiteConf, 0o644)
		}, unsupportedC, helperproto.ConfigReasonNULByte, ""},
	} {
		t.Run(name, func(t *testing.T) {
			old := apacheReadBudget
			defer func() { apacheReadBudget = old }()
			w := newApacheWorld(t)
			tc.setup(w)
			class, reason, file := w.refusal(t)
			assert.Equal(t, tc.class, class)
			assert.Equal(t, tc.reason, reason)
			assert.Equal(t, tc.file, file)
		})
	}
}

// After a file a user can write, every later failure reads "changed" naming that file: the
// user's Include must not tell whether a root-only path exists.
func TestApacheDumpFailureAfterAWritableFileNamesIt(t *testing.T) {
	w := newApacheWorld(t)
	w.f.write(apacheConfPath, apacheMainConf+"IncludeOptional /root/*.conf\n", 0o666)
	w.includes("(3) "+apacheSite, "(4) /root/secret.conf")
	class, reason, file := w.refusal(t)
	assert.Equal(t, helperproto.ConfigErrUntrusted, class)
	assert.Equal(t, helperproto.ConfigReasonChanged, reason)
	assert.Equal(t, apacheConfPath, file)
	assert.NotContains(t, w.f.out.String(), "secret")

	t.Run("a parse failure after a writable file", func(t *testing.T) {
		w := newApacheWorld(t)
		require.NoError(t, os.Chmod(w.f.host(apacheConfPath), 0o666))
		w.f.write(apacheSite, "<VirtualHost *:443>\n", 0o644) // unbalanced: ErrSyntax
		class, reason, file := w.refusal(t)
		assert.Equal(t, helperproto.ConfigErrUntrusted, class)
		assert.Equal(t, helperproto.ConfigReasonChanged, reason)
		assert.Equal(t, apacheConfPath, file)
	})
}

func TestApacheDumpWritableConfigMarksEveryPair(t *testing.T) {
	w := newApacheWorld(t)
	require.NoError(t, os.Chmod(w.f.host(apacheSite), 0o666))
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, true, m["config_valid"])
	assert.Equal(t, []any{apacheSite}, m["writable"])
	assert.Equal(t, []any{helperproto.WarnConfigFileWritable}, m["warnings"])
	servers := m["servers"].([]any)
	require.Len(t, servers, 2)
	for _, sv := range servers {
		for _, p := range sv.(map[string]any)["pairs"].([]any) {
			assert.Equal(t, apacheconf.ReasonConfigFileWritable, p.(map[string]any)["unsupported"])
		}
	}
	assert.Equal(t, []any{}, m["files"], "no pair is supported, so no file is described")
}

func TestApacheDumpRefusesArguments(t *testing.T) {
	w := newApacheWorld(t)
	code, m := w.f.run(helperproto.SubApacheDump, "x")
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeUsage, m["code"])
	assert.Empty(t, w.calls)
}

func TestApacheDumpNeedsRoot(t *testing.T) {
	w := newApacheWorld(t)
	w.f.s.euid = func() int { return 1000 }
	code, m := w.f.run(helperproto.SubApacheDump)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeNotRoot, m["code"])
	assert.Empty(t, w.calls)
}

func TestApacheDumpOutputBudget(t *testing.T) {
	old := dumpBudget
	defer func() { dumpBudget = old }()
	w := newApacheWorld(t)
	dumpBudget = len(w.www.FullchainPEM) + 10
	code, m := w.dump(t)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeOutputTooLarge, m["code"])
}

type fileState struct {
	size  int64
	mtime int64
	mode  fs.FileMode
}

// snapshot is (path, size, mtime, mode) of everything under the fixture root.
func snapshot(t *testing.T, root string) map[string]fileState {
	t.Helper()
	out := map[string]fileState{}
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = fileState{size: fi.Size(), mtime: fi.ModTime().UnixNano(), mode: fi.Mode()}
		return nil
	}))
	return out
}

func TestApacheDumpWritesNothing(t *testing.T) {
	w := newApacheWorld(t)
	require.NoError(t, os.Chmod(w.f.host("/etc/apache2/ssl/api.key"), 0o644)) // a key group/others can read
	before := snapshot(t, w.f.root)
	outcomes := []func(){
		func() {},
		func() { require.NoError(t, os.Chmod(w.f.host(apacheSite), 0o666)) },
		func() { require.NoError(t, os.Chmod(w.f.host(apacheSite), 0o644)) },
		func() { w.set(argsIncludes, apacheAnswer{err: errors.New("exit status 1")}) },
		func() { w.set(argsIncludes, apacheAnswer{out: apacheIncludes}) },
		func() { w.includes("(2) " + apacheSite) },
		func() { w.includes("(3) /etc/apache2/sites-enabled/gone.conf") },
		func() { w.includes("(3) " + apacheSite) },
		func() { w.set(argsRunCfg, apacheAnswer{err: fmt.Errorf("%w", errProgramKilled)}) },
		func() { w.set(argsV, apacheAnswer{err: fs.ErrNotExist}) },
	}
	for i, change := range outcomes {
		change()
		code, m := w.dump(t)
		assert.NotEqual(t, helperproto.ExitRefused, code, "outcome %d: %v", i, m)
	}
	after := snapshot(t, w.f.root)
	// The chmod round trip of outcome 1/2 restored the mode; the ctime is not compared.
	assert.Equal(t, before, after)
}

func TestApacheCtlChoice(t *testing.T) {
	assert.Equal(t, []string{"/usr/sbin/apache2ctl", "/usr/sbin/httpd"}, apacheCtlPaths)
	assert.NotContains(t, apacheCtlPaths, "/usr/sbin/apachectl", "Rocky's apachectl refuses extra arguments")
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	old := apacheCtlPaths
	defer func() { apacheCtlPaths = old }()
	dir := t.TempDir()
	script := func(name string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\necho "+name+" \"$@\"\n"), 0o700)) //nolint:gosec // G306: a test program that must run
		return p
	}
	ctl, httpd := filepath.Join(dir, "apache2ctl"), filepath.Join(dir, "httpd")
	apacheCtlPaths = []string{ctl, httpd}

	script("apachectl")
	_, _, err := runApacheCtl(context.Background(), "-V")
	assert.ErrorIs(t, err, fs.ErrNotExist, "neither present: apachectl is never used")
	assert.True(t, missingProgram(err))

	script("httpd")
	out, _, err := runApacheCtl(context.Background(), "-D", "DUMP_INCLUDES", "-t")
	require.NoError(t, err)
	assert.Equal(t, "httpd -D DUMP_INCLUDES -t\n", string(out))

	script("apache2ctl")
	out, _, err = runApacheCtl(context.Background(), "-V")
	require.NoError(t, err)
	assert.Equal(t, "apache2ctl -V\n", string(out), "apache2ctl when both exist")
}

func TestApacheParseError(t *testing.T) {
	for _, tc := range []struct {
		err                 error
		class, reason, file string
	}{
		{apacheconf.ErrTooLarge, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooLarge, ""},
		{apacheconf.ErrLineTooLong, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooLarge, ""},
		{apacheconf.ErrTooComplex, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooComplex, ""},
		{apacheconf.ErrTooDeep, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooComplex, ""},
		{apacheconf.ErrNUL, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonNULByte, ""},
		{apacheconf.ErrName, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonNameNotAllowed, ""},
		{apacheconf.ErrIncludeMismatch, helperproto.ConfigErrUntrusted, helperproto.ConfigReasonChanged, ""},
		{apacheconf.ErrOutput, helperproto.ConfigErrUntrusted, helperproto.ConfigReasonUnexpectedText, ""},
		{apacheconf.ErrSyntax, helperproto.ConfigErrSyntax, "", ""},
		{fmt.Errorf("%w (line 3)", apacheconf.ErrOutput), helperproto.ConfigErrUntrusted, helperproto.ConfigReasonUnexpectedText, ""},
	} {
		e := apacheParseError(tc.err)
		assert.Equal(t, []string{tc.class, tc.reason, tc.file}, []string{e.class, e.reason, e.file}, "%v", tc.err)
	}
}

// An lstat error other than "does not exist" is not "not installed": it is returned as is.
func TestApacheCtlLstatError(t *testing.T) {
	old := apacheCtlPaths
	defer func() { apacheCtlPaths = old }()
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	apacheCtlPaths = []string{filepath.Join(file, "apache2ctl")}
	_, _, err := runApacheCtl(context.Background(), "-V")
	require.Error(t, err)
	assert.False(t, missingProgram(err), "%v", err)
}
