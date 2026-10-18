//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/haproxyconf"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// haproxyV is "haproxy -v" as Debian 12 prints it.
const haproxyV = `HAProxy version 2.6.12-1+deb12u3 2025/10/03 - https://haproxy.org/
Status: long-term supported branch - will stop receiving fixes around Q2 2027.
Known bugs: http://www.haproxy.org/bugs/bugs-2.6.12.html
Running on: Linux 6.1.0 x86_64
`

const (
	haproxyArgsV = "-v"
	haproxyArgsC = "-c -f /etc/haproxy/haproxy.cfg"
	haproxyList  = "/etc/haproxy/lists/sni.lst"
	// haproxyCfg: a frontend with a combined PEM and a PEM with its key beside it, and a listen
	// whose crt-list gives SNI names.
	haproxyCfg = `global
    log /dev/log local0
defaults
    mode http
frontend fe_https
    bind :9443 ssl crt /etc/haproxy/certs/a.pem crt /etc/haproxy/certs/b.pem
    default_backend be
listen li_sni
    bind :9444 ssl crt-list /etc/haproxy/lists/sni.lst
    server s1 127.0.0.1:8080
backend be
    server s1 127.0.0.1:8080
`
	haproxyListText = "/etc/haproxy/certs/c.pem [alpn h2] www.example.test api.example.test !*.internal.test\n"
	// haproxyNotice is what "haproxy -c" prints on stderr: never part of the answer.
	haproxyNotice = "[ALERT] parsing [/etc/haproxy/secret.cfg:3]: unknown keyword 'hunter2'\n"
)

// exitStatus is a program's non-zero exit as runProgram returns it (*exec.ExitError has ExitCode).
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitStatus) ExitCode() int { return int(e) }

// haproxyWorld is a Debian server with HAProxy: haproxy.cfg, a crt-list and three certificates
// exist on disk and the program answers from a table keyed by its arguments.
type haproxyWorld struct {
	f       *fixture
	answers map[string]apacheAnswer
	calls   []string
	a, b, c pki.Leaf
	walked  map[string]int // directories the walks opened, by name
}

func newHAProxyWorld(t *testing.T) *haproxyWorld {
	f := newFixture(t)
	for _, d := range []string{"/etc/haproxy", "/etc/haproxy/certs", "/etc/haproxy/lists"} {
		f.mkdir(d, 0o755)
	}
	ca := pki.NewCA("Helper HAProxy Test", pki.ECDSA256, testNow)
	w := &haproxyWorld{f: f, walked: map[string]int{},
		a: ca.Issue(pki.Opts{CommonName: "a.example.test"}, testNow),
		b: ca.Issue(pki.Opts{CommonName: "b.example.test"}, testNow),
		c: ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)}
	f.write(haproxyConfPath, haproxyCfg, 0o644)
	f.write(haproxyList, haproxyListText, 0o644)
	f.write("/etc/haproxy/certs/a.pem", string(w.a.FullchainPEM)+string(w.a.KeyPEM), 0o600)
	f.write("/etc/haproxy/certs/b.pem", string(w.b.FullchainPEM), 0o644)
	f.write("/etc/haproxy/certs/b.pem.key", string(w.b.KeyPEM), 0o600)
	f.write("/etc/haproxy/certs/c.pem", string(w.c.FullchainPEM)+string(w.c.KeyPEM), 0o600)
	w.answers = map[string]apacheAnswer{
		haproxyArgsV: {out: haproxyV},
		haproxyArgsC: {errOut: haproxyNotice},
	}
	f.s.runHAProxy = func(_ context.Context, args ...string) ([]byte, []byte, error) {
		key := strings.Join(args, " ")
		w.calls = append(w.calls, key)
		a, ok := w.answers[key]
		if !ok {
			return nil, nil, errors.New("unexpected arguments")
		}
		return []byte(a.out), []byte(a.errOut), a.err
	}
	f.s.walkHook = func(name string) { w.walked[name]++ }
	return w
}

func (w *haproxyWorld) set(args string, a apacheAnswer) { w.answers[args] = a }

func (w *haproxyWorld) dump(t *testing.T) (int, map[string]any) {
	t.Helper()
	w.calls = nil
	clear(w.walked)
	return w.f.run(helperproto.SubHAProxyDump)
}

// refusal runs a dump and returns its class, reason and file; the answer is empty, never partial.
func (w *haproxyWorld) refusal(t *testing.T) (class, reason, file string) {
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

func serverPairs(sv map[string]any) []map[string]any { return asList(sv["pairs"]) }

func TestHAProxyDumpRunsTwoCommandsInOrder(t *testing.T) {
	w := newHAProxyWorld(t)
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, []string{"-v", "-c -f /etc/haproxy/haproxy.cfg"}, w.calls)
}

func TestHAProxyDumpListsTwoFrontends(t *testing.T) {
	w := newHAProxyWorld(t)
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, true, m["ok"])
	assert.Equal(t, "2.6.12-1+deb12u3", m["version"])
	assert.Equal(t, haproxyConfPath, m["conf_path"])
	assert.Equal(t, true, m["config_valid"])
	assert.Equal(t, "", m["config_error"])
	assert.Equal(t, "", m["config_error_reason"])
	assert.Equal(t, "", m["config_error_file"])
	assert.Equal(t, []any{}, m["warnings"])
	assert.Equal(t, []any{}, m["writable"])

	servers := asList(m["servers"])
	require.Len(t, servers, 2)
	fe, li := servers[0], servers[1]
	assert.Equal(t, "fe_https", fe["section"])
	assert.Equal(t, haproxyConfPath, fe["file"])
	assert.Equal(t, float64(6), fe["line"])
	assert.Equal(t, []any{}, fe["names"])
	assert.Equal(t, []any{map[string]any{"addr": "", "port": float64(9443), "default_server": false}}, fe["listens"])
	assert.Equal(t, []map[string]any{
		{"cert": "/etc/haproxy/certs/a.pem", "key": "/etc/haproxy/certs/a.pem", "inherited": false, "unsupported": "", "raw": ""},
		{"cert": "/etc/haproxy/certs/b.pem", "key": "/etc/haproxy/certs/b.pem.key", "inherited": false, "unsupported": "", "raw": ""},
	}, serverPairs(fe))
	assert.Equal(t, false, fe["stream"])
	assert.Equal(t, "li_sni", li["section"])
	assert.Equal(t, float64(9), li["line"])
	assert.Equal(t, []any{"www.example.test", "api.example.test"}, li["names"])
	assert.Equal(t, []any{map[string]any{"addr": "", "port": float64(9444), "default_server": false}}, li["listens"])
	assert.Equal(t, []map[string]any{
		{"cert": "/etc/haproxy/certs/c.pem", "key": "/etc/haproxy/certs/c.pem", "inherited": false, "unsupported": "", "raw": ""},
	}, serverPairs(li))

	files := asList(m["files"])
	require.Len(t, files, 6)
	for i, want := range []struct {
		kind, path, mode string
		pem              []byte
		size             int
	}{
		{"cert", "/etc/haproxy/certs/a.pem", "0600", w.a.FullchainPEM, 0},
		{"cert", "/etc/haproxy/certs/b.pem", "0644", w.b.FullchainPEM, 0},
		{"cert", "/etc/haproxy/certs/c.pem", "0600", w.c.FullchainPEM, 0},
		{"key", "/etc/haproxy/certs/a.pem", "0600", nil, len(w.a.FullchainPEM) + len(w.a.KeyPEM)},
		{"key", "/etc/haproxy/certs/b.pem.key", "0600", nil, len(w.b.KeyPEM)},
		{"key", "/etc/haproxy/certs/c.pem", "0600", nil, len(w.c.FullchainPEM) + len(w.c.KeyPEM)},
	} {
		fi := files[i]
		assert.Equal(t, want.kind, fi["kind"], want.path)
		assert.Equal(t, want.path, fi["path"])
		assert.Equal(t, want.path, fi["resolved"])
		assert.Equal(t, true, fi["exists"])
		assert.Equal(t, "", fi["problem"], want.path)
		assert.Equal(t, want.mode, fi["mode"], want.path)
		if want.kind == "cert" {
			assert.Equal(t, string(want.pem), fi["pem"], "certificate blocks only")
			assert.NotEmpty(t, fi["sha256"])
		} else {
			assert.Equal(t, float64(want.size), fi["size"])
			assert.Equal(t, "", fi["pem"], "a key file is never read")
			assert.Equal(t, "", fi["sha256"])
		}
	}
	assert.Equal(t, hexOf(string(w.b.FullchainPEM)), files[1]["sha256"])
	out := w.f.out.String()
	assert.NotContains(t, out, privateKeyMarker)
	assert.NotContains(t, out, string(w.a.KeyPEM[30:70]))
	assert.NotContains(t, out, "hunter2", "stderr is never part of the answer")
	assert.NotContains(t, out, "internal.test", "a negative filter is not a name")
	assert.Contains(t, w.f.loggedLines(), "haproxy-dump ")
}

// D3: exit 2 ("no listener") is valid; any other non-zero exit is an invalid configuration of
// class syntax, and then nothing is read.
func TestHAProxyDumpValidity(t *testing.T) {
	t.Run("exit 2 is valid", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.set(haproxyArgsC, apacheAnswer{errOut: "[WARNING] no listener\n", err: exitStatus(2)})
		code, m := w.dump(t)
		require.Equal(t, 0, code, "%v", m)
		assert.Equal(t, true, m["config_valid"])
		assert.Len(t, m["servers"], 2)
	})
	for _, exit := range []int{1, 3, 255} {
		t.Run(fmt.Sprintf("exit %d", exit), func(t *testing.T) {
			w := newHAProxyWorld(t)
			w.set(haproxyArgsC, apacheAnswer{errOut: haproxyNotice, err: exitStatus(exit)})
			class, reason, file := w.refusal(t)
			assert.Equal(t, []string{helperproto.ConfigErrSyntax, "", ""}, []string{class, reason, file})
			_, m := w.f.run(helperproto.SubHAProxyDump)
			assert.Equal(t, "2.6.12-1+deb12u3", m["version"])
			assert.Equal(t, haproxyConfPath, m["conf_path"])
			for _, s := range []string{"hunter2", "secret.cfg", "ALERT"} {
				assert.NotContains(t, w.f.out.String(), s)
			}
			assert.Zero(t, w.walked["haproxy"], "neither haproxy.cfg nor a crt-list is opened: %v", w.walked)
			assert.Zero(t, w.walked["etc"], "nothing is walked at all: %v", w.walked)
		})
	}
}

// haproxyValid on what runProgram really returns.
func TestHAProxyValidExitCodes(t *testing.T) {
	needSh(t)
	for code, valid := range map[int]bool{0: true, 1: false, 2: true, 3: false} {
		_, _, err := runProgram(context.Background(), "/bin/sh", 1<<10, "-c", fmt.Sprintf("exit %d", code))
		assert.Equal(t, valid, haproxyValid(err), "exit %d", code)
	}
	assert.False(t, haproxyValid(errors.New("exit status 2")), "only an exit code counts")
}

func TestHAProxyDumpNotInstalled(t *testing.T) {
	for name, a := range map[string]apacheAnswer{
		"no program":         {err: &fs.PathError{Op: "fork/exec", Path: haproxyPath, Err: fs.ErrNotExist}},
		"no version line":    {out: "Usage : haproxy [-f <cfgfile|cfgdir>]*\n"},
		"not HAProxy":        {out: "nginx version: nginx/1.22.1\n"},
		"bad version":        {out: "HAProxy version 2.6;rm 2025/10/03\n"},
		"version not first":  {out: "x\nHAProxy version 2.6.12 2025/10/03\n"},
		"old spelling, fine": {out: "HA-Proxy version 1.8.30 2021/04/12\n"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newHAProxyWorld(t)
			w.set(haproxyArgsV, a)
			code, m := w.dump(t)
			if name == "old spelling, fine" {
				require.Equal(t, 0, code, "%v", m)
				assert.Equal(t, "1.8.30", m["version"])
				return
			}
			assert.Equal(t, helperproto.ExitPrecondition, code)
			assert.Equal(t, false, m["ok"])
			assert.Equal(t, helperproto.CodeSoftwareNotFound, m["code"])
			assert.Equal(t, []string{"-v"}, w.calls)
		})
	}
	t.Run("removed between the runs", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.set(haproxyArgsC, apacheAnswer{err: &fs.PathError{Op: "fork/exec", Path: haproxyPath, Err: fs.ErrNotExist}})
		code, m := w.dump(t)
		assert.Equal(t, helperproto.ExitPrecondition, code)
		assert.Equal(t, helperproto.CodeSoftwareNotFound, m["code"])
	})
}

func TestHAProxyDumpKilledIsIOError(t *testing.T) {
	for _, args := range []string{haproxyArgsV, haproxyArgsC} {
		t.Run(args, func(t *testing.T) {
			w := newHAProxyWorld(t)
			w.set(args, apacheAnswer{err: fmt.Errorf("%w: %w", errProgramKilled, context.DeadlineExceeded)})
			code, m := w.dump(t)
			assert.Equal(t, helperproto.ExitFailed, code)
			assert.Equal(t, helperproto.CodeIOError, m["code"])
			assert.Zero(t, w.walked["haproxy"])
		})
	}
	t.Run("-v exits non-zero", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.set(haproxyArgsV, apacheAnswer{out: haproxyV, err: exitStatus(1)})
		code, m := w.dump(t)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
	})
}

func TestHAProxyDumpUntrusted(t *testing.T) {
	const (
		untrustedC   = helperproto.ConfigErrUntrusted
		unsupportedC = helperproto.ConfigErrUnsupported
	)
	manyLists := func(w *haproxyWorld) {
		var b strings.Builder
		b.WriteString("frontend f\n    bind :9443 ssl")
		for i := range haproxyconf.MaxCrtLists + 1 {
			p := fmt.Sprintf("/etc/haproxy/lists/l%d.lst", i)
			w.f.write(p, "/etc/haproxy/certs/a.pem\n", 0o644)
			b.WriteString(" crt-list " + p)
		}
		w.f.write(haproxyConfPath, b.String()+"\n", 0o644)
	}
	for name, tc := range map[string]struct {
		setup               func(w *haproxyWorld)
		class, reason, file string
	}{
		"haproxy.cfg in a group-writable directory": {func(w *haproxyWorld) {
			require.NoError(t, os.Chmod(w.f.host("/etc/haproxy"), 0o775))
		}, untrustedC, helperproto.ConfigReasonNotRootControlled, haproxyConfPath},
		"haproxy.cfg missing after a valid -c": {func(w *haproxyWorld) {
			require.NoError(t, os.Remove(w.f.host(haproxyConfPath)))
		}, untrustedC, helperproto.ConfigReasonMissing, haproxyConfPath},
		"haproxy.cfg not a regular file": {func(w *haproxyWorld) {
			require.NoError(t, os.Remove(w.f.host(haproxyConfPath)))
			w.f.mkdir(haproxyConfPath, 0o755)
		}, untrustedC, helperproto.ConfigReasonNotRegular, haproxyConfPath},
		"a crt-list missing": {func(w *haproxyWorld) {
			require.NoError(t, os.Remove(w.f.host(haproxyList)))
		}, untrustedC, helperproto.ConfigReasonMissing, haproxyList},
		"a crt-list in a group-writable directory": {func(w *haproxyWorld) {
			require.NoError(t, os.Chmod(w.f.host("/etc/haproxy/lists"), 0o775))
		}, untrustedC, helperproto.ConfigReasonNotRootControlled, haproxyList},
		"program error at -v": {func(w *haproxyWorld) {
			w.set(haproxyArgsV, apacheAnswer{err: &programError{path: haproxyPath}})
		}, untrustedC, helperproto.ConfigReasonNotRootControlled, haproxyPath},
		"program error at -c": {func(w *haproxyWorld) {
			w.set(haproxyArgsC, apacheAnswer{err: &programError{path: haproxyPath}})
		}, untrustedC, helperproto.ConfigReasonNotRootControlled, haproxyPath},
		"-c output over the cap": {func(w *haproxyWorld) {
			w.set(haproxyArgsC, apacheAnswer{err: errTooLarge})
		}, unsupportedC, helperproto.ConfigReasonTooLarge, ""},
		"parser ErrTooComplex": {manyLists, unsupportedC, helperproto.ConfigReasonTooComplex, ""},
		"parser ErrTooDeep": {func(w *haproxyWorld) {
			w.f.write(haproxyConfPath, strings.Repeat(".if 1\n", haproxyconf.MaxDepth+1)+strings.Repeat(".endif\n", haproxyconf.MaxDepth+1), 0o644)
		}, unsupportedC, helperproto.ConfigReasonTooComplex, ""},
		"parser ErrSyntax": {func(w *haproxyWorld) {
			w.f.write(haproxyConfPath, "frontend f\n    bind :9443 ssl crt \"/etc/haproxy/certs/a.pem\n", 0o644)
		}, helperproto.ConfigErrSyntax, "", ""},
		"parser ErrNUL": {func(w *haproxyWorld) {
			w.f.write(haproxyConfPath, "\x00"+haproxyCfg, 0o644)
		}, unsupportedC, helperproto.ConfigReasonNULByte, ""},
		"a line over the parser's limit": {func(w *haproxyWorld) {
			w.f.write(haproxyConfPath, "# "+strings.Repeat("a", haproxyconf.MaxLine)+"\n"+haproxyCfg, 0o644)
		}, unsupportedC, helperproto.ConfigReasonTooLarge, ""},
		"files over the read budget": {func(w *haproxyWorld) {
			haproxyReadBudget = len(haproxyCfg) + len(haproxyListText) - 1
		}, unsupportedC, helperproto.ConfigReasonTooLarge, ""},
	} {
		t.Run(name, func(t *testing.T) {
			old := haproxyReadBudget
			defer func() { haproxyReadBudget = old }()
			w := newHAProxyWorld(t)
			tc.setup(w)
			class, reason, file := w.refusal(t)
			assert.Equal(t, []string{tc.class, tc.reason, tc.file}, []string{class, reason, file})
		})
	}
}

func TestHAProxyDumpWritableConfigMarksEveryPair(t *testing.T) {
	w := newHAProxyWorld(t)
	require.NoError(t, os.Chmod(w.f.host(haproxyList), 0o666))
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, true, m["config_valid"])
	assert.Equal(t, []any{haproxyList}, m["writable"])
	assert.Equal(t, []any{helperproto.WarnConfigFileWritable}, m["warnings"])
	servers := asList(m["servers"])
	require.Len(t, servers, 2)
	for _, sv := range servers {
		for _, p := range serverPairs(sv) {
			assert.Equal(t, haproxyconf.ReasonConfigFileWritable, p["unsupported"])
		}
	}
	assert.Equal(t, []any{}, m["files"], "no pair is supported, so no file is described")

	t.Run("a writable crt-list, then a missing crt-list", func(t *testing.T) {
		w := newHAProxyWorld(t)
		require.NoError(t, os.Chmod(w.f.host(haproxyList), 0o666))
		w.f.write(haproxyConfPath, haproxyCfg+"frontend fe_two\n    bind :9445 ssl crt-list /etc/haproxy/lists/gone.lst\n", 0o644)
		class, reason, file := w.refusal(t)
		assert.Equal(t, []string{helperproto.ConfigErrUntrusted, helperproto.ConfigReasonChanged, haproxyList}, []string{class, reason, file})
	})
	t.Run("a writable haproxy.cfg, then a parse failure", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.f.write(haproxyConfPath, haproxyCfg+".if 1\n", 0o666) // unbalanced: ErrSyntax
		class, reason, file := w.refusal(t)
		assert.Equal(t, []string{helperproto.ConfigErrUntrusted, helperproto.ConfigReasonChanged, haproxyConfPath}, []string{class, reason, file})
	})
	// Review I1: nothing a writable haproxy.cfg names is read, so a missing crt-list or a huge
	// directory changes nothing: each naming is one config_file_writable pair of its text.
	t.Run("a writable haproxy.cfg naming a missing crt-list and a huge directory", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.f.mkdir("/etc/haproxy/big", 0o755)
		for i := range haproxyconf.MaxDirEntries + 1 {
			w.f.write(fmt.Sprintf("/etc/haproxy/big/%04d.pem", i), "", 0o644)
		}
		require.NoError(t, os.Remove(w.f.host(haproxyList)))
		w.f.write(haproxyConfPath, "frontend f\n    bind :9443 ssl crt /etc/haproxy/big crt-list "+haproxyList+"\n", 0o666)
		code, m := w.dump(t)
		require.Equal(t, 0, code, "%v", m)
		assert.Equal(t, true, m["config_valid"], "%v", m)
		assert.Equal(t, []any{haproxyConfPath}, m["writable"])
		assert.Equal(t, []map[string]any{
			{"cert": "", "key": "", "inherited": false, "unsupported": haproxyconf.ReasonConfigFileWritable, "raw": "/etc/haproxy/big"},
			{"cert": "", "key": "", "inherited": false, "unsupported": haproxyconf.ReasonConfigFileWritable, "raw": haproxyList},
		}, serverPairs(asList(m["servers"])[0]))
		assert.NotContains(t, w.f.out.String(), "0000.pem")
	})
}

// Review I1 (the reviewer's cases): a haproxy.cfg a user other than root can change names
// root-only files and directories, actively or in a region "-c" skips. The helper walks, lists
// and opens none of them, and no line or entry name of theirs reaches the answer; only the text
// the user wrote in haproxy.cfg does.
func TestHAProxyDumpWritableConfigReadsNothingItNames(t *testing.T) {
	for name, cfg := range map[string]string{
		"in .if defined(X)": ".if defined(NEVER_SET)\nfrontend z\n    bind :9445 ssl crt-list /root/notes crt /root/keys\n.endif\n",
		"active":            "frontend z\n    bind :9445 ssl crt-list /root/notes crt /root/keys\n",
	} {
		t.Run(name, func(t *testing.T) {
			w := newHAProxyWorld(t)
			w.f.mkdir("/root/keys", 0o700)
			w.f.write("/root/notes", "/s3cr3t-line-one\nTOPSECRET_two\n", 0o600)
			w.f.write("/root/keys/db-password.txt", "hunter2", 0o600)
			w.f.write("/root/keys/id_ed25519", "k", 0o600)
			w.f.write(haproxyConfPath, haproxyCfg+cfg, 0o666)
			seen := w.recordOpens()
			code, m := w.dump(t)
			require.Equal(t, 0, code, "%v", m)
			assert.Equal(t, true, m["config_valid"], "%v", m)
			assert.Zero(t, w.walked["root"], "/root is never walked: %v", w.walked)
			for _, p := range *seen {
				assert.NotContains(t, p, "/root", "opened %s", p)
			}
			out := w.f.out.String()
			for _, secret := range []string{"s3cr3t", "TOPSECRET", "db-password", "id_ed25519", "hunter2"} {
				assert.NotContains(t, out, secret)
			}
			servers := asList(m["servers"])
			z := servers[len(servers)-1]
			assert.Equal(t, []map[string]any{
				{"cert": "", "key": "", "inherited": false, "unsupported": haproxyconf.ReasonConfigFileWritable, "raw": "/root/notes"},
				{"cert": "", "key": "", "inherited": false, "unsupported": haproxyconf.ReasonConfigFileWritable, "raw": "/root/keys"},
			}, serverPairs(z))
			assert.Equal(t, []any{}, m["files"])
		})
	}
}

// Review I2: a crt-list named only in a region "-c" may have skipped, and absent, gives a
// conditional pair and config_file_not_read; the rest of the dump stands. An active naming of
// the same file still makes the configuration untrusted.
func TestHAProxyDumpMissingCrtListInUncertainRegion(t *testing.T) {
	staging := ".if defined(STAGING)\nfrontend z\n    bind :9445 ssl crt-list /etc/haproxy/lists/staging.lst\n.endif\n"
	w := newHAProxyWorld(t)
	w.f.write(haproxyConfPath, haproxyCfg+staging, 0o644)
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, true, m["config_valid"], "%v", m)
	assert.Equal(t, []any{haproxyconf.WarnConfigFileNotRead}, m["warnings"])
	servers := asList(m["servers"])
	require.Len(t, servers, 3)
	assert.Equal(t, []map[string]any{
		{"cert": "", "key": "", "inherited": false, "unsupported": haproxyconf.ReasonConditional, "raw": "/etc/haproxy/lists/staging.lst"},
	}, serverPairs(servers[2]))
	assert.Len(t, m["files"], 6, "the other frontends are described as before")

	t.Run("also named actively", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.f.write(haproxyConfPath, haproxyCfg+staging+"frontend y\n    bind :9446 ssl crt-list /etc/haproxy/lists/staging.lst\n", 0o644)
		class, reason, file := w.refusal(t)
		assert.Equal(t, []string{helperproto.ConfigErrUntrusted, helperproto.ConfigReasonMissing, "/etc/haproxy/lists/staging.lst"}, []string{class, reason, file})
	})
	t.Run("a bound is never softened", func(t *testing.T) {
		old := haproxyReadBudget
		defer func() { haproxyReadBudget = old }()
		w := newHAProxyWorld(t)
		w.f.write("/etc/haproxy/lists/staging.lst", strings.Repeat("#\n", 100), 0o644)
		w.f.write(haproxyConfPath, haproxyCfg+staging, 0o644)
		haproxyReadBudget = len(haproxyCfg) + len(staging) + len(haproxyListText) + 10
		class, reason, _ := w.refusal(t)
		assert.Equal(t, []string{helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooLarge}, []string{class, reason})
	})
}

// recordOpens makes fsMagic record the guest path of every descriptor it is asked about: rf.open
// (describeCert, keyInCert) checks a file's file system on an O_PATH descriptor before it opens
// the file for reading, and listings check only directories.
func (w *haproxyWorld) recordOpens() *[]string {
	var seen []string
	w.f.s.fsMagic = func(fd int) (int64, error) {
		if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
			if g, ok := w.f.s.guest(p); ok {
				seen = append(seen, g)
			}
		}
		return unix.EXT4_SUPER_MAGIC, nil
	}
	return &seen
}

// Controller ruling on Task 6 concern 1: when a user other than root can change haproxy.cfg or
// a crt-list, no certificate file it names is opened, not even by keyInCert, and no pair carries
// a key path (no oracle on whether a root-only file holds a private key).
func TestHAProxyDumpWritableConfigOpensNoCertificate(t *testing.T) {
	certFiles := func(seen []string) []string {
		var out []string
		for _, p := range seen {
			if strings.HasPrefix(p, "/etc/haproxy/certs/") {
				out = append(out, p)
			}
		}
		return out
	}
	t.Run("control: a root-only configuration opens them", func(t *testing.T) {
		w := newHAProxyWorld(t)
		seen := w.recordOpens()
		code, m := w.dump(t)
		require.Equal(t, 0, code, "%v", m)
		assert.Contains(t, certFiles(*seen), "/etc/haproxy/certs/a.pem")
	})
	for name, file := range map[string]string{"haproxy.cfg": haproxyConfPath, "a crt-list": haproxyList} {
		t.Run(name, func(t *testing.T) {
			w := newHAProxyWorld(t)
			require.NoError(t, os.Chmod(w.f.host(file), 0o666))
			seen := w.recordOpens()
			code, m := w.dump(t)
			require.Equal(t, 0, code, "%v", m)
			assert.Equal(t, true, m["config_valid"])
			assert.Equal(t, []any{file}, m["writable"])
			assert.Empty(t, certFiles(*seen), "no certificate file is opened")
			assert.Equal(t, []any{}, m["files"])
			for _, sv := range asList(m["servers"]) {
				for _, p := range serverPairs(sv) {
					assert.Equal(t, haproxyconf.ReasonConfigFileWritable, p["unsupported"])
					assert.Equal(t, "", p["key"], "no key was resolved")
				}
			}
		})
	}
}

// Review Focus 4: a crt-list named by two frontends is read once.
func TestHAProxyDumpReadsEachCrtListOnce(t *testing.T) {
	w := newHAProxyWorld(t)
	w.f.write(haproxyConfPath, haproxyCfg+"frontend fe_two\n    bind :9445 ssl crt-list /etc/haproxy/lists/sni.lst\n", 0o644)
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	servers := asList(m["servers"])
	require.Len(t, servers, 3)
	assert.Equal(t, "fe_two", servers[2]["section"])
	assert.Equal(t, []any{"www.example.test", "api.example.test"}, servers[2]["names"])
	assert.Equal(t, 1, w.walked["lists"], "the crt-list is opened once: %v", w.walked)
}

// Ruling 10: a crt directory gives one pair per certificate entry; key, OCSP, issuer and SCT
// files, subdirectories and (from 2.6 on) dotfiles are not certificates.
func TestHAProxyDumpCrtDirectory(t *testing.T) {
	w := newHAProxyWorld(t)
	d := "/etc/haproxy/certdir"
	w.f.mkdir(d, 0o755)
	w.f.mkdir(d+"/sub", 0o755)
	w.f.write(d+"/x.pem", string(w.b.FullchainPEM), 0o644)
	w.f.write(d+"/x.pem.key", string(w.b.KeyPEM), 0o600)
	w.f.write(d+"/x.pem.issuer", "issuer", 0o644)
	w.f.write(d+"/x.pem.ocsp", "ocsp", 0o644)
	w.f.write(d+"/.hidden.pem", string(w.a.FullchainPEM), 0o644)
	w.f.symlink("../certs/c.pem", d+"/y.pem")
	w.f.write(haproxyConfPath, "frontend f\n    bind :9443 ssl crt "+d+"\n", 0o644)
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	servers := asList(m["servers"])
	require.Len(t, servers, 1)
	assert.Equal(t, []map[string]any{
		{"cert": d + "/x.pem", "key": d + "/x.pem.key", "inherited": false, "unsupported": "", "raw": ""},
		{"cert": d + "/y.pem", "key": d + "/y.pem", "inherited": false, "unsupported": "", "raw": ""},
	}, serverPairs(servers[0]))
	files := asList(m["files"])
	require.Len(t, files, 4)
	assert.Equal(t, "/etc/haproxy/certs/c.pem", files[1]["resolved"])
	assert.Equal(t, true, files[1]["symlinked"])
}

// Final review I2: a link in a crt folder whose target lies below a directory that is not
// root-controlled is loaded by HAProxy; it is listed, and its file reports not_root_controlled,
// as the same file named by crt does.
func TestHAProxyDumpCrtDirectoryLinkNotRootControlled(t *testing.T) {
	w := newHAProxyWorld(t)
	d := "/etc/haproxy/certdir"
	w.f.mkdir(d, 0o755)
	w.f.mkdir("/srv", 0o755)
	w.f.mkdir("/srv/acme", 0o777)
	w.f.write("/srv/acme/x.pem", string(w.a.FullchainPEM)+string(w.a.KeyPEM), 0o600)
	w.f.symlink("/srv/acme/x.pem", d+"/x.pem")
	for _, cfg := range []string{"crt " + d, "crt /srv/acme/x.pem"} {
		w.f.write(haproxyConfPath, "frontend f\n    bind :9443 ssl "+cfg+"\n", 0o644)
		code, m := w.dump(t)
		require.Equal(t, 0, code, "%v", m)
		require.Len(t, asList(m["servers"]), 1, cfg)
		pairs := serverPairs(asList(m["servers"])[0])
		require.Len(t, pairs, 1, cfg)
		files := asList(m["files"])
		require.NotEmpty(t, files, cfg)
		assert.Equal(t, pairs[0]["cert"], files[0]["path"], cfg)
		assert.Equal(t, helperproto.FileNotRootControlled, files[0]["problem"], cfg)
		assert.Equal(t, "", files[0]["pem"], cfg)
	}
}

// Final review M5: past maxDirLinks links walked in all crt folders together, the discovery is
// refused as too_complex rather than run into the helper's time limit.
func TestHAProxyDumpCrtDirectoryLinkBudget(t *testing.T) {
	w := newHAProxyWorld(t)
	var cfg strings.Builder
	cfg.WriteString("frontend f\n    bind :9443 ssl")
	for j := range 2 {
		d := fmt.Sprintf("/etc/haproxy/d%d", j)
		w.f.mkdir(d, 0o755)
		cfg.WriteString(" crt " + d)
		for i := range maxDirLinks/2 + j {
			w.f.symlink("/etc/haproxy/certs/a.pem", fmt.Sprintf("%s/l%04d.pem", d, i))
		}
	}
	w.f.write(haproxyConfPath, cfg.String()+"\n", 0o644)
	class, reason, file := w.refusal(t)
	assert.Equal(t, []string{helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooComplex, ""}, []string{class, reason, file})
	// Each dump has its own budget: one link fewer passes, twice.
	require.NoError(t, os.Remove(w.f.host("/etc/haproxy/d1/l0000.pem")))
	for range 2 {
		code, m := w.dump(t)
		require.Equal(t, 0, code, "%v", m)
		require.Equal(t, true, m["config_valid"], "%v", m)
	}
}

// C15: HAProxy loads "w.pem.rsa" as itself, but the helper reads and reports only files with a
// certificate name (a link must never lead it to /etc/shadow): the location has problem bad_name.
func TestHAProxyDumpCertWithoutCertExtension(t *testing.T) {
	w := newHAProxyWorld(t)
	w.f.write("/etc/haproxy/certs/w.pem.rsa", string(w.a.FullchainPEM)+string(w.a.KeyPEM), 0o600)
	w.f.write(haproxyConfPath, "frontend f\n    bind :9443 ssl crt /etc/haproxy/certs/w.pem.rsa\n", 0o644)
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	files := asList(m["files"])
	require.NotEmpty(t, files)
	assert.Equal(t, "cert", files[0]["kind"])
	assert.Equal(t, "/etc/haproxy/certs/w.pem.rsa", files[0]["path"])
	assert.Equal(t, helperproto.FileBadName, files[0]["problem"])
	assert.Equal(t, "", files[0]["pem"])
	assert.NotContains(t, w.f.out.String(), privateKeyMarker)
}

// Ruling 2 and C14: conf.d is never read, and never silent: a warning unless it is absent, not a
// directory, or a directory that can be listed safely and holds no *.cfg.
func TestHAProxyDumpWarnsAboutConfDir(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(w *haproxyWorld)
		warn  bool
	}{
		"extra.cfg": {func(w *haproxyWorld) {
			w.f.mkdir(haproxyConfDir, 0o755)
			w.f.write(haproxyConfDir+"/extra.cfg", "frontend x\n", 0o644)
		}, true},
		"a link to a .cfg": {func(w *haproxyWorld) {
			w.f.mkdir(haproxyConfDir, 0o755)
			w.f.write("/etc/haproxy/other", "frontend x\n", 0o644)
			w.f.symlink("../other", haproxyConfDir+"/extra.cfg")
		}, true},
		"only README": {func(w *haproxyWorld) {
			w.f.mkdir(haproxyConfDir, 0o755)
			w.f.write(haproxyConfDir+"/README", "x", 0o644)
		}, false},
		"a subdirectory named x.cfg": {func(w *haproxyWorld) {
			w.f.mkdir(haproxyConfDir+"/x.cfg", 0o755)
		}, false},
		"empty":     {func(w *haproxyWorld) { w.f.mkdir(haproxyConfDir, 0o755) }, false},
		"no conf.d": {func(*haproxyWorld) {}, false},
		"conf.d is a file": {func(w *haproxyWorld) {
			w.f.write(haproxyConfDir, "frontend x\n", 0o644)
		}, false},
		// C14: these exist as directories that cannot be listed safely.
		"a 0777 directory": {func(w *haproxyWorld) { w.f.mkdir(haproxyConfDir, 0o777) }, true},
		"a 0775 directory with a .cfg": {func(w *haproxyWorld) {
			w.f.mkdir(haproxyConfDir, 0o775)
			w.f.write(haproxyConfDir+"/extra.cfg", "frontend x\n", 0o644)
		}, true},
		"too many entries": {func(w *haproxyWorld) {
			w.f.mkdir(haproxyConfDir, 0o755)
			for i := range haproxyconf.MaxDirEntries + 1 {
				w.f.write(fmt.Sprintf("%s/%04d", haproxyConfDir, i), "", 0o644)
			}
		}, true},
		"a link to a directory elsewhere": {func(w *haproxyWorld) {
			w.f.mkdir("/srv", 0o755)
			w.f.mkdir("/srv/haproxy.d", 0o755)
			w.f.write("/srv/haproxy.d/extra.cfg", "frontend x\n", 0o644)
			w.f.symlink("/srv/haproxy.d", haproxyConfDir)
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			w := newHAProxyWorld(t)
			tc.setup(w)
			code, m := w.dump(t)
			require.Equal(t, 0, code, "%v", m)
			if tc.warn {
				assert.Equal(t, []any{helperproto.WarnConfigDirNotRead}, m["warnings"])
			} else {
				assert.Equal(t, []any{}, m["warnings"])
			}
			assert.Len(t, m["servers"], 2, "conf.d is never read")
			assert.NotContains(t, w.f.out.String(), "frontend x")
		})
	}
	t.Run("special file system", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.f.mkdir(haproxyConfDir, 0o755)
		conf := w.f.host(haproxyConfDir)
		w.f.s.fsMagic = func(fd int) (int64, error) {
			if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil && p == conf {
				return unix.PROC_SUPER_MAGIC, nil
			}
			return unix.EXT4_SUPER_MAGIC, nil
		}
		_, m := w.dump(t)
		assert.Equal(t, []any{helperproto.WarnConfigDirNotRead}, m["warnings"])
	})
	t.Run("not given for an invalid configuration", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.f.mkdir(haproxyConfDir, 0o755)
		w.f.write(haproxyConfDir+"/extra.cfg", "frontend x\n", 0o644)
		w.set(haproxyArgsC, apacheAnswer{err: exitStatus(1)})
		w.refusal(t)
	})
}

func TestKeyInCert(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/haproxy", 0o755)
	cert := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	for name, tc := range map[string]struct {
		path, content string
		want          bool
	}{
		"PRIVATE KEY":           {"/etc/haproxy/p8.pem", cert + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", true},
		"RSA PRIVATE KEY":       {"/etc/haproxy/rsa.pem", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n" + cert, true},
		"EC PRIVATE KEY":        {"/etc/haproxy/ec.pem", cert + "-----BEGIN EC PRIVATE KEY-----", true},
		"ENCRYPTED PRIVATE KEY": {"/etc/haproxy/enc.pem", cert + "-----BEGIN ENCRYPTED PRIVATE KEY-----\n", true},
		"CRLF line ends":        {"/etc/haproxy/crlf.pem", "-----BEGIN PRIVATE KEY-----\r\nAAAA\r\n", true},
		"certificate only":      {"/etc/haproxy/cert.pem", cert, false},
		"empty":                 {"/etc/haproxy/empty.pem", "", false},
		"not at a line start":   {"/etc/haproxy/mid.pem", cert + " -----BEGIN PRIVATE KEY-----\n", false},
		"trailing text":         {"/etc/haproxy/trail.pem", cert + "-----BEGIN PRIVATE KEY----- x\n", false},
		"lower case":            {"/etc/haproxy/lower.pem", cert + "-----BEGIN private KEY-----\n", false},
		"other characters":      {"/etc/haproxy/other.pem", cert + "-----BEGIN EC2 PRIVATE KEY-----\n", false},
		"a public key":          {"/etc/haproxy/pub.pem", "-----BEGIN PUBLIC KEY-----\n", false},
		"no certificate name":   {"/etc/haproxy/w.pem.rsa", cert + "-----BEGIN PRIVATE KEY-----\n", false},
	} {
		f.write(tc.path, tc.content, 0o600)
		assert.Equal(t, tc.want, f.s.keyInCert(tc.path), name)
	}
	assert.False(t, f.s.keyInCert("/etc/haproxy/missing.pem"), "missing")
	assert.False(t, f.s.keyInCert("/etc/haproxy/../shadow.pem"), "not a helper path")

	t.Run("hard-linked", func(t *testing.T) {
		require.NoError(t, os.Link(f.host("/etc/haproxy/p8.pem"), f.host("/etc/haproxy/p8-link.pem")))
		assert.False(t, f.s.keyInCert("/etc/haproxy/p8.pem"))
	})
	t.Run("in a group-writable directory", func(t *testing.T) {
		f.mkdir("/etc/haproxy/open", 0o775)
		f.write("/etc/haproxy/open/k.pem", "-----BEGIN PRIVATE KEY-----\n", 0o600)
		assert.False(t, f.s.keyInCert("/etc/haproxy/open/k.pem"))
	})
	t.Run("too large", func(t *testing.T) {
		f.write("/etc/haproxy/big.pem", "-----BEGIN PRIVATE KEY-----\n"+strings.Repeat("A", helperproto.MaxCertFileSize), 0o600)
		assert.False(t, f.s.keyInCert("/etc/haproxy/big.pem"))
	})
	t.Run("a link to a key", func(t *testing.T) {
		f.symlink("p8-link.pem", "/etc/haproxy/l.pem")
		f.write("/etc/haproxy/single.pem", "-----BEGIN PRIVATE KEY-----\n", 0o600)
		f.symlink("single.pem", "/etc/haproxy/l2.pem")
		assert.True(t, f.s.keyInCert("/etc/haproxy/l2.pem"))
	})
}

// Rule 14 and Review Focus 3: a crt directory over MaxDirEntries is too_complex, not a hang; the
// names of all listings together stay within the read budget.
func TestHAProxyDumpBounds(t *testing.T) {
	big := func(w *haproxyWorld, n int) {
		w.f.mkdir("/etc/haproxy/big", 0o755)
		for i := range n {
			w.f.write(fmt.Sprintf("/etc/haproxy/big/%04d.pem", i), "", 0o644)
		}
		w.f.write(haproxyConfPath, "frontend f\n    bind :9443 ssl crt /etc/haproxy/big\n", 0o644)
	}
	t.Run("4097 entries", func(t *testing.T) {
		w := newHAProxyWorld(t)
		big(w, haproxyconf.MaxDirEntries+1)
		start := time.Now()
		class, reason, file := w.refusal(t)
		assert.Equal(t, []string{helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooComplex, ""}, []string{class, reason, file})
		assert.Less(t, time.Since(start), 10*time.Second)
	})
	t.Run("4096 entries are listed", func(t *testing.T) {
		w := newHAProxyWorld(t)
		big(w, haproxyconf.MaxDirEntries)
		code, m := w.dump(t)
		require.Equal(t, 0, code)
		assert.Equal(t, true, m["config_valid"], "%v", m["config_error_reason"])
		assert.Len(t, serverPairs(asList(m["servers"])[0]), haproxyconf.MaxDirEntries)
	})
	t.Run("entries of any kind count", func(t *testing.T) {
		w := newHAProxyWorld(t)
		big(w, 1)
		for i := range haproxyconf.MaxDirEntries {
			w.f.mkdir(fmt.Sprintf("/etc/haproxy/big/d%04d", i), 0o755)
		}
		class, reason, _ := w.refusal(t)
		assert.Equal(t, []string{helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooComplex}, []string{class, reason})
	})
	t.Run("directory names count in the read budget", func(t *testing.T) {
		old := haproxyReadBudget
		defer func() { haproxyReadBudget = old }()
		w := newHAProxyWorld(t)
		big(w, 10)
		cfg := "frontend f\n    bind :9443 ssl crt /etc/haproxy/big\n"
		haproxyReadBudget = len(cfg) + 10*len("0000.pem") - 1
		class, reason, _ := w.refusal(t)
		assert.Equal(t, []string{helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooLarge}, []string{class, reason})
		haproxyReadBudget++
		_, m := w.dump(t)
		assert.Equal(t, true, m["config_valid"])
	})
}

func TestHAProxyDumpRefusesArguments(t *testing.T) {
	w := newHAProxyWorld(t)
	code, m := w.f.run(helperproto.SubHAProxyDump, "x")
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeUsage, m["code"])
	assert.Empty(t, w.calls)
}

func TestHAProxyDumpNeedsRoot(t *testing.T) {
	w := newHAProxyWorld(t)
	w.f.s.euid = func() int { return 1000 }
	code, m := w.f.run(helperproto.SubHAProxyDump)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeNotRoot, m["code"])
	assert.Empty(t, w.calls)
}

func TestHAProxyDumpOutputBudget(t *testing.T) {
	old := dumpBudget
	defer func() { dumpBudget = old }()
	w := newHAProxyWorld(t)
	dumpBudget = len(w.a.FullchainPEM) + 10
	code, m := w.dump(t)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeOutputTooLarge, m["code"])
}

// outcome summarizes a dump: the error code, "valid" (with the writable files), or the
// configuration error's class/reason.
func outcome(code int, m map[string]any) string {
	switch {
	case code != 0:
		return fmt.Sprint(m["code"])
	case m["config_valid"] == true:
		return fmt.Sprintf("valid writable=%v warnings=%v", m["writable"], m["warnings"])
	}
	return fmt.Sprintf("%v/%v", m["config_error"], m["config_error_reason"])
}

// Every outcome of a dump leaves the whole fixture root as it was: (path, size, mtime, mode) are
// compared around each run, and each run is checked to be the outcome it is meant to be (review M5).
func TestHAProxyDumpWritesNothing(t *testing.T) {
	w := newHAProxyWorld(t)
	w.f.mkdir(haproxyConfDir, 0o755)
	w.f.write(haproxyConfDir+"/extra.cfg", "frontend x\n", 0o644)
	require.NoError(t, os.Chmod(w.f.host("/etc/haproxy/certs/b.pem.key"), 0o644)) // a key others can read
	chmod := func(guest string, mode os.FileMode) func() {
		return func() { require.NoError(t, os.Chmod(w.f.host(guest), mode)) }
	}
	cfg := func(text string) func() { return func() { w.f.write(haproxyConfPath, text, 0o644) } }
	dirNote := fmt.Sprintf("[%s %s]", helperproto.WarnConfigDirNotRead, helperproto.WarnKeyGroupOpen)
	writableNote := fmt.Sprintf(" warnings=[%s %s]", helperproto.WarnConfigDirNotRead, helperproto.WarnConfigFileWritable)
	for i, o := range []struct {
		change func()
		want   string
	}{
		{func() {}, "valid writable=[] warnings=" + dirNote},
		{func() { w.set(haproxyArgsC, apacheAnswer{err: exitStatus(2)}) }, "valid writable=[] warnings=" + dirNote},
		{func() { w.set(haproxyArgsC, apacheAnswer{err: exitStatus(1)}) }, "syntax/"},
		{func() { w.set(haproxyArgsC, apacheAnswer{}) }, "valid writable=[] warnings=" + dirNote},
		{chmod(haproxyList, 0o666), "valid writable=[" + haproxyList + "]" + writableNote},
		{chmod(haproxyList, 0o644), "valid writable=[] warnings=" + dirNote},
		{chmod(haproxyConfPath, 0o666), "valid writable=[" + haproxyConfPath + "]" + writableNote},
		{chmod(haproxyConfPath, 0o644), "valid writable=[] warnings=" + dirNote},
		{chmod("/etc/haproxy/lists", 0o775), "untrusted/not_root_controlled"},
		{chmod("/etc/haproxy/lists", 0o755), "valid writable=[] warnings=" + dirNote},
		{chmod(haproxyConfDir, 0o777), "valid writable=[] warnings=" + dirNote},
		{chmod(haproxyConfDir, 0o755), "valid writable=[] warnings=" + dirNote},
		{cfg(haproxyCfg + "frontend g\n    bind :1 ssl crt-list /etc/haproxy/lists/gone.lst\n"), "untrusted/missing"},
		{cfg(haproxyCfg + ".if defined(X)\nfrontend g\n    bind :1 ssl crt-list /etc/haproxy/lists/gone.lst\n.endif\n"),
			"valid writable=[] warnings=[" + haproxyconf.WarnConfigFileNotRead + " " + helperproto.WarnConfigDirNotRead + " " + helperproto.WarnKeyGroupOpen + "]"},
		{cfg(haproxyCfg + "frontend g\n    bind :1 ssl crt \"/x\n"), "syntax/"},
		{cfg(strings.Repeat(".if 1\n", haproxyconf.MaxDepth+1) + strings.Repeat(".endif\n", haproxyconf.MaxDepth+1)), "unsupported/too_complex"},
		{cfg(haproxyCfg), "valid writable=[] warnings=" + dirNote},
		{func() { w.set(haproxyArgsV, apacheAnswer{err: &programError{path: haproxyPath}}) }, "untrusted/not_root_controlled"},
		{func() { w.set(haproxyArgsV, apacheAnswer{out: haproxyV}) }, "valid writable=[] warnings=" + dirNote},
		{func() { w.set(haproxyArgsC, apacheAnswer{err: fmt.Errorf("%w", errProgramKilled)}) }, helperproto.CodeIOError},
		{func() { w.set(haproxyArgsV, apacheAnswer{err: fs.ErrNotExist}) }, helperproto.CodeSoftwareNotFound},
	} {
		o.change()
		before := snapshot(t, w.f.root)
		code, m := w.dump(t)
		assert.Equal(t, o.want, outcome(code, m), "outcome %d", i)
		// The ctime is not compared.
		assert.Equal(t, before, snapshot(t, w.f.root), "outcome %d wrote something", i)
	}
}

func TestHAProxyParseError(t *testing.T) {
	for _, tc := range []struct {
		err           error
		class, reason string
	}{
		{haproxyconf.ErrTooLarge, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooLarge},
		{haproxyconf.ErrLineTooLong, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooLarge},
		{haproxyconf.ErrTooComplex, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooComplex},
		{haproxyconf.ErrTooDeep, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooComplex},
		{haproxyconf.ErrNUL, helperproto.ConfigErrUnsupported, helperproto.ConfigReasonNULByte},
		{haproxyconf.ErrSyntax, helperproto.ConfigErrSyntax, ""},
		{fmt.Errorf("/etc/haproxy/haproxy.cfg (line 3): %w", haproxyconf.ErrTooDeep), helperproto.ConfigErrUnsupported, helperproto.ConfigReasonTooComplex},
	} {
		e := haproxyParseError(tc.err)
		assert.Equal(t, []string{tc.class, tc.reason, ""}, []string{e.class, e.reason, e.file}, "%v", tc.err)
	}
}

// The helper's own peak on haproxyconf's hostile inputs (Task 5 carry): Parse, ResolveKeys, the
// wire servers, finishDump's encoding and the reply, measured end to end. "max servers and names"
// and "listens of a crt-list" are over ServerDumpOutput, so they are refused (OUTPUT_TOO_LARGE)
// after the encoding; "half the servers" fits and is written.
func TestHAProxyDumpHostileMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates hundreds of MiB")
	}
	bind := "frontend f\n    bind " + strings.Repeat(":1,", haproxyconf.MaxListens) + " ssl crt-list " + haproxyList + "\n"
	lines := strings.Repeat("/etc/haproxy/certs/a.pem\n", haproxyconf.MaxServers-1)
	for name, tc := range map[string]struct {
		cfg, list string
		exit      int
	}{
		"max servers and names": {bind, strings.Repeat("/etc/haproxy/certs/a.pem n\n", haproxyconf.MaxServers-1) +
			"/etc/haproxy/certs/a.pem" + strings.Repeat(" n", haproxyconf.MaxNames-haproxyconf.MaxServers+1) + "\n", helperproto.ExitFailed},
		"listens of a crt-list": {bind, lines, helperproto.ExitFailed},
		// Half the servers, one listen each: about 8.5 MB of JSON, within ServerDumpOutput.
		"half the servers": {"frontend f\n    bind :1 ssl crt-list " + haproxyList + "\n", lines[:len(lines)/2], helperproto.ExitOK},
	} {
		t.Run(name, func(t *testing.T) {
			w := newHAProxyWorld(t)
			w.f.write(haproxyList, tc.list, 0o644)
			w.f.write(haproxyConfPath, tc.cfg, 0o644)
			var code int
			peak := measurePeak(func() { code = run([]string{helperproto.SubHAProxyDump}, w.f.s) })
			t.Logf("haproxy-dump, %s: peak heap %d MiB, exit %d, answer %d bytes: %q", name, peak>>20, code, w.f.out.Len(), truncate(w.f.out.String(), 80))
			assert.Equal(t, tc.exit, code)
			if code == helperproto.ExitFailed {
				assert.Contains(t, w.f.out.String(), helperproto.CodeOutputTooLarge)
			}
			assert.Less(t, peak, uint64(160<<20))
		})
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// measurePeak runs f and returns the peak heap in use above the starting heap, sampled every
// 200 µs (haproxyconf's measureHeap).
func measurePeak(f func()) uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(100))
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var top atomic.Uint64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > before.HeapAlloc && ms.HeapAlloc-before.HeapAlloc > top.Load() {
				top.Store(ms.HeapAlloc - before.HeapAlloc)
			}
			select {
			case <-done:
				return
			case <-time.After(200 * time.Microsecond):
			}
		}
	}()
	f()
	close(done)
	wg.Wait()
	return top.Load()
}

// Review M2: keyInCert reads at most MaxServerFiles certificates (what finishDump describes);
// past that the answer is false without a read.
func TestHAProxyDumpKeyInCertIsBounded(t *testing.T) {
	w := newHAProxyWorld(t)
	w.f.mkdir("/etc/haproxy/many", 0o755)
	for i := range helperproto.MaxServerFiles + 1 {
		w.f.write(fmt.Sprintf("/etc/haproxy/many/%04d.pem", i), "", 0o644)
	}
	w.f.write(haproxyConfPath, "frontend f\n    bind :9443 ssl crt /etc/haproxy/many\n", 0o644)
	seen := w.recordOpens()
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	last := fmt.Sprintf("/etc/haproxy/many/%04d.pem", helperproto.MaxServerFiles)
	assert.NotContains(t, *seen, last, "the certificate past the bound is never opened")
	assert.Contains(t, *seen, fmt.Sprintf("/etc/haproxy/many/%04d.pem", helperproto.MaxServerFiles-1))
	// Final review M1: the pair whose certificate was not read stays conditional, with no key
	// guessed; the ones before it are resolved (no key in the file: the companion).
	pairs := serverPairs(asList(m["servers"])[0])
	require.Len(t, pairs, helperproto.MaxServerFiles+1)
	assert.Equal(t, map[string]any{"cert": "", "key": "", "inherited": false, "unsupported": "conditional", "raw": last}, pairs[helperproto.MaxServerFiles])
	before := fmt.Sprintf("/etc/haproxy/many/%04d.pem", helperproto.MaxServerFiles-1)
	assert.Equal(t, map[string]any{"cert": before, "key": before + ".key", "inherited": false, "unsupported": "", "raw": ""}, pairs[helperproto.MaxServerFiles-1])
}

// Re-review R1: the entries of a crt-list a user other than root can write name paths of that
// user's choice, even under a root-owned haproxy.cfg. None is walked, listed or opened: a
// root-only directory, a file, an absent path and a directory over MaxDirEntries all give the
// same config_file_writable pair of the entry's text, and the dump stands.
func TestHAProxyDumpWritableCrtListReadsNothingItNames(t *testing.T) {
	w := newHAProxyWorld(t)
	w.f.mkdir("/root/keys", 0o700)
	w.f.write("/root/keys/id_ed25519", "k", 0o600)
	w.f.write("/root/secret.pem", "SECRET", 0o600)
	w.f.mkdir("/etc/haproxy/big", 0o755)
	for i := range haproxyconf.MaxDirEntries + 1 {
		w.f.write(fmt.Sprintf("/etc/haproxy/big/%04d.pem", i), "", 0o644)
	}
	entries := []string{"/root/keys", "/root/secret.pem", "/root/absent.pem", "/etc/haproxy/big"}
	w.f.write(haproxyList, strings.Join(entries, " x.test\n")+" x.test\n", 0o666)
	seen := w.recordOpens()
	code, m := w.dump(t)
	require.Equal(t, 0, code, "%v", m)
	require.Equal(t, true, m["config_valid"], "%v", m)
	assert.Equal(t, []any{haproxyList}, m["writable"])
	assert.Zero(t, w.walked["root"], "/root is never walked: %v", w.walked)
	assert.Zero(t, w.walked["big"], "the big directory is never walked: %v", w.walked)
	for _, p := range *seen {
		assert.False(t, strings.HasPrefix(p, "/root") || strings.HasPrefix(p, "/etc/haproxy/big"), "opened %s", p)
	}
	servers := asList(m["servers"])
	require.Len(t, servers, 1+len(entries))
	for i, e := range entries {
		assert.Equal(t, []map[string]any{{"cert": "", "key": "", "inherited": false,
			"unsupported": haproxyconf.ReasonConfigFileWritable, "raw": e}}, serverPairs(servers[1+i]), e)
	}
	out := w.f.out.String()
	for _, s := range []string{"id_ed25519", "SECRET", "0000.pem"} {
		assert.NotContains(t, out, s)
	}
}

// Re-review R2: only an absent or not-regular crt-list is softened in an uncertain region; one
// that is not root-controlled (in a 1777 /tmp) stays untrusted there too.
func TestHAProxyDumpUnsafeCrtListInUncertainRegion(t *testing.T) {
	region := func(list string) string {
		return haproxyCfg + ".if defined(PROD)\nfrontend z\n    bind :9445 ssl crt-list " + list + "\n.endif\n"
	}
	t.Run("in /tmp", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.f.mkdir("/tmp", 0o1777)
		w.f.write("/tmp/x.lst", "/etc/haproxy/certs/a.pem\n", 0o644)
		w.f.write(haproxyConfPath, region("/tmp/x.lst"), 0o644)
		class, reason, file := w.refusal(t)
		assert.Equal(t, []string{helperproto.ConfigErrUntrusted, helperproto.ConfigReasonNotRootControlled, "/tmp/x.lst"}, []string{class, reason, file})
	})
	t.Run("not a regular file is softened", func(t *testing.T) {
		w := newHAProxyWorld(t)
		w.f.mkdir("/etc/haproxy/lists/dir.lst", 0o755)
		w.f.write(haproxyConfPath, region("/etc/haproxy/lists/dir.lst"), 0o644)
		code, m := w.dump(t)
		require.Equal(t, 0, code, "%v", m)
		assert.Equal(t, true, m["config_valid"], "%v", m)
		assert.Equal(t, []any{haproxyconf.WarnConfigFileNotRead}, m["warnings"])
	})
}

// Re-review R3: a failure Parse cached before a writable file was read is masked when it ends
// the dump after one: "changed" naming the writable file.
func TestHAProxyDumpCachedFailureIsMasked(t *testing.T) {
	w := newHAProxyWorld(t)
	gone := "/etc/haproxy/lists/gone.lst"
	w.f.write(haproxyConfPath, ".if defined(X)\nfrontend z\n    bind :9445 ssl crt-list "+gone+"\n.endif\n"+
		haproxyCfg+"frontend y\n    bind :9446 ssl crt-list "+gone+"\n", 0o644)
	require.NoError(t, os.Chmod(w.f.host(haproxyList), 0o666))
	class, reason, file := w.refusal(t)
	assert.Equal(t, []string{helperproto.ConfigErrUntrusted, helperproto.ConfigReasonChanged, haproxyList}, []string{class, reason, file})
}

// Review M3: a directory that walks but cannot be listed (its entries cannot be looked up: mode
// 0444, no search bit) is untrusted "changed" naming it. Root ignores the mode bits, so the
// root-only suite skips it.
func TestHAProxyDumpUnlistableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0444 directory")
	}
	w := newHAProxyWorld(t)
	d := "/etc/haproxy/ro"
	w.f.mkdir(d, 0o755)
	w.f.write(d+"/a.pem", "", 0o644)
	require.NoError(t, os.Chmod(w.f.host(d), 0o444))
	t.Cleanup(func() { _ = os.Chmod(w.f.host(d), 0o755) })
	w.f.write(haproxyConfPath, "frontend f\n    bind :9443 ssl crt "+d+"\n", 0o644)
	class, reason, file := w.refusal(t)
	assert.Equal(t, []string{helperproto.ConfigErrUntrusted, helperproto.ConfigReasonChanged, d}, []string{class, reason, file})
}
