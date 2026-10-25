//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/nginx/nginxconf"
	"alice/internal/testutil/pki"
)

// The fidelity test: the same scenario runs against the real helper (on a temporary directory
// tree, through its sys indirection) and against the emulated Nginx of the fake SSH server
// (internal/providers/linuxssh/linuxsshtest), and every answer is compared: exit status, error
// code, phase, failed_step, cause_step, error, steps, unsupported reasons, warnings, config_error
// class, reason and file, the files described, and what is left on disk. The helper is the
// specification: a difference means the emulator is wrong. The scenarios are in the order of the
// table in the Task 9 report.
//
// What differs by construction and is normalized away: the helper's messages (the emulator's
// are fixed text), the names of owners and groups (the helper's fixture is owned by the test's
// uid), and the file and line of a server block (the emulator generates its own configuration
// file, conf.d/emu.conf, where the helper fixture has conf.d/www.conf).

const (
	fidCrt = "/etc/nginx/ssl/www.crt"
	fidKey = "/etc/nginx/ssl/www.key"
	fidSSL = "/etc/nginx/ssl"
	wwwCfg = "/etc/nginx/conf.d/www.conf"
	emuCfg = "/etc/nginx/conf.d/emu.conf"
)

type twin struct {
	t       *testing.T
	w       *deployWorld
	e       *linuxsshtest.Emulator
	h       linuxsshtest.Handler
	third   pki.Leaf // a leaf for a third deployment
	sameKey pki.Leaf // another certificate of the old key: a changed file that still loads
	killed  bool

	failTests int
	renames   int
	rename    func(n int) error
}

func newTwin(t *testing.T, withNginx bool) *twin {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("the scenarios use the permission bits of an unprivileged user")
	}
	w := newDeployWorld(t)
	e := linuxsshtest.NewEmulator()
	if withNginx {
		e.EnableNginx("1.22.1")
		e.AddSite(linuxsshtest.NginxSite{Names: []string{"www.example.test"}, Port: 443, CertPath: fidCrt, KeyPath: fidKey},
			w.leaf.FullchainPEM, w.leaf.KeyPEM)
		e.AddUnsupported([]string{"both.example.test"}, 443, "/etc/nginx/ssl/both.pem", nginxconf.ReasonCombinedFile)
	}
	tw := &twin{t: t, w: w, e: e, h: e.Handler(),
		third:   pki.NewCA("Third", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow),
		sameKey: pki.NewCA("Same", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test", Key: w.leaf.Key}, testNow)}
	inner := w.f.s.runNginx
	w.f.s.runNginx = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		if !withNginx {
			return inner(ctx, args...) // the fixture's nginx is missing
		}
		if tw.killed {
			return nil, nil, errProgramKilled
		}
		// Like real nginx, -T and -t load every ssl_certificate and ssl_certificate_key; a dump a test
		// forged (the races the helper guards against) is not the host's: -T then passes.
		if stderr := tw.pairStderr(); stderr != "" && (args[0] == "-t" || (args[0] == "-T" && tw.w.dump == nil)) {
			return nil, []byte(stderr), errors.New("exit status 1")
		}
		if args[0] == "-t" && tw.failTests > 0 {
			tw.failTests--
			return nil, []byte("nginx: [emerg] unexpected \"}\" in /etc/nginx/nginx.conf:3"), errors.New("exit status 1")
		}
		return inner(ctx, args...)
	}
	if !withNginx {
		w.missing = true
	}
	w.f.s.beforeRename = func() error {
		tw.renames++
		if tw.rename != nil {
			return tw.rename(tw.renames)
		}
		return nil
	}
	return tw
}

// pairStderr is what nginx prints when it cannot load the pair of the www server (the text the
// helper classifies); "" when it loads. Written independently of the emulator: it reads the fixture's
// files with the standard library only.
func (tw *twin) pairStderr() string {
	certPath, keyPath := tw.w.f.host(fidCrt), tw.w.f.host(fidKey)
	for _, p := range []string{certPath, keyPath} {
		st, err := os.Lstat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return "nginx: [emerg] cannot load certificate \"" + p + "\": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)"
		case err == nil && !st.Mode().IsRegular():
			return "" // a FIFO or a directory: not something these scenarios ask nginx about
		}
	}
	certPEM, _ := os.ReadFile(certPath)
	keyPEM, _ := os.ReadFile(keyPath)
	blocks := 0
	for rest := certPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			blocks++
			if _, err := x509.ParseCertificate(b.Bytes); err != nil {
				return "nginx: [emerg] cannot load certificate: PEM_read_bio_X509_AUX() failed"
			}
		}
	}
	if blocks == 0 {
		return "nginx: [emerg] cannot load certificate: PEM_read_bio_X509_AUX() failed"
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		if strings.Contains(err.Error(), "does not match") {
			return "nginx: [emerg] SSL_CTX_use_PrivateKey() failed (SSL: error:05800074:x509 certificate routines::key values mismatch)"
		}
		return "nginx: [emerg] cannot load certificate key: PEM_read_bio_PrivateKey() failed"
	}
	return ""
}

// ---- running a command on both ----------------------------------------------------------------

type answer struct {
	exit   int
	killed bool
	m      map[string]any
}

func (tw *twin) emuLine(sub string, args []string) string {
	var b strings.Builder
	if sub != helperproto.SubTLSProbe {
		b.WriteString("sudo -n ")
	}
	b.WriteString(helperproto.HelperPath + " " + sub)
	for _, a := range args {
		if strings.HasPrefix(a, "--") && a != "--" && !strings.ContainsAny(a, " '") {
			b.WriteString(" " + a)
		} else {
			b.WriteString(" '" + a + "'")
		}
	}
	return b.String()
}

func (tw *twin) runHelper(sub, stdin string, args ...string) answer {
	tw.t.Helper()
	tw.w.f.s.stdin = strings.NewReader(stdin)
	code, m := tw.w.f.run(append([]string{sub}, args...)...)
	return answer{exit: code, m: m}
}

func (tw *twin) runEmu(sub, stdin string, args ...string) answer {
	tw.t.Helper()
	r := tw.h(tw.emuLine(sub, args), []byte(stdin))
	if r.Signal != "" {
		return answer{exit: -1, killed: true}
	}
	var m map[string]any
	if len(r.Stdout) > 0 {
		require.NoError(tw.t, json.Unmarshal(r.Stdout, &m), string(r.Stdout))
	}
	return answer{exit: r.Exit, m: m}
}

// normalize makes the two answers comparable (see the comment at the top of the file).
func normalize(sub string, a answer, helperSide bool) answer {
	if a.m == nil {
		return a
	}
	raw, _ := json.Marshal(a.m)
	text := string(raw)
	if helperSide {
		text = strings.ReplaceAll(text, wwwCfg, emuCfg)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(text), &m)
	delete(m, "message")
	if sub == helperproto.SubNginxDump || sub == helperproto.SubApacheDump || sub == helperproto.SubHAProxyDump {
		for _, s := range asList(m["servers"]) {
			delete(s, "file")
			delete(s, "line")
		}
		for _, f := range asList(m["files"]) {
			delete(f, "owner")
			delete(f, "group")
		}
	}
	a.m = m
	return a
}

func asList(v any) []map[string]any {
	var out []map[string]any
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(map[string]any))
	}
	return out
}

// same runs the command on both and requires the same answer; it returns the helper's.
func (tw *twin) same(sub, stdin string, args ...string) answer {
	tw.t.Helper()
	h := normalize(sub, tw.runHelper(sub, stdin, args...), true)
	e := normalize(sub, tw.runEmu(sub, stdin, args...), false)
	assert.Equal(tw.t, h.exit, e.exit, "exit status of %s %v", sub, args)
	assert.Equal(tw.t, h.m, e.m, "answer of %s %v", sub, args)
	return h
}

// ---- mirrored changes to the two worlds ---------------------------------------------------------

func (tw *twin) put(guest string, content []byte) {
	tw.t.Helper()
	require.NoError(tw.t, os.WriteFile(tw.w.f.host(guest), content, 0o600)) // keeps the mode of an existing file
	tw.e.SetNginxFile(guest, content)
}

func (tw *twin) remove(guest string) {
	tw.t.Helper()
	require.NoError(tw.t, os.Remove(tw.w.f.host(guest)))
	tw.e.RemoveNginxFile(guest)
}

func (tw *twin) chmod(guest string, mode os.FileMode) {
	tw.t.Helper()
	require.NoError(tw.t, os.Chmod(tw.w.f.host(guest), mode))
	tw.e.SetNginxFileMode(guest, "root", "root", uint32(mode))
}

// linkWildcard moves the pair into an acme.sh-style "*.example.test" directory and makes the
// configured names root's links to it (A1-I1).
func (tw *twin) linkWildcard() {
	tw.t.Helper()
	linkIntoWildcardDir(tw.t, tw.w)
	tw.e.SetNginxFileResolved(fidCrt, wildcardDir+"/fullchain.cer")
	tw.e.SetNginxFileResolved(fidKey, wildcardDir+"/*.example.test.key")
}

func (tw *twin) failTest(n int) { tw.failTests = n; tw.e.FailConfigTest(n) }

func (tw *twin) failReload(n int) { tw.w.reloadFail = n; tw.e.FailReload(n) }

func (tw *twin) killNginx() { tw.killed = true; tw.e.SetNginxKilled(true) }

// dirProblem makes the directory of the certificate and key (/etc/nginx/ssl) one the walk refuses.
func (tw *twin) dirNotRootControlled() {
	tw.t.Helper()
	require.NoError(tw.t, os.Chmod(tw.w.f.host(fidSSL), 0o775))
	tw.e.SetFileProblem(fidCrt, helperproto.FileNotRootControlled)
	tw.e.SetFileProblem(fidKey, helperproto.FileNotRootControlled)
}

func (tw *twin) dirSpecialFS() {
	tw.w.magicAt(fidSSL, unix.PROC_SUPER_MAGIC)
	tw.e.SetFileProblem(fidCrt, helperproto.FileSpecialFS)
	tw.e.SetFileProblem(fidKey, helperproto.FileSpecialFS)
}

// kill kills both helpers at the named point of the next transaction (the helper's own point names).
func (tw *twin) kill(point string) {
	fired := false
	tw.w.f.s.afterDeployStep = func(name string) error {
		if name == point && !fired {
			fired = true
			return errKilled
		}
		return nil
	}
	tw.e.KillAt(point)
}

func (tw *twin) revive() { tw.w.f.s.afterDeployStep, tw.w.f.s.killed = nil, false }

// ---- command helpers ------------------------------------------------------------------------

func (tw *twin) deployArgs(op, in, expect string) []string {
	return []string{"--op", op, "--cert", fidCrt, "--key", fidKey, "--expect-cert-sha256", expect, "--content-sha256", hexOf(in)}
}

func (tw *twin) deploy(op string) answer {
	tw.t.Helper()
	in := tw.w.newInput()
	return tw.same(helperproto.SubNginxDeploy, in, tw.deployArgs(op, in, tw.w.oldSHA())...)
}

func (tw *twin) status(op string) answer { return tw.same(helperproto.SubNginxStatus, "", "--op", op) }

func (tw *twin) restore(op string) answer {
	return tw.same(helperproto.SubNginxRestore, "", "--op", op)
}

func (tw *twin) dump() answer { return tw.same(helperproto.SubNginxDump, "") }

// sameFiles requires both worlds to hold the same certificate and key.
func (tw *twin) sameFiles(want string) {
	tw.t.Helper()
	cert, key := tw.w.f.read(fidCrt), tw.w.f.read(fidKey)
	assert.Equal(tw.t, cert, string(tw.e.NginxFile(fidCrt)), "certificate file")
	assert.Equal(tw.t, key, string(tw.e.NginxFile(fidKey)), "key file")
	switch want {
	case "old":
		assert.Equal(tw.t, string(tw.w.leaf.FullchainPEM), cert)
		assert.Equal(tw.t, string(tw.w.leaf.KeyPEM), key)
	case "new":
		assert.Equal(tw.t, string(tw.w.newLeaf.FullchainPEM), cert)
		assert.Equal(tw.t, string(tw.w.newLeaf.KeyPEM), key)
	}
}

// ---- the scenarios ----------------------------------------------------------------------------------

func TestEmulatorFidelityDump(t *testing.T) {
	dumpOf := func(tw *twin) string { return tw.w.dumpText() }
	emuDump := func(tw *twin) string { return tw.e.NginxDumpText() }
	// forge replaces the text nginx -T prints, in both worlds, by f of each world's own text.
	forge := func(tw *twin, f func(text string, helper bool) string) {
		tw.w.setDump(f(dumpOf(tw), true))
		tw.e.SetNginxDump(f(emuDump(tw), false))
	}
	conf := func(tw *twin, path, content string) {
		tw.w.setConf(confFile{path, content})
		tw.e.SetNginxConfig(path, content)
	}
	const main = "/etc/nginx/nginx.conf"
	type scenario struct {
		name  string
		nginx bool
		run   func(t *testing.T, tw *twin)
	}
	for _, sc := range []scenario{
		{"a valid configuration with a supported and an unsupported pair", true, func(t *testing.T, tw *twin) {
			a := tw.dump()
			assert.Equal(t, true, a.m["config_valid"])
		}},
		{"nginx missing", false, func(t *testing.T, tw *twin) {
			a := tw.dump()
			assert.Equal(t, helperproto.CodeNginxNotFound, a.m["code"])
			assert.Equal(t, helperproto.CodeNginxNotFound, tw.same(helperproto.SubNginxTest, "").m["code"])
		}},
		{"nginx killed", true, func(t *testing.T, tw *twin) {
			tw.killNginx()
			assert.Equal(t, helperproto.CodeIOError, tw.dump().m["code"])
			assert.Equal(t, helperproto.CodeIOError, tw.same(helperproto.SubNginxTest, "").m["code"])
		}},
		{"nginx -t fails", true, func(t *testing.T, tw *twin) {
			tw.same(helperproto.SubNginxTest, "")
			tw.w.tFails = "nginx: [emerg] unexpected \"}\" in /etc/nginx/nginx.conf:3"
			tw.e.SetConfigInvalid(helperproto.ConfigErrSyntax)
			assert.Equal(t, false, tw.same(helperproto.SubNginxTest, "").m["valid"])
			assert.Equal(t, helperproto.ConfigErrSyntax, tw.dump().m["config_error"])
		}},
		{"warning key_group_open (a 0644 key)", true, func(t *testing.T, tw *twin) {
			tw.chmod(fidKey, 0o644)
			assert.Equal(t, []any{helperproto.WarnKeyGroupOpen}, tw.dump().m["warnings"])
		}},
		{"no warning for 0640 and 0660 keys (root's group)", true, func(t *testing.T, tw *twin) {
			for _, m := range []os.FileMode{0o640, 0o660, 0o600, 0o400} {
				tw.chmod(fidKey, m)
				assert.Equal(t, []any{}, tw.dump().m["warnings"], "%o", m)
			}
		}},
		{"warning key_group_open (others can read)", true, func(t *testing.T, tw *twin) {
			tw.chmod(fidKey, 0o604)
			assert.Equal(t, []any{helperproto.WarnKeyGroupOpen}, tw.dump().m["warnings"])
		}},
		{"warning certificate_block_dropped (forged dump: nginx would not load it)", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s })
			tw.put(fidCrt, append(append([]byte{}, tw.w.leaf.FullchainPEM...), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"...))
			assert.Equal(t, []any{helperproto.WarnCertificateBlockDropped}, tw.dump().m["warnings"])
		}},
		{"config_file_writable (a writable configuration file)", true, func(t *testing.T, tw *twin) {
			tw.chmod(wwwCfg, 0o666)
			tw.e.SetNginxFileMode(emuCfg, "root", "root", 0o666)
			a := tw.dump()
			assert.Equal(t, []any{helperproto.WarnConfigFileWritable}, a.m["warnings"])
			assert.Equal(t, []any{emuCfg}, a.m["writable"])
		}},
		{"syntax error in the configuration", true, func(t *testing.T, tw *twin) {
			conf(tw, main, "http {\n")
			assert.Equal(t, helperproto.ConfigErrSyntax, tw.dump().m["config_error"])
		}},
		{"NUL byte", true, func(t *testing.T, tw *twin) {
			text := "# configuration file /etc/nginx/nginx.conf:\nhttp { }\x00\n"
			tw.w.setDump(text)
			tw.e.SetNginxDump(text)
			assert.Equal(t, helperproto.ConfigReasonNULByte, tw.dump().m["config_error_reason"])
		}},
		{"too many arguments", true, func(t *testing.T, tw *twin) {
			conf(tw, main, "http { server { server_name"+strings.Repeat(" a", 5000)+"; } }")
			assert.Equal(t, helperproto.ConfigReasonTooComplex, tw.dump().m["config_error_reason"])
		}},
		{"nested too deep", true, func(t *testing.T, tw *twin) {
			conf(tw, main, strings.Repeat("a {", 120)+strings.Repeat("}", 120))
			assert.Equal(t, helperproto.ConfigReasonTooComplex, tw.dump().m["config_error_reason"])
		}},
		{"line too long", true, func(t *testing.T, tw *twin) {
			conf(tw, main, "# "+strings.Repeat("x", nginxconf.MaxLine+1))
			assert.Equal(t, helperproto.ConfigReasonTooLarge, tw.dump().m["config_error_reason"])
		}},
		{"include loop", true, func(t *testing.T, tw *twin) {
			conf(tw, main, "include /etc/nginx/nginx.conf;")
			assert.Equal(t, helperproto.ConfigReasonIncludeLoop, tw.dump().m["config_error_reason"])
		}},
		{"relative conf path", true, func(t *testing.T, tw *twin) {
			tw.w.version = strings.Replace(nginxV, "/etc/nginx/nginx.conf", "conf/nginx.conf", 1)
			tw.e.SetNginxConfPath("conf/nginx.conf")
			assert.Equal(t, helperproto.ConfigReasonNoConfPath, tw.dump().m["config_error_reason"])
		}},
		{"no conf path (a source build)", true, func(t *testing.T, tw *twin) {
			tw.w.version = strings.Replace(nginxV, "--conf-path=/etc/nginx/nginx.conf ", "", 1)
			tw.e.SetNginxConfPath("")
			assert.Equal(t, helperproto.ConfigReasonNoConfPath, tw.dump().m["config_error_reason"])
		}},
		{"unclean conf path", true, func(t *testing.T, tw *twin) {
			tw.w.version = strings.Replace(nginxV, "/etc/nginx/nginx.conf", "/etc/nginx//nginx.conf", 1)
			tw.e.SetNginxConfPath("/etc/nginx//nginx.conf")
			assert.Equal(t, helperproto.ConfigReasonNoConfPath, tw.dump().m["config_error_reason"])
		}},
		{"output over the cap", true, func(t *testing.T, tw *twin) {
			tw.w.tooBig = true
			conf(tw, main, "# "+strings.Repeat("x", helperproto.MaxServerConfig)+"\nhttp { include /etc/nginx/conf.d/*.conf; }\n")
			assert.Equal(t, helperproto.ConfigReasonTooLarge, tw.dump().m["config_error_reason"])
		}},
		{"duplicate file", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s + "# configuration file /etc/nginx/nginx.conf:\nhttp { }\n" })
			assert.Equal(t, helperproto.ConfigReasonDuplicateFile, tw.dump().m["config_error_reason"])
		}},
		{"text before the first marker", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return "http { server { }}\n" + s })
			assert.Equal(t, helperproto.ConfigReasonUnexpectedText, tw.dump().m["config_error_reason"])
		}},
		{"an empty dump", true, func(t *testing.T, tw *twin) {
			forge(tw, func(string, bool) string { return "" })
			assert.Equal(t, helperproto.ConfigReasonWrongFirstFile, tw.dump().m["config_error_reason"])
		}},
		{"a file changed since nginx read it", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s })
			tw.put(wwwCfg, append(append([]byte{}, tw.w.f.read(wwwCfg)...), "#\n"...))
			tw.e.SetNginxFile(emuCfg, append(tw.e.NginxFile(emuCfg), "#\n"...))
			assert.Equal(t, helperproto.ConfigReasonChanged, tw.dump().m["config_error_reason"])
		}},
		{"no line feed after the file", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return strings.TrimSuffix(s, "\n") })
			assert.Equal(t, helperproto.ConfigReasonChanged, tw.dump().m["config_error_reason"])
		}},
		{"a configuration file that does not exist", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s })
			require.NoError(t, os.Remove(tw.w.f.host(wwwCfg)))
			tw.e.RemoveNginxFile(emuCfg)
			assert.Equal(t, helperproto.ConfigReasonMissing, tw.dump().m["config_error_reason"])
		}},
		{"a FIFO", true, func(t *testing.T, tw *twin) {
			require.NoError(t, os.Remove(tw.w.f.host(wwwCfg)))
			require.NoError(t, unix.Mkfifo(tw.w.f.host(wwwCfg), 0o644))
			tw.e.SetFileProblem(emuCfg, helperproto.FileNotRegular)
			assert.Equal(t, helperproto.ConfigReasonNotRegular, tw.dump().m["config_error_reason"])
		}},
		{"a name with a space", true, func(t *testing.T, tw *twin) {
			tw.w.f.write("/etc/nginx/conf.d/a b.conf", "", 0o644)
			forge(tw, func(s string, _ bool) string { return s + "# configuration file /etc/nginx/conf.d/a b.conf:\n\n" })
			assert.Equal(t, helperproto.ConfigReasonNameNotAllowed, tw.dump().m["config_error_reason"])
		}},
		{"a relative name", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s + "# configuration file conf.d/www.conf:\nhttp { }\n" })
			assert.Equal(t, helperproto.ConfigReasonNameNotAllowed, tw.dump().m["config_error_reason"])
		}},
		{"a group-writable directory", true, func(t *testing.T, tw *twin) {
			require.NoError(t, os.Chmod(tw.w.f.host("/etc/nginx/conf.d"), 0o775))
			tw.e.SetFileProblem(emuCfg, helperproto.FileNotRootControlled)
			assert.Equal(t, helperproto.ConfigReasonNotRootControlled, tw.dump().m["config_error_reason"])
		}},
		{"a configuration directory on procfs", true, func(t *testing.T, tw *twin) {
			tw.w.magicAt("/etc/nginx/conf.d", unix.PROC_SUPER_MAGIC)
			tw.e.SetFileProblem(emuCfg, helperproto.FileSpecialFS)
			assert.Equal(t, helperproto.ConfigReasonSpecialFS, tw.dump().m["config_error_reason"])
		}},
		{"pair files nginx cannot load make nginx -T fail", true, func(t *testing.T, tw *twin) {
			tw.remove(fidCrt)
			a := tw.dump()
			assert.Equal(t, helperproto.ConfigErrFileMissing, a.m["config_error"])
			assert.Equal(t, helperproto.ConfigErrFileMissing, tw.same(helperproto.SubNginxTest, "").m["error"])
			tw.put(fidCrt, tw.w.leaf.FullchainPEM)
			tw.chmod(fidCrt, 0o644) // a recreated file has the creator's mode
			tw.remove(fidKey)
			assert.Equal(t, helperproto.ConfigErrFileMissing, tw.dump().m["config_error"])
			tw.put(fidKey, tw.third.KeyPEM)
			tw.chmod(fidKey, 0o600)
			assert.Equal(t, helperproto.ConfigErrKeyMismatch, tw.dump().m["config_error"])
			assert.Equal(t, helperproto.ConfigErrKeyMismatch, tw.same(helperproto.SubNginxTest, "").m["error"])
			tw.put(fidKey, []byte("garbled"))
			assert.Equal(t, helperproto.ConfigErrKeyLoad, tw.dump().m["config_error"])
			tw.put(fidKey, tw.w.leaf.KeyPEM)
			tw.put(fidCrt, []byte("garbled"))
			assert.Equal(t, helperproto.ConfigErrCertLoad, tw.dump().m["config_error"])
			tw.put(fidCrt, tw.w.leaf.FullchainPEM)
			assert.Equal(t, true, tw.dump().m["config_valid"])
		}},
		{"certificate file problems: missing (forged dump)", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s })
			tw.remove(fidCrt)
			assert.Equal(t, helperproto.FileMissing, asList(tw.dump().m["files"])[0]["problem"])
		}},
		{"certificate file problems: missing key (forged dump)", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s })
			tw.remove(fidKey)
			assert.Equal(t, helperproto.FileMissing, asList(tw.dump().m["files"])[1]["problem"])
		}},
		{"certificate file problems: a FIFO", true, func(t *testing.T, tw *twin) {
			require.NoError(t, os.Remove(tw.w.f.host(fidCrt)))
			require.NoError(t, unix.Mkfifo(tw.w.f.host(fidCrt), 0o644))
			tw.e.SetFileProblem(fidCrt, helperproto.FileNotRegular)
			assert.Equal(t, helperproto.FileNotRegular, asList(tw.dump().m["files"])[0]["problem"])
		}},
		{"certificate file problems: a hard-linked key", true, func(t *testing.T, tw *twin) {
			require.NoError(t, os.Link(tw.w.f.host(fidKey), tw.w.f.host("/etc/nginx/ssl/other.key")))
			tw.e.SetFileProblem(fidKey, helperproto.FileHardLinked)
			assert.Equal(t, helperproto.FileHardLinked, asList(tw.dump().m["files"])[1]["problem"])
		}},
		{"certificate file problems: too large", true, func(t *testing.T, tw *twin) {
			tw.put(fidCrt, append(append([]byte{}, tw.w.leaf.FullchainPEM...), strings.Repeat("\n", helperproto.MaxCertFileSize)...))
			assert.Equal(t, helperproto.FileTooLarge, asList(tw.dump().m["files"])[0]["problem"])
		}},
		{"certificate file problems: not a certificate (forged dump)", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s })
			tw.put(fidCrt, []byte("hello"))
			assert.Equal(t, helperproto.FileNotACertificate, asList(tw.dump().m["files"])[0]["problem"])
		}},
		{"certificate file problems: an unreadable first block (forged dump)", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s })
			tw.put(fidCrt, append([]byte(unreadableCertPEM), tw.w.leaf.FullchainPEM[len(tw.w.leaf.CertPEM):]...))
			d := tw.dump().m
			assert.Equal(t, helperproto.FileLeafUnreadable, asList(d["files"])[0]["problem"])
			assert.Equal(t, "", asList(d["files"])[0]["pem"])
			assert.Equal(t, []any{helperproto.WarnCertificateBlockDropped}, d["warnings"])
		}},
		{"a leaf labelled X509 CERTIFICATE (KI-39)", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s })
			inter := tw.w.leaf.FullchainPEM[len(tw.w.leaf.CertPEM):]
			tw.put(fidCrt, []byte(relabel(tw.w.leaf.CertPEM, "X509 CERTIFICATE")+string(inter)))
			d := tw.dump().m
			assert.Equal(t, string(tw.w.leaf.FullchainPEM), asList(d["files"])[0]["pem"])
			assert.Equal(t, []any{}, d["warnings"])
		}},
		{"a leaf labelled TRUSTED CERTIFICATE, and a later one skipped (KI-39)", true, func(t *testing.T, tw *twin) {
			forge(tw, func(s string, _ bool) string { return s })
			inter := tw.w.leaf.FullchainPEM[len(tw.w.leaf.CertPEM):]
			tw.put(fidCrt, []byte(trustedPEM(t, tw.w.leaf.Cert.Raw)+string(inter)))
			d := tw.dump().m
			assert.Equal(t, string(tw.w.leaf.FullchainPEM), asList(d["files"])[0]["pem"])
			assert.Equal(t, []any{}, d["warnings"])
			tw.put(fidCrt, []byte(string(tw.w.leaf.CertPEM)+trustedPEM(t, tw.w.leaf.Cert.Raw)))
			d = tw.dump().m
			assert.Equal(t, string(tw.w.leaf.CertPEM), asList(d["files"])[0]["pem"])
			assert.Equal(t, []any{helperproto.WarnCertificateBlockDropped}, d["warnings"])
		}},
		{"certificate file problems: the directory is not root controlled", true, func(t *testing.T, tw *twin) {
			tw.dirNotRootControlled()
			assert.Equal(t, helperproto.FileNotRootControlled, asList(tw.dump().m["files"])[0]["problem"])
		}},
		{"certificate file problems: the directory is on procfs", true, func(t *testing.T, tw *twin) {
			tw.dirSpecialFS()
			assert.Equal(t, helperproto.FileSpecialFS, asList(tw.dump().m["files"])[0]["problem"])
		}},
		{"answer over the budget", true, func(t *testing.T, tw *twin) {
			old := dumpBudget
			dumpBudget = 100
			defer func() { dumpBudget = old }()
			tw.e.SetNginxDumpBudget(100)
			assert.Equal(t, helperproto.CodeOutputTooLarge, tw.dump().m["code"])
		}},
	} {
		t.Run(sc.name, func(t *testing.T) { sc.run(t, newTwin(t, sc.nginx)) })
	}
}

func TestEmulatorFidelityDeploy(t *testing.T) {
	type scenario struct {
		name string
		run  func(t *testing.T, tw *twin)
	}
	for _, sc := range []scenario{
		{"committed, then restored", func(t *testing.T, tw *twin) {
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.PhaseCommitted, a.m["phase"])
			tw.sameFiles("new")
			assert.Equal(t, helperproto.PhaseCommitted, tw.status(opA).m["phase"])
			assert.Equal(t, helperproto.PhaseCommitted, tw.deploy(opA).m["phase"], "the journal answers the same operation")
			assert.Equal(t, helperproto.PhaseRestored, tw.restore(opA).m["phase"])
			tw.sameFiles("old")
			assert.Equal(t, helperproto.PhaseRestored, tw.status(opA).m["phase"])
			tw.same(helperproto.SubNginxRestore, "", "--op", opA)
			assert.Equal(t, helperproto.PhaseRestored, tw.deploy(opA).m["phase"], "the restored operation answers from its journal")
		}},
		{"modes: a 0640 key stays 0640, the certificate never gets wider", func(t *testing.T, tw *twin) {
			tw.chmod(fidKey, 0o640)
			tw.chmod(fidCrt, 0o664)
			tw.deploy(opA)
			files := asList(tw.dump().m["files"])
			assert.Equal(t, "0644", files[0]["mode"])
			assert.Equal(t, "0640", files[1]["mode"])
			tw.restore(opA)
			files = asList(tw.dump().m["files"])
			assert.Equal(t, "0664", files[0]["mode"], "nginx-restore puts the exact old mode back")
			assert.Equal(t, "0640", files[1]["mode"])
			tw.chmod(fidKey, 0o444)
			tw.deploy(opB)
			assert.Equal(t, "0600", asList(tw.dump().m["files"])[1]["mode"], "an old 0444 key becomes 0600")
		}},
		{"unchanged", func(t *testing.T, tw *twin) {
			in := input(tw.w.leaf.FullchainPEM, tw.w.leaf.KeyPEM)
			a := tw.same(helperproto.SubNginxDeploy, in, tw.deployArgs(opA, in, tw.w.oldSHA())...)
			assert.Equal(t, helperproto.PhaseUnchanged, a.m["phase"])
			tw.status(opA)
			tw.restore(opA)
		}},
		{"refusal: the pair resolves to a name the vocabulary cannot carry (A1-I1)", func(t *testing.T, tw *twin) {
			tw.linkWildcard()
			files := asList(tw.dump().m["files"])
			assert.Equal(t, helperproto.FileNameNotAllowed, files[0]["problem"])
			assert.Equal(t, helperproto.FileNameNotAllowed, files[1]["problem"])
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.CodePathNotAllowed, a.m["code"])
			assert.Equal(t, helperproto.PhaseNone, tw.status(opA).m["phase"])
		}},
		{"refusal: nginx is not running (A1 m3)", func(t *testing.T, tw *twin) {
			tw.w.f.s.runSystemctl = func(context.Context, ...string) error { return errors.New("exit status 3") }
			tw.e.SetNginxNotRunning(true)
			assert.Equal(t, helperproto.CodeNginxNotRunning, tw.deploy(opA).m["code"])
			tw.status(opA)
			tw.sameFiles("old")
		}},
		{"operation id of another deployment", func(t *testing.T, tw *twin) {
			tw.deploy(opA)
			in := input(tw.w.leaf.FullchainPEM, tw.w.leaf.KeyPEM)
			a := tw.same(helperproto.SubNginxDeploy, in, tw.deployArgs(opA, in, hexOf(string(tw.w.newLeaf.FullchainPEM)))...)
			assert.Equal(t, helperproto.CodeInvalidArgument, a.m["code"])
		}},
		{"refusal: the certificate hash changed", func(t *testing.T, tw *twin) {
			tw.put(fidCrt, tw.sameKey.FullchainPEM)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.CodeHashMismatch, a.m["code"])
			tw.status(opA)
		}},
		// nginx -T loads the pair files: a missing or unloadable one is a configuration error, not
		// NOT_FOUND / HASH_MISMATCH (those need the file to change after nginx -T: a forged dump).
		{"refusal: certificate missing (nginx -T fails)", func(t *testing.T, tw *twin) {
			tw.remove(fidCrt)
			assert.Equal(t, helperproto.CodeConfigInvalid, tw.deploy(opA).m["code"])
		}},
		{"refusal: key missing (nginx -T fails)", func(t *testing.T, tw *twin) {
			tw.remove(fidKey)
			assert.Equal(t, helperproto.CodeConfigInvalid, tw.deploy(opA).m["code"])
		}},
		{"refusal: certificate garbled (nginx -T fails)", func(t *testing.T, tw *twin) {
			tw.put(fidCrt, []byte("garbled"))
			assert.Equal(t, helperproto.CodeConfigInvalid, tw.deploy(opA).m["code"])
		}},
		{"refusal: certificate missing after nginx -T (forged dump): NOT_FOUND", func(t *testing.T, tw *twin) {
			tw.w.setDump(tw.w.dumpText())
			tw.e.SetNginxDump(tw.e.NginxDumpText())
			tw.remove(fidCrt)
			assert.Equal(t, helperproto.CodeNotFound, tw.deploy(opA).m["code"])
		}},
		{"refusal: key missing after nginx -T (forged dump): NOT_FOUND", func(t *testing.T, tw *twin) {
			tw.w.setDump(tw.w.dumpText())
			tw.e.SetNginxDump(tw.e.NginxDumpText())
			tw.remove(fidKey)
			assert.Equal(t, helperproto.CodeNotFound, tw.deploy(opA).m["code"])
		}},
		{"refusal: a FIFO certificate", func(t *testing.T, tw *twin) {
			require.NoError(t, os.Remove(tw.w.f.host(fidCrt)))
			require.NoError(t, unix.Mkfifo(tw.w.f.host(fidCrt), 0o644))
			tw.e.SetFileProblem(fidCrt, helperproto.FileNotRegular)
			assert.Equal(t, helperproto.CodeNotRegularFile, tw.deploy(opA).m["code"])
		}},
		{"refusal: a hard-linked key", func(t *testing.T, tw *twin) {
			require.NoError(t, os.Link(tw.w.f.host(fidKey), tw.w.f.host("/etc/nginx/ssl/other.key")))
			tw.e.SetFileProblem(fidKey, helperproto.FileHardLinked)
			assert.Equal(t, helperproto.CodeUnsafeFile, tw.deploy(opA).m["code"])
		}},
		{"refusal: a certificate over the size limit", func(t *testing.T, tw *twin) {
			tw.put(fidCrt, append(append([]byte{}, tw.w.leaf.FullchainPEM...), strings.Repeat("\n", helperproto.MaxCertFileSize)...))
			assert.Equal(t, helperproto.CodeTooLarge, tw.deploy(opA).m["code"])
		}},
		{"refusal: the directory is not root controlled", func(t *testing.T, tw *twin) {
			tw.dirNotRootControlled()
			assert.Equal(t, helperproto.CodePathNotAllowed, tw.deploy(opA).m["code"])
		}},
		{"refusal: the directory is on procfs", func(t *testing.T, tw *twin) {
			tw.dirSpecialFS()
			assert.Equal(t, helperproto.CodePathNotAllowed, tw.deploy(opA).m["code"])
		}},
		{"refusal: the pair is not in the configuration", func(t *testing.T, tw *twin) {
			in := tw.w.newInput()
			a := tw.same(helperproto.SubNginxDeploy, in, "--op", opA, "--cert", "/etc/nginx/ssl/other.crt", "--key", fidKey,
				"--expect-cert-sha256", tw.w.oldSHA(), "--content-sha256", hexOf(in))
			assert.Equal(t, helperproto.CodeConfigChanged, a.m["code"])
		}},
		{"refusal: an unsupported (combined) pair", func(t *testing.T, tw *twin) {
			in := tw.w.newInput()
			a := tw.same(helperproto.SubNginxDeploy, in, "--op", opA, "--cert", "/etc/nginx/ssl/both.pem", "--key", "/etc/nginx/ssl/both.pem2",
				"--expect-cert-sha256", tw.w.oldSHA(), "--content-sha256", hexOf(in))
			assert.Equal(t, helperproto.CodeConfigChanged, a.m["code"])
		}},
		{"refusal: a writable configuration file (config_file_writable)", func(t *testing.T, tw *twin) {
			tw.chmod(wwwCfg, 0o666)
			tw.e.SetNginxFileMode(emuCfg, "root", "root", 0o666)
			assert.Equal(t, helperproto.CodeConfigChanged, tw.deploy(opA).m["code"])
		}},
		{"refusal: the configuration is invalid", func(t *testing.T, tw *twin) {
			tw.w.tFails = "nginx: [emerg] unexpected \"}\" in /etc/nginx/nginx.conf:3"
			tw.e.SetConfigInvalid(helperproto.ConfigErrSyntax)
			assert.Equal(t, helperproto.CodeConfigInvalid, tw.deploy(opA).m["code"])
		}},
		{"refusal: no space", func(t *testing.T, tw *twin) {
			tw.w.f.s.statfs = func(int) (int64, error) { return 1, nil }
			tw.e.SetFreeBytes(1)
			assert.Equal(t, helperproto.CodeNoSpace, tw.deploy(opA).m["code"])
			tw.status(opA)
		}},
		{"refusal: too many operations kept", func(t *testing.T, tw *twin) {
			old := maxNginxOps
			maxNginxOps = 1
			defer func() { maxNginxOps = old }()
			tw.e.SetMaxNginxOps(1)
			tw.deploy(opA)
			in := input(tw.w.leaf.FullchainPEM, tw.w.leaf.KeyPEM)
			a := tw.same(helperproto.SubNginxDeploy, in, tw.deployArgs(opB, in, hexOf(string(tw.w.newLeaf.FullchainPEM)))...)
			assert.Equal(t, helperproto.CodeNoSpace, a.m["code"])
			tw.status(opB)
		}},
		{"refusal: the lock is held (BUSY), status active", func(t *testing.T, tw *twin) {
			old := lockWait
			lockWait = 100 * time.Millisecond
			defer func() { lockWait = old }()
			lock, err := tw.w.f.s.nginxLock(context.Background())
			require.NoError(t, err)
			tw.e.HoldLock(true)
			assert.Equal(t, helperproto.CodeBusy, tw.deploy(opA).m["code"])
			assert.Equal(t, helperproto.CodeBusy, tw.restore(opA).m["code"])
			assert.Equal(t, true, tw.status(opA).m["active"])
			require.NoError(t, lock.Close())
			tw.e.HoldLock(false)
			assert.Equal(t, false, tw.status(opA).m["active"])
		}},
		{"refusal: the key cannot be created (IO_ERROR)", func(t *testing.T, tw *twin) {
			require.NoError(t, os.Chmod(tw.w.f.host(fidSSL), 0o555))
			t.Cleanup(func() { _ = os.Chmod(tw.w.f.host(fidSSL), 0o755) })
			tw.e.FailWriteIn(fidSSL)
			assert.Equal(t, helperproto.CodeIOError, tw.deploy(opA).m["code"])
			tw.status(opA)
		}},
		{"refusal: the certificate changes before the key is replaced", func(t *testing.T, tw *twin) {
			tw.rename = func(n int) error {
				if n == 1 {
					return os.WriteFile(tw.w.f.host(fidCrt), []byte("someone else's"), 0o644)
				}
				return nil
			}
			tw.e.InterfereAt(helperproto.StepBackup, fidCrt, []byte("someone else's"))
			assert.Equal(t, helperproto.CodeHashMismatch, tw.deploy(opA).m["code"])
			tw.status(opA)
			tw.sameFiles("")
		}},
		{"refusal: the journal cannot be written", func(t *testing.T, tw *twin) {
			tw.w.f.s.afterDeployStep = func(name string) error {
				if name == "journal prepared staged" {
					return errors.New("disk")
				}
				return nil
			}
			tw.e.FailJournalWrite(helperproto.PhasePrepared)
			assert.Equal(t, helperproto.CodeIOError, tw.deploy(opA).m["code"])
			tw.status(opA)
		}},
		{"content errors", func(t *testing.T, tw *twin) {
			good := tw.w.newInput()
			args := tw.deployArgs(opA, good, tw.w.oldSHA())
			a := tw.same(helperproto.SubNginxDeploy, good[:len(good)-10], args...)
			assert.Equal(t, helperproto.CodeContentMismatch, a.m["code"])
			for _, in := range []string{"cert", input(tw.w.newLeaf.FullchainPEM, tw.w.leaf.KeyPEM), `{"cert_pem":"a","key_pem":"b","x":"c"}`,
				`{"cert_pem":"a","cert_pem":"b"}`, input(tw.w.newLeaf.FullchainPEM, nil)} {
				a := tw.same(helperproto.SubNginxDeploy, in, tw.deployArgs(opA, in, tw.w.oldSHA())...)
				assert.Equal(t, helperproto.CodeBadContent, a.m["code"], in)
			}
			in := strings.Repeat("x", helperproto.MaxDeployInput+1)
			assert.Equal(t, helperproto.CodeTooLarge, tw.same(helperproto.SubNginxDeploy, in, tw.deployArgs(opA, in, tw.w.oldSHA())...).m["code"])
		}},
		{"argument errors past sudoers", func(t *testing.T, tw *twin) {
			in := tw.w.newInput()
			for _, args := range [][]string{
				{"--op", "0190F5A0-0000-7000-8000-0000000000D1", "--cert", fidCrt, "--key", fidKey, "--expect-cert-sha256", tw.w.oldSHA(), "--content-sha256", hexOf(in)},
				{"--op", opA, "--cert", "/etc/../shadow", "--key", fidKey, "--expect-cert-sha256", tw.w.oldSHA(), "--content-sha256", hexOf(in)},
				{"--op", opA, "--cert", fidCrt, "--key", fidCrt, "--expect-cert-sha256", tw.w.oldSHA(), "--content-sha256", hexOf(in)},
				{"--op", opA, "--cert", fidCrt, "--key", fidKey, "--expect-cert-sha256", strings.Repeat("g", 64), "--content-sha256", hexOf(in)},
			} {
				a := tw.same(helperproto.SubNginxDeploy, in, args...)
				assert.Equal(t, helperproto.CodeInvalidArgument, a.m["code"], "%v", args)
			}
			for _, sub := range []string{helperproto.SubNginxRestore, helperproto.SubNginxStatus} {
				assert.Equal(t, helperproto.CodeInvalidArgument, tw.same(sub, "", "--op", strings.Repeat("z", 36)).m["code"])
			}
		}},
		{"restored: nginx -t fails", func(t *testing.T, tw *twin) {
			tw.failTest(1)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.PhaseRestored, a.m["phase"])
			assert.Equal(t, helperproto.StepConfigTest, a.m["failed_step"])
			tw.sameFiles("old")
			tw.status(opA)
			tw.restore(opA)
		}},
		{"restored: the reload fails", func(t *testing.T, tw *twin) {
			tw.failReload(1)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.StepReload, a.m["failed_step"])
			tw.sameFiles("old")
			assert.Equal(t, tw.w.reloads, tw.e.Reloads())
		}},
		{"restored: the commit journal cannot be written", func(t *testing.T, tw *twin) {
			tw.w.f.s.afterDeployStep = func(name string) error {
				if name == "journal committed staged" {
					return errors.New("disk")
				}
				return nil
			}
			tw.e.FailJournalWrite(helperproto.PhaseCommitted)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.StepJournal, a.m["failed_step"])
			tw.sameFiles("old")
		}},
		{"restored: nginx killed during nginx -t", func(t *testing.T, tw *twin) {
			tw.w.f.s.afterDeployStep = func(name string) error {
				if name == helperproto.StepWriteCert {
					tw.killed = true
				}
				return nil
			}
			tw.e.KillNginxAt(helperproto.StepWriteCert)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.PhaseRestoreFailed, a.m["phase"])
			assert.Equal(t, helperproto.StepRollbackConfigTest, a.m["failed_step"])
			tw.status(opA)
		}},
		{"restore_failed: the rollback's nginx -t fails", func(t *testing.T, tw *twin) {
			tw.failTest(2)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.StepRollbackConfigTest, a.m["failed_step"])
			tw.status(opA)
			tw.failTest(0)
			assert.Equal(t, helperproto.PhaseRestored, tw.restore(opA).m["phase"])
		}},
		{"restore_failed: the rollback's reload fails", func(t *testing.T, tw *twin) {
			tw.failReload(2)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.StepRollbackReload, a.m["failed_step"])
			tw.status(opA)
			assert.Equal(t, helperproto.PhaseRestored, tw.restore(opA).m["phase"])
		}},
		{"restore_failed: the key cannot be restored (a mixed pair)", func(t *testing.T, tw *twin) {
			tw.failTest(1)
			tw.rename = func(n int) error {
				if n == 4 {
					return errors.New("disk")
				}
				return nil
			}
			tw.e.FailRestoreFile(fidKey)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.StepRestore, a.m["failed_step"])
			tw.sameFiles("")
			tw.status(opA)
			tw.rename = nil
			tw.e.FailRestoreFile("")
			assert.Equal(t, helperproto.PhaseRestored, tw.restore(opA).m["phase"])
			tw.sameFiles("old")
		}},
		{"restore_failed: nothing can be restored", func(t *testing.T, tw *twin) {
			tw.failTest(1)
			tw.rename = func(n int) error {
				if n == 3 {
					return errors.New("disk")
				}
				return nil
			}
			tw.e.FailRestoreFile(fidCrt)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.StepRestore, a.m["failed_step"])
			tw.sameFiles("new")
			tw.status(opA)
		}},
		{"restore_failed: the certificate is changed by someone else mid-deployment (file_changed)", func(t *testing.T, tw *twin) {
			tw.rename = func(n int) error {
				if n == 2 {
					return os.WriteFile(tw.w.f.host(fidCrt), []byte("someone else's"), 0o644)
				}
				return nil
			}
			tw.e.InterfereAt(helperproto.StepWriteKey, fidCrt, []byte("someone else's"))
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.PhaseRestoreFailed, a.m["phase"])
			assert.Equal(t, helperproto.RestoreErrFileChanged, a.m["error"])
			assert.Equal(t, helperproto.StepWriteCert, a.m["cause_step"])
			tw.sameFiles("")
			tw.status(opA)
			assert.Equal(t, helperproto.CodeHashMismatch, tw.restore(opA).m["code"])
			tw.status(opA)
		}},
		{"restore_failed: a partial rollback that failed, finished by nginx-restore", func(t *testing.T, tw *twin) {
			// Someone else changes the certificate before its rename (write_cert fails), and the
			// rollback cannot put the key back: the operation is partial, and nginx-restore later
			// restores only its own file.
			tw.rename = func(n int) error {
				switch n {
				case 2:
					return os.WriteFile(tw.w.f.host(fidCrt), []byte("someone else's"), 0o644)
				case 3:
					return errors.New("disk")
				}
				return nil
			}
			tw.e.InterfereAt(helperproto.StepWriteKey, fidCrt, []byte("someone else's"))
			tw.e.FailRestoreFile(fidKey)
			a := tw.deploy(opA)
			assert.Equal(t, helperproto.StepRestore, a.m["failed_step"])
			assert.Equal(t, helperproto.StepWriteCert, a.m["cause_step"])
			tw.status(opA)
			tw.rename = nil
			tw.e.FailRestoreFile("")
			r := tw.restore(opA)
			assert.Equal(t, helperproto.PhaseRestoreFailed, r.m["phase"])
			assert.Equal(t, helperproto.RestoreErrFileChanged, r.m["error"])
			tw.sameFiles("")
			assert.Equal(t, string(tw.w.leaf.KeyPEM), tw.w.f.read(fidKey), "its own file is back")
			tw.status(opA)
		}},
	} {
		t.Run(sc.name, func(t *testing.T) { sc.run(t, newTwin(t, true)) })
	}
}

func TestEmulatorFidelityRestoreAndSuperseded(t *testing.T) {
	t.Run("unknown operation", func(t *testing.T) {
		tw := newTwin(t, true)
		assert.Equal(t, helperproto.CodeUnknownOp, tw.restore(opA).m["code"])
		assert.Equal(t, helperproto.PhaseNone, tw.status(opA).m["phase"])
	})
	t.Run("someone else changed a file after the deployment", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		tw.put(fidCrt, []byte("someone else's"))
		assert.Equal(t, helperproto.CodeHashMismatch, tw.restore(opA).m["code"])
		tw.status(opA)
		assert.Equal(t, helperproto.CodeHashMismatch, tw.restore(opA).m["code"], "the same refusal again")
		tw.sameFiles("")
	})
	t.Run("the key changed between the restore's renames: restore_failed, not a refusal (A1-I2)", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		point := "renamed " + stagedName(opA, kindCert)
		tw.w.f.s.afterDeployStep = func(name string) error {
			if name == point {
				require.NoError(t, os.WriteFile(tw.w.f.host(fidKey), []byte("someone else's"), 0o600))
			}
			return nil
		}
		tw.e.InterfereAt(point, fidKey, []byte("someone else's"))
		a := tw.restore(opA)
		tw.w.f.s.afterDeployStep = nil
		assert.Equal(t, helperproto.PhaseRestoreFailed, a.m["phase"])
		assert.Equal(t, helperproto.RestoreErrFileChanged, a.m["error"])
		tw.status(opA)
		assert.Equal(t, helperproto.CodeHashMismatch, tw.restore(opA).m["code"], "nothing more to do: the refusal")
	})
	t.Run("the restoring journal cannot be written: nothing restored (m6)", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		tw.w.f.s.afterDeployStep = func(name string) error {
			if name == "journal restoring staged" {
				return errors.New("disk")
			}
			return nil
		}
		tw.e.FailJournalWrite(helperproto.PhaseRestoring)
		assert.Equal(t, helperproto.CodeIOError, tw.restore(opA).m["code"])
		tw.w.f.s.afterDeployStep = nil
		tw.sameFiles("new")
		tw.status(opA)
	})
	// A, B, C: only the operation that last replaced the pair's files can be restored.
	chain := func(t *testing.T) (*twin, string) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		in := input(tw.third.FullchainPEM, tw.third.KeyPEM)
		a := tw.same(helperproto.SubNginxDeploy, in, tw.deployArgs(opB, in, hexOf(string(tw.w.newLeaf.FullchainPEM)))...)
		require.Equal(t, helperproto.PhaseCommitted, a.m["phase"])
		return tw, in
	}
	t.Run("an older operation is superseded", func(t *testing.T) {
		tw, _ := chain(t)
		assert.Equal(t, helperproto.CodeSuperseded, tw.restore(opA).m["code"])
		tw.sameFiles("")
	})
	t.Run("an operation that changed nothing is passed over", func(t *testing.T) {
		tw, in := chain(t)
		third := tw.third
		a := tw.same(helperproto.SubNginxDeploy, in, tw.deployArgs(opC, in, hexOf(string(third.FullchainPEM)))...)
		assert.Equal(t, helperproto.PhaseUnchanged, a.m["phase"])
		assert.Equal(t, helperproto.CodeSuperseded, tw.restore(opA).m["code"])
		assert.Equal(t, helperproto.PhaseRestored, tw.restore(opB).m["phase"], "B is still the latest: C changed nothing")
		tw.sameFiles("")
		assert.Equal(t, 1.0, tw.same(helperproto.SubCleanup, "", "--op", opC).m["removed"])
		assert.Equal(t, helperproto.CodeSuperseded, tw.restore(opA).m["code"])
		assert.Equal(t, 1.0, tw.same(helperproto.SubCleanup, "", "--op", opB).m["removed"])
		assert.Equal(t, helperproto.CodeSuperseded, tw.restore(opA).m["code"], "after the latest is cleaned up no older one is restorable")
	})
	t.Run("an operation that took the pair record and changed nothing is passed over", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		// B is killed right after it took the pair record (its journal says prepared).
		in := input(tw.third.FullchainPEM, tw.third.KeyPEM)
		args := tw.deployArgs(opB, in, hexOf(string(tw.w.newLeaf.FullchainPEM)))
		tw.kill("pair record renamed")
		_ = tw.runHelper(helperproto.SubNginxDeploy, in, args...)
		_ = tw.runEmu(helperproto.SubNginxDeploy, in, args...)
		tw.revive()
		assert.Equal(t, helperproto.PhasePrepared, tw.status(opB).m["phase"])
		assert.Equal(t, helperproto.PhasePrepared, tw.restore(opB).m["phase"], "nothing to restore")
		// Removing B hands the record back to A: A is restorable, and stays so.
		assert.Equal(t, 1.0, tw.same(helperproto.SubCleanup, "", "--op", opB).m["removed"])
		assert.Equal(t, helperproto.PhaseRestored, tw.restore(opA).m["phase"])
		tw.sameFiles("old")
	})
	t.Run("a no-op that took the record does not make the one before it unrestorable", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		in := input(tw.third.FullchainPEM, tw.third.KeyPEM)
		args := tw.deployArgs(opB, in, hexOf(string(tw.w.newLeaf.FullchainPEM)))
		tw.kill("pair record renamed")
		_ = tw.runHelper(helperproto.SubNginxDeploy, in, args...)
		_ = tw.runEmu(helperproto.SubNginxDeploy, in, args...)
		tw.revive()
		assert.Equal(t, helperproto.PhaseRestored, tw.restore(opA).m["phase"], "A is still the operation that last replaced the files")
		tw.sameFiles("old")
	})
	t.Run("the latest one is restorable", func(t *testing.T) {
		tw, _ := chain(t)
		assert.Equal(t, helperproto.PhaseRestored, tw.restore(opB).m["phase"])
		tw.sameFiles("")
	})
	t.Run("a re-sent interrupted deployment that a later one superseded", func(t *testing.T) {
		tw := newTwin(t, true)
		in := tw.w.newInput()
		argsA := tw.deployArgs(opA, in, tw.w.oldSHA())
		tw.kill("journal writing renamed")
		_ = tw.runHelper(helperproto.SubNginxDeploy, in, argsA...)
		_ = tw.runEmu(helperproto.SubNginxDeploy, in, argsA...)
		tw.revive()
		assert.Equal(t, helperproto.PhaseWriting, tw.status(opA).m["phase"])
		// A1 m1: B is refused while A, the pair's latest, is interrupted.
		inB := input(tw.third.FullchainPEM, tw.third.KeyPEM)
		a := tw.same(helperproto.SubNginxDeploy, inB, tw.deployArgs(opB, inB, tw.w.oldSHA())...)
		assert.Equal(t, helperproto.CodeRecoveryPending, a.m["code"])
		assert.Equal(t, helperproto.PhaseRestored, tw.restore(opA).m["phase"])
		// B replaces the pair and commits; A (restored) is now superseded.
		a = tw.same(helperproto.SubNginxDeploy, inB, tw.deployArgs(opB, inB, tw.w.oldSHA())...)
		assert.Equal(t, helperproto.PhaseCommitted, a.m["phase"])
		assert.Equal(t, helperproto.PhaseRestored, tw.same(helperproto.SubNginxDeploy, in, argsA...).m["phase"])
		tw.restore(opA)
		assert.Equal(t, 1.0, tw.same(helperproto.SubCleanup, "", "--op", opA).m["removed"], "a superseded operation is not kept for recovery")
	})
	t.Run("a mixed pair left by a kill: nginx -T fails, a new deployment is refused, nginx-restore repairs it", func(t *testing.T) {
		tw := newTwin(t, true)
		in := tw.w.newInput()
		argsA := tw.deployArgs(opA, in, tw.w.oldSHA())
		tw.kill(helperproto.StepWriteKey)
		_ = tw.runHelper(helperproto.SubNginxDeploy, in, argsA...)
		_ = tw.runEmu(helperproto.SubNginxDeploy, in, argsA...)
		tw.revive()
		d := tw.dump()
		assert.Equal(t, false, d.m["config_valid"])
		assert.Equal(t, helperproto.ConfigErrKeyMismatch, d.m["config_error"])
		assert.Equal(t, helperproto.ConfigErrKeyMismatch, tw.same(helperproto.SubNginxTest, "").m["error"])
		inB := input(tw.third.FullchainPEM, tw.third.KeyPEM)
		a := tw.same(helperproto.SubNginxDeploy, inB, tw.deployArgs(opB, inB, tw.w.oldSHA())...)
		assert.Equal(t, helperproto.CodeConfigInvalid, a.m["code"])
		assert.Equal(t, helperproto.PhaseNone, tw.status(opB).m["phase"])
		assert.Equal(t, helperproto.PhaseWriting, tw.status(opA).m["phase"])
		r := tw.restore(opA)
		assert.Equal(t, helperproto.PhaseRestored, r.m["phase"], "nginx-restore does not need nginx -T")
		tw.sameFiles("old")
		assert.Equal(t, true, tw.dump().m["config_valid"])
		assert.Equal(t, true, tw.same(helperproto.SubNginxTest, "").m["valid"])
		assert.Equal(t, helperproto.PhaseRestored, tw.same(helperproto.SubNginxDeploy, in, argsA...).m["phase"], "a re-send answers from the journal")
		tw.status(opA)
	})
	t.Run("a re-sent deployment after a kill at write_key rolls the mixed pair back itself", func(t *testing.T) {
		tw := newTwin(t, true)
		in := tw.w.newInput()
		argsA := tw.deployArgs(opA, in, tw.w.oldSHA())
		tw.kill(helperproto.StepWriteKey)
		_ = tw.runHelper(helperproto.SubNginxDeploy, in, argsA...)
		_ = tw.runEmu(helperproto.SubNginxDeploy, in, argsA...)
		tw.revive()
		a := tw.same(helperproto.SubNginxDeploy, in, argsA...)
		assert.Equal(t, helperproto.PhaseRestored, a.m["phase"])
		tw.sameFiles("old")
		assert.Equal(t, true, tw.dump().m["config_valid"])
	})
	t.Run("cleanup while the lock is held", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		old := lockWait
		lockWait = 100 * time.Millisecond
		defer func() { lockWait = old }()
		lock, err := tw.w.f.s.nginxLock(context.Background())
		require.NoError(t, err)
		tw.e.HoldLock(true)
		assert.Equal(t, helperproto.CodeBusy, tw.same(helperproto.SubCleanup, "", "--op", opA).m["code"])
		require.NoError(t, lock.Close())
		tw.e.HoldLock(false)
		assert.Equal(t, 1.0, tw.same(helperproto.SubCleanup, "", "--op", opA).m["removed"])
	})
	t.Run("cleanup", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.kill(helperproto.StepWriteKey)
		in := tw.w.newInput()
		args := tw.deployArgs(opA, in, tw.w.oldSHA())
		_ = tw.runHelper(helperproto.SubNginxDeploy, in, args...)
		_ = tw.runEmu(helperproto.SubNginxDeploy, in, args...)
		tw.revive()
		assert.Equal(t, helperproto.CodeBusy, tw.same(helperproto.SubCleanup, "", "--op", opA).m["code"], "an interrupted operation is kept")
		tw.restore(opA)
		assert.Equal(t, 1.0, tw.same(helperproto.SubCleanup, "", "--op", opA).m["removed"])
		assert.Equal(t, 0.0, tw.same(helperproto.SubCleanup, "", "--op", opA).m["removed"])
		assert.Equal(t, helperproto.PhaseNone, tw.status(opA).m["phase"])
	})
}

// The helper is killed at every point of a deployment and of a rollback: what it leaves (status,
// the files, what nginx-restore then answers) is the same in the emulator.
// The rollback guard (protocol 10, R48): the same refusals, phases and steps on both, and neither
// puts the forbidden pair back.
func TestEmulatorFidelityRollbackGuard(t *testing.T) {
	deployGuarded := func(tw *twin, op string, spki, leaf []string) answer {
		in := guardedInput(tw.w.newLeaf.FullchainPEM, tw.w.newLeaf.KeyPEM, spki, leaf)
		return tw.same(helperproto.SubNginxDeploy, in, tw.deployArgs(op, in, tw.w.oldSHA())...)
	}
	restoreGuarded := func(tw *twin, op, stdin string) answer {
		return tw.same(helperproto.SubNginxRestore, stdin, "--op", op)
	}
	t.Run("the transaction's own rollback", func(t *testing.T) {
		for name, fail := range map[string]func(tw *twin){"config test": func(tw *twin) { tw.failTest(1) }, "reload": func(tw *twin) { tw.failReload(1) }} {
			t.Run(name, func(t *testing.T) {
				tw := newTwin(t, true)
				fail(tw)
				a := deployGuarded(tw, opA, []string{spkiOf(t, tw.w.leaf.Cert)}, nil)
				assert.Equal(t, helperproto.PhaseRestoreForbidden, a.m["phase"])
				tw.status(opA)
				restoreGuarded(tw, opA, "")
				restoreGuarded(tw, opA, restoreInput([]string{spkiOf(t, tw.w.leaf.Cert)}, nil))
				tw.sameFiles("new")
			})
		}
	})
	t.Run("nginx-restore of a committed operation", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		a := restoreGuarded(tw, opA, restoreInput(nil, []string{leafOf(tw.w.leaf.Cert)}))
		assert.Equal(t, helperproto.PhaseRestoreForbidden, a.m["phase"])
		tw.status(opA)
		tw.sameFiles("new")
	})
	t.Run("an unrelated list restores as before", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		a := restoreGuarded(tw, opA, restoreInput([]string{spkiOf(t, tw.third.Cert)}, nil))
		assert.Equal(t, helperproto.PhaseRestored, a.m["phase"])
		tw.sameFiles("old")
	})
	t.Run("an interrupted operation re-sent with the list", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.kill(helperproto.StepWriteCert)
		in := tw.w.newInput()
		tw.runHelper(helperproto.SubNginxDeploy, in, tw.deployArgs(opA, in, tw.w.oldSHA())...)
		assert.True(t, tw.runEmu(helperproto.SubNginxDeploy, in, tw.deployArgs(opA, in, tw.w.oldSHA())...).killed)
		tw.revive()
		a := deployGuarded(tw, opA, []string{spkiOf(t, tw.w.leaf.Cert)}, nil)
		assert.Equal(t, helperproto.PhaseRestoreForbidden, a.m["phase"])
		tw.sameFiles("new")
	})
	t.Run("refusals", func(t *testing.T) {
		tw := newTwin(t, true)
		a := deployGuarded(tw, opA, []string{"absent"}, nil)
		assert.Equal(t, helperproto.CodeBadContent, a.m["code"])
		tw.deploy(opA)
		for _, bad := range []string{"nope", `{"forbidden_spki_sha256":[]}`, `{"forbidden_spki_sha256":["ab"],"forbidden_leaf_sha256":[]}`} {
			assert.Equal(t, helperproto.CodeInvalidArgument, restoreGuarded(tw, opA, bad).m["code"], bad)
		}
		tw.sameFiles("new")
	})
}

func TestEmulatorFidelityKillPoints(t *testing.T) {
	keyFile, certFile := stagedName(opA, kindKey), stagedName(opA, kindCert)
	deployPoints := []string{
		"journal prepared staged", "journal prepared renamed", "backup cert", "backup key", "backup", "pair record staged", "pair record renamed",
		"journal writing staged", "journal writing renamed",
		"stage " + keyFile, "staged " + keyFile, "renamed " + keyFile, "write_key",
		"stage " + certFile, "staged " + certFile, "renamed " + certFile, "write_cert",
		"config_test", "reload", "journal committed staged", "journal committed renamed",
	}
	for _, p := range deployPoints {
		t.Run("deploy killed at "+p, func(t *testing.T) {
			tw := newTwin(t, true)
			tw.kill(p)
			in := tw.w.newInput()
			args := tw.deployArgs(opA, in, tw.w.oldSHA())
			h := tw.runHelper(helperproto.SubNginxDeploy, in, args...)
			e := tw.runEmu(helperproto.SubNginxDeploy, in, args...)
			assert.Equal(t, helperproto.ExitFailed, h.exit, "the test kill answers IO_ERROR; a real kill prints nothing")
			assert.True(t, e.killed, "the emulated helper printed nothing")
			tw.revive()
			tw.sameFiles("")
			st := tw.status(opA)
			tw.same(helperproto.SubNginxTest, "") // a mixed pair: key_mismatch, in both
			tw.same(helperproto.SubNginxDump, "")
			tw.restore(opA)
			tw.sameFiles("old")
			tw.status(opA)
			_ = st
		})
	}
	// After a kill the same deployment sent again.
	for _, p := range []string{"backup", "journal writing renamed", "renamed " + keyFile, "write_key", "write_cert", "config_test", "reload"} {
		t.Run("deploy killed at "+p+", sent again", func(t *testing.T) {
			tw := newTwin(t, true)
			tw.kill(p)
			in := tw.w.newInput()
			args := tw.deployArgs(opA, in, tw.w.oldSHA())
			_ = tw.runHelper(helperproto.SubNginxDeploy, in, args...)
			_ = tw.runEmu(helperproto.SubNginxDeploy, in, args...)
			tw.revive()
			tw.same(helperproto.SubNginxDeploy, in, args...)
			tw.sameFiles("")
			tw.status(opA)
		})
	}
	for _, p := range []string{"journal restoring staged", "journal restoring renamed", "stage " + certFile, "renamed " + certFile, "renamed " + keyFile,
		"restore", "rollback_config_test", "rollback_reload", "journal restored staged", "journal restored renamed"} {
		t.Run("restore killed at "+p, func(t *testing.T) {
			tw := newTwin(t, true)
			tw.deploy(opA)
			tw.kill(p)
			_ = tw.runHelper(helperproto.SubNginxRestore, "", "--op", opA)
			e := tw.runEmu(helperproto.SubNginxRestore, "", "--op", opA)
			assert.True(t, e.killed)
			tw.revive()
			tw.sameFiles("")
			tw.status(opA)
			tw.restore(opA)
			tw.sameFiles("old")
			tw.status(opA)
		})
	}
}

// The helper is killed inside the rollback of its own failed deployment: status, a re-sent deployment
// and nginx-restore then answer the same.
func TestEmulatorFidelityKillInsideOwnRollback(t *testing.T) {
	for _, p := range []string{"journal restoring staged", "journal restoring renamed", "stage " + stagedName(opA, kindCert), "renamed " + stagedName(opA, kindCert),
		"renamed " + stagedName(opA, kindKey), "restore", "rollback_config_test", "rollback_reload", "journal restored staged", "journal restored renamed"} {
		for _, resendFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("killed at %s, resend first %v", p, resendFirst), func(t *testing.T) {
				tw := newTwin(t, true)
				tw.failTest(1) // the deployment fails at nginx -t and rolls back
				tw.kill(p)
				in := tw.w.newInput()
				args := tw.deployArgs(opA, in, tw.w.oldSHA())
				h := tw.runHelper(helperproto.SubNginxDeploy, in, args...)
				e := tw.runEmu(helperproto.SubNginxDeploy, in, args...)
				assert.Equal(t, helperproto.ExitFailed, h.exit)
				assert.True(t, e.killed)
				tw.revive()
				tw.sameFiles("")
				tw.status(opA)
				if resendFirst {
					tw.same(helperproto.SubNginxDeploy, in, args...)
					tw.sameFiles("")
					tw.status(opA)
				}
				tw.restore(opA)
				tw.sameFiles("old")
				tw.status(opA)
				tw.same(helperproto.SubNginxDeploy, in, args...)
			})
		}
	}
}

// tls-probe: the helper connects to a real TLS server; the emulator answers from its host.
func TestEmulatorFidelityProbe(t *testing.T) {
	tw := newTwin(t, true)
	sni := make(chan string, 8)
	port := startTLS(t, tw.w.leaf, sni)
	var n int
	_, err := fmt.Sscanf(port, "%d", &n)
	require.NoError(t, err)
	tw.e.AddSite(linuxsshtest.NginxSite{Names: []string{"probe.example.test"}, Port: n, Default: true, CertPath: "/etc/nginx/ssl/probe.crt", KeyPath: "/etc/nginx/ssl/probe.key"},
		tw.w.leaf.FullchainPEM, tw.w.leaf.KeyPEM)
	probe := func(addr, port, sni, kt string) answer {
		return tw.same(helperproto.SubTLSProbe, "", "--addr", addr, "--port", port, "--sni", sni, "--key-type", kt)
	}
	a := probe("127.0.0.1", port, "probe.example.test", "any")
	assert.Equal(t, 2.0, a.m["chain_length"])
	probe("127.0.0.1", port, helperproto.NoSNI, "any")
	probe("127.0.0.1", port, "probe.example.test", "ecdsa")
	assert.Equal(t, helperproto.CodeProbeFailed, probe("127.0.0.1", port, "probe.example.test", "rsa").m["code"], "no RSA certificate")
	assert.Equal(t, helperproto.CodeProbeFailed, probe("127.0.0.1", "1", "probe.example.test", "any").m["code"], "nothing listens")
	assert.Equal(t, helperproto.CodeInvalidArgument, probe("localhost", port, "a.example.test", "any").m["code"])
	assert.Equal(t, helperproto.CodeInvalidArgument, probe("127.0.0.1", "08", "a.example.test", "any").m["code"])
	assert.Equal(t, helperproto.CodeInvalidArgument, probe("127.0.0.1", port, "A.example.test", "any").m["code"])
	assert.Equal(t, helperproto.CodeInvalidArgument, probe("127.0.0.1", port, "a.example.test", "dsa").m["code"])
}

// Without root the helper refuses every privileged subcommand before anything else.
func TestEmulatorFidelityNotRoot(t *testing.T) {
	tw := newTwin(t, true)
	tw.w.f.s.euid = func() int { return 1000 }
	for _, sub := range []string{helperproto.SubNginxDump, helperproto.SubNginxTest, helperproto.SubNginxDeploy, helperproto.SubNginxRestore, helperproto.SubNginxStatus} {
		h := normalize(sub, tw.runHelper(sub, ""), true)
		line := "/usr/local/libexec/alice-helper " + sub // no sudo
		r := tw.h(line, nil)
		var m map[string]any
		require.NoError(t, json.Unmarshal(r.Stdout, &m))
		delete(m, "message")
		assert.Equal(t, h.exit, r.Exit, sub)
		assert.Equal(t, h.m, m, sub)
	}
}

// AUD-05: nginx-fence on both, in every state it can meet.
func TestEmulatorFidelityFence(t *testing.T) {
	fence := func(tw *twin, op string) answer { return tw.same(helperproto.SubNginxFence, "", "--op", op) }
	t.Run("no journal: fenced, deploy refused, idempotent", func(t *testing.T) {
		tw := newTwin(t, true)
		assert.Equal(t, helperproto.PhaseFenced, fence(tw, opA).m["phase"])
		assert.Equal(t, helperproto.CodeFenced, tw.deploy(opA).m["code"])
		tw.sameFiles("old")
		tw.status(opA)
		assert.Equal(t, helperproto.PhaseFenced, fence(tw, opA).m["phase"])
		tw.restore(opA)
		assert.Equal(t, 0.0, tw.same(helperproto.SubCleanup, "", "--op", opA).m["removed"])
		assert.Equal(t, helperproto.PhaseCommitted, tw.deploy(opB).m["phase"])
	})
	t.Run("committed: answered, nothing changed", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opA)
		assert.Equal(t, helperproto.PhaseCommitted, fence(tw, opA).m["phase"])
		assert.Equal(t, helperproto.PhaseRestored, tw.restore(opA).m["phase"])
	})
	t.Run("prepared: fenced, the record handed back", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.deploy(opB)
		tw.kill("pair record renamed")
		in := input(tw.w.leaf.FullchainPEM, tw.w.leaf.KeyPEM)
		args := tw.deployArgs(opA, in, hexOf(string(tw.w.newLeaf.FullchainPEM)))
		_ = tw.runHelper(helperproto.SubNginxDeploy, in, args...)
		_ = tw.runEmu(helperproto.SubNginxDeploy, in, args...)
		tw.revive()
		assert.Equal(t, helperproto.PhasePrepared, tw.status(opA).m["phase"])
		assert.Equal(t, helperproto.PhaseFenced, fence(tw, opA).m["phase"])
		assert.Equal(t, helperproto.CodeFenced, tw.same(helperproto.SubNginxDeploy, in, args...).m["code"])
		assert.Equal(t, helperproto.PhaseRestored, tw.restore(opB).m["phase"], "the tombstone supersedes nothing")
	})
	t.Run("the lock is held: BUSY", func(t *testing.T) {
		tw := newTwin(t, true)
		old := lockWait
		lockWait = 20 * time.Millisecond
		defer func() { lockWait = old }()
		lock, err := tw.w.f.s.nginxLock(context.Background())
		require.NoError(t, err)
		tw.e.HoldLock(true)
		assert.Equal(t, helperproto.CodeBusy, fence(tw, opA).m["code"])
		_ = lock.Close()
		tw.e.HoldLock(false)
	})
	t.Run("tombstones do not count against the backup cap; fences have their own (fix round 1)", func(t *testing.T) {
		tw := newTwin(t, true)
		oldOps, oldFences := maxNginxOps, maxNginxFences
		maxNginxOps, maxNginxFences = 1, 2
		defer func() { maxNginxOps, maxNginxFences = oldOps, oldFences }()
		tw.e.SetMaxNginxOps(1)
		tw.e.SetMaxNginxFences(2)
		fence(tw, opA)
		fence(tw, opB)
		const opC, opD = "0190f5a0-0000-7000-8000-0000000000d3", "0190f5a0-0000-7000-8000-0000000000d4"
		assert.Equal(t, helperproto.PhaseCommitted, tw.deploy(opC).m["phase"])
		assert.Equal(t, helperproto.CodeNoSpace, fence(tw, opD).m["code"])
		assert.Equal(t, helperproto.PhaseFenced, fence(tw, opA).m["phase"])
	})
	t.Run("RECOVERY_PENDING names the blocking operation (fix round 1)", func(t *testing.T) {
		tw := newTwin(t, true)
		tw.kill(helperproto.StepReload)
		in := tw.w.newInput()
		args := tw.deployArgs(opA, in, tw.w.oldSHA())
		_ = tw.runHelper(helperproto.SubNginxDeploy, in, args...)
		_ = tw.runEmu(helperproto.SubNginxDeploy, in, args...)
		tw.revive()
		inB := input(tw.third.FullchainPEM, tw.third.KeyPEM)
		a := tw.same(helperproto.SubNginxDeploy, inB, tw.deployArgs(opB, inB, hexOf(string(tw.w.newLeaf.FullchainPEM)))...)
		assert.Equal(t, opA, a.m["pending_op"])
	})
	for _, p := range []string{"journal fenced staged", "journal fenced renamed"} {
		t.Run("killed at "+p, func(t *testing.T) {
			tw := newTwin(t, true)
			tw.kill(p)
			_ = tw.runHelper(helperproto.SubNginxFence, "", "--op", opA)
			_ = tw.runEmu(helperproto.SubNginxFence, "", "--op", opA)
			tw.revive()
			tw.status(opA)
			assert.Equal(t, helperproto.PhaseFenced, fence(tw, opA).m["phase"])
		})
	}
}

// AUD-03, AUD-22: authkeys-list on both, for the same accounts and files: users, cleaned homes,
// paths, hashes, inline content, accounts, accounts_complete, unlisted, truncated and warnings are
// equal. The helper side keeps the base fixture's root, daemon, alice-svc, deploy and nobody (the
// emulator's own world) and adds the same entries as the emulator, with files only in homes of
// the test's uid (run as a normal user, root's and alice-svc's files would be listed
// unsupported). The emulator diverges on purpose in one respect: it has no shells, so it reports
// a bad home for every user it has, where the helper reports one only for an account its rule
// would scan; every entry here is such an account (a login shell, uid >= 1000). Users are
// compared by name, not in uid order: the emulator's deploy has uid 1001 whatever the test's uid.
func TestEmulatorFidelityAuthKeysList(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	e := linuxsshtest.NewEmulator()
	e.SetSSHD(globalSSHD)
	var passwd strings.Builder
	for _, l := range strings.Split(f.read("/etc/passwd"), "\n") {
		for _, keep := range []string{"root:", "daemon:", "alice-svc:", "deploy:", "nobody:"} {
			if strings.HasPrefix(l, keep) {
				passwd.WriteString(l + "\n")
			}
		}
	}
	for _, a := range []struct {
		name string
		uid  int
		home string
	}{
		{"john.doe", f.uid, "/home/john.doe"}, {"Deploy2", f.uid, "/home/Deploy2"}, {"svc$", f.uid, "/home/svc"},
		{"trail", f.uid, "/home/trail/"}, {"bad name", 1009, "/home/bad"}, {"dotdot", 1010, "/home/x/../dotdot"},
	} {
		fmt.Fprintf(&passwd, "%s:x:%d:%d::%s:/bin/bash\n", a.name, a.uid, a.uid, a.home)
		e.AddUser(a.name, a.uid, a.home)
	}
	f.write("/etc/passwd", passwd.String(), 0o644)
	for _, h := range []string{"/home/deploy", "/home/john.doe", "/home/Deploy2", "/home/svc", "/home/trail"} {
		f.mkdir(h+"/.ssh", 0o700)
		content := "ssh-ed25519 AAAA " + h + "\n"
		f.write(h+"/.ssh/authorized_keys", content, 0o600)
		e.SetFile(h+"/.ssh/authorized_keys", []byte(content))
	}
	code, helper := f.run("authkeys-list")
	require.Equal(t, 0, code, "%v", helper)
	r := e.Handler()("sudo -n "+helperproto.HelperPath+" authkeys-list", nil)
	require.Zero(t, r.Exit)
	var emu map[string]any
	require.NoError(t, json.Unmarshal(r.Stdout, &emu))

	shape := func(m map[string]any) map[string]any {
		users := map[string]any{}
		for _, u := range asList(m["users"]) {
			var files []any
			for _, fi := range asList(u["files"]) {
				files = append(files, map[string]any{"path": fi["path"], "exists": fi["exists"], "sha256": fi["sha256"],
					"inline": fi["inline"], "content_b64": fi["content_b64"]})
			}
			users[u["user"].(string)] = map[string]any{"home": u["home"], "files": files}
		}
		return map[string]any{"users": users, "accounts": m["accounts"], "accounts_complete": m["accounts_complete"],
			"unlisted": m["unlisted"], "truncated": m["truncated"], "warnings": m["warnings"]}
	}
	want := shape(helper)
	assert.Equal(t, want, shape(emu))
	// The scenario is what it claims: every new kind of entry is there.
	assert.Len(t, want["users"], 7, "root, alice-svc, deploy, john.doe, Deploy2, svc$, trail")
	assert.Equal(t, []any{map[string]any{"uid": 1009.0, "reason": "name"}, map[string]any{"uid": 1010.0, "reason": "home"}}, want["unlisted"])
	assert.Equal(t, "/home/trail", want["users"].(map[string]any)["trail"].(map[string]any)["home"])
}

// S8, M3: a listing over MaxListOutput is cut the same way on both sides (helperproto.FitList):
// the same users are left out, the first of them is named, and the account list is incomplete.
func TestEmulatorFidelityAuthKeysListTruncated(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	e := linuxsshtest.NewEmulator()
	f.global = longPatterns(10)
	e.SetSSHD(f.global)
	var passwd strings.Builder
	for _, l := range strings.Split(f.read("/etc/passwd"), "\n") {
		for _, keep := range []string{"root:", "daemon:", "alice-svc:", "deploy:", "nobody:"} {
			if strings.HasPrefix(l, keep) {
				passwd.WriteString(l + "\n")
			}
		}
	}
	for i := 0; i < 195; i++ {
		fmt.Fprintf(&passwd, "u%d:x:%d:%d::/home/deploy:/bin/bash\n", i, 3000+i, 3000+i)
		e.AddUser(fmt.Sprintf("u%d", i), 3000+i, "/home/deploy")
	}
	f.write("/etc/passwd", passwd.String(), 0o644)
	_, helper := f.run("authkeys-list")
	var emu map[string]any
	require.NoError(t, json.Unmarshal(e.Handler()("sudo -n "+helperproto.HelperPath+" authkeys-list", nil).Stdout, &emu))
	names := func(m map[string]any) []string {
		var out []string
		for _, u := range asList(m["users"]) {
			out = append(out, u["user"].(string))
		}
		return out
	}
	require.Equal(t, true, helper["truncated"])
	for _, k := range []string{"truncated", "truncated_from_uid", "accounts_complete", "accounts", "unlisted"} {
		assert.Equal(t, helper[k], emu[k], k)
	}
	assert.ElementsMatch(t, names(helper), names(emu))
}
