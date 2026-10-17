//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/haproxyconf"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/testutil/pki"
)

// The HAProxy fidelity test: one scenario runs against the real helper (a temporary tree and a fake
// haproxy program that answers from a table written here, independently of the emulator) and
// against the emulated HAProxy of the fake SSH server, and the answers are compared: exit status,
// error code, config_* fields, servers (with section; file and line normalized: the helper's
// fixture and the emulator write the same haproxy.cfg, but lines are not the point), listens,
// pairs, files (owner and group normalized), warnings and writable. The helper is the specification.

const (
	haCertDir = "/etc/haproxy/certs"
)

// haList is the crt-list of the SNI sites of one frontend on one port (the emulator's naming, fixed here).
func haList(frontend string, port int) string {
	return "/etc/haproxy/emu-" + frontend + "-" + strconv.Itoa(port) + ".crtlist"
}

type haSite struct {
	linuxsshtest.HAProxySite
	leaf pki.Leaf
}

type haproxyTwin struct {
	t     *testing.T
	f     *fixture
	e     *linuxsshtest.Emulator
	sites []haSite
}

// haConf renders the sites as haproxy.cfg and the crt-lists by path (written here, not taken from
// the emulator): a frontend per distinct name, a "bind ... crt" per site without SNI names and one
// "bind ... crt-list" per frontend and port that has sites with SNI names.
func haConf(sites []haSite) (cfg string, lists map[string]string) {
	var b strings.Builder
	lists = map[string]string{}
	b.WriteString("global\n    log /dev/log local0\ndefaults\n    mode http\n")
	var order []string
	for _, s := range sites {
		if !contains(order, s.Frontend) {
			order = append(order, s.Frontend)
		}
	}
	for _, fe := range order {
		b.WriteString("frontend " + fe + "\n")
		for _, s := range sites {
			if s.Frontend != fe {
				continue
			}
			if len(s.SNI) == 0 {
				b.WriteString("    bind :" + strconv.Itoa(s.Port) + " ssl crt " + s.CertPath + "\n")
				continue
			}
			if _, bound := lists[haList(fe, s.Port)]; !bound {
				b.WriteString("    bind :" + strconv.Itoa(s.Port) + " ssl crt-list " + haList(fe, s.Port) + "\n")
			}
			lists[haList(fe, s.Port)] += s.CertPath + " " + strings.Join(s.SNI, " ") + "\n"
		}
	}
	return b.String(), lists
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func newHAProxyTwin(t *testing.T, installed bool, sites []haSite) *haproxyTwin {
	t.Helper()
	f := newFixture(t)
	for _, d := range []string{"/etc/haproxy", haCertDir} {
		f.mkdir(d, 0o755)
	}
	e := linuxsshtest.NewEmulator()
	tw := &haproxyTwin{t: t, f: f, e: e, sites: sites}
	if !installed {
		return tw // the fixture's default: the program is missing
	}
	e.EnableHAProxy("2.6.12")
	f.s.runHAProxy = func(_ context.Context, args ...string) ([]byte, []byte, error) {
		switch strings.Join(args, " ") {
		case "-v":
			return []byte("HAProxy version 2.6.12 2025/10/03 - https://haproxy.org/\n"), nil, nil
		case "-c -f /etc/haproxy/haproxy.cfg":
			return nil, []byte("Configuration file is valid\n"), nil
		}
		return nil, nil, errors.New("unexpected arguments")
	}
	cfg, lists := haConf(sites)
	f.write(haproxyConfPath, cfg, 0o644)
	for p, text := range lists {
		f.write(p, text, 0o644)
	}
	for _, s := range sites {
		if s.KeyBeside {
			f.write(s.CertPath, string(s.leaf.FullchainPEM), 0o644)
			f.write(s.CertPath+".key", string(s.leaf.KeyPEM), 0o600)
		} else {
			f.write(s.CertPath, string(s.leaf.FullchainPEM)+string(s.leaf.KeyPEM), 0o600)
		}
		e.AddHAProxySite(s.HAProxySite, s.leaf.FullchainPEM, s.leaf.KeyPEM)
	}
	return tw
}

func (tw *haproxyTwin) dump() (helper, emu answer) {
	tw.t.Helper()
	code, m := tw.f.run(helperproto.SubHAProxyDump)
	helper = normalize(helperproto.SubHAProxyDump, answer{exit: code, m: m}, true)
	r := tw.e.Handler()("sudo -n "+helperproto.HelperPath+" "+helperproto.SubHAProxyDump, nil)
	var em map[string]any
	if len(r.Stdout) > 0 {
		require.NoError(tw.t, json.Unmarshal(r.Stdout, &em), string(r.Stdout))
	}
	emu = normalize(helperproto.SubHAProxyDump, answer{exit: r.Exit, m: em}, false)
	return helper, emu
}

// chmod changes a file on both hosts.
func (tw *haproxyTwin) chmod(guest string, mode os.FileMode) {
	tw.t.Helper()
	require.NoError(tw.t, os.Chmod(tw.f.host(guest), mode))
	tw.e.SetNginxFileMode(guest, "root", "root", uint32(mode))
}

// setConfig replaces haproxy.cfg on both hosts.
func (tw *haproxyTwin) setConfig(text string) {
	tw.t.Helper()
	tw.f.write(haproxyConfPath, text, 0o644)
	tw.e.SetHAProxyConfig(text)
}

// putFile creates a file on both hosts.
func (tw *haproxyTwin) putFile(guest, content string, mode os.FileMode) {
	tw.t.Helper()
	tw.f.write(guest, content, mode)
	tw.e.SetHAProxyFile(guest, []byte(content))
	tw.e.SetNginxFileMode(guest, "root", "root", uint32(mode))
}

func TestHAProxyEmulatorFidelity(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the scenarios use the permission bits of an unprivileged user")
	}
	ca := pki.NewCA("Fidelity HAProxy", pki.ECDSA256, testNow)
	www := ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	api := ca.Issue(pki.Opts{CommonName: "api.example.test"}, testNow)
	wwwSite := haSite{linuxsshtest.HAProxySite{Frontend: "fe_www", Port: 9443, CertPath: haCertDir + "/www.pem"}, www}
	besideSite := haSite{linuxsshtest.HAProxySite{Frontend: "fe_www", Port: 9444, CertPath: haCertDir + "/blog.pem", KeyBeside: true}, www}
	api2Site := haSite{linuxsshtest.HAProxySite{Frontend: "fe_api2", Port: 9446, CertPath: haCertDir + "/api2.pem",
		SNI: []string{"api2.example.test"}}, www}
	api3Site := haSite{linuxsshtest.HAProxySite{Frontend: "fe_api", Port: 9447, CertPath: haCertDir + "/api3.pem",
		SNI: []string{"api3.example.test"}}, www}
	apiSite := haSite{linuxsshtest.HAProxySite{Frontend: "fe_api", Port: 9445, CertPath: haCertDir + "/api.pem",
		SNI: []string{"api.example.test", "alt.example.test"}}, api}

	type scenario struct {
		name      string
		installed bool
		sites     []haSite
		prep      func(tw *haproxyTwin)
		check     func(t *testing.T, m map[string]any, exit int)
	}
	field := func(want map[string]any) func(*testing.T, map[string]any, int) {
		return func(t *testing.T, m map[string]any, _ int) {
			for k, v := range want {
				assert.Equal(t, v, m[k], k)
			}
		}
	}
	scenarios := []scenario{
		{name: "not installed", installed: false, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, helperproto.ExitPrecondition, exit)
			assert.Equal(t, helperproto.CodeSoftwareNotFound, m["code"])
		}},
		{name: "two frontends, a file and a crt-list", installed: true, sites: []haSite{wwwSite, apiSite}, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, 0, exit)
			assert.Equal(t, true, m["config_valid"])
			servers := asList(m["servers"])
			require.Len(t, servers, 2)
			assert.Equal(t, "fe_www", servers[0]["section"])
			assert.Equal(t, "fe_api", servers[1]["section"])
			assert.Equal(t, []any{"api.example.test", "alt.example.test"}, servers[1]["names"])
			assert.Len(t, m["files"], 4)
			assert.Equal(t, []any{}, m["warnings"])
		}},
		{name: "two frontends with SNI sites on different ports", installed: true, sites: []haSite{apiSite, api3Site, api2Site}, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, 0, exit)
			servers := asList(m["servers"])
			require.Len(t, servers, 3)
			for i, want := range []struct {
				section, name string
				port          float64
			}{{"fe_api", "api.example.test", 9445}, {"fe_api", "api3.example.test", 9447}, {"fe_api2", "api2.example.test", 9446}} {
				assert.Equal(t, want.section, servers[i]["section"])
				assert.Equal(t, want.name, servers[i]["names"].([]any)[0])
				assert.Len(t, serverPairs(servers[i]), 1, "only its own certificate")
				assert.Equal(t, want.port, asList(servers[i]["listens"])[0]["port"])
			}
		}},
		{name: "writable haproxy.cfg", installed: true, sites: []haSite{wwwSite, apiSite}, prep: func(tw *haproxyTwin) {
			tw.chmod(haproxyConfPath, 0o666)
		}, check: func(t *testing.T, m map[string]any, _ int) {
			assert.Equal(t, []any{haproxyConfPath}, m["writable"])
			assert.Equal(t, []any{helperproto.WarnConfigFileWritable}, m["warnings"])
			assert.Empty(t, m["files"], "nothing the configuration names is opened")
		}},
		{name: "missing crt-list in an active region", installed: true, prep: func(tw *haproxyTwin) {
			tw.setConfig("frontend f\n    bind :9443 ssl crt-list /etc/haproxy/gone.lst\n")
		}, check: field(map[string]any{"config_valid": false, "config_error": helperproto.ConfigErrUntrusted, "config_error_reason": helperproto.ConfigReasonMissing})},
		{name: "missing crt-list in an uncertain region", installed: true, sites: []haSite{wwwSite}, prep: func(tw *haproxyTwin) {
			tw.setConfig("frontend f\n    bind :9443 ssl crt " + wwwSite.CertPath + "\n.if defined(X)\n    bind :9444 ssl crt-list /etc/haproxy/gone.lst\n.endif\n")
		}, check: func(t *testing.T, m map[string]any, _ int) {
			assert.Equal(t, true, m["config_valid"])
			assert.Equal(t, []any{haproxyconf.WarnConfigFileNotRead}, m["warnings"])
		}},
		{name: "combined file", installed: true, sites: []haSite{wwwSite}, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, 0, exit)
			assert.Len(t, m["files"], 2, "the combined file is listed as a certificate and as a key")
			assert.Equal(t, haCertDir+"/www.pem", asList(m["files"])[1]["path"])
		}},
		{name: "companion key", installed: true, sites: []haSite{besideSite}, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, 0, exit)
			assert.Equal(t, haCertDir+"/blog.pem.key", asList(m["files"])[1]["path"])
		}},
		{name: "crt directory", installed: true, prep: func(tw *haproxyTwin) {
			d := "/etc/haproxy/certdir"
			tw.f.mkdir(d, 0o755)
			tw.setConfig("frontend fe_dir\n    bind :9443 ssl crt " + d + "\n")
			tw.putFile(d+"/x.pem", string(www.FullchainPEM)+string(www.KeyPEM), 0o600)
			tw.putFile(d+"/y.pem", string(api.FullchainPEM), 0o644)
			tw.putFile(d+"/y.pem.key", string(api.KeyPEM), 0o600)
			tw.putFile(d+"/y.pem.ocsp", "ocsp", 0o644)
		}, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, 0, exit)
			servers := asList(m["servers"])
			require.Len(t, servers, 1)
			assert.Len(t, serverPairs(servers[0]), 2)
			assert.Len(t, m["files"], 4)
		}},
		{name: "key mode 0644", installed: true, sites: []haSite{besideSite}, prep: func(tw *haproxyTwin) {
			tw.chmod(besideSite.CertPath+".key", 0o644)
		}, check: func(t *testing.T, m map[string]any, _ int) {
			assert.Equal(t, []any{helperproto.WarnKeyGroupOpen}, m["warnings"])
		}},
		{name: "writable crt-list", installed: true, sites: []haSite{wwwSite, apiSite}, prep: func(tw *haproxyTwin) {
			tw.chmod(haList("fe_api", 9445), 0o666)
		}, check: func(t *testing.T, m map[string]any, _ int) {
			assert.Equal(t, []any{haList("fe_api", 9445)}, m["writable"])
			assert.Equal(t, []any{helperproto.WarnConfigFileWritable}, m["warnings"])
			assert.Empty(t, m["files"], "a writable configuration opens no certificate")
		}},
		{name: "invalid configuration", installed: true, sites: []haSite{wwwSite, apiSite}, prep: func(tw *haproxyTwin) {
			prev := tw.f.s.runHAProxy
			tw.f.s.runHAProxy = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
				if len(args) > 0 && args[0] == "-c" {
					return nil, nil, exitStatus(1)
				}
				return prev(ctx, args...)
			}
			tw.e.SetHAProxyConfigInvalid(true)
		}, check: field(map[string]any{"config_valid": false, "config_error": helperproto.ConfigErrSyntax})},
		{name: "killed", installed: true, sites: []haSite{wwwSite, apiSite}, prep: func(tw *haproxyTwin) {
			tw.f.s.runHAProxy = func(context.Context, ...string) ([]byte, []byte, error) { return nil, nil, errProgramKilled }
			tw.e.SetHAProxyKilled(true)
		}, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, helperproto.ExitFailed, exit)
			assert.Equal(t, helperproto.CodeIOError, m["code"])
		}},
		{name: "conf.d holds a .cfg", installed: true, sites: []haSite{wwwSite}, prep: func(tw *haproxyTwin) {
			tw.f.mkdir(haproxyConfDir, 0o755)
			tw.f.write(haproxyConfDir+"/extra.cfg", "frontend x\n", 0o644)
			tw.e.SetHAProxyConfDir("extra.cfg")
		}, check: func(t *testing.T, m map[string]any, _ int) {
			assert.Equal(t, []any{helperproto.WarnConfigDirNotRead}, m["warnings"])
			assert.Len(t, m["servers"], 1)
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			tw := newHAProxyTwin(t, sc.installed, sc.sites)
			if sc.prep != nil {
				sc.prep(tw)
			}
			h, e := tw.dump()
			assert.Equal(t, h.exit, e.exit, "exit status")
			assert.Equal(t, h.m, e.m, "answer")
			sc.check(t, h.m, h.exit)
		})
	}
}
