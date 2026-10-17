//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/testutil/pki"
)

// The Apache fidelity test: one scenario runs against the real helper (a temporary tree, a fake
// control program that answers from that tree and is written here, independently of the emulator)
// and against the emulated Apache of the fake SSH server, and the answers are compared: exit
// status, error code, config_* fields, servers (file and line normalized: the emulator generates
// sites-enabled/emu.conf where the helper fixture has alice.conf), listens, pairs, files (owner
// and group normalized), warnings and writable. The helper is the specification.

type fidSite struct {
	linuxsshtest.ApacheSite
	leaf pki.Leaf
}

type apacheTwin struct {
	t     *testing.T
	w     *apacheWorld
	e     *linuxsshtest.Emulator
	sites []fidSite
}

// siteConf renders the sites as the helper fixture's sites-enabled/alice.conf (written here, not
// taken from the emulator).
func siteConf(sites []fidSite) string {
	var b strings.Builder
	for _, s := range sites {
		b.WriteString("<VirtualHost *:" + strconv.Itoa(s.Port) + ">\n")
		b.WriteString("    ServerName " + s.Names[0] + "\n")
		if len(s.Names) > 1 {
			b.WriteString("    ServerAlias " + strings.Join(s.Names[1:], " ") + "\n")
		}
		b.WriteString("    SSLEngine on\n    SSLCertificateFile " + s.CertPath + "\n")
		if s.KeyPath != "" {
			b.WriteString("    SSLCertificateKeyFile " + s.KeyPath + "\n")
		}
		b.WriteString("</VirtualHost>\n")
	}
	return b.String()
}

func newApacheTwin(t *testing.T, installed bool, sites []fidSite) *apacheTwin {
	t.Helper()
	w := newApacheWorld(t)
	e := linuxsshtest.NewEmulator()
	tw := &apacheTwin{t: t, w: w, e: e, sites: sites}
	if !installed {
		w.f.s.runApache = newFixture(t).s.runApache // the fixture's default: the program is missing
		return tw
	}
	e.EnableApache("2.4.68")
	w.f.write(apacheSite, siteConf(sites), 0o644)
	for _, s := range sites {
		if s.KeyPath == "" {
			w.f.write(s.CertPath, string(s.leaf.FullchainPEM)+string(s.leaf.KeyPEM), 0o644)
		} else {
			w.f.write(s.CertPath, string(s.leaf.FullchainPEM), 0o644)
			w.f.write(s.KeyPath, string(s.leaf.KeyPEM), 0o600)
		}
		e.AddApacheSite(s.ApacheSite, s.leaf.FullchainPEM, s.leaf.KeyPEM)
	}
	return tw
}

func (tw *apacheTwin) dump() (helper, emu answer) {
	tw.t.Helper()
	code, m := tw.w.f.run(helperproto.SubApacheDump)
	helper = normalize(helperproto.SubApacheDump, answer{exit: code, m: m}, true)
	r := tw.e.Handler()("sudo -n "+helperproto.HelperPath+" "+helperproto.SubApacheDump, nil)
	var em map[string]any
	if len(r.Stdout) > 0 {
		require.NoError(tw.t, json.Unmarshal(r.Stdout, &em), string(r.Stdout))
	}
	emu = normalize(helperproto.SubApacheDump, answer{exit: r.Exit, m: em}, false)
	return helper, emu
}

func (tw *apacheTwin) chmod(guest string, mode os.FileMode) {
	tw.t.Helper()
	require.NoError(tw.t, os.Chmod(tw.w.f.host(guest), mode))
	tw.e.SetNginxFileMode(guest, "root", "root", uint32(mode))
}

func TestApacheEmulatorFidelity(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the scenarios use the permission bits of an unprivileged user")
	}
	ca := pki.NewCA("Fidelity Apache", pki.ECDSA256, testNow)
	www := ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	api := ca.Issue(pki.Opts{CommonName: "api.example.test"}, testNow)
	wwwSite := fidSite{linuxsshtest.ApacheSite{Names: []string{"www.example.test"}, Port: 443, CertPath: "/etc/apache2/ssl/www.crt", KeyPath: "/etc/apache2/ssl/www.key"}, www}
	apiSite := fidSite{linuxsshtest.ApacheSite{Names: []string{"api.example.test", "alt.example.test"}, Port: 443, CertPath: "/etc/apache2/ssl/api.crt", KeyPath: "/etc/apache2/ssl/api.key"}, api}
	combined := fidSite{linuxsshtest.ApacheSite{Names: []string{"api.example.test"}, Port: 8443, CertPath: "/etc/apache2/ssl/api.pem"}, api}

	type scenario struct {
		name      string
		installed bool
		sites     []fidSite
		prep      func(tw *apacheTwin)
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
		{name: "two sites", installed: true, sites: []fidSite{wwwSite, apiSite}, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, 0, exit)
			assert.Equal(t, true, m["config_valid"])
			assert.Len(t, m["servers"], 2)
			assert.Len(t, m["files"], 4)
			assert.Equal(t, []any{}, m["warnings"])
		}},
		{name: "combined file", installed: true, sites: []fidSite{wwwSite, combined}, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, 0, exit)
			assert.Len(t, m["files"], 4, "the combined file is listed as a certificate and as a key")
		}},
		{name: "cert missing", installed: true, sites: []fidSite{wwwSite, apiSite}, prep: func(tw *apacheTwin) {
			require.NoError(tw.t, os.Remove(tw.w.f.host(wwwSite.CertPath)))
			tw.e.RemoveNginxFile(wwwSite.CertPath)
		}, check: func(t *testing.T, m map[string]any, _ int) {
			assert.Equal(t, "missing", m["files"].([]any)[0].(map[string]any)["problem"])
		}},
		{name: "key mode 0644", installed: true, sites: []fidSite{wwwSite, apiSite}, prep: func(tw *apacheTwin) {
			tw.chmod(wwwSite.KeyPath, 0o644)
		}, check: func(t *testing.T, m map[string]any, _ int) {
			assert.Equal(t, []any{helperproto.WarnKeyGroupOpen}, m["warnings"])
		}},
		{name: "writable config file", installed: true, sites: []fidSite{wwwSite, apiSite}, prep: func(tw *apacheTwin) {
			tw.chmod(apacheConfPath, 0o666)
		}, check: func(t *testing.T, m map[string]any, _ int) {
			assert.Equal(t, []any{apacheConfPath}, m["writable"])
			assert.Equal(t, []any{helperproto.WarnConfigFileWritable}, m["warnings"])
			assert.Empty(t, m["files"])
		}},
		{name: "invalid configuration", installed: true, sites: []fidSite{wwwSite, apiSite}, prep: func(tw *apacheTwin) {
			tw.w.set(argsIncludes, apacheAnswer{err: errors.New("exit status 1")})
			tw.e.SetApacheConfigInvalid(true)
		}, check: field(map[string]any{"config_valid": false, "config_error": helperproto.ConfigErrSyntax})},
		{name: "killed", installed: true, sites: []fidSite{wwwSite, apiSite}, prep: func(tw *apacheTwin) {
			tw.w.set(argsV, apacheAnswer{err: errProgramKilled})
			tw.e.SetApacheKilled(true)
		}, check: func(t *testing.T, m map[string]any, exit int) {
			assert.Equal(t, helperproto.ExitFailed, exit)
			assert.Equal(t, helperproto.CodeIOError, m["code"])
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			tw := newApacheTwin(t, sc.installed, sc.sites)
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
