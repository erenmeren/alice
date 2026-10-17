package linuxsshtest

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

const (
	hCombined = "/etc/haproxy/certs/shop.pem"
	hBeside   = "/etc/haproxy/certs/blog.pem"
	hSNI      = "/etc/haproxy/certs/api.pem"
)

type haproxyLeaves struct{ shop, blog, api pki.Leaf }

func haproxyWorld(t *testing.T) (*Emulator, haproxyLeaves) {
	t.Helper()
	ca := pki.NewCA("Emu HAProxy", pki.ECDSA256, testNow)
	l := haproxyLeaves{ca.Issue(pki.Opts{CommonName: "shop.example.test"}, testNow),
		ca.Issue(pki.Opts{CommonName: "blog.example.test"}, testNow),
		ca.Issue(pki.Opts{CommonName: "api.example.test"}, testNow)}
	e := NewEmulator()
	e.EnableHAProxy("")
	e.AddHAProxySite(HAProxySite{Frontend: "fe_shop", Port: 9443, CertPath: hCombined}, l.shop.FullchainPEM, l.shop.KeyPEM)
	e.AddHAProxySite(HAProxySite{Frontend: "fe_shop", Port: 9444, CertPath: hBeside, KeyBeside: true}, l.blog.FullchainPEM, l.blog.KeyPEM)
	e.AddHAProxySite(HAProxySite{Frontend: "fe_api", Port: 9445, CertPath: hSNI, SNI: []string{"api.example.test", "alt.example.test"}}, l.api.FullchainPEM, l.api.KeyPEM)
	return e, l
}

func haproxyDump(t *testing.T, e *Emulator) (Response, helperproto.ServerDumpResponse) {
	t.Helper()
	r := e.handle(line(true, helperproto.SubHAProxyDump), nil)
	var d helperproto.ServerDumpResponse
	if r.Exit == 0 {
		require.NoError(t, json.Unmarshal(r.Stdout, &d))
	}
	return r, d
}

func TestHAProxyNotInstalled(t *testing.T) {
	e := NewEmulator()
	r := e.handle(line(true, helperproto.SubHAProxyDump), nil)
	assert.Equal(t, helperproto.ExitPrecondition, r.Exit)
	assert.Equal(t, helperproto.CodeSoftwareNotFound, codeOf(t, r))
}

func TestHAProxyProfileOffAndArgumentsRefusedBySudo(t *testing.T) {
	e, _ := haproxyWorld(t)
	e.SetHAProxyProfile(false)
	assert.Equal(t, 1, e.handle(line(true, helperproto.SubHAProxyDump), nil).Exit)
	e.SetHAProxyProfile(true)
	assert.Equal(t, 1, e.handle(line(true, helperproto.SubHAProxyDump, "x"), nil).Exit)
	r := e.handle(line(false, helperproto.SubHAProxyDump), nil)
	assert.Equal(t, helperproto.CodeNotRoot, codeOf(t, r))
}

func TestHAProxyDumpThreeSites(t *testing.T) {
	e, l := haproxyWorld(t)
	r, d := haproxyDump(t, e)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.True(t, d.ConfigValid, "%+v", d)
	assert.Equal(t, "2.6.12", d.Version)
	assert.Equal(t, "/etc/haproxy/haproxy.cfg", d.ConfPath)
	assert.Empty(t, d.Warnings)
	require.Len(t, d.Servers, 3)
	assert.Equal(t, "fe_shop", d.Servers[0].Section)
	assert.Equal(t, "fe_shop", d.Servers[1].Section)
	assert.Equal(t, "fe_api", d.Servers[2].Section)
	assert.Equal(t, []string{"api.example.test", "alt.example.test"}, d.Servers[2].Names)
	assert.Equal(t, hCombined, d.Servers[0].Pairs[0].Key, "a combined file is its own key")
	assert.Equal(t, hBeside+".key", d.Servers[1].Pairs[0].Key, "the key is beside the certificate")
	assert.Equal(t, hSNI, d.Servers[2].Pairs[0].Key)
	for _, s := range d.Servers {
		assert.Equal(t, "", s.Pairs[0].Unsupported)
	}
	var certs []helperproto.DumpFile
	for _, f := range d.Files {
		if f.Kind == "cert" {
			certs = append(certs, f)
		}
	}
	require.Len(t, certs, 3)
	assert.Equal(t, hexSum(append(append([]byte(nil), l.shop.FullchainPEM...), l.shop.KeyPEM...)), certs[0].SHA256, "the hash is of the whole file")
	assert.Equal(t, hexSum(l.blog.FullchainPEM), certs[1].SHA256)
	assert.Equal(t, string(l.shop.FullchainPEM), certs[0].PEM)
	assert.Len(t, d.Files, 6)
}

func TestHAProxyConfigInvalid(t *testing.T) {
	e, _ := haproxyWorld(t)
	e.SetHAProxyConfigInvalid(true)
	r, d := haproxyDump(t, e)
	require.Equal(t, 0, r.Exit)
	assert.False(t, d.ConfigValid)
	assert.Equal(t, helperproto.ConfigErrSyntax, d.ConfigError)
	assert.Empty(t, d.Servers)
}

func TestHAProxyKilledIsIOError(t *testing.T) {
	e, _ := haproxyWorld(t)
	e.SetHAProxyKilled(true)
	r, _ := haproxyDump(t, e)
	assert.Equal(t, helperproto.ExitFailed, r.Exit)
	assert.Equal(t, helperproto.CodeIOError, codeOf(t, r))
}

func TestHAProxyConfDirWarning(t *testing.T) {
	e, _ := haproxyWorld(t)
	e.SetHAProxyConfDir("README")
	_, d := haproxyDump(t, e)
	assert.Empty(t, d.Warnings, "only *.cfg counts")
	e.SetHAProxyConfDir("extra.cfg")
	_, d = haproxyDump(t, e)
	assert.Equal(t, []string{helperproto.WarnConfigDirNotRead}, d.Warnings)
	assert.Len(t, d.Servers, 3, "conf.d is never read")
	e.SetHAProxyConfDir()
	_, d = haproxyDump(t, e)
	assert.Empty(t, d.Warnings)
}

func TestHAProxyProtocol8AnswersVersion(t *testing.T) {
	e, _ := haproxyWorld(t)
	e.SetProtocol(8)
	v := decode[helperproto.VersionResponse](t, e.handle(line(true, helperproto.SubVersion), nil))
	assert.Equal(t, 8, v.Protocol)
}

func TestHAProxySetConfigAndWritable(t *testing.T) {
	e, _ := haproxyWorld(t)
	e.SetNginxFileMode(haproxyConfPath, "deploy", "deploy", 0o644)
	r, d := haproxyDump(t, e)
	require.Equal(t, 0, r.Exit)
	assert.Equal(t, []string{haproxyConfPath}, d.Writable)
	assert.Equal(t, "config_file_writable", d.Servers[0].Pairs[0].Unsupported)
	assert.Contains(t, d.Warnings, helperproto.WarnConfigFileWritable)
	assert.Empty(t, d.Files, "a writable configuration opens no certificate")

	e2, _ := haproxyWorld(t)
	e2.SetHAProxyConfig("frontend f\n    bind :9443 ssl crt " + hCombined + "\n.if defined(X)\n    bind :9444 ssl crt " + hBeside + "\n.endif\n")
	_, d = haproxyDump(t, e2)
	require.True(t, d.ConfigValid, "%+v", d)
	require.Len(t, d.Servers, 2)
	assert.Equal(t, "conditional", d.Servers[1].Pairs[0].Unsupported)
}

func TestHAProxyCrtDirectory(t *testing.T) {
	e, l := haproxyWorld(t)
	e.SetHAProxyFile("/etc/haproxy/dir/x.pem", append(append([]byte(nil), l.shop.FullchainPEM...), l.shop.KeyPEM...))
	e.SetHAProxyFile("/etc/haproxy/dir/x.pem.ocsp", []byte("ocsp"))
	e.SetHAProxyConfig("frontend f\n    bind :9443 ssl crt /etc/haproxy/dir\n")
	_, d := haproxyDump(t, e)
	require.True(t, d.ConfigValid, "%+v", d)
	require.Len(t, d.Servers, 1)
	require.Len(t, d.Servers[0].Pairs, 1)
	assert.Equal(t, "/etc/haproxy/dir/x.pem", d.Servers[0].Pairs[0].Cert)
}

func TestHAProxyAndApacheOnOneHostStaySeparate(t *testing.T) {
	ca := pki.NewCA("Emu HAProxy Apache", pki.ECDSA256, testNow)
	shop := ca.Issue(pki.Opts{CommonName: "shop.example.test"}, testNow)
	site := ca.Issue(pki.Opts{CommonName: "site.example.test"}, testNow)
	e := NewEmulator()
	e.EnableApache("2.4.68")
	e.AddApacheSite(ApacheSite{Names: []string{"site.example.test"}, Port: 443, CertPath: aCrt, KeyPath: aKey}, site.FullchainPEM, site.KeyPEM)
	e.AddApacheSite(ApacheSite{Names: []string{"shop.example.test"}, Port: 8443, CertPath: hCombined}, shop.FullchainPEM, shop.KeyPEM)
	e.EnableHAProxy("2.8.14")
	e.AddHAProxySite(HAProxySite{Frontend: "fe", Port: 9443, CertPath: hCombined}, shop.FullchainPEM, shop.KeyPEM)

	_, ad := apacheDump(t, e)
	require.Len(t, ad.Servers, 2)
	_, hd := haproxyDump(t, e)
	require.Len(t, hd.Servers, 1)
	assert.Equal(t, "fe", hd.Servers[0].Section)
	assert.Equal(t, "2.8.14", hd.Version)
	var as, hs string
	for _, f := range ad.Files {
		if f.Path == hCombined && f.Kind == "cert" {
			as = f.SHA256
		}
	}
	for _, f := range hd.Files {
		if f.Path == hCombined && f.Kind == "cert" {
			hs = f.SHA256
		}
	}
	assert.NotEmpty(t, hs)
	assert.Equal(t, as, hs, "the shared certificate is one file")
}
