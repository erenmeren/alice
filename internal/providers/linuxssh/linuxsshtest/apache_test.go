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
	aCrt = "/etc/apache2/ssl/shop.crt"
	aKey = "/etc/apache2/ssl/shop.key"
)

func apacheWorld(t *testing.T) (*Emulator, pki.Leaf, pki.Leaf) {
	t.Helper()
	ca := pki.NewCA("Emu Apache", pki.ECDSA256, testNow)
	shop := ca.Issue(pki.Opts{CommonName: "shop.example.test"}, testNow)
	blog := ca.Issue(pki.Opts{CommonName: "blog.example.test"}, testNow)
	e := NewEmulator()
	e.EnableApache("2.4.68")
	e.AddApacheSite(ApacheSite{Names: []string{"shop.example.test"}, Port: 443, CertPath: aCrt, KeyPath: aKey}, shop.FullchainPEM, shop.KeyPEM)
	return e, shop, blog
}

func apacheDump(t *testing.T, e *Emulator) (Response, helperproto.ServerDumpResponse) {
	t.Helper()
	r := e.handle(line(true, helperproto.SubApacheDump), nil)
	var d helperproto.ServerDumpResponse
	if r.Exit == 0 {
		require.NoError(t, json.Unmarshal(r.Stdout, &d))
	}
	return r, d
}

func TestApacheNotInstalled(t *testing.T) {
	e := NewEmulator()
	r := e.handle(line(true, helperproto.SubApacheDump), nil)
	assert.Equal(t, helperproto.ExitPrecondition, r.Exit)
	assert.Equal(t, helperproto.CodeSoftwareNotFound, codeOf(t, r))
}

func TestApacheProfileOffAndArgumentsRefusedBySudo(t *testing.T) {
	e, _, _ := apacheWorld(t)
	e.SetApacheProfile(false)
	assert.Equal(t, 1, e.handle(line(true, helperproto.SubApacheDump), nil).Exit)
	e.SetApacheProfile(true)
	assert.Equal(t, 1, e.handle(line(true, helperproto.SubApacheDump, "x"), nil).Exit)
	r := e.handle(line(false, helperproto.SubApacheDump), nil)
	assert.Equal(t, helperproto.CodeNotRoot, codeOf(t, r))
}

func TestApacheDumpTwoSites(t *testing.T) {
	e, shop, blog := apacheWorld(t)
	e.AddApacheSite(ApacheSite{Names: []string{"blog.example.test", "www.blog.example.test"}, Port: 443, CertPath: "/etc/apache2/ssl/blog.pem"}, blog.FullchainPEM, blog.KeyPEM)
	r, d := apacheDump(t, e)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.True(t, d.ConfigValid, "%+v", d)
	assert.Equal(t, "2.4.68", d.Version)
	assert.Equal(t, "/etc/apache2/apache2.conf", d.ConfPath)
	require.Len(t, d.Servers, 2)
	assert.Equal(t, []string{"shop.example.test"}, d.Servers[0].Names)
	assert.Equal(t, []string{"blog.example.test", "www.blog.example.test"}, d.Servers[1].Names)
	assert.Equal(t, aCrt, d.Servers[0].Pairs[0].Cert)
	assert.Equal(t, "/etc/apache2/ssl/blog.pem", d.Servers[1].Pairs[0].Key, "a combined file is its own key")
	var certs []helperproto.DumpFile
	for _, f := range d.Files {
		if f.Kind == "cert" {
			certs = append(certs, f)
		}
	}
	require.Len(t, certs, 2)
	assert.Equal(t, hexSum(shop.FullchainPEM), certs[0].SHA256)
	assert.Equal(t, string(shop.FullchainPEM), certs[0].PEM)
}

func TestApacheConfigInvalid(t *testing.T) {
	e, _, _ := apacheWorld(t)
	e.SetApacheConfigInvalid(true)
	r, d := apacheDump(t, e)
	require.Equal(t, 0, r.Exit)
	assert.False(t, d.ConfigValid)
	assert.Equal(t, helperproto.ConfigErrSyntax, d.ConfigError)
	assert.Empty(t, d.Servers)
}

func TestApacheKilledIsIOError(t *testing.T) {
	e, _, _ := apacheWorld(t)
	e.SetApacheKilled(true)
	r, _ := apacheDump(t, e)
	assert.Equal(t, helperproto.ExitFailed, r.Exit)
	assert.Equal(t, helperproto.CodeIOError, codeOf(t, r))
}

func TestApacheProtocol7StillAnswersVersion(t *testing.T) {
	e, _, _ := apacheWorld(t)
	e.SetProtocol(7)
	r := e.handle(line(true, helperproto.SubVersion), nil)
	v := decode[helperproto.VersionResponse](t, r)
	assert.Equal(t, 7, v.Protocol)
}

func TestApacheSetConfigOverridesAndWritableMarksPairs(t *testing.T) {
	e, _, _ := apacheWorld(t)
	e.SetNginxFileMode("/etc/apache2/apache2.conf", "deploy", "deploy", 0o644)
	r, d := apacheDump(t, e)
	require.Equal(t, 0, r.Exit)
	assert.Equal(t, []string{"/etc/apache2/apache2.conf"}, d.Writable)
	assert.Equal(t, "config_file_writable", d.Servers[0].Pairs[0].Unsupported)
	assert.Contains(t, d.Warnings, helperproto.WarnConfigFileWritable)
	assert.Empty(t, d.Files, "an unsupported pair's files are not described")

	e2, _, _ := apacheWorld(t)
	e2.SetApacheConfig("/etc/apache2/apache2.conf", "ServerRoot \"/etc/apache2\"\n")
	_, d = apacheDump(t, e2)
	assert.False(t, d.ConfigValid, "the include tree no longer matches the text")
	assert.Equal(t, helperproto.ConfigErrUntrusted, d.ConfigError)
	assert.Equal(t, helperproto.ConfigReasonChanged, d.ConfigErrorReason)
}

func TestApacheAndNginxOnOneHostStaySeparate(t *testing.T) {
	ca := pki.NewCA("Emu Both", pki.ECDSA256, testNow)
	www := ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	shop := ca.Issue(pki.Opts{CommonName: "shop.example.test"}, testNow)
	e := NewEmulator()
	e.EnableNginx("1.22.1")
	e.AddSite(NginxSite{Names: []string{"www.example.test"}, Port: 443, CertPath: crt, KeyPath: key}, www.FullchainPEM, www.KeyPEM)
	e.EnableApache("2.4.68")
	e.AddApacheSite(ApacheSite{Names: []string{"shop.example.test"}, Port: 443, CertPath: crt, KeyPath: key}, www.FullchainPEM, www.KeyPEM)
	e.AddApacheSite(ApacheSite{Names: []string{"shop2.example.test"}, Port: 8443, CertPath: aCrt, KeyPath: aKey}, shop.FullchainPEM, shop.KeyPEM)

	nr := e.handle(line(true, helperproto.SubNginxDump), nil)
	nd := decode[helperproto.ServerDumpResponse](t, nr)
	require.Len(t, nd.Servers, 1)
	assert.Equal(t, []string{"www.example.test"}, nd.Servers[0].Names)

	_, ad := apacheDump(t, e)
	require.Len(t, ad.Servers, 2)
	assert.Equal(t, []string{"shop.example.test"}, ad.Servers[0].Names)

	var ns, as string
	for _, f := range nd.Files {
		if f.Path == crt {
			ns = f.SHA256
		}
	}
	for _, f := range ad.Files {
		if f.Path == crt {
			as = f.SHA256
		}
	}
	assert.NotEmpty(t, ns)
	assert.Equal(t, ns, as, "the shared path is one file")
}
