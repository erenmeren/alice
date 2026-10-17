package apache

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

func TestDiscoverTwoSites(t *testing.T) {
	e := newEnv(t)
	res := e.discover(t)
	require.NotNil(t, res.WebServer)
	assert.Equal(t, "apache", res.WebServer.Software)
	require.Len(t, res.Certificates, 2)
	by := locationsByPath(res)
	www, api := by[wwwCert], by[apiCert]
	assert.Equal(t, wwwKey, www.Location.KeyPath)
	assert.True(t, www.Location.Supported)
	assert.Empty(t, www.Location.Unsupported)
	assert.False(t, www.Location.CustomLocation)
	require.Len(t, www.Location.Servers, 1)
	assert.Equal(t, []string{"www.example.test", "example.test"}, www.Location.Servers[0].Names)
	assert.Equal(t, []providers.CertListen{{Port: 443, DefaultServer: true}}, www.Location.Servers[0].Listens)
	assert.Equal(t, "/etc/apache2/sites-enabled/emu.conf", www.Location.Servers[0].File)
	assert.Equal(t, apiKey, api.Location.KeyPath)
	assert.True(t, api.Location.Supported)
	require.Len(t, api.Location.Servers, 1)
	assert.Equal(t, []string{"api.example.test"}, api.Location.Servers[0].Names)
	assert.Equal(t, string(e.leaf.FullchainPEM), string(www.PEMChain))
}

func TestDiscoverWithoutApacheFails(t *testing.T) {
	e := newEnv(t, withoutApache())
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
	assert.Equal(t, "apache.not_found", providerErr(t, err).Code)
	assert.Equal(t, providers.DiscoveryResult{}, res, "no partial data")
}

func TestDiscoverCombinedFileIsSupportedAndWarns(t *testing.T) {
	e := newEnv(t)
	comb := e.ca.Issue(pki.Opts{CommonName: "comb.example.test", SANs: []string{"comb.example.test"}}, e.leaf.Cert.NotBefore)
	const path = "/etc/ssl/certs/comb.pem"
	e.emu.AddApacheSite(linuxsshtestSite("comb.example.test", 9443, path, ""), comb.FullchainPEM, comb.KeyPEM)
	e.emu.SetNginxFileMode(path, "root", "root", 0o644)
	c, ok := locationsByPath(e.discover(t))[path]
	require.True(t, ok)
	l := c.Location
	assert.Equal(t, l.CertPath, l.KeyPath)
	assert.True(t, l.Supported)
	assert.Empty(t, l.Unsupported)
	assert.Equal(t, string(comb.FullchainPEM), string(c.PEMChain))
	assert.Contains(t, l.Warnings, providers.WarnKeyModeOpen)
	assert.Equal(t, "0644", l.KeyMode)
}

func TestDiscoverConditionalPairIsUnsupported(t *testing.T) {
	e := newEnv(t)
	e.emu.SetApacheConfig("/etc/apache2/sites-enabled/emu.conf", `<IfVersion ~ ^2>
<VirtualHost *:443>
    ServerName www.example.test
    SSLEngine on
    SSLCertificateFile `+wwwCert+`
    SSLCertificateKeyFile `+wwwKey+`
</VirtualHost>
</IfVersion>
`)
	c, ok := locationsByPath(e.discover(t))[wwwCert]
	require.True(t, ok)
	assert.False(t, c.Location.Supported)
	assert.Equal(t, providers.UnsupportedConditional, c.Location.Unsupported)
}

func TestDiscoverCustomLocation(t *testing.T) {
	e := newEnv(t)
	c := e.ca.Issue(pki.Opts{CommonName: "srv.example.test", SANs: []string{"srv.example.test"}}, e.leaf.Cert.NotBefore)
	e.emu.AddApacheSite(linuxsshtestSite("srv.example.test", 7443, "/srv/certs/srv.crt", "/srv/certs/srv.key"), c.FullchainPEM, c.KeyPEM)
	got, ok := locationsByPath(e.discover(t))["/srv/certs/srv.crt"]
	require.True(t, ok)
	assert.True(t, got.Location.CustomLocation)
	assert.Contains(t, got.Location.Warnings, providers.WarnCustomLocation)
}
