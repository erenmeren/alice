package haproxy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/testutil/pki"
)

func TestDiscoverTwoFrontends(t *testing.T) {
	e := newEnv(t)
	res := e.discover(t)
	require.NotNil(t, res.WebServer)
	assert.Equal(t, "haproxy", res.WebServer.Software)
	require.Len(t, res.Certificates, 2)
	by := locationsByPath(res)
	www, api := by[wwwCert], by[apiCert]
	assert.Equal(t, wwwKey, www.Location.KeyPath)
	assert.True(t, www.Location.Supported)
	assert.Empty(t, www.Location.Unsupported)
	assert.False(t, www.Location.CustomLocation)
	require.Len(t, www.Location.Servers, 1)
	assert.Equal(t, "fe_www", www.Location.Servers[0].Section)
	assert.Empty(t, www.Location.Servers[0].Names)
	assert.Equal(t, []providers.CertListen{{Port: 9443}}, www.Location.Servers[0].Listens)
	assert.Equal(t, "/etc/haproxy/haproxy.cfg", www.Location.Servers[0].File)
	assert.Equal(t, apiCert, api.Location.KeyPath, "the key is in the certificate file")
	assert.True(t, api.Location.Supported)
	require.Len(t, api.Location.Servers, 1)
	assert.Equal(t, "fe_api", api.Location.Servers[0].Section)
	assert.Equal(t, []string{"api.example.test", "alt.example.test"}, api.Location.Servers[0].Names)
	assert.Equal(t, string(e.leaf.FullchainPEM), string(www.PEMChain))
}

func TestDiscoverWithoutHAProxyFails(t *testing.T) {
	e := newEnv(t, withoutHAProxy())
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
	assert.Equal(t, "haproxy.not_found", providerErr(t, err).Code)
	assert.Equal(t, providers.DiscoveryResult{}, res, "no partial data")
}

func TestDiscoverCompanionAndCombinedKeys(t *testing.T) {
	e := newEnv(t)
	e.emu.SetNginxFileMode(wwwKey, "root", "root", 0o644)
	by := locationsByPath(e.discover(t))
	companion, combined := by[wwwCert].Location, by[apiCert].Location
	assert.Equal(t, wwwCert+".key", companion.KeyPath, "the companion file is the certificate path and .key")
	assert.True(t, companion.Supported)
	assert.Contains(t, companion.Warnings, providers.WarnKeyModeOpen)
	assert.Equal(t, "0644", companion.KeyMode)
	assert.Equal(t, combined.CertPath, combined.KeyPath)
	assert.True(t, combined.Supported)
	assert.NotContains(t, combined.Warnings, providers.WarnKeyModeOpen)
}

func TestDiscoverConditionalPairIsUnsupported(t *testing.T) {
	e := newEnv(t)
	e.emu.SetHAProxyConfig("frontend fe_www\n.if defined(X)\n    bind :9443 ssl crt " + wwwCert + "\n.endif\n")
	res := e.discover(t)
	require.NotEmpty(t, res.Certificates)
	var found bool
	for _, c := range res.Certificates {
		if c.Location.Unsupported == providers.UnsupportedConditional {
			found = true
			assert.False(t, c.Location.Supported)
		}
	}
	assert.True(t, found, "the conditional pair is listed as unsupported")
}

func TestDiscoverCustomLocation(t *testing.T) {
	e := newEnv(t)
	c := e.ca.Issue(pki.Opts{CommonName: "srv.example.test", SANs: []string{"srv.example.test"}}, e.leaf.Cert.NotBefore)
	e.emu.AddHAProxySite(linuxsshtest.HAProxySite{Frontend: "fe_srv", Port: 9445, CertPath: "/srv/certs/srv.pem"}, c.FullchainPEM, c.KeyPEM)
	got, ok := locationsByPath(e.discover(t))["/srv/certs/srv.pem"]
	require.True(t, ok)
	assert.True(t, got.Location.CustomLocation)
	assert.Contains(t, got.Location.Warnings, providers.WarnCustomLocation)
}
