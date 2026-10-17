package apache

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/providertest"
)

func TestApacheProviderDescribesItself(t *testing.T) {
	e := newEnv(t)
	providertest.CheckProvider(t, e.prov)
	assert.Equal(t, providers.KindApache, e.prov.Kind())
	assert.Equal(t, "provider.apache.name", e.prov.DisplayNameKey())
	assert.Equal(t, []providers.Capability{providers.CapAuthorizedKeys, providers.CapDiscoverCerts, providers.CapDiscoverSSHKeys,
		providers.CapKeyLogin, providers.CapTestConnection}, e.prov.Capabilities().Sorted(), "no deploy, verify or HTTP-01")
	var _ providers.ConnectionCache = e.prov
	assert.Equal(t, e.ssh.ConfigSchema(), e.prov.ConfigSchema())
	e.prov.ForgetTarget(testTarget)
	assert.Empty(t, e.prov.ValidateConfig(e.ref.Config))
}

func TestApacheConformance(t *testing.T) {
	e := newEnv(t)
	providertest.CheckSession(t, providertest.SessionHarness{
		Capabilities: e.prov.Capabilities(),
		Open: func(ctx context.Context) (providers.Session, error) {
			return e.prov.Open(ctx, e.ref, e.cred, providers.Env{})
		},
		Secrets: e.cred.secrets(t),
	})
}

func TestTestConnectionReadsTheDump(t *testing.T) {
	e := newEnv(t)
	rep, err := e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	require.NotNil(t, rep.WebServer)
	assert.Equal(t, providers.WebServerFacts{Software: "apache", Found: true, Version: "2.4.57", ConfPath: "/etc/apache2/apache2.conf", ConfigValid: true}, *rep.WebServer)
	assert.Equal(t, helperproto.Protocol, rep.HelperProtocol)
}

func TestTestConnectionChecksTheApacheProfile(t *testing.T) {
	e := newEnv(t)
	e.emu.SetApacheProfile(false)
	_, err := e.open(t).TestConnection(context.Background())
	pe := providerErr(t, err)
	assert.Equal(t, "apache.profile_missing", pe.Code)
	assert.False(t, pe.Retryable)
}

func TestApacheNotInstalledIsAWarning(t *testing.T) {
	e := newEnv(t, withoutApache())
	rep, err := e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	require.NotNil(t, rep.WebServer)
	assert.Equal(t, &providers.WebServerFacts{Software: "apache"}, rep.WebServer)
	assert.Contains(t, warningCodes(rep.Warnings), providers.WarnWebServerNotFound)
}

func TestApacheHelperTooOld(t *testing.T) {
	e := newEnv(t)
	e.emu.SetProtocol(7)
	s := e.open(t)
	rep, err := s.TestConnection(context.Background())
	require.NoError(t, err)
	assert.Nil(t, rep.WebServer)
	assert.Contains(t, warningCodes(rep.Warnings), providers.WarnWebServerHelperTooOld)

	_, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	pe := providerErr(t, err)
	assert.Equal(t, "apache.helper_too_old", pe.Code)
	assert.Equal(t, map[string]string{"helper_protocol": "7", "required_protocol": "8"}, pe.Params)
}
