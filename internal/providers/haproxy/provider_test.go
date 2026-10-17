package haproxy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/providertest"
)

func TestHAProxyProviderDescribesItself(t *testing.T) {
	e := newEnv(t)
	providertest.CheckProvider(t, e.prov)
	assert.Equal(t, providers.KindHAProxy, e.prov.Kind())
	assert.Equal(t, "provider.haproxy.name", e.prov.DisplayNameKey())
	assert.Equal(t, []providers.Capability{providers.CapAuthorizedKeys, providers.CapDiscoverCerts, providers.CapDiscoverSSHKeys,
		providers.CapKeyLogin, providers.CapTestConnection}, e.prov.Capabilities().Sorted(), "no deploy, verify or HTTP-01")
	var _ providers.ConnectionCache = e.prov
	assert.Equal(t, e.ssh.ConfigSchema(), e.prov.ConfigSchema())
	e.prov.ForgetTarget(testTarget)
	assert.Empty(t, e.prov.ValidateConfig(e.ref.Config))
}

func TestHAProxyConformance(t *testing.T) {
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
	assert.Equal(t, providers.WebServerFacts{Software: "haproxy", Found: true, Version: "2.6.12", ConfPath: "/etc/haproxy/haproxy.cfg", ConfigValid: true}, *rep.WebServer)
	assert.Equal(t, helperproto.Protocol, rep.HelperProtocol)
}

func TestTestConnectionChecksTheHAProxyProfile(t *testing.T) {
	e := newEnv(t)
	e.emu.SetHAProxyProfile(false)
	_, err := e.open(t).TestConnection(context.Background())
	pe := providerErr(t, err)
	assert.Equal(t, "haproxy.profile_missing", pe.Code)
	assert.False(t, pe.Retryable)
}

func TestHAProxyNotInstalledIsAWarning(t *testing.T) {
	e := newEnv(t, withoutHAProxy())
	rep, err := e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	require.NotNil(t, rep.WebServer)
	assert.Equal(t, &providers.WebServerFacts{Software: "haproxy"}, rep.WebServer)
	assert.Contains(t, warningCodes(rep.Warnings), providers.WarnWebServerNotFound)
}

func TestHAProxyHelperTooOld(t *testing.T) {
	e := newEnv(t)
	e.emu.SetProtocol(8)
	s := e.open(t)
	rep, err := s.TestConnection(context.Background())
	require.NoError(t, err)
	assert.Nil(t, rep.WebServer)
	assert.Contains(t, warningCodes(rep.Warnings), providers.WarnWebServerHelperTooOld)

	_, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	pe := providerErr(t, err)
	assert.Equal(t, "haproxy.helper_too_old", pe.Code)
	assert.Equal(t, map[string]string{"helper_protocol": "8", "required_protocol": "9"}, pe.Params)
	for _, c := range e.srv.Commands() {
		assert.NotContains(t, c, helperproto.SubHAProxyDump, "no haproxy-dump call reaches a helper that is too old")
	}
}
