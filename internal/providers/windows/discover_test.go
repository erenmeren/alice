package windows

import (
	"context"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

func discover(t *testing.T, e *env, req providers.DiscoverRequest) providers.DiscoveryResult {
	t.Helper()
	res, err := e.open(t).Discover(context.Background(), req)
	require.NoError(t, err)
	return res
}

func leafDER(t *testing.T, chain []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(chain)
	require.NotNil(t, b)
	return b.Bytes
}

// End to end over SSH against the demo host: every http.sys entry a location, the IIS sites as its
// servers.
func TestDiscoverListsBindingsWithSites(t *testing.T) {
	m, err := wintest.Demo(time.Now())
	require.NoError(t, err)
	e := newEnvWith(t, m)
	res := discover(t, e, providers.DiscoverRequest{SSHKeys: true, Certificates: true})
	assert.Equal(t, []string{"version", "iis-dump", "rdp-dump"}, e.srv.Commands())
	require.NotNil(t, res.WebServer)
	assert.Equal(t, providers.WebServerFacts{Software: "iis", Version: "10.0", Found: true, ConfigValid: true}, *res.WebServer)
	assert.Equal(t, []string{winproto.WarnCCSEnabled, WarnCCSPasswordMissing}, codes(res.Warnings),
		"the demo host has CCS on (W5 Ruling 25); this server has no CCS password in Alice")
	assert.Empty(t, res.SSHKeys, "no SSH half")
	assert.Empty(t, res.HostKeys)

	var paths []string
	for _, c := range res.Certificates {
		checkStorable(t, c)
		paths = append(paths, c.Location.CertPath)
	}
	assert.Equal(t, []string{"http.sys/ccs/443", "http.sys/hostnameport/www.win.example.test:443", "http.sys/ipport/0.0.0.0:5986",
		"http.sys/ipport/0.0.0.0:8443", "http.sys/ipport/0.0.0.0:9444", winproto.RDPCanonical}, paths)
	got := byPath(res.Certificates)

	ccs := got["http.sys/ccs/443"]
	assert.Equal(t, UnsupportedCCS, ccs.Location.Unsupported)
	assert.Equal(t, providers.Locator{"type": "ccs", "port": 443, "app_id": winproto.AppIDIIS}, ccs.Location.Locator)
	assert.Equal(t, []providers.CertServer{{Names: []string{"ccs.example.test"}, Listens: []providers.CertListen{{Addr: "*", Port: 443}},
		Section: "CCS Site"}}, ccs.Location.Servers, "the CCS Site binding uses the ccs record")
	assert.Nil(t, ccs.PEMChain)

	web := got["http.sys/hostnameport/www.win.example.test:443"]
	assert.True(t, web.Location.Supported)
	assert.Empty(t, web.Location.Problem)
	assert.Empty(t, web.Location.KeyProblem)
	assert.Equal(t, providers.Locator{"type": "hostnameport", "host": "www.win.example.test", "port": 443, "app_id": winproto.AppIDIIS}, web.Location.Locator)
	assert.Equal(t, []providers.CertServer{{Names: []string{"www.win.example.test"}, Listens: []providers.CertListen{{Addr: "*", Port: 443}},
		Section: "Default Web Site"}}, web.Location.Servers)
	assert.Equal(t, 2, len(pemBlocks(web.PEMChain)), "leaf and intermediate")
	assert.Equal(t, derSHA256(leafDER(t, web.PEMChain)), web.FileSHA256)
	assert.Equal(t, "My", web.Location.Details["store"])
	assert.Equal(t, sha1Hex(leafDER(t, web.PEMChain)), web.Location.Details["cert_sha1"])
	assert.Equal(t, "www.win.example.test", web.Location.Details["friendly_name"])
	assert.Equal(t, "Microsoft Software Key Storage Provider", web.Location.Details["key_provider"])
	assert.Equal(t, false, web.Location.Details["key_exportable"])
	assert.Equal(t, true, web.Location.Details["key_usable_by_system"])

	winrm := got["http.sys/ipport/0.0.0.0:5986"]
	assert.Equal(t, UnsupportedForeignApp, winrm.Location.Unsupported)
	assert.Equal(t, "winrm", winrm.Location.Details["application"])
	assert.NotEmpty(t, winrm.PEMChain, "its certificate is still known")

	intranet := got["http.sys/ipport/0.0.0.0:8443"]
	assert.True(t, intranet.Location.Supported)
	assert.Equal(t, "WebHosting", intranet.Location.Details["store"])
	assert.Equal(t, []providers.CertServer{{Names: []string{}, Listens: []providers.CertListen{{Addr: "*", Port: 8443}}, Section: "Intranet"}},
		intranet.Location.Servers)
}

func pemBlocks(b []byte) [][]byte {
	var out [][]byte
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			return out
		}
		out = append(out, blk.Bytes)
	}
}

// Review Focus 3: without IIS the WinRM binding is still listed, unsupported, and nothing is
// supported.
func TestDiscoverWithoutIISListsForeignBindings(t *testing.T) {
	m := wintest.NewModel()
	m.SetIIS(winproto.IISFacts{})
	ca := pki.NewCA("No IIS CA", pki.ECDSA256, time.Now())
	l := ca.Issue(pki.Opts{CommonName: "win-01", SANs: []string{"win-01"}}, time.Now())
	sha := m.AddCertificate("My", l.CertPEM, l.KeyPEM, wintest.CertOptions{FriendlyName: "WinRM"})
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 5986, AppID: appWinRM, CertSHA1: sha})
	e := newEnvWith(t, m)
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	require.NotNil(t, res.WebServer)
	assert.False(t, res.WebServer.Found)
	assert.True(t, res.WebServer.ConfigValid, "the bindings were read: they may be stored")
	assert.Equal(t, "iis", res.WebServer.Software)
	assert.Equal(t, []string{providers.WarnWebServerNotFound}, codes(res.Warnings))
	require.Len(t, res.Certificates, 1)
	c := res.Certificates[0]
	checkStorable(t, c)
	assert.Equal(t, "http.sys/ipport/0.0.0.0:5986", c.Location.CertPath)
	assert.False(t, c.Location.Supported)
	assert.Equal(t, UnsupportedForeignApp, c.Location.Unsupported)
	assert.Equal(t, "winrm", c.Location.Details["application"])
	assert.Equal(t, "MY", c.Location.Details["store"], "a NULL store is MY")
	assert.NotEmpty(t, c.PEMChain)
}

func TestDiscoverNotElevated(t *testing.T) {
	e := newEnv(t)
	e.model.SetElevated(false)
	_, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	pe := providerErr(t, err)
	assert.Equal(t, "windows.not_elevated", pe.Code)
	assert.Equal(t, winproto.SubIISDump, pe.Params["subcommand"])
	assert.False(t, pe.Retryable)
}

// Ruling 12: appcmd failing fails the dump; the refusal is windows.io_error (W2 Ruling 6), retryable.
func TestDiscoverAppcmdFailure(t *testing.T) {
	e := newEnv(t)
	e.model.FailAppcmd(true)
	_, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	pe := providerErr(t, err)
	assert.Equal(t, "windows.io_error", pe.Code)
	assert.Equal(t, winproto.CodeIOError, pe.Params["helper_code"])
	assert.True(t, pe.Retryable)
}

// Windows has no SSH key inventory (§2 non-goal): the SSH half sends nothing, and a request for
// neither half is not supported.
func TestDiscoverIgnoresTheSSHHalf(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, providers.DiscoveryResult{}, res)
	assert.Equal(t, []string{"version"}, e.srv.Commands())
	_, err = s.Discover(context.Background(), providers.DiscoverRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	assert.Equal(t, []string{"version"}, e.srv.Commands())
	res, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
	require.NoError(t, err)
	require.NotNil(t, res.WebServer, "certificates were read")
	assert.Empty(t, res.Certificates, "an empty table")
	assert.Equal(t, []string{"version", "iis-dump", "rdp-dump"}, e.srv.Commands())
}
