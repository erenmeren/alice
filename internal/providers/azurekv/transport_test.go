package azurekv

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/azureid"
	"alice/internal/platform/netaddr"
	"alice/internal/testutil/fakekv"
)

const testVaultHost = "alice-test.vault.azure.net"

func get(t testing.TB, g interface {
	Do(*http.Request) (*http.Response, error)
}, raw string, hdr http.Header) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
	require.NoError(t, err)
	for k, v := range hdr {
		req.Header[k] = v
	}
	return g.Do(req) //nolint:bodyclose // closed by the callers that get a response; refusals return none
}

func bearer(s *fakekv.Server) http.Header {
	return http.Header{"Authorization": {"Bearer " + s.TestClientToken()}}
}

func TestGuardedTransportRefusesOtherHosts(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	g := newGuardedTransport([]string{azureid.AuthorityHost, testVaultHost}, s.CAPool(), s.DialAddr)
	for _, raw := range []string{
		"http://alice-test.vault.azure.net/certificates", "https://alice-test.vault.azure.net:8443/certificates",
		"https://other.vault.azure.net/certificates", "https://evil.test/", "https://169.254.169.254/",
		"https://user@alice-test.vault.azure.net/certificates", "https://management.azure.com/",
		"https://alice-test.vault.azure.net./certificates", "https://alice-test.vault.azure.net.evil.test/",
	} {
		resp, err := get(t, g, raw, nil) //nolint:bodyclose // refused: no response
		assert.ErrorIs(t, err, errHostNotAllowed, raw)
		assert.Nil(t, resp, raw)
	}
	// A request whose Host header names another host is refused too.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://alice-test.vault.azure.net/certificates", nil)
	require.NoError(t, err)
	req.Host = "evil.test"
	_, err = g.Do(req) //nolint:bodyclose // refused: no response
	assert.ErrorIs(t, err, errHostNotAllowed)
	assert.Empty(t, s.Requests(), "nothing was sent")
}

func TestVaultAndLoginTransportsAreSeparate(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	login := newGuardedTransport([]string{azureid.AuthorityHost}, s.CAPool(), s.DialAddr)
	vault := newGuardedTransport([]string{testVaultHost}, s.CAPool(), s.DialAddr)
	_, err := get(t, login, "https://"+testVaultHost+"/certificates", nil) //nolint:bodyclose // refused
	assert.ErrorIs(t, err, errHostNotAllowed)
	_, err = get(t, vault, "https://"+azureid.AuthorityHost+"/x/v2.0/.well-known/openid-configuration", nil) //nolint:bodyclose // refused
	assert.ErrorIs(t, err, errHostNotAllowed)
	assert.Empty(t, s.Requests())
}

func TestPort443IsTheOwnHost(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	g := newGuardedTransport([]string{testVaultHost}, s.CAPool(), s.DialAddr)
	resp, err := get(t, g, "https://"+testVaultHost+":443/certificates?api-version="+fakekv.APIVersion, bearer(s))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRedirectIsNeverFollowed(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{ExtraHosts: []string{"169.254.169.254"}})
	g := newGuardedTransport([]string{testVaultHost}, s.CAPool(), s.DialAddr)
	for _, status := range []int{301, 302, 307, 308} {
		s.ClearRequests()
		s.FailNext("/certificates", fakekv.Fault{Status: status, Location: "https://169.254.169.254/"})
		resp, err := get(t, g, "https://"+testVaultHost+"/certificates?api-version="+fakekv.APIVersion, bearer(s)) //nolint:bodyclose // refused: no response
		assert.ErrorIs(t, err, errRedirect)
		assert.Nil(t, resp)
		reqs := s.Requests()
		require.Len(t, reqs, 1, "one request, nothing followed")
		assert.Equal(t, testVaultHost, reqs[0].Host)
	}
}

func TestRedirectRefusalIsOurOwn(t *testing.T) {
	// The client inside the transport never follows a redirect, whatever the transport check says.
	g := newGuardedTransport([]string{testVaultHost}, nil, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+testVaultHost+"/", nil)
	require.NoError(t, err)
	via := []*http.Request{req}
	assert.ErrorIs(t, g.client.CheckRedirect(req, via), http.ErrUseLastResponse)
	assert.Nil(t, g.tr.Proxy)
}

func TestDialRefusesMetadataAddress(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	for _, to := range []string{"169.254.169.254:443", "[fe80::1]:443", "0.0.0.0:443"} {
		g := newGuardedTransport([]string{testVaultHost}, s.CAPool(), func(string) string { return to })
		resp, err := get(t, g, "https://"+testVaultHost+"/certificates", nil) //nolint:bodyclose // refused: no response
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, netaddr.ErrNotAllowed, to)
	}
	// A private endpoint is allowed: the dial is attempted and fails as a connection, not as a refusal.
	g := newGuardedTransport([]string{testVaultHost}, s.CAPool(), func(string) string { return "10.1.2.3:443" })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+testVaultHost+"/certificates", nil)
	require.NoError(t, err)
	_, err = g.Do(req) //nolint:bodyclose // no response
	require.Error(t, err)
	assert.NotErrorIs(t, err, netaddr.ErrNotAllowed, "the dial was attempted; it failed as a connection")
}

func TestProxyEnvironmentIsIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	s := fakekv.Start(t, fakekv.Options{})
	g := newGuardedTransport([]string{testVaultHost}, s.CAPool(), s.DialAddr)
	resp, err := get(t, g, "https://"+testVaultHost+"/certificates?api-version="+fakekv.APIVersion, bearer(s))
	require.NoError(t, err, "the proxy would have failed the request")
	_ = resp.Body.Close()
	require.Nil(t, g.tr.Proxy)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+testVaultHost+"/", nil)
	u, err := http.ProxyFromEnvironment(req)
	require.NoError(t, err)
	require.NotNil(t, u, "the environment does name a proxy; the transport does not use it")
}

func TestBodiesAreCapped(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	g := newGuardedTransport([]string{testVaultHost}, s.CAPool(), s.DialAddr)
	for _, tc := range []struct {
		n  int
		ok bool
	}{{MaxBody, true}, {MaxBody + 1, false}} {
		s.FailNext("/certificates", fakekv.Fault{Status: 200, Body: strings.Repeat("x", tc.n)})
		resp, err := get(t, g, "https://"+testVaultHost+"/certificates?api-version="+fakekv.APIVersion, bearer(s))
		require.NoError(t, err)
		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if tc.ok {
			require.NoError(t, err)
			assert.Len(t, b, tc.n)
		} else {
			assert.ErrorIs(t, err, errBodyTooLarge)
		}
	}
}

func TestTLSMustChainToTheConfiguredRoots(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	g := newGuardedTransport([]string{testVaultHost}, nil, s.DialAddr) // system roots: the fake's CA is unknown
	_, err := get(t, g, "https://"+testVaultHost+"/certificates", nil) //nolint:bodyclose // no response
	var cv *tls.CertificateVerificationError
	require.ErrorAs(t, err, &cv)
}

func TestManagedIdentityTalksOnlyToIMDS(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	var dialed []string
	g := newIMDSTransport(s.DialAddr, func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("test dial")
	})
	for _, raw := range []string{
		"https://169.254.169.254/metadata/identity/oauth2/token", "http://169.254.169.254:8080/x", "http://169.254.169.254:443/x",
		"http://evil.test/x", "http://169.254.169.253/x", "http://" + testVaultHost + "/x", "https://" + testVaultHost + "/x",
		"http://user@169.254.169.254/x", "http://[::ffff:169.254.169.254]/x",
	} {
		resp, err := get(t, g, raw, nil) //nolint:bodyclose // refused: no response
		assert.ErrorIs(t, err, errHostNotAllowed, raw)
		assert.Nil(t, resp)
	}
	assert.Empty(t, s.Requests())
	// The dialer itself accepts one address only, before any mapping.
	_, err := g.tr.DialContext(context.Background(), "tcp", "10.0.0.1:80")
	assert.ErrorIs(t, err, errHostNotAllowed)
	_, err = g.tr.DialContext(context.Background(), "tcp", "169.254.169.254:443")
	assert.ErrorIs(t, err, errHostNotAllowed)
	assert.Empty(t, dialed, "the test dial override is reached only after the address check")
	_, err = g.tr.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	require.Error(t, err)
	assert.Equal(t, []string{"169.254.169.254:80"}, dialed)
	assert.Nil(t, g.tr.Proxy)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/", nil)
	assert.ErrorIs(t, g.client.CheckRedirect(req, nil), http.ErrUseLastResponse)
}
