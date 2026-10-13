package transport

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
)

func serverPEM(t *testing.T, s *httptest.Server) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
}

func get(t *testing.T, c *http.Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	require.NoError(t, err)
	return c.Do(req)
}

func TestCABundleTrusted(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer s.Close()
	c, err := New(serverPEM(t, s), Options{})
	require.NoError(t, err)
	res, err := get(t, c, s.URL)
	require.NoError(t, err)
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.Equal(t, "ok", string(b))
}

func TestUnknownCAFails(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer s.Close()
	c, err := New("", Options{})
	require.NoError(t, err)
	err = getErr(t, c, s.URL)
	var ua x509.UnknownAuthorityError
	require.ErrorAs(t, err, &ua)
}

func TestBadBundle(t *testing.T) {
	_, err := New("not a pem", Options{})
	require.ErrorIs(t, err, ErrCABundle)
}

func TestHTTPRefusedBeforeDial(t *testing.T) {
	var dials atomic.Int32
	c, err := New("", Options{Dial: func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, errors.New("x") }})
	require.NoError(t, err)
	for _, u := range []string{"http://example.test/", "https://user:pw@example.test/", "https://user@example.test/", "ftp://example.test/"} {
		err = getErr(t, c, u)
		require.ErrorIs(t, err, ErrURLRefused, u)
		require.NotContains(t, err.Error(), "pw@")
	}
	require.Zero(t, dials.Load())
}

func TestRedirectNotFollowed(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer s.Close()
	c, err := New(serverPEM(t, s), Options{})
	require.NoError(t, err)
	res, err := get(t, c, s.URL)
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, http.StatusFound, res.StatusCode)
	require.EqualValues(t, 1, hits.Load())
}

func TestOversizeRefused(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", MaxResponseBytes+10)))
	}))
	defer s.Close()
	c, err := New(serverPEM(t, s), Options{})
	require.NoError(t, err)
	res, err := get(t, c, s.URL)
	require.NoError(t, err)
	_, err = io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestExactCapAllowed(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", MaxResponseBytes)))
	}))
	defer s.Close()
	c, _ := New(serverPEM(t, s), Options{})
	res, err := get(t, c, s.URL)
	require.NoError(t, err)
	b, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.NoError(t, err)
	require.Len(t, b, MaxResponseBytes)
}

func TestMetadataAddressRefused(t *testing.T) {
	c, err := New("", Options{})
	require.NoError(t, err)
	for _, u := range []string{"https://169.254.169.254/latest", "https://169.254.1.1/", "https://[fd00:ec2::254]/"} {
		err = getErr(t, c, u)
		require.ErrorIs(t, err, netaddr.ErrNotAllowed, u)
	}
}

func TestPrivateAddressAllowed(t *testing.T) {
	var got atomic.Value
	c, err := New("", Options{Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		got.Store(addr)
		return nil, errors.New("fake dial")
	}})
	require.NoError(t, err)
	err = getErr(t, c, "https://10.1.2.3:14000/dir")
	require.Error(t, err)
	require.Equal(t, "10.1.2.3:14000", got.Load())
	// The default dialer lets netaddr decide: a private address is not refused by it.
	require.True(t, netaddr.Allowed(mustAddr("10.1.2.3")))
}

func TestEnvProxyIgnored(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("direct")) }))
	defer s.Close()
	var proxied atomic.Int32
	p := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxied.Add(1) }))
	defer p.Close()
	t.Setenv("HTTPS_PROXY", p.URL)
	t.Setenv("https_proxy", p.URL)
	t.Setenv("ALL_PROXY", p.URL)
	t.Setenv("NO_PROXY", "")
	c, err := New(serverPEM(t, s), Options{})
	require.NoError(t, err)
	res, err := get(t, c, s.URL)
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Zero(t, proxied.Load())
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer s.Close()
	defer close(release)
	c, err := New(serverPEM(t, s), Options{Timeout: 150 * time.Millisecond})
	require.NoError(t, err)
	start := time.Now()
	err = getErr(t, c, s.URL)
	require.Error(t, err)
	require.Less(t, time.Since(start), 3*time.Second)
	d, _ := New("", Options{})
	require.Equal(t, Timeout, d.Timeout)
}

func TestNoKeepAliveAndTLS(t *testing.T) {
	c, _ := New("", Options{})
	tr := c.Transport.(roundTripper).next.(*http.Transport)
	require.True(t, tr.DisableKeepAlives)
	require.Nil(t, tr.Proxy)
	require.EqualValues(t, 0x0303, tr.TLSClientConfig.MinVersion)
	require.False(t, tr.TLSClientConfig.InsecureSkipVerify)
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// getErr runs a request that must not produce a usable answer and returns its error.
func getErr(t *testing.T, c *http.Client, url string) error {
	t.Helper()
	res, err := get(t, c, url)
	if res != nil {
		_ = res.Body.Close()
	}
	return err
}
