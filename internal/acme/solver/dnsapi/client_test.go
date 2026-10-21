package dnsapi

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
)

// tlsServer is an httptest TLS server (its certificate names example.com) and a client mapped to it.
func tlsServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	c, err := NewHTTPClient(HTTPOptions{Hosts: []string{"Example.com"}, Roots: pool, MapAddr: func(hp string) string {
		if asciiLower(hp) == "example.com:443" {
			return addr
		}
		return hp
	}})
	require.NoError(t, err)
	return srv, c
}

func get(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	require.NoError(t, err)
	return req
}

func TestDoReadsTheAnswer(t *testing.T) {
	var ua string
	_, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Header().Set("X-Test", "1")
		_, _ = w.Write([]byte("hello"))
	})
	status, h, body, err := Do(context.Background(), c, get(t, "https://example.com/path?q=1"), "a.example")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "1", h.Get("X-Test"))
	assert.Equal(t, "hello", string(body))
	assert.Equal(t, UserAgent, ua)
	// An explicit port 443 is the same host.
	status, _, _, err = Do(context.Background(), c, get(t, "https://EXAMPLE.com:443/"), "a.example")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
}

func TestDoNeverFollowsARedirect(t *testing.T) {
	_, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.test/", http.StatusFound)
	})
	status, _, _, err := Do(context.Background(), c, get(t, "https://example.com/"), "a.example")
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, status)
}

func TestTheGuardRefusesOtherDestinations(t *testing.T) {
	_, c := tlsServer(t, func(http.ResponseWriter, *http.Request) { t.Error("nothing may arrive") })
	for _, raw := range []string{"https://other.example/", "http://example.com/", "https://example.com:8443/", "https://user:pw@example.com/"} {
		_, _, _, err := Do(context.Background(), c, get(t, raw), "a.example")
		var ae *acme.Error
		require.ErrorAs(t, err, &ae, raw)
		assert.Equal(t, acme.ReasonDNSProviderError, ae.Reason, raw)
		assert.NotErrorIs(t, err, acme.ErrDNSProviderUnreachable, "a refused destination is a setting: %s", raw)
		assert.NotContains(t, err.Error(), "example.com", raw)
	}
	// A Host header that names another host.
	req := get(t, "https://example.com/")
	req.Host = "other.example"
	_, _, _, err := Do(context.Background(), c, req, "a.example")
	require.Error(t, err)
	// A body on a refused request is closed.
	body := &closeRecorder{Reader: strings.NewReader("x")}
	req, err = http.NewRequest(http.MethodPost, "https://other.example/", body)
	require.NoError(t, err)
	res, err := c.Transport.RoundTrip(req)
	if res != nil {
		_ = res.Body.Close()
	}
	assert.ErrorIs(t, err, ErrHostNotAllowed)
	assert.True(t, body.closed)
}

type closeRecorder struct {
	*strings.Reader
	closed bool
}

func (c *closeRecorder) Close() error { c.closed = true; return nil }

func TestAnswersAreCapped(t *testing.T) {
	_, c := tlsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, MaxResponseBytes+10))
	})
	_, _, _, err := Do(context.Background(), c, get(t, "https://example.com/"), "a.example")
	var ae *acme.Error
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, http.StatusOK, ae.Status)
	assert.NotErrorIs(t, err, acme.ErrDNSProviderUnreachable)
}

func TestUnreachableAndCancelled(t *testing.T) {
	srv, c := tlsServer(t, func(http.ResponseWriter, *http.Request) {})
	srv.Close()
	_, _, _, err := Do(context.Background(), c, get(t, "https://example.com/"), "a.example")
	assert.ErrorIs(t, err, acme.ErrDNSProviderUnreachable)
	assert.Equal(t, acme.ClassTransient, acme.FailureClass(err))
	assert.NotContains(t, err.Error(), "127.0.0.1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = Do(ctx, c, get(t, "https://example.com/"), "a.example")
	assert.ErrorIs(t, err, context.Canceled)
}

func TestTheSystemRootsDoNotTrustTheTestServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c, err := NewHTTPClient(HTTPOptions{Hosts: []string{"example.com"}})
	require.NoError(t, err)
	req := get(t, srv.URL)
	_, _, _, err = Do(context.Background(), c, req, "a.example")
	require.Error(t, err, "127.0.0.1 is not an allowed host")
}

func TestAMappingNeedsRoots(t *testing.T) {
	_, err := NewHTTPClient(HTTPOptions{Hosts: []string{"example.com"}, MapAddr: func(s string) string { return s }})
	assert.ErrorIs(t, err, ErrMapNeedsRoots)
	assert.Equal(t, "x:1", TestMappedAddr("x:1"), "no mapping outside the integration seam")
}

func TestLimitedBody(t *testing.T) {
	b := &limitedBody{r: strings.NewReader("abc"), c: nopCloser{}}
	buf := make([]byte, 8)
	n, err := b.Read(buf)
	assert.Equal(t, 3, n)
	require.NoError(t, err)
	require.NoError(t, b.Close())
	b = &limitedBody{r: strings.NewReader("abc"), c: nopCloser{}, n: MaxResponseBytes}
	_, err = b.Read(buf)
	assert.True(t, errors.Is(err, ErrTooLarge))
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func srvPool(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}
