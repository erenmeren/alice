package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver"
	"alice/internal/acme/transport"
	"alice/internal/testutil/fakeacme"
)

func testCtx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

func startFake(t *testing.T, opts fakeacme.Options) *fakeacme.Server {
	t.Helper()
	s, err := fakeacme.New(opts)
	require.NoError(t, err)
	require.NoError(t, s.Start())
	t.Cleanup(s.Close)
	return s
}

// guarded is the real guarded transport trusting only the fake's TLS CA on top of the system roots.
func guarded(t *testing.T, s *fakeacme.Server) *http.Client {
	t.Helper()
	hc, err := transport.New(string(s.CAPEM()))
	require.NoError(t, err)
	return hc
}

func p256(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func newTestClient(t *testing.T, s *fakeacme.Server, mut ...func(*Config)) *Client {
	t.Helper()
	cfg := Config{DirectoryURL: s.DirectoryURL(), Key: p256(t), HTTPClient: guarded(t, s), Contact: "admin@example.test"}
	for _, m := range mut {
		m(&cfg)
	}
	c, err := New(cfg)
	require.NoError(t, err)
	return c
}

func registered(t *testing.T, s *fakeacme.Server, mut ...func(*Config)) *Client {
	t.Helper()
	c := newTestClient(t, s, mut...)
	_, err := c.RegisterAccount(testCtx(t), "", nil, true)
	require.NoError(t, err)
	return c
}

// csrFor makes a P-256 CSR for names (the first is not special: all are SANs).
func csrFor(t *testing.T, names ...string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	k := p256(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, k)
	require.NoError(t, err)
	return der, k
}

// webSolver is the in-memory solver serving HTTP-01 from an httptest server the fake is pointed at, and
// publishing DNS-01 values into the fake's DNS table.
type webSolver struct {
	*solver.Memory
	srv *httptest.Server
}

func newWebSolver(t *testing.T, s *fakeacme.Server, types ...string) *webSolver {
	t.Helper()
	m := solver.NewMemory(types...)
	m.AfterPresent = func(_ context.Context, ch solver.Challenge) error {
		if ch.Type == solver.DNS01 {
			s.DNSSet(ch.DNSName, ch.DNSValue)
		}
		return nil
	}
	m.AfterCleanUp = func(_ context.Context, ch solver.Challenge) error {
		if ch.Type == solver.DNS01 {
			s.DNSClear(ch.DNSName, ch.DNSValue)
		}
		return nil
	}
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return &webSolver{Memory: m, srv: srv}
}

// route maps every name's HTTP-01 probe to the solver's web server.
func (w *webSolver) route(s *fakeacme.Server, names ...string) {
	addr := strings.TrimPrefix(w.srv.URL, "http://")
	for _, n := range names {
		s.SetHTTPTarget(strings.TrimPrefix(n, "*."), addr)
	}
}

// recorder collects OnPresent and OnCleanUp callbacks.
type recorder struct {
	mu        sync.Mutex
	presented []solver.Challenge
	cleaned   []solver.Challenge
}

func (r *recorder) opts() []OrderOption {
	return []OrderOption{
		WithOnPresent(func(ch solver.Challenge) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.presented = append(r.presented, ch)
			return nil
		}),
		WithOnCleanUp(func(ch solver.Challenge, _ error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.cleaned = append(r.cleaned, ch)
		}),
	}
}
