package http01

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/transport"
	"alice/internal/platform/netaddr/netaddrtest"
	"alice/internal/providers/linuxssh"
	"alice/internal/testutil/fakeacme"
)

// The linuxssh connection is the production publisher (Task 10 adapts it).
var _ Publisher = (*linuxssh.Conn)(nil)

// webroot is a fake publisher: the files it holds are served by an httptest server (the "web server").
type webroot struct {
	mu        sync.Mutex
	files     map[string]string
	published []string
	removed   []string
	pubErr    error
	rmErr     error
	srv       *httptest.Server
	hits      atomic.Int64
	handler   http.HandlerFunc // replaces the file server when set
}

func newWebroot(t *testing.T) *webroot {
	t.Helper()
	w := &webroot{files: map[string]string{}}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.hits.Add(1)
		if w.handler != nil {
			w.handler(rw, r)
			return
		}
		tok, ok := strings.CutPrefix(r.URL.Path, solver.HTTPPathPrefix)
		w.mu.Lock()
		body, found := w.files[tok]
		w.mu.Unlock()
		if !ok || !found {
			http.NotFound(rw, r)
			return
		}
		_, _ = rw.Write([]byte(body))
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *webroot) PublishHTTP01Token(_ context.Context, token string, ka []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.published = append(w.published, token)
	if w.pubErr != nil {
		return w.pubErr
	}
	w.files[token] = string(ka)
	return nil
}

func (w *webroot) RemoveHTTP01Token(ctx context.Context, token string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.removed = append(w.removed, token)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if w.rmErr != nil {
		return false, w.rmErr
	}
	_, ok := w.files[token]
	delete(w.files, token)
	return ok, nil
}

func (w *webroot) port(t *testing.T) int {
	t.Helper()
	_, p, err := net.SplitHostPort(w.srv.Listener.Addr().String())
	require.NoError(t, err)
	n, err := strconv.Atoi(p)
	require.NoError(t, err)
	return n
}

// loopback resolves every name to 127.0.0.1 (names in .test are not in /etc/hosts); resolved counts lookups.
func loopback(resolved *atomic.Int64) *net.Resolver {
	return netaddrtest.Resolver(func(string) []netip.Addr {
		if resolved != nil {
			resolved.Add(1)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	})
}

func newSolver(t *testing.T, w *webroot, mut ...func(*Config)) *Solver {
	t.Helper()
	cfg := Config{Publisher: w, AllowedSuffixes: []string{"example.test"}, VerifyAttempts: 3, VerifyInterval: MinVerifyInterval}
	for _, m := range mut {
		m(&cfg)
	}
	s, err := New(cfg)
	require.NoError(t, err)
	s.port, s.resolver = w.port(t), loopback(nil)
	return s
}

var (
	tok   = strings.Repeat("T", 43)
	thumb = strings.Repeat("h", 42) + "_"
)

func chal(domain string) solver.Challenge {
	return solver.Challenge{Type: solver.HTTP01, Domain: domain, Token: tok, KeyAuth: tok + "." + thumb, HTTPPath: solver.HTTPPathPrefix + tok}
}

func ctx5(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestNewValidates(t *testing.T) {
	w := &webroot{}
	for name, c := range map[string]struct {
		cfg  Config
		want error
	}{
		"no publisher":      {Config{}, ErrNoPublisher},
		"bad suffix":        {Config{Publisher: w, AllowedSuffixes: []string{"*.example.test"}}, ErrSuffix},
		"trailing dot":      {Config{Publisher: w, AllowedSuffixes: []string{"example.test."}}, ErrSuffix},
		"empty suffix":      {Config{Publisher: w, AllowedSuffixes: []string{""}}, ErrSuffix},
		"attempts high":     {Config{Publisher: w, VerifyAttempts: MaxVerifyAttempts + 1}, ErrVerify},
		"attempts low":      {Config{Publisher: w, VerifyAttempts: -1}, ErrVerify},
		"interval low":      {Config{Publisher: w, VerifyInterval: time.Millisecond}, ErrVerify},
		"interval high":     {Config{Publisher: w, VerifyInterval: MaxVerifyInterval + time.Second}, ErrVerify},
		"interval negative": {Config{Publisher: w, VerifyInterval: -time.Second}, ErrVerify},
	} {
		_, err := New(c.cfg)
		assert.ErrorIs(t, err, c.want, name)
	}
	s, err := New(Config{Publisher: w})
	require.NoError(t, err)
	assert.Equal(t, DefaultVerifyAttempts, s.attempts)
	assert.Equal(t, DefaultVerifyInterval, s.interval)
	assert.Equal(t, 80, s.port)
	assert.Equal(t, []string{solver.HTTP01}, s.Types())
	// The whole check fits the ACME client's per-call deadline, under which Present runs.
	assert.Less(t, time.Duration(MaxVerifyAttempts)*(FetchTimeout+MaxVerifyInterval), acme.DefaultCallTimeout)
}

func TestPresentPublishesVerifiesAndCleansUp(t *testing.T) {
	w := newWebroot(t)
	var lookups atomic.Int64
	s := newSolver(t, w)
	s.resolver = loopback(&lookups)
	var hostSeen, uaSeen string
	w.handler = func(rw http.ResponseWriter, r *http.Request) {
		hostSeen, uaSeen = r.Host, r.UserAgent()
		w.mu.Lock()
		body := w.files[strings.TrimPrefix(r.URL.Path, solver.HTTPPathPrefix)]
		w.mu.Unlock()
		_, _ = rw.Write([]byte(body))
	}
	require.NoError(t, s.Present(ctx5(t), chal("WWW.Example.Test.")))
	assert.Equal(t, []string{tok}, w.published)
	assert.Equal(t, "www.example.test", hostSeen, "the Host header is the name")
	assert.Equal(t, UserAgent, uaSeen)
	assert.Positive(t, lookups.Load(), "the name is resolved and dialed through netaddr")
	require.NoError(t, s.CleanUp(ctx5(t), chal("www.example.test")))
	assert.Empty(t, w.files)
	require.NoError(t, s.CleanUp(ctx5(t), chal("www.example.test")), "a missing file is success")
}

func TestVerificationRetriesUntilServed(t *testing.T) {
	w := newWebroot(t)
	s := newSolver(t, w, func(c *Config) { c.VerifyAttempts = 4 })
	var n atomic.Int64
	w.handler = func(rw http.ResponseWriter, _ *http.Request) {
		if n.Add(1) < 3 {
			http.NotFound(rw, nil)
			return
		}
		_, _ = rw.Write([]byte(tok + "." + thumb))
	}
	var slept []time.Duration
	s.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	require.NoError(t, s.Present(ctx5(t), chal("a.example.test")))
	assert.Equal(t, int64(3), n.Load())
	assert.Equal(t, []time.Duration{MinVerifyInterval, MinVerifyInterval}, slept)
}

func TestVerificationFailures(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"mismatch": func(rw http.ResponseWriter, _ *http.Request) {
			_, _ = rw.Write([]byte(tok + "." + strings.Repeat("x", 43)))
		},
		"trailing":   func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(tok + "." + thumb + "\n")) },
		"not found":  func(rw http.ResponseWriter, r *http.Request) { http.NotFound(rw, r) },
		"server err": func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusInternalServerError) },
		"oversize": func(rw http.ResponseWriter, _ *http.Request) {
			_, _ = rw.Write([]byte(tok + "." + thumb + strings.Repeat(" ", MaxBodyBytes)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWebroot(t)
			w.handler = h
			s := newSolver(t, w)
			err := s.Present(ctx5(t), chal("a.example.test"))
			assert.Equal(t, acme.ReasonValidationFailedHTTP, acme.ReasonOf(err))
			assert.ErrorIs(t, err, ErrNotServed)
			assert.Equal(t, int64(3), w.hits.Load(), "bounded attempts")
			assert.NotContains(t, err.Error(), "http://", "no URL in the error")
			assert.NotContains(t, err.Error(), thumb, "no body in the error")
		})
	}
}

func TestRedirectIsRefusedAndNotFollowed(t *testing.T) {
	target := newWebroot(t)
	w := newWebroot(t)
	w.handler = func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, target.srv.URL+r.URL.Path, http.StatusFound)
	}
	s := newSolver(t, w)
	err := s.Present(ctx5(t), chal("a.example.test"))
	assert.Equal(t, acme.ReasonValidationFailedHTTP, acme.ReasonOf(err))
	assert.ErrorIs(t, err, ErrRedirected)
	assert.Zero(t, target.hits.Load(), "the redirect is never followed")
	assert.NotContains(t, err.Error(), target.srv.URL)
}

func TestUnreachableAndRefusedAddresses(t *testing.T) {
	w := newWebroot(t)
	s := newSolver(t, w, func(c *Config) { c.VerifyAttempts = 1 })
	s.resolver = netaddrtest.Resolver(func(string) []netip.Addr { return []netip.Addr{netip.MustParseAddr("169.254.169.254")} })
	err := s.Present(ctx5(t), chal("a.example.test"))
	assert.Equal(t, acme.ReasonValidationFailedHTTP, acme.ReasonOf(err), "netaddr refuses the metadata address")
	assert.Zero(t, w.hits.Load())
	s.resolver = loopback(nil)
	w.srv.Close()
	err = s.Present(ctx5(t), chal("a.example.test"))
	assert.Equal(t, acme.ReasonValidationFailedHTTP, acme.ReasonOf(err))
}

func TestNotAllowedNameNeverPublishesOrDials(t *testing.T) {
	for _, d := range []string{"example.org", "badexample.test", "example.test.evil", "a..example.test", "-a.example.test", "a_b.example.test"} {
		w := newWebroot(t)
		var lookups atomic.Int64
		s := newSolver(t, w)
		s.resolver = loopback(&lookups)
		err := s.Present(ctx5(t), chal(d))
		assert.Equal(t, acme.ReasonNameNotAllowed, acme.ReasonOf(err), d)
		assert.Empty(t, w.published, d)
		assert.Zero(t, lookups.Load(), d)
		assert.Zero(t, w.hits.Load(), d)
		require.NoError(t, s.CleanUp(ctx5(t), chal(d)))
		assert.Empty(t, w.removed, "nothing was published, nothing is removed")
	}
	w := newWebroot(t)
	s := newSolver(t, w, func(c *Config) { c.AllowedSuffixes = nil })
	assert.Equal(t, acme.ReasonNameNotAllowed, acme.ReasonOf(s.Present(ctx5(t), chal("a.example.test"))), "empty list refuses all")
	s = newSolver(t, w, func(c *Config) { c.AllowedSuffixes = []string{".example.test"} })
	assert.Equal(t, acme.ReasonNameNotAllowed, acme.ReasonOf(s.Present(ctx5(t), chal("example.test"))), "subdomains only")
	require.NoError(t, s.Present(ctx5(t), chal("a.example.test")))
}

func TestChallengeShapeRefused(t *testing.T) {
	w := newWebroot(t)
	s := newSolver(t, w)
	mk := func(f func(*solver.Challenge)) solver.Challenge { c := chal("a.example.test"); f(&c); return c }
	for name, c := range map[string]solver.Challenge{
		"wildcard flag":    mk(func(c *solver.Challenge) { c.Wildcard = true }),
		"wildcard name":    mk(func(c *solver.Challenge) { c.Domain = "*.example.test" }),
		"dns-01":           mk(func(c *solver.Challenge) { c.Type = solver.DNS01 }),
		"short token":      mk(func(c *solver.Challenge) { c.Token = strings.Repeat("a", 21); c.KeyAuth = c.Token + "." + thumb }),
		"long token":       mk(func(c *solver.Challenge) { c.Token = strings.Repeat("a", 129); c.KeyAuth = c.Token + "." + thumb }),
		"traversal token":  mk(func(c *solver.Challenge) { c.Token = "../../../../etc/" + strings.Repeat("a", 22) }),
		"key auth other":   mk(func(c *solver.Challenge) { c.KeyAuth = strings.Repeat("U", 43) + "." + thumb }),
		"key auth newline": mk(func(c *solver.Challenge) { c.KeyAuth += "\n" }),
		"key auth charset": mk(func(c *solver.Challenge) { c.KeyAuth = tok + "." + thumb[:42] + "/" }),
		"path mismatch":    mk(func(c *solver.Challenge) { c.HTTPPath = "/x" }),
	} {
		err := s.Present(ctx5(t), c)
		assert.Equal(t, acme.ReasonChallengeUnavailable, acme.ReasonOf(err), name)
		assert.NoError(t, s.CleanUp(ctx5(t), c), name)
	}
	assert.Empty(t, w.published)
	assert.Empty(t, w.removed)
	assert.Zero(t, w.hits.Load())
}

// outdated mimics linuxssh's error without the import (the real one is checked below).
type outdated struct{}

func (outdated) Error() string              { return "old helper" }
func (outdated) HTTP01HelperOutdated() bool { return true }

func TestPublisherErrorMapping(t *testing.T) {
	remote := errors.New("helper said: PATH_NOT_ALLOWED /var/www secret-ish text")
	for name, c := range map[string]struct {
		err    error
		reason string
	}{
		"helper refused":      {remote, acme.ReasonValidationFailedHTTP},
		"helper outdated":     {outdated{}, acme.ReasonChallengeUnavailable},
		"wrapped outdated":    {errors.Join(errors.New("x"), outdated{}), acme.ReasonChallengeUnavailable},
		"linuxssh's outdated": {linuxssh.ErrHTTP01HelperOutdated, acme.ReasonChallengeUnavailable},
	} {
		w := newWebroot(t)
		w.pubErr = c.err
		s := newSolver(t, w)
		err := s.Present(ctx5(t), chal("a.example.test"))
		assert.Equal(t, c.reason, acme.ReasonOf(err), name)
		assert.ErrorIs(t, err, c.err, "%s: the cause stays reachable for the reinstall message", name)
		assert.NotContains(t, err.Error(), "secret-ish", name)
		assert.Zero(t, w.hits.Load(), "%s: nothing to fetch", name)
	}
	w := newWebroot(t)
	w.pubErr = linuxssh.ErrHTTP01HelperOutdated
	err := newSolver(t, w).Present(ctx5(t), chal("a.example.test"))
	assert.ErrorIs(t, err, linuxssh.ErrHTTP01HelperOutdated)
}

func TestCancelledContexts(t *testing.T) {
	w := newWebroot(t)
	w.pubErr = errors.New("aborted")
	s := newSolver(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, s.Present(ctx, chal("a.example.test")), context.Canceled)

	w2 := newWebroot(t)
	w2.handler = func(rw http.ResponseWriter, r *http.Request) { http.NotFound(rw, r) }
	s2 := newSolver(t, w2)
	ctx2, cancel2 := context.WithCancel(context.Background())
	s2.sleep = func(context.Context, time.Duration) error { cancel2(); return context.Canceled }
	assert.ErrorIs(t, s2.Present(ctx2, chal("a.example.test")), context.Canceled)
	// CleanUp runs with its own context even after the order's was cancelled.
	require.NoError(t, s2.CleanUp(ctx2, chal("a.example.test")))
	assert.Equal(t, []string{tok}, w2.removed)
}

func TestCleanUpAfterFailedPresentAndRemoveError(t *testing.T) {
	w := newWebroot(t)
	w.handler = func(rw http.ResponseWriter, r *http.Request) { http.NotFound(rw, r) }
	s := newSolver(t, w)
	require.Error(t, s.Present(ctx5(t), chal("a.example.test")))
	require.NoError(t, s.CleanUp(ctx5(t), chal("a.example.test")))
	assert.Empty(t, w.files, "the published file is removed after a failed check")
	w.rmErr = outdated{}
	err := s.CleanUp(ctx5(t), chal("a.example.test"))
	assert.Equal(t, acme.ReasonChallengeUnavailable, acme.ReasonOf(err))
	w.rmErr = errors.New("io")
	err = s.CleanUp(ctx5(t), chal("a.example.test"))
	assert.Equal(t, acme.ReasonValidationFailedHTTP, acme.ReasonOf(err))
	assert.ErrorIs(t, err, ErrPublish)
}

func TestSleepCtx(t *testing.T) {
	require.NoError(t, sleepCtx(context.Background(), time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, sleepCtx(ctx, time.Hour), context.Canceled)
}

// ---- end to end: the ACME client against the fake CA, which validates through the same web server ----

func TestEndToEndOrderThroughFakeCA(t *testing.T) {
	f, err := fakeacme.New(fakeacme.Options{})
	require.NoError(t, err)
	require.NoError(t, f.Start())
	t.Cleanup(f.Close)
	require.NoError(t, f.SetChallenges(fakeacme.HTTP01))
	w := newWebroot(t)
	f.SetHTTPTarget("www.example.test", w.srv.Listener.Addr().String())
	f.SetHTTPTarget("example.test", w.srv.Listener.Addr().String())
	s := newSolver(t, w)

	hc, err := transport.New(string(f.CAPEM()))
	require.NoError(t, err)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cl, err := acme.New(acme.Config{DirectoryURL: f.DirectoryURL(), Key: k, HTTPClient: hc, Contact: "admin@example.test"})
	require.NoError(t, err)
	_, err = cl.RegisterAccount(ctx5(t), "", nil, true)
	require.NoError(t, err)
	names := []string{"www.example.test", "example.test"}
	ck, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, ck)
	require.NoError(t, err)

	chain, err := cl.Order(ctx5(t), names, der, s)
	require.NoError(t, err)
	assert.NotEmpty(t, chain)
	assert.Len(t, w.published, 2)
	assert.Len(t, w.removed, 2)
	assert.Empty(t, w.files, "every token file was removed")
	assert.GreaterOrEqual(t, f.Counters()["http-01-dials"], 2, "the CA validated through the web server")

	// A name outside the allow-list fails before anything is published; a wildcard never reaches the solver.
	_, err = cl.Order(ctx5(t), []string{"other.test"}, csr(t, "other.test"), s)
	assert.Equal(t, acme.ReasonNameNotAllowed, acme.ReasonOf(err))
	_, err = cl.Order(ctx5(t), []string{"*.example.test"}, csr(t, "*.example.test"), s)
	assert.Equal(t, acme.ReasonChallengeUnavailable, acme.ReasonOf(err))
	assert.Len(t, w.published, 2)

	// The file is published but not served: Alice's own check fails, the CA is never asked, the file goes.
	w.handler = func(rw http.ResponseWriter, r *http.Request) { http.NotFound(rw, r) }
	_, err = cl.Order(ctx5(t), []string{"example.test"}, csr(t, "example.test"), s)
	assert.Equal(t, acme.ReasonValidationFailedHTTP, acme.ReasonOf(err))
	assert.Empty(t, w.files, "cleaned up after the failure")
}

func csr(t *testing.T, names ...string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, k)
	require.NoError(t, err)
	return der
}
