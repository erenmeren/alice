package lestaging

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/acme/solver"
	"alice/internal/acme/transport"
)

func acmeErr(reason string) error { return &acme.Error{Reason: reason} }

func TestFromEnvSkipsWhenNotConfigured(t *testing.T) {
	_, err := FromEnv(env{}.get)
	var skip *SkipError
	require.ErrorAs(t, err, &skip)
	assert.Contains(t, skip.Error(), EnvDomain)
	assert.Contains(t, skip.Error(), EnvAcceptTOS)

	_, err = FromEnv(env{EnvDomain: "a.example.com", EnvAcceptTOS: "yes", EnvChallenge: "dns-01"}.get)
	require.ErrorAs(t, err, &skip)
	assert.Equal(t, []string{EnvDNSProvider + " (or " + EnvDNSHookURL + ")"}, skip.Missing)
}

func TestFromEnvDefaultsToStagingAndHTTP01(t *testing.T) {
	dir := t.TempDir()
	cfg, err := FromEnv(env{EnvDomain: "A.Example.com.", EnvAcceptTOS: "YES", EnvStateDir: dir}.get)
	require.NoError(t, err)
	assert.Equal(t, StagingDirectory, cfg.DirectoryURL)
	assert.True(t, cfg.ExpectStaging)
	assert.Equal(t, solver.HTTP01, cfg.Challenge)
	assert.Equal(t, DefaultHTTP01Listen, cfg.HTTP01Listen)
	assert.Equal(t, keygen.Default, cfg.KeyType)
	assert.Equal(t, filepath.Join(dir, "acme-staging-v02.api.letsencrypt.org"), cfg.StateDir)
	assert.Equal(t, []string{"A.Example.com"}, cfg.Names())
	assert.Nil(t, cfg.RootsPEM, "fetched at run time")
}

func TestFromEnvRefusesProductionWithoutTheFlag(t *testing.T) {
	base := env{EnvDomain: "a.example.com", EnvAcceptTOS: "1", EnvStateDir: t.TempDir(),
		EnvDirectory: "https://acme-v02.api.letsencrypt.org/directory"}
	_, err := FromEnv(base.get)
	require.ErrorIs(t, err, ErrProduction)
	base[EnvDirectory] = "https://ACME-V02.api.letsencrypt.org./directory"
	_, err = FromEnv(base.get)
	require.ErrorIs(t, err, ErrProduction)
	base[EnvAllowProduction] = "yes"
	cfg, err := FromEnv(base.get)
	require.NoError(t, err)
	assert.False(t, cfg.ExpectStaging)
	assert.Nil(t, cfg.RootsPEM, "production: the system roots")
}

func TestFromEnvRefusesWrongValues(t *testing.T) {
	roots := filepath.Join(t.TempDir(), "roots.pem")
	require.NoError(t, os.WriteFile(roots, []byte("x"), 0o600))
	ok := func(extra env) env {
		e := env{EnvDomain: "a.example.com", EnvAcceptTOS: "on", EnvStateDir: t.TempDir()}
		for k, v := range extra {
			e[k] = v
		}
		return e
	}
	for name, e := range map[string]env{
		"http directory":       ok(env{EnvDirectory: "http://ca.example.com/dir"}),
		"bad name":             ok(env{EnvDomain: "not_a_name"}),
		"wildcard domain":      ok(env{EnvDomain: "*.a.example.com"}),
		"bad challenge":        ok(env{EnvChallenge: "tls-alpn-01"}),
		"wildcard over http":   ok(env{EnvWildcard: "yes"}),
		"unknown provider":     ok(env{EnvChallenge: "dns-01", EnvDNSProvider: "nope"}),
		"bad key type":         ok(env{EnvKeyType: "dsa"}),
		"custom without roots": ok(env{EnvDirectory: "https://ca.example.com/dir"}),
		"missing roots file":   ok(env{EnvRootsFile: "/nonexistent/roots.pem"}),
		"missing CA file":      ok(env{EnvCAFile: "/nonexistent/ca.pem"}),
		"bad manual timeout":   ok(env{EnvChallenge: "dns-01", EnvDNSProvider: "manual", EnvDNSManualWait: "soon"}),
	} {
		_, err := FromEnv(e.get)
		require.Error(t, err, name)
		var skip *SkipError
		assert.False(t, errors.As(err, &skip), name)
	}
	cfg, err := FromEnv(ok(env{EnvDirectory: "https://ca.example.com/dir", EnvRootsFile: roots, EnvCAFile: roots,
		EnvChallenge: "dns-01", EnvWildcard: "true", EnvDNSHookURL: "https://hook.example.com", EnvKeyType: "rsa_2048",
		EnvDeactivate: "1"}).get)
	require.NoError(t, err)
	assert.Equal(t, "hook", cfg.DNSProvider)
	assert.Equal(t, []string{"a.example.com", "*.a.example.com"}, cfg.Names())
	assert.Equal(t, []byte("x"), cfg.RootsPEM)
	assert.Equal(t, "x", cfg.CABundlePEM)
	assert.Equal(t, keygen.RSA2048, cfg.KeyType)
	assert.True(t, cfg.Deactivate)
	assert.False(t, cfg.ExpectStaging)
}

func TestFromEnvManualProviderStretchesTheBudgets(t *testing.T) {
	cfg, err := FromEnv(env{EnvDomain: "a.example.com", EnvAcceptTOS: "yes", EnvStateDir: t.TempDir(), EnvChallenge: "dns-01",
		EnvDNSProvider: "manual", EnvWildcard: "yes", EnvDNSManualWait: "15m"}.get)
	require.NoError(t, err)
	assert.Equal(t, 17*time.Minute, cfg.CallTimeout)
	assert.Equal(t, 44*time.Minute, cfg.OrderTimeout)
}

func TestStateDirDefaultsToTheCacheDirectory(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	d, err := stateDir("", "https://ca.example.com:8443/dir")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(os.Getenv("XDG_CACHE_HOME"), "alice-le-staging", "ca.example.com_8443"), d)
}

func TestDurationEnv(t *testing.T) {
	d, err := durationEnv(env{"X": "90"}.get, "X", time.Second)
	require.NoError(t, err)
	assert.Equal(t, 90*time.Second, d)
	d, err = durationEnv(env{"X": "2m"}.get, "X", time.Second)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, d)
	d, err = durationEnv(env{}.get, "X", time.Second)
	require.NoError(t, err)
	assert.Equal(t, time.Second, d)
	_, err = durationEnv(env{"X": "-1m"}.get, "X", time.Second)
	require.Error(t, err)
}

// pki is a tiny staging-like hierarchy: a self-signed root, an intermediate and a leaf.
type pki struct {
	root, inter, leaf *x509.Certificate
	rootPEM           []byte
}

func newPKI(t *testing.T, interCN string, names ...string) pki {
	t.Helper()
	now := time.Now()
	mk := func(tmpl, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		require.NoError(t, err)
		c, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return c
	}
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return k
	}
	rk, ik, lk := key(), key(), key()
	ca := func(cn string, serial int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	}
	root := mk(ca("(STAGING) Test Root X9", 1), ca("(STAGING) Test Root X9", 1), &rk.PublicKey, rk)
	inter := mk(ca(interCN, 2), root, &ik.PublicKey, rk)
	leaf := mk(&x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: names, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, inter, &lk.PublicKey, ik)
	return pki{root: root, inter: inter, leaf: leaf, rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})}
}

func TestVerifyChain(t *testing.T) {
	names := []string{"a.example.com", "*.a.example.com"}
	p := newPKI(t, "(STAGING) Test Intermediate E9", names...)
	chain := [][]byte{p.leaf.Raw, p.inter.Raw}
	roots := []*x509.Certificate{p.root}
	rep, err := verifyChain(chain, roots, []string{"*.A.example.com", "a.example.com"}, true, time.Now())
	require.NoError(t, err)
	assert.Equal(t, []string{"", "(STAGING) Test Intermediate E9", "(STAGING) Test Root X9"}, rep.path)

	_, err = verifyChain(nil, roots, names, true, time.Now())
	require.Error(t, err)
	_, err = verifyChain([][]byte{p.leaf.Raw, []byte("junk")}, roots, names, true, time.Now())
	require.ErrorContains(t, err, "does not parse")
	_, err = verifyChain(chain, roots, names[:1], true, time.Now())
	require.ErrorContains(t, err, "the leaf names")
	_, err = verifyChain(chain, roots, names, true, time.Now().Add(48*time.Hour))
	require.ErrorContains(t, err, "expected roots")
	other := newPKI(t, "(STAGING) Other E9", names...)
	_, err = verifyChain(chain, []*x509.Certificate{other.root}, names, true, time.Now())
	require.ErrorContains(t, err, "expected roots")

	prod := newPKI(t, "Real Intermediate E9", names...)
	_, err = verifyChain([][]byte{prod.leaf.Raw, prod.inter.Raw}, []*x509.Certificate{prod.root}, names, true, time.Now())
	require.ErrorContains(t, err, "not a staging CA")
	_, err = verifyChain([][]byte{prod.leaf.Raw, prod.inter.Raw}, []*x509.Certificate{prod.root}, names, false, time.Now())
	require.NoError(t, err)
	assert.False(t, sameNameSet([]string{"a", "a"}, []string{"a", "b"}))
}

func TestFetchRoots(t *testing.T) {
	p := newPKI(t, "(STAGING) I", "a.example.com")
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.inter.Raw})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/root.pem":
			_, _ = w.Write(append([]byte("# comment\n"), p.rootPEM...))
		case "/inter.pem":
			_, _ = w.Write(interPEM)
		case "/two.pem":
			_, _ = w.Write(append(append([]byte(nil), p.rootPEM...), p.rootPEM...))
		case "/key.pem":
			_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}))
		case "/big.pem":
			_, _ = w.Write(bytes.Repeat([]byte("a"), maxRootBytes+1))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	hc, err := transport.New(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	require.NoError(t, err)
	ctx := context.Background()
	got, err := fetchRoots(ctx, hc, []string{srv.URL + "/root.pem"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "(STAGING) Test Root X9", got[0].Subject.CommonName)
	for _, path := range []string{"/inter.pem", "/two.pem", "/key.pem", "/big.pem", "/missing.pem"} {
		_, err := fetchRoots(ctx, hc, []string{srv.URL + path})
		require.Error(t, err, path)
	}
	_, err = fetchRoots(ctx, hc, []string{"https://127.0.0.1:1/root.pem"})
	require.Error(t, err)
	_, err = fetchRoots(ctx, hc, []string{"://bad"})
	require.Error(t, err)
	_, err = parseCerts([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	require.Error(t, err)
}

func TestTheRootsStepFetchesTheStagingRoots(t *testing.T) {
	p := newPKI(t, "(STAGING) I", "a.example.com")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(p.rootPEM) }))
	t.Cleanup(srv.Close)
	hc, err := transport.New(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	require.NoError(t, err)
	saved := StagingRootURLs
	t.Cleanup(func() { StagingRootURLs = saved })
	var out bytes.Buffer
	r := &Runner{cfg: Config{ExpectStaging: true}, out: &out, now: time.Now, rootsHTTP: hc, rep: &Report{}}
	StagingRootURLs = []string{srv.URL + "/x1.pem"}
	require.True(t, r.loadRoots(context.Background()))
	assert.Contains(t, out.String(), "[PASS] roots      (STAGING) Test Root X9")
	StagingRootURLs = []string{srv.URL + "/x1.pem", "https://127.0.0.1:1/x2.pem"}
	require.False(t, r.loadRoots(context.Background()))
	assert.Contains(t, out.String(), EnvRootsFile)
	r.cfg.ExpectStaging = false
	require.True(t, r.loadRoots(context.Background()))
	assert.Contains(t, out.String(), "the system's trusted roots")
}

func TestManualSolver(t *testing.T) {
	ch := solver.Challenge{Type: solver.DNS01, Domain: "a.example.com", DNSName: "_acme-challenge.a.example.com", DNSValue: "v4lue"}
	var out bytes.Buffer
	calls := 0
	m := &manualSolver{out: &out, timeout: time.Minute, interval: 10 * time.Second,
		lookup: func(_ context.Context, name string) ([]string, error) {
			calls++
			assert.Equal(t, ch.DNSName, name)
			if calls < 3 {
				return []string{"other"}, nil
			}
			return []string{"other", "v4lue"}, nil
		},
		sleep: func(context.Context, time.Duration) error { return nil }}
	require.NoError(t, m.Present(context.Background(), ch))
	assert.Equal(t, 3, calls)
	assert.Contains(t, out.String(), `_acme-challenge.a.example.com.  TXT  "v4lue"`)
	require.NoError(t, m.CleanUp(context.Background(), ch))
	assert.Contains(t, out.String(), "you may remove the TXT record")
	assert.Equal(t, []string{solver.DNS01}, m.Types())

	m.lookup = func(context.Context, string) ([]string, error) { return nil, errors.New("nxdomain") }
	require.ErrorIs(t, m.Present(context.Background(), ch), ErrRecordNotVisible)
	m.sleep = sleepCtx
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, m.Present(ctx, ch), context.Canceled)
	require.NoError(t, sleepCtx(context.Background(), time.Millisecond))
}

func TestManualProviderSettings(t *testing.T) {
	s, err := manualProvider(DNSParams{Domain: "a.example.com", Getenv: env{EnvDNSResolver: "127.0.0.1:53", EnvDNSManualWait: "30"}.get, Out: io.Discard})
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, s.(*manualSolver).timeout)
	_, err = manualProvider(DNSParams{Getenv: env{EnvDNSResolver: "no-port"}.get})
	require.Error(t, err)
	_, err = manualProvider(DNSParams{Getenv: env{EnvDNSManualWait: "x"}.get})
	require.Error(t, err)
}

func TestHookProviderSettings(t *testing.T) {
	for name, e := range map[string]env{
		"no url":       {EnvDNSHookSecret: "s3cr3t-s3cr3t-s3cr3t"},
		"no secret":    {EnvDNSHookURL: "https://hook.example.com"},
		"missing CA":   {EnvDNSHookURL: "https://hook.example.com", EnvDNSHookSecret: "s3cr3t-s3cr3t-s3cr3t", EnvDNSHookCAFile: "/nonexistent"},
		"bad wait":     {EnvDNSHookURL: "https://hook.example.com", EnvDNSHookSecret: "s3cr3t-s3cr3t-s3cr3t", EnvDNSWait: "x"},
		"bad poll":     {EnvDNSHookURL: "https://hook.example.com", EnvDNSHookSecret: "s3cr3t-s3cr3t-s3cr3t", EnvDNSPollTimeout: "x"},
		"wait too big": {EnvDNSHookURL: "https://hook.example.com", EnvDNSHookSecret: "s3cr3t-s3cr3t-s3cr3t", EnvDNSWait: "10m"},
		"http hook":    {EnvDNSHookURL: "http://hook.example.com", EnvDNSHookSecret: "s3cr3t-s3cr3t-s3cr3t"},
	} {
		_, err := hookProvider(DNSParams{Domain: "a.example.com", Getenv: e.get})
		require.Error(t, err, name)
	}
}

func TestListenPublisherServesOnlyPublishedTokens(t *testing.T) {
	p, err := newListenPublisher("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	ctx := context.Background()
	require.NoError(t, p.PublishHTTP01Token(ctx, "tok", []byte("tok.thumb")))
	get := func(method, path string) (int, string) {
		req, err := http.NewRequestWithContext(ctx, method, "http://"+p.Addr()+path, nil)
		require.NoError(t, err)
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	code, body := get(http.MethodGet, solver.HTTPPathPrefix+"tok")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "tok.thumb", body)
	code, _ = get(http.MethodGet, solver.HTTPPathPrefix+"other")
	assert.Equal(t, http.StatusNotFound, code)
	code, _ = get(http.MethodGet, "/tok")
	assert.Equal(t, http.StatusNotFound, code)
	code, _ = get(http.MethodPost, solver.HTTPPathPrefix+"tok")
	assert.Equal(t, http.StatusNotFound, code)
	removed, err := p.RemoveHTTP01Token(ctx, "tok")
	require.NoError(t, err)
	assert.True(t, removed)
	removed, err = p.RemoveHTTP01Token(ctx, "tok")
	require.NoError(t, err)
	assert.False(t, removed)

	_, err = newListenPublisher(p.Addr())
	require.ErrorContains(t, err, EnvHTTP01Webroot, "a taken port names the alternative")
}

func TestWebrootPublisher(t *testing.T) {
	root := t.TempDir()
	p, err := newWebrootPublisher(root)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, p.PublishHTTP01Token(ctx, "tok", []byte("tok.thumb")))
	b, err := os.ReadFile(filepath.Join(root, ".well-known", "acme-challenge", "tok"))
	require.NoError(t, err)
	assert.Equal(t, "tok.thumb", string(b))
	removed, err := p.RemoveHTTP01Token(ctx, "tok")
	require.NoError(t, err)
	assert.True(t, removed)
	removed, err = p.RemoveHTTP01Token(ctx, "tok")
	require.NoError(t, err)
	assert.False(t, removed)
	require.NoError(t, p.Close())

	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err = newWebrootPublisher(file)
	require.Error(t, err)
}

func TestBuildSolverForHTTP01(t *testing.T) {
	var addr string
	r := &Runner{cfg: Config{Challenge: solver.HTTP01, Domain: "a.example.com", HTTP01Listen: "127.0.0.1:0"}, onListen: func(a string) { addr = a }}
	s, closeIt, err := r.buildSolver()
	require.NoError(t, err)
	assert.Equal(t, []string{solver.HTTP01}, s.Types())
	assert.NotEmpty(t, addr)
	closeIt()

	r.cfg.HTTP01Webroot = t.TempDir()
	s, closeIt, err = r.buildSolver()
	require.NoError(t, err)
	assert.NotNil(t, s)
	closeIt()

	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	r.cfg.HTTP01Webroot = file
	_, _, err = r.buildSolver()
	require.Error(t, err)

	r.cfg = Config{Challenge: solver.DNS01, DNSProvider: "nope"}
	_, _, err = r.buildSolver()
	require.Error(t, err)
}

func TestStateFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := leafOf(dir, "missing.pem")
	require.ErrorIs(t, err, os.ErrNotExist)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, certDir), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, certDir, "x.pem"), []byte("junk"), 0o600))
	_, err = leafOf(dir, "x.pem")
	require.Error(t, err)
	st := &state{}
	_, err = st.keepCertificate(dir, [][]byte{[]byte("junk")})
	require.Error(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, accountKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), 0o600))
	_, _, err = accountKey(dir)
	require.Error(t, err)
	_, _, err = accountKey(filepath.Join(dir, certDir, "x.pem", "sub"))
	require.Error(t, err)
	assert.True(t, strings.HasSuffix(filepath.Join(dir, stateFile), "state.json"))
}
