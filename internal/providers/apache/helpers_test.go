package apache

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/testutil/pki"
)

var testTarget = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000c1")

const (
	wwwCert = "/etc/ssl/certs/www.crt"
	wwwKey  = "/etc/ssl/private/www.key"
	apiCert = "/etc/ssl/certs/api.crt"
	apiKey  = "/etc/ssl/private/api.key"
)

// fakeCred hands out one client key.
type fakeCred struct {
	signer ssh.Signer
	priv   ed25519.PrivateKey
}

func newFakeCred(t testing.TB) *fakeCred {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return &fakeCred{signer: s, priv: priv}
}

func (f *fakeCred) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return f.signer, func() {}, nil
}

func (f *fakeCred) secrets(t testing.TB) []string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(f.priv, "")
	require.NoError(t, err)
	return []string{string(pem.EncodeToMemory(block)), string(f.priv.Seed())}
}

// memHostKeys is an in-memory providers.HostKeyStore with one pinned key.
type memHostKeys struct {
	mu     sync.Mutex
	pinned *providers.HostKey
}

func (m *memHostKeys) Pinned(context.Context, uuid.UUID) (providers.HostKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pinned == nil {
		return providers.HostKey{}, providers.ErrNoPinnedKey
	}
	return *m.pinned, nil
}

func (m *memHostKeys) Observed(context.Context, uuid.UUID, providers.HostKey, bool) error { return nil }

// env is the apache provider wired to the emulated host through a fake SSH server.
type env struct {
	srv  *linuxsshtest.Server
	emu  *linuxsshtest.Emulator
	cred *fakeCred
	hk   *memHostKeys
	ssh  *linuxssh.Provider
	prov *Provider
	ref  providers.TargetRef
	ca   *pki.CA
	leaf pki.Leaf
	api  pki.Leaf
}

type envOption func(*envConfig)

type envConfig struct{ noApache bool }

// withoutApache leaves Apache uninstalled (the sudoers profile stays, as on a prepared server).
func withoutApache() envOption { return func(c *envConfig) { c.noApache = true } }

// newEnv has two TLS sites: www.example.test (separate key file) and api.example.test.
func newEnv(t *testing.T, opts ...envOption) *env {
	t.Helper()
	var cfg envConfig
	for _, o := range opts {
		o(&cfg)
	}
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	emu := linuxsshtest.NewEmulator()
	srv := linuxsshtest.NewServer(t, emu.Handler())
	cred := newFakeCred(t)
	srv.Authorize(cred.signer.PublicKey())
	hk := &memHostKeys{}
	pin := linuxssh.HostKeyOf(srv.HostKey())
	hk.pinned = &pin
	pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: hk},
		linuxssh.MaxConnections, 16, linuxssh.IdleTimeout)
	t.Cleanup(pool.Close)
	lp := linuxssh.New(linuxssh.Options{Pool: pool, AllowUnverifiedHelper: true})
	host, port := srv.Addr()
	ca := pki.NewCA("Emu", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	api := ca.Issue(pki.Opts{CommonName: "api.example.test", SANs: []string{"api.example.test"}}, now)
	if !cfg.noApache {
		emu.EnableApache("2.4.57")
	}
	emu.AddApacheSite(linuxsshtest.ApacheSite{Names: []string{"www.example.test", "example.test"}, Port: 443, CertPath: wwwCert, KeyPath: wwwKey},
		leaf.FullchainPEM, leaf.KeyPEM)
	emu.AddApacheSite(linuxsshtest.ApacheSite{Names: []string{"api.example.test"}, Port: 8443, CertPath: apiCert, KeyPath: apiKey},
		api.FullchainPEM, api.KeyPEM)
	return &env{srv: srv, emu: emu, cred: cred, hk: hk, ssh: lp, ca: ca, leaf: leaf, api: api,
		prov: New(Options{SSH: lp}),
		ref: providers.TargetRef{ID: testTarget, Name: "web-01", Kind: providers.KindApache,
			Config: providers.TargetConfig{"host": host, "port": port, "username": "alice-svc"}}}
}

func (e *env) open(t *testing.T) providers.Session {
	t.Helper()
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{Clock: clock.Real{}, HostKeys: e.hk})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func (e *env) discover(t *testing.T) providers.DiscoveryResult {
	t.Helper()
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	return res
}

func warningCodes(ws []providers.Warning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Code)
	}
	return out
}

func providerErr(t testing.TB, err error) *providers.Error {
	t.Helper()
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	return pe
}

func locationsByPath(res providers.DiscoveryResult) map[string]providers.DiscoveredCertificate {
	m := map[string]providers.DiscoveredCertificate{}
	for _, c := range res.Certificates {
		m[c.Location.CertPath] = c
	}
	return m
}

func linuxsshtestSite(name string, port int, cert, key string) linuxsshtest.ApacheSite {
	return linuxsshtest.ApacheSite{Names: []string{name}, Port: port, CertPath: cert, KeyPath: key}
}
