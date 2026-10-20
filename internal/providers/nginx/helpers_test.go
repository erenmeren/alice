package nginx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
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
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

var testTarget = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000b1")

var unitNow = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

const (
	wwwCert = "/etc/nginx/ssl/www.crt"
	wwwKey  = "/etc/nginx/ssl/www.key"
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

// secrets renders the credential's private key the ways it could leak.
func (f *fakeCred) secrets(t testing.TB) []string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(f.priv, "")
	require.NoError(t, err)
	seed := f.priv.Seed()
	return []string{
		string(pem.EncodeToMemory(block)),
		base64.StdEncoding.EncodeToString(block.Bytes)[:64],
		base64.StdEncoding.EncodeToString(seed),
		hex.EncodeToString(seed),
		string(seed),
	}
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

// emuProber stands for Alice's own TLS probe: it answers from what the emulated Nginx serves.
// remoteDown makes it unable to connect (ErrProbeUnreachable), remoteFails makes every handshake
// fail (ErrProbeFailed, e.g. a firewall that resets), notAllowed makes the target's name resolve to
// an address Alice never connects to (ErrProbeNotAllowed); calls records "port sni keyType" per probe.
type emuProber struct {
	emu         *linuxsshtest.Emulator
	mu          sync.Mutex
	remoteDown  bool
	remoteFails bool
	notAllowed  bool
	calls       []string
}

func (p *emuProber) Probe(_ context.Context, host string, port int, sni, keyType string) (Probe, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, fmt.Sprintf("%s %d %s %s", host, port, sni, keyType))
	switch {
	case p.notAllowed:
		return Probe{}, ErrProbeNotAllowed
	case p.remoteDown:
		return Probe{}, ErrProbeUnreachable
	case p.remoteFails:
		return Probe{}, ErrProbeFailed
	}
	// Alice reaches the emulated host at host: a listen on another specific address does not
	// answer there (another server block may).
	leaf, chain, ok := p.emu.ProbeServed(host, port, sni, keyType)
	if !ok {
		return Probe{}, ErrProbeFailed
	}
	return Probe{LeafSHA256: leaf, ChainLength: chain, Chain: p.emu.ProbeServedChain(host, port, sni, keyType)}, nil
}

func (p *emuProber) set(down, fails bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.remoteDown, p.remoteFails = down, fails
}

func (p *emuProber) probes() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

// steps is a recording StepLogger: "name:status" per call, and the params it was given.
type steps struct {
	mu     sync.Mutex
	names  []string
	params []map[string]string
}

func (l *steps) Step(name string, status providers.StepStatus, params map[string]string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = append(l.names, name+":"+string(status))
	l.params = append(l.params, params)
}

func (l *steps) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.names...)
}

// env is the nginx provider wired to the emulated host through a fake SSH server.
type env struct {
	srv    *linuxsshtest.Server
	emu    *linuxsshtest.Emulator
	cred   *fakeCred
	hk     *memHostKeys
	ssh    *linuxssh.Provider // the linuxssh provider the nginx provider is built on
	prov   *Provider
	ref    providers.TargetRef
	ca     *pki.CA
	leaf   pki.Leaf
	now    time.Time
	prober *emuProber
	op     uuid.UUID // the operation id of e.req
	loc    *providers.CertLocation
}

type envOption func(*envConfig)

type envConfig struct {
	noNginx  bool
	siteAddr string
}

// withSiteAddr makes the fixture site listen on addr only (listen addr:443 ssl).
func withSiteAddr(addr string) envOption { return func(c *envConfig) { c.siteAddr = addr } }

// withoutNginx leaves Nginx uninstalled (the sudoers profile stays, as on a prepared server).
func withoutNginx() envOption { return func(c *envConfig) { c.noNginx = true } }

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
	// More connections per target than production's 2: tests keep sessions open until they end.
	pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: hk},
		linuxssh.MaxConnections, 16, linuxssh.IdleTimeout)
	t.Cleanup(pool.Close)
	lp := linuxssh.New(linuxssh.Options{Pool: pool, AllowUnverifiedHelper: true})
	host, port := srv.Addr()
	ca := pki.NewCA("Emu", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	if !cfg.noNginx {
		emu.EnableNginx("1.22.1")
	}
	emu.AddSite(linuxsshtest.NginxSite{Names: []string{"www.example.test"}, Port: 443, Addr: cfg.siteAddr, CertPath: wwwCert, KeyPath: wwwKey},
		leaf.FullchainPEM, leaf.KeyPEM)
	prober := &emuProber{emu: emu}
	return &env{
		srv: srv, emu: emu, cred: cred, hk: hk, ssh: lp, ca: ca, leaf: leaf, now: now, prober: prober, op: uuid.New(),
		prov: func() *Provider {
			p := New(Options{SSH: lp, Prober: prober, RetryWait: time.Millisecond})
			p.restoreWait = time.Millisecond
			return p
		}(),
		ref: providers.TargetRef{ID: testTarget, Name: "web-01", Kind: providers.KindNginx,
			Config: providers.TargetConfig{"host": host, "port": port, "username": "alice-svc"}},
	}
}

func (e *env) open(t *testing.T) providers.Session {
	t.Helper()
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{Clock: clock.Real{}, HostKeys: e.hk})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// session is open as the package's session type (for the unexported helpers).
func (e *env) session(t *testing.T) *session {
	t.Helper()
	s, ok := e.open(t).(*session)
	require.True(t, ok)
	return s
}

// location is the fixture site's CertLocation from a discovery.
func (e *env) location(t *testing.T) providers.CertLocation {
	t.Helper()
	if e.loc != nil {
		return *e.loc
	}
	s := e.open(t)
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	require.NoError(t, s.Close())
	c, ok := locationsByPath(res)[wwwCert]
	require.True(t, ok, "the fixture site is discovered")
	require.True(t, c.Location.Supported)
	e.loc = &c.Location
	return c.Location
}

// req is the DeployRequest of leaf for the fixture location under e.op: the current file's hash,
// the served leaf as the old one, the new leaf's fingerprint, SANs and chain length, and the key.
func (e *env) req(t *testing.T, leaf pki.Leaf) providers.DeployRequest {
	t.Helper()
	return providers.DeployRequest{
		OperationID:      e.op,
		Location:         e.location(t),
		ExpectCertSHA256: hexSHA(e.emu.NginxFile(wwwCert)),
		CertificatePEM:   leaf.FullchainPEM,
		PrivateKeyPEM:    secrets.NewPlaintext(append([]byte(nil), leaf.KeyPEM...)),
		Fingerprint:      pki.Fingerprint(leaf.Cert),
		SANs:             leaf.Cert.DNSNames,
		KeyType:          "ecdsa",
		OldFingerprint:   pki.Fingerprint(e.leaf.Cert),
		OldSANs:          e.leaf.Cert.DNSNames,
		ChainLength:      2,
	}
}

// hangUpOn makes the fake server drop the connection on the next command of subcommand sub;
// every other command is the emulator's.
func hangUpOn(e *env, sub string) {
	scriptOn(e, sub, linuxsshtest.Response{Hangup: true})
}

// scriptOn makes the fake server answer the next command of subcommand sub with r (instead of the
// emulator); every other command is the emulator's.
func scriptOn(e *env, sub string, r linuxsshtest.Response) {
	intercept(e, sub, func() (linuxsshtest.Response, bool) { return r, true })
}

// beforeOn runs fn right before the next command of subcommand sub reaches the emulator (a change
// on the server between two commands of one provider call).
func beforeOn(e *env, sub string, fn func()) {
	intercept(e, sub, func() (linuxsshtest.Response, bool) { fn(); return linuxsshtest.Response{}, false })
}

// intercept calls fn for the next command of subcommand sub; when fn answers true its response is
// the command's, else the emulator answers. Every other command is the emulator's.
func intercept(e *env, sub string, fn func() (linuxsshtest.Response, bool)) {
	var mu sync.Mutex
	done := false
	h := e.emu.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		mu.Lock()
		hit := !done && (strings.Contains(cmd, " "+sub+" ") || strings.HasSuffix(cmd, " "+sub))
		if hit {
			done = true
		}
		mu.Unlock()
		if hit {
			if r, ok := fn(); ok {
				return r
			}
		}
		return h(cmd, stdin)
	})
}

// addCatchAll adds a default server on 443 (any address) serving another certificate: what
// answers a connection the fixture site does not take.
func (e *env) addCatchAll(t *testing.T) pki.Leaf {
	t.Helper()
	other := e.ca.Issue(pki.Opts{CommonName: "catch-all.example.test"}, e.now)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"_"}, Port: 443, Default: true, CertPath: "/etc/nginx/ssl/default.crt",
		KeyPath: "/etc/nginx/ssl/default.key"}, other.FullchainPEM, other.KeyPEM)
	return other
}

func warningCodes(ws []providers.Warning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Code)
	}
	return out
}

func warningsOf(ws []providers.Warning, code string) []providers.Warning {
	var out []providers.Warning
	for _, w := range ws {
		if w.Code == code {
			out = append(out, w)
		}
	}
	return out
}

// providerErr returns the *providers.Error behind err.
func providerErr(t testing.TB, err error) *providers.Error {
	t.Helper()
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	return pe
}

// locationsByPath indexes a discovery's certificates by certificate path.
func locationsByPath(res providers.DiscoveryResult) map[string]providers.DiscoveredCertificate {
	m := map[string]providers.DiscoveredCertificate{}
	for _, c := range res.Certificates {
		m[c.Location.CertPath] = c
	}
	return m
}

func hexSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
