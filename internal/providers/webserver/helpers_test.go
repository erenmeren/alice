package webserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/testutil/pki"
)

var testTarget = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000c1")

const (
	wwwCert = "/etc/nginx/ssl/www.crt"
	wwwKey  = "/etc/nginx/ssl/www.key"
)

// nginxFolders are the usual certificate folders of an Nginx server (the nginx provider's Spec).
var nginxFolders = []string{"/etc/ssl/", "/etc/nginx/", "/etc/pki/", "/etc/letsencrypt/"}

// testSpec is the Nginx web server as the nginx provider describes it.
func testSpec() Spec {
	return Spec{Kind: providers.KindNginx, DisplayNameKey: "provider.nginx.name", Dump: linuxssh.CmdNginxDump, Test: linuxssh.CmdNginxTest,
		Subcommands: []string{helperproto.SubNginxDump, helperproto.SubNginxTest, helperproto.SubNginxDeploy, helperproto.SubNginxRestore,
			helperproto.SubNginxStatus, helperproto.SubNginxFence},
		UsualFolders: nginxFolders}
}

// fakeCred hands out one client key.
type fakeCred struct{ signer ssh.Signer }

func newFakeCred(t testing.TB) *fakeCred {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return &fakeCred{signer: s}
}

func (f *fakeCred) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return f.signer, func() {}, nil
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

// env is a Base wired to the emulated host through a fake SSH server.
type env struct {
	srv  *linuxsshtest.Server
	emu  *linuxsshtest.Emulator
	cred *fakeCred
	hk   *memHostKeys
	ssh  *linuxssh.Provider
	base Base
	ref  providers.TargetRef
	leaf pki.Leaf
}

// newEnv is an Nginx server with one site (wwwCert, wwwKey); withNginx false leaves Nginx
// uninstalled (the sudoers profile stays, as on a prepared server).
func newEnv(t *testing.T, withNginx bool) *env {
	t.Helper()
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	emu := linuxsshtest.NewEmulator()
	srv := linuxsshtest.NewServer(t, emu.Handler())
	cred := newFakeCred(t)
	srv.Authorize(cred.signer.PublicKey())
	hk := &memHostKeys{}
	pin := linuxssh.HostKeyOf(srv.HostKey())
	hk.pinned = &pin
	pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: hk}, linuxssh.MaxConnections, 16, linuxssh.IdleTimeout)
	t.Cleanup(pool.Close)
	lp := linuxssh.New(linuxssh.Options{Pool: pool, AllowUnverifiedHelper: true})
	host, port := srv.Addr()
	ca := pki.NewCA("Emu", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	if withNginx {
		emu.EnableNginx("1.22.1")
	}
	emu.AddSite(linuxsshtest.NginxSite{Names: []string{"www.example.test"}, Port: 443, CertPath: wwwCert, KeyPath: wwwKey},
		leaf.FullchainPEM, leaf.KeyPEM)
	return &env{
		srv: srv, emu: emu, cred: cred, hk: hk, ssh: lp, base: NewBase(lp, testSpec()), leaf: leaf,
		ref: providers.TargetRef{ID: testTarget, Name: "web-01", Kind: providers.KindNginx,
			Config: providers.TargetConfig{"host": host, "port": port, "username": "alice-svc"}},
	}
}

func (e *env) open(t *testing.T) *Session {
	t.Helper()
	s, err := e.base.OpenSession(context.Background(), e.ref, e.cred, providers.Env{Clock: clock.Real{}, HostKeys: e.hk})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func warningCodes(ws []providers.Warning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Code)
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

func hexSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
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
