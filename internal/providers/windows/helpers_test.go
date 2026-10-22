package windows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
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
	"alice/internal/providers/windows/wintest"
)

var testTarget = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000c1")

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

// env is the Windows provider wired to the emulated Windows host (wintest) through its SSH server,
// which runs in the mode of Windows OpenSSH (every later session on a connection sees the first
// command), with a real linuxssh Dialer and Pool.
type env struct {
	model *wintest.Model
	srv   *linuxsshtest.Server
	cred  *fakeCred
	hk    *memHostKeys
	pool  *linuxssh.Pool
	prov  *Provider
	ref   providers.TargetRef

	mu    sync.Mutex
	users []string // the SSH user of every authentication
}

func newEnv(t *testing.T) *env {
	t.Helper()
	m := wintest.NewModel()
	srv := wintest.NewServer(t, m)
	cred := newFakeCred(t)
	e := &env{model: m, srv: srv, cred: cred, hk: &memHostKeys{}}
	srv.SetLoginCheck(func(user string, key ssh.PublicKey) bool {
		e.mu.Lock()
		e.users = append(e.users, user)
		e.mu.Unlock()
		return bytes.Equal(key.Marshal(), cred.signer.PublicKey().Marshal())
	})
	pin := linuxssh.HostKeyOf(srv.HostKey())
	e.hk.pinned = &pin
	e.pool = linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: e.hk},
		linuxssh.MaxConnections, linuxssh.MaxConnectionsPerTarget, linuxssh.IdleTimeout)
	t.Cleanup(e.pool.Close)
	e.prov = New(Options{Pool: e.pool, AllowUnverifiedHelper: true})
	host, port := srv.Addr()
	e.ref = providers.TargetRef{ID: testTarget, Name: "iis-01", Kind: providers.KindWindows,
		Config: providers.TargetConfig{"host": host, "port": port, "username": `CORP\alice-svc`}}
	return e
}

func (e *env) open(t *testing.T) providers.Session {
	t.Helper()
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{Clock: clock.Real{}, HostKeys: e.hk})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func (e *env) sshUsers() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.users...)
}

// waitNoOpenConnections waits until the server holds no connection (a close reaches it asynchronously).
func (e *env) waitNoOpenConnections(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.OpenConnections() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d connections stay open", e.srv.OpenConnections())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func providerErr(t *testing.T, err error) *providers.Error {
	t.Helper()
	var pe *providers.Error
	require.True(t, errors.As(err, &pe), "want *providers.Error, got %T %v", err, err)
	return pe
}
