package linuxssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

var testTarget = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000a1")

// fakeCred hands out one client key and counts releases.
type fakeCred struct {
	signer   ssh.Signer
	priv     ed25519.PrivateKey
	mu       sync.Mutex
	released int
	fetched  int
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
	f.mu.Lock()
	f.fetched++
	f.mu.Unlock()
	return f.signer, func() {
		f.mu.Lock()
		f.released++
		f.mu.Unlock()
	}, nil
}

func (f *fakeCred) fetches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetched
}

func (f *fakeCred) releases() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.released
}

type observation struct {
	key     providers.HostKey
	changed bool
}

// memHostKeys is an in-memory providers.HostKeyStore.
type memHostKeys struct {
	mu       sync.Mutex
	pinned   *providers.HostKey
	observed []observation
	fail     error
	// blockObserved, when set, makes Observed wait for it to close (a hung database).
	blockObserved chan struct{}
}

func (m *memHostKeys) Pinned(context.Context, uuid.UUID) (providers.HostKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return providers.HostKey{}, m.fail
	}
	if m.pinned == nil {
		return providers.HostKey{}, providers.ErrNoPinnedKey
	}
	return *m.pinned, nil
}

func (m *memHostKeys) Observed(_ context.Context, _ uuid.UUID, k providers.HostKey, changed bool) error {
	if m.blockObserved != nil {
		<-m.blockObserved
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.observed = append(m.observed, observation{key: k, changed: changed})
	return nil
}

func (m *memHostKeys) pin(k ssh.PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	hk := HostKeyOf(k)
	m.pinned = &hk
}

func (m *memHostKeys) observations() []observation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]observation(nil), m.observed...)
}

// testServer starts a fake SSH server answering with h and authorizing a fresh client key.
func testServer(t testing.TB, h linuxsshtest.Handler) (*linuxsshtest.Server, Config, *fakeCred) {
	t.Helper()
	srv := linuxsshtest.NewServer(t, h)
	cred := newFakeCred(t)
	srv.Authorize(cred.signer.PublicKey())
	host, port := srv.Addr()
	return srv, Config{Host: host, Port: port, Username: "alice-svc"}, cred
}

func newDialer(hk *memHostKeys) *Dialer {
	return &Dialer{Clock: clock.Real{}, HostKeys: hk}
}

// providerCode returns the reason code of a *providers.Error ("" otherwise).
func providerCode(t testing.TB, err error) *providers.Error {
	t.Helper()
	var pe *providers.Error
	require.True(t, errors.As(err, &pe), "want *providers.Error, got %T (%v)", err, err)
	return pe
}

// versionJSON is the helper's answer to "version".
func versionJSON(protocol int) linuxsshtest.Response {
	return linuxsshtest.Response{Stdout: []byte(`{"ok":true,"helper":"1.0.0","protocol":` + strconv.Itoa(protocol) + `}`)}
}

// connOf is the pooled connection behind a session of this provider.
func connOf(t *testing.T, s providers.Session) *Conn {
	t.Helper()
	ls, ok := s.(*session)
	require.True(t, ok, "a linuxssh session")
	return ls.conn
}
