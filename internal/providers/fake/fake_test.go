package fake_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/providertest"
)

type memStore struct {
	mu       sync.Mutex
	pinned   map[uuid.UUID]providers.HostKey
	observed []observation
}

type observation struct {
	key     providers.HostKey
	changed bool
}

func (m *memStore) Pinned(_ context.Context, id uuid.UUID) (providers.HostKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.pinned[id]
	if !ok {
		return providers.HostKey{}, providers.ErrNoPinnedKey
	}
	return k, nil
}

func (m *memStore) Observed(_ context.Context, _ uuid.UUID, k providers.HostKey, changed bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.observed = append(m.observed, observation{k, changed})
	return nil
}

type countingCreds struct{ signers, releases int }

func (c *countingCreds) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	c.signers++
	return nil, func() { c.releases++ }, nil
}

var (
	keyA = providers.HostKey{Type: "ssh-ed25519", PublicKey: []byte{1}, Fingerprint: "SHA256:A"}
	keyB = providers.HostKey{Type: "ssh-ed25519", PublicKey: []byte{2}, Fingerprint: "SHA256:B"}
)

func TestFakeIsAConformingProvider(t *testing.T) {
	p := fake.New(providers.KindLinuxSSH)
	providertest.CheckProvider(t, p)
	s, err := p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	providertest.CheckUnsupported(t, s, p.Capabilities())

	limited := fake.New(providers.KindNginx, providers.CapTestConnection)
	s, err = limited.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	providertest.CheckUnsupported(t, s, limited.Capabilities())
	_, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	assert.ErrorIs(t, err, providers.ErrUnsupported, "no discover_ssh_keys capability")
}

// The fake mirrors the pinning rules of the real dialer (F-30, F-31), so inventory and job tests
// see the same errors and Observed calls.
func TestFakeOpenFollowsThePinningRules(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	store := &memStore{pinned: map[uuid.UUID]providers.HostKey{}}
	p := fake.New(providers.KindLinuxSSH)
	p.Configure(func(c *fake.Config) { c.PresentedKey = keyA })
	env := providers.Env{HostKeys: store}

	_, err := p.Open(ctx, providers.TargetRef{ID: target}, nil, env)
	var pe *providers.Error
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, "target.host_key_unconfirmed", pe.Code)
	assert.Equal(t, "SHA256:A", pe.Params["fingerprint"])
	require.Len(t, store.observed, 1)
	assert.Equal(t, observation{keyA, false}, store.observed[0])

	store.pinned[target] = keyA
	creds := &countingCreds{}
	s, err := p.Open(ctx, providers.TargetRef{ID: target}, creds, env)
	require.NoError(t, err)
	assert.Equal(t, 1, creds.signers)
	assert.Equal(t, 1, creds.releases, "the credential is released after the dial")
	rep, err := s.TestConnection(ctx)
	require.NoError(t, err)
	assert.Equal(t, "SHA256:A", rep.HostKey.Fingerprint, "the report carries the presented key by default")

	p.Configure(func(c *fake.Config) { c.PresentedKey = keyB })
	_, err = p.Open(ctx, providers.TargetRef{ID: target}, creds, env)
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, "target.host_key_changed", pe.Code)
	assert.Equal(t, map[string]string{"old_fingerprint": "SHA256:A", "new_fingerprint": "SHA256:B"}, pe.Params)
	assert.Equal(t, observation{keyB, true}, store.observed[len(store.observed)-1])
	assert.Equal(t, 1, creds.signers, "no credential is decrypted for a changed key")

	p.Configure(func(c *fake.Config) { c.SkipHostKeyCheck = true })
	_, err = p.Open(ctx, providers.TargetRef{ID: target}, nil, env)
	assert.NoError(t, err)
}

func TestFakeRecordsCallsAndReturnsScriptedResults(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	boom := providers.NewError("ssh.timeout", true, nil, nil)
	p := fake.New(providers.KindLinuxSSH)
	p.Configure(func(c *fake.Config) {
		c.Discovery = providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{{OSUser: "deploy", Fingerprint: "SHA256:K"}}}
		c.RemoveResult = providers.AuthKeyResult{Changed: true, Removed: 1}
		c.AddErr = boom
	})
	s, err := p.Open(ctx, providers.TargetRef{ID: target}, nil, providers.Env{})
	require.NoError(t, err)
	res, err := s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, "SHA256:K", res.SSHKeys[0].Fingerprint)
	change := providers.AuthKeyChange{OSUser: "deploy", Fingerprint: "SHA256:K"}
	out, err := s.RemoveAuthorizedKey(ctx, change, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, out.Removed)
	_, err = s.AddAuthorizedKey(ctx, change, nil)
	assert.Same(t, boom, err)
	require.NoError(t, s.Close())

	assert.Equal(t, 1, p.Count("Open"))
	assert.Equal(t, 1, p.Count("RemoveAuthorizedKey"))
	calls := p.Calls()
	require.Len(t, calls, 5)
	assert.Equal(t, []string{"Open", "Discover", "RemoveAuthorizedKey", "AddAuthorizedKey", "Close"},
		[]string{calls[0].Method, calls[1].Method, calls[2].Method, calls[3].Method, calls[4].Method})
	assert.Equal(t, target, calls[2].Target)
	assert.Equal(t, change, calls[2].Change)

	p.Configure(func(c *fake.Config) { c.OpenErr = boom })
	_, err = p.Open(ctx, providers.TargetRef{ID: target}, nil, providers.Env{})
	assert.Same(t, boom, err)
}

func TestFakeValidatesItsConfig(t *testing.T) {
	p := fake.New(providers.KindLinuxSSH)
	errs := p.ValidateConfig(providers.TargetConfig{})
	require.Len(t, errs, 1)
	assert.Equal(t, "host", errs[0].Field)
	assert.Empty(t, p.ValidateConfig(providers.TargetConfig{"host": "web-01"}))
}

// recorder captures Errorf calls so the conformance checks can be shown to fail.
type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Helper()               {}
func (r *recorder) Errorf(string, ...any) { r.failures = append(r.failures, "x") }

// lying claims no capabilities in CheckUnsupported but answers everything.
type lying struct{ providers.UnsupportedSession }

func (lying) TestConnection(context.Context) (providers.ConnectionReport, error) {
	return providers.ConnectionReport{}, nil
}

func TestConformanceChecksFailOnBrokenProviders(t *testing.T) {
	r := &recorder{TB: t}
	providertest.CheckUnsupported(r, lying{}, providers.NewCapabilitySet())
	assert.Len(t, r.failures, 1, "TestConnection answered without the capability")

	r = &recorder{TB: t}
	providertest.CheckProvider(r, fake.New(""))
	assert.GreaterOrEqual(t, len(r.failures), 2, "no kind, and a registry refuses it")
}
