package fake_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/providertest"
	"alice/internal/secrets"
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

// recorder keeps the formatted failure messages so the conformance checks can be shown to fail
// for exactly the reason under test.
type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// liar answers the session methods it is given a function for and ErrUnsupported otherwise.
type liar struct {
	providers.UnsupportedSession
	test     func() error
	discover func() error
	list     func() error
	add      func() error
	remove   func() error
}

func (l liar) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	if l.test != nil {
		return providers.ConnectionReport{}, l.test()
	}
	return l.UnsupportedSession.TestConnection(ctx)
}

func (l liar) Discover(ctx context.Context, r providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	if l.discover != nil {
		return providers.DiscoveryResult{}, l.discover()
	}
	return l.UnsupportedSession.Discover(ctx, r)
}

func (l liar) ListAuthorizedKeys(ctx context.Context) ([]providers.DiscoveredSSHKey, error) {
	if l.list != nil {
		return nil, l.list()
	}
	return l.UnsupportedSession.ListAuthorizedKeys(ctx)
}

func (l liar) AddAuthorizedKey(ctx context.Context, c providers.AuthKeyChange, s providers.StepLogger) (providers.AuthKeyResult, error) {
	if l.add != nil {
		return providers.AuthKeyResult{}, l.add()
	}
	return l.UnsupportedSession.AddAuthorizedKey(ctx, c, s)
}

func (l liar) RemoveAuthorizedKey(ctx context.Context, c providers.AuthKeyChange, s providers.StepLogger) (providers.AuthKeyResult, error) {
	if l.remove != nil {
		return providers.AuthKeyResult{}, l.remove()
	}
	return l.UnsupportedSession.RemoveAuthorizedKey(ctx, c, s)
}

// noValidation has a required field but never reports it.
type noValidation struct{ *fake.Provider }

func (noValidation) ValidateConfig(providers.TargetConfig) []validate.FieldError { return nil }

func TestConformanceChecksFailOnBrokenSessions(t *testing.T) {
	ok := func() error { return nil }
	other := func() error { return errors.New("boom") }
	cases := []struct {
		name string
		s    liar
		want string
	}{
		{"TestConnection", liar{test: ok}, "TestConnection without its capability"},
		{"Discover", liar{discover: ok}, "Discover without its capability"},
		{"ListAuthorizedKeys", liar{list: ok}, "ListAuthorizedKeys without its capability"},
		{"AddAuthorizedKey", liar{add: ok}, "AddAuthorizedKey without its capability"},
		{"RemoveAuthorizedKey", liar{remove: ok}, "RemoveAuthorizedKey without its capability"},
		{"wrong error", liar{test: other}, "TestConnection without its capability: got boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{TB: t}
			providertest.CheckUnsupported(r, tc.s, providers.NewCapabilitySet())
			require.Len(t, r.failures, 1, "exactly one check fires: %v", r.failures)
			assert.Contains(t, r.failures[0], tc.want)
		})
	}

	t.Run("capabilities present are not checked", func(t *testing.T) {
		r := &recorder{TB: t}
		all := providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys)
		providertest.CheckUnsupported(r, liar{test: ok, discover: ok, list: ok, add: ok, remove: ok}, all)
		assert.Empty(t, r.failures)
	})
}

func TestConformanceChecksFailOnBrokenProviders(t *testing.T) {
	t.Run("no kind", func(t *testing.T) {
		r := &recorder{TB: t}
		providertest.CheckProvider(r, fake.New(""))
		require.Len(t, r.failures, 2, "%v", r.failures)
		assert.Contains(t, r.failures[0], "no kind")
		assert.Contains(t, r.failures[1], "a registry refuses it")
	})
	t.Run("required field never reported", func(t *testing.T) {
		r := &recorder{TB: t}
		providertest.CheckProvider(r, noValidation{fake.New(providers.KindLinuxSSH)})
		require.Len(t, r.failures, 1, "%v", r.failures)
		assert.Contains(t, r.failures[0], `does not report the required field "host"`)
	})
	t.Run("a good provider passes", func(t *testing.T) {
		r := &recorder{TB: t}
		providertest.CheckProvider(r, fake.New(providers.KindLinuxSSH))
		assert.Empty(t, r.failures)
	})
}

func TestFakeCapabilitiesAreACopy(t *testing.T) {
	p := fake.New(providers.KindLinuxSSH)
	c := p.Capabilities()
	delete(c, providers.CapTestConnection)
	c[providers.CapDeployCertificate] = struct{}{}
	assert.True(t, p.Capabilities().Has(providers.CapTestConnection))
	assert.False(t, p.Capabilities().Has(providers.CapDeployCertificate))
}

func TestFakeWrapsStoreAndCredentialErrors(t *testing.T) {
	ctx := context.Background()
	p := fake.New(providers.KindLinuxSSH)
	p.Configure(func(c *fake.Config) { c.PresentedKey = keyA })
	storeErr := errors.New("db down password=CANARY")
	_, err := p.Open(ctx, providers.TargetRef{ID: uuid.New()}, nil, providers.Env{HostKeys: failingStore{storeErr}})
	var pe *providers.Error
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, "target.hostkey_store", pe.Code)
	assert.True(t, pe.Retryable)
	assert.ErrorIs(t, err, storeErr)
	assert.NotContains(t, err.Error(), "CANARY")

	p.Configure(func(c *fake.Config) { c.SkipHostKeyCheck = true })
	credErr := errors.New("decrypt failed")
	_, err = p.Open(ctx, providers.TargetRef{ID: uuid.New()}, failingCreds{credErr}, providers.Env{})
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, "ssh.credential", pe.Code)
	assert.ErrorIs(t, err, credErr)
}

type failingStore struct{ err error }

func (f failingStore) Pinned(context.Context, uuid.UUID) (providers.HostKey, error) {
	return providers.HostKey{}, f.err
}

func (f failingStore) Observed(context.Context, uuid.UUID, providers.HostKey, bool) error {
	return f.err
}

type failingCreds struct{ err error }

func (f failingCreds) SSHSigner(context.Context) (ssh.Signer, func(), error) { return nil, nil, f.err }

func TestFakeCallsAreDeepCopies(t *testing.T) {
	ctx := context.Background()
	p := fake.New(providers.KindLinuxSSH)
	keys := []providers.DiscoveredSSHKey{{Fingerprint: "SHA256:K"}}
	p.Configure(func(c *fake.Config) { c.Keys = keys })
	s, err := p.Open(ctx, providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	protected := []string{"SHA256:P"}
	_, err = s.AddAuthorizedKey(ctx, providers.AuthKeyChange{ProtectedFingerprints: protected}, nil)
	require.NoError(t, err)
	protected[0] = "mutated"
	assert.Equal(t, []string{"SHA256:P"}, p.Calls()[1].Change.ProtectedFingerprints)
	p.Calls()[1].Change.ProtectedFingerprints[0] = "mutated"
	assert.Equal(t, []string{"SHA256:P"}, p.Calls()[1].Change.ProtectedFingerprints)

	got, err := s.ListAuthorizedKeys(ctx)
	require.NoError(t, err)
	got[0].Fingerprint = "mutated"
	got2, _ := s.ListAuthorizedKeys(ctx)
	assert.Equal(t, "SHA256:K", got2[0].Fingerprint, "callers cannot change the scripted keys")
}

// Run with -race: scripting the fake while sessions run must not race.
func TestFakeConfigureWhileSessionsRun(t *testing.T) {
	ctx := context.Background()
	p := fake.New(providers.KindLinuxSSH)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				p.Configure(func(c *fake.Config) {
					c.Keys = []providers.DiscoveredSSHKey{{Fingerprint: "SHA256:K"}}
					c.Discovery = providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{{}}}
				})
			}
		}()
		go func() {
			defer wg.Done()
			s, err := p.Open(ctx, providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
			if err != nil {
				return
			}
			for j := 0; j < 50; j++ {
				_, _ = s.ListAuthorizedKeys(ctx)
				_, _ = s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
				_, _ = s.AddAuthorizedKey(ctx, providers.AuthKeyChange{ProtectedFingerprints: []string{"x"}}, nil)
				_ = p.Calls()
				_ = p.Count("Open")
			}
			_ = s.Close()
		}()
	}
	wg.Wait()
	assert.Equal(t, 8, p.Count("Open"))
}

type stepFunc func(name string, st providers.StepStatus, params map[string]string)

func (f stepFunc) Step(name string, st providers.StepStatus, params map[string]string) {
	f(name, st, params)
}

func openDeployFake(t *testing.T, caps ...providers.Capability) (*fake.Provider, providers.Session) {
	t.Helper()
	p := fake.New(providers.KindNginx, caps...)
	s, err := p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	return p, s
}

func TestFakeDeployRecordsWithoutTheKey(t *testing.T) {
	p, s := openDeployFake(t, providers.CapDeployCertificate, providers.CapVerifyDeployment)
	var steps []string
	op := uuid.New()
	out, err := s.DeployCertificate(context.Background(), providers.DeployRequest{OperationID: op,
		PrivateKeyPEM: secrets.NewPlaintext([]byte("k"))}, stepFunc(func(n string, st providers.StepStatus, _ map[string]string) {
		steps = append(steps, n+":"+string(st))
	}))
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, "remote", out.Verified)
	assert.Equal(t, providers.BackupRef{OperationID: op}, out.Backup)
	assert.Equal(t, providers.PhaseCommitted, out.Phase)
	assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok", "verify:ok"}, steps)
	require.Len(t, out.Steps, 6)
	calls := p.Calls()
	last := calls[len(calls)-1]
	require.Equal(t, "DeployCertificate", last.Method)
	assert.Equal(t, op, last.Deploy.OperationID)
	assert.Equal(t, op, last.Op)
	assert.Empty(t, last.Deploy.PrivateKeyPEM.Bytes())
}

func TestFakeDeploySimulatesEveryOutcome(t *testing.T) {
	ctx := context.Background()
	uncertain := providers.NewError("ssh.timeout", true, nil, nil)
	outcomes := []struct {
		name  string
		out   providers.DeployOutcome
		err   error
		steps []string
	}{
		{"no change", providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.no_space"}, nil, []string{}},
		{"unchanged", providers.DeployOutcome{Result: providers.DeployUnchanged, Phase: providers.PhaseUnchanged}, nil, []string{"backup"}},
		{"rolled back", providers.DeployOutcome{Result: providers.DeployRolledBack, FailedStep: "config_test"}, nil, []string{"backup", "write_key", "write_cert"}},
		{"rollback failed", providers.DeployOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore"}, nil, []string{"backup"}},
		{"uncertain", providers.DeployOutcome{Result: providers.DeployUncertain}, uncertain, []string{"backup", "write_key"}},
	}
	for _, tc := range outcomes {
		t.Run(tc.name, func(t *testing.T) {
			p, s := openDeployFake(t, providers.CapDeployCertificate)
			p.Configure(func(c *fake.Config) {
				c.DeploySteps = tc.steps
				c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) { return tc.out, tc.err }
			})
			var got []string
			out, err := s.DeployCertificate(ctx, providers.DeployRequest{}, stepFunc(func(n string, _ providers.StepStatus, _ map[string]string) {
				got = append(got, n)
			}))
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.out, out)
			assert.ElementsMatch(t, tc.steps, got)
		})
	}
}

func TestFakeDeployWithoutLoggerAndWithoutCapability(t *testing.T) {
	ctx := context.Background()
	_, s := openDeployFake(t, providers.CapDeployCertificate)
	_, err := s.DeployCertificate(ctx, providers.DeployRequest{}, nil)
	require.NoError(t, err)

	_, none := openDeployFake(t, providers.CapTestConnection)
	_, err = none.DeployCertificate(ctx, providers.DeployRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = none.RollbackDeployment(ctx, providers.RollbackRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = none.DeploymentStatus(ctx, uuid.New())
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = none.VerifyDeployment(ctx, providers.VerifyRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
}

func TestFakeRollbackVerifyAndStatusDefaultsAndScripts(t *testing.T) {
	ctx := context.Background()
	p, s := openDeployFake(t, providers.CapDeployCertificate, providers.CapVerifyDeployment)
	op := uuid.New()

	rb, err := s.RollbackDeployment(ctx, providers.RollbackRequest{OperationID: op}, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, rb.Result)
	assert.Equal(t, providers.PhaseRestored, rb.Phase)

	v, err := s.VerifyDeployment(ctx, providers.VerifyRequest{Fingerprint: "ab", ChainLength: 3})
	require.NoError(t, err)
	assert.True(t, v.OK)
	assert.Equal(t, "ab", v.Served)
	assert.Equal(t, 3, v.ServedChainLength)

	st, err := s.DeploymentStatus(ctx, op)
	require.NoError(t, err)
	assert.Equal(t, providers.PhaseNone, st.Phase)

	boom := errors.New("boom")
	p.Configure(func(c *fake.Config) {
		c.Rollback = func(providers.RollbackRequest) (providers.RollbackOutcome, error) {
			return providers.RollbackOutcome{Result: providers.DeployUncertain}, boom
		}
		c.Verify = func(r providers.VerifyRequest) (providers.VerifyResult, error) {
			return providers.VerifyResult{Reason: "deployment.verify_failed", ServedChainLength: r.ChainLength + 1}, nil
		}
		c.Status = func(o uuid.UUID) (providers.DeploymentState, error) {
			return providers.DeploymentState{Phase: providers.PhaseWriting, BackupDir: o.String()}, boom
		}
	})
	rb, err = s.RollbackDeployment(ctx, providers.RollbackRequest{}, nil)
	assert.Same(t, boom, err)
	assert.Equal(t, providers.DeployUncertain, rb.Result)
	v, _ = s.VerifyDeployment(ctx, providers.VerifyRequest{ChainLength: 2})
	assert.False(t, v.OK)
	assert.Equal(t, 3, v.ServedChainLength)
	st, err = s.DeploymentStatus(ctx, op)
	assert.Same(t, boom, err)
	assert.Equal(t, providers.PhaseWriting, st.Phase)

	var methods []string
	for _, c := range p.Calls() {
		methods = append(methods, c.Method)
	}
	assert.Contains(t, methods, "RollbackDeployment")
	assert.Contains(t, methods, "VerifyDeployment")
	assert.Contains(t, methods, "DeploymentStatus")
	for _, c := range p.Calls() {
		if c.Method == "DeploymentStatus" {
			assert.Equal(t, op, c.Op)
		}
	}
}

func TestFakeDiscoverServesCertificates(t *testing.T) {
	ctx := context.Background()
	p, s := openDeployFake(t, providers.CapDiscoverCerts)
	servers := []providers.CertServer{{Names: []string{"a"}}}
	p.Configure(func(c *fake.Config) {
		c.Discovery.Certificates = []providers.DiscoveredCertificate{{Location: providers.CertLocation{Servers: servers}}}
		c.Discovery.Nginx = &providers.NginxFacts{Found: true}
	})
	res, err := s.Discover(ctx, providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	require.Len(t, res.Certificates, 1)
	res.Certificates[0].Location.Servers[0].Names[0] = "mutated"
	res.Nginx.Found = false
	again, _ := s.Discover(ctx, providers.DiscoverRequest{Certificates: true})
	assert.Equal(t, "a", again.Certificates[0].Location.Servers[0].Names[0], "callers cannot change the scripted data")
	assert.True(t, again.Nginx.Found)
	p.Configure(func(c *fake.Config) { c.Report.Nginx = &providers.NginxFacts{Found: true} })
}

func TestFakeCallsOfDeployMethodsAreCopies(t *testing.T) {
	ctx := context.Background()
	p, s := openDeployFake(t, providers.CapDeployCertificate, providers.CapVerifyDeployment)
	sans := []string{"a.example"}
	pem := []byte("PEM")
	_, err := s.DeployCertificate(ctx, providers.DeployRequest{SANs: sans, CertificatePEM: pem}, nil)
	require.NoError(t, err)
	sans[0] = "mutated"
	pem[0] = 'X'
	_, err = s.VerifyDeployment(ctx, providers.VerifyRequest{SANs: []string{"v"}, ChainLength: 2})
	require.NoError(t, err)
	_, err = s.RollbackDeployment(ctx, providers.RollbackRequest{OldChainLength: 4}, nil)
	require.NoError(t, err)
	var dep providers.DeployRequest
	var vr providers.VerifyRequest
	var rr providers.RollbackRequest
	for _, c := range p.Calls() {
		switch c.Method {
		case "DeployCertificate":
			dep = c.Deploy
		case "VerifyDeployment":
			vr = c.Verify
		case "RollbackDeployment":
			rr = c.Rollback
		}
	}
	assert.Equal(t, []string{"a.example"}, dep.SANs)
	assert.Equal(t, []byte("PEM"), dep.CertificatePEM)
	assert.Equal(t, 2, vr.ChainLength)
	assert.Equal(t, 4, rr.OldChainLength)
}
