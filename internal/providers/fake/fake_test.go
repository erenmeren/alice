package fake_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/azureid"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/providertest"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
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

func okSteps(names ...string) []providers.DeployStep {
	var out []providers.DeployStep
	for _, n := range names {
		out = append(out, providers.DeployStep{Name: n, Status: providers.StepOK})
	}
	return out
}

// With Config.Deploy set the fake reports the steps of the outcome it returns, never the default six.
func TestFakeDeploySimulatesEveryOutcome(t *testing.T) {
	ctx := context.Background()
	refusal := providers.NewError("nginx.no_space", false, nil, nil)
	lost := providers.NewError("ssh.timeout", true, nil, nil)
	failedStep := providers.DeployStep{Name: "config_test", Status: providers.StepFailed, Error: providers.ConfigErrSyntax}
	outcomes := []struct {
		name  string
		out   providers.DeployOutcome
		err   error
		steps []string // names reported to the logger
	}{
		{"no change", providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.no_space"}, refusal, nil},
		{"unchanged", providers.DeployOutcome{Result: providers.DeployUnchanged, Phase: providers.PhaseUnchanged, Steps: okSteps("backup")}, nil, []string{"backup"}},
		{"rolled back", providers.DeployOutcome{Result: providers.DeployRolledBack, FailedStep: "config_test", Reason: "certificate.config_invalid",
			Steps: append(okSteps("backup", "write_key", "write_cert"), failedStep)}, nil, []string{"backup", "write_key", "write_cert", "config_test"}},
		{"rollback failed", providers.DeployOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore", Reason: "deployment.rollback_failed", Steps: okSteps("backup")}, nil, []string{"backup"}},
		{"uncertain", providers.DeployOutcome{Result: providers.DeployUncertain, Steps: okSteps("backup", "write_key")}, lost, []string{"backup", "write_key"}},
		{"uncertain without steps", providers.DeployOutcome{Result: providers.DeployUncertain}, lost, nil},
	}
	for _, tc := range outcomes {
		t.Run(tc.name, func(t *testing.T) {
			p, s := openDeployFake(t, providers.CapDeployCertificate)
			p.Configure(func(c *fake.Config) {
				c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) { return tc.out, tc.err }
			})
			var got []string
			out, err := s.DeployCertificate(ctx, providers.DeployRequest{}, stepFunc(func(n string, _ providers.StepStatus, _ map[string]string) {
				got = append(got, n)
			}))
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.out, out)
			assert.Equal(t, tc.steps, got)
		})
	}
}

func TestFakeDeployStepStatusesComeFromTheOutcome(t *testing.T) {
	p, s := openDeployFake(t, providers.CapDeployCertificate)
	p.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			return providers.DeployOutcome{Result: providers.DeployRolledBack, FailedStep: "reload", Reason: "r",
				Steps: []providers.DeployStep{{Name: "backup", Status: providers.StepOK}, {Name: "reload", Status: providers.StepFailed}}}, nil
		}
	})
	var got []string
	_, err := s.DeployCertificate(context.Background(), providers.DeployRequest{}, stepFunc(func(n string, st providers.StepStatus, _ map[string]string) {
		got = append(got, n+":"+string(st))
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"backup:ok", "reload:failed"}, got)
}

// DeploySteps, when set (even empty), overrides both the default six and the outcome's steps.
func TestFakeDeployStepsOverride(t *testing.T) {
	for name, tc := range map[string]struct {
		steps  []string
		script bool
		want   []string
	}{
		"default committed path":       {nil, false, []string{"backup", "write_key", "write_cert", "config_test", "reload", "verify"}},
		"explicit steps, default path": {[]string{"backup"}, false, []string{"backup"}},
		"explicit empty, default path": {[]string{}, false, nil},
		"explicit steps over outcome":  {[]string{"backup", "write_key"}, true, []string{"backup", "write_key"}},
		"explicit empty over outcome":  {[]string{}, true, nil},
	} {
		t.Run(name, func(t *testing.T) {
			p, s := openDeployFake(t, providers.CapDeployCertificate)
			p.Configure(func(c *fake.Config) {
				c.DeploySteps = tc.steps
				if tc.script {
					c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
						return providers.DeployOutcome{Result: providers.DeployCommitted, Steps: okSteps("other")}, nil
					}
				}
			})
			var got []string
			_, err := s.DeployCertificate(context.Background(), providers.DeployRequest{}, stepFunc(func(n string, _ providers.StepStatus, _ map[string]string) {
				got = append(got, n)
			}))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFakeRejectsScriptedOutcomesThatBreakTheContract(t *testing.T) {
	ctx := context.Background()
	p, s := openDeployFake(t, providers.CapDeployCertificate)
	p.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			return providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "r"}, nil // a refusal needs an error
		}
		c.Rollback = func(providers.RollbackRequest) (providers.RollbackOutcome, error) {
			return providers.RollbackOutcome{}, nil // blank result
		}
		c.Status = func(uuid.UUID) (providers.DeploymentState, error) {
			return providers.DeploymentState{}, nil // blank phase
		}
	})
	assert.PanicsWithValue(t, "fake: scripted DeployCertificate result breaks the provider contract: providers: deploy: no_change without an error: a refusal carries a *providers.Error",
		func() { _, _ = s.DeployCertificate(ctx, providers.DeployRequest{}, nil) })
	assert.PanicsWithValue(t, `fake: scripted RollbackDeployment result breaks the provider contract: providers: rollback outcome: blank or unknown result ""`,
		func() { _, _ = s.RollbackDeployment(ctx, providers.RollbackRequest{}, nil) })
	assert.PanicsWithValue(t, `fake: scripted DeploymentStatus result breaks the provider contract: providers: deployment state: blank or unknown phase "blank"`,
		func() { _, _ = s.DeploymentStatus(ctx, uuid.New()) })
}

func TestFakeDiscoverHonoursTheRequest(t *testing.T) {
	ctx := context.Background()
	p, s := openDeployFake(t, providers.CapDiscoverSSHKeys, providers.CapDiscoverCerts)
	p.Configure(func(c *fake.Config) {
		c.Discovery = providers.DiscoveryResult{
			SSHKeys: []providers.DiscoveredSSHKey{{Fingerprint: "SHA256:K"}}, HostKeys: []providers.DiscoveredHostKey{{Fingerprint: "SHA256:H"}},
			SSHD: providers.SSHDSummary{Read: true}, UID0Users: []string{"root"}, Accounts: []string{"root"}, AccountsComplete: true,
			ReadFiles: []string{"/root/.ssh/authorized_keys"}, UnreadableLines: []providers.UnreadableLine{{OSUser: "u"}},
			Certificates: []providers.DiscoveredCertificate{{FileSHA256: "c"}}, Nginx: &providers.NginxFacts{Found: true},
			Warnings: []providers.Warning{{Code: "w"}},
		}
	})
	certs, err := s.Discover(ctx, providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	assert.Len(t, certs.Certificates, 1)
	assert.NotNil(t, certs.Nginx)
	assert.Empty(t, certs.SSHKeys)
	assert.Empty(t, certs.HostKeys)
	assert.Empty(t, certs.Accounts)
	assert.False(t, certs.AccountsComplete)
	assert.False(t, certs.SSHD.Read)
	assert.Empty(t, certs.ReadFiles)
	assert.Empty(t, certs.UID0Users)
	assert.Empty(t, certs.UnreadableLines)

	keys, err := s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Len(t, keys.SSHKeys, 1)
	assert.True(t, keys.AccountsComplete)
	assert.Empty(t, keys.Certificates)
	assert.Nil(t, keys.Nginx)
	assert.Equal(t, []providers.Warning{{Code: "w"}}, keys.Warnings)
}

func TestFakeCallNeverPrintsAKey(t *testing.T) {
	const canary = "KEY-CANARY-FAKE"
	call := fake.Call{Method: "DeployCertificate", Deploy: providers.DeployRequest{PrivateKeyPEM: secrets.NewPlaintext([]byte(canary))}}
	raw := []byte(canary)
	type wrapper struct{ c fake.Call }
	for _, v := range []any{call, &call, wrapper{call}, []fake.Call{call}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
			out := fmt.Sprintf(verb, v)
			assert.NotContains(t, out, canary)
			assert.NotContains(t, out, fmt.Sprintf("%x", canary))
			assert.NotContains(t, out, strings.Trim(fmt.Sprintf("%d", raw), "[]"))
		}
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

// azureCreds is a vault's credential source: a CredentialSource that is also an
// AzureCredentialSource (the inventory's source implements both; the SSH half must stay unused).
type azureCreds struct {
	identities, releases, signers int
	err                           error
}

func (c *azureCreds) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	c.signers++
	return nil, func() {}, nil
}

func (c *azureCreds) AzureIdentity(context.Context) (providers.AzureIdentity, func(), error) {
	c.identities++
	return providers.AzureIdentity{Auth: providers.AzureAuthManagedIdentity}, func() { c.releases++ }, c.err
}

func vaultFake() *fake.Provider {
	return fake.New(providers.KindAzureKV, providers.CapTestConnection, providers.CapDiscoverCerts,
		providers.CapReadCertificateSecret, providers.CapImportCertificate)
}

func openVault(t *testing.T, p *fake.Provider) providers.Session {
	t.Helper()
	s, err := p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, &azureCreds{}, providers.Env{})
	require.NoError(t, err)
	return s
}

func TestFakeOpenUsesTheAzureIdentityOfAVault(t *testing.T) {
	p := vaultFake()
	creds := &azureCreds{}
	_, err := p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, creds, providers.Env{})
	require.NoError(t, err)
	assert.Equal(t, azureCreds{identities: 1, releases: 1}, *creds, "the identity is read and released at once, the SSH signer never")

	failing := &azureCreds{err: errors.New("sealed")}
	_, err = p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, failing, providers.Env{})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.auth_failed", pe.Code)
	assert.Zero(t, failing.releases)

	_, err = p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, &countingCreds{}, providers.Env{})
	require.ErrorAs(t, err, &pe, "a vault needs an Azure credential source, as the real provider does")
	assert.Equal(t, "azure.auth_failed", pe.Code)

	_, err = p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	assert.NoError(t, err, "a test may open a fake vault without any source")

	// An SSH fake never calls AzureIdentity, even when the source offers it.
	ssh := fake.New(providers.KindLinuxSSH)
	creds = &azureCreds{}
	_, err = ssh.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, creds, providers.Env{})
	require.NoError(t, err)
	assert.Zero(t, creds.identities)
	assert.Equal(t, 1, creds.signers)
}

func TestFakeReadCertificateSecretReturnsACopyPerCall(t *testing.T) {
	p := vaultFake()
	p.Configure(func(c *fake.Config) {
		c.Secret = providers.CertificateSecret{ContentType: "application/x-pem-file", Value: providers.NewSecret([]byte("secret-bytes"))}
	})
	s := openVault(t, p)
	first, err := s.ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "web", Version: strings.Repeat("a", 32)})
	require.NoError(t, err)
	assert.Equal(t, "application/x-pem-file", first.ContentType)
	assert.Equal(t, "secret-bytes", string(first.Value.Bytes()))
	first.Zero() // what every caller does after use

	second, err := s.ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "web", Version: strings.Repeat("a", 32)})
	require.NoError(t, err)
	assert.Equal(t, "secret-bytes", string(second.Value.Bytes()), "zeroing one answer leaves the script intact")

	calls := p.Calls()
	var reads []fake.Call
	for _, c := range calls {
		if c.Method == "ReadCertificateSecret" {
			reads = append(reads, c)
		}
	}
	require.Len(t, reads, 2)
	assert.Equal(t, providers.SecretRequest{Name: "web", Version: strings.Repeat("a", 32)}, reads[0].Secret)

	p.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("azure.forbidden", false, nil, nil) })
	_, err = s.ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "web", Version: strings.Repeat("a", 32)})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.forbidden", pe.Code)
}

func TestFakeImportCertificate(t *testing.T) {
	p := vaultFake()
	s := openVault(t, p)
	op := uuid.New()
	pfx := []byte("not-really-a-pfx")
	res, err := s.ImportCertificate(context.Background(), providers.ImportRequest{OperationID: op, Name: "web", PFX: providers.NewSecret(pfx), ReplaceExisting: true}, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.ImportCreated, res.Outcome)
	require.NoError(t, res.Validate())
	assert.Equal(t, azureid.ThumbprintOf(res.CER), res.Thumbprint, "the default thumbprint is the leaf's SHA-1, as the vault's would be")
	other, err := s.ImportCertificate(context.Background(), providers.ImportRequest{Name: "web"}, nil)
	require.NoError(t, err)
	assert.NotEqual(t, res.Version, other.Version, "every default import creates a new version")
	assert.NotEqual(t, res.Thumbprint, other.Thumbprint)

	var rec fake.Call
	for _, c := range p.Calls() {
		if c.Method == "ImportCertificate" {
			rec = c
			break
		}
	}
	assert.Equal(t, "web", rec.Import.Name)
	assert.Equal(t, op, rec.Import.OperationID)
	assert.True(t, rec.Import.ReplaceExisting)
	assert.Empty(t, rec.Import.PFX.Bytes(), "the call log never keeps the PFX")
	assert.Equal(t, pfx, []byte("not-really-a-pfx"), "the caller's bytes are untouched (the caller zeroes them)")

	// A scripted import decides the outcome and sees the request with its PFX.
	var seen string
	p.Configure(func(c *fake.Config) {
		c.Import = func(req providers.ImportRequest) (providers.ImportResult, error) {
			seen = string(req.PFX.Bytes())
			return providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("timeout")
		}
	})
	res, err = s.ImportCertificate(context.Background(), providers.ImportRequest{Name: "web", PFX: providers.NewSecret([]byte("pfx"))}, nil)
	assert.Equal(t, providers.ImportUncertain, res.Outcome)
	assert.Error(t, err)
	assert.Equal(t, "pfx", seen)

	// A scripted result that breaks the outcome rules is the test's mistake: the fake fails loudly.
	p.Configure(func(c *fake.Config) {
		c.Import = func(providers.ImportRequest) (providers.ImportResult, error) {
			return providers.ImportResult{Outcome: providers.ImportRefused}, errors.New("plain")
		}
	})
	assert.Panics(t, func() { _, _ = s.ImportCertificate(context.Background(), providers.ImportRequest{Name: "web"}, nil) })
}

func TestFakeImportUsesTheLeafOfTheRequestedPFX(t *testing.T) {
	_, leafDER, pfx := selfSignedPFX(t)
	p := vaultFake()
	s := openVault(t, p)
	res, err := s.ImportCertificate(context.Background(), providers.ImportRequest{Name: "web", PFX: providers.NewSecret(pfx)}, nil)
	require.NoError(t, err)
	assert.Equal(t, leafDER, res.CER, "a decodable PFX gives the vault's leaf")
	assert.Equal(t, azureid.ThumbprintOf(leafDER), res.Thumbprint)
}

func TestFakeVaultMethodsAreUnsupportedWithoutTheirCapabilities(t *testing.T) {
	p := fake.New(providers.KindAzureKV, providers.CapTestConnection)
	s := openVault(t, p)
	providertest.CheckUnsupported(t, s, p.Capabilities())
	_, err := s.ReadCertificateSecret(context.Background(), providers.SecretRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.ImportCertificate(context.Background(), providers.ImportRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	assert.Equal(t, 2, p.Count("ReadCertificateSecret"), "refused calls are recorded too (the conformance check made one)")
	assert.Equal(t, 2, p.Count("ImportCertificate"))
}

func TestFakeDiscoversTheVaultAsScripted(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	p := vaultFake()
	p.Configure(func(c *fake.Config) {
		c.Report = providers.ConnectionReport{Azure: &providers.AzureFacts{ObjectID: "o", Checks: []providers.AzureCheck{{Name: providers.AzureCheckSignIn}}}}
		c.Discovery = providers.DiscoveryResult{KV: &providers.KVInventory{
			Certificates: []providers.KVCertificate{{Name: "web", Updated: &now, Details: &providers.KVCertificateDetails{Version: "v", CER: []byte{1, 2}},
				Versions: []providers.KVCertificateVersion{{Version: "v"}}}},
			Keys:          []providers.KVKey{{Name: "k", Details: &providers.KVKeyDetails{Version: "kv"}}},
			Secrets:       []providers.KVSecret{{Name: "s"}},
			KeysListed:    true,
			SecretsListed: true,
			Truncated:     []string{"keys"},
			Failures:      []providers.KVListFailure{{Object: "keys", Err: providers.NewError("azure.forbidden", false, nil, nil)}},
		}}
	})
	s := openVault(t, p)
	rep, err := s.TestConnection(context.Background())
	require.NoError(t, err)
	require.NotNil(t, rep.Azure)
	rep.Azure.ObjectID = "changed"
	rep.Azure.Checks[0].Name = "changed"
	rep, _ = s.TestConnection(context.Background())
	assert.Equal(t, "o", rep.Azure.ObjectID, "a caller cannot change the script through the report")
	assert.Equal(t, providers.AzureCheckSignIn, rep.Azure.Checks[0].Name)

	res, err := s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	require.NotNil(t, res.KV)
	assert.Len(t, res.KV.Certificates, 1)
	assert.Empty(t, res.KV.Keys, "keys were not asked for")
	assert.False(t, res.KV.KeysListed)
	assert.Empty(t, res.KV.Secrets)
	assert.False(t, res.KV.SecretsListed)
	assert.Equal(t, []string{"keys"}, res.KV.Truncated)
	res.KV.Certificates[0].Details.CER[0] = 9
	res.KV.Certificates[0].Versions[0].Version = "changed"

	res, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKeys: true, KVSecrets: true})
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2}, res.KV.Certificates[0].Details.CER, "the script is copied per call")
	assert.Equal(t, "v", res.KV.Certificates[0].Versions[0].Version)
	assert.Len(t, res.KV.Keys, 1)
	assert.True(t, res.KV.KeysListed)
	assert.Len(t, res.KV.Secrets, 1)
	assert.True(t, res.KV.SecretsListed)
	require.Len(t, res.KV.Failures, 1)

	res, err = s.Discover(context.Background(), providers.DiscoverRequest{KVKeys: true})
	require.NoError(t, err)
	assert.Empty(t, res.KV.Certificates, "certificates were not asked for")
	assert.Len(t, res.KV.Keys, 1)

	// An SSH-only request sees no vault half, and a fake without a KV script reports none.
	res, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Nil(t, res.KV)
	plain := vaultFake()
	s = openVault(t, plain)
	res, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKeys: true})
	require.NoError(t, err)
	assert.Nil(t, res.KV)
}

// selfSignedPFX returns a leaf, its DER and a PFX holding it with its intermediate.
func selfSignedPFX(t *testing.T) (pki.Leaf, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	ca := pki.NewCA("Fake Vault CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "web.example.test", SANs: []string{"web.example.test"}}, now)
	return leaf, leaf.Cert.Raw, pki.PFX(leaf, ca, "")
}

func TestFakeVaultRefusesWhatTheProviderMustRefuse(t *testing.T) {
	ok := strings.Repeat("a", 32)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	scripted := func() *fake.Provider {
		p := vaultFake()
		p.Configure(func(c *fake.Config) {
			c.Secret = providers.CertificateSecret{ContentType: "application/x-pem-file", Value: providers.NewSecret([]byte("v"))}
		})
		return p
	}
	reads := []struct {
		name string
		ctx  context.Context
		req  providers.SecretRequest
		p    *fake.Provider
	}{
		{"empty", context.Background(), providers.SecretRequest{}, scripted()},
		{"name only", context.Background(), providers.SecretRequest{Name: "web"}, scripted()},
		{"traversal and latest", context.Background(), providers.SecretRequest{Name: "../x", Version: "latest"}, scripted()},
		{"upper-case version", context.Background(), providers.SecretRequest{Name: "web", Version: strings.Repeat("A", 32)}, scripted()},
		{"cancelled", cancelled, providers.SecretRequest{Name: "web", Version: ok}, scripted()},
		{"nothing scripted", context.Background(), providers.SecretRequest{Name: "web", Version: ok}, vaultFake()},
	}
	for _, tc := range reads {
		s := openVault(t, tc.p)
		got, err := s.ReadCertificateSecret(tc.ctx, tc.req)
		var pe *providers.Error
		require.ErrorAs(t, err, &pe, tc.name)
		assert.Empty(t, got.Value.Bytes(), tc.name)
		assert.Empty(t, got.ContentType, tc.name)
	}
	_, err := openVault(t, scripted()).ReadCertificateSecret(cancelled, providers.SecretRequest{Name: "web", Version: ok})
	assert.ErrorIs(t, err, context.Canceled, "a cancelled read wraps the context error, as CheckSession wants")
	got, err := openVault(t, scripted()).ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "web", Version: ok})
	require.NoError(t, err)
	assert.Equal(t, "v", string(got.Value.Bytes()))

	// Imports: an invalid name is a refusal; a cancelled request was never sent: refused, without the context error as its cause.
	for _, name := range []string{"", "bad name/..", "a_b", strings.Repeat("a", 128)} {
		res, err := openVault(t, vaultFake()).ImportCertificate(context.Background(), providers.ImportRequest{Name: name}, nil)
		var pe *providers.Error
		require.ErrorAs(t, err, &pe, name)
		assert.Equal(t, providers.ImportRefused, res.Outcome, name)
		require.NoError(t, providers.CheckImportReturn(res, err), name)
		assert.Equal(t, providers.CodeKVImportInvalid, pe.Code, name)
	}
	res, err := openVault(t, vaultFake()).ImportCertificate(cancelled, providers.ImportRequest{Name: "web"}, nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, context.Canceled)
	assert.Equal(t, providers.ImportRefused, res.Outcome)
	require.NoError(t, providers.CheckImportReturn(res, err))

	// The conformance suite sees a provider that refuses an empty read.
	p := fake.New(providers.KindAzureKV, providers.CapReadCertificateSecret)
	p.Configure(func(c *fake.Config) {
		c.Secret = providers.CertificateSecret{ContentType: "application/x-pem-file", Value: providers.NewSecret([]byte("v"))}
	})
	r := &recorder{TB: t}
	providertest.CheckSession(r, providertest.SessionHarness{
		Capabilities: p.Capabilities(),
		Open: func(ctx context.Context) (providers.Session, error) {
			if err := ctx.Err(); err != nil {
				return nil, providers.NewError("azure.unreachable", true, err, nil)
			}
			return p.Open(ctx, providers.TargetRef{ID: uuid.New()}, &azureCreds{}, providers.Env{})
		},
	})
	assert.Empty(t, r.failures)
}

func TestFakeDiscoverRecordsTheRequest(t *testing.T) {
	p := vaultFake()
	s := openVault(t, p)
	known := map[string]providers.KVKnown{"web": {Version: strings.Repeat("a", 32)}}
	keys := map[string]time.Time{"k": time.Unix(1, 0)}
	_, err := s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKeys: true, KVKnown: known, KVKnownKeys: keys})
	require.NoError(t, err)
	known["web"] = providers.KVKnown{Version: "changed"}
	known["other"] = providers.KVKnown{}
	keys["k"] = time.Unix(2, 0)
	var rec fake.Call
	for _, c := range p.Calls() {
		if c.Method == "Discover" {
			rec = c
		}
	}
	assert.True(t, rec.Discover.KVKeys)
	assert.True(t, rec.Discover.Certificates)
	assert.Equal(t, map[string]providers.KVKnown{"web": {Version: strings.Repeat("a", 32)}}, rec.Discover.KVKnown)
	assert.Equal(t, map[string]time.Time{"k": time.Unix(1, 0)}, rec.Discover.KVKnownKeys)
	rec.Discover.KVKnown["x"] = providers.KVKnown{}
	for _, c := range p.Calls() {
		if c.Method == "Discover" {
			assert.Len(t, c.Discover.KVKnown, 1, "Calls returns copies")
		}
	}
}

func TestFakeVaultValidatesVaultURLNotHost(t *testing.T) {
	p := vaultFake()
	assert.Equal(t, []validate.FieldError{{Field: "vault_url", Code: validate.Required}}, p.ValidateConfig(providers.TargetConfig{}))
	assert.Equal(t, []validate.FieldError{{Field: "vault_url", Code: validate.Required}}, p.ValidateConfig(providers.TargetConfig{"host": "x"}))
	bad := p.ValidateConfig(providers.TargetConfig{"vault_url": "https://x@evil.test"})
	require.Len(t, bad, 1)
	assert.Equal(t, "vault_url", bad[0].Field)
	assert.Equal(t, validate.Pattern, bad[0].Code)
	assert.Empty(t, p.ValidateConfig(providers.TargetConfig{"vault_url": "https://contoso.vault.azure.net"}))
	assert.Empty(t, p.ValidateConfig(providers.TargetConfig{"vault_url": "contoso"}))
	providertest.CheckProvider(t, p)
}

func TestFakeImportRefusesAnExistingNameUnlessConfirmed(t *testing.T) {
	p := vaultFake()
	p.Configure(func(c *fake.Config) { c.ExistingNames = []string{"Web-Cert"} })
	s := openVault(t, p)
	res, err := s.ImportCertificate(context.Background(), providers.ImportRequest{Name: "web-cert"}, nil)
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, providers.CodeKVImportNameExists, pe.Code)
	assert.Equal(t, providers.ImportRefused, res.Outcome)
	res, err = s.ImportCertificate(context.Background(), providers.ImportRequest{Name: "WEB-CERT", ReplaceExisting: true}, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.ImportCreated, res.Outcome)
	res, err = s.ImportCertificate(context.Background(), providers.ImportRequest{Name: "new-cert"}, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.ImportCreated, res.Outcome)
}
