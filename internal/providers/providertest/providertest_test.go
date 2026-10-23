package providertest_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/providertest"
)

type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

const canary = "CANARY-6b1f0e"

// ctxSession implements TestConnection only. By default it honours its context like a good
// provider; the fields break one rule each.
type ctxSession struct {
	providers.UnsupportedSession
	ignoreCtx   bool          // succeeds with a cancelled context
	hang        time.Duration // waits this long regardless of the context
	leak        bool          // puts the canary into an error parameter
	plainErr    bool          // returns a plain error instead of *providers.Error
	unsupported bool          // answers ErrUnsupported although advertised
}

func (s ctxSession) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	if s.hang > 0 {
		time.Sleep(s.hang)
	}
	switch {
	case s.unsupported:
		return providers.ConnectionReport{}, providers.ErrUnsupported
	case s.leak:
		return providers.ConnectionReport{}, providers.NewError("ssh.auth_failed", false, nil, map[string]string{"key": canary})
	case ctx.Err() != nil && !s.ignoreCtx:
		return providers.ConnectionReport{}, providers.NewError("ssh.timeout", true, ctx.Err(), nil)
	case s.plainErr:
		return providers.ConnectionReport{}, errors.New("boom")
	}
	return providers.ConnectionReport{HelperVersion: "1"}, nil
}

func harness(s ctxSession) providertest.SessionHarness {
	return providertest.SessionHarness{
		Capabilities: providers.NewCapabilitySet(providers.CapTestConnection),
		Open: func(ctx context.Context) (providers.Session, error) {
			if err := ctx.Err(); err != nil {
				return nil, providers.NewError("ssh.timeout", true, err, nil)
			}
			return s, nil
		},
		Secrets:     []string{canary},
		CancelBound: 200 * time.Millisecond,
	}
}

func TestCheckSessionPassesAConformingSession(t *testing.T) {
	r := &recorder{TB: t}
	providertest.CheckSession(r, harness(ctxSession{}))
	assert.Empty(t, r.failures)
}

func TestCheckSessionCatchesBrokenSessions(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    ctxSession
		want string
	}{
		{"ignores the context", ctxSession{ignoreCtx: true}, "TestConnection with a cancelled context succeeded"},
		{"hangs", ctxSession{hang: time.Second}, "TestConnection with a cancelled context did not return within"},
		{"leaks a secret", ctxSession{leak: true}, "a secret appears in the output of *providers.Error"},
		{"plain error", ctxSession{plainErr: true, ignoreCtx: true}, "TestConnection returned *errors.errorString, want *providers.Error"},
		{"unsupported", ctxSession{unsupported: true}, "TestConnection answers ErrUnsupported although test_connection is advertised"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{TB: t}
			providertest.CheckSession(r, harness(tc.s))
			require.NotEmpty(t, r.failures)
			assert.Contains(t, fmt.Sprint(r.failures), tc.want)
		})
	}

	t.Run("open ignores the context", func(t *testing.T) {
		r := &recorder{TB: t}
		h := harness(ctxSession{})
		h.Open = func(context.Context) (providers.Session, error) { return ctxSession{}, nil }
		providertest.CheckSession(r, h)
		assert.Contains(t, fmt.Sprint(r.failures), "Open with a cancelled context succeeded")
	})
}

func TestCheckNoSecretsLooksAtEveryRendering(t *testing.T) {
	type result struct{ Note string }
	r := &recorder{TB: t}
	providertest.CheckNoSecrets(r, []string{canary},
		result{Note: "x" + canary},                                                                        // JSON and %+v
		providers.NewError("x", false, errors.New(canary), nil),                                           // the cause chain is rendered too
		providers.NewError("x", false, nil, map[string]string{"p": canary}),                               // params are
		providers.NewError("x", false, fmt.Errorf("a: %w", fmt.Errorf("b: %w", errors.New(canary))), nil), // deep in the chain
		providers.NewError("x", false, errors.New("harmless"), nil),
	)
	assert.Len(t, r.failures, 4, "%v", r.failures)
}

// deploySession breaks the deploy-related rules one at a time.
type deploySession struct {
	providers.UnsupportedSession
	implementsDeploy bool // DeployCertificate succeeds
	implementsVerify bool
	implementsStatus bool
	implementsDiscov bool
}

func (s deploySession) DeployCertificate(context.Context, providers.DeployRequest, providers.StepLogger) (providers.DeployOutcome, error) {
	if s.implementsDeploy {
		return providers.DeployOutcome{Result: providers.DeployCommitted}, nil
	}
	return providers.DeployOutcome{}, providers.ErrUnsupported
}

func (s deploySession) VerifyDeployment(ctx context.Context, _ providers.VerifyRequest) (providers.VerifyResult, error) {
	if s.implementsVerify {
		if err := ctx.Err(); err != nil {
			return providers.VerifyResult{}, providers.NewError("ssh.timeout", true, err, nil)
		}
		return providers.VerifyResult{}, nil
	}
	return providers.VerifyResult{}, providers.ErrUnsupported
}

func (s deploySession) DeploymentStatus(ctx context.Context, _ uuid.UUID) (providers.DeploymentState, error) {
	if s.implementsStatus {
		if err := ctx.Err(); err != nil {
			return providers.DeploymentState{}, providers.NewError("ssh.timeout", true, err, nil)
		}
		return providers.DeploymentState{Phase: providers.PhaseNone}, nil
	}
	return providers.DeploymentState{}, providers.ErrUnsupported
}

func (s deploySession) Discover(ctx context.Context, _ providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	if s.implementsDiscov {
		if err := ctx.Err(); err != nil {
			return providers.DiscoveryResult{}, providers.NewError("ssh.timeout", true, err, nil)
		}
		return providers.DiscoveryResult{}, nil
	}
	return providers.DiscoveryResult{}, providers.ErrUnsupported
}

func deployHarness(s deploySession, caps ...providers.Capability) providertest.SessionHarness {
	return providertest.SessionHarness{
		Capabilities: providers.NewCapabilitySet(caps...),
		Open: func(ctx context.Context) (providers.Session, error) {
			if err := ctx.Err(); err != nil {
				return nil, providers.NewError("ssh.timeout", true, err, nil)
			}
			return s, nil
		},
		CancelBound: 200 * time.Millisecond,
	}
}

func TestCheckSessionReportsAdvertisedButUnimplementedDeployCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    providertest.SessionHarness
		want string
	}{
		{"deploy", deployHarness(deploySession{}, providers.CapDeployCertificate), "DeploymentStatus answers ErrUnsupported although deploy_certificate is advertised"},
		{"verify", deployHarness(deploySession{}, providers.CapVerifyDeployment), "VerifyDeployment answers ErrUnsupported although verify_deployment is advertised"},
		{"discover certificates", deployHarness(deploySession{}, providers.CapDiscoverCerts), "DiscoverCertificates answers ErrUnsupported although discover_certificates is advertised"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{TB: t}
			providertest.CheckSession(r, tc.h)
			assert.Contains(t, fmt.Sprint(r.failures), tc.want)
		})
	}
}

func TestCheckSessionPassesImplementedDeployCapabilities(t *testing.T) {
	r := &recorder{TB: t}
	h := deployHarness(deploySession{implementsStatus: true, implementsVerify: true, implementsDiscov: true},
		providers.CapDeployCertificate, providers.CapVerifyDeployment, providers.CapDiscoverCerts)
	providertest.CheckSession(r, h)
	assert.Empty(t, r.failures)
}

func TestCheckUnsupportedCatchesUnadvertisedDeployMethods(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    deploySession
		caps []providers.Capability
		want string
	}{
		{"deploy", deploySession{implementsDeploy: true}, nil, "DeployCertificate without its capability"},
		{"verify", deploySession{implementsVerify: true}, []providers.Capability{providers.CapDeployCertificate}, "VerifyDeployment without its capability"},
		{"status", deploySession{implementsStatus: true}, []providers.Capability{providers.CapVerifyDeployment}, "DeploymentStatus without its capability"},
		{"discover certificates", deploySession{implementsDiscov: true}, []providers.Capability{providers.CapTestConnection}, "Discover without its capability"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{TB: t}
			providertest.CheckUnsupported(r, tc.s, providers.NewCapabilitySet(tc.caps...))
			assert.Contains(t, fmt.Sprint(r.failures), tc.want)
		})
	}
	t.Run("advertised methods are not checked", func(t *testing.T) {
		r := &recorder{TB: t}
		providertest.CheckUnsupported(r, deploySession{implementsDeploy: true, implementsVerify: true, implementsStatus: true},
			providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
				providers.CapDeployCertificate, providers.CapVerifyDeployment))
		assert.Empty(t, r.failures)
	})
}

func TestCheckOutcomeFunctionsReportContractViolations(t *testing.T) {
	r := &recorder{TB: t}
	providertest.CheckDeployOutcome(r, providers.DeployOutcome{Result: providers.DeployCommitted}, nil)
	providertest.CheckDeployOutcome(r, providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "x"}, providers.NewError("x", false, nil, nil))
	providertest.CheckRollbackOutcome(r, providers.RollbackOutcome{Result: providers.DeployRolledBack}, nil)
	providertest.CheckDeploymentState(r, providers.DeploymentState{Phase: providers.PhaseNone}, nil)
	providertest.CheckDeploymentState(r, providers.DeploymentState{}, errors.New("no state on error"))
	assert.Empty(t, r.failures)

	providertest.CheckDeployOutcome(r, providers.DeployOutcome{}, nil)
	providertest.CheckDeployOutcome(r, providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "x"}, nil)
	providertest.CheckRollbackOutcome(r, providers.RollbackOutcome{Result: providers.DeployUncertain}, nil)
	providertest.CheckDeploymentState(r, providers.DeploymentState{}, nil)
	require.Len(t, r.failures, 4, "%v", r.failures)
	assert.Contains(t, r.failures[0], "DeployCertificate")
	assert.Contains(t, r.failures[0], "blank or unknown result")
	assert.Contains(t, r.failures[1], "no_change without an error")
	assert.Contains(t, r.failures[2], "RollbackDeployment")
	assert.Contains(t, r.failures[3], "DeploymentStatus")
}

// stateSession answers DeploymentStatus with an invalid state.
type stateSession struct{ providers.UnsupportedSession }

func (stateSession) DeploymentStatus(context.Context, uuid.UUID) (providers.DeploymentState, error) {
	return providers.DeploymentState{Phase: "bogus"}, nil
}

func TestCheckSessionValidatesDeploymentStatus(t *testing.T) {
	r := &recorder{TB: t}
	providertest.CheckSession(r, providertest.SessionHarness{
		Capabilities: providers.NewCapabilitySet(providers.CapDeployCertificate),
		Open:         func(context.Context) (providers.Session, error) { return stateSession{}, nil },
		CancelBound:  200 * time.Millisecond,
	})
	assert.Contains(t, fmt.Sprint(r.failures), "DeploymentStatus returned an invalid result: providers: deployment state: blank or unknown phase")
}

// vaultSession breaks the rules of the Key Vault methods one at a time.
type vaultSession struct {
	providers.UnsupportedSession
	read       bool // ReadCertificateSecret is implemented (an empty request is refused)
	readOK     bool // ... and answers an empty request with a value
	readLeak   bool // ... and puts the canary in an error parameter
	importDone bool // ImportCertificate answers instead of ErrUnsupported
}

func (s vaultSession) ReadCertificateSecret(ctx context.Context, _ providers.SecretRequest) (providers.CertificateSecret, error) {
	switch {
	case !s.read:
		return providers.CertificateSecret{}, providers.ErrUnsupported
	case s.readLeak:
		return providers.CertificateSecret{}, providers.NewError("kv.secret_unreadable", false, nil, map[string]string{"value": canary})
	case ctx.Err() != nil:
		return providers.CertificateSecret{}, providers.NewError("azure.unreachable", true, ctx.Err(), nil)
	case s.readOK:
		return providers.CertificateSecret{ContentType: "application/x-pkcs12", Value: providers.NewSecret([]byte("v"))}, nil
	}
	return providers.CertificateSecret{}, providers.NewError("kv.version_not_deployable", false, nil, nil)
}

func (s vaultSession) ImportCertificate(context.Context, providers.ImportRequest, providers.StepLogger) (providers.ImportResult, error) {
	if s.importDone {
		return providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("x")
	}
	return providers.ImportResult{}, providers.ErrUnsupported
}

func vaultHarness(s vaultSession, caps ...providers.Capability) providertest.SessionHarness {
	h := deployHarness(deploySession{}, caps...)
	h.Open = func(ctx context.Context) (providers.Session, error) {
		if err := ctx.Err(); err != nil {
			return nil, providers.NewError("azure.unreachable", true, err, nil)
		}
		return s, nil
	}
	h.Secrets = []string{canary}
	return h
}

func TestCheckSessionCoversTheSecretRead(t *testing.T) {
	t.Run("an implemented read that refuses an empty request passes", func(t *testing.T) {
		r := &recorder{TB: t}
		providertest.CheckSession(r, vaultHarness(vaultSession{read: true}, providers.CapReadCertificateSecret))
		assert.Empty(t, r.failures)
	})
	for _, tc := range []struct {
		name string
		s    vaultSession
		want string
	}{
		{"advertised but unsupported", vaultSession{}, "ReadCertificateSecret answers ErrUnsupported although read_certificate_secret is advertised"},
		{"an empty request is read", vaultSession{read: true, readOK: true}, "ReadCertificateSecret accepted an empty request"},
		{"a secret in an error", vaultSession{read: true, readLeak: true}, "a secret appears in the output of *providers.Error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{TB: t}
			providertest.CheckSession(r, vaultHarness(tc.s, providers.CapReadCertificateSecret))
			assert.Contains(t, fmt.Sprint(r.failures), tc.want)
		})
	}
}

func TestCheckUnsupportedCoversTheVaultMethods(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    vaultSession
		caps []providers.Capability
		want string
	}{
		{"read", vaultSession{read: true}, nil, "ReadCertificateSecret without its capability"},
		{"import", vaultSession{importDone: true}, nil, "ImportCertificate without its capability"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{TB: t}
			providertest.CheckUnsupported(r, tc.s, providers.NewCapabilitySet(tc.caps...))
			assert.Contains(t, fmt.Sprint(r.failures), tc.want)
		})
	}
	t.Run("advertised methods are not checked", func(t *testing.T) {
		r := &recorder{TB: t}
		providertest.CheckUnsupported(r, vaultSession{read: true, importDone: true},
			providers.NewCapabilitySet(providers.CapReadCertificateSecret, providers.CapImportCertificate))
		assert.Empty(t, r.failures)
	})
	t.Run("a session without the methods passes", func(t *testing.T) {
		r := &recorder{TB: t}
		providertest.CheckUnsupported(r, vaultSession{}, providers.NewCapabilitySet())
		assert.Empty(t, r.failures)
	})
}

func TestCheckImportResultReportsABrokenResult(t *testing.T) {
	r := &recorder{TB: t}
	refusal := providers.NewError("azure.forbidden", false, nil, nil)
	providertest.CheckImportResult(r, providers.ImportResult{Outcome: providers.ImportRefused}, refusal)
	providertest.CheckImportResult(r, providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("timeout"))
	assert.Empty(t, r.failures)

	providertest.CheckImportResult(r, providers.ImportResult{Outcome: providers.ImportRefused}, errors.New("timeout"))
	providertest.CheckImportResult(r, providers.ImportResult{}, nil)
	require.Len(t, r.failures, 2, "%v", r.failures)
	assert.Contains(t, r.failures[0], "ImportCertificate: ")
	assert.Contains(t, r.failures[0], "refused needs a *providers.Error")
	assert.Contains(t, r.failures[1], "blank or unknown outcome")
}

// cleanerSession implements TestConnection (ctxSession) and providers.CertificateCleaner; unsupported
// makes both cleanup methods answer ErrUnsupported.
type cleanerSession struct {
	ctxSession
	unsupported bool
}

func (s cleanerSession) PlanCleanup(context.Context, []providers.CleanupRef) (providers.CleanupPlan, error) {
	if s.unsupported {
		return providers.CleanupPlan{}, providers.ErrUnsupported
	}
	return providers.CleanupPlan{}, nil
}

func (s cleanerSession) ApplyCleanup(context.Context, []providers.CleanupItem) (providers.CleanupApplyResult, error) {
	if s.unsupported {
		return providers.CleanupApplyResult{}, providers.ErrUnsupported
	}
	return providers.CleanupApplyResult{}, nil
}

// cleanup_certificates is accepted only from a session that implements providers.CertificateCleaner
// (CheckSession never calls it: a plan writes on the server); a session that implements it without the
// capability answers ErrUnsupported (CheckUnsupported).
func TestCheckSessionNeedsTheCleanerForItsCapability(t *testing.T) {
	with := func(s providers.Session) providertest.SessionHarness {
		h := harness(ctxSession{})
		h.Capabilities = providers.NewCapabilitySet(providers.CapTestConnection, providers.CapCleanupCertificates)
		h.Open = func(ctx context.Context) (providers.Session, error) {
			if err := ctx.Err(); err != nil {
				return nil, providers.NewError("ssh.timeout", true, err, nil)
			}
			return s, nil
		}
		return h
	}
	r := &recorder{TB: t}
	providertest.CheckSession(r, with(ctxSession{}))
	assert.Equal(t, []string{"cleanup_certificates is advertised but the session is no providers.CertificateCleaner"}, r.failures)

	r = &recorder{TB: t}
	providertest.CheckSession(r, with(cleanerSession{}))
	assert.Empty(t, r.failures)

	r = &recorder{TB: t}
	providertest.CheckUnsupported(r, cleanerSession{}, providers.NewCapabilitySet(providers.CapTestConnection))
	assert.Equal(t, []string{"PlanCleanup without its capability: got <nil>, want ErrUnsupported",
		"ApplyCleanup without its capability: got <nil>, want ErrUnsupported"}, r.failures)
	r = &recorder{TB: t}
	providertest.CheckUnsupported(r, cleanerSession{unsupported: true}, providers.NewCapabilitySet(providers.CapTestConnection))
	assert.Empty(t, r.failures)
	r = &recorder{TB: t}
	providertest.CheckUnsupported(r, cleanerSession{}, providers.NewCapabilitySet(providers.CapTestConnection, providers.CapCleanupCertificates))
	assert.Empty(t, r.failures, "an advertised cleaner is not checked")
}
