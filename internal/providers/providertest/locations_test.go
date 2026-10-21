package providertest_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/providertest"
	"alice/internal/testutil/pki"
)

// secretTarget is a reference counterpart of a location that is not a file: one Kubernetes-like TLS Secret, written
// whole, its previous content held by Alice (BackupHeldByAlice), never restored by itself. Each flag breaks one rule of
// the contract.
type secretTarget struct {
	providers.UnsupportedSession
	chain, key []byte
	journal    map[uuid.UUID]string
	held       bool // the provider's declared model is held_by_alice

	ignorePrecondition bool
	ignoreFence        bool
	restoreForbidden   bool
	skipHold           bool
	fenceCommitted     bool
	claimWithoutBackup bool
}

func token(chain []byte) string {
	s := sha256.Sum256(chain)
	return hex.EncodeToString(s[:])
}

func refuse(code string) (providers.DeployOutcome, error) {
	return providers.DeployOutcome{Result: providers.DeployNoChange, Reason: code}, providers.NewError(code, false, nil, nil)
}

func (s *secretTarget) DeployCertificate(ctx context.Context, req providers.DeployRequest, _ providers.StepLogger) (providers.DeployOutcome, error) {
	switch {
	case s.journal[req.OperationID] == providers.PhaseFenced && !s.ignoreFence:
		return refuse("deployment.fenced")
	case req.ExpectCertSHA256 != token(s.chain) && !s.ignorePrecondition:
		return refuse("deployment.precondition")
	}
	if s.held && !s.skipHold {
		if req.Backups == nil {
			return refuse("deployment.backup_unavailable")
		}
		if err := req.Backups.Hold(ctx, providers.HeldBackup{CertificatePEM: s.chain, PrivateKeyPEM: providers.NewSecret(bytes.Clone(s.key))}); err != nil {
			return refuse("deployment.backup_unavailable")
		}
	}
	s.chain, s.key = bytes.Clone(req.CertificatePEM), bytes.Clone(req.PrivateKeyPEM.Bytes())
	s.journal[req.OperationID] = providers.PhaseCommitted
	return providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "skipped",
		Steps:  []providers.DeployStep{{Name: providers.StepNameBackup, Status: providers.StepOK}, {Name: providers.StepNameWriteSecret, Status: providers.StepOK}},
		Backup: providers.BackupRef{OperationID: req.OperationID}}, nil
}

func (s *secretTarget) RollbackDeployment(ctx context.Context, req providers.RollbackRequest, _ providers.StepLogger) (providers.RollbackOutcome, error) {
	if s.journal[req.OperationID] != providers.PhaseCommitted {
		return providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "deployment.unknown_operation"},
			providers.NewError("deployment.unknown_operation", false, nil, nil)
	}
	if req.Guard.RefusesUnchecked() && !s.restoreForbidden {
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: providers.StepNameRestore, Error: providers.DeployErrForbidden,
			Reason: providers.ReasonRollbackForbidden}, nil
	}
	b, err := req.Backups.Load(ctx)
	if err != nil && !s.claimWithoutBackup {
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: providers.StepNameRestore,
			Reason: "deployment.backup_missing"}, nil
	}
	if err == nil {
		s.chain, s.key = b.CertificatePEM, b.PrivateKeyPEM.Bytes()
	}
	s.journal[req.OperationID] = providers.PhaseRestored
	return providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}, nil
}

func (s *secretTarget) DeploymentStatus(_ context.Context, op uuid.UUID) (providers.DeploymentState, error) {
	if p, ok := s.journal[op]; ok {
		return providers.DeploymentState{Phase: p}, nil
	}
	return providers.DeploymentState{Phase: providers.PhaseNone}, nil
}

func (s *secretTarget) FenceDeployment(_ context.Context, op uuid.UUID) (providers.DeploymentState, error) {
	if p, ok := s.journal[op]; ok && !s.fenceCommitted {
		return providers.DeploymentState{Phase: p}, nil
	}
	s.journal[op] = providers.PhaseFenced
	return providers.DeploymentState{Phase: providers.PhaseFenced}, nil
}

func locationHarness(t *testing.T, traits providers.RollbackTraits, tweak func(*secretTarget)) providertest.LocationTargetHarness {
	t.Helper()
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	ca := pki.NewCA("Conformance", pki.ECDSA256, now)
	opts := pki.Opts{CommonName: "shop.example.test", SANs: []string{"shop.example.test"}}
	cur, next := ca.Issue(opts, now), ca.Issue(opts, now)
	return providertest.LocationTargetHarness{
		Traits: traits,
		Fresh: func(context.Context) (providers.Session, error) {
			s := &secretTarget{chain: cur.FullchainPEM, key: cur.KeyPEM, journal: map[uuid.UUID]string{}, held: traits.Backup == providers.BackupHeldByAlice}
			if tweak != nil {
				tweak(s)
			}
			return s, nil
		},
		Location: providers.CertLocation{Kind: providers.LocationK8sTLSSecret, Locator: providers.Locator{"namespace": "shop", "name": "shop-tls"},
			CertPath: "shop/shop-tls", Supported: true},
		ExpectCertSHA256: token(cur.FullchainPEM),
		Current:          providertest.Chain{CertificatePEM: cur.FullchainPEM, PrivateKeyPEM: cur.KeyPEM},
		Next:             providertest.Chain{CertificatePEM: next.FullchainPEM, PrivateKeyPEM: next.KeyPEM},
	}
}

var heldTraits = providers.RollbackTraits{Backup: providers.BackupHeldByAlice}

func TestCheckLocationTargetPassesAConformingTarget(t *testing.T) {
	for name, traits := range map[string]providers.RollbackTraits{
		"held by Alice":                         heldTraits,
		"on the target, restored only by Alice": {Backup: providers.BackupOnTarget},
	} {
		r := &recorder{TB: t}
		h := locationHarness(t, traits, nil)
		if traits.Backup == providers.BackupOnTarget {
			h.Fresh = onTargetFresh(h)
		}
		providertest.CheckLocationTarget(r, h)
		assert.Empty(t, r.failures, name)
	}
}

// onTargetFresh is a counterpart that keeps the previous content itself (a BIG-IP's previous objects).
func onTargetFresh(h providertest.LocationTargetHarness) func(context.Context) (providers.Session, error) {
	return func(context.Context) (providers.Session, error) {
		return &onTargetSession{secretTarget: secretTarget{chain: h.Current.CertificatePEM, key: h.Current.PrivateKeyPEM, journal: map[uuid.UUID]string{}}}, nil
	}
}

type onTargetSession struct {
	secretTarget
	previous, previousKey []byte
}

func (s *onTargetSession) DeployCertificate(ctx context.Context, req providers.DeployRequest, l providers.StepLogger) (providers.DeployOutcome, error) {
	prev, prevKey := s.chain, s.key
	out, err := s.secretTarget.DeployCertificate(ctx, req, l)
	if out.Result == providers.DeployCommitted {
		s.previous, s.previousKey = prev, prevKey
	}
	return out, err
}

func (s *onTargetSession) RollbackDeployment(ctx context.Context, req providers.RollbackRequest, l providers.StepLogger) (providers.RollbackOutcome, error) {
	if s.journal[req.OperationID] == providers.PhaseCommitted && !req.Guard.RefusesUnchecked() {
		s.chain, s.key = s.previous, s.previousKey
		s.journal[req.OperationID] = providers.PhaseRestored
		return providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}, nil
	}
	return s.secretTarget.RollbackDeployment(ctx, req, l)
}

func TestCheckLocationTargetCatchesBrokenTargets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		traits providers.RollbackTraits
		tweak  func(*secretTarget)
		want   string
	}{
		{"ignores the compare-and-swap", heldTraits, func(s *secretTarget) { s.ignorePrecondition = true }, "precondition"},
		{"runs a fenced operation", heldTraits, func(s *secretTarget) { s.ignoreFence = true }, "fence"},
		{"fences a committed operation", heldTraits, func(s *secretTarget) { s.fenceCommitted = true }, "fence of a committed operation"},
		{"restores a forbidden backup", heldTraits, func(s *secretTarget) { s.restoreForbidden = true }, "guarded rollback"},
		{"holds nothing", heldTraits, func(s *secretTarget) { s.skipHold = true }, "did not hold"},
		{"restores without its backup", heldTraits, func(s *secretTarget) { s.claimWithoutBackup = true }, "lost backup"},
		{"self-restore with nothing held", providers.RollbackTraits{Backup: providers.BackupHeldByAlice, SelfRestores: true}, nil, "rollback traits"},
	} {
		r := &recorder{TB: t}
		h := locationHarness(t, tc.traits, tc.tweak)
		providertest.CheckLocationTarget(r, h)
		require.NotEmpty(t, r.failures, tc.name)
		assert.True(t, containsAny(r.failures, tc.want), "%s: %v", tc.name, r.failures)
	}

	// The location must not be a file, and must have a canonical locator.
	r := &recorder{TB: t}
	h := locationHarness(t, heldTraits, nil)
	h.Location.Kind, h.Location.Locator = "", nil
	providertest.CheckLocationTarget(r, h)
	assert.True(t, containsAny(r.failures, "kind"))
	assert.True(t, containsAny(r.failures, "locator"))

	// A counterpart that cannot be opened is reported, not a panic.
	r = &recorder{TB: t}
	h = locationHarness(t, heldTraits, nil)
	h.Fresh = func(context.Context) (providers.Session, error) { return nil, errors.New("no counterpart") }
	providertest.CheckLocationTarget(r, h)
	assert.True(t, containsAny(r.failures, "open"))
}

func containsAny(failures []string, s string) bool {
	for _, f := range failures {
		if strings.Contains(f, s) {
			return true
		}
	}
	return false
}

func TestMemoryBackups(t *testing.T) {
	ctx := context.Background()
	m := &providertest.MemoryBackups{}
	_, err := m.Load(ctx)
	require.ErrorIs(t, err, providers.ErrNoHeldBackup)
	assert.Nil(t, m.Held())
	require.NoError(t, m.Hold(ctx, providers.HeldBackup{CertificatePEM: []byte("a"), PrivateKeyPEM: providers.NewSecret([]byte("k"))}))
	require.NoError(t, m.Hold(ctx, providers.HeldBackup{CertificatePEM: []byte("b"), PrivateKeyPEM: providers.NewSecret([]byte("l"))}))
	b, err := m.Load(ctx)
	require.NoError(t, err)
	assert.Equal(t, "a", string(b.CertificatePEM), "the first is kept")
	assert.Equal(t, "k", string(b.PrivateKeyPEM.Bytes()))
	assert.Equal(t, 2, m.Holds)
	assert.Equal(t, 2, m.Loads)
	m.Fail = true
	assert.Error(t, m.Hold(ctx, providers.HeldBackup{}))
}
