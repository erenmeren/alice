package providertest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"alice/internal/providers"
)

// Chain is a certificate chain (leaf first) and its private key, in PEM.
type Chain struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// LocationTargetHarness drives the deployment contract of a provider whose locations are not certificate files (R59
// G7: a Windows http.sys binding, a BIG-IP client SSL profile entry, a Kubernetes TLS Secret) against its fake
// counterpart. Every case opens a session to a fresh counterpart, so the cases do not see each other's changes.
type LocationTargetHarness struct {
	// Traits are what the provider declares (providers.TraitsOf).
	Traits providers.RollbackTraits
	// Fresh opens a session to a new counterpart whose Location holds Current, with ExpectCertSHA256 its token.
	Fresh            func(ctx context.Context) (providers.Session, error)
	Location         providers.CertLocation
	ExpectCertSHA256 string
	// Current is what the location holds; Next is a certificate of the location's names with another key.
	Current, Next Chain
}

// MemoryBackups is a providers.HeldBackups in memory (what the engine's store does, without the database): it keeps
// the first backup held and counts the calls.
type MemoryBackups struct {
	mu           sync.Mutex
	held         *providers.HeldBackup
	Holds, Loads int
	// Fail makes Hold fail (the store refused: the provider must change nothing).
	Fail bool
}

// Hold keeps the first backup.
func (m *MemoryBackups) Hold(_ context.Context, b providers.HeldBackup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Holds++
	if m.Fail {
		return errors.New("providertest: the backup store refused")
	}
	if m.held == nil {
		c := providers.HeldBackup{CertificatePEM: append([]byte(nil), b.CertificatePEM...),
			PrivateKeyPEM: providers.NewSecret(append([]byte(nil), b.PrivateKeyPEM.Bytes()...))}
		m.held = &c
	}
	return nil
}

// Load returns a copy of the held backup, or providers.ErrNoHeldBackup.
func (m *MemoryBackups) Load(context.Context) (providers.HeldBackup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Loads++
	if m.held == nil {
		return providers.HeldBackup{}, providers.ErrNoHeldBackup
	}
	return providers.HeldBackup{CertificatePEM: append([]byte(nil), m.held.CertificatePEM...),
		PrivateKeyPEM: providers.NewSecret(append([]byte(nil), m.held.PrivateKeyPEM.Bytes()...))}, nil
}

// Held returns the chain of the held backup ("" when none).
func (m *MemoryBackups) Held() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.held == nil {
		return nil
	}
	return m.held.CertificatePEM
}

// CheckLocationTarget runs the deployment contract for a location that is not a file:
//
//   - the declared rollback traits are consistent, the location has a kind and a canonical locator;
//   - every outcome passes providers.CheckDeployReturn / CheckRollbackReturn and every state DeploymentState.Validate;
//   - a deployment whose ExpectCertSHA256 is not the location's token changes nothing (no_change);
//   - the fence (AUD-05): an operation fenced before it was sent answers fenced and never runs afterwards, and a fence
//     of a committed operation answers its state without changing it;
//   - a deployment commits, and its status says so; a held-backup provider holds the location's previous content
//     before the change, and refuses to change anything when it cannot (no store, or the store refuses);
//   - the guard (R48): a Required guard is satisfiable on a target that never restores by itself; a rollback whose
//     backup is forbidden restores nothing (rollback_failed, error forbidden, deployment.rollback_forbidden); a rollback
//     with an empty guard restores (rolled_back), and a held-backup provider without its backup does not claim it did.
func CheckLocationTarget(t testing.TB, h LocationTargetHarness) {
	t.Helper()
	ctx := context.Background()
	if err := h.Traits.Validate(); err != nil {
		t.Errorf("rollback traits: %v", err)
	}
	if h.Location.Kind.IsFile() || !h.Location.Kind.Known() {
		t.Errorf("the location's kind %q is not a known kind other than a file", h.Location.Kind)
	}
	if _, err := h.Location.Locator.Canonical(); err != nil {
		t.Errorf("the location's locator: %v", err)
	}
	held := h.Traits.Backup == providers.BackupHeldByAlice
	currentLeaf := leafHash(h.Current.CertificatePEM)
	open := func(name string) providers.Session {
		t.Helper()
		s, err := h.Fresh(ctx)
		if err != nil {
			t.Errorf("%s: open: %v", name, err)
			return nil
		}
		return s
	}
	deploy := func(name string, s providers.Session, op uuid.UUID, expect string, guard providers.RollbackGuard,
		b providers.HeldBackups) providers.DeployOutcome {
		t.Helper()
		out, err := s.DeployCertificate(ctx, providers.DeployRequest{OperationID: op, Location: h.Location, ExpectCertSHA256: expect,
			CertificatePEM: h.Next.CertificatePEM, PrivateKeyPEM: providers.NewSecret(append([]byte(nil), h.Next.PrivateKeyPEM...)),
			Fingerprint: leafHash(h.Next.CertificatePEM), ChainLength: chainLength(h.Next.CertificatePEM), Verify: providers.VerifyOptions{Skip: true},
			Guard: guard, Backups: b}, nopSteps{})
		if cerr := providers.CheckDeployReturn(out, err); cerr != nil {
			t.Errorf("%s: DeployCertificate: %v", name, cerr)
		}
		return out
	}
	state := func(name string, call func(context.Context, uuid.UUID) (providers.DeploymentState, error), op uuid.UUID) providers.DeploymentState {
		t.Helper()
		st, err := call(ctx, op)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			return st
		}
		if verr := st.Validate(); verr != nil {
			t.Errorf("%s: %v", name, verr)
		}
		return st
	}
	rollback := func(name string, s providers.Session, op uuid.UUID, guard providers.RollbackGuard, b providers.HeldBackups) providers.RollbackOutcome {
		t.Helper()
		out, err := s.RollbackDeployment(ctx, providers.RollbackRequest{OperationID: op, Location: h.Location,
			OldFingerprint: currentLeaf, Verify: providers.VerifyOptions{Skip: true}, Guard: guard, Backups: b}, nopSteps{})
		if cerr := providers.CheckRollbackReturn(out, err); cerr != nil {
			t.Errorf("%s: RollbackDeployment: %v", name, cerr)
		}
		return out
	}

	if s := open("precondition"); s != nil {
		out := deploy("precondition", s, uuid.New(), strings.Repeat("0", 64), providers.RollbackGuard{}, &MemoryBackups{})
		if out.Result != providers.DeployNoChange {
			t.Errorf("precondition: a location that holds another token answered %q, want no_change", out.Result)
		}
		_ = s.Close()
	}

	if s := open("fence"); s != nil {
		op := uuid.New()
		st := state("fence: FenceDeployment", s.FenceDeployment, op)
		if st.Phase != providers.PhaseFenced {
			t.Errorf("fence: an operation never sent answered phase %q, want fenced", st.Phase)
		}
		if out := deploy("fence", s, op, h.ExpectCertSHA256, providers.RollbackGuard{}, &MemoryBackups{}); out.Result != providers.DeployNoChange {
			t.Errorf("fence: a fenced operation answered %q, want no_change: it never runs", out.Result)
		}
		if st := state("fence: DeploymentStatus", s.DeploymentStatus, op); st.Phase != providers.PhaseFenced {
			t.Errorf("fence: the fenced operation's status is %q, want fenced", st.Phase)
		}
		_ = s.Close()
	}

	if s := open("deploy"); s != nil {
		op, b := uuid.New(), &MemoryBackups{}
		out := deploy("deploy", s, op, h.ExpectCertSHA256, providers.RollbackGuard{}, b)
		if out.Result != providers.DeployCommitted {
			t.Errorf("deploy: answered %q, want committed", out.Result)
		}
		if st := state("deploy: DeploymentStatus", s.DeploymentStatus, op); st.Phase != providers.PhaseCommitted {
			t.Errorf("deploy: status %q, want committed", st.Phase)
		}
		if st := state("deploy: FenceDeployment", s.FenceDeployment, op); st.Phase == providers.PhaseFenced {
			t.Errorf("deploy: a fence of a committed operation answered fenced: only an operation that wrote nothing is fenced")
		}
		if held && leafHash(b.Held()) != currentLeaf {
			t.Errorf("deploy: a held-backup provider did not hold the location's previous content")
		}
		if !held && b.Holds > 0 {
			t.Errorf("deploy: a provider that keeps its backup on the target held one in Alice")
		}

		// R48: a forbidden backup is never put back.
		forbidden := providers.RollbackGuard{ForbiddenLeaf: []string{currentLeaf}, TargetForbidden: true}
		rb := rollback("guarded rollback", s, op, forbidden, b)
		if rb.Result != providers.DeployRollbackFailed || rb.Error != providers.DeployErrForbidden || rb.Reason != providers.ReasonRollbackForbidden {
			t.Errorf("guarded rollback: answered %q (error %q, reason %q), want rollback_failed, forbidden, %s", rb.Result, rb.Error, rb.Reason,
				providers.ReasonRollbackForbidden)
		}
		_ = s.Close()
	}

	// A rollback with an empty guard restores. It runs on an operation of its own: a target may keep a
	// restore its guard once forbade forbidden for good (the Windows helper does, W2).
	if s := open("rollback"); s != nil {
		op, b := uuid.New(), &MemoryBackups{}
		if out := deploy("rollback", s, op, h.ExpectCertSHA256, providers.RollbackGuard{}, b); out.Result != providers.DeployCommitted {
			t.Errorf("rollback: the deployment answered %q, want committed", out.Result)
		}
		rb := rollback("rollback", s, op, providers.RollbackGuard{}, b)
		if rb.Result != providers.DeployRolledBack {
			t.Errorf("rollback: answered %q, want rolled_back", rb.Result)
		}
		state("rollback: DeploymentStatus", s.DeploymentStatus, op)
		_ = s.Close()
	}

	if s := open("required guard"); s != nil {
		required := providers.RollbackGuard{ForbiddenLeaf: []string{currentLeaf}, TargetForbidden: true, Required: true}
		out := deploy("required guard", s, uuid.New(), h.ExpectCertSHA256, required, &MemoryBackups{})
		if !h.Traits.SelfRestores && out.Result != providers.DeployCommitted {
			t.Errorf("required guard: a target that never restores by itself refused (%q, %s): the guard is satisfiable", out.Result, out.Reason)
		}
		_ = s.Close()
	}

	if !held {
		return
	}
	for name, b := range map[string]providers.HeldBackups{"no backup store": nil, "a refusing store": &MemoryBackups{Fail: true}} {
		if s := open(name); s != nil {
			if out := deploy(name, s, uuid.New(), h.ExpectCertSHA256, providers.RollbackGuard{}, b); out.Result != providers.DeployNoChange {
				t.Errorf("%s: answered %q, want no_change: nothing changes without the backup held", name, out.Result)
			}
			_ = s.Close()
		}
	}
	if s := open("lost backup"); s != nil {
		op := uuid.New()
		if out := deploy("lost backup", s, op, h.ExpectCertSHA256, providers.RollbackGuard{}, &MemoryBackups{}); out.Result == providers.DeployCommitted {
			if rb := rollback("lost backup", s, op, providers.RollbackGuard{}, &MemoryBackups{}); rb.Result == providers.DeployRolledBack {
				t.Errorf("lost backup: a rollback without its held backup answered rolled_back")
			}
		}
		_ = s.Close()
	}
}

type nopSteps struct{}

func (nopSteps) Step(string, providers.StepStatus, map[string]string) {}

// leafHash is the hex SHA-256 of the DER of the first certificate of a PEM chain ("" when none).
func leafHash(p []byte) string {
	b, _ := pem.Decode(p)
	if b == nil || b.Type != "CERTIFICATE" {
		return ""
	}
	if _, err := x509.ParseCertificate(b.Bytes); err != nil {
		return ""
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:])
}

func chainLength(p []byte) int {
	n := 0
	for rest := p; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return n
		}
		if b.Type == "CERTIFICATE" {
			n++
		}
	}
}
