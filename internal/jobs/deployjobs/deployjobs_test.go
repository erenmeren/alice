package deployjobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// fakeInv is an in-memory deployment record with the state machine's rules that the engine relies
// on (deployment_records.go): Begin from queued, Start from precheck only, the key only before the
// first send, outcomes refused for an unsent row, done frozen.
type fakeInv struct {
	mu       sync.Mutex
	clock    *clock.Fake
	dep      inventory.Deployment
	material inventory.Material
	target   inventory.Target
	key      []byte // the bytes handed out as PrivateKeyPEM (checked for zeroing)
	keyOut   secrets.Plaintext
	errs     map[string]error
	hooks    map[string]func(ctx context.Context) // run before the method
	log      []string
	steps    []string
	finishes []inventory.DeploymentFinish
	outcomes []inventory.OutcomeRecord
	retryAt  []time.Time
	started  *inventory.SendValues
	ctxErrs  map[string]error // the context's error when the method was called
	claims   map[string]inventory.Claim
	lost     bool // the job run's claim is lost: every write is refused (inventory's fence)
	// ops are the deployments that own operation ids (OperationDeployment).
	ops map[uuid.UUID]inventory.OperationOwner
	kv  kvFake // Key Vault deployments (kv_test.go)
	// guard is what RollbackGuard answers (R48), per deployment id when guards names it; guardErr its
	// error; guardReads counts the reads (kept out of log: the call sequences predate the guard).
	guard      providers.RollbackGuard
	guards     map[uuid.UUID]providers.RollbackGuard
	guardErr   error
	guardReads int
}

func (f *fakeInv) RollbackGuard(_ context.Context, id uuid.UUID) (providers.RollbackGuard, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.guardReads++
	if g, ok := f.guards[id]; ok {
		return g, f.guardErr
	}
	return f.guard, f.guardErr
}

var fencedWrites = []string{"BeginDeployment", "StartDeployment", "RecordDeploymentStep", "FinishDeployment", "RecordOutcome", "CheckClaim"}

func (f *fakeInv) CheckClaim(ctx context.Context) error { return f.call(ctx, "CheckClaim") }

func (f *fakeInv) call(ctx context.Context, name string) error {
	f.kv.trace.add("inv:" + name)
	f.mu.Lock()
	f.log = append(f.log, name)
	f.ctxErrs[name] = ctx.Err()
	if c, ok := inventory.ClaimFrom(ctx); ok {
		f.claims[name] = c
	}
	hook := f.hooks[name]
	f.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lost && slices.Contains(fencedWrites, name) {
		return inventory.ErrClaimLost
	}
	return f.errs[name]
}

// calls lists the deployment-record calls (D25: the target and step calls are asserted elsewhere).
func (f *fakeInv) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.log {
		if !slices.Contains([]string{"TargetRef", "RecordConnectionFailure", "RecordDeploymentStep"}, c) {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeInv) stepNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.steps...)
}

func (f *fakeInv) lastFinish() inventory.DeploymentFinish {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.finishes) == 0 {
		return inventory.DeploymentFinish{}
	}
	return f.finishes[len(f.finishes)-1]
}

func (f *fakeInv) TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error) {
	if err := f.call(ctx, "TargetRef"); err != nil {
		return providers.TargetRef{}, inventory.Target{}, err
	}
	if f.kv.vaultID != uuid.Nil && id == f.kv.vaultID {
		if f.kv.vaultErr != nil {
			return providers.TargetRef{}, inventory.Target{}, f.kv.vaultErr
		}
		return providers.TargetRef{ID: id, Name: "prod", Kind: providers.KindAzureKV}, f.kv.vault, nil
	}
	return providers.TargetRef{ID: id, Name: "web-01", Kind: providers.KindNginx}, f.target, nil
}

func (f *fakeInv) Credentials() providers.CredentialSource { return nil }
func (f *fakeInv) HostKeyStore() providers.HostKeyStore    { return nil }

func (f *fakeInv) RecordConnectionFailure(ctx context.Context, _ uuid.UUID, _ string) error {
	return f.call(ctx, "RecordConnectionFailure")
}

func (f *fakeInv) Deployment(ctx context.Context, _ uuid.UUID) (inventory.Deployment, error) {
	if err := f.call(ctx, "Deployment"); err != nil {
		return inventory.Deployment{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dep, nil
}

func (f *fakeInv) CheckRecoveryPending(ctx context.Context, _ uuid.UUID) error {
	return f.call(ctx, "CheckRecoveryPending")
}

func (f *fakeInv) OperationDeployment(ctx context.Context, op uuid.UUID) (inventory.OperationOwner, bool, error) {
	if err := f.call(ctx, "OperationDeployment"); err != nil {
		return inventory.OperationOwner{}, false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.ops[op]
	return o, ok, nil
}

func (f *fakeInv) BeginDeployment(ctx context.Context, _ uuid.UUID) (inventory.Deployment, error) {
	if err := f.call(ctx, "BeginDeployment"); err != nil {
		return inventory.Deployment{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dep.State == inventory.DeployStateQueued {
		f.dep.State, f.dep.Status = inventory.DeployStatePrecheck, inventory.DeployStatusRunning
		now := f.clock.Now()
		f.dep.StartedAt = &now
	}
	return f.dep, nil
}

func sentState(s string) bool {
	return s == inventory.DeployStateDeploying || s == inventory.DeployStateRecovering || s == inventory.DeployStateDone
}

func (f *fakeInv) DeploymentMaterial(ctx context.Context, _ uuid.UUID, withKey bool) (inventory.Material, error) {
	name := "DeploymentMaterial(false)"
	if withKey {
		name = "DeploymentMaterial(true)"
	}
	if err := f.call(ctx, name); err != nil {
		return inventory.Material{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if withKey && sentState(f.dep.State) {
		return inventory.Material{}, inventory.ErrDeploymentState
	}
	m := f.material
	m.Deployment = f.dep
	m.Recorded = sentState(f.dep.State)
	if m.Recorded {
		m.NewChainLength, m.PreviousFingerprint, m.PreviousChainLength = f.dep.NewChainLength, f.dep.PreviousFingerprint, f.dep.PreviousChainLength
	}
	m.PrivateKeyPEM = secrets.Plaintext{}
	if withKey && m.KV == nil { // a vault deployment's key comes from KVDeployMaterial, never from here
		f.key = append([]byte(nil), f.material.PrivateKeyPEM.Bytes()...)
		f.keyOut = secrets.NewPlaintext(f.key)
		m.PrivateKeyPEM = f.keyOut
	}
	return m, nil
}

func (f *fakeInv) StartDeployment(ctx context.Context, id uuid.UUID, v inventory.SendValues) error {
	if err := f.call(ctx, "StartDeployment"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dep.State != inventory.DeployStatePrecheck {
		return inventory.ErrDeploymentState
	}
	if v.OperationID != id {
		return errors.New("fake: the operation id is the deployment id")
	}
	f.started = &v
	op := v.OperationID
	now := f.clock.Now()
	f.dep.State, f.dep.OperationID, f.dep.StartedAt = inventory.DeployStateDeploying, &op, &now
	f.dep.NewChainLength, f.dep.PreviousFingerprint, f.dep.PreviousChainLength = v.NewChainLength, v.PreviousFingerprint, v.PreviousChainLength
	f.dep.ExpectCertSHA256 = v.ExpectCertSHA256
	return nil
}

func (f *fakeInv) RecordDeploymentStep(ctx context.Context, _ uuid.UUID, name string, status providers.StepStatus, params map[string]string) error {
	err := f.call(ctx, "RecordDeploymentStep")
	f.mu.Lock()
	f.steps = append(f.steps, name+":"+string(status))
	if f.kv.stepParams == nil {
		f.kv.stepParams = map[string]map[string]string{}
	}
	f.kv.stepParams[name+":"+string(status)] = maps.Clone(params)
	f.mu.Unlock()
	if h := f.hooks["step:"+name+":"+string(status)]; h != nil {
		h(ctx)
	}
	return err
}

func wasSent(d inventory.Deployment) bool {
	return (d.State == inventory.DeployStateDeploying || d.State == inventory.DeployStateRecovering) && d.OperationID != nil
}

func (f *fakeInv) finishLocked(fin inventory.DeploymentFinish) error {
	if f.dep.State == inventory.DeployStateDone {
		return nil
	}
	switch fin.Status {
	case inventory.DeployStatusFailed:
		// As inventory (B2-I1): failed after a possible send needs the proof that nothing was written.
		if wasSent(f.dep) && !fin.NothingWritten {
			return inventory.ErrDeploymentState
		}
	case inventory.DeployStatusUnchanged:
		if !wasSent(f.dep) && (f.dep.State != inventory.DeployStatePrecheck || fin.Verified == "") {
			return inventory.ErrDeploymentState
		}
	default:
		if !wasSent(f.dep) {
			return inventory.ErrDeploymentState
		}
	}
	if (fin.Status == inventory.DeployStatusSucceeded || fin.Status == inventory.DeployStatusUnchanged) && fin.Verified == "" {
		return errors.New("fake: a deployment succeeds only when verified")
	}
	f.finishes = append(f.finishes, fin)
	f.dep.State, f.dep.Status, f.dep.ErrorCode, f.dep.Verified = inventory.DeployStateDone, fin.Status, fin.ErrorCode, fin.Verified
	f.dep.ErrorParams = maps.Clone(fin.Params)
	if f.dep.ErrorParams == nil {
		f.dep.ErrorParams = map[string]string{}
	}
	return nil
}

func (f *fakeInv) FinishDeployment(ctx context.Context, _ uuid.UUID, fin inventory.DeploymentFinish) error {
	if err := f.call(ctx, "FinishDeployment"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.finishLocked(fin)
}

func (f *fakeInv) RecordOutcome(ctx context.Context, _ uuid.UUID, rec inventory.OutcomeRecord, retryAt time.Time) error {
	if err := f.call(ctx, "RecordOutcome"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outcomes = append(f.outcomes, rec)
	f.retryAt = append(f.retryAt, retryAt)
	if rec.Terminal {
		return f.finishLocked(rec.Finish)
	}
	if f.dep.State == inventory.DeployStateDone {
		return nil
	}
	if !wasSent(f.dep) {
		return inventory.ErrDeploymentState
	}
	f.dep.State, f.dep.Result, f.dep.ErrorCode = inventory.DeployStateRecovering, "uncertain", rec.Finish.ErrorCode
	if rec.Finish.VerifyFailedReason != "" {
		f.dep.VerifyFailedReason = rec.Finish.VerifyFailedReason
	}
	return nil
}

// stepLog is a jobs.StepRecorder.
type stepLog struct {
	mu    sync.Mutex
	names []string
}

func (s *stepLog) Step(name string, status providers.StepStatus, _ map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names = append(s.names, name+":"+string(status))
}

type fixture struct {
	t        *testing.T
	ctx      context.Context
	clock    *clock.Fake
	inv      *fakeInv
	prov     *fake.Provider
	h        *handlers
	steps    *stepLog
	logs     *bytes.Buffer
	id       uuid.UUID
	target   uuid.UUID
	old, nw  pki.Leaf
	current  string // the leaf served before the change
	openErr  error
	verify   *providers.VerifyResult // the pre-check's answer (nil = OK, current served)
	status   providers.DeploymentState
	statusFn func() (providers.DeploymentState, error)
	wrap     func(providers.Session) providers.Session
}

var nginxCaps = []providers.Capability{providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
	providers.CapDiscoverCerts, providers.CapDeployCertificate, providers.CapVerifyDeployment}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	f := &fixture{t: t, ctx: context.Background(), clock: clock.NewFake(now), steps: &stepLog{}, logs: &bytes.Buffer{},
		id: uuid.Must(uuid.NewV7()), target: uuid.Must(uuid.NewV7())}
	ca := pki.NewCA("Engine", pki.ECDSA256, now)
	www := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	f.old, f.nw = ca.Issue(www, now), ca.Issue(www, now)
	f.current = pki.Fingerprint(f.old.Cert)
	loc := providers.CertLocation{CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key", Supported: true,
		Servers: []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Port: 443}}}}}
	f.inv = &fakeInv{clock: f.clock, errs: map[string]error{}, hooks: map[string]func(context.Context){}, ctxErrs: map[string]error{}, claims: map[string]inventory.Claim{},
		target: inventory.Target{ID: f.target, Status: inventory.StatusOK},
		dep: inventory.Deployment{ID: f.id, TargetID: f.target, State: inventory.DeployStateQueued, Status: inventory.DeployStatusPending,
			NewFingerprint: pki.Fingerprint(f.nw.Cert), ErrorParams: map[string]string{}},
		material: inventory.Material{Location: loc, CertificatePEM: f.nw.FullchainPEM,
			PrivateKeyPEM: secrets.NewPlaintext(append([]byte(nil), f.nw.KeyPEM...)), Fingerprint: pki.Fingerprint(f.nw.Cert),
			SANs: f.nw.Cert.DNSNames, NotBefore: f.nw.Cert.NotBefore, NotAfter: f.nw.Cert.NotAfter, KeyType: "ecdsa",
			CurrentFingerprint: f.current, OldSANs: f.old.Cert.DNSNames, ExpectCertSHA256: sha(f.old.FullchainPEM), ConfigValid: true,
			NewChainLength: 2, NewCertSHA256: sha(f.nw.FullchainPEM)}}
	f.prov = fake.New(providers.KindNginx, nginxCaps...)
	f.prov.Configure(func(c *fake.Config) {
		c.OpenErr = nil
		c.Verify = func(req providers.VerifyRequest) (providers.VerifyResult, error) {
			if f.verify != nil && req.Fingerprint == f.current {
				return *f.verify, nil
			}
			return providers.VerifyResult{OK: true, Mode: "remote", Served: req.Fingerprint, ServedChainLength: max(req.ChainLength, 2)}, nil
		}
		c.Status = func(uuid.UUID) (providers.DeploymentState, error) {
			if f.statusFn != nil {
				return f.statusFn()
			}
			return f.status, nil
		}
	})
	reg := providers.NewRegistry()
	reg.Register(openErrProvider{Provider: f.prov, err: func() error { return f.openErr }, wrap: func(s providers.Session) providers.Session {
		if f.wrap != nil {
			return f.wrap(s)
		}
		return s
	}})
	reg.Freeze()
	f.h = newHandlers(Deps{Inventory: f.inv, Registry: reg, Clock: f.clock,
		Log: slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	return f
}

// openErrProvider fails Open with the fixture's error when one is set.
type openErrProvider struct {
	*fake.Provider
	err  func() error
	wrap func(providers.Session) providers.Session
}

func (p openErrProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	if err := p.err(); err != nil {
		return nil, err
	}
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return p.wrap(s), nil
}

func (f *fixture) job() jobs.Job {
	return jobs.Job{ID: uuid.Must(uuid.NewV7()), Type: jobs.CertificateDeploy, Kind: jobs.KindUser, TargetID: f.target,
		Payload: map[string]string{"deployment_id": f.id.String()}, Attempt: 1, MaxAttempts: 3}
}

func (f *fixture) recoverJob() jobs.Job {
	return jobs.Job{ID: uuid.Must(uuid.NewV7()), Type: jobs.CertificateDeployRecover, Kind: jobs.KindSystem, TargetID: f.target,
		Payload: map[string]string{"deployment_id": f.id.String()}, Attempt: 1, MaxAttempts: 1}
}

// sent puts the record where a crash after the start record leaves it.
func (f *fixture) sent(state string, startedAgo time.Duration) {
	op := f.id
	started := f.clock.Now().Add(-startedAgo)
	f.inv.dep.State, f.inv.dep.Status, f.inv.dep.OperationID, f.inv.dep.StartedAt = state, inventory.DeployStatusRunning, &op, &started
	f.inv.dep.NewChainLength, f.inv.dep.PreviousFingerprint, f.inv.dep.PreviousChainLength = 2, f.current, 2
}

func (f *fixture) keyZeroed() bool {
	return len(f.inv.key) > 0 && bytes.Equal(f.inv.key, make([]byte, len(f.inv.key)))
}

func failureOf(t *testing.T, err error) *jobs.Failure {
	t.Helper()
	var jf *jobs.Failure
	require.ErrorAs(t, err, &jf)
	return jf
}

func TestDeploySucceeds(t *testing.T) {
	f := newFixture(t)
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"deployment_id": f.id.String(), "outcome": "succeeded", "verified": "remote"}, res)
	assert.Equal(t, []string{"Deployment", "CheckRecoveryPending", "BeginDeployment", "DeploymentMaterial(true)", "StartDeployment",
		"CheckClaim", "RecordOutcome", "Deployment"}, f.inv.calls())
	require.Len(t, f.inv.outcomes, 1)
	fin := f.inv.lastFinish()
	assert.Equal(t, inventory.DeployStatusSucceeded, fin.Status)
	assert.Equal(t, "remote", fin.Verified)
	assert.Equal(t, sha(f.nw.FullchainPEM), fin.CertFileSHA256, "the location keeps the new file's hash")
	assert.Equal(t, f.clock.Now().Add(inventory.FirstRecoveryDelay), f.inv.retryAt[0])
	require.NotNil(t, f.inv.started)
	assert.Equal(t, inventory.SendValues{OperationID: f.id, ExpectCertSHA256: sha(f.old.FullchainPEM), NewChainLength: 2,
		PreviousFingerprint: f.current, PreviousChainLength: 2}, *f.inv.started, "the served certificate is recorded before the first mutation")
	assert.Equal(t, []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok",
		"reload:ok", "verify:ok"}, f.inv.stepNames())
	assert.Equal(t, f.inv.stepNames(), f.steps.names, "the job's step log sees the same steps")
	assert.True(t, f.keyZeroed(), "the key is zeroed after use")

	// The request was built from the material: the recorded chain length and operation id.
	var deploys []fake.Call
	for _, c := range f.prov.Calls() {
		if c.Method == "DeployCertificate" {
			deploys = append(deploys, c)
		}
	}
	require.Len(t, deploys, 1)
	assert.Equal(t, f.id, deploys[0].Op)
	assert.Equal(t, 2, deploys[0].Deploy.ChainLength)
	assert.Equal(t, f.current, deploys[0].Deploy.OldFingerprint)
	pre := f.prov.Calls()
	var precheck providers.VerifyRequest
	for _, c := range pre {
		if c.Method == "VerifyDeployment" {
			precheck = c.Verify
			break
		}
	}
	assert.Equal(t, f.current, precheck.Fingerprint, "the pre-check compares the currently deployed leaf")
	assert.Equal(t, "ecdsa", precheck.KeyType)
}

func TestDeployHandsTheKeyToTheSendAndZeroesIt(t *testing.T) {
	f := newFixture(t)
	var atSend []byte
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(req providers.DeployRequest) (providers.DeployOutcome, error) {
			atSend = append([]byte(nil), req.PrivateKeyPEM.Bytes()...)
			return providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "local"}, nil
		}
	})
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, f.nw.KeyPEM, atSend, "the certificate's own key is sent")
	assert.True(t, f.keyZeroed())
}

func TestDeployPrecheckRefusalsChangeNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(f *fixture)
		reason string
		params map[string]string
	}{
		{"F-19 expired at run time", func(f *fixture) { f.inv.material.NotAfter = f.clock.Now().Add(-time.Minute) }, "certificate.expired", nil},
		{"not valid yet", func(f *fixture) { f.inv.material.NotBefore = f.clock.Now().Add(time.Minute) }, "certificate.not_yet_valid", nil},
		{"configuration invalid", func(f *fixture) { f.inv.material.ConfigValid = false }, "nginx.config_invalid", nil},
		{"location no longer deployable", func(f *fixture) { f.inv.material.Location.Supported = false }, "nginx.location_unsupported", nil},
		{"F-07 cannot be checked", func(f *fixture) {
			f.verify = &providers.VerifyResult{Reason: "deployment.verify_unreachable", Params: map[string]string{"port": "443"}}
		}, "deployment.verify_unreachable", map[string]string{"port": "443"}},
		{"F-06 something else answers", func(f *fixture) {
			f.verify = &providers.VerifyResult{Mode: "remote", Served: strings.Repeat("c", 64), Reason: "deployment.verify_other",
				Params: map[string]string{"port": "8443"}}
		}, "deployment.verify_other", map[string]string{"port": "8443"}},
		{"current certificate unknown", func(f *fixture) { f.inv.material.CurrentFingerprint = "" }, "deployment.verify_other", nil},
		{"host key changed", func(f *fixture) { f.inv.target.Status = inventory.StatusHostKeyChanged }, "target.host_key_changed", nil},
		{"host key unconfirmed", func(f *fixture) { f.inv.target.Status = inventory.StatusPendingHostKey }, "target.host_key_unconfirmed", nil},
		{"disabled", func(f *fixture) { f.inv.target.Status = inventory.StatusDisabled }, "target.disabled", nil},
		{"server deleted", func(f *fixture) { f.inv.errs["TargetRef"] = inventory.ErrNotFound }, "system.not_found", nil},
		{"F-14 helper outdated", func(f *fixture) {
			f.openErr = providers.NewError("ssh.helper_outdated", false, nil, map[string]string{"helper_protocol": "3"})
		}, "ssh.helper_outdated", nil},
		{"no private key", func(f *fixture) { f.inv.errs["DeploymentMaterial(true)"] = inventory.ErrNoPrivateKey }, "certificate.no_private_key", nil},
		{"material gone", func(f *fixture) { f.inv.errs["DeploymentMaterial(true)"] = inventory.ErrNotFound }, "system.not_found", nil},
		{"a recovery is pending on the server", func(f *fixture) { f.inv.errs["CheckRecoveryPending"] = inventory.ErrRecoveryPending },
			"deployment.recovery_pending", nil},
		{"a recovery began before the start", func(f *fixture) { f.inv.errs["StartDeployment"] = inventory.ErrRecoveryPending },
			"deployment.recovery_pending", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.setup(f)
			res, err := f.h.deploy(f.ctx, f.job(), f.steps)
			jf := failureOf(t, err)
			assert.Equal(t, jobs.Permanent, jf.Class)
			assert.Equal(t, tc.reason, jf.Reason)
			assert.Equal(t, tc.params, jf.Params)
			assert.Equal(t, "failed", res["outcome"])
			assert.Zero(t, f.prov.Count("DeployCertificate"), "nothing was sent")
			assert.Equal(t, inventory.DeployStatusFailed, f.inv.lastFinish().Status)
			assert.Equal(t, tc.reason, f.inv.lastFinish().ErrorCode)
			assert.NotContains(t, f.inv.calls(), "RecordOutcome")
			if f.inv.key != nil {
				assert.True(t, f.keyZeroed(), "the key is zeroed on a refusal too")
			}
		})
	}
}

func TestDeployRetriesAConnectionFailureBeforeAnyChange(t *testing.T) {
	f := newFixture(t)
	f.openErr = providers.NewError("ssh.unreachable", true, nil, nil)
	_, err := f.h.deploy(f.ctx, f.job(), f.steps) // attempt 1 of 3
	jf := failureOf(t, err)
	assert.Equal(t, jobs.Retryable, jf.Class)
	assert.Equal(t, "ssh.unreachable", jf.Reason)
	assert.NotContains(t, f.inv.calls(), "FinishDeployment", "the deployment stays in precheck")
	assert.Equal(t, inventory.DeployStatePrecheck, f.inv.dep.State)
	assert.Contains(t, f.inv.log, "RecordConnectionFailure", "the target's status says why")
	assert.True(t, f.keyZeroed())

	j := f.job()
	j.Attempt = 3
	_, err = f.h.deploy(f.ctx, j, f.steps)
	jf = failureOf(t, err)
	assert.Equal(t, jobs.Permanent, jf.Class, "never dead with a job.dead email: the deployment's email is the alert")
	assert.Equal(t, inventory.DeployStatusFailed, f.inv.lastFinish().Status)
	assert.Equal(t, "ssh.unreachable", f.inv.lastFinish().ErrorCode)
	assert.Zero(t, f.prov.Count("DeployCertificate"))
}

func TestDeployPrecheckErrorsRetryThenFail(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fixture)
	}{
		{"verification error", func(f *fixture) {
			f.prov.Configure(func(c *fake.Config) {
				c.Verify = func(providers.VerifyRequest) (providers.VerifyResult, error) {
					return providers.VerifyResult{}, providers.NewError("ssh.unreachable", true, nil, nil)
				}
			})
		}},
		{"recovery check error", func(f *fixture) { f.inv.errs["CheckRecoveryPending"] = errors.New("db down") }},
		{"begin error", func(f *fixture) { f.inv.errs["BeginDeployment"] = errors.New("db down") }},
		{"material error", func(f *fixture) { f.inv.errs["DeploymentMaterial(true)"] = errors.New("db down") }},
		{"target read error", func(f *fixture) { f.inv.errs["TargetRef"] = errors.New("db down") }},
		{"start error", func(f *fixture) { f.inv.errs["StartDeployment"] = errors.New("db down") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.setup(f)
			_, err := f.h.deploy(f.ctx, f.job(), f.steps)
			assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
			assert.NotContains(t, f.inv.calls(), "FinishDeployment")
			j := f.job()
			j.Attempt = j.MaxAttempts
			_, err = f.h.deploy(f.ctx, j, f.steps)
			assert.Equal(t, jobs.Permanent, failureOf(t, err).Class)
			assert.Equal(t, inventory.DeployStatusFailed, f.inv.lastFinish().Status)
			assert.Zero(t, f.prov.Count("DeployCertificate"))
		})
	}
}

func verifyFailedParams() map[string]string {
	return map[string]string{"port": "443", "failed_step": "verify"}
}

func TestDeployOutcomes(t *testing.T) {
	restoreFailed := providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "rollback_reload",
		CauseStep: "config_test", Error: "syntax", Reason: "deployment.rollback_reload_failed", Params: map[string]string{"backup_dir": "/x"}}
	for _, tc := range []struct {
		name     string
		out      providers.DeployOutcome
		err      error
		rollback *providers.RollbackOutcome // the second restore after restore_failed
		rbErr    error
		status   string // "" = uncertain (recovering)
		code     string
		class    jobs.FailureClass // -1 = success
		verify   string            // the recorded verify_failed_reason
	}{
		{name: "committed", out: providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "remote"},
			status: inventory.DeployStatusSucceeded, class: -1},
		{name: "unchanged", out: providers.DeployOutcome{Result: providers.DeployUnchanged, Phase: providers.PhaseUnchanged, Verified: "local"},
			status: inventory.DeployStatusUnchanged, class: -1},
		{name: "committed without verification", out: providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted},
			code: "deployment.interrupted", class: jobs.NeedsAttention},
		{name: "helper refusal", out: providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.no_space"},
			err: providers.NewError("nginx.no_space", false, nil, nil), status: inventory.DeployStatusFailed, code: "nginx.no_space", class: jobs.Permanent},
		{name: "unchanged then verify failed", out: providers.DeployOutcome{Result: providers.DeployNoChange, Phase: providers.PhaseUnchanged,
			FailedStep: "verify", Reason: "deployment.verify_failed", Steps: []providers.DeployStep{{Name: "verify", Status: providers.StepFailed}},
			Params: map[string]string{"port": "443"}},
			err: providers.NewError("deployment.verify_failed", false, nil, nil), status: inventory.DeployStatusFailed, code: "deployment.verify_failed",
			class: jobs.Permanent, verify: "deployment.verify_failed"},
		{name: "helper rolled back", out: providers.DeployOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored,
			FailedStep: "config_test", CauseStep: "config_test", Error: "key_mismatch", Reason: "certificate.key_mismatch"},
			status: inventory.DeployStatusRolledBack, code: "certificate.key_mismatch", class: jobs.Permanent},
		{name: "verify failed, rolled back inline", out: providers.DeployOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored,
			FailedStep: "verify", CauseStep: "verify", Reason: "deployment.verify_failed", Params: map[string]string{"port": "443"}, Verified: "remote"},
			status: inventory.DeployStatusRolledBack, code: "deployment.verify_failed", class: jobs.Permanent, verify: "deployment.verify_failed"},
		{name: "files back, old not served", out: providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestored,
			FailedStep: "verify_old", CauseStep: "verify", Reason: "deployment.rollback_failed"},
			status: inventory.DeployStatusRollbackFailed, code: "deployment.rollback_failed", class: jobs.NeedsAttention},
		{name: "file changed by someone else", out: providers.DeployOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore",
			CauseStep: "verify", Error: "file_changed", Reason: "deployment.rollback_failed"},
			status: inventory.DeployStatusRollbackFailed, code: "deployment.rollback_failed", class: jobs.NeedsAttention},
		{name: "restore_failed, the second restore works", out: restoreFailed,
			rollback: &providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Verified: "remote"},
			status:   inventory.DeployStatusRolledBack, code: "deployment.config_test_failed", class: jobs.Permanent},
		{name: "restore_failed twice", out: restoreFailed,
			rollback: &providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "rollback_reload",
				CauseStep: "config_test", Reason: "deployment.rollback_reload_failed"},
			status: inventory.DeployStatusRollbackFailed, code: "deployment.rollback_reload_failed", class: jobs.NeedsAttention},
		{name: "restore_failed, the second restore is lost", out: restoreFailed,
			rollback: &providers.RollbackOutcome{Result: providers.DeployUncertain}, rbErr: providers.NewError("ssh.unreachable", true, nil, nil),
			code: "ssh.unreachable", class: jobs.NeedsAttention},
		{name: "restore_failed, the second restore is refused busy", out: restoreFailed,
			rollback: &providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "nginx.busy"}, rbErr: providers.NewError("nginx.busy", true, nil, nil),
			code: "nginx.busy", class: jobs.NeedsAttention},
		{name: "restore_failed, nothing to restore contradicts", out: restoreFailed,
			rollback: &providers.RollbackOutcome{Result: providers.DeployNoChange, Phase: providers.PhasePrepared, Reason: "deployment.nothing_to_restore"},
			code:     "deployment.interrupted", class: jobs.NeedsAttention},
		{name: "uncertain", out: providers.DeployOutcome{Result: providers.DeployUncertain}, err: providers.NewError("ssh.unreachable", true, nil, nil),
			code: "ssh.unreachable", class: jobs.NeedsAttention},
		{name: "uncertain after a failed verification", out: providers.DeployOutcome{Result: providers.DeployUncertain,
			Reason: "deployment.verify_failed", Params: verifyFailedParams()},
			err: providers.NewError("ssh.unreachable", true, nil, nil), code: "deployment.verify_failed", class: jobs.NeedsAttention,
			verify: "deployment.verify_failed"},
		{name: "unknown error", out: providers.DeployOutcome{Result: providers.DeployUncertain}, err: errors.New("eof"),
			code: "deployment.interrupted", class: jobs.NeedsAttention},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.prov.Configure(func(c *fake.Config) {
				c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) { return tc.out, tc.err }
				if tc.rollback != nil {
					c.Rollback = func(providers.RollbackRequest) (providers.RollbackOutcome, error) { return *tc.rollback, tc.rbErr }
				}
			})
			res, err := f.h.deploy(f.ctx, f.job(), f.steps)
			require.Len(t, f.inv.outcomes, 1)
			rec := f.inv.outcomes[0]
			assert.Equal(t, tc.status, rec.Finish.Status)
			assert.Equal(t, tc.status != "", rec.Terminal)
			assert.Equal(t, tc.code, rec.Finish.ErrorCode)
			assert.Equal(t, tc.verify, rec.Finish.VerifyFailedReason)
			assert.Equal(t, tc.rollback != nil, f.prov.Count("RollbackDeployment") == 1, "one more restore only after restore_failed")
			assert.LessOrEqual(t, f.prov.Count("RollbackDeployment"), 1)
			assert.Equal(t, 1, f.prov.Count("DeployCertificate"))
			assert.True(t, f.keyZeroed())
			if tc.class < 0 {
				require.NoError(t, err)
				assert.Equal(t, tc.status, res["outcome"])
				return
			}
			jf := failureOf(t, err)
			assert.Equal(t, tc.class, jf.Class)
			if tc.status == "" {
				assert.Equal(t, "deployment.interrupted", jf.Reason)
				assert.Equal(t, inventory.DeployStateRecovering, f.inv.dep.State)
				assert.Equal(t, f.clock.Now().Add(inventory.FirstRecoveryDelay), f.inv.retryAt[0])
			} else {
				assert.Equal(t, tc.code, jf.Reason)
			}
			assert.NotContains(t, jf.Params, "backup_dir", "no path in a job's error params")
		})
	}
}

func TestDeployRollbackAgainKeepsTheCause(t *testing.T) {
	f := newFixture(t)
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			return providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "restore",
				CauseStep: "verify", Reason: "deployment.rollback_failed"}, nil
		}
	})
	f.inv.hooks["RecordOutcome"] = nil
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.Error(t, err)
	rec := f.inv.outcomes[0]
	assert.Equal(t, inventory.DeployStatusRolledBack, rec.Finish.Status)
	assert.Equal(t, "verify", rec.Finish.FailedStep, "the step that started the rollback")
	assert.Equal(t, "verify", rec.Finish.CauseStep)
	var rb providers.RollbackRequest
	for _, c := range f.prov.Calls() {
		if c.Method == "RollbackDeployment" {
			rb = c.Rollback
		}
	}
	assert.Equal(t, f.id, rb.OperationID)
	assert.Equal(t, f.current, rb.OldFingerprint, "the recorded previous certificate")
}

func TestUncertainOutcomeStartsRecovery(t *testing.T) {
	f := newFixture(t)
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			return providers.DeployOutcome{Result: providers.DeployUncertain}, providers.NewError("ssh.unreachable", true, nil, nil)
		}
	})
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	jf := failureOf(t, err)
	assert.Equal(t, jobs.NeedsAttention, jf.Class)
	assert.Equal(t, "deployment.interrupted", jf.Reason)
	assert.Equal(t, "uncertain", res["outcome"])
	assert.Equal(t, []string{"Deployment", "CheckRecoveryPending", "BeginDeployment", "DeploymentMaterial(true)", "StartDeployment",
		"CheckClaim", "RecordOutcome", "Deployment"}, f.inv.calls(), "RecordOutcome only: no MarkRecovering, no RequestRecovery (the sweep paces)")
	assert.Equal(t, f.clock.Now().Add(inventory.FirstRecoveryDelay), f.inv.retryAt[0])
}

func TestDeployRecordFailureIsRetriedAndNeverResends(t *testing.T) {
	f := newFixture(t)
	f.inv.errs["RecordOutcome"] = errors.New("db down")
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
	assert.Equal(t, inventory.DeployStateDeploying, f.inv.dep.State)

	// The next attempt finds the deployment deploying: it recovers from the journal, never sends.
	delete(f.inv.errs, "RecordOutcome")
	f.status = providers.DeploymentState{Phase: providers.PhaseCommitted, NewCertSHA256: sha(f.nw.FullchainPEM), BackupDir: "/b"}
	j := f.job()
	j.Attempt = 2
	res, err := f.h.deploy(f.ctx, j, f.steps)
	require.NoError(t, err)
	assert.Equal(t, "succeeded", res["outcome"])
	assert.Equal(t, 1, f.prov.Count("DeployCertificate"), "sent once")
}

// §8.8: a deploy job that runs again after a crash never deploys again.
func TestRerunAfterACrashRecoversInsteadOfDeploying(t *testing.T) {
	for _, state := range []string{inventory.DeployStateDeploying, inventory.DeployStateRecovering} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			f.sent(state, time.Minute)
			f.status = providers.DeploymentState{Phase: providers.PhaseCommitted, NewCertSHA256: sha(f.nw.FullchainPEM), BackupDir: "/b"}
			res, err := f.h.deploy(f.ctx, f.job(), f.steps)
			require.NoError(t, err)
			assert.Equal(t, "succeeded", res["outcome"])
			assert.Zero(t, f.prov.Count("DeployCertificate"))
			assert.Equal(t, 1, f.prov.Count("DeploymentStatus"))
			assert.Contains(t, f.inv.calls(), "DeploymentMaterial(false)", "recovery never asks for the key")
			assert.NotContains(t, f.inv.calls(), "DeploymentMaterial(true)")
			assert.Equal(t, sha(f.nw.FullchainPEM), f.inv.lastFinish().CertFileSHA256, "the journal's new file hash")
		})
	}
}

func TestDeployOfAFinishedDeploymentAnswersItsRecord(t *testing.T) {
	for _, tc := range []struct {
		status string
		class  jobs.FailureClass
	}{{inventory.DeployStatusSucceeded, -1}, {inventory.DeployStatusFailed, jobs.Permanent}, {inventory.DeployStatusRolledBack, jobs.Permanent},
		{inventory.DeployStatusRollbackFailed, jobs.NeedsAttention}} {
		f := newFixture(t)
		f.inv.dep.State, f.inv.dep.Status, f.inv.dep.ErrorCode, f.inv.dep.Verified = inventory.DeployStateDone, tc.status, "x.y", "remote"
		f.inv.dep.ErrorParams = map[string]string{"port": "443", "backup_dir": "/var/lib/alice-helper/backups/x"}
		res, err := f.h.deploy(f.ctx, f.job(), f.steps)
		assert.Equal(t, tc.status, res["outcome"])
		assert.Equal(t, []string{"Deployment"}, f.inv.calls(), "nothing is done again")
		if tc.class < 0 {
			assert.NoError(t, err)
			continue
		}
		jf := failureOf(t, err)
		assert.Equal(t, tc.class, jf.Class)
		assert.Equal(t, map[string]string{"port": "443"}, jf.Params, "no path in the job's params")
		// The recovery job finding it done succeeds: nothing to recover.
		res, err = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
		require.NoError(t, err)
		assert.Equal(t, tc.status, res["outcome"])
	}
}

func TestDeployRefusesForeignJobsAndBadPayloads(t *testing.T) {
	f := newFixture(t)
	j := f.job()
	j.TargetID = uuid.Must(uuid.NewV7())
	_, err := f.h.deploy(f.ctx, j, f.steps)
	assert.Equal(t, "internal.unexpected", failureOf(t, err).Reason)
	_, err = f.h.recoverJob(f.ctx, func() jobs.Job { r := f.recoverJob(); r.TargetID = j.TargetID; return r }(), f.steps)
	assert.Equal(t, "internal.unexpected", failureOf(t, err).Reason)
	assert.Equal(t, []string{"Deployment", "Deployment"}, f.inv.calls(), "nothing touched without the deployment's server lock")

	j = f.job()
	j.Payload = map[string]string{"deployment_id": "nope"}
	_, err = f.h.deploy(f.ctx, j, f.steps)
	assert.Equal(t, jobs.Permanent, failureOf(t, err).Class)
	r := f.recoverJob()
	r.Payload = map[string]string{"deployment_id": "nope"}
	before := len(f.inv.calls())
	_, err = f.h.recoverJob(f.ctx, r, f.steps)
	assert.Equal(t, jobs.Permanent, failureOf(t, err).Class)
	assert.Len(t, f.inv.calls(), before, "a recovery without a deployment id reads nothing")
	f.inv.errs["Deployment"] = inventory.ErrNotFound
	_, err = f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, "system.not_found", failureOf(t, err).Reason)
	_, err = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	assert.Equal(t, "system.not_found", failureOf(t, err).Reason)
	f.inv.errs["Deployment"] = errors.New("db down")
	_, err = f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
	_, err = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
}

// The deploy job follows a state that changed under it (another run, a sweep) and never sends.
func TestDeployFollowsAStateThatChangedUnderIt(t *testing.T) {
	f := newFixture(t)
	f.inv.hooks["StartDeployment"] = func(context.Context) {
		f.inv.mu.Lock()
		f.inv.dep.State, f.inv.dep.Status = inventory.DeployStateDone, inventory.DeployStatusFailed
		f.inv.dep.ErrorCode = "deployment.interrupted"
		f.inv.mu.Unlock()
	}
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, "failed", res["outcome"])
	assert.Equal(t, "deployment.interrupted", failureOf(t, err).Reason)
	assert.Zero(t, f.prov.Count("DeployCertificate"))

	f = newFixture(t)
	f.inv.hooks["DeploymentMaterial(true)"] = func(context.Context) {
		f.inv.mu.Lock()
		op := f.id
		f.inv.dep.State, f.inv.dep.OperationID = inventory.DeployStateRecovering, &op
		started := f.clock.Now().Add(-time.Hour)
		f.inv.dep.StartedAt = &started
		f.inv.mu.Unlock()
	}
	f.status = providers.DeploymentState{Phase: providers.PhaseNone}
	res, err = f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, "failed", res["outcome"])
	require.Error(t, err)
	assert.Zero(t, f.prov.Count("DeployCertificate"))
	assert.Equal(t, 1, f.prov.Count("DeploymentStatus"))
}

func TestDeployCancelledBeforeTheStartRecordsNothing(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	f.prov.Configure(func(c *fake.Config) {
		c.Verify = func(req providers.VerifyRequest) (providers.VerifyResult, error) {
			cancel() // the lease is lost while the pre-check runs
			return providers.VerifyResult{OK: true, Mode: "remote", Served: req.Fingerprint, ServedChainLength: 2}, nil
		}
	})
	_, err := f.h.deploy(ctx, f.job(), f.steps)
	require.Error(t, err)
	assert.NotContains(t, f.inv.calls(), "StartDeployment")
	assert.NotContains(t, f.inv.calls(), "FinishDeployment", "a re-run deploys: nothing is recorded")
	assert.Equal(t, inventory.DeployStatePrecheck, f.inv.dep.State)
	assert.True(t, f.keyZeroed())

	// A pre-check error caused by the cancellation records nothing either, even on the last attempt.
	f = newFixture(t)
	ctx, cancel = context.WithCancel(f.ctx)
	f.prov.Configure(func(c *fake.Config) {
		c.Verify = func(providers.VerifyRequest) (providers.VerifyResult, error) {
			cancel()
			return providers.VerifyResult{}, providers.NewError("ssh.timeout", true, context.Canceled, nil)
		}
	})
	j := f.job()
	j.Attempt = 3
	_, err = f.h.deploy(ctx, j, f.steps)
	require.Error(t, err)
	assert.NotContains(t, f.inv.calls(), "FinishDeployment")
}

func TestDeployCancelledAfterTheStartEndsFailedWithoutASend(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	f.inv.hooks["StartDeployment"] = func(context.Context) { cancel() }
	res, err := f.h.deploy(ctx, f.job(), f.steps)
	assert.Equal(t, "failed", res["outcome"])
	assert.Equal(t, "deployment.interrupted", failureOf(t, err).Reason)
	assert.Zero(t, f.prov.Count("DeployCertificate"))
	assert.Equal(t, inventory.DeployStatusFailed, f.inv.lastFinish().Status)
	assert.NoError(t, f.inv.ctxErrs["FinishDeployment"], "the record is written with a context detached from the job's")
	assert.True(t, f.keyZeroed())
}

func TestDeployCancelledDuringTheSendRecordsUncertain(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			cancel() // the runner cancels the handler while nginx-deploy runs (heartbeats failed)
			return providers.DeployOutcome{Result: providers.DeployUncertain}, providers.NewError("ssh.timeout", true, context.Canceled, nil)
		}
	})
	_, err := f.h.deploy(ctx, f.job(), f.steps)
	assert.Equal(t, jobs.NeedsAttention, failureOf(t, err).Class)
	require.Len(t, f.inv.outcomes, 1)
	assert.False(t, f.inv.outcomes[0].Terminal, "nothing false: uncertain, recovery reads the journal")
	assert.Equal(t, inventory.DeployStateRecovering, f.inv.dep.State)
	assert.NoError(t, f.inv.ctxErrs["RecordOutcome"], "the outcome is written with a detached context")
}

func TestDeployCompletedOutcomeSurvivesACancelledContext(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			cancel() // the job's context ends right after the helper answered and verification passed
			return providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "remote"}, nil
		}
	})
	res, err := f.h.deploy(ctx, f.job(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, "succeeded", res["outcome"])
	assert.Equal(t, inventory.DeployStatusSucceeded, f.inv.lastFinish().Status)
}

func TestRecoveryDecisions(t *testing.T) {
	newSHA := strings.Repeat("e", 64)
	for _, tc := range []struct {
		name     string
		phase    string
		active   bool
		age      time.Duration
		verifyOK bool
		status   string // "" = stays in recovery (uncertain)
		code     string
		rollback int
	}{
		{name: "none, old", phase: providers.PhaseNone, age: 2 * time.Minute, status: inventory.DeployStatusFailed, code: "deployment.interrupted"},
		{name: "prepared, old", phase: providers.PhasePrepared, age: 2 * time.Minute, status: inventory.DeployStatusFailed, code: "deployment.interrupted"},
		// AUD-05: the fence, not a 60-second wait, makes "nothing was written" final: a young start
		// record is fenced and ends failed like an old one.
		{name: "none, young (fenced)", phase: providers.PhaseNone, age: 30 * time.Second, status: inventory.DeployStatusFailed, code: "deployment.interrupted"},
		{name: "prepared, young (fenced)", phase: providers.PhasePrepared, age: 59 * time.Second, status: inventory.DeployStatusFailed, code: "deployment.interrupted"},
		{name: "fenced by an earlier recovery", phase: providers.PhaseFenced, age: time.Hour, status: inventory.DeployStatusFailed, code: "deployment.interrupted"},
		{name: "none, active", phase: providers.PhaseNone, active: true, age: time.Hour, code: "nginx.busy"},
		{name: "none, just under a day", phase: providers.PhaseNone, age: noJournalUnknownAfter - time.Minute, status: inventory.DeployStatusFailed,
			code: "deployment.interrupted"},
		{name: "none, after a long outage (journal swept)", phase: providers.PhaseNone, age: 8 * 24 * time.Hour,
			status: inventory.DeployStatusRollbackFailed, code: "deployment.outcome_unknown"},
		{name: "prepared, after a long outage", phase: providers.PhasePrepared, age: noJournalUnknownAfter + time.Minute,
			status: inventory.DeployStatusRollbackFailed, code: "deployment.outcome_unknown"},
		{name: "committed, verified", phase: providers.PhaseCommitted, verifyOK: true, status: inventory.DeployStatusSucceeded},
		{name: "committed, not served", phase: providers.PhaseCommitted, status: inventory.DeployStatusRolledBack, code: "deployment.verify_failed", rollback: 1},
		{name: "committed, active", phase: providers.PhaseCommitted, active: true, verifyOK: true, code: "nginx.busy"},
		{name: "unchanged, verified", phase: providers.PhaseUnchanged, verifyOK: true, status: inventory.DeployStatusUnchanged},
		{name: "unchanged, not served", phase: providers.PhaseUnchanged, status: inventory.DeployStatusFailed, code: "deployment.verify_failed"},
		{name: "writing", phase: providers.PhaseWriting, status: inventory.DeployStatusRolledBack, code: "deployment.interrupted", rollback: 1},
		{name: "restoring", phase: providers.PhaseRestoring, status: inventory.DeployStatusRolledBack, code: "deployment.interrupted", rollback: 1},
		{name: "restored", phase: providers.PhaseRestored, status: inventory.DeployStatusRolledBack, code: "deployment.interrupted", rollback: 1},
		{name: "restore_failed", phase: providers.PhaseRestoreFailed, status: inventory.DeployStatusRolledBack, code: "deployment.interrupted", rollback: 1},
		{name: "writing, active", phase: providers.PhaseWriting, active: true, code: "nginx.busy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.sent(inventory.DeployStateRecovering, tc.age)
			st := providers.DeploymentState{Phase: tc.phase, Active: tc.active}
			if tc.phase != providers.PhaseNone && tc.phase != providers.PhaseFenced {
				st.NewCertSHA256, st.BackupDir = newSHA, "/var/lib/alice-helper/backups/"+f.id.String()
			}
			f.status = st
			f.prov.Configure(func(c *fake.Config) {
				c.Verify = func(req providers.VerifyRequest) (providers.VerifyResult, error) {
					assert.Equal(t, f.inv.material.Fingerprint, req.Fingerprint, "the recorded new leaf")
					assert.Equal(t, 2, req.ChainLength, "the recorded chain length (Task 11 carry)")
					if tc.verifyOK {
						return providers.VerifyResult{OK: true, Mode: "remote", Served: req.Fingerprint, ServedChainLength: 2}, nil
					}
					return providers.VerifyResult{Mode: "remote", Served: f.current, ServedChainLength: 2, Reason: "deployment.verify_failed",
						Params: map[string]string{"port": "443"}}, nil
				}
			})
			res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
			require.NoError(t, err, "a recovery that recorded what it learned succeeds")
			require.Len(t, f.inv.outcomes, 1)
			rec := f.inv.outcomes[0]
			assert.Equal(t, tc.status, rec.Finish.Status)
			assert.Equal(t, tc.code, rec.Finish.ErrorCode)
			assert.Equal(t, tc.rollback, f.prov.Count("RollbackDeployment"))
			assert.Zero(t, f.prov.Count("DeployCertificate"))
			assert.NotContains(t, f.inv.calls(), "DeploymentMaterial(true)")
			fences := 0
			if (tc.phase == providers.PhaseNone || tc.phase == providers.PhasePrepared) && !tc.active {
				fences = 1 // AUD-05: fenced before "nothing was written"; best effort before "outcome unknown"
			}
			assert.Equal(t, fences, f.prov.Count("FenceDeployment"))
			if tc.status == "" {
				assert.Equal(t, "uncertain", res["outcome"])
				assert.Equal(t, f.clock.Now().Add(inventory.RecoveryRetryInterval), f.inv.retryAt[0])
			} else {
				assert.Equal(t, tc.status, res["outcome"])
			}
			if tc.status == inventory.DeployStatusSucceeded || tc.status == inventory.DeployStatusUnchanged {
				assert.Equal(t, newSHA, rec.Finish.CertFileSHA256, "the journal's new file hash")
				assert.Equal(t, "remote", rec.Finish.Verified)
			}
			if tc.phase == providers.PhaseCommitted && tc.status == inventory.DeployStatusRolledBack {
				assert.Equal(t, "deployment.verify_failed", rec.Finish.VerifyFailedReason, "the verification failure is recorded")
				require.NotNil(t, rec.Finish.VerifyFailedPort)
				assert.Equal(t, 443, *rec.Finish.VerifyFailedPort)
				assert.Equal(t, "verify", rec.Finish.FailedStep)
			}
		})
	}
}

func TestRecoveryRollbackOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		outs   []providers.RollbackOutcome
		errs   []error
		status string
		code   string
		sends  int
		quiet  string // the reason of a recovery job that ends failed quietly
	}{
		{name: "rolled back", outs: []providers.RollbackOutcome{{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Verified: "remote"}},
			status: inventory.DeployStatusRolledBack, code: "deployment.verify_failed", sends: 1},
		{name: "rolled back, old not checkable", outs: []providers.RollbackOutcome{{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}},
			status: inventory.DeployStatusRolledBack, code: "deployment.verify_failed", sends: 1},
		{name: "files back, another certificate served", outs: []providers.RollbackOutcome{{Result: providers.DeployRollbackFailed,
			Phase: providers.PhaseRestored, FailedStep: "verify_old", Reason: "deployment.rollback_failed"}},
			status: inventory.DeployStatusRollbackFailed, code: "deployment.rollback_failed", sends: 1},
		{name: "restore_failed, then rolled back", outs: []providers.RollbackOutcome{
			{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "rollback_reload", Reason: "deployment.rollback_reload_failed"},
			{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}},
			status: inventory.DeployStatusRolledBack, code: "deployment.verify_failed", sends: 2},
		{name: "restore_failed twice", outs: []providers.RollbackOutcome{
			{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "restore", Reason: "deployment.rollback_failed"},
			{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "restore", Reason: "deployment.rollback_failed"}},
			status: inventory.DeployStatusRollbackFailed, code: "deployment.rollback_failed", sends: 2},
		{name: "file changed", outs: []providers.RollbackOutcome{{Result: providers.DeployRollbackFailed, FailedStep: "restore", Error: "file_changed",
			Reason: "deployment.rollback_failed"}}, status: inventory.DeployStatusRollbackFailed, code: "deployment.rollback_failed", sends: 1},
		{name: "superseded is final", outs: []providers.RollbackOutcome{{Result: providers.DeployNoChange, Reason: "deployment.superseded"}},
			errs: []error{providers.NewError("deployment.superseded", false, nil, nil)}, status: inventory.DeployStatusRollbackFailed,
			code: "deployment.superseded", sends: 1},
		{name: "busy: nothing was restored", outs: []providers.RollbackOutcome{{Result: providers.DeployNoChange, Reason: "nginx.busy"}},
			errs: []error{providers.NewError("nginx.busy", true, nil, nil)}, code: "nginx.busy", sends: 1, quiet: "nginx.busy"},
		{name: "unknown operation: nothing was restored", outs: []providers.RollbackOutcome{{Result: providers.DeployNoChange,
			Reason: "deployment.unknown_operation"}}, errs: []error{providers.NewError("deployment.unknown_operation", false, nil, nil)},
			code: "deployment.unknown_operation", sends: 1, quiet: "deployment.unknown_operation"},
		{name: "io error: nothing was restored", outs: []providers.RollbackOutcome{{Result: providers.DeployNoChange, Reason: "ssh.helper_refused"}},
			errs: []error{providers.NewError("ssh.helper_refused", true, nil, nil)}, code: "ssh.helper_refused", sends: 1, quiet: "ssh.helper_refused"},
		{name: "nothing to restore contradicts the journal", outs: []providers.RollbackOutcome{{Result: providers.DeployNoChange,
			Phase: providers.PhaseUnchanged, Reason: "deployment.nothing_to_restore"}}, code: "deployment.interrupted", sends: 1},
		{name: "lost", outs: []providers.RollbackOutcome{{Result: providers.DeployUncertain}},
			errs: []error{providers.NewError("ssh.unreachable", true, nil, nil)}, code: "ssh.unreachable", sends: 1, quiet: "ssh.unreachable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.sent(inventory.DeployStateRecovering, time.Hour)
			f.status = providers.DeploymentState{Phase: providers.PhaseCommitted, NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
			n := 0
			f.prov.Configure(func(c *fake.Config) {
				c.Verify = func(providers.VerifyRequest) (providers.VerifyResult, error) {
					return providers.VerifyResult{Reason: "deployment.verify_failed", Params: map[string]string{"port": "443"}}, nil
				}
				c.Rollback = func(req providers.RollbackRequest) (providers.RollbackOutcome, error) {
					assert.Equal(t, f.current, req.OldFingerprint)
					assert.Equal(t, 2, req.OldChainLength, "the recorded previous chain length")
					i := min(n, len(tc.outs)-1)
					n++
					var err error
					if i < len(tc.errs) {
						err = tc.errs[i]
					}
					return tc.outs[i], err
				}
			})
			res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
			assert.Equal(t, tc.sends, f.prov.Count("RollbackDeployment"))
			require.Len(t, f.inv.outcomes, 1)
			assert.Equal(t, tc.status, f.inv.outcomes[0].Finish.Status)
			assert.Equal(t, tc.code, f.inv.outcomes[0].Finish.ErrorCode)
			if tc.quiet != "" {
				jf := failureOf(t, err)
				assert.Equal(t, tc.quiet, jf.Reason)
				assert.NotEqual(t, jobs.NeedsAttention, jf.Class)
			} else {
				require.NoError(t, err)
			}
			want := tc.status
			if want == "" {
				want = "uncertain"
			}
			assert.Equal(t, want, res["outcome"])
		})
	}
}

// A recovery that cannot reach the server records nothing and ends quietly: the sweep paces and
// escalates (the plan's last-attempt MarkRecovering(true) is superseded).
func TestRecoveryUnreachableEndsQuietly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fixture)
	}{
		{"open fails", func(f *fixture) { f.openErr = providers.NewError("ssh.unreachable", true, nil, nil) }},
		{"status fails", func(f *fixture) {
			f.statusFn = func() (providers.DeploymentState, error) {
				return providers.DeploymentState{}, providers.NewError("ssh.unreachable", true, nil, nil)
			}
		}},
		{"verification fails", func(f *fixture) {
			f.status = providers.DeploymentState{Phase: providers.PhaseCommitted, NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
			f.prov.Configure(func(c *fake.Config) {
				c.Verify = func(providers.VerifyRequest) (providers.VerifyResult, error) {
					return providers.VerifyResult{}, providers.NewError("ssh.unreachable", true, nil, nil)
				}
			})
		}},
		{"material read fails", func(f *fixture) { f.inv.errs["DeploymentMaterial(false)"] = errors.New("db down") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.sent(inventory.DeployStateRecovering, time.Hour)
			tc.setup(f)
			_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
			jf := failureOf(t, err)
			assert.Equal(t, jobs.Retryable, jf.Class, "one attempt: the runner ends it failed without an alert")
			assert.Empty(t, f.inv.outcomes, "nothing recorded: no MarkRecovering(true), no email")
			assert.NotContains(t, f.inv.calls(), "FinishDeployment")

			// The same in a deploy job that found the deployment sent: permanent, never re-run.
			f.inv.dep.State = inventory.DeployStateDeploying
			_, err = f.h.deploy(f.ctx, f.job(), f.steps)
			assert.Equal(t, jobs.Permanent, failureOf(t, err).Class)
			assert.Zero(t, f.prov.Count("DeployCertificate"))
		})
	}
}

func TestRecoveryWithoutAnOperationIDNeverContactsTheServer(t *testing.T) {
	f := newFixture(t)
	f.inv.dep.State = inventory.DeployStateDeploying // a row the engine did not start: nothing was sent
	res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, "failed", res["outcome"])
	assert.Equal(t, inventory.DeployStatusFailed, f.inv.lastFinish().Status)
	assert.Zero(t, f.prov.Count("Open"))
}

func TestRecoveryOfAnUnsentDeploymentDoesNothing(t *testing.T) {
	f := newFixture(t)
	f.inv.dep.State = inventory.DeployStatePrecheck
	res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, "precheck", res["outcome"])
	assert.Equal(t, []string{"Deployment"}, f.inv.calls())
}

// brokenStatus answers a journal state that breaks the provider contract (the fake refuses to).
type brokenStatus struct{ providers.Session }

func (brokenStatus) DeploymentStatus(context.Context, uuid.UUID) (providers.DeploymentState, error) {
	return providers.DeploymentState{Phase: providers.PhaseNone, BackupDir: "/x"}, nil
}

// brokenFence answers a fence with a tombstone that carries a hash (the fake refuses to).
type brokenFence struct{ providers.Session }

func (brokenFence) FenceDeployment(context.Context, uuid.UUID) (providers.DeploymentState, error) {
	return providers.DeploymentState{Phase: providers.PhaseFenced, NewCertSHA256: strings.Repeat("e", 64)}, nil
}

// brokenRollback answers a restore with rolled_back AND an error (the fake refuses to).
type brokenRollback struct{ providers.Session }

func (brokenRollback) RollbackDeployment(context.Context, providers.RollbackRequest, providers.StepLogger) (providers.RollbackOutcome, error) {
	return providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}, errors.New("and an error")
}

func TestRecoveryRefusesAJournalThatBreaksTheContract(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.wrap = func(s providers.Session) providers.Session { return brokenStatus{s} }
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	assert.Equal(t, "ssh.protocol_error", failureOf(t, err).Reason)
	assert.Empty(t, f.inv.outcomes, "never acted on: a phase none with a backup directory is not \"nothing was written\"")
}

func TestRecoveryAfterAnUncertainVerificationKeepsItsReason(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	port := 8443
	f.inv.dep.VerifyFailedReason, f.inv.dep.VerifyFailedPort = "deployment.verify_chain", &port
	f.status = providers.DeploymentState{Phase: providers.PhaseRestored, FailedStep: "verify", NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	rec := f.inv.outcomes[0]
	assert.Equal(t, inventory.DeployStatusRolledBack, rec.Finish.Status)
	assert.Equal(t, "deployment.verify_chain", rec.Finish.ErrorCode, "the recorded verification failure is why it was rolled back")
	assert.Equal(t, "deployment.verify_chain", rec.Finish.VerifyFailedReason)
}

func TestRecoveryNamesTheHelpersCause(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.status = providers.DeploymentState{Phase: providers.PhaseRestored, FailedStep: "config_test", CauseStep: "config_test", Error: "key_mismatch",
		NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	rec := f.inv.outcomes[0]
	assert.Equal(t, "certificate.key_mismatch", rec.Finish.ErrorCode)
	assert.Equal(t, "config_test", rec.Finish.FailedStep)
	assert.Equal(t, "key_mismatch", rec.Finish.HelperError)
}

func TestRecoveryInADeployJobUsesTheFirstRecoveryDelay(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateDeploying, 10*time.Second)
	f.status = providers.DeploymentState{Phase: providers.PhaseNone}
	f.prov.Configure(func(c *fake.Config) {
		c.Fence = func(uuid.UUID) (providers.DeploymentState, error) { // the late helper holds the lock now
			return providers.DeploymentState{Phase: providers.PhaseNone, Active: true}, nil
		}
	})
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, jobs.NeedsAttention, failureOf(t, err).Class)
	assert.Equal(t, f.clock.Now().Add(inventory.FirstRecoveryDelay), f.inv.retryAt[0], "S6: looked again soon")
}

func TestStepRecordFailureDoesNotStopTheDeployment(t *testing.T) {
	f := newFixture(t)
	f.inv.errs["RecordDeploymentStep"] = errors.New("db down")
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, "succeeded", res["outcome"])
	assert.Contains(t, f.logs.String(), "could not record a deployment step")
	assert.Contains(t, f.logs.String(), "error_type=*errors.errorString")
	assert.NotContains(t, f.logs.String(), "db down", "an error's text is never logged")
}

func TestRegisterInstallsBothHandlers(t *testing.T) {
	r := jobs.NewRunner(jobs.RunnerConfig{})
	assert.Panics(t, func() { Register(r, Deps{}) }, "a missing dependency fails at startup")
	assert.Panics(t, func() {
		Register(nil, Deps{Inventory: &fakeInv{}, Registry: providers.NewRegistry(), Clock: clock.NewFake(time.Now())})
	})
	Register(r, Deps{Inventory: &fakeInv{}, Registry: providers.NewRegistry(), Clock: clock.NewFake(time.Now())})
	assert.Panics(t, func() {
		r.Handle(jobs.CertificateDeploy, func(context.Context, jobs.Job, jobs.StepRecorder) (map[string]any, error) { return nil, nil })
	})
	assert.Panics(t, func() {
		r.Handle(jobs.CertificateDeployRecover, func(context.Context, jobs.Job, jobs.StepRecorder) (map[string]any, error) { return nil, nil })
	})
}

// No path of either handler shows the private key: results, errors, logs, steps and records.
func TestHandlersNeverShowTheKey(t *testing.T) {
	scenarios := []func(f *fixture){
		func(*fixture) {},
		func(f *fixture) { f.inv.material.NotAfter = f.clock.Now() },
		func(f *fixture) { f.openErr = providers.NewError("ssh.unreachable", true, errors.New("dial"), nil) },
		func(f *fixture) {
			f.prov.Configure(func(c *fake.Config) {
				c.Deploy = func(req providers.DeployRequest) (providers.DeployOutcome, error) {
					// A provider that wrongly wraps the request in its error must not leak through the engine.
					return providers.DeployOutcome{Result: providers.DeployUncertain},
						providers.NewError("ssh.unreachable", true, fmt.Errorf("lost %s", req.PrivateKeyPEM.Bytes()), nil)
				}
			})
		},
	}
	for i, setup := range scenarios {
		f := newFixture(t)
		setup(f)
		res, err := f.h.deploy(f.ctx, f.job(), f.steps)
		needles := keyNeedles(f.nw.KeyPEM)
		text := fmt.Sprintf("%v %+v %#v %s %v %v", res, res, err, f.logs.String(), f.inv.finishes, f.inv.outcomes)
		if err != nil {
			text += err.Error()
		}
		for j, n := range needles {
			assert.False(t, strings.Contains(text, n), "scenario %d: key marker %d leaked", i, j)
		}
	}
}

// keyNeedles are recognisable slices of a PEM key: its base64 body, the DER as hex and base64.
func keyNeedles(keyPEM []byte) []string {
	body := strings.Join(strings.Split(strings.TrimSpace(string(keyPEM)), "\n")[1:3], "")
	der, _ := base64.StdEncoding.DecodeString(strings.Join(strings.Split(strings.TrimSpace(string(keyPEM)), "\n")[1:len(strings.Split(strings.TrimSpace(string(keyPEM)), "\n"))-1], ""))
	return []string{"PRIVATE " + "KEY", body[:40], hex.EncodeToString(der)[:40], base64.StdEncoding.EncodeToString(der)[8:48]}
}

// When the record cannot be read back after an outcome was written, the job answers what it wrote.
func TestDeployAnswersWhatItWroteWhenTheRecordCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name  string
		out   providers.DeployOutcome
		err   error
		class jobs.FailureClass // -1 = success
	}{
		{"succeeded", providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "remote"}, nil, -1},
		{"rolled back", providers.DeployOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, FailedStep: "reload",
			CauseStep: "reload", Reason: "deployment.reload_failed"}, nil, jobs.Permanent},
		{"uncertain", providers.DeployOutcome{Result: providers.DeployUncertain}, providers.NewError("ssh.unreachable", true, nil, nil),
			jobs.NeedsAttention},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.prov.Configure(func(c *fake.Config) {
				c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) { return tc.out, tc.err }
			})
			f.inv.hooks["RecordOutcome"] = func(context.Context) { f.inv.errs["Deployment"] = errors.New("db down") }
			res, err := f.h.deploy(f.ctx, f.job(), f.steps)
			if tc.class < 0 {
				require.NoError(t, err)
				assert.Equal(t, "succeeded", res["outcome"])
				return
			}
			assert.Equal(t, tc.class, failureOf(t, err).Class)
		})
	}

	f := newFixture(t)
	f.inv.material.NotAfter = f.clock.Now()
	f.inv.hooks["FinishDeployment"] = func(context.Context) { f.inv.errs["Deployment"] = errors.New("db down") }
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, "failed", res["outcome"])
	assert.Equal(t, "certificate.expired", failureOf(t, err).Reason)
}

func TestDeployRefusalThatCannotBeRecordedIsRetried(t *testing.T) {
	f := newFixture(t)
	f.inv.material.ConfigValid = false
	f.inv.errs["FinishDeployment"] = errors.New("db down")
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	jf := failureOf(t, err)
	assert.Equal(t, jobs.Retryable, jf.Class, "nothing was sent: a retry is safe")
	assert.Zero(t, f.prov.Count("DeployCertificate"))
}

func TestDeployGivesUpOnAStateThatKeepsChanging(t *testing.T) {
	f := newFixture(t)
	f.inv.errs["DeploymentMaterial(true)"] = inventory.ErrDeploymentState // yet the record keeps saying precheck
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
	assert.Zero(t, f.prov.Count("DeployCertificate"))

	f = newFixture(t)
	f.inv.hooks["DeploymentMaterial(true)"] = func(context.Context) { f.inv.errs["Deployment"] = errors.New("db down") }
	f.inv.errs["DeploymentMaterial(true)"] = inventory.ErrDeploymentState
	_, err = f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
}

func TestCauseAndPortHelpers(t *testing.T) {
	assert.Equal(t, "certificate.key_mismatch", causeReason("config_test", "key_mismatch"))
	assert.Equal(t, "deployment.config_test_failed", causeReason("config_test", "syntax"))
	assert.Equal(t, "deployment.reload_failed", causeReason("reload", ""))
	assert.Empty(t, causeReason("write_key", ""))
	assert.Nil(t, portOf(map[string]string{"port": "x"}))
	assert.Nil(t, portOf(map[string]string{"port": "70000"}))
	assert.Equal(t, 443, *portOf(map[string]string{"port": "443"}))
	assert.Nil(t, permanent(nil))
	assert.Equal(t, jobs.NeedsAttention, failureOf(t, permanent(jobs.Attention("x", nil, nil))).Class)
	assert.Equal(t, "internal.unexpected", failure(errors.New("plain")).Reason)
}

// I-1: every write carries the job run's claim (inventory fences it).
func TestEveryWriteCarriesTheJobsClaim(t *testing.T) {
	f := newFixture(t)
	j := f.job()
	j.Attempt = 2
	_, err := f.h.deploy(f.ctx, j, f.steps)
	require.NoError(t, err)
	want := inventory.Claim{JobID: j.ID, Attempt: 2}
	for _, w := range []string{"BeginDeployment", "StartDeployment", "RecordDeploymentStep", "CheckClaim", "RecordOutcome"} {
		assert.Equal(t, want, f.inv.claims[w], w)
	}

	f = newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.status = providers.DeploymentState{Phase: providers.PhaseWriting, NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
	r := f.recoverJob()
	_, err = f.h.recoverJob(f.ctx, r, f.steps)
	require.NoError(t, err)
	for _, w := range []string{"CheckClaim", "RecordOutcome"} {
		assert.Equal(t, inventory.Claim{JobID: r.ID, Attempt: 1}, f.inv.claims[w], w)
	}
}

// I-1 (a): a run that lost its job after the send records nothing; (b): one that lost it after
// the start record does not send.
func TestStaleRunsWriteNothingAndSendNothing(t *testing.T) {
	f := newFixture(t)
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			f.inv.mu.Lock()
			f.inv.lost = true // stalled past the lease: another run holds the job now
			f.inv.mu.Unlock()
			return providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "remote"}, nil
		}
	})
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, "job.lease_expired", failureOf(t, err).Reason)
	assert.Empty(t, f.inv.finishes, "the stale run's success is not recorded")
	assert.Equal(t, inventory.DeployStateDeploying, f.inv.dep.State)

	f = newFixture(t)
	f.inv.hooks["CheckClaim"] = func(context.Context) {
		f.inv.mu.Lock()
		f.inv.lost = true
		f.inv.mu.Unlock()
	}
	_, err = f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, "job.lease_expired", failureOf(t, err).Reason)
	assert.Zero(t, f.prov.Count("DeployCertificate"), "a stale run does not send")
	assert.Empty(t, f.inv.finishes)
	assert.True(t, f.keyZeroed())

	// A recovery that lost its job does not restore.
	f = newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.status = providers.DeploymentState{Phase: providers.PhaseRestored, NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
	f.inv.lost = true
	_, err = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	assert.Equal(t, "job.lease_expired", failureOf(t, err).Reason)
	assert.Zero(t, f.prov.Count("RollbackDeployment"))
	assert.Empty(t, f.inv.outcomes)

	// Nor does the deploy path's one more restore after restore_failed.
	f = newFixture(t)
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			f.inv.mu.Lock()
			f.inv.lost = true
			f.inv.mu.Unlock()
			return providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "restore",
				CauseStep: "reload", Reason: "deployment.rollback_failed"}, nil
		}
	})
	_, err = f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, "job.lease_expired", failureOf(t, err).Reason)
	assert.Zero(t, f.prov.Count("RollbackDeployment"))
	assert.Empty(t, f.inv.finishes)
}

// I-3: a write that fails on the deploy job's last attempt never ends the job dead (a second alert).
func TestLastAttemptWriteFailuresArePermanent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fixture)
	}{
		{"outcome write", func(f *fixture) { f.inv.errs["RecordOutcome"] = errors.New("db down") }},
		{"refusal write", func(f *fixture) {
			f.inv.material.ConfigValid = false
			f.inv.errs["FinishDeployment"] = errors.New("db down")
		}},
		{"read", func(f *fixture) { f.inv.errs["Deployment"] = errors.New("db down") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.setup(f)
			j := f.job()
			_, err := f.h.deploy(f.ctx, j, f.steps)
			assert.Equal(t, jobs.Retryable, failureOf(t, err).Class, "attempts left: retried")
			f = newFixture(t)
			tc.setup(f)
			j.Attempt = j.MaxAttempts
			_, err = f.h.deploy(f.ctx, j, f.steps)
			assert.Equal(t, jobs.Permanent, failureOf(t, err).Class, "the last attempt: failed, not dead")
		})
	}
}

// M-1: a provider param outside the allowlist never reaches the jobs row, on any path.
func TestJobErrorsKeepOnlyAllowedParams(t *testing.T) {
	hostile := map[string]string{"port": "443", "stderr": "remote text", "directory": "/etc/x"}
	want := map[string]string{"port": "443"}

	f := newFixture(t) // before the send, attempts left: the error is returned as it is
	f.openErr = providers.NewError("ssh.unreachable", true, nil, hostile)
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, want, failureOf(t, err).Params)

	f = newFixture(t) // a recovery that cannot reach the server
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.openErr = providers.NewError("ssh.unreachable", true, nil, hostile)
	_, err = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	assert.Equal(t, want, failureOf(t, err).Params)

	f = newFixture(t) // a recovery whose rollback was lost: the cause's params
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.status = providers.DeploymentState{Phase: providers.PhaseRestored, NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
	f.prov.Configure(func(c *fake.Config) {
		c.Rollback = func(providers.RollbackRequest) (providers.RollbackOutcome, error) {
			return providers.RollbackOutcome{Result: providers.DeployUncertain}, providers.NewError("ssh.unreachable", true, nil, hostile)
		}
	})
	_, err = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	assert.Equal(t, want, failureOf(t, err).Params)
}

// M-2: the start record's age is measured from before the journal was read (the day rule: with
// the fence, no shorter rule is left).
func TestNoJournalAgeIsMeasuredBeforeTheRead(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, noJournalUnknownAfter-time.Minute)
	f.statusFn = func() (providers.DeploymentState, error) {
		f.clock.Advance(2 * time.Minute) // a slow answer
		return providers.DeploymentState{Phase: providers.PhaseNone}, nil
	}
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStatusFailed, f.inv.outcomes[0].Finish.Status, "under a day before the read: fenced, nothing was written")
}

// M-3: a verification failure recorded only as a step (the run died during the rollback) is why the
// recovery rolled back.
func TestRecoveryReadsTheVerificationFailureFromTheSteps(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.inv.dep.Steps = []inventory.DeploymentStep{{N: 1, Name: "verify", Status: "started", Params: map[string]string{}},
		{N: 2, Name: "verify", Status: "failed", Params: map[string]string{"port": "8443", "reason": "deployment.verify_chain"}},
		{N: 3, Name: "restore", Status: "ok", Params: map[string]string{}}}
	f.status = providers.DeploymentState{Phase: providers.PhaseRestored, NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	rec := f.inv.outcomes[0]
	assert.Equal(t, "deployment.verify_chain", rec.Finish.ErrorCode)
	assert.Equal(t, "deployment.verify_chain", rec.Finish.VerifyFailedReason)
	require.NotNil(t, rec.Finish.VerifyFailedPort)
	assert.Equal(t, 8443, *rec.Finish.VerifyFailedPort)
	assert.Equal(t, "verify", rec.Finish.FailedStep)

	// A step without a usable reason is ignored.
	f = newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.inv.dep.Steps = []inventory.DeploymentStep{{N: 1, Name: "verify", Status: "failed", Params: map[string]string{"reason": "Not a code!"}}}
	f.status = providers.DeploymentState{Phase: providers.PhaseRestored, NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
	_, err = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, "deployment.interrupted", f.inv.outcomes[0].Finish.ErrorCode)
}

// M-8: a record whose referenced rows cannot be read ends at once, outcome unknown.
func TestRecoveryWithoutMaterialEndsOutcomeUnknown(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.inv.errs["DeploymentMaterial(false)"] = inventory.ErrNotFound
	f.prov.Configure(func(c *fake.Config) {
		c.Fence = func(uuid.UUID) (providers.DeploymentState, error) {
			return providers.DeploymentState{}, providers.NewError("ssh.timeout", true, nil, nil)
		}
	})
	res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, "rollback_failed", res["outcome"])
	assert.Equal(t, "deployment.outcome_unknown", f.inv.lastFinish().ErrorCode)
	assert.Equal(t, 1, f.prov.Count("FenceDeployment"), "fix round 1 minor 2: fenced, best effort; its failure changes nothing")
}

// The best-effort fence before an outcome-unknown record opens its own session; when the server
// cannot be reached the outcome is recorded all the same, without a fence.
func TestRecoveryWithoutMaterialOnAnUnreachableServerEndsOutcomeUnknown(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.inv.errs["DeploymentMaterial(false)"] = inventory.ErrNotFound
	f.openErr = providers.NewError("ssh.unreachable", true, nil, nil)
	res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, "rollback_failed", res["outcome"])
	assert.Equal(t, "deployment.outcome_unknown", f.inv.lastFinish().ErrorCode)
	assert.Zero(t, f.prov.Count("FenceDeployment"))
}

// A sent deployment whose journal is gone is "nothing was written" only shortly after the send: the
// helper sweeps a committed journal after helperproto.NginxBackupKeep (7 days), so the threshold
// after which a missing journal means "outcome unknown" must stay well below that retention (and
// at least a day of live recovery attempts).
func TestNoJournalThresholdIsWellBelowTheHelpersRetention(t *testing.T) {
	assert.LessOrEqual(t, 4*noJournalUnknownAfter, helperproto.NginxBackupKeep, "at most a quarter of the helper's shortest retention")
	assert.GreaterOrEqual(t, noJournalUnknownAfter, time.Duration(inventory.MaxRecoveryAttempts)*inventory.RecoveryRetryInterval,
		"live recovery ends within the threshold, so a later recovery only follows an outage")
}

// AUD-05: "nothing was written" is recorded only after a fence answered fenced. A fence that fails
// or is uncertain records nothing (never failed); a fence that finds a journal after all goes on
// from that journal; a start record without a time is an unknown outcome (B2 m1).
func TestRecoveryFencesBeforeNothingWasWritten(t *testing.T) {
	newSHA := strings.Repeat("e", 64)
	t.Run("the fence comes before the failed record", func(t *testing.T) {
		f := newFixture(t)
		f.sent(inventory.DeployStateRecovering, 2*time.Minute)
		f.status = providers.DeploymentState{Phase: providers.PhaseNone}
		_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
		require.NoError(t, err)
		var methods []string
		for _, c := range f.prov.Calls() {
			methods = append(methods, c.Method)
		}
		assert.Less(t, slices.Index(methods, "DeploymentStatus"), slices.Index(methods, "FenceDeployment"))
		require.Len(t, f.inv.outcomes, 1)
		assert.Equal(t, inventory.DeployStatusFailed, f.inv.outcomes[0].Finish.Status)
		assert.Equal(t, providers.PhaseNone, f.inv.outcomes[0].Finish.Phase, "the journal phase recovery saw, never fenced")
	})
	for name, fence := range map[string]func(uuid.UUID) (providers.DeploymentState, error){
		"BUSY": func(uuid.UUID) (providers.DeploymentState, error) {
			return providers.DeploymentState{}, providers.NewError("nginx.busy", true, nil, nil)
		},
		"transport": func(uuid.UUID) (providers.DeploymentState, error) {
			return providers.DeploymentState{}, providers.NewError("ssh.timeout", true, nil, nil)
		},
		"sudo refused": func(uuid.UUID) (providers.DeploymentState, error) {
			return providers.DeploymentState{}, providers.NewError("nginx.profile_missing", false, nil, nil)
		},
		"still no fence": func(uuid.UUID) (providers.DeploymentState, error) {
			return providers.DeploymentState{Phase: providers.PhaseNone}, nil
		},
		"unsupported": func(uuid.UUID) (providers.DeploymentState, error) {
			return providers.DeploymentState{}, providers.ErrUnsupported
		},
	} {
		t.Run("fence fails: "+name+": nothing recorded, never failed", func(t *testing.T) {
			for _, m := range []string{"recovery", "deploy"} {
				f := newFixture(t)
				f.sent(inventory.DeployStateRecovering, 2*time.Minute)
				f.status = providers.DeploymentState{Phase: providers.PhasePrepared, NewCertSHA256: newSHA, BackupDir: "/b"}
				f.prov.Configure(func(c *fake.Config) { c.Fence = fence })
				var err error
				if m == "recovery" {
					_, err = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
				} else {
					_, err = f.h.deploy(f.ctx, f.job(), f.steps)
				}
				require.Error(t, err, m)
				for _, o := range f.inv.outcomes {
					assert.NotEqual(t, inventory.DeployStatusFailed, o.Finish.Status, m)
				}
				assert.NotContains(t, f.inv.calls(), "FinishDeployment", m)
				assert.Equal(t, 1, f.prov.Count("FenceDeployment"), m)
			}
		})
	}
	t.Run("the fence answers a state that breaks the contract: nothing recorded, never failed", func(t *testing.T) {
		for _, m := range []string{"recovery", "deploy"} {
			f := newFixture(t)
			f.sent(inventory.DeployStateRecovering, 2*time.Minute)
			f.status = providers.DeploymentState{Phase: providers.PhaseNone}
			f.wrap = func(s providers.Session) providers.Session { return brokenFence{s} }
			var err error
			if m == "recovery" {
				_, err = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
			} else {
				_, err = f.h.deploy(f.ctx, f.job(), f.steps)
			}
			assert.Equal(t, "ssh.protocol_error", failureOf(t, err).Reason, m)
			assert.Empty(t, f.inv.outcomes, m)
			assert.NotContains(t, f.inv.calls(), "FinishDeployment", m)
		}
	})
	t.Run("the fence finds a committed journal: verified from it", func(t *testing.T) {
		f := newFixture(t)
		f.sent(inventory.DeployStateRecovering, 2*time.Minute)
		f.status = providers.DeploymentState{Phase: providers.PhaseNone}
		f.prov.Configure(func(c *fake.Config) {
			c.Fence = func(uuid.UUID) (providers.DeploymentState, error) {
				return providers.DeploymentState{Phase: providers.PhaseCommitted, NewCertSHA256: newSHA, BackupDir: "/b"}, nil
			}
		})
		_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
		require.NoError(t, err)
		require.Len(t, f.inv.outcomes, 1)
		assert.Equal(t, inventory.DeployStatusSucceeded, f.inv.outcomes[0].Finish.Status)
		assert.Equal(t, newSHA, f.inv.outcomes[0].Finish.CertFileSHA256)
	})
	t.Run("the fence finds a writing journal: rolled back", func(t *testing.T) {
		f := newFixture(t)
		f.sent(inventory.DeployStateRecovering, 2*time.Minute)
		f.status = providers.DeploymentState{Phase: providers.PhaseNone}
		f.prov.Configure(func(c *fake.Config) {
			c.Fence = func(uuid.UUID) (providers.DeploymentState, error) {
				return providers.DeploymentState{Phase: providers.PhaseWriting, NewCertSHA256: newSHA, BackupDir: "/b"}, nil
			}
		})
		_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
		require.NoError(t, err)
		assert.Equal(t, 1, f.prov.Count("RollbackDeployment"))
		require.Len(t, f.inv.outcomes, 1)
		assert.Equal(t, inventory.DeployStatusRolledBack, f.inv.outcomes[0].Finish.Status)
	})
	t.Run("the fence answers active: busy, uncertain", func(t *testing.T) {
		f := newFixture(t)
		f.sent(inventory.DeployStateRecovering, 2*time.Minute)
		f.status = providers.DeploymentState{Phase: providers.PhaseNone}
		f.prov.Configure(func(c *fake.Config) {
			c.Fence = func(uuid.UUID) (providers.DeploymentState, error) {
				return providers.DeploymentState{Phase: providers.PhaseNone, Active: true}, nil
			}
		})
		res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
		require.NoError(t, err)
		assert.Equal(t, "uncertain", res["outcome"])
		assert.NotContains(t, f.inv.calls(), "FinishDeployment")
		require.Len(t, f.inv.outcomes, 1)
		assert.False(t, f.inv.outcomes[0].Terminal)
		assert.Equal(t, "nginx.busy", f.inv.outcomes[0].Finish.ErrorCode)
	})
	t.Run("B2 m1: no start time: the outcome is unknown, never failed", func(t *testing.T) {
		f := newFixture(t)
		f.sent(inventory.DeployStateRecovering, time.Hour)
		f.inv.dep.StartedAt = nil
		f.status = providers.DeploymentState{Phase: providers.PhaseNone}
		_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
		require.NoError(t, err)
		require.Len(t, f.inv.outcomes, 1)
		assert.Equal(t, inventory.DeployStatusRollbackFailed, f.inv.outcomes[0].Finish.Status)
		assert.Equal(t, "deployment.outcome_unknown", f.inv.outcomes[0].Finish.ErrorCode)
		assert.Equal(t, 1, f.prov.Count("FenceDeployment"), "fenced, best effort")
	})
}

// B2-I1: a re-read that fails in refollow records nothing (it may follow a send): a retry, never
// "failed, nothing written", also on the last attempt.
func TestRefollowReadErrorRecordsNothing(t *testing.T) {
	f := newFixture(t)
	f.inv.errs["StartDeployment"] = inventory.ErrDeploymentState // raced: the state changed under the run
	reads := 0
	f.inv.hooks["Deployment"] = func(context.Context) {
		reads++
		if reads == 2 {
			f.inv.mu.Lock()
			f.inv.errs["Deployment"] = errors.New("db down")
			f.inv.mu.Unlock()
		}
	}
	j := f.job()
	j.Attempt = j.MaxAttempts
	_, err := f.h.deploy(f.ctx, j, f.steps)
	require.Error(t, err)
	assert.NotContains(t, f.inv.calls(), "FinishDeployment")
	assert.Empty(t, f.inv.outcomes)
	assert.Zero(t, f.prov.Count("DeployCertificate"))
}

// B2 m3: a transient claim-check error before the one more restore does not skip it silently: the
// deployment stays in recovery (uncertain), whose rollback sends it.
func TestRollbackAgainTransientClaimErrorIsUncertain(t *testing.T) {
	f := newFixture(t)
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			return providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "restore",
				CauseStep: "verify", Reason: "deployment.rollback_failed"}, nil
		}
	})
	checks := 0
	f.inv.hooks["CheckClaim"] = func(context.Context) {
		checks++
		if checks == 2 { // the check before the one more restore
			f.inv.mu.Lock()
			f.inv.errs["CheckClaim"] = errors.New("db blip")
			f.inv.mu.Unlock()
		}
	}
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.Error(t, err)
	require.Len(t, f.inv.outcomes, 1)
	assert.False(t, f.inv.outcomes[0].Terminal, "not rollback_failed without the one more restore")
	assert.Equal(t, inventory.DeployStateRecovering, f.inv.dep.State)
	assert.Zero(t, f.prov.Count("RollbackDeployment"))
}

// The cross-area note of B1: a terminal "unchanged, verification skipped" that the location no
// longer allows (ErrDeploymentState) ends the deployment failed, not in a retryable job error.
func TestUnchangedSkippedThatIsNoLongerAllowedEndsFailed(t *testing.T) {
	f := newFixture(t)
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			return providers.DeployOutcome{Result: providers.DeployUnchanged, Phase: providers.PhaseUnchanged, Verified: "skipped"}, nil
		}
	})
	calls := 0
	f.inv.hooks["RecordOutcome"] = func(context.Context) {
		calls++
		f.inv.mu.Lock()
		defer f.inv.mu.Unlock()
		if calls == 1 {
			// As inventory answers it: only for a deployment without a send (the record holds no
			// operation id), where failed needs no proof of nothing written.
			f.inv.errs["RecordOutcome"] = inventory.ErrDeploymentState
			f.inv.dep.State, f.inv.dep.OperationID, f.inv.dep.StartedAt = inventory.DeployStatePrecheck, nil, nil
		} else {
			delete(f.inv.errs, "RecordOutcome")
		}
	}
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, "failed", res["outcome"])
	jf := failureOf(t, err)
	assert.Equal(t, jobs.Permanent, jf.Class)
	assert.Equal(t, "deployment.verify_other", jf.Reason)
	require.Len(t, f.inv.outcomes, 1)
	assert.Equal(t, inventory.DeployStatusFailed, f.inv.outcomes[0].Finish.Status)
	assert.Equal(t, providers.PhaseUnchanged, f.inv.outcomes[0].Finish.Phase)
	assert.Equal(t, 2, calls)
}

// Fix rounds 1 and 2, Important 1: a first send refused because an interrupted operation blocks
// the pair.
func TestDeployMeetsAPendingOperation(t *testing.T) {
	pendingOp := uuid.MustParse("0190f5a0-0000-7000-8000-00000000abcd")
	refusalOf := func(reason string, p map[string]string) (providers.DeployOutcome, error) {
		e := providers.NewError(reason, false, nil, p)
		return providers.DeployOutcome{Result: providers.DeployNoChange, Reason: e.Code, Params: maps.Clone(p)}, e
	}
	pending := func() (providers.DeployOutcome, error) {
		return refusalOf("deployment.recovery_pending", map[string]string{"operation_id": pendingOp.String()})
	}
	fileChanged := func() (providers.DeployOutcome, error) { return refusalOf("nginx.file_changed", nil) }
	committed := func() (providers.DeployOutcome, error) {
		return providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "remote"}, nil
	}
	restored := func() (providers.RollbackOutcome, error) {
		return providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}, nil
	}
	hashMismatch := func() (providers.RollbackOutcome, error) { // someone else's file: nothing restored
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore", Error: providers.DeployErrFileChanged,
			Reason: "deployment.rollback_failed"}, nil
	}
	superseded := func() (providers.RollbackOutcome, error) { // a later operation owns the files: nothing put back
		e := providers.NewError("deployment.superseded", false, nil, nil)
		return providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: e.Code}, e
	}
	type tc struct {
		name       string
		owner      *inventory.OperationOwner // the deployment Alice knows for pendingOp (nil: none)
		ownerErr   error
		claimErrAt int // the n-th CheckClaim fails (transiently)
		rollback   func() (providers.RollbackOutcome, error)
		second     func() (providers.DeployOutcome, error)
		status     string
		code       string
		sends      int
		rollbacks  int
		stepStates []string
	}
	for _, c := range []tc{
		{name: "unknown: restored, sent again, committed", rollback: restored, second: committed,
			status: inventory.DeployStatusSucceeded, sends: 2, rollbacks: 1, stepStates: []string{"started", "ok"}},
		{name: "unknown: restored, the second send refused file_changed: rolled_back pending_change_restored (round 2 Important 1)",
			rollback: restored, second: fileChanged, status: inventory.DeployStatusRolledBack, code: "deployment.pending_change_restored",
			sends: 2, rollbacks: 1, stepStates: []string{"started", "ok"}},
		{name: "unknown: restored, refused RECOVERY_PENDING again: pending_change_restored", rollback: restored, second: pending,
			status: inventory.DeployStatusRolledBack, code: "deployment.pending_change_restored", sends: 2, rollbacks: 1, stepStates: []string{"started", "ok"}},
		{name: "unknown: superseded (nothing put back), sent again", rollback: func() (providers.RollbackOutcome, error) {
			e := providers.NewError("deployment.superseded", false, nil, nil)
			return providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: e.Code}, e
		}, second: committed, status: inventory.DeployStatusSucceeded, sends: 2, rollbacks: 1, stepStates: []string{"started", "skipped"}},
		{name: "unknown: HASH_MISMATCH (nothing restored) releases the pair: sent again (round 2 minor 2)", rollback: hashMismatch, second: committed,
			status: inventory.DeployStatusSucceeded, sends: 2, rollbacks: 1, stepStates: []string{"started", "skipped"}},
		{name: "unknown: HASH_MISMATCH, then refused file_changed: the refusal is truthful", rollback: hashMismatch, second: fileChanged,
			status: inventory.DeployStatusFailed, code: "nginx.file_changed", sends: 2, rollbacks: 1, stepStates: []string{"started", "skipped"}},
		{name: "unknown: the restore fails (IO_ERROR of an unreadable journal)", rollback: func() (providers.RollbackOutcome, error) {
			e := providers.NewError("ssh.helper_refused", true, nil, map[string]string{"helper_code": "IO_ERROR"})
			return providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: e.Code, Params: maps.Clone(e.Params)}, e
		}, status: inventory.DeployStatusFailed, code: "deployment.server_operation_pending", sends: 1, rollbacks: 1, stepStates: []string{"started", "failed"}},
		{name: "unknown: restore_failed", rollback: func() (providers.RollbackOutcome, error) {
			return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "restore",
				Reason: "deployment.rollback_failed"}, nil
		}, status: inventory.DeployStatusFailed, code: "deployment.server_operation_pending", sends: 1, rollbacks: 1, stepStates: []string{"started", "failed"}},
		{name: "unknown: the restore is uncertain", rollback: func() (providers.RollbackOutcome, error) {
			return providers.RollbackOutcome{Result: providers.DeployUncertain}, providers.NewError("ssh.timeout", true, nil, nil)
		}, status: inventory.DeployStatusFailed, code: "deployment.server_operation_pending", sends: 1, rollbacks: 1, stepStates: []string{"started", "failed"}},
		{name: "unknown: the claim check before the restore fails: no restore, the refusal (round 2 minor 4)", claimErrAt: 2,
			status: inventory.DeployStatusFailed, code: "deployment.recovery_pending", sends: 1},
		{name: "unknown: the claim check before the second send fails after a restore: pending_change_restored, no send (minor 5)",
			claimErrAt: 3, rollback: restored, status: inventory.DeployStatusRolledBack, code: "deployment.pending_change_restored",
			sends: 1, rollbacks: 1, stepStates: []string{"started", "ok"}},
		{name: "known: a finished rollback_failed deployment of this server and location: restored",
			owner: &inventory.OperationOwner{State: inventory.DeployStateDone, Status: inventory.DeployStatusRollbackFailed}, rollback: restored,
			second: committed, status: inventory.DeployStatusSucceeded, sends: 2, rollbacks: 1, stepStates: []string{"started", "ok"}},
		{name: "known: a succeeded deployment: no restore (round 2 minor 1)",
			owner:  &inventory.OperationOwner{State: inventory.DeployStateDone, Status: inventory.DeployStatusSucceeded},
			status: inventory.DeployStatusFailed, code: "deployment.server_operation_pending", sends: 1},
		{name: "known: rollback_failed of another location: no restore",
			owner:  &inventory.OperationOwner{State: inventory.DeployStateDone, Status: inventory.DeployStatusRollbackFailed, LocationID: uuid.New()},
			status: inventory.DeployStatusFailed, code: "deployment.server_operation_pending", sends: 1},
		{name: "known: an unfinished deployment: today's refusal",
			owner:  &inventory.OperationOwner{State: inventory.DeployStateRecovering, Status: inventory.DeployStatusRunning},
			status: inventory.DeployStatusFailed, code: "deployment.recovery_pending", sends: 1},
		{name: "the lookup fails: today's refusal", ownerErr: errors.New("db down"), status: inventory.DeployStatusFailed,
			code: "deployment.recovery_pending", sends: 1},
		{name: "unknown: nothing put back, refused RECOVERY_PENDING again: server_operation_pending (not pending_change_restored)",
			rollback: superseded, second: pending, status: inventory.DeployStatusFailed, code: "deployment.server_operation_pending",
			sends: 2, rollbacks: 1, stepStates: []string{"started", "skipped"}},
		{name: "unknown: nothing put back, the claim check before the second send fails: the first refusal, no send",
			claimErrAt: 3, rollback: hashMismatch, status: inventory.DeployStatusFailed, code: "deployment.recovery_pending",
			sends: 1, rollbacks: 1, stepStates: []string{"started", "skipped"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.inv.ops = map[uuid.UUID]inventory.OperationOwner{}
			if c.owner != nil {
				o := *c.owner
				if o.TargetID == uuid.Nil {
					o.TargetID = f.inv.dep.TargetID
				}
				if o.LocationID == uuid.Nil {
					o.LocationID = f.inv.dep.LocationID
				}
				f.inv.ops[pendingOp] = o
			}
			if c.ownerErr != nil {
				f.inv.errs["OperationDeployment"] = c.ownerErr
			}
			checks := 0
			f.inv.hooks["CheckClaim"] = func(context.Context) {
				checks++
				f.inv.mu.Lock()
				defer f.inv.mu.Unlock()
				if checks == c.claimErrAt {
					f.inv.errs["CheckClaim"] = errors.New("db blip")
				} else {
					delete(f.inv.errs, "CheckClaim")
				}
			}
			sends := 0
			var keys [][]byte
			f.prov.Configure(func(cfg *fake.Config) {
				cfg.Deploy = func(req providers.DeployRequest) (providers.DeployOutcome, error) {
					sends++
					keys = append(keys, append([]byte(nil), req.PrivateKeyPEM.Bytes()...))
					assert.Equal(t, f.id, req.OperationID, "the same operation id")
					if sends == 1 {
						return pending()
					}
					return c.second()
				}
				cfg.Rollback = func(req providers.RollbackRequest) (providers.RollbackOutcome, error) {
					assert.Equal(t, pendingOp, req.OperationID, "the pending operation is restored, not this deployment's")
					assert.Empty(t, req.OldFingerprint)
					return c.rollback()
				}
			})
			res, _ := f.h.deploy(f.ctx, f.job(), f.steps)
			assert.Equal(t, c.status, res["outcome"])
			assert.Equal(t, c.sends, sends)
			assert.Equal(t, c.rollbacks, f.prov.Count("RollbackDeployment"))
			fin := f.inv.lastFinish()
			assert.Equal(t, c.status, fin.Status)
			assert.Equal(t, c.code, fin.ErrorCode)
			if c.status == inventory.DeployStatusFailed {
				assert.True(t, fin.NothingWritten, "the helper refused before any write")
			}
			if c.code == "deployment.server_operation_pending" || c.code == "deployment.pending_change_restored" {
				assert.Equal(t, pendingOp.String(), fin.Params["operation_id"])
			}
			if c.code == "deployment.pending_change_restored" {
				assert.Equal(t, providers.PhaseRestored, fin.Phase)
				assert.Equal(t, stepRecoverPending, fin.FailedStep)
			}
			var states []string
			for _, st := range f.inv.stepNames() {
				if after, ok := strings.CutPrefix(st, stepRecoverPending+":"); ok {
					states = append(states, after)
				}
			}
			assert.Equal(t, c.stepStates, states)
			if sends == 2 {
				assert.Equal(t, keys[0], keys[1], "the second send carries the key")
			}
			assert.True(t, f.keyZeroed(), "the key is zeroed afterwards")
		})
	}
}

// Fix round 2, Important 1, the crash path: recovery finds the deployment fenced (no journal) and a
// recover_pending ok step: rolled_back deployment.pending_change_restored, not "failed, nothing
// written".
func TestRecoveryAfterARestoredPendingOperation(t *testing.T) {
	for _, phase := range []string{providers.PhaseNone, providers.PhaseFenced} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t)
			f.sent(inventory.DeployStateRecovering, 2*time.Minute)
			op := uuid.New().String()
			f.inv.dep.Steps = []inventory.DeploymentStep{{Name: stepRecoverPending, Status: "started", Params: map[string]string{"operation_id": op}},
				{Name: stepRecoverPending, Status: "ok", Params: map[string]string{"operation_id": op}}}
			f.status = providers.DeploymentState{Phase: phase}
			_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
			require.NoError(t, err)
			require.Len(t, f.inv.outcomes, 1)
			fin := f.inv.outcomes[0].Finish
			assert.Equal(t, inventory.DeployStatusRolledBack, fin.Status)
			assert.Equal(t, "deployment.pending_change_restored", fin.ErrorCode)
			assert.Equal(t, op, fin.Params["operation_id"])
		})
	}
}

// The proof flag is set only where nothing-written is proven: a refusal before the send that met
// a deployment which may have sent (state deploying) is refused by the inventory guard and records
// nothing (W2 review of e0cd19e).
func TestBeforeSendRefusalOnASentDeploymentRecordsNothing(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateDeploying, time.Minute)
	j := f.job()
	j.Attempt = j.MaxAttempts
	_, err := f.h.beforeSend(f.ctx, j, f.inv.dep, jobs.Fail("nginx.no_space", nil, nil))
	require.Error(t, err)
	assert.Empty(t, f.inv.finishes, "no record written")
	assert.Equal(t, inventory.DeployStateDeploying, f.inv.dep.State)
	assert.Contains(t, f.inv.calls(), "FinishDeployment", "the guard refused it")
}

// The run's claim and the record's state are checked on every path before the send:
// a claim lost at the begin record or at a refusal's record stops the run with nothing written; a
// claim check that fails (not lost) right before the send ends the deployment failed with the proof
// that nothing was written; a deployment that finished while the run began it is answered from its
// record. None of them sends.
func TestDeployBeforeTheSendClaimAndStateEdges(t *testing.T) {
	t.Run("claim lost at the begin record: stale, nothing recorded", func(t *testing.T) {
		f := newFixture(t)
		f.inv.lost = true
		_, err := f.h.deploy(f.ctx, f.job(), f.steps)
		assert.Equal(t, "job.lease_expired", failureOf(t, err).Reason)
		assert.Empty(t, f.inv.finishes)
		assert.Equal(t, inventory.DeployStateQueued, f.inv.dep.State)
		assert.Zero(t, f.prov.Count("Open"))
	})
	t.Run("claim lost when the refusal is recorded: stale, nothing recorded", func(t *testing.T) {
		f := newFixture(t)
		f.inv.material.ConfigValid = false
		f.inv.hooks["DeploymentMaterial(true)"] = func(context.Context) {
			f.inv.mu.Lock()
			f.inv.lost = true
			f.inv.mu.Unlock()
		}
		_, err := f.h.deploy(f.ctx, f.job(), f.steps)
		assert.Equal(t, "job.lease_expired", failureOf(t, err).Reason)
		assert.Contains(t, f.inv.calls(), "FinishDeployment")
		assert.Empty(t, f.inv.finishes)
		assert.Zero(t, f.prov.Count("DeployCertificate"))
		assert.True(t, f.keyZeroed())
	})
	t.Run("the claim check before the send fails: failed interrupted, nothing written", func(t *testing.T) {
		f := newFixture(t)
		f.inv.errs["CheckClaim"] = errors.New("db blip")
		res, err := f.h.deploy(f.ctx, f.job(), f.steps)
		assert.Equal(t, inventory.DeployStatusFailed, res["outcome"])
		assert.Equal(t, "deployment.interrupted", failureOf(t, err).Reason)
		fin := f.inv.lastFinish()
		assert.Equal(t, inventory.DeployStatusFailed, fin.Status)
		assert.Equal(t, "deployment.interrupted", fin.ErrorCode)
		assert.True(t, fin.NothingWritten, "the send is known not to have happened")
		assert.Zero(t, f.prov.Count("DeployCertificate"))
		assert.True(t, f.keyZeroed())
	})
	t.Run("finished while the run began it: answered from the record", func(t *testing.T) {
		f := newFixture(t)
		f.inv.hooks["BeginDeployment"] = func(context.Context) {
			f.inv.mu.Lock()
			f.inv.dep.State, f.inv.dep.Status, f.inv.dep.ErrorCode = inventory.DeployStateDone, inventory.DeployStatusFailed, "deployment.interrupted"
			f.inv.mu.Unlock()
		}
		res, err := f.h.deploy(f.ctx, f.job(), f.steps)
		assert.Equal(t, inventory.DeployStatusFailed, res["outcome"])
		assert.Equal(t, "deployment.interrupted", failureOf(t, err).Reason)
		assert.NotContains(t, f.inv.calls(), "DeploymentMaterial(true)", "the key is never handed out")
		assert.Empty(t, f.inv.finishes)
		assert.Zero(t, f.prov.Count("DeployCertificate"))
	})
}

// A recovery whose claim check before the restore fails transiently (not lost) restores nothing and
// records nothing: the next recovery reads the journal again.
func TestRecoveryTransientClaimErrorBeforeTheRestoreRecordsNothing(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	f.status = providers.DeploymentState{Phase: providers.PhaseWriting, NewCertSHA256: strings.Repeat("e", 64), BackupDir: "/b"}
	f.inv.errs["CheckClaim"] = errors.New("db blip")
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	jf := failureOf(t, err)
	assert.Equal(t, jobs.Retryable, jf.Class)
	assert.Equal(t, "internal.unexpected", jf.Reason)
	assert.Zero(t, f.prov.Count("RollbackDeployment"))
	assert.Empty(t, f.inv.outcomes)
	assert.Equal(t, inventory.DeployStateRecovering, f.inv.dep.State)
}

// A committed journal whose verification the location skips (verification off) ends succeeded with
// verified "skipped" and the verify step recorded as skipped, not ok.
func TestRecoveryOfACommittedJournalWithVerificationSkipped(t *testing.T) {
	f := newFixture(t)
	f.sent(inventory.DeployStateRecovering, time.Hour)
	newSHA := strings.Repeat("e", 64)
	f.status = providers.DeploymentState{Phase: providers.PhaseCommitted, NewCertSHA256: newSHA, BackupDir: "/b"}
	f.prov.Configure(func(c *fake.Config) {
		c.Verify = func(providers.VerifyRequest) (providers.VerifyResult, error) {
			return providers.VerifyResult{OK: true, Mode: "skipped"}, nil
		}
	})
	res, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStatusSucceeded, res["outcome"])
	fin := f.inv.lastFinish()
	assert.Equal(t, "skipped", fin.Verified)
	assert.Equal(t, newSHA, fin.CertFileSHA256)
	assert.Contains(t, f.inv.stepNames(), providers.StepNameVerify+":"+string(providers.StepSkipped))
	assert.NotContains(t, f.inv.stepNames(), providers.StepNameVerify+":"+string(providers.StepOK))
}

// Only a provider's own error is recorded on the server as a connection failure; a failure to record
// it is logged (without the cause) and changes nothing for the deployment, which is retried.
func TestConnectionFailureRecording(t *testing.T) {
	f := newFixture(t)
	f.openErr = errors.New("not a provider error")
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
	assert.NotContains(t, f.inv.log, "RecordConnectionFailure")

	f = newFixture(t)
	f.openErr = providers.NewError("ssh.unreachable", true, nil, nil)
	f.inv.errs["RecordConnectionFailure"] = errors.New("db down")
	_, err = f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, "ssh.unreachable", failureOf(t, err).Reason)
	assert.Contains(t, f.inv.log, "RecordConnectionFailure")
	assert.Contains(t, f.logs.String(), "could not record a connection failure")
	assert.NotContains(t, f.logs.String(), "db down", "only the error type is logged")
	assert.Zero(t, f.prov.Count("DeployCertificate"))
}

// A restore of a pending operation whose answer breaks the provider contract is not relied on: the
// recover_pending step fails, nothing is sent again, and the deployment ends failed
// server_operation_pending (nothing written by this deployment).
func TestDeployPendingOperationRestoreThatBreaksTheContract(t *testing.T) {
	pendingOp := uuid.MustParse("0190f5a0-0000-7000-8000-00000000abcd")
	f := newFixture(t)
	sends := 0
	f.prov.Configure(func(cfg *fake.Config) {
		cfg.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			sends++
			p := map[string]string{"operation_id": pendingOp.String()}
			e := providers.NewError("deployment.recovery_pending", false, nil, p)
			return providers.DeployOutcome{Result: providers.DeployNoChange, Reason: e.Code, Params: maps.Clone(p)}, e
		}
	})
	f.wrap = func(s providers.Session) providers.Session { return brokenRollback{s} }
	res, _ := f.h.deploy(f.ctx, f.job(), f.steps)
	assert.Equal(t, inventory.DeployStatusFailed, res["outcome"])
	assert.Equal(t, 1, sends, "not sent again")
	fin := f.inv.lastFinish()
	assert.Equal(t, "deployment.server_operation_pending", fin.ErrorCode)
	assert.Equal(t, pendingOp.String(), fin.Params["operation_id"])
	assert.True(t, fin.NothingWritten)
	assert.Equal(t, []string{stepRecoverPending + ":started", stepRecoverPending + ":failed"},
		slices.DeleteFunc(f.inv.stepNames(), func(s string) bool { return !strings.HasPrefix(s, stepRecoverPending+":") }))
	assert.True(t, f.keyZeroed())
}

// A location whose verification is off skips the pre-check: the step is recorded skipped, nothing
// is asked of the website before the send, and no served certificate is recorded as the previous
// one (Alice did not see it).
func TestDeployWithVerificationOffSkipsThePrecheck(t *testing.T) {
	f := newFixture(t)
	f.inv.material.Verify.Skip = true
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStatusSucceeded, res["outcome"])
	require.NotEmpty(t, f.inv.stepNames())
	assert.Equal(t, stepPrecheck+":"+string(providers.StepSkipped), f.inv.stepNames()[0])
	assert.NotContains(t, f.inv.stepNames(), stepPrecheck+":"+string(providers.StepStarted))
	for _, c := range f.prov.Calls() {
		if c.Method == "VerifyDeployment" {
			assert.NotEqual(t, f.current, c.Verify.Fingerprint, "the served certificate is not checked")
		}
	}
	require.NotNil(t, f.inv.started)
	assert.Empty(t, f.inv.started.PreviousFingerprint)
	assert.Zero(t, f.inv.started.PreviousChainLength)
	assert.Equal(t, 1, f.prov.Count("DeployCertificate"))
}
