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
}

func (f *fakeInv) call(ctx context.Context, name string) error {
	f.mu.Lock()
	f.log = append(f.log, name)
	f.ctxErrs[name] = ctx.Err()
	hook, err := f.hooks[name], f.errs[name]
	f.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
	return err
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
	if withKey {
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

func (f *fakeInv) RecordDeploymentStep(ctx context.Context, _ uuid.UUID, name string, status providers.StepStatus, _ map[string]string) error {
	err := f.call(ctx, "RecordDeploymentStep")
	f.mu.Lock()
	f.steps = append(f.steps, name+":"+string(status))
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
	f.inv = &fakeInv{clock: f.clock, errs: map[string]error{}, hooks: map[string]func(context.Context){}, ctxErrs: map[string]error{},
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
		"RecordOutcome", "Deployment"}, f.inv.calls())
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
		"RecordOutcome", "Deployment"}, f.inv.calls(), "RecordOutcome only: no MarkRecovering, no RequestRecovery (the sweep paces)")
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
		{name: "none, within the budget (S6)", phase: providers.PhaseNone, age: 30 * time.Second, code: "deployment.interrupted"},
		{name: "prepared, within the budget (S6)", phase: providers.PhasePrepared, age: 59 * time.Second, code: "deployment.interrupted"},
		{name: "none, active", phase: providers.PhaseNone, active: true, age: time.Hour, code: "nginx.busy"},
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
			if tc.phase != providers.PhaseNone {
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
	Register(r, Deps{})
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
