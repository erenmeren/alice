package kvjobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/azureid"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/secrets"
)

const (
	canary     = "CANARY-kv-error-text-7f3a"
	validVer   = "0123456789abcdef0123456789abcdef"
	validThumb = "0123456789abcdef0123456789abcdef01234567"
)

// vaultSource is the credential source of a vault: the fake provider only checks that it hands out an
// identity.
type vaultSource struct{}

func (vaultSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, nil, errors.New("a vault has no SSH key")
}

func (vaultSource) AzureIdentity(context.Context) (providers.AzureIdentity, func(), error) {
	return providers.AzureIdentity{Auth: providers.AzureAuthClientSecret}, func() {}, nil
}

// fakeInv is the inventory of the handler tests: every method records its name, answers from its
// fields and keeps what it was given.
type fakeInv struct {
	mu    sync.Mutex
	calls []string

	target    inventory.Target
	targetErr error

	connErr     error
	connections []providers.ConnectionReport
	failures    []error
	failErr     error

	slotErr  error
	released int

	pollReq    providers.DiscoverRequest
	pollReqErr error
	reconcile  inventory.KVSummary
	reconErr   error
	reconCtx   context.Context
	reconRes   providers.DiscoveryResult

	cert    inventory.KVCertificateDetail
	certErr error

	imp         inventory.KVImport
	impErr      error
	material    inventory.ImportMaterial
	materialErr error
	markErr     error
	finishErr   error
	finished    []finishCall
	finishState string // the state FinishImport answers with
	failedQueue []string
	importErrs  []error // consumed one per Import call (then impErr)
	failQErr    error
	onMark      func()
}

type finishCall struct {
	res         providers.ImportResult
	cause       error
	ctx         context.Context
	ctxErr      error // the context's state when FinishImport was called
	hasDeadline bool
	claim       inventory.Claim
}

func (f *fakeInv) rec(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *fakeInv) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeInv) count(name string) int {
	n := 0
	for _, c := range f.called() {
		if c == name {
			n++
		}
	}
	return n
}

func (f *fakeInv) TargetRef(_ context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error) {
	f.rec("TargetRef")
	if f.targetErr != nil {
		return providers.TargetRef{}, inventory.Target{}, f.targetErr
	}
	t := f.target
	kind, _ := providers.KindForTargetType(t.Type)
	return providers.TargetRef{ID: id, Name: "prod", Kind: kind, Config: providers.TargetConfig{"vault_url": "https://prod.vault.azure.net"}}, t, nil
}

func (f *fakeInv) VaultCredentials(uuid.UUID) inventory.VaultCredentialSource {
	f.rec("VaultCredentials")
	return vaultSource{}
}

func (f *fakeInv) RecordKVConnection(_ context.Context, _ uuid.UUID, r providers.ConnectionReport) error {
	f.rec("RecordKVConnection")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connections = append(f.connections, r)
	return f.connErr
}

func (f *fakeInv) RecordKVFailure(_ context.Context, _ uuid.UUID, cause error) error {
	f.rec("RecordKVFailure")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = append(f.failures, cause)
	return f.failErr
}

func (f *fakeInv) AcquireKVPoll(ctx context.Context) (func(), error) {
	f.rec("AcquireKVPoll")
	if f.slotErr != nil {
		return nil, f.slotErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return func() { f.mu.Lock(); f.released++; f.mu.Unlock() }, nil
}

func (f *fakeInv) KVPollRequest(context.Context, uuid.UUID) (providers.DiscoverRequest, error) {
	f.rec("KVPollRequest")
	return f.pollReq, f.pollReqErr
}

func (f *fakeInv) ReconcileKV(ctx context.Context, _ uuid.UUID, res providers.DiscoveryResult) (inventory.KVSummary, error) {
	f.rec("ReconcileKV")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconCtx, f.reconRes = ctx, res
	return f.reconcile, f.reconErr
}

func (f *fakeInv) KVCertificate(context.Context, uuid.UUID, uuid.UUID) (inventory.KVCertificateDetail, error) {
	f.rec("KVCertificate")
	return f.cert, f.certErr
}

func (f *fakeInv) Import(context.Context, uuid.UUID, uuid.UUID) (inventory.KVImport, error) {
	f.rec("Import")
	f.mu.Lock()
	if len(f.importErrs) > 0 {
		err := f.importErrs[0]
		f.importErrs = f.importErrs[1:]
		f.mu.Unlock()
		return f.imp, err
	}
	f.mu.Unlock()
	return f.imp, f.impErr
}

func (f *fakeInv) ImportMaterial(ctx context.Context, _ uuid.UUID) (inventory.ImportMaterial, error) {
	f.rec("ImportMaterial")
	return f.material, f.materialErr
}

func (f *fakeInv) MarkImportSent(context.Context, uuid.UUID) error {
	f.rec("MarkImportSent")
	if f.onMark != nil {
		f.onMark()
	}
	return f.markErr
}

func (f *fakeInv) FinishImport(ctx context.Context, _ uuid.UUID, res providers.ImportResult, cause error) (inventory.KVImport, error) {
	f.rec("FinishImport")
	f.mu.Lock()
	defer f.mu.Unlock()
	_, hasDeadline := ctx.Deadline()
	claim, _ := inventory.ClaimFrom(ctx)
	f.finished = append(f.finished, finishCall{res: res, cause: cause, ctx: ctx, ctxErr: ctx.Err(), hasDeadline: hasDeadline, claim: claim})
	out := f.imp
	out.State = f.finishState
	if out.State == "" {
		out.State = map[string]string{providers.ImportCreated: inventory.ImportSucceeded, providers.ImportRefused: inventory.ImportFailed,
			providers.ImportUncertain: inventory.ImportUncertain}[res.Outcome]
	}
	if res.Outcome == providers.ImportCreated {
		out.Version = res.Version
	}
	return out, f.finishErr
}

func (f *fakeInv) FailQueuedImport(_ context.Context, _ uuid.UUID, code string) (inventory.KVImport, error) {
	f.rec("FailQueuedImport")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failedQueue = append(f.failedQueue, code)
	return f.imp, f.failQErr
}

var _ Inventory = (*fakeInv)(nil)

// spyProvider wraps the scripted Key Vault provider: it records the context deadline of every call,
// keeps the secret value a read returned (to see it zeroed) and can hold or panic a call.
type spyProvider struct {
	*fake.Provider
	mu        sync.Mutex
	deadlines map[string]time.Duration
	secrets   [][]byte
	panicIn   string
	hook      func(method string)
	closeErr  error
}

func (p *spyProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	p.note("Open", ctx)
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return &spySession{Session: s, p: p}, nil
}

func (p *spyProvider) note(method string, ctx context.Context) {
	if dl, ok := ctx.Deadline(); ok {
		p.mu.Lock()
		if p.deadlines == nil {
			p.deadlines = map[string]time.Duration{}
		}
		p.deadlines[method] = time.Until(dl)
		p.mu.Unlock()
	}
	if p.hook != nil {
		p.hook(method)
	}
	if p.panicIn == method {
		panic(canary + " panic in " + method)
	}
}

func (p *spyProvider) deadline(method string) (time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.deadlines[method]
	return d, ok
}

type spySession struct {
	providers.Session
	p *spyProvider
}

func (s *spySession) Close() error {
	err := s.Session.Close()
	if s.p.closeErr != nil {
		return s.p.closeErr
	}
	return err
}

func (s *spySession) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	s.p.note("TestConnection", ctx)
	return s.Session.TestConnection(ctx)
}

func (s *spySession) Discover(ctx context.Context, r providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	s.p.note("Discover", ctx)
	return s.Session.Discover(ctx, r)
}

func (s *spySession) ReadCertificateSecret(ctx context.Context, r providers.SecretRequest) (providers.CertificateSecret, error) {
	s.p.note("ReadCertificateSecret", ctx)
	sec, err := s.Session.ReadCertificateSecret(ctx, r)
	if err == nil {
		s.p.mu.Lock()
		s.p.secrets = append(s.p.secrets, sec.Value.Bytes())
		s.p.mu.Unlock()
	}
	return sec, err
}

func (s *spySession) ImportCertificate(ctx context.Context, r providers.ImportRequest, l providers.StepLogger) (providers.ImportResult, error) {
	s.p.note("ImportCertificate", ctx)
	return s.Session.ImportCertificate(ctx, r, l)
}

type fixture struct {
	t     *testing.T
	inv   *fakeInv
	prov  *spyProvider
	reg   *providers.Registry
	h     *handlers
	logs  *bytes.Buffer
	vault uuid.UUID
}

func okChecks() []providers.AzureCheck {
	return []providers.AzureCheck{
		{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListKeys, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListSecrets, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultNotChecked},
		{Name: providers.AzureCheckImport, Result: providers.AzureResultNotChecked},
	}
}

func newFixture(t *testing.T, withProvider bool) *fixture {
	t.Helper()
	f := &fixture{t: t, inv: &fakeInv{}, reg: providers.NewRegistry(), logs: &bytes.Buffer{}, vault: uuid.New()}
	f.inv.target = inventory.Target{ID: f.vault, Type: inventory.TypeAzureKeyVault, Status: inventory.StatusOK}
	f.prov = &spyProvider{Provider: fake.New(providers.KindAzureKV, providers.CapTestConnection, providers.CapDiscoverCerts,
		providers.CapReadCertificateSecret, providers.CapImportCertificate)}
	f.prov.Configure(func(c *fake.Config) {
		c.Report = providers.ConnectionReport{Azure: &providers.AzureFacts{ObjectID: "99999999-8888-7777-6666-555555555555",
			TenantID: "1111aaaa-2222-bbbb-3333-cccc4444dddd", PermissionModel: "rbac", Checks: okChecks(), CheckedAt: time.Now()}}
	})
	if withProvider {
		f.reg.Register(f.prov)
	}
	f.reg.Freeze()
	f.h = newHandlers(Deps{Inventory: f.inv, Registry: f.reg, Clock: clock.NewFake(time.Now()),
		Log: slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	return f
}

func (f *fixture) job(typ jobs.Type, payload map[string]string) jobs.Job {
	if payload == nil {
		payload = map[string]string{}
	}
	return jobs.Job{ID: uuid.New(), Type: typ, Kind: jobs.KindUser, TargetID: f.vault, Payload: payload, Attempt: 1,
		MaxAttempts: jobs.MaxAttemptsFor(typ)}
}

type noSteps struct{}

func (noSteps) Step(string, providers.StepStatus, map[string]string) {}

// failure returns the classified job error.
func failure(t *testing.T, err error) *jobs.Failure {
	t.Helper()
	var f *jobs.Failure
	require.ErrorAs(t, err, &f, "a classified failure")
	return f
}

// failureWith checks the class and the reason of a job failure and returns it for further checks.
func failureWith(t *testing.T, err error, class jobs.FailureClass, reason string) *jobs.Failure {
	t.Helper()
	f := failure(t, err)
	assert.Equal(t, reason, f.Reason)
	assert.Equal(t, class, f.Class)
	return f
}

func requireFailure(t *testing.T, err error, class jobs.FailureClass, reason string) {
	t.Helper()
	_ = failureWith(t, err, class, reason)
}

func TestRegisterPanicsOnAMissingDependency(t *testing.T) {
	r := jobs.NewRunner(jobs.RunnerConfig{})
	reg := providers.NewRegistry()
	inv := &fakeInv{}
	assert.Panics(t, func() { Register(nil, Deps{Inventory: inv, Registry: reg, Clock: clock.Real{}}) })
	assert.Panics(t, func() { Register(r, Deps{Registry: reg, Clock: clock.Real{}}) })
	assert.Panics(t, func() { Register(r, Deps{Inventory: inv, Clock: clock.Real{}}) })
	assert.Panics(t, func() { Register(r, Deps{Inventory: inv, Registry: reg}) })
	assert.NotPanics(t, func() { Register(r, Deps{Inventory: inv, Registry: reg, Clock: clock.Real{}}) }, "no logger is fine")
	for _, typ := range []jobs.Type{jobs.KVTestConnection, jobs.KVPoll, jobs.KVImport} {
		assert.True(t, r.Handles(typ), typ.Name)
	}
	assert.False(t, r.Handles(jobs.KVSchedule), "periodic types have no handler")
	assert.False(t, r.Handles(jobs.KVAutoDeploy))
}

// What every handler refuses before it opens anything.
func TestHandlersRefuseWhatCannotRun(t *testing.T) {
	handlers := map[string]func(*fixture) (map[string]any, error){
		"test": func(f *fixture) (map[string]any, error) {
			return f.h.testConnection(context.Background(), f.job(jobs.KVTestConnection, nil), noSteps{})
		},
		"poll": func(f *fixture) (map[string]any, error) {
			return f.h.poll(context.Background(), f.job(jobs.KVPoll, nil), noSteps{})
		},
	}
	for name, run := range handlers {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			f.inv.targetErr = inventory.ErrNotFound
			_, err := run(f)
			requireFailure(t, err, jobs.Permanent, "system.not_found")
			assert.Empty(t, f.prov.Calls(), "a deleted vault is not opened")
			assert.Zero(t, f.inv.count("RecordKVFailure"), "nothing is recorded against a deleted vault")

			f = newFixture(t, true)
			f.inv.target.Status = inventory.StatusDisabled
			_, err = run(f)
			requireFailure(t, err, jobs.Permanent, "target.disabled")
			assert.Empty(t, f.prov.Calls())
			assert.Zero(t, f.inv.count("RecordKVFailure"), "a disabled vault is dropped, not marked")
			assert.Zero(t, f.inv.count("RecordKVConnection"))
			assert.Zero(t, f.inv.count("ReconcileKV"))

			f = newFixture(t, true)
			f.inv.target.Type = inventory.TypeNginx
			_, err = run(f)
			f2 := failureWith(t, err, jobs.Permanent, "internal.unexpected")
			assert.ErrorIs(t, f2, inventory.ErrNotAVault)
			assert.Empty(t, f.prov.Calls(), "a server's id never reaches the Key Vault provider")
			assert.Zero(t, f.inv.count("RecordKVFailure"))

			f = newFixture(t, false)
			_, err = run(f)
			requireFailure(t, err, jobs.Permanent, "internal.unexpected")
			assert.Zero(t, f.inv.count("RecordKVFailure"), "a build without the provider does not blame the vault")

			f = newFixture(t, true)
			f.inv.targetErr = errors.New(canary)
			_, err = run(f)
			requireFailure(t, err, jobs.Retryable, "internal.unexpected")
			assert.NotContains(t, f.logs.String(), canary)
		})
	}
}

func TestTestConnectionDecisionTable(t *testing.T) {
	ctx := context.Background()
	t.Run("Open fails with a closed code", func(t *testing.T) {
		f := newFixture(t, true)
		f.prov.Configure(func(c *fake.Config) {
			c.OpenErr = providers.NewError("azure.auth_failed", false, errors.New(canary), map[string]string{"aadsts": "AADSTS7000215"})
		})
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, nil), noSteps{})
		fl := failureWith(t, err, jobs.Permanent, "azure.auth_failed")
		assert.Equal(t, "AADSTS7000215", fl.Params["aadsts"])
		require.Len(t, f.inv.failures, 1)
		var pe *providers.Error
		require.ErrorAs(t, f.inv.failures[0], &pe)
		assert.Equal(t, "azure.auth_failed", pe.Code)
		assert.Zero(t, f.inv.count("RecordKVConnection"))
		assert.Equal(t, 1, jobs.MaxAttemptsFor(jobs.KVTestConnection), "one attempt")
		assert.NotContains(t, f.logs.String(), canary)
	})
	t.Run("the first call fails", func(t *testing.T) {
		f := newFixture(t, true)
		f.prov.Configure(func(c *fake.Config) { c.TestErr = providers.NewError("azure.vault_not_found", false, nil, nil) })
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, nil), noSteps{})
		requireFailure(t, err, jobs.Permanent, "azure.vault_not_found")
		assert.Equal(t, 1, f.inv.count("RecordKVFailure"))
		assert.Equal(t, 1, f.prov.Count("Close"), "the session is closed")
	})
	t.Run("a report", func(t *testing.T) {
		f := newFixture(t, true)
		res, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, nil), noSteps{})
		require.NoError(t, err)
		require.Len(t, f.inv.connections, 1)
		assert.Equal(t, providers.AzureResultOK, f.inv.connections[0].Azure.Checks[1].Result)
		assert.Equal(t, "99999999-8888-7777-6666-555555555555", res["object_id"])
		assert.Equal(t, "rbac", res["permission_model"])
		checks, ok := res["checks"].([]map[string]string)
		require.True(t, ok)
		assert.Len(t, checks, 6)
		assert.Equal(t, map[string]string{"name": "sign_in", "result": "ok"}, checks[0])
		assert.Zero(t, f.inv.count("RecordKVFailure"))
		assert.Zero(t, f.inv.count("KVCertificate"), "a plain check reads no secret")
		assert.Zero(t, f.prov.Count("ReadCertificateSecret"))
		assert.Equal(t, 1, f.prov.Count("Close"))
		assert.NotContains(t, f.inv.calls, "AcquireKVPoll", "a check does not take a poll slot")
	})
	t.Run("a report the database refuses", func(t *testing.T) {
		f := newFixture(t, true)
		f.inv.connErr = inventory.ErrNotFound
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, nil), noSteps{})
		requireFailure(t, err, jobs.Permanent, "system.not_found")
		f = newFixture(t, true)
		f.inv.connErr = errors.New(canary)
		_, err = f.h.testConnection(ctx, f.job(jobs.KVTestConnection, nil), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		assert.NotContains(t, f.logs.String(), canary)
	})
	t.Run("a deadline on every provider call", func(t *testing.T) {
		f := newFixture(t, true)
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, nil), noSteps{})
		require.NoError(t, err)
		for _, m := range []string{"Open", "TestConnection"} {
			d, ok := f.prov.deadline(m)
			require.True(t, ok, m)
			assert.LessOrEqual(t, d, 2*time.Minute, m)
		}
	})
}

func readSecretFixture(t *testing.T) (*fixture, uuid.UUID, map[string]string) {
	f := newFixture(t, true)
	cert := uuid.New()
	exportable := true
	f.inv.cert = inventory.KVCertificateDetail{KVCertificate: inventory.KVCertificate{ID: cert, TargetID: f.vault, Name: "web-cert",
		CurrentVersion: validVer, Exportable: &exportable}}
	f.prov.Configure(func(c *fake.Config) {
		c.Secret = providers.CertificateSecret{ContentType: "application/x-pem-file", Value: providers.NewSecret([]byte("pretend-pem-with-key"))}
	})
	return f, cert, map[string]string{"read_secret_of": cert.String()}
}

func TestTestConnectionWithASecretRead(t *testing.T) {
	ctx := context.Background()
	rowOf := func(rep providers.ConnectionReport, name string) providers.AzureCheck {
		for _, c := range rep.Azure.Checks {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("no row %s", name)
		return providers.AzureCheck{}
	}
	t.Run("ok: the row is ok and the value is zeroed", func(t *testing.T) {
		f, _, payload := readSecretFixture(t)
		res, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		require.NoError(t, err)
		require.Len(t, f.inv.connections, 1)
		assert.Equal(t, providers.AzureResultOK, rowOf(f.inv.connections[0], providers.AzureCheckReadSecret).Result)
		calls := f.prov.Calls()
		var read *fake.Call
		for i := range calls {
			if calls[i].Method == "ReadCertificateSecret" {
				read = &calls[i]
			}
		}
		require.NotNil(t, read)
		assert.Equal(t, providers.SecretRequest{Name: "web-cert", Version: validVer}, read.Secret, "the exact current version, never latest")
		require.Len(t, f.prov.secrets, 1)
		assert.Equal(t, make([]byte, len(f.prov.secrets[0])), f.prov.secrets[0], "the secret value was zeroed")
		var found bool
		for _, c := range res["checks"].([]map[string]string) {
			if c["name"] == "read_secret" {
				found = true
				assert.Equal(t, "ok", c["result"])
			}
		}
		assert.True(t, found)
		assert.NotContains(t, f.logs.String(), "pretend-pem")
		d, ok := f.prov.deadline("ReadCertificateSecret")
		require.True(t, ok)
		assert.LessOrEqual(t, d, 2*time.Minute)
	})
	t.Run("403: the check ran and the role is named", func(t *testing.T) {
		f, _, payload := readSecretFixture(t)
		f.prov.Configure(func(c *fake.Config) {
			c.SecretErr = providers.NewError("azure.forbidden", false, errors.New(canary), map[string]string{"role": providers.RoleKeyVaultSecretsUser})
		})
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		require.NoError(t, err, "the check ran: a refusal is its result, not a job failure")
		row := rowOf(f.inv.connections[0], providers.AzureCheckReadSecret)
		assert.Equal(t, providers.AzureResultForbidden, row.Result)
		assert.Equal(t, providers.RoleKeyVaultSecretsUser, row.Role)
		assert.Equal(t, "azure.forbidden", row.Reason)
		assert.NotContains(t, f.logs.String(), canary)
	})
	t.Run("403 without a role param still names the secrets role", func(t *testing.T) {
		f, _, payload := readSecretFixture(t)
		f.prov.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("azure.forbidden", false, nil, nil) })
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		require.NoError(t, err)
		assert.Equal(t, providers.RoleKeyVaultSecretsUser, rowOf(f.inv.connections[0], providers.AzureCheckReadSecret).Role)
	})
	t.Run("a firewall refusal is forbidden without a role", func(t *testing.T) {
		f, _, payload := readSecretFixture(t)
		f.prov.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("azure.firewall", false, nil, nil) })
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		require.NoError(t, err)
		row := rowOf(f.inv.connections[0], providers.AzureCheckReadSecret)
		assert.Equal(t, providers.AzureResultForbidden, row.Result)
		assert.Empty(t, row.Role)
	})
	t.Run("another failure is the job's, the rest of the report is kept", func(t *testing.T) {
		f, _, payload := readSecretFixture(t)
		f.prov.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("azure.unreachable", true, nil, nil) })
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		requireFailure(t, err, jobs.Retryable, "azure.unreachable")
		require.Len(t, f.inv.connections, 1, "what the check learned is stored")
		assert.Equal(t, providers.AzureResultNotChecked, rowOf(f.inv.connections[0], providers.AzureCheckReadSecret).Result)
		assert.Zero(t, f.inv.count("RecordKVFailure"), "a read of one secret says nothing about the vault's sign-in")
	})
	t.Run("the secret of an unreadable certificate is the certificate's problem", func(t *testing.T) {
		f, _, payload := readSecretFixture(t)
		f.prov.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("kv.secret_unreadable", false, nil, nil) })
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		requireFailure(t, err, jobs.Permanent, "kv.secret_unreadable")
		assert.Equal(t, providers.AzureResultNotChecked, rowOf(f.inv.connections[0], providers.AzureCheckReadSecret).Result)
	})
	t.Run("the certificate changed since the request", func(t *testing.T) {
		f, _, payload := readSecretFixture(t)
		f.inv.certErr = inventory.ErrNotFound
		_, err := f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		requireFailure(t, err, jobs.Permanent, "kv.certificate_not_found")
		assert.Empty(t, f.prov.Calls(), "nothing is opened for it")

		f, _, payload = readSecretFixture(t)
		f.inv.cert.CurrentVersion = ""
		_, err = f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		requireFailure(t, err, jobs.Permanent, "kv.version_not_deployable")

		f, _, payload = readSecretFixture(t)
		f.inv.cert.Exportable = nil
		_, err = f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		requireFailure(t, err, jobs.Permanent, "kv.version_not_deployable")

		f, _, payload = readSecretFixture(t)
		f.inv.certErr = errors.New(canary)
		_, err = f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		assert.NotContains(t, f.logs.String(), canary)

		f, _, _ = readSecretFixture(t)
		_, err = f.h.testConnection(ctx, f.job(jobs.KVTestConnection, map[string]string{"read_secret_of": "not-a-uuid"}), noSteps{})
		requireFailure(t, err, jobs.Permanent, "internal.unexpected")
	})
	t.Run("a panic in the read still zeroes the value and closes", func(t *testing.T) {
		f, _, payload := readSecretFixture(t)
		f.prov.panicIn = "TestConnection"
		assert.Panics(t, func() { _, _ = f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{}) })
		assert.Equal(t, 1, f.prov.Count("Close"), "the session is closed while the panic unwinds")
	})
}

func TestPollDecisionTable(t *testing.T) {
	ctx := context.Background()
	t.Run("the request, the claim and the result", func(t *testing.T) {
		f := newFixture(t, true)
		f.inv.pollReq = providers.DiscoverRequest{Certificates: true, KVKeys: true, KVSecrets: true,
			KVKnown: map[string]providers.KVKnown{"web-cert": {Version: validVer, Thumbprint: validThumb}}}
		f.inv.reconcile = inventory.KVSummary{Certificates: 3, NewVersions: 1, MissingCertificates: 2, Keys: 4, Secrets: 5, NewCertificates: 1,
			HeldVersions: 1, Status: inventory.StatusOK}
		f.prov.Configure(func(c *fake.Config) {
			c.Discovery = providers.DiscoveryResult{KV: &providers.KVInventory{Certificates: []providers.KVCertificate{{Name: "web-cert"}}}}
		})
		j := f.job(jobs.KVPoll, nil)
		j.Attempt = 1
		res, err := f.h.poll(ctx, j, noSteps{})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"certificates": 3, "new_certificates": 1, "new_versions": 1, "held_versions": 1, "removed": 2,
			"keys": 4, "secrets": 5, "status": inventory.StatusOK}, res)
		calls := f.prov.Calls()
		var disc fake.Call
		for _, c := range calls {
			if c.Method == "Discover" {
				disc = c
			}
		}
		assert.Equal(t, f.inv.pollReq.KVKnown, disc.Discover.KVKnown, "the provider is asked what inventory asked for")
		assert.True(t, disc.Discover.KVKeys)
		claim, ok := inventory.ClaimFrom(f.inv.reconCtx)
		require.True(t, ok, "the result is stored under the job's claim")
		assert.Equal(t, inventory.Claim{JobID: j.ID, Attempt: 1}, claim)
		require.NotNil(t, f.inv.reconRes.KV)
		assert.Equal(t, "web-cert", f.inv.reconRes.KV.Certificates[0].Name)
		assert.Zero(t, f.inv.count("RecordKVFailure"))
		assert.Equal(t, []string{"TargetRef", "AcquireKVPoll", "KVPollRequest", "VaultCredentials", "ReconcileKV"}, f.inv.called(),
			"slot first, then the request, then the session, then the store")
		assert.Equal(t, 1, f.inv.released, "the slot is released")
		assert.Equal(t, 1, f.prov.Count("Close"))
	})
	t.Run("a deadline bounds Discover and the store is not under it", func(t *testing.T) {
		f := newFixture(t, true)
		_, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
		require.NoError(t, err)
		d, ok := f.prov.deadline("Discover")
		require.True(t, ok)
		assert.LessOrEqual(t, d, pollTimeout)
		assert.Greater(t, d, 11*time.Minute, "longer than the provider's own 11 minute budget, which is the real bound")
		_, has := f.inv.reconCtx.Deadline()
		assert.False(t, has, "storing the result is not under the provider's limit")
	})
	t.Run("a whole-vault failure is recorded and classified as the provider says", func(t *testing.T) {
		for code, class := range map[string]jobs.FailureClass{"azure.unreachable": jobs.Retryable, "azure.auth_failed": jobs.Permanent,
			"azure.throttled": jobs.Retryable} {
			f := newFixture(t, true)
			f.prov.Configure(func(c *fake.Config) {
				c.DiscoverErr = providers.NewError(code, class == jobs.Retryable, errors.New(canary), nil)
			})
			_, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
			requireFailure(t, err, class, code)
			require.Len(t, f.inv.failures, 1, code)
			var pe *providers.Error
			require.ErrorAs(t, f.inv.failures[0], &pe)
			assert.Equal(t, code, pe.Code)
			assert.Zero(t, f.inv.count("ReconcileKV"))
			assert.Equal(t, 1, f.inv.released, "the slot is released on failure")
			assert.Equal(t, 1, f.prov.Count("Close"))
			assert.NotContains(t, f.logs.String(), canary)
		}
	})
	t.Run("Open fails", func(t *testing.T) {
		f := newFixture(t, true)
		f.prov.Configure(func(c *fake.Config) { c.OpenErr = providers.NewError("azure.auth_failed", false, nil, nil) })
		_, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
		requireFailure(t, err, jobs.Permanent, "azure.auth_failed")
		assert.Equal(t, 1, f.inv.count("RecordKVFailure"))
		assert.Equal(t, 1, f.inv.released)
	})
	t.Run("the claim was lost while the result was stored", func(t *testing.T) {
		f := newFixture(t, true)
		f.inv.reconErr = fmt.Errorf("wrapped: %w", inventory.ErrClaimLost)
		_, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
		requireFailure(t, err, jobs.Retryable, "job.lease_expired")
		assert.Zero(t, f.inv.count("RecordKVFailure"), "the run that holds the job now owns the outcome")
	})
	t.Run("the vault was deleted meanwhile", func(t *testing.T) {
		f := newFixture(t, true)
		f.inv.reconErr = inventory.ErrNotFound
		_, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
		requireFailure(t, err, jobs.Permanent, "system.not_found")
		assert.Zero(t, f.inv.count("RecordKVFailure"))
	})
	t.Run("a poll of a vault that is gone or disabled ends quietly", func(t *testing.T) {
		for _, dropped := range []string{"deleted", "disabled"} {
			f := newFixture(t, true)
			f.inv.reconcile = inventory.KVSummary{Dropped: dropped}
			res, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
			require.NoError(t, err)
			assert.Equal(t, dropped, res["dropped"])
			assert.Zero(t, f.inv.count("RecordKVFailure"))
		}
	})
	t.Run("the request is refused", func(t *testing.T) {
		for err, want := range map[error]string{inventory.ErrNotFound: "system.not_found", inventory.ErrTargetNotReady: "target.disabled"} {
			f := newFixture(t, true)
			f.inv.pollReqErr = err
			_, e := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
			requireFailure(t, e, jobs.Permanent, want)
			assert.Empty(t, f.prov.Calls())
			assert.Zero(t, f.inv.count("RecordKVFailure"))
			assert.Equal(t, 1, f.inv.released)
		}
		f := newFixture(t, true)
		f.inv.pollReqErr = errors.New(canary)
		_, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		assert.NotContains(t, f.logs.String(), canary)
	})
	t.Run("an inventory that refuses the result", func(t *testing.T) {
		f := newFixture(t, true)
		f.inv.reconErr = providers.NewError("internal.unexpected", false, nil, nil)
		_, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
		requireFailure(t, err, jobs.Permanent, "internal.unexpected")
		assert.Equal(t, 1, f.inv.count("RecordKVFailure"), "an answer past the bounds is the vault's failure")

		f = newFixture(t, true)
		f.inv.reconErr = errors.New(canary)
		_, err = f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		assert.Zero(t, f.inv.count("RecordKVFailure"), "a database error is not the vault's")
		assert.NotContains(t, f.logs.String(), canary)
	})
	t.Run("the job's own context ends", func(t *testing.T) {
		f := newFixture(t, true)
		jobCtx, cancel := context.WithCancel(ctx)
		f.prov.hook = func(m string) {
			if m == "Discover" {
				cancel()
			}
		}
		f.prov.Configure(func(c *fake.Config) {
			c.DiscoverErr = providers.NewError("azure.unreachable", true, context.Canceled, nil)
		})
		_, err := f.h.poll(jobCtx, f.job(jobs.KVPoll, nil), noSteps{})
		requireFailure(t, err, jobs.Retryable, "job.lease_expired")
		assert.Zero(t, f.inv.count("RecordKVFailure"), "a shutdown or a lost lease is not the vault's failure")
		assert.Equal(t, 1, f.inv.released)
	})
	t.Run("no poll slot", func(t *testing.T) {
		f := newFixture(t, true)
		f.inv.slotErr = context.Canceled
		_, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
		requireFailure(t, err, jobs.Retryable, "job.lease_expired")
		assert.Empty(t, f.prov.Calls())
		assert.Zero(t, f.inv.released)
	})
	t.Run("a panic in the provider releases the slot and closes the session", func(t *testing.T) {
		f := newFixture(t, true)
		f.prov.panicIn = "Discover"
		assert.Panics(t, func() { _, _ = f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{}) })
		assert.Equal(t, 1, f.inv.released, "a panic never leaks a poll slot")
		assert.Equal(t, 1, f.prov.Count("Close"))
	})
	t.Run("a panic in the store releases the slot", func(t *testing.T) {
		f := newFixture(t, true)
		f.h.d.Inventory = &panicReconcile{fakeInv: f.inv}
		assert.Panics(t, func() { _, _ = f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{}) })
		assert.Equal(t, 1, f.inv.released)
	})
}

type panicReconcile struct{ *fakeInv }

func (p *panicReconcile) ReconcileKV(context.Context, uuid.UUID, providers.DiscoveryResult) (inventory.KVSummary, error) {
	panic(canary)
}

func importFixture(t *testing.T) (*fixture, []byte) {
	f := newFixture(t, true)
	pfx := []byte("pretend-pfx-with-the-private-key")
	id := uuid.New()
	f.inv.imp = inventory.KVImport{ID: id, VaultID: f.vault, CertificateID: uuid.New(), Name: "new-cert", State: inventory.ImportQueued, Thumbprint: validThumb}
	f.inv.material = inventory.ImportMaterial{VaultID: f.vault, Request: providers.ImportRequest{OperationID: id, Name: "new-cert",
		PFX: secrets.NewPlaintext(pfx), KeyType: "rsa", KeySize: 2048, LeafThumbprint: validThumb}}
	return f, pfx
}

func importJob(f *fixture) jobs.Job {
	return f.job(jobs.KVImport, map[string]string{"import_id": f.inv.imp.ID.String()})
}

func createdResult() providers.ImportResult {
	cer := []byte("the leaf der")
	return providers.ImportResult{Outcome: providers.ImportCreated, Version: validVer, Thumbprint: azureid.ThumbprintOf(cer), CER: cer}
}

func scriptImport(f *fixture, res providers.ImportResult, err error) {
	f.prov.Configure(func(c *fake.Config) {
		c.Import = func(providers.ImportRequest) (providers.ImportResult, error) { return res, err }
	})
}

func zeroed(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

func TestImportDecisionTable(t *testing.T) {
	ctx := context.Background()
	t.Run("a finished import is read back, never sent", func(t *testing.T) {
		for _, state := range []string{inventory.ImportSucceeded, inventory.ImportFailed, inventory.ImportUncertain} {
			f, pfx := importFixture(t)
			f.inv.imp.State, f.inv.imp.Version = state, validVer
			res, err := f.h.importToKV(ctx, importJob(f), noSteps{})
			require.NoError(t, err, state)
			assert.Equal(t, state, res["state"])
			assert.Empty(t, f.prov.Calls(), state)
			assert.Zero(t, f.inv.count("ImportMaterial"), state)
			assert.Zero(t, f.inv.count("MarkImportSent"), state)
			assert.Zero(t, f.inv.count("FinishImport"), state)
			assert.True(t, !zeroed(pfx), "nothing was built, nothing to zero: the fake's own buffer is untouched")
		}
	})
	t.Run("running: a run after a send or a crash after MarkImportSent", func(t *testing.T) {
		f, _ := importFixture(t)
		f.inv.imp.State = inventory.ImportRunning
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		fl := failureWith(t, err, jobs.Permanent, "azure.unexpected_response")
		assert.Equal(t, map[string]string{"state": "uncertain"}, fl.Params)
		assert.Empty(t, f.prov.Calls(), "no provider call: not even a session")
		assert.Zero(t, f.inv.count("ImportMaterial"), "the key is not decrypted again")
		assert.Zero(t, f.inv.count("MarkImportSent"))
		require.Len(t, f.inv.finished, 1)
		assert.Equal(t, providers.ImportUncertain, f.inv.finished[0].res.Outcome)
		require.Error(t, f.inv.finished[0].cause)
	})
	t.Run("running, and the record cannot be written", func(t *testing.T) {
		f, _ := importFixture(t)
		f.inv.imp.State = inventory.ImportRunning
		f.inv.finishErr = errors.New(canary)
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		assert.Empty(t, f.prov.Calls())
		assert.NotContains(t, f.logs.String(), canary)

		f, _ = importFixture(t)
		f.inv.imp.State = inventory.ImportRunning
		f.inv.finishErr = inventory.ErrClaimLost
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "job.lease_expired")

		f, _ = importFixture(t)
		f.inv.imp.State = inventory.ImportRunning
		f.inv.finishErr = inventory.ErrImportState
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Permanent, "azure.unexpected_response")
	})
	t.Run("the import is unknown or of another vault", func(t *testing.T) {
		f, _ := importFixture(t)
		f.inv.impErr = inventory.ErrNotFound
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Permanent, "system.not_found")
		f, _ = importFixture(t)
		f.inv.impErr = errors.New(canary)
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		f, _ = importFixture(t)
		_, err = f.h.importToKV(ctx, f.job(jobs.KVImport, map[string]string{"import_id": "nope"}), noSteps{})
		requireFailure(t, err, jobs.Permanent, "internal.unexpected")
	})
	t.Run("the vault cannot be used at all", func(t *testing.T) {
		f, _ := importFixture(t)
		f.inv.targetErr = inventory.ErrNotFound
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Permanent, "system.not_found")
		assert.Equal(t, []string{"system.not_found"}, f.inv.failedQueue)

		f, _ = importFixture(t)
		f.inv.target.Status = inventory.StatusDisabled
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Permanent, "target.disabled")
		assert.Equal(t, []string{"target.disabled"}, f.inv.failedQueue)

		f, _ = importFixture(t)
		f.inv.target.Type = inventory.TypeNginx
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Permanent, "internal.unexpected")
		assert.Equal(t, []string{"internal.unexpected"}, f.inv.failedQueue)

		f, _ = importFixture(t)
		f.h.d.Registry = providers.NewRegistry()
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Permanent, "internal.unexpected")
		assert.Equal(t, []string{"internal.unexpected"}, f.inv.failedQueue, "a build without the provider ends the queued import: it would block its name")
		assert.Zero(t, f.inv.count("ImportMaterial"))

		f, _ = importFixture(t)
		f.inv.targetErr = errors.New(canary)
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		assert.Empty(t, f.inv.failedQueue, "attempts are left")
		assert.NotContains(t, f.logs.String(), canary)
	})
	t.Run("no key", func(t *testing.T) {
		f, _ := importFixture(t)
		f.inv.materialErr = inventory.ErrNoPrivateKey
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Permanent, "certificate.no_private_key")
		require.Len(t, f.inv.finished, 1)
		assert.Equal(t, providers.ImportRefused, f.inv.finished[0].res.Outcome)
		var pe *providers.Error
		require.ErrorAs(t, f.inv.finished[0].cause, &pe)
		assert.Equal(t, "certificate.no_private_key", pe.Code)
		assert.Zero(t, f.prov.Count("ImportCertificate"))
		assert.Zero(t, f.inv.count("MarkImportSent"))
	})
	t.Run("what ImportMaterial refuses before anything is sent", func(t *testing.T) {
		for err, want := range map[error]string{inventory.ErrCertificateExpired: "certificate.expired", inventory.ErrUnsupportedKey: "certificate.unsupported_key",
			inventory.ErrImportChanged: "kv.import_invalid"} {
			f, _ := importFixture(t)
			f.inv.materialErr = err
			_, e := f.h.importToKV(ctx, importJob(f), noSteps{})
			requireFailure(t, e, jobs.Permanent, want)
			require.Len(t, f.inv.finished, 1, want)
			assert.Equal(t, providers.ImportRefused, f.inv.finished[0].res.Outcome)
			assert.Zero(t, f.prov.Count("ImportCertificate"))
		}
	})
	t.Run("the vault vanished or is disabled before the job ran", func(t *testing.T) {
		for err, want := range map[error]string{inventory.ErrNotFound: "system.not_found", inventory.ErrVaultUnavailable: "target.disabled"} {
			f, _ := importFixture(t)
			f.inv.materialErr = err
			_, e := f.h.importToKV(ctx, importJob(f), noSteps{})
			requireFailure(t, e, jobs.Permanent, want)
			assert.Equal(t, []string{want}, f.inv.failedQueue)
			assert.Zero(t, f.prov.Count("ImportCertificate"))
			assert.Zero(t, f.inv.count("FinishImport"))
		}
	})
	t.Run("ImportMaterial: state, claim, database", func(t *testing.T) {
		f, _ := importFixture(t)
		f.inv.materialErr = inventory.ErrImportState
		res, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		require.NoError(t, err, "ended quietly: never sent")
		assert.NotEmpty(t, res["state"])
		assert.Zero(t, f.prov.Count("ImportCertificate"))

		f, _ = importFixture(t)
		f.inv.materialErr = inventory.ErrClaimLost
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "job.lease_expired")
		assert.Zero(t, f.inv.count("FinishImport"))

		f, _ = importFixture(t)
		f.inv.materialErr = errors.New(canary)
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		assert.Zero(t, f.inv.count("FinishImport"), "attempts are left: the import stays queued")
		assert.NotContains(t, f.logs.String(), canary)

		// The last attempt must not leave the import queued forever (it would block its name).
		f, _ = importFixture(t)
		f.inv.materialErr = errors.New(canary)
		j := importJob(f)
		j.Attempt = j.MaxAttempts
		_, err = f.h.importToKV(ctx, j, noSteps{})
		requireFailure(t, err, jobs.Permanent, "internal.unexpected")
		require.Len(t, f.inv.finished, 1)
		assert.Equal(t, providers.ImportRefused, f.inv.finished[0].res.Outcome)
	})
	t.Run("Open fails retryably with attempts left", func(t *testing.T) {
		f, pfx := importFixture(t)
		f.prov.Configure(func(c *fake.Config) {
			c.OpenErr = providers.NewError("azure.unreachable", true, errors.New(canary), nil)
		})
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "azure.unreachable")
		assert.Zero(t, f.inv.count("MarkImportSent"), "nothing was sent")
		assert.Zero(t, f.inv.count("FinishImport"), "the next attempt starts over")
		assert.Zero(t, f.inv.count("RecordKVFailure"), "an import does not change the vault's health or its poll back-off")
		assert.Zero(t, f.inv.count("ImportMaterial"), "the key is decrypted only once the session is open")
		assert.False(t, zeroed(pfx), "no PFX was built")
		assert.NotContains(t, f.logs.String(), canary)
	})
	t.Run("Open fails retryably on the last attempt", func(t *testing.T) {
		f, pfx := importFixture(t)
		f.prov.Configure(func(c *fake.Config) {
			c.OpenErr = providers.NewError("azure.unreachable", true, context.DeadlineExceeded, nil)
		})
		j := importJob(f)
		j.Attempt = j.MaxAttempts
		_, err := f.h.importToKV(ctx, j, noSteps{})
		requireFailure(t, err, jobs.Permanent, "azure.unreachable")
		require.Len(t, f.inv.finished, 1, "it ends failed (can retry): nothing was ever sent")
		assert.Equal(t, providers.ImportRefused, f.inv.finished[0].res.Outcome, "refused, although the open's cause was a deadline")
		var pe *providers.Error
		require.ErrorAs(t, f.inv.finished[0].cause, &pe)
		assert.Equal(t, "azure.unreachable", pe.Code)
		assert.NoError(t, providers.CheckImportReturn(f.inv.finished[0].res, f.inv.finished[0].cause), "a refusal that obeys the outcome rules")
		assert.Zero(t, f.inv.count("ImportMaterial"))
		_ = pfx
	})
	t.Run("Open fails for good", func(t *testing.T) {
		f, pfx := importFixture(t)
		f.prov.Configure(func(c *fake.Config) { c.OpenErr = providers.NewError("azure.auth_failed", false, nil, nil) })
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Permanent, "azure.auth_failed")
		require.Len(t, f.inv.finished, 1)
		assert.Equal(t, providers.ImportRefused, f.inv.finished[0].res.Outcome)
		assert.Zero(t, f.inv.count("MarkImportSent"))
		assert.Zero(t, f.inv.count("ImportMaterial"))
		_ = pfx
	})
	t.Run("the claim is lost before the send", func(t *testing.T) {
		f, pfx := importFixture(t)
		f.inv.markErr = inventory.ErrClaimLost
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "job.lease_expired")
		assert.Zero(t, f.prov.Count("ImportCertificate"), "no send")
		assert.Zero(t, f.inv.count("FinishImport"))
		assert.True(t, zeroed(pfx))
	})
	t.Run("the mark is refused or fails", func(t *testing.T) {
		f, pfx := importFixture(t)
		f.inv.markErr = inventory.ErrImportState
		res, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		require.NoError(t, err, "somebody else sent it: nothing more to do here")
		assert.NotNil(t, res)
		assert.Zero(t, f.prov.Count("ImportCertificate"))
		assert.True(t, zeroed(pfx))

		f, pfx = importFixture(t)
		f.inv.markErr = errors.New(canary)
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		assert.Zero(t, f.prov.Count("ImportCertificate"), "a mark that did not commit sends nothing")
		assert.True(t, zeroed(pfx))
		assert.NotContains(t, f.logs.String(), canary)
	})
	t.Run("created", func(t *testing.T) {
		f, pfx := importFixture(t)
		scriptImport(f, createdResult(), nil)
		res, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"state": inventory.ImportSucceeded, "version": validVer}, res)
		require.Len(t, f.inv.finished, 1)
		assert.Equal(t, providers.ImportCreated, f.inv.finished[0].res.Outcome)
		assert.Nil(t, f.inv.finished[0].cause)
		assert.Equal(t, []string{"Import", "TargetRef", "VaultCredentials", "ImportMaterial", "MarkImportSent", "FinishImport"}, f.inv.called(),
			"the mark is committed before the provider is called and the outcome follows")
		assert.Equal(t, 1, f.prov.Count("ImportCertificate"))
		assert.True(t, zeroed(pfx))
		assert.Equal(t, 1, f.prov.Count("Close"))
		d, ok := f.prov.deadline("ImportCertificate")
		require.True(t, ok)
		assert.LessOrEqual(t, d, 5*time.Minute)
		assert.Greater(t, d, 105*time.Second, "longer than the import's own ~105 s budget")
	})
	t.Run("refused", func(t *testing.T) {
		f, pfx := importFixture(t)
		refusal := providers.NewError("azure.forbidden", false, errors.New(canary), map[string]string{"role": providers.RoleKeyVaultCertificatesOfficer})
		scriptImport(f, providers.ImportResult{Outcome: providers.ImportRefused}, refusal)
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		fl := failureWith(t, err, jobs.Permanent, "azure.forbidden")
		assert.Equal(t, providers.RoleKeyVaultCertificatesOfficer, fl.Params["role"])
		require.Len(t, f.inv.finished, 1)
		assert.Equal(t, providers.ImportRefused, f.inv.finished[0].res.Outcome)
		assert.True(t, zeroed(pfx))
		assert.NotContains(t, f.logs.String(), canary)
	})
	t.Run("uncertain", func(t *testing.T) {
		f, pfx := importFixture(t)
		cause := providers.NewError("azure.unreachable", true, context.DeadlineExceeded, nil)
		scriptImport(f, providers.ImportResult{Outcome: providers.ImportUncertain}, cause)
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		fl := failureWith(t, err, jobs.Permanent, "azure.unreachable")
		assert.Equal(t, map[string]string{"state": "uncertain"}, fl.Params)
		require.Len(t, f.inv.finished, 1)
		assert.Equal(t, providers.ImportUncertain, f.inv.finished[0].res.Outcome)
		assert.Equal(t, 1, f.prov.Count("ImportCertificate"), "exactly one send")
		assert.True(t, zeroed(pfx))
	})
	t.Run("a contract violation is uncertain, never created or refused", func(t *testing.T) {
		// created with an error and uncertain without one both break CheckImportReturn: inventory
		// turns them into uncertain; the job reports uncertain and does not send again.
		for _, tc := range []struct {
			res providers.ImportResult
			err error
		}{
			{createdResult(), providers.NewError("azure.unreachable", true, nil, nil)},
			{providers.ImportResult{Outcome: providers.ImportUncertain}, nil},
			{providers.ImportResult{}, nil},
		} {
			f, pfx := importFixture(t)
			// The scripted provider panics on a violation, so the violation is produced by a wrapper.
			f.reg = providers.NewRegistry()
			f.reg.Register(violating{spyProvider: f.prov, res: tc.res, err: tc.err})
			f.reg.Freeze()
			f.h.d.Registry = f.reg
			f.inv.finishState = inventory.ImportUncertain
			_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
			fl := failureWith(t, err, jobs.Permanent, "azure.unexpected_response")
			assert.Equal(t, map[string]string{"state": "uncertain"}, fl.Params)
			require.Len(t, f.inv.finished, 1)
			assert.True(t, zeroed(pfx))
		}
	})
	t.Run("the lease is lost during the send: the outcome is still recorded", func(t *testing.T) {
		f, _ := importFixture(t)
		jobCtx, cancel := context.WithCancel(ctx)
		f.prov.Configure(func(c *fake.Config) {
			c.Import = func(providers.ImportRequest) (providers.ImportResult, error) {
				cancel() // the runner cancels the job's context when it loses the lease
				return createdResult(), nil
			}
		})
		res, err := f.h.importToKV(jobCtx, importJob(f), noSteps{})
		require.NoError(t, err)
		assert.Equal(t, inventory.ImportSucceeded, res["state"])
		require.Len(t, f.inv.finished, 1)
		require.NoError(t, f.inv.finished[0].ctxErr, "recorded on a context detached from the job's")
		assert.True(t, f.inv.finished[0].hasDeadline, "but bounded")
		assert.Equal(t, importJob(f).Attempt, f.inv.finished[0].claim.Attempt, "the claim travels with it")
	})
	t.Run("the outcome cannot be recorded", func(t *testing.T) {
		f, _ := importFixture(t)
		scriptImport(f, createdResult(), nil)
		f.inv.finishErr = errors.New(canary)
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "internal.unexpected")
		assert.Equal(t, 1, f.prov.Count("ImportCertificate"), "the next run finds the import running and never sends")
		assert.NotContains(t, f.logs.String(), canary)

		f, _ = importFixture(t)
		scriptImport(f, createdResult(), nil)
		f.inv.finishErr = inventory.ErrClaimLost
		_, err = f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Retryable, "job.lease_expired")
	})
}

// violating answers an import with a result that breaks the outcome rules (the scripted provider
// refuses to).
type violating struct {
	*spyProvider
	res providers.ImportResult
	err error
}

func (v violating) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := v.spyProvider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return violatingSession{Session: s, res: v.res, err: v.err}, nil
}

type violatingSession struct {
	providers.Session
	res providers.ImportResult
	err error
}

func (v violatingSession) ImportCertificate(context.Context, providers.ImportRequest, providers.StepLogger) (providers.ImportResult, error) {
	return v.res, v.err
}

// A panic in the provider after the mark never leaves the PFX behind, and the job's rerun is the
// "running" row of the table.
func TestImportPanicZeroesThePFX(t *testing.T) {
	f, pfx := importFixture(t)
	f.prov.panicIn = "ImportCertificate"
	assert.Panics(t, func() { _, _ = f.h.importToKV(context.Background(), importJob(f), noSteps{}) })
	assert.True(t, zeroed(pfx))
	assert.Equal(t, 1, f.prov.Count("Close"))
	assert.Equal(t, 1, f.inv.count("MarkImportSent"))

	// The rerun the runner schedules (the panic became a retryable failure): the import is running now.
	f.inv.imp.State = inventory.ImportRunning
	f.prov.panicIn = ""
	before := f.prov.Count("ImportCertificate")
	_, err := f.h.importToKV(context.Background(), importJob(f), noSteps{})
	requireFailure(t, err, jobs.Permanent, "azure.unexpected_response")
	assert.Equal(t, before, f.prov.Count("ImportCertificate"), "never sent twice")
}

// A canary in an error's text, a panic value or a secret never reaches the logs or the failure.
func TestNoTextOfAnErrorIsKept(t *testing.T) {
	f, _ := importFixture(t)
	scriptImport(f, providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New(canary))
	_, err := f.h.importToKV(context.Background(), importJob(f), noSteps{})
	fl := failure(t, err)
	assert.NotContains(t, fl.Error(), canary)
	assert.NotContains(t, fmt.Sprint(fl.Params), canary)
	assert.NotContains(t, f.logs.String(), canary)
	assert.False(t, strings.Contains(f.logs.String(), "pretend-pfx"))
}

func TestPeriodicTasks(t *testing.T) {
	sched := &fakeScheduler{polled: 3}
	task := ScheduleTask(sched, time.Minute)
	assert.Equal(t, jobs.KVSchedule, task.Type)
	assert.Equal(t, time.Minute, task.Every)
	require.NoError(t, task.Run(context.Background()))
	assert.Equal(t, 1, sched.scheduleCalls)
	sched.err = errors.New(canary)
	assert.Error(t, task.Run(context.Background()))

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	plan := &fakePlanner{created: 2}
	pt := AutoDeployTask(plan, 90*time.Second, log)
	assert.Equal(t, jobs.KVAutoDeploy, pt.Type)
	assert.Equal(t, 90*time.Second, pt.Every)
	require.NoError(t, pt.Run(context.Background()))
	assert.Equal(t, 1, plan.calls)
	assert.NotContains(t, logs.String(), canary)
	plan.err = errors.Join(errors.New(canary), errors.New("second "+canary))
	err := pt.Run(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), canary, "the joined errors of single bindings carry their text: only the type is kept")
	assert.NotContains(t, logs.String(), canary)
	assert.Contains(t, logs.String(), "error_type")
	plan.err = inventory.ErrClaimLost
	assert.ErrorIs(t, pt.Run(context.Background()), inventory.ErrClaimLost)
}

type fakeScheduler struct {
	scheduleCalls int
	polled        int
	err           error
}

func (f *fakeScheduler) ScheduleKVPolls(context.Context) (int, error) {
	f.scheduleCalls++
	return f.polled, f.err
}

type fakePlanner struct {
	calls   int
	created int
	err     error
}

func (f *fakePlanner) PlanKVAutoDeploy(context.Context) (int, error) {
	f.calls++
	return f.created, f.err
}
