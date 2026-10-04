package deployjobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/secrets"
)

// trace is one ordered log of what the engine called on the inventory and on both providers, so a
// test can say "the vault was read before the first SSH call". A nil trace records nothing.
type trace struct {
	mu          sync.Mutex
	ev          []string
	deadline    map[string]time.Time // ctx deadline seen by azurekv Open and ReadCertificateSecret
	closePanics bool                 // the azurekv session's Close panics
	onRead      func()               // runs inside ReadCertificateSecret, before the provider answers
	readHook    func(ctx context.Context) (providers.CertificateSecret, error, bool)
}

func (t *trace) add(s string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.ev = append(t.ev, s)
	t.mu.Unlock()
}

// only returns the events whose name is in want, in order.
func (t *trace) only(want ...string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for _, e := range t.ev {
		if slices.Contains(want, e) {
			out = append(out, e)
		}
	}
	return out
}

type traceProvider struct {
	providers.Provider
	name string
	t    *trace
}

func (p traceProvider) Open(ctx context.Context, ref providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	p.t.add(p.name + ":Open")
	if dl, ok := ctx.Deadline(); ok && p.name == "azurekv" {
		p.t.mu.Lock()
		p.t.deadline["open"] = dl
		p.t.mu.Unlock()
	}
	s, err := p.Provider.Open(ctx, ref, c, e)
	if err != nil {
		return nil, err
	}
	return traceSession{Session: s, name: p.name, t: p.t}, nil
}

type traceSession struct {
	providers.Session
	name string
	t    *trace
}

func (s traceSession) Close() error {
	if s.name == "azurekv" {
		s.t.add("azurekv:Close")
		if s.t.closePanics {
			panic("close crashed")
		}
	}
	return s.Session.Close()
}

func (s traceSession) ReadCertificateSecret(ctx context.Context, req providers.SecretRequest) (providers.CertificateSecret, error) {
	s.t.add("azurekv:ReadCertificateSecret")
	if dl, ok := ctx.Deadline(); ok {
		s.t.mu.Lock()
		s.t.deadline["read"] = dl
		s.t.mu.Unlock()
	}
	if s.t.onRead != nil {
		s.t.onRead()
	}
	if s.t.readHook != nil {
		if sec, err, ok := s.t.readHook(ctx); ok {
			return sec, err
		}
	}
	return s.Session.ReadCertificateSecret(ctx, req)
}

func (s traceSession) VerifyDeployment(ctx context.Context, req providers.VerifyRequest) (providers.VerifyResult, error) {
	s.t.add(s.name + ":VerifyDeployment")
	return s.Session.VerifyDeployment(ctx, req)
}

func (s traceSession) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	s.t.add(s.name + ":DeployCertificate")
	return s.Session.DeployCertificate(ctx, req, log)
}

// kvFake is what fakeInv needs to serve a Key Vault deployment.
type kvFake struct {
	trace      *trace
	vaultID    uuid.UUID
	vault      inventory.Target
	vaultErr   error
	key        []byte                      // the key PEM KVDeployMaterial hands out
	warnings   []string                    // Material.Warnings
	entry      []byte                      // the secret as KVDeployMaterial received it
	secret     []byte                      // the very slice the engine handed over (checked for zeroing)
	noZero     bool                        // a KVDeployMaterial that does not zero the secret (the engine must)
	mutate     func(m *inventory.Material) // changes the material KVDeployMaterial returns (a misbehaving inventory)
	stepParams map[string]map[string]string
	kvCalls    int // calls of KVDeployMaterial
}

func (f *fakeInv) VaultCredentials(uuid.UUID) inventory.VaultCredentialSource { return nil }

func (f *fakeInv) KVDeployPrecheck(ctx context.Context, _ uuid.UUID) error {
	return f.call(ctx, "KVDeployPrecheck")
}

// KVDeployMaterial is the inventory's contract in miniature: the secret is zeroed on every path,
// only a queued or precheck deployment gets material, the key is a fresh holder.
func (f *fakeInv) KVDeployMaterial(ctx context.Context, _ uuid.UUID, secret providers.CertificateSecret) (inventory.Material, error) {
	f.mu.Lock()
	f.kv.entry = slices.Clone(secret.Value.Bytes())
	f.kv.secret = secret.Value.Bytes()
	noZero := f.kv.noZero
	f.mu.Unlock()
	if !noZero {
		defer secret.Value.Zero()
	}
	if err := f.call(ctx, "KVDeployMaterial"); err != nil {
		return inventory.Material{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if sentState(f.dep.State) {
		return inventory.Material{}, inventory.ErrDeploymentState
	}
	m := f.material
	m.Deployment = f.dep
	m.Warnings = slices.Clone(f.kv.warnings)
	f.key = slices.Clone(f.kv.key)
	f.keyOut = secrets.NewPlaintext(f.key)
	m.PrivateKeyPEM = f.keyOut
	if f.kv.mutate != nil {
		f.kv.mutate(&m)
	}
	return m, nil
}

func allZero(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

type kvFixture struct {
	*fixture
	az      *fake.Provider
	tr      *trace
	vault   uuid.UUID
	version string
	canary  []byte // the vault secret's value as the vault sends it
}

const kvSecretsRole = "Key Vault Secrets User"

// newKVFixture is the Phase 4 fixture whose deployment comes from a vault version: the deployment
// names a binding, the material names its vault source, the azurekv fake answers the secret read.
func newKVFixture(t *testing.T) *kvFixture {
	t.Helper()
	f := newFixture(t)
	k := &kvFixture{fixture: f, tr: &trace{deadline: map[string]time.Time{}}, vault: uuid.Must(uuid.NewV7()), version: fmt.Sprintf("%032x", 1),
		canary: []byte("PKCS12-CANARY-" + uuid.NewString())}
	k.az = fake.New(providers.KindAzureKV, providers.CapTestConnection, providers.CapReadCertificateSecret)
	k.az.Configure(func(c *fake.Config) {
		c.OpenErr = nil
		c.Secret = providers.CertificateSecret{ContentType: "application/x-pkcs12", Value: providers.NewSecret(slices.Clone(k.canary))}
	})
	binding := uuid.Must(uuid.NewV7())
	f.inv.dep.BindingID, f.inv.dep.KVVersion = &binding, k.version
	f.inv.material.KV = &inventory.KVSource{VaultID: k.vault, KVCertificateID: uuid.Must(uuid.NewV7()), VersionID: uuid.Must(uuid.NewV7()),
		Name: "web-cert", Version: k.version, Thumbprint: strings.Repeat("ab", 20)}
	f.inv.material.PrivateKeyPEM = secrets.Plaintext{}
	f.inv.kv = kvFake{trace: k.tr, vaultID: k.vault, vault: inventory.Target{ID: k.vault, Status: inventory.StatusOK}, key: slices.Clone(f.nw.KeyPEM)}
	k.registry(true)
	return k
}

// registry installs the traced providers; withVault false leaves the azurekv provider out.
func (k *kvFixture) registry(withVault bool) {
	reg := providers.NewRegistry()
	reg.Register(traceProvider{Provider: openErrProvider{Provider: k.prov, err: func() error { return k.openErr }, wrap: func(s providers.Session) providers.Session {
		if k.wrap != nil {
			return k.wrap(s)
		}
		return s
	}}, name: "nginx", t: k.tr})
	if withVault {
		reg.Register(traceProvider{Provider: k.az, name: "azurekv", t: k.tr})
	}
	reg.Freeze()
	k.h.d.Registry = reg
}

func (k *kvFixture) sshCalls() int { return len(k.prov.Calls()) }

func TestKVDeploymentReadsTheSecretBeforeAnySSH(t *testing.T) {
	t.Run("the order of a vault deployment", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.kv.warnings = []string{inventory.WarnChainIncomplete}
		var atSend providers.DeployRequest
		var keyAtSend []byte
		k.prov.Configure(func(c *fake.Config) {
			c.Deploy = func(req providers.DeployRequest) (providers.DeployOutcome, error) {
				atSend, keyAtSend = req, bytes.Clone(req.PrivateKeyPEM.Bytes())
				return providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "local"}, nil
			}
		})
		res, err := k.h.deploy(k.ctx, k.job(), k.steps)
		require.NoError(t, err)
		assert.Equal(t, "succeeded", res["outcome"])
		assert.Equal(t, []string{"azurekv:Open", "azurekv:ReadCertificateSecret", "azurekv:Close", "inv:KVDeployMaterial", "nginx:Open",
			"nginx:VerifyDeployment", "inv:StartDeployment", "nginx:DeployCertificate"},
			k.tr.only("azurekv:Open", "azurekv:ReadCertificateSecret", "azurekv:Close", "inv:KVDeployMaterial", "nginx:Open", "nginx:VerifyDeployment",
				"inv:StartDeployment", "nginx:DeployCertificate"), "the vault is read and closed, the secret checked, and only then is the server touched")
		reads := k.az.Calls()
		require.Equal(t, 3, len(reads), "Open, ReadCertificateSecret, Close")
		assert.Equal(t, providers.SecretRequest{Name: "web-cert", Version: k.version}, reads[1].Secret, "the deployment's own vault certificate and exact version")
		assert.Equal(t, k.vault, reads[1].Target)
		assert.Equal(t, k.nw.KeyPEM, keyAtSend, "the material's key reaches the send")
		assert.Equal(t, k.nw.FullchainPEM, atSend.CertificatePEM)
		assert.True(t, k.keyZeroed(), "the key is zeroed after the send")
		assert.True(t, allZero(k.inv.kv.secret), "the vault secret is zeroed")
		assert.Equal(t, []string{stepKVSecret + ":started", stepKVSecret + ":ok"}, k.inv.stepNames()[:2], "the vault step comes first")
		assert.Equal(t, map[string]string{"reason": "chain_incomplete"}, k.inv.kv.stepParams[stepKVSecret+":ok"], "an incomplete chain is said on the step")
	})

	t.Run("a complete chain says nothing on the step", func(t *testing.T) {
		k := newKVFixture(t)
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		require.NoError(t, err)
		assert.Empty(t, k.inv.kv.stepParams[stepKVSecret+":ok"])
	})

	t.Run("a failed read: the server saw nothing, not even a connection", func(t *testing.T) {
		k := newKVFixture(t)
		k.az.Configure(func(c *fake.Config) {
			c.SecretErr = providers.NewError("azure.forbidden", false, nil, map[string]string{"role": kvSecretsRole, "model": "rbac"})
		})
		res, err := k.h.deploy(k.ctx, k.job(), k.steps)
		jf := failureOf(t, err)
		assert.Equal(t, "azure.forbidden", jf.Reason)
		assert.Equal(t, "failed", res["outcome"])
		assert.Zero(t, k.sshCalls(), "no SSH call at all")
		assert.NotContains(t, k.inv.calls(), "StartDeployment")
	})
}

func TestKVMaterialFailures(t *testing.T) {
	forbidden := providers.NewError("azure.forbidden", false, nil, map[string]string{"role": kvSecretsRole, "model": "rbac", "azure_code": "Forbidden",
		"azure_request_id": "00000000-0000-0000-0000-000000000001", "stderr": "remote text"})
	for _, tc := range []struct {
		name    string
		setup   func(k *kvFixture)
		attempt int // 0 = 1
		reason  string
		class   jobs.FailureClass
		finish  bool // the deployment ends failed with the reason
		params  map[string]string
		step    string // the failed step recorded on the deployment
		noRead  bool   // the secret is not read
	}{
		{"F-41 the secrets role is missing", func(k *kvFixture) { k.az.Configure(func(c *fake.Config) { c.SecretErr = forbidden }) }, 0,
			"azure.forbidden", jobs.Permanent, true, map[string]string{"role": kvSecretsRole, "model": "rbac", "azure_code": "Forbidden",
				"azure_request_id": "00000000-0000-0000-0000-000000000001"}, stepKVSecret, false},
		{"the version is disabled", func(k *kvFixture) {
			k.az.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("kv.version_disabled", false, nil, nil) })
		}, 0, "kv.version_disabled", jobs.Permanent, true, nil, stepKVSecret, false},
		{"the certificate is gone", func(k *kvFixture) {
			k.az.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("kv.certificate_not_found", false, nil, nil) })
		}, 0, "kv.certificate_not_found", jobs.Permanent, true, nil, stepKVSecret, false},
		{"the vault is unreachable, attempts left", func(k *kvFixture) {
			k.az.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("azure.unreachable", true, nil, nil) })
		}, 1, "azure.unreachable", jobs.Retryable, false, nil, "", false},
		{"the vault throttles, attempts left", func(k *kvFixture) {
			k.az.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("azure.throttled", true, nil, nil) })
		}, 1, "azure.throttled", jobs.Retryable, false, nil, "", false},
		{"the vault throttles on the last attempt (I-3)", func(k *kvFixture) {
			k.az.Configure(func(c *fake.Config) { c.SecretErr = providers.NewError("azure.throttled", true, nil, nil) })
		}, 3, "azure.throttled", jobs.Permanent, true, nil, stepKVSecret, false},
		{"the vault refuses the sign-in", func(k *kvFixture) {
			k.az.Configure(func(c *fake.Config) {
				c.OpenErr = providers.NewError("azure.auth_failed", false, nil, map[string]string{"aadsts": "7000215"})
			})
		}, 0, "azure.auth_failed", jobs.Permanent, true, map[string]string{"aadsts": "7000215"}, stepKVSecret, true},
		{"the secret is another version", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = inventory.ErrSecretMismatch }, 0,
			"kv.secret_mismatch", jobs.Permanent, true, nil, stepKVSecret, false},
		{"the secret is unreadable", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = inventory.ErrSecretUnreadable }, 0,
			"kv.secret_unreadable", jobs.Permanent, true, nil, stepKVSecret, false},
		{"F-17 the chain is incomplete and nobody confirmed it", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = inventory.ErrChainUnconfirmed }, 0,
			"certificate.chain_unconfirmed", jobs.Permanent, true, nil, stepKVSecret, false},
		{"F-19 the secret's leaf expired", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = inventory.ErrCertificateExpired }, 0,
			"certificate.expired", jobs.Permanent, true, nil, stepKVSecret, false},
		{"the decode slots are busy", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = inventory.ErrPFXBusy }, 1,
			"certificate.pfx_busy", jobs.Retryable, false, nil, "", false},
		{"the decode slots are busy on the last attempt", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = inventory.ErrPFXBusy }, 3,
			"certificate.pfx_busy", jobs.Permanent, true, nil, stepKVSecret, false},
		{"the deployment's version row is gone", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = inventory.ErrNotFound }, 0,
			"system.not_found", jobs.Permanent, true, nil, stepKVSecret, false},
		{"database fails after the read, attempts left (reverts the round-1 rule)", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = errors.New("database down") }, 1,
			"internal.unexpected", jobs.Retryable, false, nil, "", false},
		{"serialization failure after the read, attempts left", func(k *kvFixture) {
			k.inv.errs["KVDeployMaterial"] = fmt.Errorf("inventory: record: %w", &pgconn.PgError{Code: "40001"})
		}, 1, "internal.unexpected", jobs.Retryable, false, nil, "", false},
		{"unknown error after the read on the last attempt", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = errors.New("database down") }, 3,
			"internal.unexpected", jobs.Permanent, true, nil, stepKVSecret, false},
		{"the vault was deleted", func(k *kvFixture) { k.inv.kv.vaultErr = inventory.ErrNotFound }, 0,
			"kv.vault_unavailable", jobs.Permanent, true, nil, stepKVSecret, true},
		{"the vault is disabled", func(k *kvFixture) { k.inv.kv.vault.Status = inventory.StatusDisabled }, 0,
			"kv.vault_unavailable", jobs.Permanent, true, nil, stepKVSecret, true},
		{"the vault cannot be read from the database", func(k *kvFixture) { k.inv.kv.vaultErr = errors.New("database down") }, 1,
			"internal.unexpected", jobs.Retryable, false, nil, "", true},
		{"no azurekv provider in this build", func(k *kvFixture) { k.registry(false) }, 0,
			"internal.unexpected", jobs.Permanent, true, nil, stepKVSecret, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKVFixture(t)
			tc.setup(k)
			j := k.job()
			if tc.attempt > 0 {
				j.Attempt = tc.attempt
			}
			res, err := k.h.deploy(k.ctx, j, k.steps)
			jf := failureOf(t, err)
			assert.Equal(t, tc.reason, jf.Reason)
			assert.Equal(t, tc.class, jf.Class)
			assert.Zero(t, k.sshCalls(), "no SSH call: nothing was sent, nothing was connected")
			assert.NotContains(t, k.inv.calls(), "StartDeployment")
			assert.NotContains(t, k.inv.calls(), "RecordOutcome")
			if tc.noRead {
				assert.Zero(t, k.az.Count("ReadCertificateSecret"))
			}
			if tc.finish {
				assert.Equal(t, "failed", res["outcome"])
				fin := k.inv.lastFinish()
				assert.Equal(t, inventory.DeployStatusFailed, fin.Status)
				assert.Equal(t, tc.reason, fin.ErrorCode)
				assert.Equal(t, tc.step, fin.FailedStep)
				if tc.params != nil {
					assert.Equal(t, tc.params, fin.Params, "only the allowlisted params")
					assert.Equal(t, tc.params, jf.Params)
				}
				assert.Contains(t, k.inv.stepNames(), stepKVSecret+":failed")
			} else {
				assert.Empty(t, k.inv.finishes, "the deployment stays queued for the next attempt: nothing is finished")
				assert.Equal(t, inventory.DeployStatePrecheck, k.inv.dep.State)
			}
			if k.inv.kv.secret != nil {
				assert.True(t, allZero(k.inv.kv.secret), "the vault secret is zeroed on every failure")
			}
			if k.inv.key != nil {
				assert.True(t, k.keyZeroed())
			}
		})
	}
}

func TestKVStepEdges(t *testing.T) {
	t.Run("a stale run records nothing and returns the lease answer", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.errs["KVDeployMaterial"] = inventory.ErrClaimLost
		res, err := k.h.deploy(k.ctx, k.job(), k.steps)
		assert.Nil(t, res)
		assert.Equal(t, "job.lease_expired", failureOf(t, err).Reason)
		assert.Empty(t, k.inv.finishes)
		assert.Zero(t, k.sshCalls())
	})

	t.Run("a state that changed under the run is followed", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.errs["KVDeployMaterial"] = inventory.ErrDeploymentState
		k.inv.hooks["KVDeployMaterial"] = func(context.Context) {
			k.inv.mu.Lock()
			k.inv.dep.State, k.inv.dep.Status, k.inv.dep.ErrorCode = inventory.DeployStateDone, inventory.DeployStatusFailed, "deployment.interrupted"
			k.inv.mu.Unlock()
		}
		res, err := k.h.deploy(k.ctx, k.job(), k.steps)
		assert.Equal(t, "deployment.interrupted", failureOf(t, err).Reason, "the record as the other run left it")
		assert.Equal(t, "failed", res["outcome"])
		assert.Zero(t, k.sshCalls())
	})

	t.Run("a context that ends during the read releases the job", func(t *testing.T) {
		k := newKVFixture(t)
		ctx, cancel := context.WithCancel(k.ctx)
		defer cancel()
		k.tr.onRead = cancel
		res, err := k.h.deploy(ctx, k.job(), k.steps)
		assert.Nil(t, res)
		jf := failureOf(t, err)
		assert.Equal(t, "deployment.interrupted", jf.Reason)
		assert.Equal(t, jobs.Retryable, jf.Class)
		assert.Empty(t, k.inv.finishes, "nothing is recorded as the outcome: a re-run reads the vault again")
		assert.Zero(t, k.sshCalls())
		assert.Contains(t, k.inv.stepNames(), stepKVSecret+":failed")
	})

	t.Run("a context that ends while the secret is checked releases the job", func(t *testing.T) {
		k := newKVFixture(t)
		ctx, cancel := context.WithCancel(k.ctx)
		defer cancel()
		k.inv.hooks["KVDeployMaterial"] = func(context.Context) { cancel() }
		k.inv.errs["KVDeployMaterial"] = context.Canceled
		_, err := k.h.deploy(ctx, k.job(), k.steps)
		jf := failureOf(t, err)
		assert.Equal(t, "deployment.interrupted", jf.Reason)
		assert.Equal(t, jobs.Retryable, jf.Class)
		assert.Empty(t, k.inv.finishes)
		assert.Zero(t, k.sshCalls())
		assert.True(t, allZero(k.inv.kv.secret))
	})

	t.Run("the read has a one minute budget of its own", func(t *testing.T) {
		k := newKVFixture(t)
		before := time.Now()
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		require.NoError(t, err)
		k.tr.mu.Lock()
		defer k.tr.mu.Unlock()
		for _, what := range []string{"open", "read"} {
			dl, ok := k.tr.deadline[what]
			require.True(t, ok, what)
			assert.WithinDuration(t, before.Add(time.Minute), dl, 5*time.Second, what)
		}
	})

	t.Run("a budget that runs out ends before anything is sent, retryable", func(t *testing.T) {
		old := kvReadBudget
		kvReadBudget = 20 * time.Millisecond
		t.Cleanup(func() { kvReadBudget = old })
		k := newKVFixture(t)
		k.tr.readHook = func(ctx context.Context) (providers.CertificateSecret, error, bool) {
			<-ctx.Done()
			return providers.CertificateSecret{}, ctx.Err(), true // a raw context error, not a provider's
		}
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		jf := failureOf(t, err)
		assert.Equal(t, "azure.unreachable", jf.Reason)
		assert.Equal(t, jobs.Retryable, jf.Class)
		assert.Zero(t, k.sshCalls())
		assert.Empty(t, k.inv.finishes)
	})

	t.Run("an uploaded certificate never touches the vault", func(t *testing.T) {
		f := newFixture(t)
		reg := providers.NewRegistry()
		tr := &trace{deadline: map[string]time.Time{}}
		az := fake.New(providers.KindAzureKV, providers.CapReadCertificateSecret)
		reg.Register(traceProvider{Provider: az, name: "azurekv", t: tr})
		reg.Register(openErrProvider{Provider: f.prov, err: func() error { return nil }, wrap: func(s providers.Session) providers.Session { return s }})
		reg.Freeze()
		f.h.d.Registry = reg
		_, err := f.h.deploy(f.ctx, f.job(), f.steps)
		require.NoError(t, err)
		assert.Zero(t, len(az.Calls()))
		assert.NotContains(t, f.inv.calls(), "KVDeployMaterial")
		assert.NotContains(t, f.inv.stepNames(), stepKVSecret+":started")
		assert.True(t, f.keyZeroed())
	})
}

// D6: the vault's key is zeroed on every path, whether the run ends before the send, at it, after it
// or in a panic. Each row keeps the holder KVDeployMaterial handed out and checks it afterwards.
func TestKVKeyIsZeroedOnEveryPath(t *testing.T) {
	recordOnly := map[string]bool{"expired at run time": true, "not valid yet": true, "configuration invalid": true, "location unsupported": true}
	committed := func(providers.DeployRequest) (providers.DeployOutcome, error) {
		return providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "local"}, nil
	}
	for _, tc := range []struct {
		name  string
		setup func(k *kvFixture)
	}{
		{"success", func(k *kvFixture) {}},
		{"expired at run time", func(k *kvFixture) { k.inv.material.NotAfter = k.clock.Now().Add(-time.Minute) }},
		{"not valid yet", func(k *kvFixture) { k.inv.material.NotBefore = k.clock.Now().Add(time.Minute) }},
		{"configuration invalid", func(k *kvFixture) { k.inv.material.ConfigValid = false }},
		{"location unsupported", func(k *kvFixture) { k.inv.material.Location.Supported = false }},
		{"the server cannot be opened", func(k *kvFixture) { k.openErr = providers.NewError("ssh.unreachable", false, nil, nil) }},
		{"the pre-check refuses (F-06)", func(k *kvFixture) {
			k.verify = &providers.VerifyResult{Mode: "remote", Served: strings.Repeat("c", 64), Reason: "deployment.verify_other"}
		}},
		{"the pre-check cannot compare", func(k *kvFixture) { k.inv.material.CurrentFingerprint = "" }},
		{"the start record fails", func(k *kvFixture) { k.inv.errs["StartDeployment"] = errors.New("database down") }},
		{"a recovery began before the start", func(k *kvFixture) { k.inv.errs["StartDeployment"] = inventory.ErrRecoveryPending }},
		{"the claim is lost before the send", func(k *kvFixture) { k.inv.errs["CheckClaim"] = inventory.ErrClaimLost }},
		{"the send is refused", func(k *kvFixture) {
			k.prov.Configure(func(c *fake.Config) {
				c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
					e := providers.NewError("nginx.busy", true, nil, nil)
					return providers.DeployOutcome{Result: providers.DeployNoChange, Reason: e.Code}, e
				}
			})
		}},
		{"the send rolls back", func(k *kvFixture) {
			k.prov.Configure(func(c *fake.Config) {
				c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
					return providers.DeployOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, FailedStep: providers.StepNameReload,
						Reason: "deployment.reload_failed"}, nil
				}
			})
		}},
		{"the outcome is uncertain", func(k *kvFixture) {
			k.prov.Configure(func(c *fake.Config) {
				c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
					return providers.DeployOutcome{Result: providers.DeployUncertain}, providers.NewError("ssh.timeout", true, nil, nil)
				}
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKVFixture(t)
			k.prov.Configure(func(c *fake.Config) { c.Deploy = committed })
			tc.setup(k)
			_, _ = k.h.deploy(k.ctx, k.job(), k.steps)
			if recordOnly[tc.name] {
				// M-1 (these rows used to require a handed-out key): the record alone refuses, so the
				// vault is never asked and no key exists to zero.
				assert.Zero(t, len(k.az.Calls()), "no vault call")
				assert.Nil(t, k.inv.key, "no key was handed out")
				return
			}
			require.NotNil(t, k.inv.key, "the vault step handed out a key")
			assert.True(t, k.keyZeroed(), "the vault's key is zeroed when the run ends")
			assert.True(t, allZero(k.inv.kv.secret), "and so is the vault secret")
			assert.NotEmpty(t, k.inv.kv.entry)
			assert.False(t, allZero(k.inv.kv.entry), "the secret was not already empty when the engine passed it on (not a vacuous check)")
		})
	}

	t.Run("the context ends between the read and the start record", func(t *testing.T) {
		k := newKVFixture(t)
		ctx, cancel := context.WithCancel(k.ctx)
		defer cancel()
		k.inv.hooks["step:"+stepKVSecret+":ok"] = func(context.Context) { cancel() }
		_, err := k.h.deploy(ctx, k.job(), k.steps)
		assert.Equal(t, "deployment.interrupted", failureOf(t, err).Reason)
		assert.True(t, k.keyZeroed())
		assert.Zero(t, k.prov.Count("DeployCertificate"))
	})

	t.Run("a panic in the provider's send", func(t *testing.T) {
		k := newKVFixture(t)
		k.prov.Configure(func(c *fake.Config) {
			c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) { panic("provider crashed") }
		})
		assert.PanicsWithValue(t, "provider crashed", func() { _, _ = k.h.deploy(k.ctx, k.job(), k.steps) })
		assert.True(t, k.keyZeroed(), "a deferred zeroing runs while the panic unwinds")
	})

	t.Run("a panic in the pre-check", func(t *testing.T) {
		k := newKVFixture(t)
		k.prov.Configure(func(c *fake.Config) {
			c.Verify = func(providers.VerifyRequest) (providers.VerifyResult, error) { panic("provider crashed") }
		})
		assert.Panics(t, func() { _, _ = k.h.deploy(k.ctx, k.job(), k.steps) })
		assert.True(t, k.keyZeroed())
	})

	t.Run("a panic in the inventory after the secret was handed over", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.kv.noZero = true // a KVDeployMaterial that forgot: the engine zeroes the secret itself
		k.inv.hooks["KVDeployMaterial"] = func(context.Context) { panic("inventory crashed") }
		assert.PanicsWithValue(t, "inventory crashed", func() { _, _ = k.h.deploy(k.ctx, k.job(), k.steps) })
		assert.True(t, allZero(k.inv.kv.secret), "the engine zeroes the secret it read, whatever the inventory does")
		assert.Zero(t, k.sshCalls())
	})

	t.Run("an inventory that does not zero the secret", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.kv.noZero = true
		k.inv.errs["KVDeployMaterial"] = inventory.ErrSecretUnreadable
		_, _ = k.h.deploy(k.ctx, k.job(), k.steps)
		assert.True(t, allZero(k.inv.kv.secret))
	})

	t.Run("a failed read hands over no secret and leaves nothing", func(t *testing.T) {
		k := newKVFixture(t)
		var got []byte
		k.tr.readHook = func(context.Context) (providers.CertificateSecret, error, bool) {
			got = bytes.Clone(k.canary)
			v := bytes.Clone(k.canary)
			k.inv.kv.secret = v // a provider that returns a value together with its error
			return providers.CertificateSecret{ContentType: "application/x-pkcs12", Value: providers.NewSecret(v)},
				providers.NewError("azure.unreachable", true, nil, nil), true
		}
		_, _ = k.h.deploy(k.ctx, k.job(), k.steps)
		require.NotEmpty(t, got)
		assert.True(t, allZero(k.inv.kv.secret), "a value returned with an error is zeroed too")
	})
}

// Nothing of the vault secret or the key reaches a log, a step, a finish record or a job answer.
func TestKVSecretNeverShows(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(k *kvFixture)
	}{
		{"success", func(k *kvFixture) {}},
		{"the vault refuses", func(k *kvFixture) {
			k.az.Configure(func(c *fake.Config) {
				c.SecretErr = providers.NewError("azure.forbidden", false, errors.New("cause "+string(k.canary)), map[string]string{"role": kvSecretsRole})
			})
		}},
		{"the secret is unreadable", func(k *kvFixture) { k.inv.errs["KVDeployMaterial"] = inventory.ErrSecretUnreadable }},
		{"the send fails", func(k *kvFixture) {
			k.prov.Configure(func(c *fake.Config) {
				c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
					e := providers.NewError("nginx.busy", true, nil, nil)
					return providers.DeployOutcome{Result: providers.DeployNoChange, Reason: e.Code}, e
				}
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKVFixture(t)
			tc.setup(k)
			res, err := k.h.deploy(k.ctx, k.job(), k.steps)
			seen := fmt.Sprintf("%v %v %+v %v %v", res, err, k.inv.finishes, k.inv.outcomes, k.inv.stepNames()) +
				fmt.Sprint(k.inv.kv.stepParams) + k.logs.String() + strings.Join(k.steps.names, ",")
			var jf *jobs.Failure
			if errors.As(err, &jf) {
				seen += fmt.Sprint(jf.Params) + jf.Reason
			}
			for _, needle := range append(keyNeedles(k.nw.KeyPEM), string(k.canary), "PKCS12-CANARY") {
				assert.NotContains(t, seen, needle)
			}
		})
	}
}

// D5 (with the allowlist of inventory.errorParamKeys): the vault's closed params reach the
// deployment and the job; text outside the allowlist does not.
func TestKVParamsKeepTheAzureKeys(t *testing.T) {
	k := newKVFixture(t)
	k.az.Configure(func(c *fake.Config) {
		c.SecretErr = providers.NewError("azure.forbidden", false, nil, map[string]string{"role": kvSecretsRole, "model": "access_policy",
			"azure_code": "ForbiddenByRbac", "azure_request_id": "00000000-0000-0000-0000-000000000002", "aadsts": "700016", "reason": "tenant_mismatch",
			"client_address": "203.0.113.7", "stderr": "remote text", "directory": "/etc/x"})
	})
	_, err := k.h.deploy(k.ctx, k.job(), k.steps)
	want := map[string]string{"role": kvSecretsRole, "model": "access_policy", "azure_code": "ForbiddenByRbac",
		"azure_request_id": "00000000-0000-0000-0000-000000000002", "aadsts": "700016", "reason": "tenant_mismatch", "client_address": "203.0.113.7"}
	assert.Equal(t, want, failureOf(t, err).Params)
	assert.Equal(t, want, k.inv.lastFinish().Params)
}

// A recovery of a vault deployment never reads the vault: it works from the journal and the record.
func TestKVRecoveryNeedsNoVaultAccess(t *testing.T) {
	k := newKVFixture(t)
	k.sent(inventory.DeployStateRecovering, time.Hour)
	k.status = providers.DeploymentState{Phase: providers.PhaseCommitted, NewCertSHA256: sha(k.nw.FullchainPEM), BackupDir: "/b"}
	_, err := k.h.recoverJob(k.ctx, k.recoverJob(), k.steps)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStatusSucceeded, k.inv.lastFinish().Status)
	assert.Equal(t, sha(k.nw.FullchainPEM), k.inv.lastFinish().CertFileSHA256, "the file hash is the journal's, not what the certificate row holds now")
	assert.Zero(t, len(k.az.Calls()), "no vault call")
	assert.NotContains(t, k.inv.calls(), "KVDeployMaterial")
	assert.NotContains(t, k.inv.calls(), "DeploymentMaterial(true)")
}

// A deploy job that finds the record sent never reads the vault either.
func TestKVDeployJobAfterTheSendRecoversWithoutTheVault(t *testing.T) {
	k := newKVFixture(t)
	k.sent(inventory.DeployStateDeploying, time.Minute)
	k.status = providers.DeploymentState{Phase: providers.PhaseNone}
	_, _ = k.h.deploy(k.ctx, k.job(), k.steps)
	assert.Zero(t, len(k.az.Calls()))
	assert.NotContains(t, k.inv.calls(), "KVDeployMaterial")
}

// A run interrupted before the start record leaves the deployment in its pre-check; the next run
// reads the vault again (nothing of the secret was kept) and deploys.
func TestKVResumeReadsTheVaultAgain(t *testing.T) {
	k := newKVFixture(t)
	ctx, cancel := context.WithCancel(k.ctx)
	defer cancel()
	k.inv.hooks["step:"+stepKVSecret+":ok"] = func(context.Context) { cancel() }
	_, err := k.h.deploy(ctx, k.job(), k.steps)
	assert.Equal(t, "deployment.interrupted", failureOf(t, err).Reason)
	assert.Equal(t, 1, k.az.Count("ReadCertificateSecret"))
	assert.True(t, allZero(k.inv.kv.secret))
	assert.True(t, k.keyZeroed())
	assert.Equal(t, inventory.DeployStatePrecheck, k.inv.dep.State)

	delete(k.inv.hooks, "step:"+stepKVSecret+":ok")
	_, err = k.h.deploy(k.ctx, k.job(), k.steps)
	require.NoError(t, err)
	assert.Equal(t, 2, k.az.Count("ReadCertificateSecret"), "the second run reads the vault again")
	assert.Equal(t, inventory.DeployStatusSucceeded, k.inv.lastFinish().Status)

	// A resume that finds the secret refused now ends failed, nothing sent.
	k = newKVFixture(t)
	ctx2, cancel2 := context.WithCancel(k.ctx)
	defer cancel2()
	k.inv.hooks["step:"+stepKVSecret+":ok"] = func(context.Context) { cancel2() }
	_, _ = k.h.deploy(ctx2, k.job(), k.steps)
	delete(k.inv.hooks, "step:"+stepKVSecret+":ok")
	baseline := k.sshCalls() // the interrupted run had already begun its pre-check
	k.az.Configure(func(c *fake.Config) {
		c.SecretErr = providers.NewError("azure.forbidden", false, nil, map[string]string{"role": kvSecretsRole})
	})
	_, err = k.h.deploy(k.ctx, k.job(), k.steps)
	assert.Equal(t, "azure.forbidden", failureOf(t, err).Reason)
	assert.Equal(t, baseline, k.sshCalls(), "the second run made no SSH call: the vault refused first")
	assert.Equal(t, inventory.DeployStatusFailed, k.inv.lastFinish().Status)
}

// Every refusal the inventory can give is a closed reason, Permanent, in both places it can come from:
// the pre-check, asked before any vault call (zero vault calls, zero SSH calls), and KVDeployMaterial,
// which judges again after the read (one read, no retry).
var kvSentinels = []struct {
	err    error
	reason string
}{
	{inventory.ErrBindingGone, "kv.binding_gone"},
	{inventory.ErrAutoDeployOff, "kv.auto_deploy_off"},
	{inventory.ErrVaultUnavailable, "kv.vault_unavailable"},
	{inventory.ErrKVCertificateMissing, "kv.certificate_not_found"},
	{inventory.ErrVersionDisabled, "kv.version_disabled"},
	{inventory.ErrVersionHeld, "kv.version_held"},
	{inventory.ErrCertificateExpired, "certificate.expired"},
	{inventory.ErrCertificateNotYetValid, "certificate.not_yet_valid"},
	{inventory.ErrNotFound, "system.not_found"},
}

func TestKVRefusalsOfTheInventory(t *testing.T) {
	for _, sc := range kvSentinels {
		t.Run("precheck "+sc.reason, func(t *testing.T) {
			k := newKVFixture(t)
			k.inv.errs["KVDeployPrecheck"] = fmt.Errorf("wrapped: %w", sc.err)
			res, err := k.h.deploy(k.ctx, k.job(), k.steps)
			jf := failureOf(t, err)
			assert.Equal(t, jobs.Permanent, jf.Class)
			assert.Equal(t, sc.reason, jf.Reason)
			assert.Equal(t, "failed", res["outcome"])
			assert.Zero(t, len(k.az.Calls()), "not one vault call: no Open, no read")
			assert.Zero(t, k.sshCalls())
			assert.NotContains(t, k.inv.calls(), "KVDeployMaterial")
			fin := k.inv.lastFinish()
			assert.Equal(t, sc.reason, fin.ErrorCode)
			assert.Equal(t, stepKVSecret, fin.FailedStep)
			assert.Nil(t, k.inv.key, "no key was handed out")
		})
		t.Run("material "+sc.reason, func(t *testing.T) {
			k := newKVFixture(t)
			k.inv.errs["KVDeployMaterial"] = fmt.Errorf("wrapped: %w", sc.err)
			_, err := k.h.deploy(k.ctx, k.job(), k.steps)
			jf := failureOf(t, err)
			assert.Equal(t, jobs.Permanent, jf.Class)
			assert.Equal(t, sc.reason, jf.Reason)
			assert.Equal(t, 1, k.az.Count("ReadCertificateSecret"))
			assert.Zero(t, k.sshCalls())
			assert.Equal(t, stepKVSecret, k.inv.lastFinish().FailedStep)
		})
	}

	t.Run("an unknown error of the pre-check reads nothing and is retried", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.errs["KVDeployPrecheck"] = errors.New("database down")
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		jf := failureOf(t, err)
		assert.Equal(t, jobs.Retryable, jf.Class)
		assert.Equal(t, "internal.unexpected", jf.Reason)
		assert.Zero(t, len(k.az.Calls()), "nothing was read: a retry costs no secret")
		assert.Empty(t, k.inv.finishes)
	})

	t.Run("an unknown error after the read is retried and the second attempt succeeds: two reads", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.errs["KVDeployMaterial"] = &pgconn.PgError{Code: "40001"}
		k.inv.hooks["KVDeployMaterial"] = func(context.Context) {
			k.inv.mu.Lock()
			defer k.inv.mu.Unlock()
			if k.inv.kv.kvCalls++; k.inv.kv.kvCalls > 1 {
				delete(k.inv.errs, "KVDeployMaterial") // the blip is over
			}
		}
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		jf := failureOf(t, err)
		assert.Equal(t, jobs.Retryable, jf.Class)
		assert.Equal(t, inventory.DeployStatePrecheck, k.inv.dep.State, "the record waits in its pre-check")
		assert.Empty(t, k.inv.finishes)
		assert.Zero(t, k.sshCalls())
		assert.Equal(t, 1, k.az.Count("ReadCertificateSecret"))
		_, err = k.h.deploy(k.ctx, k.job(), k.steps)
		require.NoError(t, err)
		assert.Equal(t, 2, k.az.Count("ReadCertificateSecret"), "the retry reads again: the normal resume")
		assert.Equal(t, inventory.DeployStatusSucceeded, k.inv.lastFinish().Status)
	})

	t.Run("a state that changed under the pre-check is followed", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.errs["KVDeployPrecheck"] = inventory.ErrDeploymentState
		k.inv.hooks["KVDeployPrecheck"] = func(context.Context) {
			k.inv.mu.Lock()
			k.inv.dep.State, k.inv.dep.Status, k.inv.dep.ErrorCode = inventory.DeployStateDone, inventory.DeployStatusFailed, "deployment.cancelled"
			k.inv.mu.Unlock()
		}
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		assert.Equal(t, "deployment.cancelled", failureOf(t, err).Reason)
		assert.Zero(t, len(k.az.Calls()))
	})

	t.Run("a stale run in the pre-check records nothing", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.errs["KVDeployPrecheck"] = inventory.ErrClaimLost
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		assert.Equal(t, "job.lease_expired", failureOf(t, err).Reason)
		assert.Empty(t, k.inv.finishes)
		assert.Zero(t, len(k.az.Calls()))
	})

	t.Run("a context that ends in the pre-check releases the job", func(t *testing.T) {
		k := newKVFixture(t)
		ctx, cancel := context.WithCancel(k.ctx)
		defer cancel()
		k.inv.hooks["KVDeployPrecheck"] = func(context.Context) { cancel() }
		k.inv.errs["KVDeployPrecheck"] = context.Canceled
		_, err := k.h.deploy(ctx, k.job(), k.steps)
		assert.Equal(t, "deployment.interrupted", failureOf(t, err).Reason)
		assert.Zero(t, len(k.az.Calls()))
	})

	t.Run("the material step of the first read refuses the same way", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.errs["DeploymentMaterial(true)"] = inventory.ErrBindingGone
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		assert.Equal(t, "kv.binding_gone", failureOf(t, err).Reason)
		assert.Zero(t, len(k.az.Calls()))
	})
}

// M-1: what the record alone can refuse is refused before the vault is asked for a key, and again
// after the read (the record may have changed meanwhile).
func TestKVRecordOnlyRefusalsComeBeforeTheVault(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(k *kvFixture)
		reason string
	}{
		{"expired by the stored row", func(k *kvFixture) { k.inv.material.NotAfter = k.clock.Now().Add(-time.Minute) }, "certificate.expired"},
		{"not valid yet", func(k *kvFixture) { k.inv.material.NotBefore = k.clock.Now().Add(time.Minute) }, "certificate.not_yet_valid"},
		{"configuration invalid", func(k *kvFixture) { k.inv.material.ConfigValid = false }, "nginx.config_invalid"},
		{"location unsupported", func(k *kvFixture) { k.inv.material.Location.Supported = false }, "nginx.location_unsupported"},
		{"server disabled", func(k *kvFixture) { k.inv.target.Status = inventory.StatusDisabled }, "target.disabled"},
		{"server host key changed", func(k *kvFixture) { k.inv.target.Status = inventory.StatusHostKeyChanged }, "target.host_key_changed"},
		{"server deleted", func(k *kvFixture) { k.inv.errs["TargetRef"] = inventory.ErrNotFound }, "system.not_found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKVFixture(t)
			tc.setup(k)
			_, err := k.h.deploy(k.ctx, k.job(), k.steps)
			assert.Equal(t, tc.reason, failureOf(t, err).Reason)
			assert.Zero(t, len(k.az.Calls()), "the vault was not called")
			assert.NotContains(t, k.inv.calls(), "KVDeployMaterial")
			assert.NotContains(t, k.inv.calls(), "KVDeployPrecheck")
			assert.Nil(t, k.inv.key, "no key was handed out")
			assert.Zero(t, k.sshCalls())
		})
	}
	t.Run("the record changes during the read: refused again after it, key zeroed", func(t *testing.T) {
		k := newKVFixture(t)
		k.tr.onRead = func() { k.inv.material.NotAfter = k.clock.Now().Add(-time.Minute) }
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		assert.Equal(t, "certificate.expired", failureOf(t, err).Reason)
		assert.True(t, k.keyZeroed())
		assert.Zero(t, k.sshCalls())
	})
}

// M-2: a panic in the vault session's Close leaves no secret behind.
func TestKVSecretIsZeroedWhenCloseCrashes(t *testing.T) {
	k := newKVFixture(t)
	k.tr.closePanics = true
	var held []byte
	k.tr.readHook = func(context.Context) (providers.CertificateSecret, error, bool) {
		held = bytes.Clone(k.canary)
		k.inv.kv.secret = held
		return providers.CertificateSecret{ContentType: "application/x-pkcs12", Value: providers.NewSecret(held)}, nil, true
	}
	assert.PanicsWithValue(t, "close crashed", func() { _, _ = k.h.deploy(k.ctx, k.job(), k.steps) })
	assert.True(t, allZero(held), "the value the vault returned is zero after the panic")
	assert.Zero(t, k.sshCalls())
}

// M-3: the key is zero the moment the send returns, before anything else runs: not at the end of the run.
func TestKVKeyIsZeroBeforeTheOutcomeIsRecordedAndBeforeTheRestore(t *testing.T) {
	t.Run("before RecordOutcome", func(t *testing.T) {
		k := newKVFixture(t)
		var zero bool
		k.inv.hooks["RecordOutcome"] = func(context.Context) { zero = k.keyZeroed() }
		_, err := k.h.deploy(k.ctx, k.job(), k.steps)
		require.NoError(t, err)
		assert.True(t, zero, "the key was already zero when the outcome was recorded")
	})
	t.Run("before the restore over SSH", func(t *testing.T) {
		k := newKVFixture(t)
		var zero bool
		k.prov.Configure(func(c *fake.Config) {
			c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
				return providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "restore",
					CauseStep: "verify", Reason: "deployment.rollback_failed"}, nil
			}
			c.Rollback = func(providers.RollbackRequest) (providers.RollbackOutcome, error) {
				zero = k.keyZeroed()
				return providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}, nil
			}
		})
		_, _ = k.h.deploy(k.ctx, k.job(), k.steps)
		assert.Equal(t, 1, k.prov.Count("RollbackDeployment"))
		assert.True(t, zero, "the key was already zero when the restore was sent")
	})
}

// M-4: the material the inventory returns is checked against the record the run started from.
func TestKVMaterialOfAnotherDeploymentIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(m *inventory.Material)
	}{
		{"another fingerprint", func(m *inventory.Material) { m.Fingerprint = strings.Repeat("d", 64) }},
		{"another deployment", func(m *inventory.Material) { m.Deployment.ID = uuid.Must(uuid.NewV7()) }},
		{"another certificate path", func(m *inventory.Material) { m.Location.CertPath = "/etc/nginx/ssl/other.crt" }},
		{"another key path", func(m *inventory.Material) { m.Location.KeyPath = "/etc/nginx/ssl/other.key" }},
		{"another vault version", func(m *inventory.Material) {
			kv := *m.KV
			kv.VersionID = uuid.Must(uuid.NewV7())
			m.KV = &kv
		}},
		{"no vault source", func(m *inventory.Material) { m.KV = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKVFixture(t)
			k.inv.kv.mutate = tc.mutate
			_, err := k.h.deploy(k.ctx, k.job(), k.steps)
			jf := failureOf(t, err)
			assert.Equal(t, jobs.Permanent, jf.Class)
			assert.Equal(t, "internal.unexpected", jf.Reason)
			assert.Zero(t, k.sshCalls())
			assert.True(t, k.keyZeroed(), "the key of the refused material is zeroed")
			assert.Equal(t, stepKVSecret, k.inv.lastFinish().FailedStep)
		})
	}
}

// M-5: a job error's param values are bounded as the deployment record bounds them: valid UTF-8, no
// control characters, at most 256 bytes.
func TestJobParamValuesAreBounded(t *testing.T) {
	long := "x" + strings.Repeat("é", 400) // cuts inside no rune
	in := map[string]string{"role": "Key Vault\nSecrets\x00 User" + long, "port": "44\r3", "model": "ok", "azure_code": string([]byte{0xff, 'A'})}
	out := jobParams(in)
	assert.Equal(t, "ok", out["model"])
	assert.Equal(t, "443", out["port"])
	assert.Equal(t, "A", out["azure_code"], "invalid UTF-8 dropped")
	assert.NotContains(t, out["role"], "\n")
	assert.NotContains(t, out["role"], "\x00")
	assert.LessOrEqual(t, len(out["role"]), 256)
	assert.True(t, utf8.ValidString(out["role"]))
	assert.True(t, strings.HasPrefix(out["role"], "Key VaultSecrets User"))
	assert.Equal(t, 5015, len(strings.Repeat("a", 5000)+"\n"+strings.Repeat("b", 14)))
	assert.Len(t, jobParams(map[string]string{"role": strings.Repeat("a", 5000) + "\n" + strings.Repeat("b", 14)})["role"], 256)
}

// M-7: a step that was started is closed: on a state that changed under the run, and on a panic; a lost
// claim writes nothing.
func TestKVStepIsClosedOnEveryPath(t *testing.T) {
	t.Run("a state that changed", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.errs["KVDeployMaterial"] = inventory.ErrDeploymentState
		k.inv.hooks["KVDeployMaterial"] = func(context.Context) {
			k.inv.mu.Lock()
			k.inv.dep.State, k.inv.dep.Status, k.inv.dep.ErrorCode = inventory.DeployStateDone, inventory.DeployStatusFailed, "x.y"
			k.inv.mu.Unlock()
		}
		_, _ = k.h.deploy(k.ctx, k.job(), k.steps)
		assert.Equal(t, []string{stepKVSecret + ":started", stepKVSecret + ":skipped"}, k.inv.stepNames())
		assert.Equal(t, "state_changed", k.inv.kv.stepParams[stepKVSecret+":skipped"]["reason"])
	})
	t.Run("a panic", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.hooks["KVDeployMaterial"] = func(context.Context) { panic("inventory crashed") }
		assert.Panics(t, func() { _, _ = k.h.deploy(k.ctx, k.job(), k.steps) })
		assert.Equal(t, []string{stepKVSecret + ":started", stepKVSecret + ":failed"}, k.inv.stepNames())
		assert.Equal(t, "internal.unexpected", k.inv.kv.stepParams[stepKVSecret+":failed"]["reason"])
	})
	t.Run("a lost claim writes nothing", func(t *testing.T) {
		k := newKVFixture(t)
		k.inv.errs["KVDeployMaterial"] = inventory.ErrClaimLost
		_, _ = k.h.deploy(k.ctx, k.job(), k.steps)
		assert.Equal(t, []string{stepKVSecret + ":started"}, k.inv.stepNames(), "a stale run writes no closing step")
	})
}

// Completeness: every Err* the inventory's KVDeployPrecheck and KVDeployMaterial name has a decision
// here. The test reads the source of kv_material.go (it cannot edit it), lists the Err identifiers those
// two functions mention, and fails when one is missing from known (a new refusal needs a row in
// kvRefusals, or an explicit entry in special) or when a known refusal has no reason.
func TestEveryInventoryRefusalOfTheVaultStepHasAReason(t *testing.T) {
	known := map[string]error{
		"ErrBindingGone": inventory.ErrBindingGone, "ErrAutoDeployOff": inventory.ErrAutoDeployOff, "ErrVaultUnavailable": inventory.ErrVaultUnavailable,
		"ErrKVCertificateMissing": inventory.ErrKVCertificateMissing, "ErrVersionDisabled": inventory.ErrVersionDisabled, "ErrVersionHeld": inventory.ErrVersionHeld,
		"ErrCertificateExpired": inventory.ErrCertificateExpired, "ErrCertificateNotYetValid": inventory.ErrCertificateNotYetValid,
		"ErrSecretMismatch": inventory.ErrSecretMismatch, "ErrSecretUnreadable": inventory.ErrSecretUnreadable, "ErrChainUnconfirmed": inventory.ErrChainUnconfirmed,
		"ErrNotFound": inventory.ErrNotFound,
		// handled by the engine on purpose, not by a reason of their own
		"ErrPFXBusy": inventory.ErrPFXBusy, "ErrDeploymentState": inventory.ErrDeploymentState, "ErrClaimLost": inventory.ErrClaimLost,
	}
	special := map[string]bool{"ErrPFXBusy": true, "ErrDeploymentState": true, "ErrClaimLost": true}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "../../inventory/kv_material.go", nil, 0)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "KVDeployPrecheck" && fn.Name.Name != "KVDeployMaterial") {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.SelectorExpr); ok {
				return false // certs.ErrExpired and the like are other packages' errors, mapped inside the inventory
			}
			if id, ok := n.(*ast.Ident); ok && strings.HasPrefix(id.Name, "Err") && len(id.Name) > 3 {
				seen[id.Name] = true
			}
			return true
		})
	}
	require.NotEmpty(t, seen, "the two functions were found")
	for name := range seen {
		sentinel, ok := known[name]
		require.True(t, ok, "inventory.%s is returned by the material step: give it a row in kvRefusals and list it here", name)
		if special[name] {
			continue
		}
		reason, ok := kvRefusal(sentinel)
		assert.True(t, ok && reason != "", "inventory.%s has no closed reason", name)
	}
	for name := range known {
		if !special[name] {
			_, ok := kvRefusal(known[name])
			assert.True(t, ok, "%s is listed but has no row", name)
		}
	}
}
