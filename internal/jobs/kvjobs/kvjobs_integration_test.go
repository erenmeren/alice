//go:build integration

package kvjobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/azureid"
	"alice/internal/platform/clock"
	"alice/internal/platform/logging"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/pki"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

const (
	itTenant = "1111aaaa-2222-bbbb-3333-cccc4444dddd"
	itClient = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// holdProvider is the scripted Key Vault provider with a hook in Discover: a test can hold a poll
// in flight, count the polls that run at once, or make one panic.
type holdProvider struct {
	*fake.Provider
	hook atomic.Pointer[func(ctx context.Context, target uuid.UUID)]
}

func (p *holdProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return &holdSession{Session: s, p: p, target: t.ID}, nil
}

type holdSession struct {
	providers.Session
	p      *holdProvider
	target uuid.UUID
}

func (s *holdSession) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	if h := s.p.hook.Load(); h != nil {
		(*h)(ctx, s.target)
	}
	return s.Session.Discover(ctx, req)
}

type world struct {
	t      *testing.T
	ctx    context.Context
	db     *pgtest.DB
	clock  *clock.Fake
	logs   *syncBuffer
	lic    *license.Service
	queue  *jobs.Queue
	inv    *inventory.Service
	reg    *providers.Registry
	az     *holdProvider
	runner *jobs.Runner
	admin  inventory.Actor
	ca     *pki.CA
	secret string // the vault's client secret (never allowed in a log)
}

func newWorld(t *testing.T) *world {
	t.Helper()
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	w := &world{t: t, ctx: context.Background(), db: pgtest.New(t), clock: clock.NewFake(now), logs: &syncBuffer{}, secret: fakekv.NewClientSecret()}
	log := logging.New(w.logs, slog.LevelDebug)
	keyring, err := secrets.LoadOrCreateMasterKey(w.ctx, w.db.App, t.TempDir(), now)
	require.NoError(t, err)
	auditLog := audit.New(w.clock)
	w.lic = license.New(license.Config{Pool: w.db.App, Keyring: keyring, Audit: auditLog, Clock: w.clock, Uptime: w.clock,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), Targets: inventory.Counter{}, Notifier: notify.AdminNotifier{Clock: w.clock}, Log: log})
	require.NoError(t, w.lic.Start(w.ctx))
	w.queue = jobs.NewQueue(jobs.QueueConfig{Pool: w.db.App, Keyring: keyring, Audit: auditLog, Clock: w.clock, Gate: w.lic})
	w.ca = pki.NewCA("KV", pki.ECDSA256, now)
	roots := x509.NewCertPool()
	roots.AddCert(w.ca.Root)
	w.reg = providers.NewRegistry()
	w.reg.Register(fake.New(providers.KindLinuxSSH))
	w.reg.Register(fake.New(providers.KindNginx, providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
		providers.CapDiscoverCerts, providers.CapDeployCertificate, providers.CapVerifyDeployment))
	w.az = &holdProvider{Provider: fake.New(providers.KindAzureKV, providers.CapTestConnection, providers.CapDiscoverCerts,
		providers.CapReadCertificateSecret, providers.CapImportCertificate)}
	w.az.Configure(func(c *fake.Config) {
		c.Report = providers.ConnectionReport{Azure: &providers.AzureFacts{ObjectID: "99999999-8888-7777-6666-555555555555", TenantID: itTenant,
			PermissionModel: "rbac", Checks: okChecks(), CheckedAt: now}}
	})
	w.reg.Register(w.az)
	w.reg.Freeze()
	w.inv = inventory.New(inventory.Config{Pool: w.db.App, Keyring: keyring, Audit: auditLog, Clock: w.clock, License: w.lic, Registry: w.reg,
		Jobs: w.queue, Notifier: notify.AdminNotifier{Clock: w.clock}, Log: log, Roots: roots})
	_, err = w.inv.EnsurePlatformKey(w.ctx)
	require.NoError(t, err)
	w.runner = w.newRunner("alice")
	id := uuid.Must(uuid.NewV7())
	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'ada', 'ada@example.com', 'Ada Yılmaz', 'x', 'admin', $2, $2)`, id, now)
	require.NoError(t, err)
	w.admin = inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: "ada"}, UserID: id, Role: rbac.Admin}
	return w
}

func (w *world) newRunner(worker string) *jobs.Runner {
	r := jobs.NewRunner(jobs.RunnerConfig{Pool: w.db.App, Queue: w.queue, Gate: w.lic, Audit: audit.New(w.clock), Clock: w.clock,
		Log: logging.New(w.logs, slog.LevelDebug), Workers: 1, WorkerID: worker, Jitter: func() float64 { return 0 },
		Notifier: notify.AdminNotifier{Clock: w.clock}})
	Register(r, Deps{Inventory: w.inv, Registry: w.reg, Clock: w.clock, Log: logging.New(w.logs, slog.LevelDebug)})
	return r
}

func (w *world) evaluate() {
	w.t.Helper()
	require.NoError(w.t, w.lic.Tick(w.ctx))
}

// drain runs the license evaluation, then due jobs until none is left.
func (w *world) drain() {
	w.t.Helper()
	w.evaluate()
	for range 50 {
		ran, err := w.runner.RunOnce(w.ctx)
		require.NoError(w.t, err)
		if !ran {
			return
		}
	}
	w.t.Fatal("jobs did not drain")
}

func (w *world) addVault(name string) uuid.UUID {
	w.t.Helper()
	w.evaluate()
	v, _, _, err := w.inv.CreateVault(w.ctx, w.admin, inventory.NewVault{Name: name, VaultURL: "https://" + name + ".vault.azure.net",
		Auth: providers.AzureAuthClientSecret, TenantID: itTenant, ClientID: itClient, ClientSecret: secrets.NewPlaintext([]byte(w.secret))})
	require.NoError(w.t, err)
	return v.ID
}

func ver(n int) string { return fmt.Sprintf("%032x", n) }

// listed is a vault certificate as a provider reads it: the listing plus the details of its current
// version (created at the time named).
func listed(name string, l pki.Leaf, version string, created time.Time, older ...string) providers.KVCertificate {
	th := azureid.ThumbprintOf(l.Cert.Raw)
	nb, exp := l.Cert.NotBefore.UTC(), l.Cert.NotAfter.UTC()
	yes := true
	c := providers.KVCertificate{Name: name, Thumbprint: th, Enabled: true, NotBefore: &nb, Expires: &exp, Created: &created, Updated: &created,
		Details: &providers.KVCertificateDetails{Version: version, Thumbprint: th, Updated: &created, CER: l.Cert.Raw, Exportable: &yes, KeyType: "ecdsa",
			KeySize: 256, ContentType: "pkcs12", IssuerName: "Unknown", AutoRenew: true},
		Versions: []providers.KVCertificateVersion{{Version: version, Thumbprint: th, Enabled: true, NotBefore: &nb, Expires: &exp, Created: &created}}}
	for i, v := range older {
		old := created.Add(-time.Duration(i+1) * time.Hour)
		c.Versions = append(c.Versions, providers.KVCertificateVersion{Version: v, Thumbprint: fmt.Sprintf("%040x", i+1), Enabled: true,
			NotBefore: &nb, Expires: &exp, Created: &old})
	}
	return c
}

// vaultSays scripts what the vault answers to the next polls.
func (w *world) vaultSays(certs ...providers.KVCertificate) {
	w.az.Configure(func(c *fake.Config) {
		c.DiscoverErr = nil
		c.Discovery = providers.DiscoveryResult{KV: &providers.KVInventory{Certificates: certs, KeysListed: true, SecretsListed: true}}
	})
}

func (w *world) poll(vault uuid.UUID) jobs.View {
	w.t.Helper()
	_, err := w.inv.RequestDiscovery(w.ctx, w.admin, vault)
	require.NoError(w.t, err)
	w.drain()
	return w.lastJob(jobs.KVPoll.Name)
}

func (w *world) lastJob(typ string) jobs.View {
	w.t.Helper()
	var id uuid.UUID
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT id FROM jobs WHERE type = $1 ORDER BY created_at DESC, id DESC LIMIT 1", typ).Scan(&id))
	v, err := w.queue.Get(w.ctx, id)
	require.NoError(w.t, err)
	return v
}

func (w *world) count(sql string, args ...any) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, sql, args...).Scan(&n))
	return n
}

func (w *world) audits(action string) int {
	return w.count("SELECT count(*) FROM audit_log WHERE action = $1", action)
}

func (w *world) status(vault uuid.UUID) (status, code string) {
	w.t.Helper()
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT status, last_error_code FROM targets WHERE id = $1", vault).Scan(&status, &code))
	return
}

type versionRow struct {
	Held       bool
	HeldReason string
	Thumbprint string
}

func (w *world) versions(vault uuid.UUID, name string) map[string]versionRow {
	w.t.Helper()
	rows, err := w.db.Owner.Query(w.ctx, `SELECT v.version, v.held, v.held_reason, v.thumbprint FROM kv_certificate_versions v
JOIN kv_certificates c ON c.id = v.kv_certificate_id WHERE c.target_id = $1 AND c.name = $2`, vault, name)
	require.NoError(w.t, err)
	defer rows.Close()
	out := map[string]versionRow{}
	for rows.Next() {
		var v string
		var r versionRow
		require.NoError(w.t, rows.Scan(&v, &r.Held, &r.HeldReason, &r.Thumbprint))
		out[v] = r
	}
	require.NoError(w.t, rows.Err())
	return out
}

func (w *world) certID(vault uuid.UUID, name string) uuid.UUID {
	w.t.Helper()
	var id uuid.UUID
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT id FROM kv_certificates WHERE target_id = $1 AND name = $2", vault, name).Scan(&id))
	return id
}

func (w *world) noLeaks() {
	w.t.Helper()
	logs := w.logs.String()
	assert.NotContains(w.t, logs, w.secret, "the vault's client secret never reaches a log")
	assert.NotContains(w.t, logs, canary)
	for _, table := range []string{"jobs", "audit_log", "targets"} {
		assert.Zero(w.t, w.count(fmt.Sprintf("SELECT count(*) FROM %s t WHERE t::text LIKE $1", table), "%"+w.secret+"%"), table)
	}
}

func TestPollJobEndToEnd(t *testing.T) {
	w := newWorld(t)
	vault := w.addVault("prod")
	l1 := w.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, w.clock.Now())
	w.vaultSays(listed("web-cert", l1, ver(1), w.clock.Now()))
	w.drain() // the poll queued when the vault was added
	first := w.lastJob(jobs.KVPoll.Name)
	assert.Equal(t, jobs.StatusSucceeded, first.Status)
	assert.Equal(t, float64(1), first.Result["certificates"])
	assert.Equal(t, inventory.StatusOK, first.Result["status"])
	require.Contains(t, w.versions(vault, "web-cert"), ver(1))
	assert.Equal(t, 1, w.az.Count("Discover"))

	// A renewal: the next poll records a new version, audited once.
	w.clock.Advance(20 * time.Minute)
	l2 := w.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, w.clock.Now())
	w.vaultSays(listed("web-cert", l2, ver(2), w.clock.Now(), ver(1)))
	job := w.poll(vault)
	assert.Equal(t, jobs.StatusSucceeded, job.Status)
	assert.Equal(t, float64(1), job.Result["new_versions"])
	assert.Contains(t, w.versions(vault, "web-cert"), ver(2))
	assert.Equal(t, 1, w.audits("kv.certificate.new_version"))
	calls := w.az.Calls()
	var last fake.Call
	for _, c := range calls {
		if c.Method == "Discover" {
			last = c
		}
	}
	assert.Contains(t, last.Discover.KVKnown, "web-cert", "inventory's known set is what the provider is asked with")

	// The certificate listing is refused (the role is gone): the vault is degraded, the other lists are still stored
	// (the keys and secrets are read again when the last read is four intervals old).
	w.clock.Advance(61 * time.Minute)
	now := w.clock.Now()
	w.az.Configure(func(c *fake.Config) {
		c.Discovery = providers.DiscoveryResult{KV: &providers.KVInventory{KeysListed: true, SecretsListed: true,
			Keys: []providers.KVKey{{Name: "signing", Enabled: true, Created: &now, Updated: &now, Details: &providers.KVKeyDetails{Version: ver(9), KeyType: "rsa", Size: 2048}}},
			Failures: []providers.KVListFailure{{Object: "certificates", Err: providers.NewError("azure.forbidden", false, nil,
				map[string]string{"role": providers.RoleKeyVaultReader})}}}}
	})
	job = w.poll(vault)
	assert.Equal(t, jobs.StatusSucceeded, job.Status, "the poll ran: a refused list is the vault's status, not a job failure")
	st, code := w.status(vault)
	assert.Equal(t, inventory.StatusDegraded, st)
	assert.Equal(t, "azure.forbidden", code)
	assert.Equal(t, 1, w.count("SELECT count(*) FROM kv_keys WHERE target_id = $1", vault), "the keys were still stored")
	assert.Contains(t, w.versions(vault, "web-cert"), ver(2), "the certificates are untouched")

	// The whole vault fails: the sign-in is refused. The job fails with the closed code, no dead-job email, the vault says why.
	w.clock.Advance(20 * time.Minute)
	w.az.Configure(func(c *fake.Config) {
		c.DiscoverErr = providers.NewError("azure.auth_failed", false, errors.New(canary), nil)
	})
	job = w.poll(vault)
	assert.Equal(t, jobs.StatusFailed, job.Status)
	assert.Equal(t, "azure.auth_failed", job.LastErrorCode)
	st, code = w.status(vault)
	assert.Equal(t, inventory.StatusAuthFailed, st)
	assert.Equal(t, "azure.auth_failed", code)

	// Unreachable on its one attempt: the job is failed, never dead (no job.dead email: the vault carries it).
	w.clock.Advance(20 * time.Minute)
	w.az.Configure(func(c *fake.Config) {
		c.DiscoverErr = providers.NewError("azure.unreachable", true, errors.New(canary), nil)
	})
	job = w.poll(vault)
	assert.Equal(t, jobs.StatusFailed, job.Status)
	assert.Equal(t, "azure.unreachable", job.LastErrorCode)
	assert.Zero(t, w.audits("job.dead"), "a failed poll does not alert by itself")
	assert.Zero(t, w.count("SELECT count(*) FROM notifications_outbox WHERE template_key LIKE 'job.dead%'"))
	st, _ = w.status(vault)
	assert.Equal(t, inventory.StatusUnreachable, st)
	w.noLeaks()
}

func TestTestConnectionJobEndToEnd(t *testing.T) {
	w := newWorld(t)
	vault := w.addVault("prod")
	l1 := w.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, w.clock.Now())
	w.vaultSays(listed("web-cert", l1, ver(1), w.clock.Now()))
	w.drain()
	cert := w.certID(vault, "web-cert")

	// A plain check.
	_, err := w.inv.RequestAccessCheck(w.ctx, w.admin, vault, uuid.Nil)
	require.NoError(t, err)
	w.drain()
	job := w.lastJob(jobs.KVTestConnection.Name)
	assert.Equal(t, jobs.StatusSucceeded, job.Status)
	assert.Equal(t, "rbac", job.Result["permission_model"])
	assert.Zero(t, w.az.Count("ReadCertificateSecret"))
	accessReads := func() int {
		return w.count("SELECT count(*) FROM audit_log WHERE action = 'kv.secret_read' AND details->>'purpose' = 'access_check'")
	}
	assert.Zero(t, accessReads(), "a plain check reads no secret and audits none")

	// With a secret read: proves the Secrets User role; the value is never stored.
	secret := []byte("pretend-pem-with-the-private-key")
	w.az.Configure(func(c *fake.Config) {
		c.Secret = providers.CertificateSecret{ContentType: "application/x-pem-file", Value: providers.NewSecret(secret)}
	})
	_, err = w.inv.RequestAccessCheck(w.ctx, w.admin, vault, cert)
	require.NoError(t, err)
	w.drain()
	job = w.lastJob(jobs.KVTestConnection.Name)
	assert.Equal(t, jobs.StatusSucceeded, job.Status)
	var facts string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT facts::text FROM targets WHERE id = $1", vault).Scan(&facts))
	assert.Contains(t, facts, `"name": "read_secret", "result": "ok"`)
	assert.Equal(t, 1, w.az.Count("ReadCertificateSecret"))
	assert.Equal(t, 1, accessReads(), "one kv.secret_read row per read")
	var detail map[string]string
	var result string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT details, result FROM audit_log WHERE action = 'kv.secret_read' AND details->>'purpose' = 'access_check'").Scan(&detail, &result))
	assert.Equal(t, "web-cert", detail["certificate_name"])
	assert.Equal(t, ver(1), detail["version"])
	assert.Equal(t, "success", result)
	assert.NotContains(t, fmt.Sprint(detail), string(secret), "the value is never audited")
	reads := w.az.Calls()
	for _, c := range reads {
		if c.Method == "ReadCertificateSecret" {
			assert.Equal(t, providers.SecretRequest{Name: "web-cert", Version: ver(1)}, c.Secret)
		}
	}

	// The role is missing: the check ran, the row is forbidden with the role, the vault is degraded.
	w.clock.Advance(time.Minute)
	w.az.Configure(func(c *fake.Config) {
		c.SecretErr = providers.NewError("azure.forbidden", false, errors.New(canary), map[string]string{"role": providers.RoleKeyVaultSecretsUser})
	})
	_, err = w.inv.RequestAccessCheck(w.ctx, w.admin, vault, cert)
	require.NoError(t, err)
	w.drain()
	job = w.lastJob(jobs.KVTestConnection.Name)
	assert.Equal(t, jobs.StatusSucceeded, job.Status, "the check ran")
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT facts::text FROM targets WHERE id = $1", vault).Scan(&facts))
	assert.Contains(t, facts, `"role": "Key Vault Secrets User"`)
	assert.Equal(t, 2, accessReads(), "a refused read is audited too")
	assert.Equal(t, 1, w.count("SELECT count(*) FROM audit_log WHERE action = 'kv.secret_read' AND details->>'purpose' = 'access_check' AND result = 'failure' AND details->>'reason' = 'azure.forbidden'"))
	st, code := w.status(vault)
	assert.Equal(t, inventory.StatusDegraded, st)
	assert.Equal(t, "azure.forbidden", code)

	// The vault is deleted while the check waits in the queue: it fails with not_found and records nothing.
	w.az.Configure(func(c *fake.Config) { c.SecretErr = nil })
	_, err = w.inv.RequestAccessCheck(w.ctx, w.admin, vault, uuid.Nil)
	require.NoError(t, err)
	require.NoError(t, w.inv.DeleteVault(w.ctx, w.admin, vault, false))
	before := w.az.Count("Open")
	w.drain()
	job = w.lastJob(jobs.KVTestConnection.Name)
	assert.Equal(t, jobs.StatusFailed, job.Status)
	assert.Equal(t, "system.not_found", job.LastErrorCode)
	assert.Equal(t, before, w.az.Count("Open"), "nothing was opened")
	w.noLeaks()
}

// uploadWithKey uploads a leaf with its key and returns its certificate id.
func (w *world) uploadWithKey(cn string) (inventory.Certificate, pki.Leaf) {
	w.t.Helper()
	l := w.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, w.clock.Now())
	c, _, err := w.inv.UploadCertificate(w.ctx, w.admin, inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(l.KeyPEM)})
	require.NoError(w.t, err)
	return c, l
}

func (w *world) importState(id uuid.UUID) (state, code string) {
	w.t.Helper()
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT state, error_code FROM kv_imports WHERE id = $1", id).Scan(&state, &code))
	return
}

// The vault has no idempotency key: an import whose answer was lost, whose job was retried after the
// mark, or whose job was delivered again, is sent exactly once. The next poll that lists the version
// created after the request settles it (the wire version, with the real provider against the fake
// Azure service and Fault{Reset: true, Apply: true}, needs the tagged dial seam of Task 19: Task 18).
func TestImportJobNeverResends(t *testing.T) {
	w := newWorld(t)
	vault := w.addVault("prod")
	w.vaultSays()
	w.drain()
	cert, leaf := w.uploadWithKey("new.example.test")
	var sends atomic.Int32
	var created atomic.Pointer[pki.Leaf]
	w.az.Configure(func(c *fake.Config) {
		c.Import = func(req providers.ImportRequest) (providers.ImportResult, error) {
			sends.Add(1)
			// The vault carried the request out, then the answer was lost (a 503 with Apply, or a reset).
			created.Store(&leaf)
			return providers.ImportResult{Outcome: providers.ImportUncertain}, providers.NewError("azure.unreachable", true, context.DeadlineExceeded, nil)
		}
	})
	im, err := w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
	require.NoError(t, err)
	w.drain()
	job := w.lastJob(jobs.KVImport.Name)
	assert.Equal(t, jobs.StatusFailed, job.Status)
	assert.Equal(t, "azure.unreachable", job.LastErrorCode)
	assert.Equal(t, "uncertain", job.ErrorParams["state"])
	state, _ := w.importState(im.ID)
	assert.Equal(t, inventory.ImportUncertain, state)
	assert.Equal(t, int32(1), sends.Load(), "exactly one import request")
	assert.Equal(t, 1, w.az.Count("ImportCertificate"))

	// The same job delivered again (a lost lease, a requeue after a crash): nothing is sent.
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE jobs SET status = 'queued', finished_at = NULL, locked_by = NULL, locked_until = NULL, run_at = $2 WHERE id = $1",
		job.ID, w.clock.Now())
	require.NoError(t, err)
	w.drain()
	again, err := w.queue.Get(w.ctx, job.ID)
	require.NoError(t, err)
	assert.Equal(t, jobs.StatusSucceeded, again.Status, "the record is read back")
	assert.Equal(t, inventory.ImportUncertain, again.Result["state"])
	assert.Equal(t, int32(1), sends.Load(), "still exactly one request")
	assert.Equal(t, 1, w.az.Count("ImportCertificate"))

	// The next poll sees a version created after the request with the import's thumbprint: imported.
	w.clock.Advance(20 * time.Minute)
	w.vaultSays(listed("new-cert", *created.Load(), ver(1), w.clock.Now()))
	w.poll(vault)
	state, _ = w.importState(im.ID)
	assert.Equal(t, inventory.ImportSucceeded, state, "settled by the poll, not by a second send")
	assert.Equal(t, int32(1), sends.Load())
	w.noLeaks()
}

// A crash, or a panic, after MarkImportSent committed: the runner retries the job (attempt 2 of 3),
// which finds the import running and must not send.
func TestImportJobRetriedAfterTheMarkNeverResends(t *testing.T) {
	w := newWorld(t)
	vault := w.addVault("prod")
	w.vaultSays()
	w.drain()
	cert, _ := w.uploadWithKey("new.example.test")
	var sends atomic.Int32
	w.az.Configure(func(c *fake.Config) {
		c.Import = func(providers.ImportRequest) (providers.ImportResult, error) {
			sends.Add(1)
			panic(canary + " the process died in the middle of the send")
		}
	})
	im, err := w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
	require.NoError(t, err)
	w.drain()
	job := w.lastJob(jobs.KVImport.Name)
	assert.Equal(t, jobs.StatusQueued, job.Status, "the panic is a retryable failure: attempt 2 is queued")
	state, _ := w.importState(im.ID)
	assert.Equal(t, inventory.ImportRunning, state, "the mark committed before the send")
	w.clock.Advance(time.Hour)
	w.drain()
	job = w.lastJob(jobs.KVImport.Name)
	assert.Equal(t, jobs.StatusFailed, job.Status)
	assert.Equal(t, "azure.unexpected_response", job.LastErrorCode)
	assert.Equal(t, "uncertain", job.ErrorParams["state"])
	state, _ = w.importState(im.ID)
	assert.Equal(t, inventory.ImportUncertain, state)
	assert.Equal(t, int32(1), sends.Load(), "the retry sent nothing")
	assert.NotContains(t, w.logs.String(), canary, "a panic value is never logged")
	w.noLeaks()
}

func TestImportJobOutcomes(t *testing.T) {
	t.Run("created: version one, then a poll lists it once", func(t *testing.T) {
		w := newWorld(t)
		vault := w.addVault("prod")
		w.vaultSays()
		w.drain()
		cert, leaf := w.uploadWithKey("new.example.test")
		im, err := w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
		require.NoError(t, err)
		w.drain()
		job := w.lastJob(jobs.KVImport.Name)
		assert.Equal(t, jobs.StatusSucceeded, job.Status)
		assert.Equal(t, inventory.ImportSucceeded, job.Result["state"])
		state, _ := w.importState(im.ID)
		assert.Equal(t, inventory.ImportSucceeded, state)
		assert.Len(t, w.versions(vault, "new-cert"), 1)
		assert.Equal(t, 1, w.az.Count("ImportCertificate"))
		for _, c := range w.az.Calls() {
			if c.Method == "ImportCertificate" {
				assert.Equal(t, "new-cert", c.Import.Name)
				assert.Equal(t, azureid.ThumbprintOf(leaf.Cert.Raw), c.Import.LeafThumbprint)
				assert.False(t, c.Import.ReplaceExisting)
			}
		}
		w.noLeaks()
	})
	t.Run("refused for a missing role: nothing is created", func(t *testing.T) {
		w := newWorld(t)
		vault := w.addVault("prod")
		w.vaultSays()
		w.drain()
		cert, _ := w.uploadWithKey("new.example.test")
		w.az.Configure(func(c *fake.Config) {
			c.Import = func(providers.ImportRequest) (providers.ImportResult, error) {
				return providers.ImportResult{Outcome: providers.ImportRefused}, providers.NewError("azure.forbidden", false, errors.New(canary),
					map[string]string{"role": providers.RoleKeyVaultCertificatesOfficer})
			}
		})
		im, err := w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
		require.NoError(t, err)
		w.drain()
		job := w.lastJob(jobs.KVImport.Name)
		assert.Equal(t, jobs.StatusFailed, job.Status)
		assert.Equal(t, "azure.forbidden", job.LastErrorCode)
		assert.Equal(t, providers.RoleKeyVaultCertificatesOfficer, job.ErrorParams["role"])
		state, code := w.importState(im.ID)
		assert.Equal(t, inventory.ImportFailed, state)
		assert.Equal(t, "azure.forbidden", code)
		assert.Empty(t, w.versions(vault, "new-cert"), "nothing was created")
		w.noLeaks()
	})
	t.Run("the vault is unreachable before anything is sent: three attempts, then failed with a way to retry", func(t *testing.T) {
		w := newWorld(t)
		vault := w.addVault("prod")
		w.vaultSays()
		w.drain()
		cert, _ := w.uploadWithKey("new.example.test")
		w.az.Configure(func(c *fake.Config) {
			c.OpenErr = providers.NewError("azure.unreachable", true, context.DeadlineExceeded, nil)
		})
		im, err := w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
		require.NoError(t, err)
		for range 3 {
			w.drain()
			w.clock.Advance(time.Hour)
		}
		job := w.lastJob(jobs.KVImport.Name)
		assert.Equal(t, jobs.StatusFailed, job.Status)
		assert.Equal(t, "azure.unreachable", job.LastErrorCode)
		state, code := w.importState(im.ID)
		assert.Equal(t, inventory.ImportFailed, state)
		assert.Equal(t, "azure.unreachable", code)
		got, err := w.inv.Import(w.ctx, vault, im.ID)
		require.NoError(t, err)
		assert.True(t, got.CanRetry, "nothing reached the vault: a new request is safe")
		assert.Zero(t, w.az.Count("ImportCertificate"))
		assert.Zero(t, w.audits("job.dead"), "the import's own mail is the alert")
	})
	t.Run("the vault is deleted while the import waits", func(t *testing.T) {
		w := newWorld(t)
		vault := w.addVault("prod")
		w.vaultSays()
		w.drain()
		cert, _ := w.uploadWithKey("new.example.test")
		im, err := w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
		require.NoError(t, err)
		require.NoError(t, w.inv.DeleteVault(w.ctx, w.admin, vault, false))
		opens := w.az.Count("Open")
		w.drain()
		// Deleting the vault ended its queued import itself (kv.import_vault_deleted): the job reads the
		// record back, sends nothing and fails with the record's code (never "succeeded" for a failed import),
		// for good: no retry, no dead-job mail.
		job := w.lastJob(jobs.KVImport.Name)
		assert.Equal(t, jobs.StatusFailed, job.Status)
		assert.Equal(t, inventory.ReasonImportVaultDeleted, job.LastErrorCode)
		assert.Zero(t, w.audits("job.dead"))
		state, code := w.importState(im.ID)
		assert.Equal(t, inventory.ImportFailed, state, "a queued import of a vanished vault must not block its name for ever")
		assert.Equal(t, inventory.ReasonImportVaultDeleted, code)
		assert.Zero(t, w.az.Count("ImportCertificate"))
		assert.Equal(t, opens, w.az.Count("Open"), "no session was opened for it")
	})
}

// L-87: the license locks while a poll is in flight. The poll finishes and stores its result, the new
// version is HELD (ruling S8: it never deploys by itself, not even after the license returns), no
// deployment is planned, and the periodic planner and scheduler are refused by the gate.
func TestL87PollInFlightAtLock(t *testing.T) {
	w := newWorld(t)
	vault := w.addVault("prod")
	l1 := w.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, w.clock.Now())
	w.vaultSays(listed("web-cert", l1, ver(1), w.clock.Now()))
	w.drain()
	require.Contains(t, w.versions(vault, "web-cert"), ver(1))

	// A website bound to the certificate with automatic deployment on.
	srv := w.nginxServer("web-01", l1)
	b, err := w.inv.CreateBinding(w.ctx, w.admin, inventory.BindingInput{KVCertificateID: w.certID(vault, "web-cert"), LocationIDs: []uuid.UUID{srv}})
	require.NoError(t, err)
	_, err = w.inv.SetAutoDeploy(w.ctx, w.admin, b.ID, b.Version, true)
	require.NoError(t, err)

	// A renewal is pending in Azure; the poll is held in flight.
	w.clock.Advance(20 * time.Minute)
	w.evaluate()
	l2 := w.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, w.clock.Now())
	w.vaultSays(listed("web-cert", l2, ver(2), w.clock.Now(), ver(1)))
	started, release := make(chan struct{}), make(chan struct{})
	hook := func(context.Context, uuid.UUID) { close(started); <-release }
	w.az.hook.Store(&hook)
	_, err = w.inv.RequestDiscovery(w.ctx, w.admin, vault)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, e := w.runner.RunOnce(w.ctx); done <- e }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the poll did not start")
	}

	// The license locks while the request is in flight.
	w.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, w.lic.Tick(w.ctx))
	require.ErrorIs(t, w.lic.Allow(license.ClassChange), license.ErrLocked)
	require.ErrorIs(t, w.lic.Allow(license.ClassReadOnly), license.ErrLocked)
	close(release)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the poll did not finish")
	}
	job := w.lastJob(jobs.KVPoll.Name)
	assert.Equal(t, jobs.StatusSucceeded, job.Status, "an in-flight read-only job finishes and stores its result")
	vs := w.versions(vault, "web-cert")
	require.Contains(t, vs, ver(2), "the in-flight poll stored what it read")
	assert.True(t, vs[ver(2)].Held, "a version detected in lock is held for an Administrator")
	assert.Equal(t, "license", vs[ver(2)].HeldReason)
	assert.False(t, vs[ver(1)].Held)
	assert.Zero(t, w.count("SELECT count(*) FROM deployments"), "no deployment was planned")
	assert.Zero(t, w.count("SELECT count(*) FROM jobs WHERE type = 'certificate.deploy'"))

	// The planner is refused by the gate in lock (its periodic task), and called directly it plans nothing.
	var planned atomic.Int32
	plan := &countingPlanner{n: &planned, inv: w.inv}
	sched := jobs.NewScheduler(w.clock, w.lic, logging.New(w.logs, slog.LevelDebug), AutoDeployTask(plan, time.Minute, nil),
		ScheduleTask(w.inv, time.Minute, nil))
	assert.ErrorIs(t, sched.RunNow(w.ctx, jobs.KVAutoDeploy.Name), license.ErrLocked)
	assert.ErrorIs(t, sched.RunNow(w.ctx, jobs.KVSchedule.Name), license.ErrLocked)
	assert.Zero(t, planned.Load(), "the planner never ran")
	n, err := w.inv.PlanKVAutoDeploy(w.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Zero(t, w.count("SELECT count(*) FROM deployments"))

	// A poll queued in lock does not run: read-only work waits for the license, it is never carried out in lock.
	discovers := w.az.Count("Discover")
	_, err = w.inv.RequestDiscovery(w.ctx, w.admin, vault)
	require.NoError(t, err)
	ran, err := w.runner.RunOnce(w.ctx)
	require.NoError(t, err)
	assert.False(t, ran, "the runner claims nothing in lock")
	assert.Equal(t, discovers, w.az.Count("Discover"), "no request reached the vault")

	// The license returns: the held version is still not deployed automatically (R40 row 21).
	w.clock.Advance(time.Minute)
	p := licensetest.Payload(w.lic.Snapshot().InstallationID, w.clock.Now(), w.clock.Now().Add(365*24*time.Hour), 5)
	_, err = w.lic.Install(w.ctx, licensetest.Sign(p), audit.SystemActor("test"), uuid.Nil)
	require.NoError(t, err)
	require.NoError(t, w.lic.Allow(license.ClassChange), "the gate is open again")
	w.clock.Advance(time.Minute)
	n, err = w.inv.PlanKVAutoDeploy(w.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "a held version is released only by an Administrator")
	assert.Zero(t, w.count("SELECT count(*) FROM deployments"))
	assert.True(t, w.versions(vault, "web-cert")[ver(2)].Held)
	assert.NoError(t, sched.RunNow(w.ctx, jobs.KVAutoDeploy.Name), "the planner ticks again with the license")
	assert.Equal(t, int32(1), planned.Load())
	w.noLeaks()
}

type countingPlanner struct {
	n   *atomic.Int32
	inv *inventory.Service
}

func (c *countingPlanner) PlanKVAutoDeploy(ctx context.Context) (int, error) {
	c.n.Add(1)
	return c.inv.PlanKVAutoDeploy(ctx)
}

// nginxServer seeds a server serving old on one website and returns its location's id.
func (w *world) nginxServer(name string, old pki.Leaf) uuid.UUID {
	w.t.Helper()
	tg, _, err := w.inv.CreateTarget(w.ctx, w.admin, inventory.NewTarget{Name: name, Type: "linux", Host: name + ".example.com"})
	require.NoError(w.t, err)
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE targets SET type = 'nginx', status = 'ok' WHERE id = $1", tg.ID)
	require.NoError(w.t, err)
	sum := sha256.Sum256(old.FullchainPEM)
	loc := providers.CertLocation{CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key", ResolvedCertPath: "/etc/nginx/ssl/www.crt",
		Supported: true, KeyExists: true, KeyMode: "0600", KeyOwner: "root", KeyGroup: "root",
		Servers: []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Port: 443}}, File: "/etc/nginx/sites-enabled/default", Line: 1}}}
	_, err = w.inv.Reconcile(w.ctx, tg.ID, providers.DiscoveryResult{Nginx: &providers.NginxFacts{Found: true, ConfigValid: true, Version: "1.22.1"},
		Certificates: []providers.DiscoveredCertificate{{Location: loc, PEMChain: old.FullchainPEM, FileSHA256: hex.EncodeToString(sum[:])}}})
	require.NoError(w.t, err)
	page, err := w.inv.ListLocations(w.ctx, tg.ID, false)
	require.NoError(w.t, err)
	require.Len(w.t, page.Items, 1)
	return page.Items[0].ID
}

// S12: at most two vault polls run at a time; the others wait for a slot.
func TestAtMostTwoPollsRunAtOnce(t *testing.T) {
	w := newWorld(t)
	var vaults []uuid.UUID
	for _, n := range []string{"one", "two", "three"} {
		vaults = append(vaults, w.addVault(n))
	}
	w.vaultSays()
	var running, peak atomic.Int32
	release := make(chan struct{})
	hook := func(ctx context.Context, _ uuid.UUID) {
		cur := running.Add(1)
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		running.Add(-1)
	}
	w.az.hook.Store(&hook)
	runners := []*jobs.Runner{w.newRunner("a"), w.newRunner("b"), w.newRunner("c")}
	var wg sync.WaitGroup
	for _, r := range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.RunOnce(w.ctx)
			assert.NoError(t, err)
		}()
	}
	require.Eventually(t, func() bool { return running.Load() == 2 }, 10*time.Second, 5*time.Millisecond, "two polls are in flight")
	time.Sleep(300 * time.Millisecond) // the third stays queued: the runner does not claim it
	assert.Equal(t, int32(2), running.Load(), "the third poll waits in the queue")
	close(release)
	wg.Wait()
	ran, err := runners[0].RunOnce(w.ctx) // a slot is free: the third poll runs
	require.NoError(t, err)
	assert.True(t, ran)
	assert.Equal(t, int32(2), peak.Load(), "never more than two at once")
	for _, v := range vaults {
		assert.Equal(t, 1, w.count("SELECT count(*) FROM jobs WHERE type = 'kv.poll' AND target_id = $1 AND status = 'succeeded'", v))
	}
	w.noLeaks()
}

// A poll queued before the lock does not run in lock, and a vault that was disabled meanwhile is
// dropped without a mark on it.
func TestPollsStopInLockAndDropDisabledVaults(t *testing.T) {
	w := newWorld(t)
	vault := w.addVault("prod")
	w.vaultSays()
	// Disabled before the first poll runs: the job fails cleanly and the vault carries no failure.
	_, err := w.db.Owner.Exec(w.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", vault)
	require.NoError(t, err)
	w.drain()
	job := w.lastJob(jobs.KVPoll.Name)
	assert.Equal(t, jobs.StatusFailed, job.Status)
	assert.Equal(t, "target.disabled", job.LastErrorCode)
	assert.Zero(t, w.az.Count("Discover"))
	st, code := w.status(vault)
	assert.Equal(t, inventory.StatusDisabled, st)
	assert.Empty(t, code)
	assert.Zero(t, w.count("SELECT poll_failures FROM targets WHERE id = $1", vault), "no failure is recorded against a disabled vault")
}

// I3: a poll beyond the two that may run does not occupy a worker. With 11 due vaults and 8 workers, two
// polls run and every other worker is free to claim other work (a deployment, an import, an access check);
// the polls that wait stay queued with their attempt unspent, and a freed slot starts the next one.
func TestPollsBeyondTwoDoNotOccupyWorkers(t *testing.T) {
	w := newWorld(t)
	p := licensetest.Payload(w.lic.Snapshot().InstallationID, w.clock.Now(), w.clock.Now().Add(365*24*time.Hour), 50)
	_, err := w.lic.Install(w.ctx, licensetest.Sign(p), audit.SystemActor("test"), uuid.Nil)
	require.NoError(t, err)
	// More than maxCandidates (10) polls are queued AHEAD of the job of another type: the claim query itself
	// must skip the capped polls, or one claim would give up after ten of them and return nothing.
	for i := range 13 {
		w.addVault(fmt.Sprintf("vault-%d", i))
	}
	extra := w.addVault("other")
	w.vaultSays()
	var running, started atomic.Int32
	one, all := make(chan struct{}), make(chan struct{})
	hook := func(ctx context.Context, _ uuid.UUID) {
		running.Add(1)
		started.Add(1)
		select {
		case <-one:
		case <-all:
		case <-ctx.Done():
		}
		running.Add(-1)
	}
	w.az.hook.Store(&hook)
	results := make(chan bool, 16)
	work := func(r *jobs.Runner) {
		ran, err := r.RunOnce(w.ctx)
		assert.NoError(t, err)
		results <- ran
	}
	for i := range 8 {
		go work(w.newRunner(fmt.Sprintf("w%d", i)))
	}
	require.Eventually(t, func() bool { return running.Load() == 2 }, 10*time.Second, 5*time.Millisecond, "two polls are in flight")
	for range 6 {
		select {
		case ran := <-results:
			assert.False(t, ran, "a worker that finds only polls beyond the cap claims nothing")
		case <-time.After(5 * time.Second):
			t.Fatal("a worker is parked behind a poll that waits for a slot")
		}
	}
	assert.Equal(t, 2, w.count("SELECT count(*) FROM jobs WHERE type = 'kv.poll' AND status = 'running'"))
	assert.Equal(t, 12, w.count("SELECT count(*) FROM jobs WHERE type = 'kv.poll' AND status = 'queued' AND attempts = 0"),
		"the polls that wait are not spent")

	// Another type is claimed and finishes while both polls are held.
	_, err = w.inv.RequestAccessCheck(w.ctx, w.admin, extra, uuid.Nil)
	require.NoError(t, err)
	ran, err := w.runner.RunOnce(w.ctx)
	require.NoError(t, err)
	assert.True(t, ran)
	assert.Equal(t, jobs.StatusSucceeded, w.lastJob(jobs.KVTestConnection.Name).Status)
	assert.Equal(t, int32(2), running.Load(), "the polls are still two")

	// A slot frees: the next poll starts, and never more than two run.
	one <- struct{}{}
	require.Eventually(t, func() bool { return <-results }, 10*time.Second, 5*time.Millisecond, "one poll finished")
	go work(w.newRunner("next"))
	require.Eventually(t, func() bool { return started.Load() == 3 && running.Load() == 2 }, 10*time.Second, 5*time.Millisecond, "the next poll started")
	assert.Equal(t, 2, w.count("SELECT count(*) FROM jobs WHERE type = 'kv.poll' AND status = 'running'"))
	close(all)
	for range 2 {
		<-results
	}
	require.Eventually(t, func() bool { return len(results) == 0 && running.Load() == 0 }, 10*time.Second, 5*time.Millisecond)
	w.noLeaks()
}

// finishFails is an inventory whose FinishImport always fails: the outcome of a send can never be recorded.
type finishFails struct{ *inventory.Service }

func (finishFails) FinishImport(context.Context, uuid.UUID, providers.ImportResult, error) (inventory.KVImport, error) {
	return inventory.KVImport{}, errors.New(canary + " the database is gone")
}

// I1: an import whose job ends without the handler finishing it must not block its name for ever.
// Inventory's SweepImports (called by kv.schedule every minute) ends it: queued -> failed, running ->
// uncertain (never sent again), whatever the job's own end was.
func TestImportsEndWhenTheirJobDoes(t *testing.T) {
	setup := func(t *testing.T) (*world, uuid.UUID, inventory.Certificate, pki.Leaf, inventory.KVImport) {
		w := newWorld(t)
		vault := w.addVault("prod")
		w.vaultSays()
		w.drain()
		cert, leaf := w.uploadWithKey("new.example.test")
		im, err := w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
		require.NoError(t, err)
		return w, vault, cert, leaf, im
	}
	sweep := func(w *world, want int) {
		t.Helper()
		n, err := w.inv.SweepImports(w.ctx)
		require.NoError(t, err)
		assert.Equal(t, want, n)
	}
	// settledByAPoll lists the imported version after the request: the uncertain import is imported.
	settledByAPoll := func(w *world, vault uuid.UUID, id uuid.UUID, leaf pki.Leaf) {
		t.Helper()
		w.clock.Advance(20 * time.Minute)
		w.vaultSays(listed("new-cert", leaf, ver(1), w.clock.Now()))
		w.poll(vault)
		state, _ := w.importState(id)
		assert.Equal(t, inventory.ImportSucceeded, state)
	}

	t.Run("the job is discarded while the import is queued", func(t *testing.T) {
		w, vault, cert, _, im := setup(t)
		_, err := w.db.Owner.Exec(w.ctx, "UPDATE jobs SET status = 'cancelled', finished_at = $2 WHERE id = $1", *im.JobID, w.clock.Now())
		require.NoError(t, err)
		require.NoError(t, ScheduleTask(w.inv, time.Minute, nil).Run(w.ctx), "the per-minute kv.schedule tick ends it")
		state, code := w.importState(im.ID)
		assert.Equal(t, inventory.ImportFailed, state)
		assert.Equal(t, inventory.ReasonImportCancelled, code)
		assert.Zero(t, w.az.Count("ImportCertificate"))
		_, err = w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
		assert.NoError(t, err, "the name is free again")
	})
	t.Run("the last attempt is reaped before the mark", func(t *testing.T) {
		w, vault, cert, _, im := setup(t)
		_, err := w.db.Owner.Exec(w.ctx, "UPDATE jobs SET status = 'dead', attempts = max_attempts, finished_at = $2 WHERE id = $1", *im.JobID, w.clock.Now())
		require.NoError(t, err)
		sweep(w, 1)
		state, _ := w.importState(im.ID)
		assert.Equal(t, inventory.ImportFailed, state)
		assert.Zero(t, w.az.Count("ImportCertificate"))
		_, err = w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
		assert.NoError(t, err)
	})
	t.Run("a panic after the mark on the last attempt", func(t *testing.T) {
		w, vault, _, leaf, im := setup(t)
		var sends atomic.Int32
		w.az.Configure(func(c *fake.Config) {
			c.OpenErr = providers.NewError("azure.unreachable", true, nil, nil) // attempts 1 and 2 never get a session
			c.Import = func(providers.ImportRequest) (providers.ImportResult, error) {
				sends.Add(1)
				panic(canary + " the process died in the send")
			}
		})
		for range 2 {
			w.drain()
			w.clock.Advance(time.Hour)
		}
		w.az.Configure(func(c *fake.Config) { c.OpenErr = nil })
		w.drain() // attempt 3: the mark commits, the send panics
		job := w.lastJob(jobs.KVImport.Name)
		assert.Equal(t, jobs.StatusDead, job.Status)
		state, _ := w.importState(im.ID)
		assert.Equal(t, inventory.ImportRunning, state, "nothing ends it by itself")
		sweep(w, 1)
		state, _ = w.importState(im.ID)
		assert.Equal(t, inventory.ImportUncertain, state)
		assert.Equal(t, int32(1), sends.Load())
		settledByAPoll(w, vault, im.ID, leaf)
		assert.Equal(t, int32(1), sends.Load())
		assert.NotContains(t, w.logs.String(), canary)
	})
	t.Run("the outcome cannot be recorded on any attempt", func(t *testing.T) {
		w, vault, _, leaf, im := setup(t)
		var sends atomic.Int32
		w.az.Configure(func(c *fake.Config) {
			c.Import = func(providers.ImportRequest) (providers.ImportResult, error) {
				sends.Add(1)
				return providers.ImportResult{Outcome: providers.ImportUncertain}, providers.NewError("azure.unreachable", true, context.DeadlineExceeded, nil)
			}
		})
		broken := jobs.NewRunner(jobs.RunnerConfig{Pool: w.db.App, Queue: w.queue, Gate: w.lic, Audit: audit.New(w.clock), Clock: w.clock,
			Log: logging.New(w.logs, slog.LevelDebug), Workers: 1, WorkerID: "broken", Jitter: func() float64 { return 0 },
			Notifier: notify.AdminNotifier{Clock: w.clock}})
		Register(broken, Deps{Inventory: finishFails{w.inv}, Registry: w.reg, Clock: w.clock})
		for range 3 {
			w.evaluate()
			_, err := broken.RunOnce(w.ctx)
			require.NoError(t, err)
			w.clock.Advance(time.Hour)
		}
		job := w.lastJob(jobs.KVImport.Name)
		assert.Equal(t, jobs.StatusDead, job.Status)
		state, _ := w.importState(im.ID)
		assert.Equal(t, inventory.ImportRunning, state)
		assert.Equal(t, int32(1), sends.Load(), "the retries never sent again")
		sweep(w, 1)
		state, _ = w.importState(im.ID)
		assert.Equal(t, inventory.ImportUncertain, state)
		settledByAPoll(w, vault, im.ID, leaf)
		assert.Equal(t, int32(1), sends.Load())
		assert.NotContains(t, w.logs.String(), canary)
	})
}

// M3, L-26: an import queued before the license locks is held (blocked_license), sends nothing in lock,
// and runs after an Administrator confirms it once the gate has reopened.
func TestImportIsHeldInLockAndRunsAfterTheLicenseReturns(t *testing.T) {
	w := newWorld(t)
	vault := w.addVault("prod")
	w.vaultSays()
	w.drain()
	cert, _ := w.uploadWithKey("new.example.test")
	im, err := w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: cert.ID, Name: "new-cert"})
	require.NoError(t, err)

	w.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, w.lic.Tick(w.ctx))
	require.ErrorIs(t, w.lic.Allow(license.ClassChange), license.ErrLocked)
	opens := w.az.Count("Open")
	ran, err := w.runner.RunOnce(w.ctx)
	require.NoError(t, err)
	assert.False(t, ran)
	job := w.lastJob(jobs.KVImport.Name)
	assert.Equal(t, jobs.StatusBlocked, job.Status, "held for an Administrator")
	assert.Equal(t, opens, w.az.Count("Open"), "nothing reached the vault")
	assert.Zero(t, w.az.Count("ImportCertificate"))
	state, _ := w.importState(im.ID)
	assert.Equal(t, inventory.ImportQueued, state)
	assert.ErrorIs(t, w.queue.Confirm(w.ctx, w.admin.Audit, w.admin.UserID, job.ID), license.ErrLocked, "not while the gate refuses it")

	w.clock.Advance(time.Minute)
	p := licensetest.Payload(w.lic.Snapshot().InstallationID, w.clock.Now(), w.clock.Now().Add(365*24*time.Hour), 5)
	_, err = w.lic.Install(w.ctx, licensetest.Sign(p), audit.SystemActor("test"), uuid.Nil)
	require.NoError(t, err)
	require.NoError(t, w.queue.Confirm(w.ctx, w.admin.Audit, w.admin.UserID, job.ID))
	w.drain()
	assert.Equal(t, jobs.StatusSucceeded, w.lastJob(jobs.KVImport.Name).Status)
	state, _ = w.importState(im.ID)
	assert.Equal(t, inventory.ImportSucceeded, state)
	assert.Equal(t, 1, w.az.Count("ImportCertificate"))
	w.noLeaks()
}

// M5: the e2e build's reset statement, as written in cmd/alice/testapi_e2e.go, over a database with a vault
// and its credential, vault certificates, a binding, and two imports (one finished): every table but the
// two it keeps is empty afterwards.
func TestE2EResetStatementEmptiesTheVaultTables(t *testing.T) {
	w := newWorld(t)
	vault := w.addVault("prod")
	l1 := w.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, w.clock.Now())
	w.vaultSays(listed("web-cert", l1, ver(1), w.clock.Now()))
	w.drain()
	srv := w.nginxServer("web-01", l1)
	_, err := w.inv.CreateBinding(w.ctx, w.admin, inventory.BindingInput{KVCertificateID: w.certID(vault, "web-cert"), LocationIDs: []uuid.UUID{srv}})
	require.NoError(t, err)
	done, _ := w.uploadWithKey("new.example.test")
	_, err = w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: done.ID, Name: "new-cert"})
	require.NoError(t, err)
	w.drain() // finished: its history is frozen
	open, _ := w.uploadWithKey("new2.example.test")
	_, err = w.inv.RequestImport(w.ctx, w.admin, inventory.ImportInput{VaultID: vault, CertificateID: open.ID, Name: "queued-cert"})
	require.NoError(t, err)
	for _, table := range []string{"kv_imports", "bindings", "kv_certificate_versions", "kv_certificates", "targets"} {
		require.NotZero(t, w.count("SELECT count(*) FROM "+table), table)
	}
	require.Equal(t, 1, w.count("SELECT count(*) FROM kv_imports WHERE finished_at IS NOT NULL"))
	require.Equal(t, 1, w.count("SELECT count(*) FROM credentials WHERE purpose = 'azure_vault'"))

	src, err := os.ReadFile("../../../cmd/alice/testapi_e2e.go")
	require.NoError(t, err)
	m := regexp.MustCompile("(?s)const resetSQL = `(.*?)`").FindSubmatch(src)
	require.NotNil(t, m, "the reset statement")
	for _, stmt := range []string{"ALTER TABLE audit_log DISABLE TRIGGER USER", string(m[1]), "ALTER TABLE audit_log ENABLE TRIGGER USER"} {
		_, err := w.db.Owner.Exec(w.ctx, stmt)
		require.NoError(t, err, stmt)
	}
	rows, err := w.db.Owner.Query(w.ctx, "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		tables = append(tables, n)
	}
	rows.Close()
	var left []string
	for _, tb := range tables {
		if w.count(fmt.Sprintf("SELECT count(*) FROM %q", tb)) > 0 {
			left = append(left, tb)
		}
	}
	assert.ElementsMatch(t, []string{"master_key_versions", "goose_db_version"}, left, "only the two kept tables hold rows")
}
