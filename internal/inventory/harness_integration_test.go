//go:build integration

package inventory_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var start = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// recordingJobs is the inventory.Enqueuer of these tests: it records every request made inside
// a committed or rolled-back transaction (the tests only look at committed outcomes). With next
// set it also passes the request on (the real queue, which writes the job row in tx); fail makes
// the next request fail.
type recordingJobs struct {
	mu   sync.Mutex
	reqs []inventory.JobRequest
	next inventory.Enqueuer
	fail error
}

func (r *recordingJobs) EnqueueTx(ctx context.Context, tx pgx.Tx, req inventory.JobRequest) (uuid.UUID, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	next, fail := r.next, r.fail
	r.fail = nil
	r.mu.Unlock()
	if fail != nil {
		return uuid.Nil, fail
	}
	if next != nil {
		return next.EnqueueTx(ctx, tx, req)
	}
	return uuid.New(), nil
}

func (r *recordingJobs) requests() []inventory.JobRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]inventory.JobRequest(nil), r.reqs...)
}

type harness struct {
	t       *testing.T
	ctx     context.Context
	db      *pgtest.DB
	clock   *clock.Fake
	keyring *secrets.Keyring
	audit   *audit.Log
	lic     *license.Service
	reg     *providers.Registry
	prov    *fake.Provider
	azure   *fake.Provider // the registry's fake azurekv provider (withAzure), nil otherwise
	jobs    *recordingJobs
	svc     *inventory.Service
	logs    *bytes.Buffer
}

type harnessOption func(*inventory.Config)

// newHarness builds a real license service (evaluation, 5 targets) and an inventory service on
// a fresh database. The provider registry holds the fake linuxssh provider.
func newHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()
	h := &harness{t: t, ctx: context.Background(), db: pgtest.New(t), clock: clock.NewFake(start), logs: &bytes.Buffer{}}
	var err error
	h.keyring, err = secrets.LoadOrCreateMasterKey(h.ctx, h.db.App, t.TempDir(), h.clock.Now())
	require.NoError(t, err)
	h.audit = audit.New(h.clock)
	h.lic = license.New(license.Config{
		Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Uptime: h.clock,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), Targets: inventory.Counter{},
		Notifier: notify.AdminNotifier{Clock: h.clock}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, h.lic.Start(h.ctx))
	h.prov = fake.New(providers.KindLinuxSSH)
	h.reg = providers.NewRegistry()
	h.reg.Register(h.prov)
	h.reg.Freeze()
	h.jobs = &recordingJobs{}
	cfg := inventory.Config{
		Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, License: h.lic,
		Registry: h.reg, Jobs: h.jobs, Notifier: notify.AdminNotifier{Clock: h.clock},
		Log: slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, o := range opts {
		o(&cfg)
	}
	if p, ok := cfg.Registry.Get(providers.KindAzureKV); ok {
		h.azure, _ = p.(*fake.Provider)
	}
	h.svc = inventory.New(cfg)
	return h
}

// nginxCaps are the capabilities of the nginx provider (nginx.New).
var nginxCaps = []providers.Capability{providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
	providers.CapDiscoverCerts, providers.CapDeployCertificate, providers.CapVerifyDeployment}

// withNginxProvider replaces the registry with one holding the harness's fake linuxssh provider and
// a fake nginx provider with the nginx capabilities.
func withNginxProvider() harnessOption {
	return func(c *inventory.Config) {
		ssh, _ := c.Registry.Get(providers.KindLinuxSSH)
		reg := providers.NewRegistry()
		reg.Register(ssh)
		reg.Register(fake.New(providers.KindNginx, nginxCaps...))
		reg.Freeze()
		c.Registry = reg
	}
}

// withApacheProvider registers a fake apache provider next to linuxssh.
func withApacheProvider() harnessOption {
	return func(c *inventory.Config) {
		ssh, _ := c.Registry.Get(providers.KindLinuxSSH)
		reg := providers.NewRegistry()
		reg.Register(ssh)
		reg.Register(fake.New(providers.KindApache, providers.CapTestConnection, providers.CapDiscoverSSHKeys,
			providers.CapAuthorizedKeys, providers.CapDiscoverCerts, providers.CapKeyLogin))
		reg.Freeze()
		c.Registry = reg
	}
}

// pinnedKey records a host key for the target, confirms it as a new Administrator and returns it
// (the target is then checking, as after a real confirmation).
func (h *harness) pinnedKey(target uuid.UUID) providers.HostKey {
	h.t.Helper()
	k := ed25519HostKey(h.t)
	require.NoError(h.t, h.svc.HostKeyStore().Observed(h.ctx, target, k, false))
	admin := h.user("pin-"+target.String()[:8]+"-"+uuid.NewString()[:4], rbac.Admin, "")
	_, err := h.svc.ConfirmHostKey(h.ctx, admin, target, keyID(h.t, h, target, k.Fingerprint), k.Fingerprint)
	require.NoError(h.t, err)
	return k
}

// user inserts an enabled local user with the role and returns an actor for it.
func (h *harness) user(name string, role rbac.Role, email string) inventory.Actor {
	h.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'x', $5, $6, $6)`, id, name, email, name+" Yılmaz", string(role), h.clock.Now())
	require.NoError(h.t, err)
	return inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: name}, UserID: id, Role: role}
}

// installLicense uploads a test license for this installation that starts now.
func (h *harness) installLicense(id string, maxTargets int, days int) {
	h.t.Helper()
	p := licensetest.Payload(h.lic.Snapshot().InstallationID, h.clock.Now(), h.clock.Now().Add(time.Duration(days)*24*time.Hour), maxTargets)
	p.LicenseID = id
	_, err := h.lic.Install(h.ctx, licensetest.Sign(p), audit.SystemActor("test"), uuid.Nil)
	require.NoError(h.t, err)
}

func (h *harness) count(sql string, args ...any) int {
	h.t.Helper()
	var n int
	require.NoError(h.t, h.db.Owner.QueryRow(h.ctx, sql, args...).Scan(&n))
	return n
}

func (h *harness) audits(action string) int {
	return h.count("SELECT count(*) FROM audit_log WHERE action = $1", action)
}

func (h *harness) auditDetails(action string) []map[string]string {
	h.t.Helper()
	rows, err := h.db.Owner.Query(h.ctx, "SELECT details FROM audit_log WHERE action = $1 ORDER BY seq", action)
	require.NoError(h.t, err)
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var d map[string]string
		require.NoError(h.t, rows.Scan(&d))
		out = append(out, d)
	}
	require.NoError(h.t, rows.Err())
	return out
}

// mustList lists the live targets and fails the test on error.
func mustList(t *testing.T, h *harness) []inventory.Target {
	t.Helper()
	list, err := h.svc.ListTargets(h.ctx)
	require.NoError(t, err)
	return list
}

// add creates a linux target and fails the test on error.
func (h *harness) add(a inventory.Actor, name, host string) inventory.Target {
	h.t.Helper()
	tg, _, err := h.svc.CreateTarget(h.ctx, a, inventory.NewTarget{Name: name, Type: "linux", Host: host})
	require.NoError(h.t, err)
	return tg
}

// seedTarget inserts a target row of any type as the owner role (types without a provider yet).
func (h *harness) seedTarget(name, typ, host string) uuid.UUID {
	h.t.Helper()
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(h.t, err)
	id := uuid.Must(uuid.NewV7())
	if typ == "azure_key_vault" {
		// A vault has its own credential row (migration 00008): both rows in one transaction, the
		// credential's foreign key to the vault being deferred. The envelope bytes are placeholders:
		// nothing here opens them.
		tx, err := h.db.Owner.Begin(h.ctx)
		require.NoError(h.t, err)
		defer func() { _ = tx.Rollback(h.ctx) }()
		cred := uuid.Must(uuid.NewV7())
		_, err = tx.Exec(h.ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, 'azure_vault', 'azure_sp_secret', '{}', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2, $3)`, cred, h.clock.Now(), id)
		require.NoError(h.t, err)
		_, err = tx.Exec(h.ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, discovery_interval_seconds, created_at, updated_at)
VALUES ($1, $2, 'azure_key_vault', jsonb_build_object('vault_url', 'https://' || $3::text, 'host', $3::text, 'port', 443), $4, 'ok', 900, $5, $5)`,
			id, name, host, cred, h.clock.Now())
		require.NoError(h.t, err)
		require.NoError(h.t, tx.Commit(h.ctx))
		return id
	}
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, $2, $3, jsonb_build_object('host', $4::text, 'port', 22, 'username', 'alice-svc'), $5, 'ok', $6, $6)`,
		id, name, typ, host, pk.ID, h.clock.Now())
	require.NoError(h.t, err)
	return id
}
