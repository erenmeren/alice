//go:build integration

package acmejobs

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver"
	"alice/internal/acme/solver/http01"
	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/logging"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

// syncBuffer collects every log line of the stack for the leak scan.
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

// lockGate is the license service with a lock switch. lockWhen, when set, locks it at the first ClassChange question
// it answers true for (a lock that begins in the middle of an order); onLock runs when that happens.
type lockGate struct {
	*license.Service
	locked   atomic.Bool
	lockWhen func() bool
	onLock   func()
}

func (g *lockGate) Allow(c license.Class) error {
	if c != license.ClassAlways && !g.locked.Load() && g.lockWhen != nil && g.lockWhen() {
		g.locked.Store(true)
		if g.onLock != nil {
			g.onLock()
		}
	}
	if g.locked.Load() && c != license.ClassAlways {
		return license.ErrLocked
	}
	return g.Service.Allow(c)
}

type world struct {
	t        *testing.T
	ctx      context.Context
	db       *pgtest.DB
	clock    *clock.Fake
	logs     *syncBuffer
	lic      *license.Service
	gate     *lockGate
	queue    *jobs.Queue
	inv      *inventory.Service
	reg      *providers.Registry
	pub      *memPublisher
	web      *httptest.Server
	h        *handlers
	runner   *jobs.Runner
	fake     *fakeacme.Server
	admin    inventory.Actor
	operator inventory.Actor
	provider inventory.ACMEProvider
	account  inventory.ACMEAccount
	hook     inventory.ACMEHook
}

func newWorld(t *testing.T) *world {
	t.Helper()
	now := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	w := &world{t: t, ctx: ctx, db: pgtest.New(t), clock: clock.NewFake(now), logs: &syncBuffer{}, pub: &memPublisher{files: map[string]string{}}}
	log := logging.New(w.logs, slog.LevelDebug)
	keyring, err := secrets.LoadOrCreateMasterKey(w.ctx, w.db.App, t.TempDir(), now)
	require.NoError(t, err)
	auditLog := audit.New(w.clock)
	w.lic = license.New(license.Config{Pool: w.db.App, Keyring: keyring, Audit: auditLog, Clock: w.clock, Uptime: w.clock,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), Targets: inventory.Counter{}, Notifier: notify.AdminNotifier{Clock: w.clock}, Log: log})
	require.NoError(t, w.lic.Start(w.ctx))
	w.gate = &lockGate{Service: w.lic}
	w.queue = jobs.NewQueue(jobs.QueueConfig{Pool: w.db.App, Keyring: keyring, Audit: auditLog, Clock: w.clock, Gate: w.gate})
	w.reg = providers.NewRegistry()
	w.reg.Register(fake.New(providers.KindLinuxSSH))
	w.reg.Register(pubProvider{Provider: fake.New(providers.KindNginx, providers.CapTestConnection, providers.CapHTTP01), pub: w.pub})
	w.reg.Freeze()
	w.inv = inventory.New(inventory.Config{Pool: w.db.App, Keyring: keyring, Audit: auditLog, Clock: w.clock, License: w.gate, Registry: w.reg,
		Jobs: w.queue, Notifier: notify.AdminNotifier{Clock: w.clock}, Log: log})
	_, err = w.inv.EnsurePlatformKey(w.ctx)
	require.NoError(t, err)
	w.h = newHandlers(Deps{Inventory: w.inv, Registry: w.reg, Gate: w.gate, Clock: w.clock, Log: log})
	w.h.newHTTP01 = func(c http01.Config) (solver.Solver, error) { return publishOnly{pub: c.Publisher}, nil }
	w.runner = jobs.NewRunner(jobs.RunnerConfig{Pool: w.db.App, Queue: w.queue, Gate: w.gate, Audit: audit.New(w.clock), Clock: w.clock,
		Log: log, Workers: 1, WorkerID: "acme-test", Jitter: func() float64 { return 0 }, Notifier: notify.AdminNotifier{Clock: w.clock}})
	w.runner.Handle(jobs.ACMEIssue, w.h.issue)
	w.runner.Handle(jobs.ACMERenew, w.h.issue)
	w.runner.Handle(jobs.ACMECleanup, w.h.cleanup)

	w.fake, err = fakeacme.New(fakeacme.Options{Now: w.clock.Now, NoTerms: true})
	require.NoError(t, err)
	require.NoError(t, w.fake.Start())
	t.Cleanup(w.fake.Close)
	w.web = httptest.NewServer(w.pub)
	t.Cleanup(w.web.Close)

	w.admin = w.user("ada", rbac.Admin)
	w.operator = w.user("otto", rbac.Operator)
	// The provider's bundle: the fake's TLS CA (to reach it) and its issuing root (so the chain is complete, A3).
	w.provider, err = w.inv.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Fake CA", DirectoryURL: w.fake.DirectoryURL(),
		CABundlePEM: string(w.fake.CAPEM()) + string(w.fake.IssuerRootPEM()), AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	w.account, err = w.inv.RegisterACMEAccount(w.ctx, w.admin, w.provider.ID, "ops@example.test", false)
	require.NoError(t, err)
	none := 0
	w.hook, err = w.inv.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: "fake dns", URL: w.fake.Credentials().HookURL,
		CABundlePEM: string(w.fake.CAPEM()), Secret: secrets.NewPlaintext([]byte(w.fake.Credentials().HookSecret)),
		AllowedSuffixes: []string{"example.test"}, PropagationWaitSeconds: &none, PollTimeoutSeconds: 5})
	require.NoError(t, err)
	return w
}

func (w *world) user(name string, role rbac.Role) inventory.Actor {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := w.db.Owner.Exec(w.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, $2, $3, $6, 'x', $4, $5, $5)`, id, name, name+"@example.test", string(role), w.clock.Now(), name+" Yılmaz")
	require.NoError(w.t, err)
	return inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: name}, UserID: id, Role: role}
}

// dnsCert defines a DNS-01 certificate through the fake's hook.
func (w *world) dnsCert(names ...string) inventory.ACMECertificate {
	w.t.Helper()
	hook := w.hook.ID
	c, err := w.inv.CreateACMECertificate(w.ctx, w.admin, inventory.ACMECertificateInput{ProviderID: w.provider.ID, Names: names,
		Challenge: inventory.ACMEChallengeDNS01, HookID: &hook})
	require.NoError(w.t, err)
	return c
}

// webTarget is an Nginx server (status ok) for HTTP-01 certificates.
func (w *world) webTarget(name string) uuid.UUID {
	w.t.Helper()
	pk, err := w.inv.EnsurePlatformKey(w.ctx)
	require.NoError(w.t, err)
	id := uuid.Must(uuid.NewV7())
	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, $2, 'nginx', jsonb_build_object('host', $5::text, 'port', 22, 'username', 'alice-svc'), $3, 'ok', $4, $4)`,
		id, name, pk.ID, w.clock.Now(), name+".example.test")
	require.NoError(w.t, err)
	return id
}

// order requests an order as the Operator.
func (w *world) order(c inventory.ACMECertificate, kind string) inventory.ACMEOrder {
	w.t.Helper()
	o, err := w.inv.RequestOrder(w.ctx, w.operator, c.ID, kind)
	require.NoError(w.t, err)
	return o
}

// drain runs due jobs until none is left.
func (w *world) drain() {
	w.t.Helper()
	for range 50 {
		ran, err := w.runner.RunOnce(w.ctx)
		require.NoError(w.t, err)
		if !ran {
			return
		}
	}
	w.t.Fatal("jobs did not drain")
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

func (w *world) getOrder(id uuid.UUID) inventory.ACMEOrder {
	w.t.Helper()
	o, err := w.inv.GetACMEOrder(w.ctx, id)
	require.NoError(w.t, err)
	return o
}

func (w *world) getCert(id uuid.UUID) inventory.ACMECertificate {
	w.t.Helper()
	c, err := w.inv.GetACMECertificate(w.ctx, id)
	require.NoError(w.t, err)
	return c
}

// keyColumns is how many pending_key_* columns of the order are set.
func (w *world) keyColumns(order uuid.UUID) int {
	return w.count(`SELECT (pending_key_ct IS NOT NULL)::int + (pending_key_nonce IS NOT NULL)::int + (pending_key_wrapped_dek IS NOT NULL)::int
    + (pending_key_version IS NOT NULL)::int FROM acme_orders WHERE id = $1`, order)
}

// job is the newest job of a type: its status, error code and attempts.
func (w *world) job(typ string) (status, code string, attempts int) {
	w.t.Helper()
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, `SELECT status, last_error_code, attempts FROM jobs WHERE type = $1 ORDER BY created_at DESC, id DESC
LIMIT 1`, typ).Scan(&status, &code, &attempts))
	return status, code, attempts
}

// dnsLeft is how many TXT values the fake's DNS still holds.
func (w *world) dnsLeft() int {
	n := 0
	for _, v := range w.fake.DNSRecords() {
		n += len(v)
	}
	return n
}
