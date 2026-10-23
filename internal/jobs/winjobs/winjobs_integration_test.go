//go:build integration

package winjobs

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: a Windows thumbprint is an identifier, not a security hash
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/deployjobs"
	"alice/internal/jobs/targetjobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/tlsverify"
	"alice/internal/providers/windows"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/pki"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

const wwwName = "www.example.test"

// unreachable is Alice's own TLS probe that never reaches the emulated server: the helper's tls-probe verifies.
type unreachable struct{}

func (unreachable) Probe(context.Context, string, int, string, string) (tlsverify.Probe, error) {
	return tlsverify.Probe{}, tlsverify.ErrProbeUnreachable
}

func thumbprintOf(l pki.Leaf) string {
	sum := sha1.Sum(l.Cert.Raw) //nolint:gosec // G401: see the import
	return hex.EncodeToString(sum[:])
}

// stack is the whole of Alice that a cleanup goes through: PostgreSQL, the real queue and runner with the target,
// deployment and cleanup handlers, the inventory and the Windows provider over SSH to wintest's modelled host.
type stack struct {
	t      *testing.T
	ctx    context.Context
	db     *pgtest.DB
	clock  *clock.Fake
	lic    *license.Service
	inv    *inventory.Service
	runner *jobs.Runner
	admin  inventory.Actor
	ca     *pki.CA
	model  *wintest.Model
	target uuid.UUID
	loc    uuid.UUID
}

func newStack(t *testing.T) *stack {
	t.Helper()
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	s := &stack{t: t, ctx: context.Background(), db: pgtest.New(t), clock: clock.NewFake(now)}
	log := slog.New(slog.DiscardHandler)
	keyring, err := secrets.LoadOrCreateMasterKey(s.ctx, s.db.App, t.TempDir(), now)
	require.NoError(t, err)
	al := audit.New(s.clock)
	s.lic = license.New(license.Config{Pool: s.db.App, Keyring: keyring, Audit: al, Clock: s.clock, Uptime: s.clock,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), Targets: inventory.Counter{}, Notifier: notify.AdminNotifier{Clock: s.clock}, Log: log})
	require.NoError(t, s.lic.Start(s.ctx))
	t.Cleanup(s.lic.Close)
	queue := jobs.NewQueue(jobs.QueueConfig{Pool: s.db.App, Keyring: keyring, Audit: al, Clock: s.clock, Gate: s.lic})
	s.ca = pki.NewCA("Cleanup", pki.ECDSA256, now)
	roots := x509.NewCertPool()
	roots.AddCert(s.ca.Root)
	reg := providers.NewRegistry()
	s.inv = inventory.New(inventory.Config{Pool: s.db.App, Keyring: keyring, Audit: al, Clock: s.clock, License: s.lic,
		Registry: reg, Jobs: queue, Notifier: notify.ServiceNotifier{Clock: s.clock}, Log: log, Roots: roots})
	pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: s.inv.HostKeyStore()}, linuxssh.MaxConnections, 16, linuxssh.IdleTimeout)
	t.Cleanup(pool.Close)
	reg.Register(windows.New(windows.Options{Pool: pool, AllowUnverifiedHelper: true, Prober: unreachable{}, Attempts: 1, RetryWait: time.Millisecond}))
	reg.Freeze()
	_, err = s.inv.EnsurePlatformKey(s.ctx)
	require.NoError(t, err)
	s.runner = jobs.NewRunner(jobs.RunnerConfig{Pool: s.db.App, Queue: queue, Gate: s.lic, Audit: al, Clock: s.clock, Log: log, Workers: 1,
		WorkerID: "alice", Jitter: func() float64 { return 0 }, Notifier: notify.ServiceNotifier{Clock: s.clock}})
	targetjobs.Register(s.runner, targetjobs.Deps{Inventory: s.inv, Registry: reg, Clock: s.clock, Log: log})
	deployjobs.Register(s.runner, deployjobs.Deps{Inventory: s.inv, Registry: reg, Clock: s.clock, Log: log})
	Register(s.runner, Deps{Inventory: s.inv, Registry: reg, Clock: s.clock, Log: log})
	id := uuid.Must(uuid.NewV7())
	_, err = s.db.Owner.Exec(s.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'ada', 'ada@example.com', 'Ada', 'x', 'admin', $2, $2)`, id, now)
	require.NoError(t, err)
	s.admin = inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: "ada"}, UserID: id, Role: rbac.Admin}
	return s
}

// drain runs the license evaluation, then due jobs until none is left.
func (s *stack) drain() {
	s.t.Helper()
	require.NoError(s.t, s.lic.Tick(s.ctx))
	for range 50 {
		ran, err := s.runner.RunOnce(s.ctx)
		require.NoError(s.t, err)
		if !ran {
			return
		}
	}
	s.t.Fatal("jobs did not drain")
}

// addServer starts an emulated Windows server whose IIS binding serves old (not Alice's), adds it, confirms its host key
// and discovers it.
func (s *stack) addServer(old pki.Leaf) {
	s.t.Helper()
	pk, err := s.inv.PlatformKey(s.ctx)
	require.NoError(s.t, err)
	s.model = wintest.NewModel()
	s.model.SetNow(s.clock.Now())
	s.model.SetLockWait(50 * time.Millisecond)
	s.model.AddIntermediate(s.ca.IntermediatePEM)
	sha1 := s.model.AddCertificate("My", old.CertPEM, old.KeyPEM, wintest.CertOptions{FriendlyName: "www"})
	s.model.AddBinding(winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: wwwName, Port: 443, AppID: winproto.AppIDIIS,
		CertSHA1: sha1, Store: "My"})
	s.model.AddSite(winproto.Site{Name: "Default Web Site", ID: 1, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:443:" + wwwName, SSLFlags: 1}}})
	srv := wintest.NewServer(s.t, s.model)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk.PublicKey))
	require.NoError(s.t, err)
	srv.Authorize(pub)
	host, port := srv.Addr()
	tg, _, err := s.inv.CreateTarget(s.ctx, s.admin, inventory.NewTarget{Name: "iis-01", Type: inventory.TypeWindows, Host: host, Port: port})
	require.NoError(s.t, err)
	s.target = tg.ID
	s.drain()
	keys, err := s.inv.ListHostKeys(s.ctx, tg.ID)
	require.NoError(s.t, err)
	require.Len(s.t, keys, 1)
	_, err = s.inv.ConfirmHostKey(s.ctx, s.admin, tg.ID, keys[0].ID, keys[0].Fingerprint)
	require.NoError(s.t, err)
	s.drain()
	list, err := s.inv.ListLocations(s.ctx, tg.ID, false)
	require.NoError(s.t, err)
	require.Len(s.t, list.Items, 1)
	require.True(s.t, list.Items[0].Deployable, list.Items[0].UnsupportedReason)
	s.loc = list.Items[0].ID
}

// deploy uploads l with its key and deploys it to the binding through the deployment engine.
func (s *stack) deploy(l pki.Leaf) {
	s.t.Helper()
	c, _, err := s.inv.UploadCertificate(s.ctx, s.admin, inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(l.KeyPEM)})
	require.NoError(s.t, err)
	require.NoError(s.t, s.lic.Tick(s.ctx))
	got, err := s.inv.RequestDeployment(s.ctx, s.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.loc}})
	require.NoError(s.t, err)
	s.drain()
	d, err := s.inv.Deployment(s.ctx, got[0].ID)
	require.NoError(s.t, err)
	require.Equal(s.t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
}

// lastCleanup is the result and status of the newest windows.cleanup job.
func (s *stack) lastCleanup() (string, map[string]any) {
	s.t.Helper()
	var status string
	var raw []byte
	require.NoError(s.t, s.db.Owner.QueryRow(s.ctx, `SELECT status, result FROM jobs WHERE type = 'windows.cleanup' AND target_id = $1
ORDER BY created_at DESC, id DESC LIMIT 1`, s.target).Scan(&status, &raw))
	var out map[string]any
	require.NoError(s.t, json.Unmarshal(raw, &out))
	return status, out
}

// Design §13 W3: the daily cleanup over SSH against the emulated server. A certificate Alice imported and replaced is a
// candidate the first day (the helper starts counting); a week later, with Alice's rollback window over too, the next
// run removes it, key first, and audits it. The bound certificate and the one Alice did not import stay.
func TestWindowsCleanupRemovesAnAgedCertificate(t *testing.T) {
	s := newStack(t)
	opts := pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}
	old, first, second := s.ca.Issue(opts, s.clock.Now()), s.ca.Issue(opts, s.clock.Now()), s.ca.Issue(opts, s.clock.Now())
	s.addServer(old)
	s.deploy(first)
	s.deploy(second)
	require.True(t, s.model.HasCertificate("My", thumbprintOf(first)), "the replaced import is still in the store")

	n, err := s.inv.ScheduleWindowsCleanup(s.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	s.drain()
	status, res := s.lastCleanup()
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 1, res["candidates"], "the replaced import; the bound one and the one Alice did not import are no candidates")
	assert.EqualValues(t, 0, res["removed"], "the helper counts from today")
	assert.True(t, s.model.HasCertificate("My", thumbprintOf(first)))

	s.clock.Advance(8 * 24 * time.Hour)
	s.model.Advance(8 * 24 * time.Hour)
	n, err = s.inv.ScheduleWindowsCleanup(s.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	s.drain()
	status, res = s.lastCleanup()
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 1, res["removed"], "%v", res)
	assert.False(t, s.model.HasCertificate("My", thumbprintOf(first)), "removed")
	assert.False(t, s.model.HasKey("My", thumbprintOf(first)), "with its key")
	assert.True(t, s.model.HasCertificate("My", thumbprintOf(second)), "the bound certificate stays")
	assert.True(t, s.model.HasCertificate("My", thumbprintOf(old)), "the certificate Alice did not import stays")
	var details map[string]string
	require.NoError(t, s.db.Owner.QueryRow(s.ctx, "SELECT details FROM audit_log WHERE action = 'windows.certificate_removed'").Scan(&details))
	delete(details, "service_id")
	assert.Equal(t, map[string]string{"store": "My", "sha1": thumbprintOf(first), "sha256": pki.Fingerprint(first.Cert), "reason": "aged"}, details)
}
