//go:build integration

package canaryjobs

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/deployjobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/httpcheck"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/pki"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

// stack is PostgreSQL, the real queue and runner with the deployment and canary handlers, the inventory and the fake
// Nginx provider; the round's HTTP check is the product's httpcheck against a local TLS server serving the deployed
// leaf.
type stack struct {
	t      *testing.T
	ctx    context.Context
	db     *pgtest.DB
	clock  *clock.Fake
	lic    *license.Service
	inv    *inventory.Service
	runner *jobs.Runner
	admin  inventory.Actor
	leaf   pki.Leaf
	cert   inventory.Certificate
	target uuid.UUID
	locs   []uuid.UUID
	status atomic.Int32 // what /healthz answers
}

func newStack(t *testing.T) *stack {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	s := &stack{t: t, ctx: context.Background(), db: pgtest.New(t), clock: clock.NewFake(now)}
	s.status.Store(http.StatusOK)
	log := slog.New(slog.DiscardHandler)
	keyring, err := secrets.LoadOrCreateMasterKey(s.ctx, s.db.App, t.TempDir(), now)
	require.NoError(t, err)
	al := audit.New(s.clock)
	s.lic = license.New(license.Config{Pool: s.db.App, Keyring: keyring, Audit: al, Clock: s.clock, Uptime: s.clock,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), Targets: inventory.Counter{}, Notifier: notify.AdminNotifier{Clock: s.clock}, Log: log})
	require.NoError(t, s.lic.Start(s.ctx))
	t.Cleanup(s.lic.Close)
	queue := jobs.NewQueue(jobs.QueueConfig{Pool: s.db.App, Keyring: keyring, Audit: al, Clock: s.clock, Gate: s.lic})
	ca := pki.NewCA("Canary", pki.ECDSA256, now.Add(-time.Hour))
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	reg := providers.NewRegistry()
	reg.Register(fake.New(providers.KindNginx, providers.CapTestConnection, providers.CapDiscoverCerts, providers.CapDeployCertificate,
		providers.CapVerifyDeployment))
	reg.Freeze()
	s.inv = inventory.New(inventory.Config{Pool: s.db.App, Keyring: keyring, Audit: al, Clock: s.clock, License: s.lic,
		Registry: reg, Jobs: queue, Notifier: notify.ServiceNotifier{Clock: s.clock}, Log: log, Roots: roots})
	_, err = s.inv.EnsurePlatformKey(s.ctx)
	require.NoError(t, err)
	s.runner = jobs.NewRunner(jobs.RunnerConfig{Pool: s.db.App, Queue: queue, Gate: s.lic, Audit: al, Clock: s.clock, Log: log, Workers: 1,
		WorkerID: "alice", Jitter: func() float64 { return 0 }, Notifier: notify.ServiceNotifier{Clock: s.clock}})
	deployjobs.Register(s.runner, deployjobs.Deps{Inventory: s.inv, Registry: reg, Clock: s.clock, Log: log})
	Register(s.runner, Deps{Inventory: s.inv, Registry: reg, Checker: httpcheck.HTTPChecker{Clock: clock.Real{}}, Clock: s.clock, Log: log,
		UserAgent: "Alice-canary/test"})
	id := uuid.Must(uuid.NewV7())
	_, err = s.db.Owner.Exec(s.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'ada', 'ada@example.com', 'Ada', 'x', 'admin', $2, $2)`, id, now)
	require.NoError(t, err)
	s.admin = inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: "ada"}, UserID: id, Role: rbac.Admin}

	// The health server listens on a port the system chooses (a fixed one collided on CI); the websites name it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	healthPort := ln.Addr().(*net.TCPAddr).Port

	// One Nginx server on 127.0.0.1 with two websites listening on the health server's port, holding an old leaf.
	tg, _, err := s.inv.CreateTarget(s.ctx, s.admin, inventory.NewTarget{Name: "web-01", Type: inventory.TypeNginx, Host: "127.0.0.1", Port: 22})
	require.NoError(t, err)
	s.target = tg.ID
	_, err = s.db.Owner.Exec(s.ctx, "UPDATE targets SET status = 'ok' WHERE id = $1", s.target)
	require.NoError(t, err)
	_, err = s.db.Owner.Exec(s.ctx, "DELETE FROM jobs")
	require.NoError(t, err)
	www := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	old := ca.Issue(www, now.Add(-time.Hour))
	s.leaf = ca.Issue(www, now.Add(-time.Hour))
	loc := func(path string) providers.DiscoveredCertificate {
		sum := sha256.Sum256(old.FullchainPEM)
		return providers.DiscoveredCertificate{Location: providers.CertLocation{CertPath: path, KeyPath: path + ".key", ResolvedCertPath: path,
			Supported: true, KeyExists: true, KeyMode: "0600", KeyOwner: "root", KeyGroup: "root",
			Servers: []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Port: healthPort}},
				File: "/etc/nginx/sites-enabled/default", Line: 1}}}, PEMChain: old.FullchainPEM, FileSHA256: hex.EncodeToString(sum[:])}
	}
	_, err = s.inv.Reconcile(s.ctx, s.target, providers.DiscoveryResult{WebServer: &providers.WebServerFacts{Found: true, ConfigValid: true,
		Version: "1.22.1"}, Certificates: []providers.DiscoveredCertificate{loc("/etc/nginx/ssl/a.crt"), loc("/etc/nginx/ssl/b.crt")}})
	require.NoError(t, err)
	page, err := s.inv.ListLocations(s.ctx, s.target, false)
	require.NoError(t, err)
	for _, l := range page.Items {
		s.locs = append(s.locs, l.ID)
	}
	require.Len(t, s.locs, 2)
	s.cert, _, err = s.inv.UploadCertificate(s.ctx, s.admin, inventory.UploadInput{CertificatePEM: string(s.leaf.FullchainPEM),
		PrivateKeyPEM: string(s.leaf.KeyPEM)})
	require.NoError(t, err)

	// The health server serves the deployed leaf.
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(int(s.status.Load()))
	}), ReadHeaderTimeout: 5 * time.Second}
	cert := tls.Certificate{Certificate: [][]byte{s.leaf.Cert.Raw}, PrivateKey: s.leaf.Key}
	go func() {
		_ = srv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	}()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

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

// CAN-21: a request becomes a rollout, its wave-1 deployment holds, the advance queues one round per due hold (dedupe
// canary.check:<id>, the deployment's server), and the round job runs the real HTTPS check against the server and records
// pass, then fail when the application answers 503.
func TestAdvanceTaskQueuesOneJobPerDueRound(t *testing.T) {
	s := newStack(t)
	var svc uuid.UUID
	require.NoError(t, s.db.Owner.QueryRow(s.ctx, "SELECT id FROM services WHERE is_default").Scan(&svc))
	_, err := s.db.Owner.Exec(s.ctx, `UPDATE services SET policy_version = 2 WHERE id = $1`, svc)
	require.NoError(t, err)
	_, err = s.db.Owner.Exec(s.ctx, `INSERT INTO service_policies (service_id, version, body, created_at) VALUES ($1, 2,
'{"schema":1,"canary":{"enabled":true,"hold":"1m","interval":"15s","check":{"path":"/healthz"}}}', now())`, svc)
	require.NoError(t, err)
	got, r, err := s.inv.RequestDeploymentWithRollout(s.ctx, s.admin, inventory.DeployRequestInput{CertificateID: s.cert.ID, LocationIDs: s.locs})
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Len(t, got, 1)
	hold := got[0].ID
	s.drain()
	d, err := s.inv.Deployment(s.ctx, hold)
	require.NoError(t, err)
	require.Equal(t, inventory.DeployStateHolding, d.State)

	task := AdvanceTask(s.inv, 10*time.Second, nil)
	require.NoError(t, task.Run(s.ctx))
	require.NoError(t, task.Run(s.ctx))
	var n int
	var target uuid.UUID
	require.NoError(t, s.db.Owner.QueryRow(s.ctx, "SELECT count(*), min(target_id::text)::uuid FROM jobs WHERE type = 'canary.check' AND dedupe_key = $1",
		"canary.check:"+hold.String()).Scan(&n, &target))
	assert.Equal(t, 1, n, "one round per due hold")
	assert.Equal(t, s.target, target, "the round serializes with the server's deployments")

	s.drain()
	var result, tlsResult string
	var status *int
	require.NoError(t, s.db.Owner.QueryRow(s.ctx, "SELECT last_result, last_tls, last_http_status FROM canary_checks WHERE deployment_id = $1", hold).
		Scan(&result, &tlsResult, &status))
	assert.Equal(t, "pass", result)
	assert.Equal(t, "pass", tlsResult)
	require.NotNil(t, status)
	assert.Equal(t, 200, *status)

	s.status.Store(http.StatusServiceUnavailable)
	s.clock.Advance(16 * time.Second)
	require.NoError(t, task.Run(s.ctx))
	s.drain()
	require.NoError(t, s.db.Owner.QueryRow(s.ctx, "SELECT last_result, last_http_status FROM canary_checks WHERE deployment_id = $1", hold).
		Scan(&result, &status))
	assert.Equal(t, "fail", result)
	assert.Equal(t, 503, *status)
	var reason string
	require.NoError(t, s.db.Owner.QueryRow(s.ctx, "SELECT last_reason FROM canary_checks WHERE deployment_id = $1", hold).Scan(&reason))
	assert.Equal(t, httpcheck.ReasonHTTPStatus, reason)
}
