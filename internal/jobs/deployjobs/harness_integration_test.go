//go:build integration

package deployjobs

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/driftjobs"
	"alice/internal/jobs/targetjobs"
	"alice/internal/jobs/winjobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/logging"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/nginx"
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

const (
	wwwCert = "/etc/nginx/ssl/www.crt"
	wwwKey  = "/etc/nginx/ssl/www.key"
	apiCert = "/etc/nginx/ssl/api.crt"
	apiKey  = "/etc/nginx/ssl/api.key"
	wwwName = "www.example.test"
	apiName = "api.example.test"
)

// syncBuffer collects every log line of the stack (handlers, runner, inventory) for the leak test.
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

// lockGate is the license service with a switch that puts it in lock (the runner and the queue
// only ask Allow; how the lock came about does not matter to them).
type lockGate struct {
	*license.Service
	locked atomic.Bool
}

func (g *lockGate) Allow(c license.Class) error {
	if g.locked.Load() && c != license.ClassAlways {
		return license.ErrLocked
	}
	return g.Service.Allow(c)
}

// emuProber is Alice's own TLS probe against the emulated Nginx. Every emulated host listens on
// 127.0.0.1, so with several hosts Alice's probe cannot tell which one it would reach: it is then
// unreachable and the server-side probe (tls-probe, per host) decides (verified "local"). hook, when
// it returns a function, changes each answer (R51: what the website presents on the way to Alice).
type emuProber struct {
	emus func() []*server
	hook func() func(nginx.Probe) (nginx.Probe, error)
}

func (p emuProber) Probe(_ context.Context, _ string, port int, sni, keyType string) (nginx.Probe, error) {
	emus := p.emus()
	if len(emus) != 1 {
		return nginx.Probe{}, nginx.ErrProbeUnreachable
	}
	leaf, chain, ok := emus[0].emu.ProbeServed("", port, sni, keyType)
	if !ok {
		return nginx.Probe{}, nginx.ErrProbeFailed
	}
	pr := nginx.Probe{LeafSHA256: leaf, ChainLength: chain, Chain: emus[0].emu.ProbeServedChain("", port, sni, keyType)}
	if p.hook != nil {
		if h := p.hook(); h != nil {
			return h(pr)
		}
	}
	return pr, nil
}

// hookProvider lets a test wrap the sessions the nginx provider opens.
type hookProvider struct {
	*nginx.Provider
	wrap func(providers.TargetRef, providers.Session) providers.Session
}

func (p hookProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil || p.wrap == nil {
		return s, err
	}
	return p.wrap(t, s), nil
}

// server is one emulated Nginx host and its target.
type server struct {
	srv     *linuxsshtest.Server
	emu     *linuxsshtest.Emulator
	host    string
	sshPort int
	target  uuid.UUID
	locs    map[string]uuid.UUID // cert path -> location id
}

type env struct {
	t       *testing.T
	ctx     context.Context
	db      *pgtest.DB
	clock   *clock.Fake
	logs    *syncBuffer
	keyring *secrets.Keyring
	audit   *audit.Log
	lic     *license.Service
	gate    *lockGate
	queue   *jobs.Queue
	inv     *inventory.Service
	prov    *nginx.Provider
	win     *windows.Provider // the Windows provider, its servers emulated by wintest (windows_integration_test.go)
	az      *fake.Provider    // the scripted azurekv provider (Key Vault deployments, kv_integration_test.go)
	reg     *providers.Registry
	runner  *jobs.Runner
	admin   inventory.Actor
	ca      *pki.CA
	old, nw pki.Leaf
	cert    inventory.Certificate // nw, uploaded with its key
	mu      sync.Mutex
	servers []*server
	wins    []*winServer
	wrap    atomic.Pointer[func(providers.TargetRef, providers.Session) providers.Session]
	probe   atomic.Pointer[func(nginx.Probe) (nginx.Probe, error)]
}

func newEnv(t *testing.T) *env {
	t.Helper()
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	e := &env{t: t, ctx: context.Background(), db: pgtest.New(t), clock: clock.NewFake(now), logs: &syncBuffer{}}
	log := logging.New(e.logs, slog.LevelDebug)
	var err error
	e.keyring, err = secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, t.TempDir(), e.clock.Now())
	require.NoError(t, err)
	e.audit = audit.New(e.clock)
	e.lic = license.New(license.Config{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clock, Uptime: e.clock,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), Targets: inventory.Counter{}, Notifier: notify.AdminNotifier{Clock: e.clock}, Log: log})
	require.NoError(t, e.lic.Start(e.ctx))
	t.Cleanup(e.lic.Close)
	e.gate = &lockGate{Service: e.lic}
	e.queue = jobs.NewQueue(jobs.QueueConfig{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clock, Gate: e.gate})
	e.ca = pki.NewCA("Deploy", pki.ECDSA256, now)
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Root)
	e.reg = providers.NewRegistry()
	e.inv = inventory.New(inventory.Config{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clock, License: e.lic,
		Registry: e.reg, Jobs: e.queue, Notifier: notify.ServiceNotifier{Clock: e.clock}, Log: log, Roots: roots})
	pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: e.inv.HostKeyStore()}, linuxssh.MaxConnections, 16,
		linuxssh.IdleTimeout)
	t.Cleanup(pool.Close)
	ssh := linuxssh.New(linuxssh.Options{Pool: pool, AllowUnverifiedHelper: true})
	// One verification attempt per endpoint: the provider's waits run on the session clock, which is
	// the fake clock here.
	e.prov = nginx.New(nginx.Options{SSH: ssh, Prober: emuProber{emus: e.serverList, hook: e.probeHook}, Attempts: 1})
	e.reg.Register(hookProvider{Provider: e.prov, wrap: e.wrapSession})
	// The Windows provider on the same pool, Alice's probe reaching the emulated listeners (winProber), one
	// verification attempt (its waits run on the session clock, the fake clock here).
	e.win = windows.New(windows.Options{Pool: pool, AllowUnverifiedHelper: true, Prober: winProber{wins: e.winList}, Attempts: 1,
		RetryWait: time.Millisecond})
	e.reg.Register(winHookProvider{Provider: e.win, wrap: e.wrapSession})
	e.az = fake.New(providers.KindAzureKV, providers.CapTestConnection, providers.CapDiscoverCerts, providers.CapReadCertificateSecret)
	e.reg.Register(e.az)
	e.reg.Freeze()
	_, err = e.inv.EnsurePlatformKey(e.ctx)
	require.NoError(t, err)
	e.runner = e.newRunner("alice")
	e.register(e.runner)
	id := uuid.Must(uuid.NewV7())
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'ada', 'ada@example.com', 'Ada Yılmaz', 'x', 'admin', $2, $2)`, id, e.clock.Now())
	require.NoError(t, err)
	e.admin = inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: "ada"}, UserID: id, Role: rbac.Admin}
	www := pki.Opts{CommonName: wwwName, SANs: []string{wwwName, apiName}}
	e.old, e.nw = e.ca.Issue(www, now), e.ca.Issue(www, now)
	return e
}

// probeHook is the change setProbe installed (nil: none).
func (e *env) probeHook() func(nginx.Probe) (nginx.Probe, error) {
	if h := e.probe.Load(); h != nil {
		return *h
	}
	return nil
}

// setProbe makes Alice's own probe pass every answer through h (nil: none).
func (e *env) setProbe(h func(nginx.Probe) (nginx.Probe, error)) {
	if h == nil {
		e.probe.Store(nil)
		return
	}
	e.probe.Store(&h)
}

func (e *env) serverList() []*server {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.servers)
}

func (e *env) wrapSession(t providers.TargetRef, s providers.Session) providers.Session {
	if w := e.wrap.Load(); w != nil {
		return (*w)(t, s)
	}
	return s
}

// setWrap makes every session opened from now on pass through w (nil: none).
func (e *env) setWrap(w func(providers.TargetRef, providers.Session) providers.Session) {
	if w == nil {
		e.wrap.Store(nil)
		return
	}
	e.wrap.Store(&w)
}

func (e *env) log() *slog.Logger { return logging.New(e.logs, slog.LevelDebug) }

func (e *env) newRunner(worker string) *jobs.Runner {
	return jobs.NewRunner(jobs.RunnerConfig{Pool: e.db.App, Queue: e.queue, Gate: e.gate, Audit: e.audit, Clock: e.clock,
		Log: e.log(), Workers: 1, WorkerID: worker, Jitter: func() float64 { return 0 }, Notifier: notify.ServiceNotifier{Clock: e.clock}})
}

// register installs the target and deployment handlers on r, the way cmd/alice will (Task 19).
func (e *env) register(r *jobs.Runner) {
	targetjobs.Register(r, targetjobs.Deps{Inventory: e.inv, Registry: e.reg, Clock: e.clock, Log: e.log()})
	Register(r, Deps{Inventory: e.inv, Registry: e.reg, Clock: e.clock, Log: e.log()})
}

// addServer starts an emulated Nginx host serving the old certificate on the given sites, adds it
// as a target, confirms its host key and runs the first test and discovery.
func (e *env) addServer(name string, sites ...linuxsshtest.NginxSite) *server {
	e.t.Helper()
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(e.t, err)
	s := &server{emu: linuxsshtest.NewEmulator(), locs: map[string]uuid.UUID{}}
	s.emu.EnableNginx("1.22.1")
	for _, site := range sites {
		s.emu.AddSite(site, e.old.FullchainPEM, e.old.KeyPEM)
	}
	s.srv = linuxsshtest.NewServer(e.t, s.emu.Handler())
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk.PublicKey))
	require.NoError(e.t, err)
	s.srv.Authorize(pub)
	s.host, s.sshPort = s.srv.Addr()
	e.mu.Lock()
	e.servers = append(e.servers, s)
	e.mu.Unlock()
	tg, _, err := e.inv.CreateTarget(e.ctx, e.admin, inventory.NewTarget{Name: name, Type: inventory.TypeNginx, Host: s.host, Port: s.sshPort})
	require.NoError(e.t, err)
	s.target = tg.ID
	e.drain()
	keys, err := e.inv.ListHostKeys(e.ctx, tg.ID)
	require.NoError(e.t, err)
	require.Len(e.t, keys, 1)
	_, err = e.inv.ConfirmHostKey(e.ctx, e.admin, tg.ID, keys[0].ID, keys[0].Fingerprint)
	require.NoError(e.t, err)
	e.drain()
	got, err := e.inv.GetTarget(e.ctx, tg.ID)
	require.NoError(e.t, err)
	require.Equal(e.t, inventory.StatusOK, got.Status, "the server is connected and discovered")
	list, err := e.inv.ListLocations(e.ctx, tg.ID, false)
	require.NoError(e.t, err)
	for _, l := range list.Items {
		s.locs[l.CertPath] = l.ID
	}
	require.Len(e.t, s.locs, len(sites), "every site is a location")
	return s
}

func wwwSite() linuxsshtest.NginxSite {
	return linuxsshtest.NginxSite{Names: []string{wwwName}, Port: 443, CertPath: wwwCert, KeyPath: wwwKey}
}

func apiSite() linuxsshtest.NginxSite {
	return linuxsshtest.NginxSite{Names: []string{apiName}, Port: 443, CertPath: apiCert, KeyPath: apiKey}
}

// upload stores the new certificate with its key.
func (e *env) upload() inventory.Certificate {
	e.t.Helper()
	if e.cert.ID != uuid.Nil {
		return e.cert
	}
	c, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(e.nw.FullchainPEM),
		PrivateKeyPEM: string(e.nw.KeyPEM)})
	require.NoError(e.t, err)
	require.True(e.t, c.ChainComplete)
	e.cert = c
	return c
}

// request asks for the new certificate on the locations and returns the deployments in order.
func (e *env) request(locs ...uuid.UUID) []uuid.UUID {
	e.t.Helper()
	e.evaluate()
	c := e.upload()
	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: locs})
	require.NoError(e.t, err)
	out := make([]uuid.UUID, 0, len(got))
	for _, g := range got {
		out = append(out, g.ID)
	}
	return out
}

// evaluate runs the license evaluation, as a running server does at least hourly in every
// process: tests move the clock by days, and the gate refuses gated work after 3 hours without
// an evaluation (AUD-02).
func (e *env) evaluate() {
	e.t.Helper()
	require.NoError(e.t, e.lic.Tick(e.ctx))
}

// drain runs the license evaluation, then due jobs until none is left.
func (e *env) drain() {
	e.t.Helper()
	e.evaluate()
	for range 50 {
		ran, err := e.runner.RunOnce(e.ctx)
		require.NoError(e.t, err)
		if !ran {
			return
		}
	}
	e.t.Fatal("jobs did not drain")
}

// settle runs the sweep and the jobs, a minute apart on the clock, until the deployment is done.
func (e *env) settle(id uuid.UUID) inventory.Deployment {
	e.t.Helper()
	for range 40 {
		_, err := e.inv.SweepDeployments(e.ctx)
		require.NoError(e.t, err)
		e.drain()
		if d := e.deployment(id); d.State == inventory.DeployStateDone {
			return d
		}
		e.clock.Advance(time.Minute)
	}
	e.t.Fatalf("deployment %s did not end", id)
	return inventory.Deployment{}
}

func (e *env) deployment(id uuid.UUID) inventory.Deployment {
	e.t.Helper()
	d, err := e.inv.Deployment(e.ctx, id)
	require.NoError(e.t, err)
	return d
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, sql, args...).Scan(&n))
	return n
}

func (e *env) audits(action string) int {
	return e.count("SELECT count(*) FROM audit_log WHERE action = $1", action)
}

func (e *env) jobOf(id uuid.UUID) jobs.View {
	e.t.Helper()
	d := e.deployment(id)
	require.NotNil(e.t, d.JobID)
	v, err := e.queue.Get(e.ctx, *d.JobID)
	require.NoError(e.t, err)
	return v
}

func leafOf(t *testing.T, chain []byte) string {
	t.Helper()
	b, _ := pem.Decode(chain)
	require.NotNil(t, b)
	c, err := x509.ParseCertificate(b.Bytes)
	require.NoError(t, err)
	return pki.Fingerprint(c)
}

// assertPair checks the files on the server: a complete pair (the key belongs to the certificate),
// the certificate the record claims (want: e.old or e.nw), and that the website serves exactly it.
func (e *env) assertPair(s *server, certPath, keyPath, sni string, want pki.Leaf) {
	e.t.Helper()
	certPEM, keyPEM := s.emu.NginxFile(certPath), s.emu.NginxFile(keyPath)
	_, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(e.t, err, "the files on the server are a matching pair, never mixed")
	assert.Equal(e.t, pki.Fingerprint(want.Cert), leafOf(e.t, certPEM), "the certificate file holds what the record claims")
	assert.Equal(e.t, pki.Fingerprint(want.Cert), s.emu.Served(443, sni), "the website serves what the record claims")
}

// killer simulates a process kill at injected points: the goroutine running the handler ends at
// once (runtime.Goexit: nothing after the point runs, no outcome is returned to the runner, the
// job stays running with its lease). Goexit runs the handler's deferred calls, which is the one
// difference from a real kill: those defers only zero the key and close the provider session; none
// writes a record or sends a command, so what the database and the server hold afterwards is what
// a SIGKILL at that point leaves. A stalling killer instead blocks the run at the point until the
// test releases it (a process paused past its lease). Points: "before:<Method>" and "after:<Method>" of the
// inventory, "step:<name>:<status>" when a step was recorded, "session:after:<Method>" when a
// provider call returned.
type killer struct {
	points map[string]bool
	fired  atomic.Value  // the point that fired
	panics bool          // panic instead of ending the goroutine (the runner recovers a panic)
	stall  chan struct{} // non-nil: block at the point until closed (reached is closed on arrival)
	reach  chan struct{}
	on     map[string]func() // called at a point (any point name), before the kill check
}

// newStaller returns a killer that pauses the run at point until resume is called.
func newStaller(point string) *killer {
	k := newKiller(point)
	k.stall, k.reach = make(chan struct{}), make(chan struct{})
	return k
}

func (k *killer) resume() { close(k.stall) }

func newKiller(points ...string) *killer {
	k := &killer{points: map[string]bool{}}
	for _, p := range points {
		k.points[p] = true
	}
	return k
}

func (k *killer) at(point string) {
	if fn := k.on[point]; fn != nil {
		fn()
	}
	if k.points[point] && k.fired.Load() == nil {
		k.fired.Store(point)
		if k.stall != nil {
			close(k.reach)
			<-k.stall
			return
		}
		if k.panics {
			panic("killed at " + point)
		}
		runtime.Goexit()
	}
}

func (k *killer) firedAt() string {
	p, _ := k.fired.Load().(string)
	return p
}

// killInv is the inventory of a process that dies at the killer's points.
type killInv struct {
	*inventory.Service
	k *killer
}

func (i killInv) StartDeployment(ctx context.Context, id uuid.UUID, v inventory.SendValues) error {
	i.k.at("before:StartDeployment")
	err := i.Service.StartDeployment(ctx, id, v)
	i.k.at("after:StartDeployment")
	return err
}

func (i killInv) RecordOutcome(ctx context.Context, id uuid.UUID, rec inventory.OutcomeRecord, retryAt time.Time) error {
	i.k.at("before:RecordOutcome")
	return i.Service.RecordOutcome(ctx, id, rec, retryAt)
}

func (i killInv) FinishDeployment(ctx context.Context, id uuid.UUID, f inventory.DeploymentFinish) error {
	i.k.at("before:FinishDeployment")
	return i.Service.FinishDeployment(ctx, id, f)
}

func (i killInv) RecordDeploymentStep(ctx context.Context, id uuid.UUID, name string, status providers.StepStatus, params map[string]string) error {
	i.k.at("before-step:" + name + ":" + string(status))
	err := i.Service.RecordDeploymentStep(ctx, id, name, status, params)
	i.k.at("step:" + name + ":" + string(status))
	return err
}

// killSession is a provider session of a process that dies when a call returned.
type killSession struct {
	providers.Session
	k *killer
}

func (s killSession) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	out, err := s.Session.DeployCertificate(ctx, req, log)
	s.k.at("session:after:DeployCertificate")
	return out, err
}

func (s killSession) RollbackDeployment(ctx context.Context, req providers.RollbackRequest, log providers.StepLogger) (providers.RollbackOutcome, error) {
	out, err := s.Session.RollbackDeployment(ctx, req, log)
	s.k.at("session:after:RollbackDeployment")
	return out, err
}

// runDying runs one job in a process that dies at k's points: a runner of its own (its heartbeat
// never beats on the fake clock), its handlers on the killing inventory and sessions. It returns
// once the job's goroutine ended (killed or not).
func (e *env) runDying(k *killer) {
	e.t.Helper()
	select {
	case <-e.startDying(k):
	case <-time.After(time.Minute):
		e.t.Fatal("the dying process did not end")
	}
}

// startDying starts one job in a separate process (see runDying) and returns when it ends.
func (e *env) startDying(k *killer) <-chan struct{} {
	e.t.Helper()
	r := jobs.NewRunner(jobs.RunnerConfig{Pool: e.db.App, Queue: e.queue, Gate: e.gate, Audit: e.audit, Clock: e.clock,
		Log: e.log(), Workers: 1, WorkerID: "dying", Heartbeat: 24 * time.Hour, Jitter: func() float64 { return 0 },
		Notifier: notify.ServiceNotifier{Clock: e.clock}})
	reg := providers.NewRegistry()
	reg.Register(hookProvider{Provider: e.prov, wrap: func(_ providers.TargetRef, s providers.Session) providers.Session {
		return killSession{Session: s, k: k}
	}})
	reg.Register(winHookProvider{Provider: e.win, wrap: func(_ providers.TargetRef, s providers.Session) providers.Session {
		return killSession{Session: s, k: k}
	}})
	reg.Register(e.az)
	reg.Freeze()
	targetjobs.Register(r, targetjobs.Deps{Inventory: e.inv, Registry: e.reg, Clock: e.clock})
	Register(r, Deps{Inventory: killInv{Service: e.inv, k: k}, Registry: reg, Clock: e.clock, Log: e.log()})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.RunOnce(e.ctx)
	}()
	return done
}

// restart is Alice starting again after a kill: the lease of the killed job expires, the
// startup pass re-queues (or ends) it.
func (e *env) restart() {
	e.t.Helper()
	e.clock.Advance(46 * time.Second)
	_, err := e.runner.Recover(e.ctx)
	require.NoError(e.t, err)
}

// winHookProvider lets a test wrap the sessions the Windows provider opens (the same switch as hookProvider).
type winHookProvider struct {
	*windows.Provider
	wrap func(providers.TargetRef, providers.Session) providers.Session
}

func (p winHookProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil || p.wrap == nil {
		return s, err
	}
	return p.wrap(t, s), nil
}

// winServer is one emulated Windows server (wintest's model behind its SSH server, which runs in the mode of
// Windows OpenSSH) and its target: IIS with the site "Default Web Site" whose https binding *:443:www.example.test
// is the http.sys hostnameport record www.example.test:443 in My, serving the old certificate.
type winServer struct {
	model   *wintest.Model
	srv     *linuxsshtest.Server
	host    string
	sshPort int
	target  uuid.UUID
	loc     uuid.UUID // the location of the binding (winText)
	locator winproto.Locator
	oldSHA1 string
}

// winText is the canonical text (the location's cert path) of the emulated binding.
const winText = "http.sys/hostnameport/" + wwwName + ":443"

func (e *env) winList() []*winServer {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.wins)
}

// addWinServer starts an emulated Windows server, adds it as a target, confirms its host key and runs the first
// connection test and discovery: the binding is a deployable location.
func (e *env) addWinServer(name string) *winServer {
	e.t.Helper()
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(e.t, err)
	m := wintest.NewModel()
	m.SetLockWait(50 * time.Millisecond) // BUSY in milliseconds, not winproto.LockWait
	m.AddIntermediate(e.ca.IntermediatePEM)
	s := &winServer{model: m, locator: winproto.Locator{Type: winproto.BindingHostnamePort, Host: wwwName, Port: 443, AppID: winproto.AppIDIIS}}
	s.oldSHA1 = m.AddCertificate("My", e.old.CertPEM, e.old.KeyPEM, wintest.CertOptions{FriendlyName: "www"})
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: wwwName, Port: 443, AppID: winproto.AppIDIIS,
		CertSHA1: s.oldSHA1, Store: "My"})
	m.AddSite(winproto.Site{Name: "Default Web Site", ID: 1, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:443:" + wwwName, SSLFlags: 1}}})
	s.srv = wintest.NewServer(e.t, m) // after the binding: its TLS listener starts with the server
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk.PublicKey))
	require.NoError(e.t, err)
	s.srv.Authorize(pub)
	s.host, s.sshPort = s.srv.Addr()
	e.mu.Lock()
	e.wins = append(e.wins, s)
	e.mu.Unlock()
	tg, _, err := e.inv.CreateTarget(e.ctx, e.admin, inventory.NewTarget{Name: name, Type: inventory.TypeWindows, Host: s.host, Port: s.sshPort})
	require.NoError(e.t, err)
	s.target = tg.ID
	e.drain()
	keys, err := e.inv.ListHostKeys(e.ctx, tg.ID)
	require.NoError(e.t, err)
	require.Len(e.t, keys, 1)
	_, err = e.inv.ConfirmHostKey(e.ctx, e.admin, tg.ID, keys[0].ID, keys[0].Fingerprint)
	require.NoError(e.t, err)
	e.drain()
	got, err := e.inv.GetTarget(e.ctx, tg.ID)
	require.NoError(e.t, err)
	require.Equal(e.t, inventory.StatusOK, got.Status, "the Windows server is connected and discovered")
	list, err := e.inv.ListLocations(e.ctx, tg.ID, false)
	require.NoError(e.t, err)
	for _, l := range list.Items {
		if l.CertPath == winText {
			require.True(e.t, l.Deployable, "the binding is deployable: %s", l.UnsupportedReason)
			s.loc = l.ID
		}
	}
	require.NotEqual(e.t, uuid.Nil, s.loc, "the binding is a location")
	return s
}

// winProber is Alice's own TLS probe against the emulated Windows servers: a probe of a binding port reaches the
// model's listener for it (Model.Endpoint), with a fresh handshake (no session cache). Every emulated server listens on
// 127.0.0.1, so with several Windows servers Alice's probe cannot tell which one it would reach: it is then unreachable
// and the helper's tls-probe decides.
type winProber struct{ wins func() []*winServer }

func (p winProber) Probe(ctx context.Context, _ string, port int, sni, keyType string) (tlsverify.Probe, error) {
	wins := p.wins()
	if len(wins) != 1 {
		return tlsverify.Probe{}, tlsverify.ErrProbeUnreachable
	}
	ep := wins[0].model.Endpoint(port)
	if ep == "" {
		return tlsverify.Probe{}, tlsverify.ErrProbeUnreachable
	}
	cfg := helperproto.ProbeTLSConfig(sni, keyType)
	cfg.ClientSessionCache, cfg.SessionTicketsDisabled = nil, true
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", ep)
	if err != nil {
		return tlsverify.Probe{}, fmt.Errorf("%w: %w", tlsverify.ErrProbeFailed, err)
	}
	defer func() { _ = conn.Close() }()
	cs := conn.(*tls.Conn).ConnectionState()
	chain := make([][]byte, 0, len(cs.PeerCertificates))
	for _, c := range cs.PeerCertificates {
		chain = append(chain, c.Raw)
	}
	return tlsverify.Probe{LeafSHA256: pki.Fingerprint(cs.PeerCertificates[0]), ChainLength: len(chain), NotAfter: cs.PeerCertificates[0].NotAfter,
		Chain: chain}, nil
}

// winDriftWorld is the Windows ACME world of TestWindowsACMEAutomaticDeployment (the ACME world with an emulated Windows
// server whose IIS binding is the ACME certificate's location) with the drift work (driftjobs: the drift.observe handler,
// the drift.schedule and drift.repair tasks) and the certificate cleanup (winjobs: the windows.cleanup handler) on the
// same runner. The driftWorld it embeds watches the binding, so its observe, observation, repairNow, setMode and mails
// are the binding's. The ACME certificate (C2) is issued and deployed to the binding by the planner and the engine; the
// certificate the binding named before Alice (e.old, C1) is what another tool binds again. The fake CA's leaves live 90
// days here, so a renewal (renewEarly) and the cleanup's week after it pass before C2 expires (the helper removes an
// expired certificate without waiting). The helper's clock starts at Alice's.
type winDriftWorld struct {
	*driftWorld
	win    *winServer
	c2SHA1 string // C2's thumbprint, as the binding names it
}

func newWinDriftWorld(t *testing.T) *winDriftWorld {
	t.Helper()
	w := newACMEWorld(t)
	require.NoError(t, w.fake.SetLeafLifetime(90*24*time.Hour))
	driftjobs.Register(w.runner, driftjobs.Deps{Inventory: w.inv, Registry: w.reg, Clock: w.clock, Log: w.log()})
	winjobs.Register(w.runner, winjobs.Deps{Inventory: w.inv, Registry: w.reg, Clock: w.clock, Log: w.log()})
	s := w.addWinServer("iis-01")
	s.model.SetNow(w.clock.Now())
	w.loc = s.loc // the ACME world's location is the binding from here on
	d := &driftWorld{acmeWorld: w, schedule: driftjobs.ScheduleTask(w.inv, time.Minute, w.log()),
		repair: driftjobs.RepairTask(w.inv, time.Minute, w.log())}
	d.acme, d.c2 = w.issueFirst()
	require.Equal(t, d.c2, s.served(), "the binding serves C2")
	return &winDriftWorld{driftWorld: d, win: s, c2SHA1: s.bound()}
}

// repoint is another tool binding the certificate sha1 (in My) to the binding, as netsh http update sslcert would.
func (w *winDriftWorld) repoint(sha1 string) {
	w.t.Helper()
	b, ok := w.win.model.Binding(w.win.locator)
	require.True(w.t, ok)
	b.CertSHA1 = sha1
	require.NoError(w.t, w.win.model.Host().UpdateBinding(context.Background(), b))
}

// renewEarly renews the ACME certificate as soon as it is due (a 90-day leaf is due 30 days before its end), lets the
// planner and the engine deploy the renewal (C3) over C2, and sets the helper's clock to Alice's. It returns C3 and its
// fingerprint.
func (w *winDriftWorld) renewEarly() (uuid.UUID, string) {
	w.t.Helper()
	old, _ := w.current(w.acme.ID)
	var na time.Time
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT not_after FROM certificates WHERE id = $1", old).Scan(&na))
	w.setClock(na.Add(-30*24*time.Hour + time.Hour))
	require.NoError(w.t, w.acmeWorld.schedule.Run(w.ctx))
	w.drain()
	cur, fp := w.current(w.acme.ID)
	require.NotEqual(w.t, old, cur, "renewed")
	ids := w.planDeploy(cur)
	require.Len(w.t, ids, 1)
	w.drain()
	d := w.deployment(ids[0])
	require.Equal(w.t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	require.Equal(w.t, inventory.TriggerACMERenewal, d.Trigger)
	require.Equal(w.t, fp, w.win.served(), "C3 serves")
	w.win.model.SetNow(w.clock.Now())
	return cur, fp
}

// cleanupNow queues a windows.cleanup of the Windows server (as windows.cleanup_schedule does, without its once a day)
// and runs it; it returns the job's status and result.
func (e *env) cleanupNow(s *winServer) (string, map[string]any) {
	e.t.Helper()
	e.evaluate()
	id, _, err := e.queue.Enqueue(e.ctx, jobs.Spec{Type: jobs.WindowsCleanup, TargetID: s.target, Payload: map[string]string{},
		Kind: jobs.KindScheduled, DedupeKey: "windows.cleanup:test:" + uuid.NewString()})
	require.NoError(e.t, err)
	e.drain()
	var status string
	var raw []byte
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT status, result FROM jobs WHERE id = $1", id).Scan(&status, &raw))
	var out map[string]any
	require.NoError(e.t, json.Unmarshal(raw, &out))
	return status, out
}

// keptReasons maps the DER SHA-256 of every certificate a cleanup result keeps to its reason.
func keptReasons(res map[string]any) map[string]string {
	out := map[string]string{}
	list, _ := res["kept"].([]any)
	for _, k := range list {
		m, _ := k.(map[string]any)
		fp, _ := m["sha256"].(string)
		reason, _ := m["reason"].(string)
		out[fp] = reason
	}
	return out
}

// helperVerdict asks the helper itself, through a provider session of its own, to remove the certificate (reason aged)
// and returns its answer: the helper judges every rule again under its lock, so a certificate in use, not Alice's or not
// unused long enough is kept with the helper's reason (and one that may go is removed).
func (e *env) helperVerdict(s *winServer, store, sha1, sha256 string) providers.CleanupItemResult {
	e.t.Helper()
	ref, _, err := e.inv.TargetRef(e.ctx, s.target)
	require.NoError(e.t, err)
	sess, err := e.win.Open(e.ctx, ref, e.inv.Credentials(), providers.Env{Clock: e.clock, HostKeys: e.inv.HostKeyStore(), Log: e.log()})
	require.NoError(e.t, err)
	defer func() { require.NoError(e.t, sess.Close()) }()
	cleaner, ok := sess.(providers.CertificateCleaner)
	require.True(e.t, ok)
	res, err := cleaner.ApplyCleanup(e.ctx, []providers.CleanupItem{{Store: store, SHA1: sha1, SHA256: sha256, Reason: providers.CleanupAged}})
	require.NoError(e.t, err)
	require.Len(e.t, res.Results, 1)
	return res.Results[0]
}
