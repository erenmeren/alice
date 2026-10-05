//go:build integration

package sshkeyjobs_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/sshkeyjobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/sshkeys"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var start = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// runTimeout only guards against a test that hangs for good (a bug): a FaultHang call is ended by the
// harness itself, which ends the job's context when the fault fires (F10, review I8), so no run of the
// suite depends on how fast the machine is.
const runTimeout = 2 * time.Minute

// lockGate is the license service with a switch that puts it in lock. It does not ask the real
// service: the tests move the clock by days, after which the service would say the license was not
// checked recently.
type lockGate struct {
	*license.Service
	locked atomic.Bool
}

func (g *lockGate) Allow(c license.Class) error {
	if g.locked.Load() && c != license.ClassAlways {
		return license.ErrLocked
	}
	return nil
}

func (g *lockGate) lock()   { g.locked.Store(true) }
func (g *lockGate) unlock() { g.locked.Store(false) }

// recordingNotifier records every NotifyAdmins call and queues the email in the outbox as production does.
type recordingNotifier struct {
	mu    sync.Mutex
	calls []notice
	next  notify.AdminNotifier
}

type notice struct {
	template string
	params   map[string]string
}

func (r *recordingNotifier) NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	if err := r.next.NotifyAdmins(ctx, tx, template, params); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, notice{template: template, params: params})
	return nil
}

type env struct {
	t          *testing.T
	ctx        context.Context
	db         *pgtest.DB
	clock      *clock.Fake
	tick       *tickClock // the services' clock: e.clock, moving 1 ms on every read while ticking
	keyring    *secrets.Keyring
	audit      *audit.Log
	gate       *lockGate
	queue      *jobs.Queue
	inv        *inventory.Service
	notifier   *recordingNotifier
	keys       *sshkeys.Service
	world      *fake.KeyWorld
	provider   *fake.Provider
	reg        *providers.Registry
	runner     *jobs.Runner
	log        *slog.Logger
	platform   inventory.PlatformKey
	operator   inventory.Actor
	admin      inventory.Actor
	adminID    uuid.UUID
	adminAudit audit.Actor
	killer     atomic.Pointer[killer] // the process dies at its points (setKiller)
	cancelJob  atomic.Pointer[context.CancelFunc]
	jobSeq     atomic.Int64 // the current run of a job (RunOnce), for the call log
	jobsMu     sync.Mutex
	undoJobs   map[int64]bool // runs that began an undo (BeginUndo answered)
	lockJobs   map[int64]bool // runs in whose calls the licence lock began (their sends were in flight)
	fault      atomic.Pointer[func(fake.FaultPoint) fake.Fault]
	callsMu    sync.Mutex
	calls      map[int]callInfo
	// unprotected counts Add and Remove requests that did not carry Alice's own fingerprint among the
	// protected ones (review I7): every test fails when one did.
	unprotected atomic.Int32
}

// jobContext is the context of one RunOnce; a FaultHang ends it (the job's own deadline, F-39).
func (e *env) jobContext() (context.Context, context.CancelFunc) {
	e.jobSeq.Add(1)
	ctx, cancel := context.WithTimeout(e.ctx, runTimeout)
	e.cancelJob.Store(&cancel)
	return ctx, cancel
}

// callInfo is what the harness notes about one world call: the test clock when the call proceeds and
// whether the licence gate was locked when it began (a lock that fires in the call does not count for it).
type callInfo struct {
	begun  time.Time // when the call began (the time the sender's checks saw)
	at     time.Time // when the call proceeded, after the events injected in it (a clock step is not time the call took)
	locked bool
	job    int64 // the run of a job (RunOnce) that made the call
}

// setFault installs the test's fault decision (nil: none) behind the harness's own hook.
func (e *env) setFault(f func(fake.FaultPoint) fake.Fault) {
	if f == nil {
		e.fault.Store(nil)
		return
	}
	e.fault.Store(&f)
}

// hook is the world's fault decision for every test: it notes each call (callInfo), asks the test's
// decision, and ends the running job's context at once for a FaultHang, as the job's deadline would end it
// on a slow host (no wall clock involved).
func (e *env) hook(p fake.FaultPoint) fake.Fault {
	locked, begun := e.gate.locked.Load(), e.clock.Now()
	x := fake.FaultNone
	if f := e.fault.Load(); f != nil {
		x = (*f)(p)
	}
	// The time is read after the call's own events: a clock step injected in the call is a step of the
	// clock, not time the call took.
	e.callsMu.Lock()
	e.calls[p.N] = callInfo{begun: begun, at: e.clock.Now(), locked: locked, job: e.jobSeq.Load()}
	e.callsMu.Unlock()
	if x == fake.FaultHang {
		if c := e.cancelJob.Load(); c != nil {
			(*c)()
		}
	}
	return x
}

// call is what the harness noted about the world's n-th call.
func (e *env) call(n int) callInfo {
	e.callsMu.Lock()
	defer e.callsMu.Unlock()
	return e.calls[n]
}

func newEnv(t *testing.T) *env { t.Helper(); return newEnvWith(t, nil) }

// newEnvWith builds the environment; real, when set, registers the providers instead of the fake key
// world (it runs after the inventory exists: a real provider needs its host-key store).
func newEnvWith(t *testing.T, real func(e *env)) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), db: pgtest.New(t), clock: clock.NewFake(start), world: fake.NewKeyWorld()}
	e.tick = &tickClock{Fake: e.clock}
	// A lock-order mistake fails fast with SQLSTATE 55P03 instead of hanging the suite.
	var dbName string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT current_database()").Scan(&dbName))
	_, err := e.db.Owner.Exec(e.ctx, "ALTER DATABASE "+pgx.Identifier{dbName}.Sanitize()+" SET lock_timeout = '60s'")
	require.NoError(t, err)
	e.db.App.Reset()
	e.dropAtEnd()
	e.world.SetClock(e.clock.Now) // FaultLateWrite follows the test clock
	e.calls = map[int]callInfo{}
	e.undoJobs, e.lockJobs = map[int64]bool{}, map[int64]bool{}
	e.world.SetFault(e.hook)
	e.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	e.keyring, err = secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, t.TempDir(), e.clock.Now())
	require.NoError(t, err)
	e.audit = audit.New(e.tick)
	lic := license.New(license.Config{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.tick, Uptime: e.tick,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), Targets: inventory.Counter{}, Notifier: notify.AdminNotifier{Clock: e.tick}, Log: e.log})
	require.NoError(t, lic.Start(e.ctx))
	e.gate = &lockGate{Service: lic}
	e.notifier = &recordingNotifier{next: notify.AdminNotifier{Clock: e.tick}}
	e.queue = jobs.NewQueue(jobs.QueueConfig{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.tick, Gate: e.gate})
	e.provider = fake.New(providers.KindLinuxSSH, providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
		providers.CapKeyLogin)
	e.provider.Configure(func(c *fake.Config) { c.World = e.world })
	e.reg = providers.NewRegistry()
	e.inv = inventory.New(inventory.Config{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.tick, License: e.gate,
		Registry: e.reg, Jobs: e.queue, Notifier: notify.AdminNotifier{Clock: e.tick}, Log: e.log})
	if real != nil {
		real(e)
	} else {
		e.reg.Register(hookProvider{Provider: e.provider, e: e})
	}
	e.reg.Freeze()
	e.platform, err = e.inv.EnsurePlatformKey(e.ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		if n := e.unprotected.Load(); n > 0 {
			t.Errorf("%d add or remove requests did not protect Alice's own key", n)
		}
	})
	e.keys = sshkeys.New(sshkeys.Config{HelperBudget: helperproto.HelperBudget, Pool: e.db.App, Keyring: e.keyring, Audit: e.audit,
		Clock: e.tick, License: e.gate, Inventory: e.inv, Jobs: e.queue, Notifier: e.notifier, Log: e.log})
	// The heartbeat never beats on the fake clock: a lease ends only when a test moves the clock past it.
	e.runner = jobs.NewRunner(jobs.RunnerConfig{Pool: e.db.App, Queue: e.queue, Gate: e.gate, Audit: e.audit, Clock: e.tick, Log: e.log,
		Workers: 1, WorkerID: "alice", Heartbeat: 24 * time.Hour, Jitter: func() float64 { return 0 },
		Notifier: notify.AdminNotifier{Clock: e.tick}})
	sshkeyjobs.Register(e.runner, sshkeyjobs.Deps{Keys: killKeys{Service: e.keys, e: e}, Targets: e.inv, Registry: e.reg, Clock: e.tick,
		Log: e.log, Gate: e.gate})
	e.admin = e.user("ada", rbac.Admin)
	e.adminID, e.adminAudit = e.admin.UserID, e.admin.Audit
	e.operator = e.user("oscar", rbac.Operator)
	return e
}

func (e *env) user(name string, role rbac.Role) inventory.Actor {
	e.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'x', $5, $6, $6)`, id, name, name+"@example.com", name, string(role), e.clock.Now())
	require.NoError(e.t, err)
	return inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: name, RequestID: uuid.NewString()}, UserID: id, Role: role}
}

// keyFile is a user's authorized_keys file on the servers of these tests.
func keyFile(user string) string {
	if user == "root" {
		return "/root/.ssh/authorized_keys"
	}
	return "/home/" + user + "/.ssh/authorized_keys"
}

// serverUsers are the accounts every test server has, each reading its own key file; the connection
// account alice-svc holds Alice's platform key.
var serverUsers = []string{"deploy", "app", "root", fake.ConnectionAccount}

// server adds a confirmed, connected Linux target whose last scan read sshd and listed every user's key
// files completely, and builds it in the world: an empty key file per user, the platform key's line in
// the connection account's file.
func (e *env) server(name string, extra ...providers.UserKeyFiles) uuid.UUID {
	e.t.Helper()
	files := []providers.UserKeyFiles{}
	for _, u := range serverUsers {
		files = append(files, providers.UserKeyFiles{OSUser: u, Files: []string{keyFile(u)}, Complete: true})
	}
	files = append(files, extra...)
	facts, err := json.Marshal(inventory.Facts{SSHD: &providers.SSHDSummary{Read: true, PubkeyAuthentication: "yes",
		PermitRootLogin: "prohibit-password", AuthorizedKeysFile: []string{".ssh/authorized_keys"}, AuthorizedKeysCommand: "none"},
		KeyFiles: files})
	require.NoError(e.t, err)
	id := uuid.Must(uuid.NewV7())
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, facts, created_at, updated_at)
VALUES ($1, $2, 'linux', jsonb_build_object('host', $3::text, 'port', 22, 'username', 'alice-svc'), $4, 'ok', $5, $6, $6)`,
		id, name, name+".example.com", e.platform.ID, facts, e.clock.Now())
	require.NoError(e.t, err)
	for _, u := range serverUsers {
		if u == fake.ConnectionAccount {
			e.world.Put(id, u, keyFile(u), e.platform.PublicKey)
			continue
		}
		e.world.Put(id, u, keyFile(u))
	}
	return id
}

func (e *env) generate(label string) sshkeys.ManagedKey {
	e.t.Helper()
	for {
		k, err := e.keys.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: label})
		if errors.Is(err, sshkeys.ErrGenerateBusy) { // parallel scenarios share the process's generation slots
			time.Sleep(5 * time.Millisecond)
			continue
		}
		require.NoError(e.t, err)
		return k
	}
}

// dropAtEnd drops the test's database when the test ends (the property test makes hundreds).
func (e *env) dropAtEnd() {
	e.t.Cleanup(func() {
		e.db.App.Close()
		e.db.Owner.Close()
		u, err := url.Parse(e.db.OwnerURL)
		if err != nil {
			return
		}
		name := strings.TrimPrefix(u.Path, "/")
		u.Path = "/postgres"
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, u.String())
		if err != nil {
			return
		}
		defer func() { _ = conn.Close(ctx) }()
		_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})
}

// otherKeyLine is the authorized_keys line of a fresh key nobody manages.
func (e *env) otherKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sp, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " someone@laptop"
}

func (e *env) job(id uuid.UUID) jobs.View {
	e.t.Helper()
	v, err := e.queue.Get(e.ctx, id)
	require.NoError(e.t, err)
	return v
}

// events are the world's calls of the method (late landings left out).
func (e *env) events(method string) []fake.Event {
	var out []fake.Event
	for _, ev := range e.world.Events() {
		if ev.Method == method && !ev.Landed {
			out = append(out, ev)
		}
	}
	return out
}

func (e *env) countEvents(method string) int { return len(e.events(method)) }

// worldCalls is the number of Add, Remove and VerifyKeyLogin calls the world answered so far.
func (e *env) worldCalls() int {
	n := 0
	for _, ev := range e.world.Events() {
		if !ev.Landed {
			n++
		}
	}
	return n
}

func (e *env) targetStatus(id uuid.UUID) string {
	e.t.Helper()
	tg, err := e.inv.GetTarget(e.ctx, id)
	require.NoError(e.t, err)
	return tg.Status
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

// lastAuditDetail is one details value of the newest audit row of the action ("" when none).
func (e *env) lastAuditDetail(action, key string) string {
	e.t.Helper()
	var v *string
	err := e.db.Owner.QueryRow(e.ctx, "SELECT details->>$2 FROM audit_log WHERE action = $1 ORDER BY seq DESC LIMIT 1", action, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && v == nil) {
		return ""
	}
	require.NoError(e.t, err)
	return *v
}

// runOnce runs one due job under the per-call timeout (F10).
func (e *env) runOnce() bool {
	e.t.Helper()
	ctx, cancel := e.jobContext()
	defer cancel()
	ran, err := e.runner.RunOnce(ctx)
	require.NoError(e.t, err)
	return ran
}

// drain runs due jobs until none is left.
func (e *env) drain() {
	e.t.Helper()
	for range 200 {
		if !e.runOnce() {
			return
		}
	}
	e.t.Fatal("jobs did not drain")
}

// restart is Alice starting again after a kill: the killed job's lease expires and the startup pass
// re-queues (or ends) it.
func (e *env) restart() {
	e.t.Helper()
	e.clock.Advance(46 * time.Second)
	_, err := e.runner.Recover(e.ctx)
	require.NoError(e.t, err)
}

// killer simulates a process kill at injected points: the goroutine running the handler ends at once
// (runtime.Goexit: nothing after the point runs, no outcome reaches the runner, the job stays running
// with its lease). Goexit runs the handler's deferred calls, which only close the provider session; none
// writes a record or sends a command, so what the database and the world hold afterwards is what a
// SIGKILL at that point leaves. Points: "before:<Method>" and "after:<Method>" of the Keys interface,
// "session:after:<Method>" when a provider call returned. afterCall > 0 kills at the first
// "session:after:" point once the world answered that many calls.
type killer struct {
	points    map[string]bool
	afterCall int
	calls     func() int
	fired     atomic.Value      // the point that fired
	on        map[string]func() // called at a point (any point name), before the kill check
}

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
	if k.fired.Load() != nil {
		return
	}
	hit := k.points[point]
	if !hit && k.afterCall > 0 && strings.HasPrefix(point, "session:after:") && k.calls() >= k.afterCall {
		hit = true
	}
	if hit {
		k.fired.Store(point)
		runtime.Goexit()
	}
}

func (k *killer) firedAt() string {
	p, _ := k.fired.Load().(string)
	return p
}

// setKiller installs k in the Keys and session wrappers (nil removes it).
func (e *env) setKiller(k *killer) {
	if k != nil && k.afterCall > 0 && k.calls == nil {
		k.calls = e.worldCalls
	}
	e.killer.Store(k)
}

func (e *env) at(point string) {
	if k := e.killer.Load(); k != nil {
		k.at(point)
	}
}

// drainDying runs jobs, each in a goroutine of its own, until none is due or the killer fired (the
// process died: the rest of the queue waits for the restart).
func (e *env) drainDying() {
	e.t.Helper()
	for range 200 {
		var ran bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			ctx, cancel := e.jobContext()
			defer cancel()
			ran, _ = e.runner.RunOnce(ctx)
		}()
		select {
		case <-done:
		case <-time.After(time.Minute):
			e.t.Fatal("the dying process did not end")
		}
		if k := e.killer.Load(); (k != nil && k.firedAt() != "") || !ran {
			return
		}
	}
	e.t.Fatal("jobs did not drain")
}

// hookProvider wraps every session the fake opens in a killSession.
type hookProvider struct {
	*fake.Provider
	e *env
}

func (p hookProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, env providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, env)
	if err != nil {
		return s, err
	}
	return killSession{Session: s, e: p.e}, nil
}

// killSession is a provider session of a process that may die when a call returned.
type killSession struct {
	providers.Session
	e *env
}

func (s killSession) protects(req providers.AuthKeyChange) {
	if !slices.Contains(req.ProtectedFingerprints, s.e.platform.Fingerprint) {
		s.e.unprotected.Add(1)
	}
}

func (s killSession) AddAuthorizedKey(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	s.protects(req)
	res, err := s.Session.AddAuthorizedKey(ctx, req, log)
	s.e.at("session:after:AddAuthorizedKey")
	return res, err
}

func (s killSession) RemoveAuthorizedKey(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	s.protects(req)
	res, err := s.Session.RemoveAuthorizedKey(ctx, req, log)
	s.e.at("session:after:RemoveAuthorizedKey")
	return res, err
}

func (s killSession) VerifyKeyLogin(ctx context.Context, req providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
	res, err := s.Session.VerifyKeyLogin(ctx, req)
	s.e.at("session:after:VerifyKeyLogin")
	return res, err
}

func (s killSession) ListKeys(ctx context.Context) (providers.KeyListing, error) {
	res, err := s.Session.ListKeys(ctx)
	s.e.at("session:after:ListKeys")
	return res, err
}

// killKeys is the SSH key module of a process that may die before or after each of its calls.
type killKeys struct {
	*sshkeys.Service
	e *env
}

func (k killKeys) DeployJob(ctx context.Context, jobID, targetID uuid.UUID, payload map[string]string) (sshkeys.DeployJob, error) {
	k.e.at("before:DeployJob")
	d, err := k.Service.DeployJob(ctx, jobID, targetID, payload)
	k.e.at("after:DeployJob")
	return d, err
}

func (k killKeys) FinishDeploy(ctx context.Context, actor audit.Actor, d sshkeys.DeployJob, out sshkeys.DeployOutcome) error {
	k.e.at("before:FinishDeploy")
	err := k.Service.FinishDeploy(ctx, actor, d, out)
	k.e.at("after:FinishDeploy")
	return err
}

func (k killKeys) BeginDeploySendWith(ctx context.Context, jobID uuid.UUID, d sshkeys.DeployJob, before sshkeys.DeployEvidence) (sshkeys.DeploySend, error) {
	k.e.at("before:BeginDeploySend")
	s, err := k.Service.BeginDeploySendWith(ctx, jobID, d, before)
	k.e.at("after:BeginDeploySend")
	return s, err
}

func (k killKeys) LocationWork(ctx context.Context, id uuid.UUID) (sshkeys.LocationWork, error) {
	k.e.at("before:LocationWork")
	w, err := k.Service.LocationWork(ctx, id)
	k.e.at("after:LocationWork")
	return w, err
}

func (k killKeys) BeginAdd(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	k.e.at("before:BeginAdd")
	op, err := k.Service.BeginAdd(ctx, id)
	k.e.at("after:BeginAdd")
	return op, err
}

func (k killKeys) FinishAdd(ctx context.Context, id uuid.UUID, r sshkeys.AddRecord) error {
	k.e.at("before:FinishAdd")
	err := k.Service.FinishAdd(ctx, id, r)
	k.e.at("after:FinishAdd")
	return err
}

func (k killKeys) RecordVerify(ctx context.Context, id uuid.UUID, r sshkeys.VerifyRecord) error {
	k.e.at("before:RecordVerify")
	err := k.Service.RecordVerify(ctx, id, r)
	k.e.at("after:RecordVerify")
	return err
}

func (k killKeys) RecordReverify(ctx context.Context, id uuid.UUID, r sshkeys.VerifyRecord) error {
	k.e.at("before:RecordReverify")
	err := k.Service.RecordReverify(ctx, id, r)
	k.e.at("after:RecordReverify")
	return err
}

func (k killKeys) BeginRemove(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	k.e.at("before:BeginRemove")
	op, err := k.Service.BeginRemove(ctx, id)
	k.e.at("after:BeginRemove")
	return op, err
}

func (k killKeys) FinishRemove(ctx context.Context, actor audit.Actor, id uuid.UUID, r sshkeys.RemoveRecord) error {
	k.e.at("before:FinishRemove")
	err := k.Service.FinishRemove(ctx, actor, id, r)
	k.e.at("after:FinishRemove")
	return err
}

func (k killKeys) BeginUndo(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	k.e.at("before:BeginUndo")
	op, err := k.Service.BeginUndo(ctx, id)
	if err == nil {
		k.e.jobsMu.Lock()
		k.e.undoJobs[k.e.jobSeq.Load()] = true
		k.e.jobsMu.Unlock()
	}
	k.e.at("after:BeginUndo")
	return op, err
}

func (k killKeys) FinishUndo(ctx context.Context, actor audit.Actor, id uuid.UUID, r sshkeys.UndoRecord) error {
	k.e.at("before:FinishUndo")
	err := k.Service.FinishUndo(ctx, actor, id, r)
	k.e.at("after:FinishUndo")
	return err
}

func (k killKeys) Advance(ctx context.Context, id uuid.UUID) error {
	k.e.at("before:Advance")
	err := k.Service.Advance(ctx, id)
	k.e.at("after:Advance")
	return err
}

// tickClock is the services' clock: the test's fake clock, which moves one millisecond on every read
// while ticking is on, as a real clock does between two reads (a frozen clock hides a join on two
// separate clock reads: Task 9 re-review C1).
type tickClock struct {
	*clock.Fake
	on atomic.Bool
}

func (c *tickClock) Now() time.Time {
	if c.on.Load() {
		c.Advance(time.Millisecond)
	}
	return c.Fake.Now()
}

// setKeyFiles replaces the key files the server's last scan listed.
func (e *env) setKeyFiles(target uuid.UUID, files []providers.UserKeyFiles) {
	e.t.Helper()
	raw, err := json.Marshal(files)
	require.NoError(e.t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE targets SET facts = jsonb_set(facts, '{key_files}', $2::jsonb) WHERE id = $1", target, string(raw))
	require.NoError(e.t, err)
}

// lockNow locks the licence gate and notes the job run in flight, if any (its sends may finish: L-85).
func (e *env) lockNow(inCall bool) {
	if inCall {
		e.jobsMu.Lock()
		e.lockJobs[e.jobSeq.Load()] = true
		e.jobsMu.Unlock()
	}
	e.gate.lock()
}

// allowedInLock reports whether a call made while locked belongs to a job run that was in flight when the
// lock began, or to an undo (L-86).
func (e *env) allowedInLock(c callInfo) bool {
	e.jobsMu.Lock()
	defer e.jobsMu.Unlock()
	return e.lockJobs[c.job] || e.undoJobs[c.job]
}
