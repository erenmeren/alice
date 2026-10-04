//go:build integration

package targetjobs_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
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
	"alice/internal/jobs/targetjobs"
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

type env struct {
	t      *testing.T
	ctx    context.Context
	db     *pgtest.DB
	clock  *clock.Fake
	lic    *license.Service
	prov   *fake.Provider
	queue  *jobs.Queue
	runner *jobs.Runner
	inv    *inventory.Service
	admin  inventory.Actor
}

// wrapProvider lets a test replace the sessions the fake provider opens.
type wrapProvider struct {
	*fake.Provider
	wrap func(providers.Session) providers.Session
}

func (w wrapProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := w.Provider.Open(ctx, t, c, e)
	if err != nil || w.wrap == nil {
		return s, err
	}
	return w.wrap(s), nil
}

func newEnv(t *testing.T, wrap func(providers.Session) providers.Session) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), db: pgtest.New(t), clock: clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keyring, err := secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, t.TempDir(), e.clock.Now())
	require.NoError(t, err)
	auditLog := audit.New(e.clock)
	e.lic = license.New(license.Config{Pool: e.db.App, Keyring: keyring, Audit: auditLog, Clock: e.clock, Uptime: e.clock,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), Targets: inventory.Counter{}, Log: log})
	require.NoError(t, e.lic.Start(e.ctx))
	e.prov = fake.New(providers.KindLinuxSSH)
	reg := providers.NewRegistry()
	reg.Register(wrapProvider{Provider: e.prov, wrap: wrap})
	reg.Freeze()
	e.queue = jobs.NewQueue(jobs.QueueConfig{Pool: e.db.App, Keyring: keyring, Audit: auditLog, Clock: e.clock, Gate: e.lic})
	e.inv = inventory.New(inventory.Config{Pool: e.db.App, Keyring: keyring, Audit: auditLog, Clock: e.clock, License: e.lic,
		Registry: reg, Jobs: e.queue, Notifier: notify.AdminNotifier{Clock: e.clock}, Log: log})
	_, err = e.inv.EnsurePlatformKey(e.ctx)
	require.NoError(t, err)
	e.runner = jobs.NewRunner(jobs.RunnerConfig{Pool: e.db.App, Queue: e.queue, Gate: e.lic, Audit: auditLog, Clock: e.clock,
		Log: log, Workers: 1, Jitter: func() float64 { return 0 }, Notifier: notify.AdminNotifier{Clock: e.clock}})
	targetjobs.Register(e.runner, targetjobs.Deps{Inventory: e.inv, Registry: reg, Clock: e.clock, Log: log})
	id := uuid.Must(uuid.NewV7())
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'ada', 'ada@example.com', 'Ada Yılmaz', 'x', 'admin', $2, $2)`, id, e.clock.Now())
	require.NoError(t, err)
	e.admin = inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: "ada"}, UserID: id, Role: rbac.Admin}
	return e
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
	for range 20 {
		ran, err := e.runner.RunOnce(e.ctx)
		require.NoError(e.t, err)
		if !ran {
			return
		}
	}
	e.t.Fatal("jobs did not drain")
}

func (e *env) job(id uuid.UUID) jobs.View {
	e.t.Helper()
	v, err := e.queue.Get(e.ctx, id)
	require.NoError(e.t, err)
	return v
}

func (e *env) status(id uuid.UUID) string {
	e.t.Helper()
	tg, err := e.inv.GetTarget(e.ctx, id)
	require.NoError(e.t, err)
	return tg.Status
}

func hostKey(t *testing.T) providers.HostKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return providers.HostKey{Type: k.Type(), PublicKey: k.Marshal(), Fingerprint: ssh.FingerprintSHA256(k)}
}

func key(user, path string, line int, fp string) providers.DiscoveredSSHKey {
	return providers.DiscoveredSSHKey{OSUser: user, FilePath: path, LineNo: line, PublicKey: "ssh-ed25519 AAAA" + fp,
		Fingerprint: fp, KeyType: "ssh-ed25519", Bits: 256}
}

// confirmed adds a target, lets the first test stop at the fingerprint, confirms it and runs the
// test and the first discovery.
func (e *env) confirmed(k providers.HostKey, keys ...providers.DiscoveredSSHKey) inventory.Target {
	e.t.Helper()
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(e.t, err)
	keys = append(keys, key("alice-svc", "/var/lib/alice-svc/.ssh/authorized_keys", 1, pk.Fingerprint))
	files := []string{}
	for _, dk := range keys {
		files = append(files, dk.FilePath)
	}
	e.prov.Configure(func(c *fake.Config) {
		c.PresentedKey = k
		c.Report = providers.ConnectionReport{HostKey: k, HelperVersion: "1.0.0", HelperProtocol: 1}
		c.Discovery = providers.DiscoveryResult{SSHKeys: keys, ReadFiles: files, SSHD: providers.SSHDSummary{Read: true, AuthorizedKeysCommand: "none"}}
	})
	tg, firstJob, err := e.inv.CreateTarget(e.ctx, e.admin, inventory.NewTarget{Name: "web-01", Type: "linux", Host: "web-01.example.com"})
	require.NoError(e.t, err)
	e.drain()
	v := e.job(firstJob)
	require.Equal(e.t, jobs.StatusFailed, v.Status)
	require.Equal(e.t, "target.host_key_unconfirmed", v.LastErrorCode)
	recs, err := e.inv.ListHostKeys(e.ctx, tg.ID)
	require.NoError(e.t, err)
	require.Len(e.t, recs, 1)
	_, err = e.inv.ConfirmHostKey(e.ctx, e.admin, tg.ID, recs[0].ID, k.Fingerprint)
	require.NoError(e.t, err)
	e.drain()
	require.Equal(e.t, inventory.StatusOK, e.status(tg.ID))
	return tg
}

// F-30 end to end through the queue: the first test only shows the fingerprint; after the
// confirmation the test succeeds and the first discovery runs by itself.
func TestFirstConnectionWaitsForConfirmationThenDiscovers(t *testing.T) {
	e := newEnv(t, nil)
	k := hostKey(t)
	tg := e.confirmed(k, key("deploy", "/home/deploy/.ssh/authorized_keys", 1, "SHA256:dep0000000000000000000000000000000000000000"))
	assert.Equal(t, 1, e.prov.Count("TestConnection"), "the unconfirmed attempt never reached TestConnection")
	assert.Equal(t, 1, e.prov.Count("Discover"))

	locs, err := e.inv.ListTargetKeys(e.ctx, tg.ID, false)
	require.NoError(t, err)
	require.Len(t, locs, 2)
	own := 0
	for _, l := range locs {
		if l.IsAliceConnectionKey {
			own++
		}
	}
	assert.Equal(t, 1, own)
	got, err := e.inv.GetTarget(e.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", got.Facts.HelperVersion)
	require.NotNil(t, got.LastDiscoveryAt)

	// A second test does not queue another first discovery.
	id, err := e.inv.RequestTest(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	e.drain()
	v := e.job(id)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, k.Fingerprint, v.Result["host_key_fingerprint"])
	assert.NotContains(t, v.Result, "discovery_job_id")
	assert.Equal(t, 1, e.prov.Count("Discover"))
}

// F-31, including scheduled jobs: once the identity changed, no handler opens a session again.
func TestChangedHostKeyBlocksEveryJob(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t))
	e.prov.Configure(func(c *fake.Config) { c.PresentedKey = hostKey(t) })
	id, err := e.inv.RequestTest(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	e.drain()
	assert.Equal(t, "target.host_key_changed", e.job(id).LastErrorCode)
	assert.Equal(t, inventory.StatusHostKeyChanged, e.status(tg.ID))
	assert.Equal(t, 1, countRows(t, e, "SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.host_key_changed'"))

	opens := e.prov.Count("Open")
	testID, err := e.inv.RequestTest(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	scheduled, _, err := e.queue.Enqueue(e.ctx, jobs.Spec{Type: jobs.TargetDiscover, TargetID: tg.ID, Kind: jobs.KindScheduled})
	require.NoError(t, err)
	e.drain()
	for _, j := range []uuid.UUID{testID, scheduled} {
		v := e.job(j)
		assert.Equal(t, jobs.StatusFailed, v.Status)
		assert.Equal(t, "target.host_key_changed", v.LastErrorCode)
	}
	assert.Equal(t, opens, e.prov.Count("Open"), "no session is opened to a changed server")
	n, err := e.inv.ScheduleDiscovery(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "only connected targets are scheduled")
	assert.Equal(t, 1, countRows(t, e, "SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.host_key_changed'"))

	// F-32: after the re-pin the next test succeeds and starts a discovery by itself.
	var observed inventory.HostKeyRecord
	recs, err := e.inv.ListHostKeys(e.ctx, tg.ID)
	require.NoError(t, err)
	for _, r := range recs {
		if r.Status == "observed" {
			observed = r
		}
	}
	require.NotEqual(t, uuid.Nil, observed.ID)
	discovers := e.prov.Count("Discover")
	_, err = e.inv.RepinHostKey(e.ctx, e.admin, tg.ID, observed.ID, observed.Fingerprint, "Server reinstalled, ticket CHG-1042")
	require.NoError(t, err)
	e.drain()
	assert.Equal(t, inventory.StatusOK, e.status(tg.ID))
	assert.Equal(t, discovers+1, e.prov.Count("Discover"), "a successful test after a re-pin queues a discovery")
}

func countRows(t *testing.T, e *env, sql string) int {
	t.Helper()
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, sql).Scan(&n))
	return n
}

func locationOf(t *testing.T, e *env, target uuid.UUID, fp string) inventory.KeyLocation {
	t.Helper()
	locs, err := e.inv.ListTargetKeys(e.ctx, target, true)
	require.NoError(t, err)
	for _, l := range locs {
		if l.Fingerprint == fp {
			return l
		}
	}
	t.Fatalf("no location %s", fp)
	return inventory.KeyLocation{}
}

func TestRemoveKeyJob(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t), key("deploy", "/home/deploy/.ssh/authorized_keys", 1, "SHA256:dep0000000000000000000000000000000000000000"))
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(t, err)
	e.prov.Configure(func(c *fake.Config) {
		c.RemoveResult = providers.AuthKeyResult{Changed: true, Removed: 1, Verified: true}
	})
	loc := locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000")
	jobID, err := e.inv.RequestKeyRemoval(e.ctx, e.admin, loc.ID, false)
	require.NoError(t, err)
	e.drain()
	v := e.job(jobID)
	require.Equal(t, jobs.StatusSucceeded, v.Status, v.LastErrorCode)
	assert.Equal(t, true, v.Result["verified"])

	var change providers.AuthKeyChange
	for _, c := range e.prov.Calls() {
		if c.Method == "RemoveAuthorizedKey" {
			change = c.Change
		}
	}
	assert.Equal(t, providers.AuthKeyChange{OperationID: jobID, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys",
		Fingerprint: "SHA256:dep0000000000000000000000000000000000000000", ProtectedFingerprints: []string{pk.Fingerprint}}, change)
	require.NotNil(t, locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000").RemovedAt)
	assert.Equal(t, 1, countRows(t, e, "SELECT count(*) FROM audit_log WHERE action = 'sshkey.removed'"))
}

// F-36: a forged job for Alice's own key never reaches the provider.
func TestRemoveOwnKeyJobNeverReachesTheProvider(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t))
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(t, err)
	own := locationOf(t, e, tg.ID, pk.Fingerprint)
	_, err = e.inv.RequestKeyRemoval(e.ctx, e.admin, own.ID, true)
	require.ErrorIs(t, err, inventory.ErrOwnKeyProtected)

	opens := e.prov.Count("Open")
	forged, _, err := e.queue.Enqueue(e.ctx, jobs.Spec{Type: jobs.SSHKeyRemove, TargetID: tg.ID, Kind: jobs.KindUser,
		Payload: map[string]string{"location_id": own.ID.String(), "fingerprint": pk.Fingerprint, "os_user": own.OSUser,
			"file_path": own.FilePath, "confirm_last_root_key": "true"}})
	require.NoError(t, err)
	e.drain()
	v := e.job(forged)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "sshkey.own_key_protected", v.LastErrorCode)
	assert.Equal(t, opens, e.prov.Count("Open"))
	assert.Zero(t, e.prov.Count("RemoveAuthorizedKey"))
	assert.Nil(t, locationOf(t, e, tg.ID, pk.Fingerprint).RemovedAt)
}

// stepSession reports the write step before failing, like a connection lost during authkeys-write.
type stepSession struct {
	providers.Session
	wrote bool
}

func (s *stepSession) RemoveAuthorizedKey(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	if s.wrote {
		log.Step("read", providers.StepStarted, nil)
		log.Step("write", providers.StepStarted, nil)
	}
	return providers.AuthKeyResult{}, providers.NewError("ssh.file_changed", true, nil, nil)
}

// §8.4: a retryable failure before the first mutation is retried; after it, never.
func TestRemoveFailureRetriesOnlyBeforeTheWrite(t *testing.T) {
	for _, wrote := range []bool{false, true} {
		e := newEnv(t, func(s providers.Session) providers.Session { return &stepSession{Session: s, wrote: wrote} })
		tg := e.confirmed(hostKey(t), key("deploy", "/home/deploy/.ssh/authorized_keys", 1, "SHA256:dep0000000000000000000000000000000000000000"))
		jobID, err := e.inv.RequestKeyRemoval(e.ctx, e.admin, locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000").ID, false)
		require.NoError(t, err)
		e.drain()
		v := e.job(jobID)
		assert.Equal(t, "ssh.file_changed", v.LastErrorCode)
		if wrote {
			assert.Equal(t, jobs.StatusFailed, v.Status, "after the write a failure is final")
		} else {
			assert.Equal(t, jobs.StatusQueued, v.Status, "before the write a retryable failure is retried later")
		}
		assert.Equal(t, 1, countRows(t, e, "SELECT count(*) FROM audit_log WHERE action = 'sshkey.remove_failed'"))
		assert.Nil(t, locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000").RemovedAt)
	}
}

// L-29: in lock no Phase 3 job does remote work: nothing is claimed, the provider sees no call,
// a queued removal waits for an Administrator and a queued scan is cancelled.
func TestL29NoRemoteWorkInLock(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t), key("deploy", "/home/deploy/.ssh/authorized_keys", 1, "SHA256:dep0000000000000000000000000000000000000000"))
	removal, err := e.inv.RequestKeyRemoval(e.ctx, e.admin, locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000").ID, false)
	require.NoError(t, err)
	scan, err := e.inv.RequestDiscovery(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	calls := len(e.prov.Calls())

	e.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, e.lic.Tick(e.ctx))
	require.ErrorIs(t, e.lic.Allow(license.ClassChange), license.ErrLocked)
	e.drain()
	assert.Equal(t, calls, len(e.prov.Calls()), "zero remote commands in lock")
	assert.Equal(t, jobs.StatusBlocked, e.job(removal).Status)
	assert.Equal(t, jobs.StatusCancelled, e.job(scan).Status)
	assert.Nil(t, locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000").RemovedAt)
}

// §8.4: when the provider reports a change together with the error, the outcome is uncertain:
// the job stops for a person (never retried, even for a retryable reason) and the key is not
// recorded as removed; the backup the helper made is shown.
func TestRemoveWithAnUncertainOutcomeIsNeverRetried(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t), key("deploy", "/home/deploy/.ssh/authorized_keys", 1, "SHA256:dep0000000000000000000000000000000000000000"))
	e.prov.Configure(func(c *fake.Config) {
		c.RemoveResult = providers.AuthKeyResult{Changed: true, Removed: 1, Backup: "/var/lib/alice-helper/backup/1"}
		c.RemoveErr = providers.NewError("ssh.timeout", true, nil, nil)
	})
	jobID, err := e.inv.RequestKeyRemoval(e.ctx, e.admin, locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000").ID, false)
	require.NoError(t, err)
	e.drain()
	v := e.job(jobID)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "ssh.timeout", v.LastErrorCode)
	assert.Equal(t, true, v.Result["needs_attention"])
	assert.Equal(t, true, v.Result["changed"])
	assert.Equal(t, "/var/lib/alice-helper/backup/1", v.Result["backup"])
	assert.Equal(t, 1, e.prov.Count("RemoveAuthorizedKey"))
	assert.Nil(t, locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000").RemovedAt)
	assert.Equal(t, 1, countRows(t, e, "SELECT count(*) FROM audit_log WHERE action = 'sshkey.remove_failed'"))
	assert.Equal(t, inventory.StatusUnreachable, e.status(tg.ID), "a connection reason marks the target")
}

// §13.4 step 5: a write whose re-read shows other content is not a removal. Until a restore
// exists the job stops for a person with the helper's backup; the key is not recorded as removed.
func TestRemoveUnverifiedStopsForAPerson(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t), key("deploy", "/home/deploy/.ssh/authorized_keys", 1, "SHA256:dep0000000000000000000000000000000000000000"))
	e.prov.Configure(func(c *fake.Config) {
		c.RemoveResult = providers.AuthKeyResult{Changed: true, Removed: 1, Backup: "/var/lib/alice-helper/backup/2"}
	})
	jobID, err := e.inv.RequestKeyRemoval(e.ctx, e.admin, locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000").ID, false)
	require.NoError(t, err)
	e.drain()
	v := e.job(jobID)
	require.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "sshkey.verify_failed", v.LastErrorCode)
	assert.Equal(t, true, v.Result["needs_attention"])
	assert.Equal(t, true, v.Result["changed"])
	assert.Equal(t, float64(1), v.Result["removed"])
	assert.Equal(t, false, v.Result["verified"])
	assert.Equal(t, "/var/lib/alice-helper/backup/2", v.Result["backup"])
	assert.Nil(t, locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000").RemovedAt)
	assert.Zero(t, countRows(t, e, "SELECT count(*) FROM audit_log WHERE action = 'sshkey.removed'"))
	assert.Equal(t, 1, countRows(t, e,
		"SELECT count(*) FROM audit_log WHERE action = 'sshkey.remove_failed' AND details->>'reason' = 'sshkey.verify_failed'"))
	assert.Equal(t, inventory.StatusOK, e.status(tg.ID))
}

// A disabled target runs no job at all.
func TestDisabledTargetRunsNoJob(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t), key("deploy", "/home/deploy/.ssh/authorized_keys", 1, "SHA256:dep0000000000000000000000000000000000000000"))
	loc := locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000")
	removal, err := e.inv.RequestKeyRemoval(e.ctx, e.admin, loc.ID, false)
	require.NoError(t, err)
	test, err := e.inv.RequestTest(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	scan, err := e.inv.RequestDiscovery(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	opens := e.prov.Count("Open")
	e.drain()
	for _, id := range []uuid.UUID{removal, test, scan} {
		assert.Equal(t, jobs.StatusFailed, e.job(id).Status)
		assert.Equal(t, "target.disabled", e.job(id).LastErrorCode)
	}
	assert.Equal(t, opens, e.prov.Count("Open"))
}

// A refusal of the operation is audited on the key and leaves the target alone; an
// authentication failure marks the target (R37 item 13).
func TestRemoveFailureReasonsAndTheTargetStatus(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t), key("deploy", "/home/deploy/.ssh/authorized_keys", 1, "SHA256:dep0000000000000000000000000000000000000000"))
	loc := locationOf(t, e, tg.ID, "SHA256:dep0000000000000000000000000000000000000000")
	e.prov.Configure(func(c *fake.Config) { c.RemoveErr = providers.NewError("sshkey.last_root_key", false, nil, nil) })
	refused, err := e.inv.RequestKeyRemoval(e.ctx, e.admin, loc.ID, false)
	require.NoError(t, err)
	e.drain()
	assert.Equal(t, jobs.StatusFailed, e.job(refused).Status)
	assert.Equal(t, "sshkey.last_root_key", e.job(refused).LastErrorCode)
	got, err := e.inv.GetTarget(e.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusOK, got.Status)
	assert.Empty(t, got.LastErrorCode)

	e.prov.Configure(func(c *fake.Config) {
		c.RemoveErr = providers.NewError("ssh.auth_failed", false, nil, map[string]string{"reason": "key_refused"})
	})
	denied, err := e.inv.RequestKeyRemoval(e.ctx, e.admin, loc.ID, false)
	require.NoError(t, err)
	e.drain()
	assert.Equal(t, "ssh.auth_failed", e.job(denied).LastErrorCode)
	assert.Equal(t, map[string]string{"reason": "key_refused"}, e.job(denied).ErrorParams)
	assert.Equal(t, inventory.StatusAuthFailed, e.status(tg.ID))
	assert.Equal(t, 2, countRows(t, e, "SELECT count(*) FROM audit_log WHERE action = 'sshkey.remove_failed'"))
}

// A failed scan maps its reason onto the target and is retried later; a deleted target's queued
// jobs fail without connecting.
func TestDiscoverFailureAndDeletedTarget(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t))
	e.prov.Configure(func(c *fake.Config) { c.DiscoverErr = providers.NewError("ssh.unreachable", true, nil, nil) })
	scan, err := e.inv.RequestDiscovery(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	e.drain()
	assert.Equal(t, jobs.StatusQueued, e.job(scan).Status)
	assert.Equal(t, "ssh.unreachable", e.job(scan).LastErrorCode)
	assert.Equal(t, inventory.StatusUnreachable, e.status(tg.ID))

	test, err := e.inv.RequestTest(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	require.NoError(t, e.inv.DeleteTarget(e.ctx, e.admin, tg.ID))
	opens := e.prov.Count("Open")
	e.drain()
	assert.Equal(t, jobs.StatusFailed, e.job(test).Status)
	assert.Equal(t, "system.not_found", e.job(test).LastErrorCode)
	assert.Equal(t, opens, e.prov.Count("Open"))
}
