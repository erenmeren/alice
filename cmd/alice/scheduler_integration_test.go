//go:build integration

package main

import (
	"bytes"
	"context"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/i18n"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/logging"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
	"alice/locales"
)

// Every periodic task of serve runs through RunNow on a real database: the daily audit
// verification writes its audit row as the system, the hourly cleanup removes expired sessions
// and finished jobs older than 90 days (and keeps newer ones), and discovery scheduling works
// with no targets (R37 item 15); the SSH key rotation tasks run on the wired service (nothing to plan
// or sweep; a key retired 31 days ago loses its private key). The incident, drift, TLS renewal, audit forwarding and
// heartbeat tasks run on the wired services too: nothing to advance, observe or forward, no listener to renew, and the
// heartbeat alice selfcheck reads is written.
func TestServeSchedulerTasksRun(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL": d.AppURL, "ALICE_MIGRATE_DATABASE_URL": d.OwnerURL,
		"ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": t.TempDir(),
	}))
	require.NoError(t, err)
	log := slog.New(slog.DiscardHandler)
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	svc, err := buildServices(ctx, d.App, cfg, catalog, clock.Real{}, log)
	require.NoError(t, err)
	t.Cleanup(svc.sshPool.Close)
	require.NoError(t, svc.license.Start(ctx))
	sched := buildScheduler(svc, buildSender(d.App, svc, catalog, clock.Real{}, log), clock.Real{}, log)

	user := insertUser(t, d, "ops", "admin")
	_, err = d.Owner.Exec(ctx, `INSERT INTO sessions (id_hash, user_id, kind, created_at, last_seen_at, expires_at, idle_expires_at)
		VALUES ('\x01', $1, 'full', '2000-01-01', '2000-01-01', '2000-01-02', '2000-01-01')`, user)
	require.NoError(t, err)
	for _, finished := range []time.Time{time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Now().UTC()} {
		_, err = d.Owner.Exec(ctx, `INSERT INTO jobs (id, type, class, kind, payload_mac, status, run_at, max_attempts, created_at, finished_at)
			VALUES (gen_random_uuid(), 'audit.verify', 'always', 'system', decode(repeat('00', 32), 'hex'), 'succeeded', $1, 1, $1, $1)`, finished)
		require.NoError(t, err)
	}

	// A generated key retired 31 days ago: sshkey.destroy_retired destroys its private key (30 days, R41 row 23).
	_, err = d.Owner.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek,
    key_version, created_at) VALUES ('00000000-0000-0000-0000-0000000000a1', 'ssh_key', 'ed25519', 256, repeat('a', 64), '\x01',
    decode(repeat('00', 12), 'hex'), '\x02', 1, now() - interval '40 days')`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, managed, private_key_id, first_seen_at,
    created_at, retired_at) VALUES (gen_random_uuid(), 'SHA256:`+strings.Repeat("R", 43)+`', 'ssh-ed25519', 256, 'ssh-ed25519 AAAA', true,
    '00000000-0000-0000-0000-0000000000a1', now() - interval '40 days', now() - interval '40 days', now() - interval '31 days')`)
	require.NoError(t, err)

	// Two SSO sign-in states: one expired a minute ago, one live (maintenance.cleanup prunes the first, contract C1).
	provider := uuid.New()
	_, err = d.Owner.Exec(ctx, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim, authorization_endpoint,
    token_endpoint, jwks_uri, enabled, created_at, updated_at) VALUES ($1, 'Corp', 'https://idp.example.test', 'alice', '{openid}', 'groups',
    'https://idp.example.test/authorize', 'https://idp.example.test/token', 'https://idp.example.test/jwks', true, now(), now())`, provider)
	require.NoError(t, err)
	for i, expires := range []time.Time{time.Now().Add(-time.Minute), time.Now().Add(5 * time.Minute)} {
		_, err = d.Owner.Exec(ctx, `INSERT INTO oidc_login_states (state_hash, provider_id, binding_hash, nonce, code_verifier, purpose, next_path,
    created_at, expires_at) VALUES ($1, $2, $3, $4, $4, 'login', '/', $5::timestamptz - interval '5 minutes', $5)`,
			bytes.Repeat([]byte{byte(i + 1)}, 32), provider, bytes.Repeat([]byte{9}, 32), strings.Repeat("n", 42)+strconv.Itoa(i), expires)
		require.NoError(t, err)
	}

	for _, task := range []jobs.Type{jobs.LicenseEvaluate, jobs.NotifySend, jobs.AuditVerify, jobs.MaintenanceCleanup, jobs.DiscoverySchedule,
		jobs.DeploymentRecoverySweep, jobs.KVSchedule, jobs.KVAutoDeploy, jobs.RotationPlan, jobs.RotationSweep, jobs.SSHKeyDestroyRetired,
		jobs.AlertsScan, jobs.ACMESchedule, jobs.ACMEAutoDeploy, jobs.ACMESweep, jobs.NetdiscoSchedule, jobs.NetdiscoRetention,
		jobs.IncidentAdvance, jobs.DriftSchedule, jobs.DriftRepair, jobs.TLSRenew, jobs.AuditForward, jobs.JobsHeartbeat} {
		require.NoError(t, sched.RunNow(ctx, task.Name), task.Name)
	}

	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM audit_log WHERE action = 'audit.verified' AND actor_type = 'system'"))
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM sessions"), "the expired session was pruned")
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM jobs"), "only the job finished more than 90 days ago was pruned")
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM oidc_login_states"), "the expired sign-in state was pruned, the live one kept")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM jobs WHERE finished_at < '2001-01-01'"))
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM managed_private_keys WHERE destroyed_at IS NOT NULL AND ciphertext IS NULL"),
		"the retired key's private key was destroyed by the wired sshkey.destroy_retired task")
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM audit_log WHERE action = 'sshkey.private_key_destroyed'"))
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM settings WHERE key = '"+heartbeatKey+"'"),
		"jobs.heartbeat wrote the heartbeat alice selfcheck reads")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM audit_log WHERE action = 'https.temporary_renewed'"),
		"a command has no listener: tls.renew renews nothing")
	assert.Error(t, sched.RunNow(ctx, "unknown.task"), "only the listed tasks exist")
}

// rotationStack is serve's services and scheduler on a fresh database with the platform key. started
// starts the licence service; without it the gate has no evaluation and refuses everything but
// ClassAlways work (ErrUnverified, the state of a licence Alice cannot check), as in a lock.
func rotationStack(t *testing.T, started bool) (*pgtest.DB, *services, *jobs.Scheduler) {
	t.Helper()
	d := pgtest.New(t)
	ctx := context.Background()
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL": d.AppURL, "ALICE_MIGRATE_DATABASE_URL": d.OwnerURL,
		"ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": t.TempDir(),
	}))
	require.NoError(t, err)
	log := slog.New(slog.DiscardHandler)
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	svc, err := buildServices(ctx, d.App, cfg, catalog, clock.Real{}, log)
	require.NoError(t, err)
	t.Cleanup(svc.sshPool.Close)
	if started {
		require.NoError(t, svc.license.Start(ctx))
	}
	_, err = svc.inventory.EnsurePlatformKey(ctx)
	require.NoError(t, err)
	return d, svc, buildScheduler(svc, buildSender(d.App, svc, catalog, clock.Real{}, log), clock.Real{}, log)
}

// Each rotation task calls its own service function: rotation.plan creates the previewed run of a policy
// whose notice is due (and the sweep does not), and rotation.sweep advances live runs. In a lock the
// sweep still runs (ClassAlways, no second gate in the wiring) and pauses a run whose adds are not sent
// yet (L-85), while the planner is held by the gate. A task that called the wrong function, or a sweep
// wrapped in a licence check, fails here.
func TestRotationTasksCallTheirServiceFunctions(t *testing.T) {
	ctx := context.Background()
	t.Run("plan plans, sweep does not", func(t *testing.T) {
		d, _, sched := rotationStack(t, true)
		f := newRotFixture(t, d, time.Now().UTC().Add(-time.Hour), true)
		f.must("UPDATE rotation_policies SET enabled = true, next_run_at = $2 WHERE id = $1", f.policy, time.Now().UTC().Add(time.Hour))
		runs := "SELECT count(*) FROM rotations WHERE policy_id = '" + f.policy.String() + "'"

		require.NoError(t, sched.RunNow(ctx, jobs.RotationSweep.Name))
		require.NoError(t, sched.RunNow(ctx, jobs.SSHKeyDestroyRetired.Name))
		assert.Zero(t, countRows(t, d, runs), "neither the sweep nor the hourly task plans a run")

		require.NoError(t, sched.RunNow(ctx, jobs.RotationPlan.Name))
		assert.Equal(t, 1, countRows(t, d, runs+" AND trigger = 'scheduled' AND status = 'dry_run_notified'"),
			"the planner created the previewed run of the due policy")
	})
	t.Run("sweep pauses in lock, plan is held", func(t *testing.T) {
		d, _, sched := rotationStack(t, false)
		f := newRotFixture(t, d, time.Now().UTC().Add(-time.Hour), true)
		f.createRun()
		f.start()
		f.must("UPDATE rotation_policies SET enabled = true, next_run_at = $2 WHERE id = $1", f.policy, time.Now().UTC().Add(time.Hour))

		require.ErrorIs(t, sched.RunNow(ctx, jobs.RotationPlan.Name), license.ErrUnverified, "the gate holds the planner")
		require.NoError(t, sched.RunNow(ctx, jobs.RotationSweep.Name), "the sweep runs whatever the licence")
		assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM rotations WHERE id = '"+f.run.String()+"' AND paused_license"),
			"the sweep paused the run: no add is sent while the licence cannot be checked")
		assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM rotations WHERE policy_id = '"+f.policy.String()+"'"), "nothing was planned")
	})
}

// alertsStack is serve's services and scheduler on a fresh database, logging to a buffer the test reads.
func alertsStack(t *testing.T) (*pgtest.DB, *services, *jobs.Scheduler, *lockedBuffer) {
	t.Helper()
	d := pgtest.New(t)
	ctx := context.Background()
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL": d.AppURL, "ALICE_MIGRATE_DATABASE_URL": d.OwnerURL,
		"ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": t.TempDir(),
	}))
	require.NoError(t, err)
	logs := &lockedBuffer{}
	log := logging.New(logs, slog.LevelInfo)
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	svc, err := buildServices(ctx, d.App, cfg, catalog, clock.Real{}, log)
	require.NoError(t, err)
	t.Cleanup(svc.sshPool.Close)
	require.NoError(t, svc.license.Start(ctx))
	return d, svc, buildScheduler(svc, buildSender(d.App, svc, catalog, clock.Real{}, log), clock.Real{}, log), logs
}

// seedExpiring puts a certificate expiring in left on a new server, so it is monitored.
func seedExpiring(t *testing.T, d *pgtest.DB, server, cn string, left time.Duration) {
	t.Helper()
	ctx := context.Background()
	target, err := seed.Target(ctx, d.Owner, server, "linux", "ok", nil)
	require.NoError(t, err)
	_, err = seed.Certificate(ctx, d.Owner, cn, time.Now().Add(left), []uuid.UUID{target}, cn)
	require.NoError(t, err)
}

// The wired alerts.scan records and queues expiry notices. With the default recipients (every Administrator) and no
// Administrator holding an e-mail address, the notice is recorded but reaches nobody: the task says so in one WARN line
// with an event name (Task 7 review carry), and says nothing once someone receives the notices.
func TestAlertsScanTaskQueuesNoticesAndWarnsWithoutRecipients(t *testing.T) {
	d, svc, sched, logs := alertsStack(t)
	ctx := context.Background()
	admin := insertUser(t, d, "ada", "admin")
	seedExpiring(t, d, "web-1", "www.example.test", 5*24*time.Hour)

	require.NoError(t, sched.RunNow(ctx, jobs.AlertsScan.Name))
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM alerts WHERE threshold_days = 7"))
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM notifications_outbox WHERE template_key LIKE 'alert.%'"))
	assert.Equal(t, 1, strings.Count(logs.String(), `"event":"alerts.no_recipients"`), logs.String())
	assert.Regexp(t, `"level":"WARN","msg":"alerts: expiry notices were recorded but no e-mail was queued[^\n]*"event":"alerts.no_recipients"`,
		logs.String())

	_, err := d.Owner.Exec(ctx, `UPDATE users SET email = 'ada@example.com' WHERE id = $1`, admin)
	require.NoError(t, err)
	seedExpiring(t, d, "web-2", "api.example.test", 3*24*time.Hour)
	require.NoError(t, sched.RunNow(ctx, jobs.AlertsScan.Name))
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM notifications_outbox WHERE template_key LIKE 'alert.%' AND to_address = 'ada@example.com'"))

	// Administrators switched off and no extra address (a stored value; the settings form refuses it): nobody, so the
	// line comes again although an Administrator has an address.
	_, err = d.Owner.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('notify.recipients', '{"administrators":false,"addresses":[],"version":1}')`)
	require.NoError(t, err)
	seedExpiring(t, d, "web-3", "shop.example.test", 4*24*time.Hour)
	require.NoError(t, sched.RunNow(ctx, jobs.AlertsScan.Name))
	assert.Equal(t, 2, strings.Count(logs.String(), `"event":"alerts.no_recipients"`))

	// Extra addresses only (Administrators still off): the notice reaches the address, no line.
	_, err = svc.notifySettings.SaveRecipients(ctx, audit.SystemActor("test"), 1, notify.Recipients{
		Addresses: []notify.Address{{Email: "ops@example.com", Locale: "en"}}})
	require.NoError(t, err)
	seedExpiring(t, d, "web-4", "mail.example.test", 2*24*time.Hour)
	require.NoError(t, sched.RunNow(ctx, jobs.AlertsScan.Name))
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM notifications_outbox WHERE template_key LIKE 'alert.%' AND to_address = 'ops@example.com'"))
	assert.Equal(t, 2, strings.Count(logs.String(), `"event":"alerts.no_recipients"`))

	// Nothing new is due: no notice, no recipient check, no line.
	require.NoError(t, sched.RunNow(ctx, jobs.AlertsScan.Name))
	assert.Equal(t, 4, countRows(t, d, "SELECT count(*) FROM alerts"))
	assert.Equal(t, 2, strings.Count(logs.String(), `"event":"alerts.no_recipients"`))
}

// Task 13 review minor 3: when the lock's own session ends while the task runs, the lock is gone; the release step
// notices it and says so (event <name>_lock_lost). A normal run logs no such line.
func TestRunExclusiveReportsALostLock(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	logs := &lockedBuffer{}
	log := logging.New(logs, slog.LevelInfo)
	require.NoError(t, runExclusive(ctx, d.App, "test.exclusive", log, func(context.Context) error { return nil }))
	assert.NotContains(t, logs.String(), "lock_lost")

	ran := false
	require.NoError(t, runExclusive(ctx, d.App, "test.exclusive", log, func(ctx context.Context) error {
		ran = true
		_, err := d.Owner.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_locks
WHERE locktype = 'advisory' AND granted AND pid <> pg_backend_pid()`)
		return err
	}))
	assert.True(t, ran)
	assert.Contains(t, logs.String(), `"event":"test.exclusive_lock_lost"`)
	assert.Regexp(t, `"level":"WARN","msg":"scheduled task lost its lock`, logs.String())

	// The pool dropped the dead connection: the next run takes the lock again.
	ran = false
	require.NoError(t, runExclusive(ctx, d.App, "test.exclusive", log, func(context.Context) error { ran = true; return nil }))
	assert.True(t, ran)
}

// One alerts.scan at a time, also across processes (Task 8 review carry: two overlapping scans could record a less
// urgent level after a more urgent one). In one process the scheduler runs a task once at a time (tick and RunNow
// share its semaphore); the scan also holds a database lock, so a scan of another process (a leadership handover)
// makes this one skip instead of overlapping.
func TestAlertsScanRunsOneAtATime(t *testing.T) {
	d, _, sched, logs := alertsStack(t)
	ctx := context.Background()
	seedExpiring(t, d, "web-1", "www.example.test", 5*24*time.Hour)

	other, err := d.Owner.Acquire(ctx)
	require.NoError(t, err)
	defer other.Release()
	_, err = other.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended('alerts.scan', 0))`)
	require.NoError(t, err)
	require.NoError(t, sched.RunNow(ctx, jobs.AlertsScan.Name), "a skipped scan is no failure")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM alerts"), "the scan skipped while another one runs")
	assert.Contains(t, logs.String(), `"event":"alerts.scan_skipped"`)

	_, err = other.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended('alerts.scan', 0))`)
	require.NoError(t, err)
	require.NoError(t, sched.RunNow(ctx, jobs.AlertsScan.Name))
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM alerts"))
	var free bool
	require.NoError(t, other.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended('alerts.scan', 0))`).Scan(&free))
	assert.True(t, free, "the scan released its lock")
	_, err = other.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended('alerts.scan', 0))`)
	require.NoError(t, err)
}
