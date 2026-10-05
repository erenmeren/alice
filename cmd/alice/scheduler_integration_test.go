//go:build integration

package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/testutil/pgtest"
	"alice/locales"
)

// Every periodic task of serve runs through RunNow on a real database: the daily audit
// verification writes its audit row as the system, the hourly cleanup removes expired sessions
// and finished jobs older than 90 days (and keeps newer ones), and discovery scheduling works
// with no targets (R37 item 15); the SSH key rotation tasks run on the wired service (nothing to plan
// or sweep; a key retired 31 days ago loses its private key).
func TestServeSchedulerTasksRun(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL": d.AppURL, "ALICE_MIGRATE_DATABASE_URL": d.OwnerURL,
		"ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": t.TempDir(),
	}))
	require.NoError(t, err)
	log := slog.New(slog.DiscardHandler)
	svc, err := buildServices(ctx, d.App, cfg, clock.Real{}, log)
	require.NoError(t, err)
	t.Cleanup(svc.sshPool.Close)
	require.NoError(t, svc.license.Start(ctx))
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	sender, err := buildSender(d.App, cfg, catalog, clock.Real{}, log)
	require.NoError(t, err)
	sched := buildScheduler(svc, sender, clock.Real{}, log)

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

	for _, task := range []jobs.Type{jobs.LicenseEvaluate, jobs.NotifySend, jobs.AuditVerify, jobs.MaintenanceCleanup, jobs.DiscoverySchedule,
		jobs.DeploymentRecoverySweep, jobs.KVSchedule, jobs.KVAutoDeploy, jobs.RotationPlan, jobs.RotationSweep, jobs.SSHKeyDestroyRetired} {
		require.NoError(t, sched.RunNow(ctx, task.Name), task.Name)
	}

	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM audit_log WHERE action = 'audit.verified' AND actor_type = 'system'"))
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM sessions"), "the expired session was pruned")
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM jobs"), "only the job finished more than 90 days ago was pruned")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM jobs WHERE finished_at < '2001-01-01'"))
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM managed_private_keys WHERE destroyed_at IS NOT NULL AND ciphertext IS NULL"),
		"the retired key's private key was destroyed by the wired sshkey.destroy_retired task")
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM audit_log WHERE action = 'sshkey.private_key_destroyed'"))
	assert.Error(t, sched.RunNow(ctx, "unknown.task"), "only the listed tasks exist")
}
