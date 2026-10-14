//go:build integration

package backup_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup"
)

var discoveryCounts = map[string]int{"discovery_scopes": 1, "discovery_scans": 1, "discovery_certificates": 1, "discovery_endpoints": 1}

// seedDiscovery inserts one scope, one finished scan, one leaf certificate and one endpoint presenting it, and returns
// the scope.
func seedDiscovery(e *env) uuid.UUID {
	e.t.Helper()
	exec := func(sql string, args ...any) {
		e.t.Helper()
		_, err := e.db.Owner.Exec(e.ctx, sql, args...)
		require.NoError(e.t, err, sql)
	}
	scope, scan := uuid.New(), uuid.New()
	fp := strings.Repeat("d", 64)
	now := e.clk.Now()
	exec(`INSERT INTO discovery_scopes (id, name, entries, ports, schedule_hours, created_at, updated_at)
VALUES ($1, 'Office LAN', '["10.0.0.0/30"]', '{443}', 24, $2, $2)`, scope, now)
	exec(`INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, finished_at, endpoints_total, endpoints_answered)
VALUES ($1, $2, 'schedule', 'done', $3, $3, $3, 4, 1)`, scan, scope, now)
	exec(`INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, issuer_cn, not_before, not_after, key_algorithm, pem, first_seen, last_seen)
VALUES ($1, true, 'www.corp.example', 'Corp CA', $2, $2::timestamptz + interval '30 days', 'ecdsa', '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', $2, $2)`,
		fp, now)
	exec(`INSERT INTO discovery_endpoints (id, scope_id, address, port, fingerprint_sha256, state, first_seen, last_seen, last_scanned_at, last_scan_id)
VALUES ($1, $2, '10.0.0.1', 443, $3, 'present', $4, $4, $4, $5)`, uuid.New(), scope, fp, now, scan)
	return scope
}

// The discovery tables travel in the backup (the table list is the schema's): Create counts them in the manifest,
// VerifyDeep reads them back and a Restore brings them into a database that lost them.
func TestDiscoveryBackupCycle(t *testing.T) {
	e := newRestoreEnv(t)
	seedDiscovery(e)
	info := e.create(backup.KindManual)

	m, err := e.svc.VerifyDeep(e.ctx, info.Path, []byte(passphrase))
	require.NoError(t, err)
	for table, want := range discoveryCounts {
		assert.Equal(t, int64(want), m.Tables[table], table)
	}

	_, err = e.db.Owner.Exec(e.ctx, "TRUNCATE discovery_endpoints, discovery_certificates, discovery_scans, discovery_scopes")
	require.NoError(t, err)
	require.Zero(t, e.count("SELECT count(*) FROM discovery_scopes"))

	_, err = e.restore(info.Path, nil)
	require.NoError(t, err)
	e.reload()
	for table, want := range discoveryCounts {
		assert.Equal(t, want, e.count("SELECT count(*) FROM "+table), table)
	}
	assert.Equal(t, 1, e.count("SELECT count(*) FROM discovery_endpoints e JOIN discovery_certificates c USING (fingerprint_sha256) WHERE e.state = 'present'"))
}

// A restored clone does not carry on the original's scans: a scan queued or running at backup time is ended as failed
// with discovery.scan_interrupted (its partial results are kept), and the backup's live netdisco.scan jobs are
// cancelled, so neither the reaper nor the queue starts a scan in the clone. Finished scans are left as they were.
func TestRestoreEndsInFlightDiscoveryScans(t *testing.T) {
	e := newRestoreEnv(t)
	scope := seedDiscovery(e)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := e.db.Owner.Exec(e.ctx, sql, args...)
		require.NoError(t, err, sql)
	}
	now := e.clk.Now()
	other := uuid.New()
	exec(`INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at) VALUES ($1, 'DMZ', '["10.1.0.1"]', '{443}', $2, $2)`, other, now)
	running, queued := uuid.New(), uuid.New()
	exec(`INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, endpoints_total, endpoints_answered)
VALUES ($1, $2, 'manual', 'running', $3, $3, 4, 2)`, running, scope, now)
	exec(`INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at) VALUES ($1, $2, 'schedule', 'queued', $3)`, queued, other, now)
	mac := make([]byte, 32)
	runJob, queuedJob := uuid.New(), uuid.New()
	exec(`INSERT INTO jobs (id, type, class, kind, payload, payload_mac, dedupe_key, status, run_at, attempts, max_attempts, locked_by, locked_until, created_at)
VALUES ($1, 'netdisco.scan', 'read_only', 'user', $2, $3, $4, 'running', $5, 1, 1, 'worker-1/1', $5::timestamptz + interval '1 hour', $5)`,
		runJob, `{"scan_id":"`+running.String()+`"}`, mac, "netdisco.scan:"+scope.String(), now)
	exec(`INSERT INTO job_attempts (id, job_id, attempt, worker_id, started_at) VALUES ($1, $2, 1, 'worker-1/1', $3)`, uuid.New(), runJob, now)
	exec(`INSERT INTO jobs (id, type, class, kind, payload, payload_mac, dedupe_key, status, run_at, attempts, max_attempts, created_at)
VALUES ($1, 'netdisco.scan', 'read_only', 'system', $2, $3, $4, 'queued', $5, 0, 1, $5)`,
		queuedJob, `{"scan_id":"`+queued.String()+`"}`, mac, "netdisco.scan:"+other.String(), now)
	info := e.create(backup.KindManual)
	e.clk.Advance(time.Minute)

	res, err := e.restore(info.Path, nil)
	require.NoError(t, err)
	e.reload()

	for _, id := range []uuid.UUID{running, queued} {
		var state, code string
		var finished bool
		require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT state, error_code, finished_at IS NOT NULL FROM discovery_scans WHERE id = $1", id).
			Scan(&state, &code, &finished))
		assert.Equal(t, "failed", state, "the original's scan does not run in the clone")
		assert.Equal(t, "discovery.scan_interrupted", code)
		assert.True(t, finished)
	}
	assert.Equal(t, 2, e.count("SELECT endpoints_answered FROM discovery_scans WHERE id = $1", running), "the partial counts are kept")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM discovery_scans WHERE state = 'done'"), "a finished scan is untouched")
	assert.Zero(t, e.count("SELECT count(*) FROM discovery_scans WHERE state IN ('queued', 'running')"))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM discovery_endpoints WHERE state = 'present'"), "results are kept")
	for _, id := range []uuid.UUID{runJob, queuedJob} {
		var status string
		require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT status FROM jobs WHERE id = $1", id).Scan(&status))
		assert.Equal(t, "cancelled", status, "the backup's scan job does not run in the clone")
	}
	assert.Zero(t, e.count("SELECT count(*) FROM job_attempts WHERE job_id = $1 AND finished_at IS NULL", runJob), "the cut-off attempt is closed")
	assert.True(t, slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "2 network discovery scans") }), res.Warnings)
	// Task 9 review 3: each scan the restore ended has its one discovery.scan.finished row (actor restore, ids and counts
	// only); the finished scan of the backup gets none.
	for _, id := range []uuid.UUID{running, queued} {
		var actor, actorType, result string
		var details map[string]string
		require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT actor_name, actor_type, result, details FROM audit_log
WHERE action = 'discovery.scan.finished' AND object_type = 'discovery_scan' AND object_id = $1`, id.String()).Scan(&actor, &actorType, &result, &details))
		assert.Equal(t, [3]string{"restore", "system", "failure"}, [3]string{actor, actorType, result})
		assert.Equal(t, "failed", details["state"])
		assert.Equal(t, "discovery.scan_interrupted", details["error_code"])
		assert.Equal(t, id.String(), details["scan_id"])
	}
	assert.Equal(t, "2", strconv.Itoa(e.count(`SELECT endpoints_answered FROM discovery_scans WHERE id = $1`, running)))
	assert.Zero(t, e.count(`SELECT count(*) FROM discovery_scans s WHERE (SELECT count(*) FROM audit_log a WHERE a.action = 'discovery.scan.finished'
  AND a.object_id = s.id::text) <> CASE WHEN s.state = 'done' THEN 0 ELSE 1 END`), "exactly one row per scan the restore ended")
}

// A restored clone does not scan on its own either: every scope with a schedule is switched off (enabled gates both
// scheduled and manual scans, so an Administrator turns it on again on the clone), even when its last scheduled scan is
// long overdue; a scope without a schedule is left as it was. Review minor 1.
func TestRestoreSwitchesOffDiscoverySchedules(t *testing.T) {
	e := newRestoreEnv(t)
	scheduled := seedDiscovery(e) // schedule_hours 24
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := e.db.Owner.Exec(e.ctx, sql, args...)
		require.NoError(t, err, sql)
	}
	now := e.clk.Now()
	manual, off := uuid.New(), uuid.New()
	exec("UPDATE discovery_scopes SET last_scheduled_at = $2::timestamptz - interval '3 days' WHERE id = $1", scheduled, now)
	exec(`INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at) VALUES ($1, 'Manual only', '["10.1.0.1"]', '{443}', $2, $2)`, manual, now)
	exec(`INSERT INTO discovery_scopes (id, name, entries, ports, schedule_hours, enabled, created_at, updated_at)
VALUES ($1, 'Already off', '["10.2.0.1"]', '{443}', 1, false, $2, $2)`, off, now)
	info := e.create(backup.KindManual)
	e.clk.Advance(time.Hour)

	res, err := e.restore(info.Path, nil)
	require.NoError(t, err)
	e.reload()

	assert.Zero(t, e.count("SELECT count(*) FROM discovery_scopes WHERE enabled AND schedule_hours IS NOT NULL"),
		"no schedule can fire in the clone, not even an overdue one")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM discovery_scopes WHERE id = $1 AND NOT enabled AND schedule_hours = 24 AND updated_at > created_at AND version = 2", scheduled),
		"the schedule itself is kept for the Administrator to turn on again")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM discovery_scopes WHERE id = $1 AND enabled", manual), "a scope without a schedule is untouched")
	assert.True(t, slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "1 network discovery scan schedules") }), res.Warnings)
}

// The scan the restore ends is finished no earlier than it started, even when the backup's clock ran ahead of the
// clone's (the CHECK finished_at >= started_at would fail the whole restore).
func TestRestoreEndsScanStartedAfterRestoreClock(t *testing.T) {
	e := newRestoreEnv(t)
	scope := seedDiscovery(e)
	scan := uuid.New()
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at)
VALUES ($1, $2, 'manual', 'running', $3, $3::timestamptz + interval '2 days')`, scan, scope, e.clk.Now())
	require.NoError(t, err)
	info := e.create(backup.KindManual)
	e.clk.Advance(time.Minute)

	_, err = e.restore(info.Path, nil)
	require.NoError(t, err)
	e.reload()
	assert.Equal(t, 1, e.count("SELECT count(*) FROM discovery_scans WHERE id = $1 AND state = 'failed' AND finished_at >= started_at", scan))
}
