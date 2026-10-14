//go:build integration

package netdiscojobs

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/netaddr"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/scanpolicy"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

// t0 is a Wednesday morning in Istanbul (UTC+3, no DST).
var t0 = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)

// lockGate is a license gate with a lock switch: locked refuses everything but ClassAlways work.
type lockGate struct{ locked atomic.Bool }

func (g *lockGate) Allow(c license.Class) error {
	if g.locked.Load() && c != license.ClassAlways {
		return license.ErrLocked
	}
	return nil
}

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

type world struct {
	t      *testing.T
	ctx    context.Context
	db     *pgtest.DB
	clock  *clock.Fake
	gate   *lockGate
	logs   *syncBuffer
	queue  *jobs.Queue
	audit  *audit.Log
	deps   Deps
	runner *jobs.Runner
	sched  *jobs.Scheduler
	user   uuid.UUID
}

// denyAll is the scan policy of the tests: every address is refused at expansion, so a scan records its endpoints as
// excluded and never dials (nothing on the host's network is touched).
func denyAll(context.Context, netaddr.ScanPolicyInputs) (netaddr.ScanPolicy, error) {
	return scanpolicy.Permissive(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")), nil
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	w := &world{t: t, ctx: ctx, db: pgtest.New(t), clock: clock.NewFake(t0), gate: &lockGate{}, logs: &syncBuffer{}}
	log := slog.New(slog.NewTextHandler(w.logs, nil))
	keyring, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	al := audit.New(w.clock)
	w.audit = al
	w.queue = jobs.NewQueue(jobs.QueueConfig{Pool: w.db.App, Keyring: keyring, Audit: al, Clock: w.clock, Gate: w.gate})
	w.deps = Deps{Pool: w.db.App, Queue: w.queue, License: w.gate, Clock: w.clock, Log: log, DatabaseURL: w.db.AppURL,
		NewPolicy: denyAll, Audit: al}
	w.runner = jobs.NewRunner(jobs.RunnerConfig{Pool: w.db.App, Queue: w.queue, Gate: w.gate, Audit: al, Clock: w.clock, Log: log,
		Workers: 1, WorkerID: "netdisco-test", Jitter: func() float64 { return 0 }})
	Register(w.runner, w.deps)
	w.sched = jobs.NewScheduler(w.clock, w.gate, log, ScheduleTask(w.deps, time.Minute), RetentionTask(w.deps, time.Hour))
	w.user = uuid.Must(uuid.NewV7())
	_, err = w.db.Owner.Exec(ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'otto', 'otto@example.test', 'Otto', 'x', 'operator', $2, $2)`, w.user, t0)
	require.NoError(t, err)
	w.exec(`INSERT INTO settings (key, value, updated_at) VALUES ('discovery.allowed_networks', '["10.0.0.0/8"]', $1)`, t0)
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	_, err := w.db.Owner.Exec(w.ctx, sql, args...)
	require.NoError(w.t, err)
}

func (w *world) count(sql string, args ...any) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, sql, args...).Scan(&n))
	return n
}

// scopeOpts are the schedule columns of a test scope.
type scopeOpts struct {
	hours             int // 0: no schedule
	start, end, zone  string
	disabled, deleted bool
	lastScheduled     *time.Time
	entries           []string
}

// scope inserts a scope (the API's work in production).
func (w *world) scope(name string, o scopeOpts) uuid.UUID {
	w.t.Helper()
	id := uuid.New()
	if o.zone == "" {
		o.zone = "UTC"
	}
	if o.entries == nil {
		o.entries = []string{"10.0.0.8/30"}
	}
	var hours *int
	if o.hours > 0 {
		hours = &o.hours
	}
	var start, end *string
	if o.start != "" {
		start, end = &o.start, &o.end
	}
	var deleted *time.Time
	if o.deleted {
		deleted = &t0
	}
	w.exec(`INSERT INTO discovery_scopes (id, name, entries, ports, enabled, schedule_hours, window_start, window_end, window_tz,
    last_scheduled_at, created_at, updated_at, deleted_at)
VALUES ($1, $2, $3, '{443}', $4, $5, $6::time, $7::time, $8, $9, $10, $10, $11)`,
		id, name, o.entries, !o.disabled, hours, start, end, o.zone, o.lastScheduled, t0, deleted)
	return id
}

// start queues a scan the way the API will (StartTx in one transaction).
func (w *world) start(scope uuid.UUID, trigger string) (uuid.UUID, uuid.UUID, error) {
	w.t.Helper()
	var scan, job uuid.UUID
	err := db.InTx(w.ctx, w.db.App, func(tx pgx.Tx) error {
		var err error
		req := StartRequest{ScopeID: scope, Trigger: trigger, Now: w.clock.Now()}
		if trigger == TriggerManual {
			req.RequestedBy, req.Role = w.user, "operator"
		}
		scan, job, err = StartTx(w.ctx, tx, w.queue, req)
		return err
	})
	return scan, job, err
}

type scanRow struct {
	state, code, trigger string
	total, excluded      int
}

func (w *world) scan(id uuid.UUID) scanRow {
	w.t.Helper()
	var r scanRow
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, `SELECT state, error_code, trigger, endpoints_total, endpoints_excluded
FROM discovery_scans WHERE id = $1`, id).Scan(&r.state, &r.code, &r.trigger, &r.total, &r.excluded))
	return r
}

type jobRow struct {
	status, code, kind, dedupe string
	payload                    map[string]string
	result                     map[string]any
}

func (w *world) job(id uuid.UUID) jobRow {
	w.t.Helper()
	var r jobRow
	var dedupe *string
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, `SELECT status, last_error_code, kind, dedupe_key, payload, coalesce(result, '{}')
FROM jobs WHERE id = $1`, id).Scan(&r.status, &r.code, &r.kind, &dedupe, &r.payload, &r.result))
	if dedupe != nil {
		r.dedupe = *dedupe
	}
	return r
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

// active is the number of scans queued or running.
func (w *world) active() int {
	return w.count(`SELECT count(*) FROM discovery_scans WHERE state IN ('queued', 'running')`)
}

// auditRow is one discovery.scan.finished row.
type auditRow struct {
	result  string
	details map[string]string
}

// finished lists the discovery.scan.finished audit rows of a scan.
func (w *world) finished(scan uuid.UUID) []auditRow {
	w.t.Helper()
	rows, err := w.db.Owner.Query(w.ctx, `SELECT result, details FROM audit_log WHERE action = 'discovery.scan.finished' AND object_id = $1
  AND object_type = 'discovery_scan' AND actor_type = 'system' ORDER BY seq`, scan.String())
	require.NoError(w.t, err)
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (auditRow, error) {
		var a auditRow
		return a, r.Scan(&a.result, &a.details)
	})
	require.NoError(w.t, err)
	return out
}

// requireOneFinishedPerEndedScan is the invariant of Task 9 review 3: every scan that is over has exactly one
// discovery.scan.finished row, whichever path ended it, and a scan in flight has none.
func (w *world) requireOneFinishedPerEndedScan() {
	w.t.Helper()
	bad := w.count(`SELECT count(*) FROM discovery_scans s WHERE (SELECT count(*) FROM audit_log a WHERE a.action = 'discovery.scan.finished'
  AND a.object_id = s.id::text) <> CASE WHEN s.state IN ('queued', 'running') THEN 0 ELSE 1 END`)
	require.Zero(w.t, bad, "every ended scan has exactly one discovery.scan.finished row")
}
