package netdiscojobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/discovery"
	"alice/internal/jobs"
	"alice/internal/platform/db"
)

// ScheduleWave is how many scans one schedule tick queues at most (and never more than may run at once).
const ScheduleWave = 2

// Errors of a tick whose steps failed (their own errors are logged by type only); the next tick tries again.
var (
	errScheduleFailed  = errors.New("netdiscojobs: the discovery schedule failed for some scopes")
	errRetentionFailed = errors.New("netdiscojobs: the discovery retention failed")
)

type tasks struct{ d Deps }

func newTasks(d Deps) *tasks { return &tasks{d: d.withLog()} }

// ScheduleTask is the periodic netdisco.schedule (ClassReadOnly: the scheduler's gate pauses it in lock and while the
// licence cannot be verified). It runs on the leader only (the scheduler's lock), every minute in a release build and
// never on the wall clock in the e2e build (the journeys run it with POST /test/scheduler/run). Each tick first ends
// the scans whose job is gone (EndOrphanScans), then queues the scans of the enabled, live scopes whose schedule is due
// (Due), oldest schedule first, at most ScheduleWave and never beyond jobs.MaxConcurrentNetdiscoScans queued or
// running scans (manual ones count); a scope with a scan queued or running is skipped.
func ScheduleTask(d Deps, every time.Duration) jobs.Task {
	if d.Pool == nil || d.Queue == nil || d.Clock == nil || d.Audit == nil {
		panic("netdiscojobs: ScheduleTask needs Deps.Pool, Deps.Queue, Deps.Clock and Deps.Audit")
	}
	return jobs.Task{Type: jobs.NetdiscoSchedule, Every: every, Run: newTasks(d).schedule}
}

// RetentionTask is the periodic netdisco.retention (ClassAlways: it runs in lock too, and deletes or ends only
// discovery rows). It runs on the leader only, every hour in a release build and never on the wall clock in the e2e
// build. Each run ends the scans whose job is gone (EndOrphanScans), then runs discovery.PGStore.Retain.
func RetentionTask(d Deps, every time.Duration) jobs.Task {
	if d.Pool == nil || d.Clock == nil || d.Audit == nil {
		panic("netdiscojobs: RetentionTask needs Deps.Pool, Deps.Clock and Deps.Audit")
	}
	return jobs.Task{Type: jobs.NetdiscoRetention, Every: every, Run: newTasks(d).retain}
}

// EndOrphanScans ends, as failed with discovery.scan_interrupted (ALC-DSC-0012), every scan that is queued or running
// while no netdisco.scan job for it is queued or running: its job ended without ending it (a worker that died while the
// end hook could not run, a job ended outside the runner). A scan and its job are written in one transaction
// (StartTx), and no new job is ever queued for an existing scan, so such a scan can never run again. Each ended scan's
// discovery.scan.finished row is written in the same transaction. It returns how many it ended.
func EndOrphanScans(ctx context.Context, pool *pgxpool.Pool, log *audit.Log, now time.Time) (int64, error) {
	var n int64
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE discovery_scans s SET state = 'failed', error_code = $1, finished_at = greatest($2::timestamptz, s.started_at)
WHERE s.state IN ('queued', 'running')
  AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.dedupe_key = 'netdisco.scan:' || s.scope_id::text
                  AND j.status IN ('queued', 'running', 'blocked_license') AND j.payload->>'scan_id' = s.id::text)
RETURNING s.id`, discovery.ReasonInterrupted, now)
		if err != nil {
			return err
		}
		ended, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, id := range ended {
			if err := AuditFinished(ctx, tx, log, id); err != nil {
				return err
			}
		}
		n = int64(len(ended))
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("netdiscojobs: end the orphan scans: %w", err)
	}
	return n, nil
}

func (t *tasks) endOrphans(ctx context.Context, now time.Time) bool {
	n, err := EndOrphanScans(ctx, t.d.Pool, t.d.Audit, now)
	if err != nil {
		t.d.Log.Error("ending discovery scans whose job ended failed", "error_type", fmt.Sprintf("%T", err))
		return false
	}
	if n > 0 {
		t.d.Log.Info("ended discovery scans whose job ended", "count", n)
	}
	return true
}

// candidate is a scope the schedule may queue a scan of.
type candidate struct {
	id    uuid.UUID
	sched discovery.Schedule
	last  *time.Time
}

// schedule is one netdisco.schedule tick.
func (t *tasks) schedule(ctx context.Context) error {
	now := t.d.Clock.Now()
	ok := t.endOrphans(ctx, now)
	free, list, err := t.candidates(ctx)
	if err != nil {
		t.d.Log.Error("reading the discovery scopes to schedule failed", "error_type", fmt.Sprintf("%T", err))
		return errScheduleFailed
	}
	free = min(free, ScheduleWave)
	queued := 0
	for _, c := range list {
		if queued >= free {
			break
		}
		var last time.Time
		if c.last != nil {
			last = *c.last
		}
		due, err := Due(c.sched, last, now)
		if err != nil {
			t.d.Log.Error("the schedule of a discovery scope cannot be read; it is skipped", "scope_id", c.id.String(),
				"error_type", fmt.Sprintf("%T", err))
			ok = false
			continue
		}
		if !due {
			continue
		}
		started, err := t.startScheduled(ctx, c, now)
		switch {
		case err != nil:
			t.d.Log.Error("queueing a scheduled discovery scan failed", "scope_id", c.id.String(), "error_type", fmt.Sprintf("%T", err))
			ok = false
		case started:
			queued++
		}
	}
	if queued > 0 {
		t.d.Log.Info("queued scheduled discovery scans", "count", queued)
	}
	if !ok {
		return errScheduleFailed
	}
	return nil
}

// candidates returns how many more scans may be queued or running now, and the enabled, live, scheduled scopes with no
// scan queued or running, oldest schedule first.
func (t *tasks) candidates(ctx context.Context) (int, []candidate, error) {
	var active int
	if err := t.d.Pool.QueryRow(ctx, `SELECT count(*) FROM discovery_scans WHERE state IN ('queued', 'running')`).Scan(&active); err != nil {
		return 0, nil, err
	}
	free := jobs.MaxConcurrentNetdiscoScans - active
	if free <= 0 {
		return 0, nil, nil
	}
	rows, err := t.d.Pool.Query(ctx, `SELECT id, schedule_hours, coalesce(to_char(window_start, 'HH24:MI'), ''),
    coalesce(to_char(window_end, 'HH24:MI'), ''), window_tz, last_scheduled_at
FROM discovery_scopes sc
WHERE deleted_at IS NULL AND enabled AND schedule_hours IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM discovery_scans x WHERE x.scope_id = sc.id AND x.state IN ('queued', 'running'))
ORDER BY last_scheduled_at NULLS FIRST, id`)
	if err != nil {
		return 0, nil, err
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (candidate, error) {
		var c candidate
		err := r.Scan(&c.id, &c.sched.Hours, &c.sched.WindowStart, &c.sched.WindowEnd, &c.sched.TimeZone, &c.last)
		return c, err
	})
	return free, list, err
}

// startScheduled queues a scheduled scan of c and records it as the scope's last scheduled scan, in one transaction.
// It reports false, writing nothing, when the scope changed since it was read (another process scheduled it, it was
// switched off or deleted) or has a scan in flight now.
func (t *tasks) startScheduled(ctx context.Context, c candidate, now time.Time) (bool, error) {
	errSkip := errors.New("skip")
	err := db.InTx(ctx, t.d.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE discovery_scopes SET last_scheduled_at = $2
WHERE id = $1 AND last_scheduled_at IS NOT DISTINCT FROM $3 AND enabled AND deleted_at IS NULL`, c.id, now, c.last)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errSkip
		}
		_, _, err = StartTx(ctx, tx, t.d.Queue, StartRequest{ScopeID: c.id, Trigger: TriggerSchedule, Now: now})
		if errors.Is(err, discovery.ErrScanRunning) || errors.Is(err, discovery.ErrScopeNotFound) {
			return errSkip
		}
		return err
	})
	switch {
	case errors.Is(err, errSkip):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// retain is one netdisco.retention run.
func (t *tasks) retain(ctx context.Context) error {
	now := t.d.Clock.Now()
	ok := t.endOrphans(ctx, now)
	st, err := storeOf(t.d).Retain(ctx, now)
	switch {
	case err != nil:
		t.d.Log.Error("the discovery retention failed", "error_type", fmt.Sprintf("%T", err))
		ok = false
	case st != (discovery.RetentionStats{}):
		t.d.Log.Info("discovery retention removed old rows", "interrupted_scans", st.Interrupted, "endpoints", st.Endpoints,
			"certificates", st.Certificates, "scans", st.Scans)
	}
	if !ok {
		return errRetentionFailed
	}
	return nil
}
