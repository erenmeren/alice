//go:build integration

package netdiscojobs

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery"
	"alice/internal/jobs"
	"alice/internal/license"
)

func (w *world) schedule() {
	w.t.Helper()
	require.NoError(w.t, w.sched.RunNow(w.ctx, jobs.NetdiscoSchedule.Name))
}

// scansOf counts the scans of a scope by trigger.
func (w *world) scansOf(scope uuid.UUID, trigger string) int {
	return w.count(`SELECT count(*) FROM discovery_scans WHERE scope_id = $1 AND trigger = $2`, scope, trigger)
}

// The schedule queues the scans of due scopes, at most ScheduleWave per tick and never beyond the number of scans that
// may run at once (MaxConcurrentNetdiscoScans, manual ones included); each scan is queued with its job (trigger
// schedule, a scheduled job) and the scope's last_scheduled_at. Disabled, deleted and unscheduled scopes are never
// scheduled.
func TestScheduleQueuesDueScopesInWaves(t *testing.T) {
	w := newWorld(t)
	var due []uuid.UUID
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		due = append(due, w.scope(name, scopeOpts{hours: 6}))
	}
	recent := t0.Add(-time.Hour)
	never := []uuid.UUID{
		w.scope("off", scopeOpts{hours: 6, disabled: true}),
		w.scope("deleted", scopeOpts{hours: 6, deleted: true}),
		w.scope("manual only", scopeOpts{}),
		w.scope("recent", scopeOpts{hours: 6, lastScheduled: &recent}),
	}
	scheduled := func() int { return w.count(`SELECT count(*) FROM discovery_scans WHERE trigger = 'schedule'`) }

	w.schedule()
	assert.Equal(t, 2, scheduled(), "one wave")
	assert.Equal(t, 2, w.count(`SELECT count(*) FROM jobs WHERE type = 'netdisco.scan' AND kind = 'scheduled' AND status = 'queued'`))
	assert.Equal(t, 2, w.count(`SELECT count(*) FROM discovery_scopes WHERE last_scheduled_at = $1`, t0))
	w.clock.Advance(time.Minute)
	w.schedule()
	assert.Equal(t, 2, scheduled(), "two scans are queued: the cap is reached")

	w.drain()
	w.schedule()
	assert.Equal(t, 4, scheduled())
	w.drain()
	w.schedule()
	assert.Equal(t, 5, scheduled())
	w.drain()
	w.schedule()
	assert.Equal(t, 5, scheduled(), "every due scope was scanned; none is due again within six hours")
	for _, id := range due {
		assert.Equal(t, 1, w.scansOf(id, "schedule"))
	}
	for _, id := range never {
		assert.Zero(t, w.scansOf(id, "schedule"))
	}
	assert.Zero(t, w.active())

	w.clock.Advance(6 * time.Hour)
	w.schedule()
	assert.Equal(t, 7, scheduled(), "the interval has passed: the next wave")
	assert.Equal(t, 1, w.scansOf(never[3], "schedule"), "the scope scanned an hour before the start is due now too")
}

// A scope that has a scan queued or running (a manual one) is not scheduled, and the manual scan counts against the
// number of scans that may run at once.
func TestScheduleSkipsBusyScopesAndCountsManualScans(t *testing.T) {
	w := newWorld(t)
	busy := w.scope("busy", scopeOpts{hours: 1})
	others := []uuid.UUID{w.scope("x", scopeOpts{hours: 1}), w.scope("y", scopeOpts{hours: 1})}
	_, _, err := w.start(busy, TriggerManual)
	require.NoError(t, err)
	w.schedule()
	assert.Zero(t, w.scansOf(busy, "schedule"))
	assert.Equal(t, 1, w.scansOf(others[0], "schedule")+w.scansOf(others[1], "schedule"), "one place was left")
	assert.Equal(t, 2, w.active())
}

// A scope read as due whose scan started in between (a manual scan queued after the schedule's read): starting it
// reports false and writes nothing, its last_scheduled_at included.
func TestStartScheduledSkipsAScopeThatGotAScanInFlight(t *testing.T) {
	w := newWorld(t)
	scope := w.scope("lab", scopeOpts{hours: 1})
	_, _, err := w.start(scope, TriggerManual)
	require.NoError(t, err)
	started, err := newTasks(w.deps).startScheduled(w.ctx, candidate{id: scope}, t0)
	require.NoError(t, err)
	assert.False(t, started)
	assert.Zero(t, w.scansOf(scope, "schedule"))
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_scopes WHERE last_scheduled_at IS NOT NULL`), "the update rolled back")
}

// The window is evaluated in the scope's time zone: a scope with a window 22:00-04:30 in Istanbul (UTC+3) is not
// scheduled at noon there and is at 22:00.
func TestScheduleHonoursTheWindowInTheScopesZone(t *testing.T) {
	w := newWorld(t)
	scope := w.scope("night", scopeOpts{hours: 6, start: "22:00", end: "04:30", zone: "Europe/Istanbul"})
	w.schedule()
	assert.Zero(t, w.scansOf(scope, "schedule"), "12:00 in Istanbul")
	w.clock.Advance(9*time.Hour + 59*time.Minute)
	w.schedule()
	assert.Zero(t, w.scansOf(scope, "schedule"), "21:59 in Istanbul")
	w.clock.Advance(time.Minute)
	w.schedule()
	assert.Equal(t, 1, w.scansOf(scope, "schedule"), "22:00 in Istanbul")
}

// A scope whose stored schedule cannot be read (a zone this build does not know) is skipped and logged; the others are
// scheduled; the tick reports the failure.
func TestScheduleSkipsAnUnreadableSchedule(t *testing.T) {
	w := newWorld(t)
	bad := w.scope("bad", scopeOpts{hours: 1, start: "00:00", end: "23:00", zone: "Mars/Olympus"})
	good := w.scope("good", scopeOpts{hours: 1})
	err := w.sched.RunNow(w.ctx, jobs.NetdiscoSchedule.Name)
	require.ErrorIs(t, err, errScheduleFailed)
	assert.Zero(t, w.scansOf(bad, "schedule"))
	assert.Equal(t, 1, w.scansOf(good, "schedule"))
	assert.Contains(t, w.logs.String(), "the schedule of a discovery scope cannot be read")
	assert.NotContains(t, w.logs.String(), "Mars")
}

// Two leaders overlapping one tick (P2-06): a scope whose last_scheduled_at changed since it was read is not scheduled
// again.
func TestScheduleDoesNotRepeatAConcurrentTick(t *testing.T) {
	w := newWorld(t)
	scope := w.scope("lab", scopeOpts{hours: 1})
	tk := newTasks(w.deps)
	stale := candidate{id: scope, sched: discovery.Schedule{Hours: 1}}
	w.exec(`UPDATE discovery_scopes SET last_scheduled_at = $2 WHERE id = $1`, scope, t0.Add(-2*time.Hour))
	started, err := tk.startScheduled(w.ctx, stale, t0)
	require.NoError(t, err)
	assert.False(t, started)
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_scans`))
	assert.Zero(t, w.count(`SELECT count(*) FROM jobs`))

	fresh := stale
	last := t0.Add(-2 * time.Hour)
	fresh.last = &last
	started, err = tk.startScheduled(w.ctx, fresh, t0)
	require.NoError(t, err)
	assert.True(t, started)
	assert.Equal(t, 1, w.scansOf(scope, "schedule"))
}

// In lock the schedule (ReadOnly) is paused by the scheduler's gate: nothing is queued. Retention (ClassAlways) runs in
// lock and deletes only discovery rows.
func TestLockPausesTheScheduleButNotTheRetention(t *testing.T) {
	w := newWorld(t)
	scope := w.scope("lab", scopeOpts{hours: 1})
	deleted := w.scope("deleted", scopeOpts{})
	for _, id := range []uuid.UUID{scope, deleted} {
		_, _, err := w.start(id, TriggerManual)
		require.NoError(t, err)
	}
	w.drain()
	require.Equal(t, 8, w.count(`SELECT count(*) FROM discovery_endpoints`))
	w.exec(`UPDATE discovery_endpoints SET state = 'gone', gone_since = $2 WHERE scope_id = $1`, scope, t0.AddDate(0, 0, -100))
	w.exec(`UPDATE discovery_scopes SET deleted_at = $2 WHERE id = $1`, deleted, t0)
	others := w.otherTableCounts()

	w.gate.locked.Store(true)
	err := w.sched.RunNow(w.ctx, jobs.NetdiscoSchedule.Name)
	require.ErrorIs(t, err, license.ErrLocked)
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_scans WHERE trigger = 'schedule'`), "nothing is scheduled in lock")

	require.NoError(t, w.sched.RunNow(w.ctx, jobs.NetdiscoRetention.Name))
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_endpoints`), "gone for 100 days, and the deleted scope's")
	assert.Equal(t, others, w.otherTableCounts(), "nothing outside discovery_* changes")
	assert.Contains(t, w.logs.String(), "discovery retention removed old rows")

	w.gate.locked.Store(false)
	w.schedule()
	assert.Equal(t, 1, w.scansOf(scope, "schedule"), "after the lock the schedule resumes")
}

// otherTableCounts counts the rows of every table that is not a discovery table.
func (w *world) otherTableCounts() map[string]int {
	w.t.Helper()
	rows, err := w.db.Owner.Query(w.ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename NOT LIKE 'discovery\_%'`)
	require.NoError(w.t, err)
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(w.t, err)
	require.Greater(w.t, len(names), 20)
	out := map[string]int{}
	for _, n := range names {
		out[n] = w.count(`SELECT count(*) FROM ` + pgx.Identifier{n}.Sanitize())
	}
	return out
}
