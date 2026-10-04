package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// AUD-02: the gate's decision is a pure function of the last successfully evaluated snapshot,
// the monotonic time since that evaluation and the bounds (LocksAt, MaxEvaluationAge).
func TestGateDecisionTable(t *testing.T) {
	grace := snapshotAt(expiry.Add(6*day), baseline()) // locks in 24 h
	require.Equal(t, license.PhaseGrace, grace.Eval.Phase)
	untilLock := grace.Eval.LocksAt.Sub(grace.Reading.Effective)
	require.Equal(t, day, untilLock)
	active := snapshotAt(expiry.Add(-100*day), baseline())
	locked := snapshotAt(expiry.Add(200*day), baseline())
	notReady := active
	notReady.Ready = false

	type row struct {
		name  string
		snap  license.Snapshot
		class license.Class
		since time.Duration
		want  error // nil = allowed
		not   error // the answer must not match this
	}
	rows := []row{
		{"no class", active, license.ClassUnset, 0, license.ErrUnclassified, license.ErrLocked},
		{"unknown class", active, license.Class(42), 0, license.ErrUnclassified, license.ErrLocked},
		{"always, fresh", active, license.ClassAlways, 0, nil, nil},
		{"always, stale", active, license.ClassAlways, 400 * day, nil, nil},
		{"always, locked", locked, license.ClassAlways, 0, nil, nil},
		{"always, not started", notReady, license.ClassAlways, 0, nil, nil},
		{"not started: never evaluated", notReady, license.ClassChange, 0, license.ErrUnverified, nil},
		{"not started, read-only", notReady, license.ClassReadOnly, 0, license.ErrUnverified, nil},
		{"active, fresh", active, license.ClassChange, 0, nil, nil},
		{"active, read-only, fresh", active, license.ClassReadOnly, time.Hour, nil, nil},
		{"active, exactly the maximum age", active, license.ClassChange, license.MaxEvaluationAge, nil, nil},
		{"active, stale", active, license.ClassChange, license.MaxEvaluationAge + time.Nanosecond, license.ErrUnverified, nil},
		{"active, read-only, stale", active, license.ClassReadOnly, 3*time.Hour + time.Minute, license.ErrUnverified, nil},
		{"evaluated locked, fresh", locked, license.ClassChange, 0, license.ErrLocked, license.ErrUnverified},
		{"evaluated locked, read-only", locked, license.ClassReadOnly, time.Minute, license.ErrLocked, license.ErrUnverified},
		{"evaluated locked, stale", locked, license.ClassChange, 4 * time.Hour, license.ErrUnverified, nil},
		{"grace, 3 h after the evaluation", grace, license.ClassChange, license.MaxEvaluationAge, nil, nil},
		{"grace, LocksAt reached by uptime but stale", grace, license.ClassChange, untilLock, license.ErrUnverified, nil},
	}
	// A grace period that ends within the maximum age: LocksAt reached by uptime while fresh.
	soon := snapshotAt(expiry.Add(7*day-time.Hour), baseline())
	require.Equal(t, license.PhaseGrace, soon.Eval.Phase)
	rows = append(rows,
		row{"grace, 59 minutes before LocksAt", soon, license.ClassChange, 59 * time.Minute, nil, nil},
		row{"grace, LocksAt reached 1 h after the evaluation", soon, license.ClassChange, time.Hour, license.ErrLocked, license.ErrUnverified},
		row{"grace, LocksAt passed, read-only", soon, license.ClassReadOnly, 2 * time.Hour, license.ErrLocked, license.ErrUnverified},
		row{"grace, LocksAt passed and stale", soon, license.ClassChange, 5 * time.Hour, license.ErrUnverified, nil},
	)
	for _, r := range rows {
		got := license.AllowIn(r.snap, r.class, r.since)
		if r.want == nil {
			assert.NoError(t, got, r.name)
		} else {
			assert.ErrorIs(t, got, r.want, r.name)
		}
		if r.not != nil {
			assert.NotErrorIs(t, got, r.not, r.name)
		}
	}
}

// Every path that treats a refusal as "held in lock" keeps working: ErrUnverified is an ErrLocked.
func TestErrUnverifiedIsALockRefusal(t *testing.T) {
	assert.ErrorIs(t, license.ErrUnverified, license.ErrLocked)
	assert.NotErrorIs(t, license.ErrLocked, license.ErrUnverified)
}

// The held jump of R26 keeps license time on the held clock, and the gate advances that time by
// uptime only: a forward jump of the wall clock between evaluations neither locks nor unlocks.
func TestGateAdvancesTheEffectiveTimeNotTheWallClock(t *testing.T) {
	s := snapshotAt(expiry.Add(6*day), baseline())
	s.Reading.Wall = expiry.Add(300 * day) // the system clock jumped; the evaluation held it
	assert.NoError(t, license.AllowIn(s, license.ClassChange, time.Hour))
	s.Reading.Wall = expiry.Add(-300 * day) // the system clock was set back; license time did not follow
	assert.ErrorIs(t, license.AllowIn(s, license.ClassChange, day), license.ErrLocked)
}
