package license_test

import (
	"errors"
	"fmt"
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
		{"evaluated locked, fresh", locked, license.ClassChange, 0, license.ErrLocked, license.ErrLockDue},
		{"evaluated locked, read-only", locked, license.ClassReadOnly, time.Minute, license.ErrLocked, license.ErrLockDue},
		{"evaluated locked, stale", locked, license.ClassChange, 4 * time.Hour, license.ErrUnverified, nil},
		{"grace, 3 h after the evaluation", grace, license.ClassChange, license.MaxEvaluationAge, nil, nil},
		{"grace, LocksAt reached by uptime but stale", grace, license.ClassChange, untilLock, license.ErrUnverified, nil},
	}
	// A grace period that ends within the maximum age: LocksAt reached by uptime while fresh.
	soon := snapshotAt(expiry.Add(7*day-time.Hour), baseline())
	require.Equal(t, license.PhaseGrace, soon.Eval.Phase)
	rows = append(rows,
		row{"grace, 59 minutes before LocksAt", soon, license.ClassChange, 59 * time.Minute, nil, nil},
		row{"grace, LocksAt reached 1 h after the evaluation", soon, license.ClassChange, time.Hour, license.ErrLockDue, license.ErrUnverified},
		row{"grace, LocksAt passed, read-only", soon, license.ClassReadOnly, 2 * time.Hour, license.ErrLockDue, license.ErrUnverified},
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
		if r.want != nil && r.not != nil {
			assert.NotErrorIs(t, got, license.ErrUnverified, r.name)
		}
		if errors.Is(r.want, license.ErrLocked) {
			confirmed := !errors.Is(r.want, license.ErrUnverified) && !errors.Is(r.want, license.ErrLockDue)
			assert.Equal(t, confirmed, license.ConfirmedLock(got), "%s: only an evaluated lock is confirmed", r.name)
		}
	}
}

// The gate's own clock can be wrong: a pending license that starts between the last evaluation
// and LocksAt keeps the license active, so a lock estimated from LocksAt is only "due" (refused,
// nothing lasting decided) until an evaluation confirms or refutes it.
func TestLockDueIsNotAConfirmedLock(t *testing.T) {
	at := expiry.Add(7*day - time.Hour) // grace, one hour before LocksAt
	renewal := lic(2, "LIC-B", at.Add(30*time.Minute), expiry.Add(400*day), 10)
	snap := snapshotAt(at, append(baseline(), renewal))
	require.Equal(t, license.PhaseGrace, snap.Eval.Phase)
	require.NotNil(t, snap.Eval.Pending)
	later := at.Add(time.Hour)
	assert.Equal(t, license.PhaseActive, license.Evaluate(later, installedAt, append(baseline(), renewal)).Phase,
		"an evaluation at that instant finds the renewal in force")
	err := license.AllowIn(snap, license.ClassChange, time.Hour)
	assert.ErrorIs(t, err, license.ErrLockDue)
	assert.ErrorIs(t, err, license.ErrLocked, "refused as in lock (fail closed), answered ALC-LIC-0001")
	assert.False(t, license.ConfirmedLock(err), "but nothing lasting is decided from it")
}

func TestDenialReasons(t *testing.T) {
	assert.Equal(t, "unverified", license.DenialReason(license.ErrUnverified))
	assert.Equal(t, "lock_due", license.DenialReason(fmt.Errorf("deploy: %w", license.ErrLockDue)))
	assert.Equal(t, "locked", license.DenialReason(license.ErrLocked))
	assert.Empty(t, license.DenialReason(license.ErrTargetLimit))
	assert.Empty(t, license.DenialReason(nil))
	assert.True(t, license.ConfirmedLock(fmt.Errorf("x: %w", license.ErrLocked)))
	assert.False(t, license.ConfirmedLock(license.ErrUnverified))
	assert.False(t, license.ConfirmedLock(nil))
	assert.ErrorIs(t, license.ErrLockDue, license.ErrLocked)
	assert.NotErrorIs(t, license.ErrLockDue, license.ErrUnverified)
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
	soon := snapshotAt(expiry.Add(7*day-time.Hour), baseline())
	soon.Reading.Wall = expiry.Add(-300 * day)
	assert.ErrorIs(t, license.AllowIn(soon, license.ClassChange, time.Hour), license.ErrLockDue)
}
