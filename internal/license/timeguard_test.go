package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

var w0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func guardAt(hwm time.Time) *license.Guard {
	g := &license.Guard{}
	g.SetHWM(license.HWMRecord{At: hwm, Seq: 7})
	return g
}

// L-50: the HWM follows the clock.
func TestGuardFollowsTheClock(t *testing.T) {
	g := guardAt(w0)
	for h := 1; h <= 50; h++ {
		r, events := g.Observe(w0.Add(time.Duration(h)*time.Hour), time.Duration(h)*time.Hour)
		assert.Empty(t, events)
		assert.True(t, r.Effective.Equal(w0.Add(time.Duration(h)*time.Hour)))
	}
	assert.True(t, g.HWM().At.Equal(w0.Add(50*time.Hour)))
	next := g.NextRecord()
	assert.Equal(t, uint64(8), next.Seq)
	assert.Equal(t, uint64(8), g.HWM().Seq)
}

// L-51 (grace day per L-22's rule, R36 item 11), L-52, L-63.
func TestGuardRollback(t *testing.T) {
	hwm := expiry.Add(2*day + time.Hour)
	g := guardAt(hwm)
	r, events := g.Observe(expiry.Add(-10*day), 0)
	assert.Equal(t, []license.ClockEvent{license.EventRollback}, events)
	assert.True(t, r.Behind)
	assert.True(t, r.Effective.Equal(hwm), "a rolled-back clock never extends the license")
	e := license.Evaluate(r.Effective, installedAt, baseline())
	assert.Equal(t, license.PhaseGrace, e.Phase)
	assert.Equal(t, 3, e.GraceDay)

	g = guardAt(w0)
	r, events = g.Observe(w0.Add(-30*time.Minute), 0) // L-52
	assert.Empty(t, events)
	assert.False(t, r.Behind)
	assert.True(t, r.Effective.Equal(w0))

	r, events = g.Observe(w0.Add(-90*time.Second), time.Minute) // L-63
	assert.Empty(t, events)
	assert.False(t, r.Behind)

	_, events = g.Observe(w0.Add(-66*time.Minute), 2*time.Minute)
	assert.Equal(t, []license.ClockEvent{license.EventRollback}, events, "beyond 65 minutes")
}

// Time keeps moving with uptime while the clock is behind: rolling the clock back a year
// must not freeze the license for a year.
func TestGuardAdvancesWithUptimeWhileBehind(t *testing.T) {
	g := guardAt(w0)
	r, _ := g.Observe(w0.Add(-365*day), 0)
	assert.True(t, r.Effective.Equal(w0))
	r, events := g.Observe(w0.Add(-365*day+3*time.Hour), 3*time.Hour)
	assert.Equal(t, []license.ClockEvent{license.EventRollback}, events)
	assert.True(t, r.Behind)
	assert.True(t, r.Effective.Equal(w0.Add(3*time.Hour)))
}

// L-58: restarts with a rolled-back clock never move the effective time backwards.
func TestGuardRestartsNeverMoveBackwards(t *testing.T) {
	g := guardAt(w0)
	last := w0
	for i := range 10 {
		r, _ := g.Observe(w0.Add(-time.Duration(i+1)*day), 0)
		assert.False(t, r.Effective.Before(last), "restart %d", i)
		last = r.Effective
		saved := g.NextRecord()
		g = &license.Guard{} // a restart: a new process loads the saved record
		g.SetHWM(saved)
	}
	assert.True(t, g.HWM().At.Equal(w0))
}

// L-59, L-60: a suspicious forward jump is held for 24 h of uptime, then accepted.
func TestGuardForwardJump(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 0)
	r, events := g.Observe(w0.Add(200*day), time.Hour)
	assert.Equal(t, []license.ClockEvent{license.EventJumpDetected}, events)
	require.NotNil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(time.Hour)), "license math keeps the extrapolated time")
	assert.True(t, r.Jump.Expected.Equal(w0.Add(time.Hour)))
	assert.Equal(t, 200*day-time.Hour, r.Jump.By)
	assert.True(t, g.HWM().At.Equal(w0.Add(time.Hour)), "the jumped time is not stored as the HWM")

	r, events = g.Observe(w0.Add(200*day+10*time.Hour), 11*time.Hour)
	assert.Empty(t, events)
	require.NotNil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(11*time.Hour)))

	r, events = g.Observe(w0.Add(200*day+24*time.Hour), 25*time.Hour)
	assert.Equal(t, []license.ClockEvent{license.EventJumpAccepted}, events)
	assert.Nil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(200*day+24*time.Hour)), "after 24 h of uptime the new time counts (L-60)")
	assert.Equal(t, license.PhaseLocked, license.Evaluate(r.Effective, installedAt, []license.Installed{lic(1, "LIC-A", w0.Add(-300*day), w0.Add(100*day), 10)}).Phase)
}

// L-62: a 36-hour correction is below the 48-hour threshold.
func TestGuardSmallForwardCorrectionIsAccepted(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 0)
	r, events := g.Observe(w0.Add(37*time.Hour), time.Hour)
	assert.Empty(t, events)
	assert.Nil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(37*time.Hour)))
}

func TestGuardJumpClearedWhenTheClockIsFixed(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 0)
	g.Observe(w0.Add(100*day), time.Hour)
	r, events := g.Observe(w0.Add(3*time.Hour), 2*time.Hour) // the administrator set the right time
	assert.Equal(t, []license.ClockEvent{license.EventJumpCleared}, events)
	assert.Nil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(3*time.Hour)))
}

// L-61: a correction license accepts the new time at once.
func TestGuardAcceptJump(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 0)
	_, _, ok := g.PendingJump()
	require.False(t, ok)
	g.Observe(w0.Add(100*day), time.Hour)
	expected, detected, ok := g.PendingJump()
	require.True(t, ok)
	assert.True(t, expected.Equal(w0.Add(time.Hour)))
	assert.True(t, detected.Equal(w0.Add(100*day)))
	assert.True(t, g.AcceptJump())
	assert.False(t, g.AcceptJump(), "nothing left to accept")
	r, events := g.Observe(w0.Add(100*day+time.Minute), time.Hour+time.Minute)
	assert.Empty(t, events)
	assert.True(t, r.Effective.Equal(w0.Add(100*day+time.Minute)))
	assert.True(t, g.HWM().At.Equal(w0.Add(100*day+time.Minute)), "the HWM stays at the new time")
}

// A pending jump survives a restart: its 24 hours restart from the new process start.
func TestGuardRestoreJump(t *testing.T) {
	g := guardAt(w0.Add(time.Hour))
	g.RestoreJump(w0.Add(time.Hour), w0.Add(100*day), 0)
	r, _ := g.Observe(w0.Add(100*day+time.Hour), time.Hour)
	require.NotNil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(2*time.Hour)))
	_, events := g.Observe(w0.Add(101*day+time.Hour), 25*time.Hour)
	assert.Equal(t, []license.ClockEvent{license.EventJumpAccepted}, events)
}

func TestGuardToleratesUptimeGoingBackwards(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 10*time.Hour)
	r, events := g.Observe(w0.Add(time.Hour), time.Hour)
	assert.Empty(t, events)
	assert.True(t, r.Effective.Equal(w0.Add(time.Hour)))
}

// Setting a rolled-back clock right again is not a suspicious jump: the wall clock only
// catches up with the trusted time, which kept moving with uptime.
func TestGuardFixingARolledBackClockIsNotAJump(t *testing.T) {
	g := guardAt(w0)
	_, events := g.Observe(w0.Add(-365*day), 0)
	assert.Equal(t, []license.ClockEvent{license.EventRollback}, events)
	r, events := g.Observe(w0.Add(2*time.Hour), 2*time.Hour)
	assert.Empty(t, events)
	assert.Nil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(2*time.Hour)))

	// A real jump from a clock that is behind is measured from the trusted time.
	g = guardAt(w0)
	g.Observe(w0.Add(-365*day), 0)
	r, events = g.Observe(w0.Add(100*day), time.Hour)
	assert.Equal(t, []license.ClockEvent{license.EventJumpDetected}, events)
	require.NotNil(t, r.Jump)
	assert.True(t, r.Jump.Expected.Equal(w0.Add(time.Hour)))
	assert.True(t, r.Effective.Equal(w0.Add(time.Hour)))
}
