package plan

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// §26.8 "overlap boundaries with the fake clock": a timer is due at its instant, not a nanosecond before.
func TestOverlapBoundaries(t *testing.T) {
	c := clock.NewFake(t0)
	until := OverlapUntil(c.Now(), 7*1440)
	assert.Equal(t, t0.Add(7*24*time.Hour), until)
	c.Advance(7*24*time.Hour - time.Nanosecond)
	assert.False(t, Due(c.Now(), until))
	c.Advance(time.Nanosecond)
	assert.True(t, Due(c.Now(), until))
	c.Advance(time.Hour)
	assert.True(t, Due(c.Now(), until))
	assert.Equal(t, t0, OverlapUntil(t0, 0), "an overlap of 0 ends at the verification")
	assert.Equal(t, t0.Add(time.Minute), OverlapUntil(t0, 1))
}

func TestScheduleTimes(t *testing.T) {
	assert.Equal(t, t0.Add(90*24*time.Hour), FirstRun(t0, 90))
	assert.Equal(t, t0.Add(24*time.Hour), NextRun(t0, 1))
	next := t0.Add(48 * time.Hour)
	assert.Equal(t, next.Add(-24*time.Hour), NoticeDue(next, 24))
	assert.Equal(t, next, PlannedFor(t0, next, 24), "enough notice: the scheduled time")
	assert.Equal(t, t0.Add(30*time.Hour), PlannedFor(t0.Add(6*time.Hour), t0.Add(10*time.Hour), 24), "late: now + notice")
	assert.Equal(t, t0.Add(14*24*time.Hour), DecisionDue(t0))
}

func TestReminder(t *testing.T) {
	at, ok := ReminderDue(t0, 3*1440)
	assert.True(t, ok)
	assert.Equal(t, t0.Add(-24*time.Hour), at)
	_, ok = ReminderDue(t0, 48*60)
	assert.False(t, ok, "an overlap of 48 hours or less gets no reminder")
}

func TestFresh(t *testing.T) {
	assert.True(t, Fresh(t0, t0))
	assert.True(t, Fresh(t0, t0.Add(-15*time.Minute)))
	assert.False(t, Fresh(t0, t0.Add(-15*time.Minute-time.Nanosecond)))
	assert.False(t, Fresh(t0, t0.Add(time.Second)), "a verification in the future is not fresh")
}
