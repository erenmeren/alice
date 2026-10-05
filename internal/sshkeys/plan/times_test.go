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

// Re-review A-m5: after downtime the next run moves past every missed interval in one step, to the
// first boundary whose notice is still ahead (one nothing-to-rotate mail, not one per tick).
func TestNextRunAfterCatchesUpInOneStep(t *testing.T) {
	prev := t0
	assert.Equal(t, t0.Add(7*day), NextRunAfter(prev, 7, 24, t0), "on time: one interval")
	now := t0.Add(10*7*day + time.Hour) // ten intervals missed
	next := NextRunAfter(prev, 7, 24, now)
	assert.Equal(t, t0.Add(11*7*day), next)
	assert.True(t, NoticeDue(next, 24).After(now), "the next notice is ahead")
	assert.False(t, NoticeDue(next.Add(-7*day), 24).After(now), "and it is the first such boundary")
	// The notice of the boundary right after now has passed already: one more interval.
	now = t0.Add(3*7*day - time.Hour)
	assert.Equal(t, t0.Add(4*7*day), NextRunAfter(prev, 7, 24, now))
	// A notice longer than the interval still lands ahead of now.
	next = NextRunAfter(prev, 1, 72, t0.Add(30*day))
	assert.True(t, NoticeDue(next, 72).After(t0.Add(30*day)))
	assert.False(t, NoticeDue(next.Add(-day), 72).After(t0.Add(30*day)))
	assert.Equal(t, t0.Add(day), NextRunAfter(prev, 1, 0, t0.Add(-day)), "a clock behind: one interval, never earlier")
}

// Re-review N-m10: a run cancelled for an undelivered notice counts for its own interval only: the
// next boundary after now is the next run, even when its notice is already due (1-day intervals);
// after downtime the missed boundaries are skipped.
func TestNextBoundaryAfterKeepsTheNextInterval(t *testing.T) {
	for _, days := range []int{1, 2, 7} {
		prev := t0
		cancelledAt := prev.Add(time.Minute) // cancelled at about its planned time
		assert.Equal(t, prev.Add(time.Duration(days)*day), NextBoundaryAfter(prev, days, cancelledAt), "%d days", days)
		late := prev.Add(time.Duration(5*days)*day + time.Hour) // downtime
		assert.Equal(t, prev.Add(time.Duration(6*days)*day), NextBoundaryAfter(prev, days, late), "%d days after downtime", days)
		assert.Equal(t, prev.Add(time.Duration(days)*day), NextBoundaryAfter(prev, days, prev.Add(-day)), "%d days, clock behind", days)
	}
}
