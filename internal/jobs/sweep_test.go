package jobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSweepDue: the lock sweep runs at most once per poll interval, and a last sweep that lies in the future (the
// clock was set back, or the e2e demo clock was reset after a sweep at a later time) never counts as recent: otherwise
// queued work would not be held until the clock caught up with it.
func TestSweepDue(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	poll := 2 * time.Second
	assert.True(t, sweepDue(time.Time{}, now, poll), "never swept")
	assert.False(t, sweepDue(now.Add(-time.Second), now, poll), "swept within the poll interval")
	assert.True(t, sweepDue(now.Add(-poll), now, poll), "swept a poll interval ago")
	assert.True(t, sweepDue(now.Add(31*24*time.Hour), now, poll), "last sweep in the future (clock set back)")
}
