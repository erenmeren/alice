package backup_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	l, err := time.LoadLocation(name)
	require.NoError(t, err)
	return l
}

func TestLastScheduled(t *testing.T) {
	ist := mustLoc(t, "Europe/Istanbul")                 // UTC+3, no daylight saving
	now := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC) // 04:00 in Istanbul
	assert.Equal(t, time.Date(2026, 10, 9, 23, 30, 0, 0, time.UTC), backup.LastScheduled(now, ist, "02:30"))
	now = time.Date(2026, 10, 9, 23, 29, 0, 0, time.UTC) // 02:29 local: the previous day's run
	assert.Equal(t, time.Date(2026, 10, 8, 23, 30, 0, 0, time.UTC), backup.LastScheduled(now, ist, "02:30"))
	exact := time.Date(2026, 10, 9, 23, 30, 0, 0, time.UTC)
	assert.Equal(t, exact, backup.LastScheduled(exact, ist, "02:30"), "the instant itself counts")
	assert.Equal(t, time.UTC, backup.LastScheduled(now, ist, "02:30").Location())
}

func TestDueAcrossDaylightSaving(t *testing.T) {
	ny := mustLoc(t, "America/New_York")
	// 2026-03-08: 02:30 does not exist in New York; Go resolves it to 01:30 EST, which is 06:30Z; the run happens once, at that instant.
	spring := time.Date(2026, 3, 8, 8, 0, 0, 0, time.UTC) // 04:00 EDT
	assert.Equal(t, time.Date(2026, 3, 8, 6, 30, 0, 0, time.UTC), backup.LastScheduled(spring, ny, "02:30"))
	// 2026-11-01: 01:30 happens twice; the first one counts and the second does not run again.
	first := time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC)  // 01:30 EDT
	second := time.Date(2026, 11, 1, 6, 40, 0, 0, time.UTC) // 01:40 EST, after the repeat of 01:30
	assert.True(t, backup.Due(first, ny, "01:30", time.Date(2026, 10, 31, 5, 31, 0, 0, time.UTC)))
	assert.False(t, backup.Due(second, ny, "01:30", first.Add(time.Minute)))
}

func TestDue(t *testing.T) {
	utc := time.UTC
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, utc)
	assert.True(t, backup.Due(now, utc, "02:30", time.Time{}), "never backed up")
	assert.True(t, backup.Due(now, utc, "02:30", now.Add(-48*time.Hour)), "missed run catches up at the next check (§20.2)")
	assert.False(t, backup.Due(now, utc, "02:30", time.Date(2026, 10, 10, 2, 31, 0, 0, utc)), "already done today")
	assert.True(t, backup.Due(now, utc, "02:30", time.Date(2026, 10, 10, 2, 29, 0, 0, utc)), "a run before the instant does not count")
	assert.False(t, backup.Due(time.Date(2026, 10, 10, 2, 29, 0, 0, utc), utc, "02:30", time.Date(2026, 10, 9, 2, 31, 0, 0, utc)))
	assert.False(t, backup.Due(now, utc, "02:30", time.Date(2026, 10, 10, 2, 30, 0, 0, utc)), "a run at the instant counts")
}

func TestParseTimeOfDay(t *testing.T) {
	for _, ok := range []string{"00:00", "02:30", "23:59", "12:05"} {
		_, _, err := backup.ParseTimeOfDay(ok)
		assert.NoError(t, err, ok)
	}
	for _, bad := range []string{"", "2:30", "24:00", "12:60", "12-30", "12:3", "1230", " 02:30", "02:30 ", "+1:30", "٠٢:٣٠"} {
		_, _, err := backup.ParseTimeOfDay(bad)
		assert.Error(t, err, bad)
	}
	assert.Equal(t, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), backup.LastScheduled(time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC),
		time.UTC, "not a time"), "an unreadable time falls back to midnight rather than never running")
}
