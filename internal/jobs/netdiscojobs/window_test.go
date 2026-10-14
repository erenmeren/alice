package netdiscojobs

import (
	"testing"
	"time"
	_ "time/tzdata" // the zone database the production binary embeds (cmd/alice): the DST cases do not depend on the host

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery"
)

func zone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	require.NoError(t, err)
	return loc
}

// simulate ticks the schedule every minute from from to to (a scheduler tick, no wall clock) and returns the instants
// it queued a scan at; each queued scan becomes the new last.
func simulate(t *testing.T, s discovery.Schedule, from, to time.Time) []time.Time {
	t.Helper()
	var last time.Time
	var out []time.Time
	for now := from; now.Before(to); now = now.Add(time.Minute) {
		due, err := Due(s, last, now)
		require.NoError(t, err)
		if due {
			out = append(out, now)
			last = now
		}
	}
	return out
}

// perDay counts the scans per local date of loc.
func perDay(loc *time.Location, at []time.Time) map[string]int {
	out := map[string]int{}
	for _, a := range at {
		out[a.In(loc).Format(time.DateOnly)]++
	}
	return out
}

func locals(loc *time.Location, at []time.Time) []string {
	out := make([]string, 0, len(at))
	for _, a := range at {
		out = append(out, a.In(loc).Format("2006-01-02 15:04 MST"))
	}
	return out
}

func TestDueWithoutAWindowCountsRealHours(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	every6 := discovery.Schedule{Hours: 6}
	for _, tc := range []struct {
		name string
		s    discovery.Schedule
		last time.Time
		want bool
	}{
		{"no schedule", discovery.Schedule{}, time.Time{}, false},
		{"never scanned", every6, time.Time{}, true},
		{"exactly the interval", every6, now.Add(-6 * time.Hour), true},
		{"a minute early", every6, now.Add(-6*time.Hour + time.Minute), false},
		{"last in the future: the clock was set back", every6, now.Add(time.Hour), true},
	} {
		got, err := Due(tc.s, tc.last, now)
		require.NoError(t, err, tc.name)
		assert.Equal(t, tc.want, got, tc.name)
	}
	at := simulate(t, discovery.Schedule{Hours: 6, TimeZone: "America/New_York"}, time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC))
	require.Len(t, at, 12)
	for i := 1; i < len(at); i++ {
		assert.Equal(t, 6*time.Hour, at[i].Sub(at[i-1]), "real hours, across the spring-forward night too")
	}
}

func TestDueRefusesAnInvalidSchedule(t *testing.T) {
	now := time.Now()
	for _, s := range []discovery.Schedule{
		{Hours: 1, WindowStart: "22:00", WindowEnd: "04:00", TimeZone: "Mars/Olympus"},
		{Hours: 1, WindowStart: "25:00", WindowEnd: "04:00"},
		{Hours: 1, WindowStart: "22:00", WindowEnd: "4:00"},
		{Hours: 1, WindowStart: "22:00", WindowEnd: "22:00"},
		{Hours: 1, WindowStart: "22:00"},
	} {
		_, err := Due(s, time.Time{}, now)
		assert.ErrorIs(t, err, discovery.ErrSchedule, "%+v", s)
	}
}

// A window may cross midnight; inside it the scans start at the window's opening and then every interval (slots), and
// none starts outside it.
func TestDueInsideAWindowThatCrossesMidnight(t *testing.T) {
	ist := zone(t, "Europe/Istanbul")
	s := discovery.Schedule{Hours: 6, WindowStart: "22:00", WindowEnd: "04:30", TimeZone: "Europe/Istanbul"}
	at := simulate(t, s, time.Date(2026, 10, 14, 12, 0, 0, 0, ist), time.Date(2026, 10, 16, 12, 0, 0, 0, ist))
	assert.Equal(t, []string{"2026-10-14 22:00 +03", "2026-10-15 04:00 +03", "2026-10-15 22:00 +03", "2026-10-16 04:00 +03"}, locals(ist, at))

	// Opened at 23:10 for the first time (a new scope, or a scope that was busy): the scan starts at once, the next one at
	// the next slot of the window (04:00), not six hours later (outside the window).
	got, err := Due(s, time.Time{}, time.Date(2026, 10, 14, 23, 10, 0, 0, ist))
	require.NoError(t, err)
	assert.True(t, got)
	got, err = Due(s, time.Date(2026, 10, 14, 23, 10, 0, 0, ist), time.Date(2026, 10, 15, 3, 59, 0, 0, ist))
	require.NoError(t, err)
	assert.False(t, got)
	got, err = Due(s, time.Date(2026, 10, 14, 23, 10, 0, 0, ist), time.Date(2026, 10, 15, 4, 0, 0, 0, ist))
	require.NoError(t, err)
	assert.True(t, got)
	got, err = Due(s, time.Time{}, time.Date(2026, 10, 15, 4, 30, 0, 0, ist))
	require.NoError(t, err)
	assert.False(t, got, "the window's end is not in it")
	got, err = Due(s, time.Time{}, time.Date(2026, 10, 15, 21, 59, 0, 0, ist))
	require.NoError(t, err)
	assert.False(t, got)
}

// DST, spring forward (America/New_York, 2026-03-08: 02:00 EST jumps to 03:00 EDT). A window whose start does not exist
// that day opens at the jump (03:00 EDT) and lasts its usual length: no day is skipped, and the daily scan happens once
// every local day.
func TestDueOnTheSpringForwardDay(t *testing.T) {
	ny := zone(t, "America/New_York")
	from, to := time.Date(2026, 3, 6, 0, 0, 0, 0, ny), time.Date(2026, 3, 11, 0, 0, 0, 0, ny)

	daily := simulate(t, discovery.Schedule{Hours: 24, WindowStart: "02:00", WindowEnd: "03:00", TimeZone: "America/New_York"}, from, to)
	assert.Equal(t, []string{"2026-03-06 02:00 EST", "2026-03-07 02:00 EST", "2026-03-08 03:00 EDT", "2026-03-09 02:00 EDT",
		"2026-03-10 02:00 EDT"}, locals(ny, daily))

	// A window that lies inside the missing hour.
	inside := simulate(t, discovery.Schedule{Hours: 24, WindowStart: "02:10", WindowEnd: "02:40", TimeZone: "America/New_York"}, from, to)
	assert.Equal(t, map[string]int{"2026-03-06": 1, "2026-03-07": 1, "2026-03-08": 1, "2026-03-09": 1, "2026-03-10": 1}, perDay(ny, inside))
	assert.Equal(t, "2026-03-08 03:00 EDT", locals(ny, inside)[2])

	// Hourly inside a window that starts in the missing hour: the slots start at the jump and stop at the local end
	// (04:00 EDT), so the day has one scan, not none.
	hourly := simulate(t, discovery.Schedule{Hours: 1, WindowStart: "02:30", WindowEnd: "04:00", TimeZone: "America/New_York"}, from, to)
	assert.Equal(t, map[string]int{"2026-03-06": 2, "2026-03-07": 2, "2026-03-08": 1, "2026-03-09": 2, "2026-03-10": 2}, perDay(ny, hourly))
	assert.Equal(t, []string{"2026-03-08 03:00 EDT", "2026-03-09 02:30 EDT"}, locals(ny, hourly)[4:6])

	// A window that spans the jump ends at its local end time (03:00 EDT), not two real hours after it opened: the
	// hourly slots of the day are 01:00 EST only (02:00 does not exist), and the window never reaches 04:00 EDT.
	across := simulate(t, discovery.Schedule{Hours: 1, WindowStart: "01:00", WindowEnd: "03:00", TimeZone: "America/New_York"}, from, to)
	assert.Equal(t, map[string]int{"2026-03-06": 2, "2026-03-07": 2, "2026-03-08": 1, "2026-03-09": 2, "2026-03-10": 2}, perDay(ny, across))
	assert.Equal(t, []string{"2026-03-08 01:00 EST"}, locals(ny, across)[4:5])
	got, err := Due(discovery.Schedule{Hours: 1, WindowStart: "01:00", WindowEnd: "03:00", TimeZone: "America/New_York"},
		time.Time{}, time.Date(2026, 3, 8, 3, 30, 0, 0, ny))
	require.NoError(t, err)
	assert.False(t, got, "03:30 EDT is after the window's local end")

	// A daily scan right after the window opens on a 23-hour day is not refused for being 23 hours after the last one.
	late := simulate(t, discovery.Schedule{Hours: 24, WindowStart: "01:00", WindowEnd: "01:20", TimeZone: "America/New_York"}, from, to)
	assert.Equal(t, map[string]int{"2026-03-06": 1, "2026-03-07": 1, "2026-03-08": 1, "2026-03-09": 1, "2026-03-10": 1}, perDay(ny, late))
}

// DST, fall back (America/New_York, 2026-11-01: 02:00 EDT goes back to 01:00 EST, so 01:00-02:00 happens twice). A
// window opens at the first occurrence of its start and lasts its usual length in real time: the repeated hour opens
// nothing again, so there are no double scans, and every local day still has its scan.
func TestDueOnTheFallBackDay(t *testing.T) {
	ny := zone(t, "America/New_York")
	from, to := time.Date(2026, 10, 30, 0, 0, 0, 0, ny), time.Date(2026, 11, 4, 0, 0, 0, 0, ny)

	daily := simulate(t, discovery.Schedule{Hours: 24, WindowStart: "01:00", WindowEnd: "02:00", TimeZone: "America/New_York"}, from, to)
	assert.Equal(t, []string{"2026-10-30 01:00 EDT", "2026-10-31 01:00 EDT", "2026-11-01 01:00 EDT", "2026-11-02 01:00 EST",
		"2026-11-03 01:00 EST"}, locals(ny, daily))

	hourly := simulate(t, discovery.Schedule{Hours: 1, WindowStart: "00:30", WindowEnd: "02:30", TimeZone: "America/New_York"}, from, to)
	assert.Equal(t, map[string]int{"2026-10-30": 2, "2026-10-31": 2, "2026-11-01": 2, "2026-11-02": 2, "2026-11-03": 2}, perDay(ny, hourly))
	assert.Equal(t, []string{"2026-11-01 00:30 EDT", "2026-11-01 01:30 EDT"}, locals(ny, hourly)[4:6], "01:30 EST is not scanned again")

	// A window that spans the repeated hour lasts its usual two real hours (it ends at 02:00 EST, before its local end
	// 03:00 EST is reached a third hour later): two hourly scans, as on any day.
	across := simulate(t, discovery.Schedule{Hours: 1, WindowStart: "01:00", WindowEnd: "03:00", TimeZone: "America/New_York"}, from, to)
	assert.Equal(t, map[string]int{"2026-10-30": 2, "2026-10-31": 2, "2026-11-01": 2, "2026-11-02": 2, "2026-11-03": 2}, perDay(ny, across))
	assert.Equal(t, []string{"2026-11-01 01:00 EDT", "2026-11-01 01:00 EST"}, locals(ny, across)[4:6])

	// The repeated hour itself as a window: one scan, at its first occurrence.
	repeated := simulate(t, discovery.Schedule{Hours: 1, WindowStart: "01:00", WindowEnd: "02:00", TimeZone: "America/New_York"}, from, to)
	assert.Equal(t, 1, perDay(ny, repeated)["2026-11-01"])
	assert.Equal(t, "2026-11-01 01:00 EDT", locals(ny, repeated)[2])
}

// Half-hour DST (Australia/Lord_Howe, 2026-10-04: 02:00 jumps to 02:30) follows the same rule.
func TestDueOnAHalfHourJump(t *testing.T) {
	lh := zone(t, "Australia/Lord_Howe")
	at := simulate(t, discovery.Schedule{Hours: 24, WindowStart: "02:00", WindowEnd: "02:15", TimeZone: "Australia/Lord_Howe"},
		time.Date(2026, 10, 2, 0, 0, 0, 0, lh), time.Date(2026, 10, 7, 0, 0, 0, 0, lh))
	assert.Equal(t, map[string]int{"2026-10-02": 1, "2026-10-03": 1, "2026-10-04": 1, "2026-10-05": 1, "2026-10-06": 1}, perDay(lh, at))
	assert.Equal(t, "2026-10-04 02:30", at[2].In(lh).Format("2006-01-02 15:04"))
}

// An interval of a day or more with a window counts local days between window openings: every N-th window, where N is
// the interval in days rounded up, so a scan is never earlier than the interval allows by more than a DST shift.
func TestDueWithAMultiDayIntervalCountsWindows(t *testing.T) {
	ist := zone(t, "Europe/Istanbul")
	from, to := time.Date(2026, 10, 1, 0, 0, 0, 0, ist), time.Date(2026, 10, 9, 0, 0, 0, 0, ist)
	for _, tc := range []struct {
		hours int
		days  []string
	}{
		{48, []string{"2026-10-01", "2026-10-03", "2026-10-05", "2026-10-07"}},
		{30, []string{"2026-10-01", "2026-10-03", "2026-10-05", "2026-10-07"}},
		{72, []string{"2026-10-01", "2026-10-04", "2026-10-07"}},
		{168, []string{"2026-10-01", "2026-10-08"}},
	} {
		at := simulate(t, discovery.Schedule{Hours: tc.hours, WindowStart: "03:00", WindowEnd: "05:00", TimeZone: "Europe/Istanbul"}, from, to)
		var days []string
		for _, a := range at {
			days = append(days, a.In(ist).Format(time.DateOnly))
			assert.Equal(t, "03:00", a.In(ist).Format("15:04"))
		}
		assert.Equal(t, tc.days, days, "every %d hours", tc.hours)
	}

	// A scan queued outside any window (the window was added later) counts its local date.
	s := discovery.Schedule{Hours: 48, WindowStart: "03:00", WindowEnd: "05:00", TimeZone: "Europe/Istanbul"}
	last := time.Date(2026, 10, 1, 12, 0, 0, 0, ist)
	got, err := Due(s, last, time.Date(2026, 10, 2, 3, 0, 0, 0, ist))
	require.NoError(t, err)
	assert.False(t, got)
	got, err = Due(s, last, time.Date(2026, 10, 3, 3, 0, 0, 0, ist))
	require.NoError(t, err)
	assert.True(t, got)
}

// A scope that was busy when its slot came (a scan still running) gets its scan later in the same window; once the
// window has closed, it waits for the next one.
func TestDueCatchesUpInsideTheWindowOnly(t *testing.T) {
	ist := zone(t, "Europe/Istanbul")
	s := discovery.Schedule{Hours: 24, WindowStart: "01:00", WindowEnd: "03:00", TimeZone: "Europe/Istanbul"}
	last := time.Date(2026, 10, 14, 1, 0, 0, 0, ist)
	for _, tc := range []struct {
		now  time.Time
		want bool
	}{
		{time.Date(2026, 10, 15, 2, 59, 0, 0, ist), true},
		{time.Date(2026, 10, 15, 3, 0, 0, 0, ist), false},
		{time.Date(2026, 10, 15, 0, 59, 0, 0, ist), false},
	} {
		got, err := Due(s, last, tc.now)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got, tc.now.String())
	}
}
