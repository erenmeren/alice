package expiry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

func days(n float64) time.Duration { return time.Duration(n * float64(24*time.Hour)) }

func TestNormalize(t *testing.T) {
	got, err := Normalize([]int{7, 60, 1, 30, 14})
	require.NoError(t, err)
	assert.Equal(t, []int{60, 30, 14, 7, 1}, got)
	in := []int{1, 2}
	got, err = Normalize(in)
	require.NoError(t, err)
	assert.Equal(t, []int{2, 1}, got)
	assert.Equal(t, []int{1, 2}, in, "the input is not changed")
	for _, bad := range [][]int{nil, {}, {0}, {-1}, {366}, {7, 7}, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}} {
		_, err := Normalize(bad)
		assert.ErrorIs(t, err, ErrThresholds, "%v", bad)
	}
	got, err = Normalize([]int{365, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	require.NoError(t, err)
	assert.Len(t, got, MaxThresholds)
	assert.Equal(t, []int{60, 30, 14, 7, 1}, DefaultThresholds)
}

func TestLevel(t *testing.T) {
	th := DefaultThresholds
	cases := []struct {
		left  time.Duration
		level int
		ok    bool
	}{
		{days(61), 0, false},
		{days(60) + time.Second, 0, false},
		{days(60), 60, true},
		{days(31), 60, true},
		{days(30), 30, true},
		{days(14.5), 30, true},
		{days(14), 14, true},
		{days(7), 7, true},
		{days(1) + time.Second, 7, true},
		{days(1), 1, true},
		{time.Second, 1, true},
		{0, Expired, true},
		{-days(400), Expired, true},
	}
	for _, c := range cases {
		level, ok := Level(t0.Add(c.left), t0, th)
		assert.Equal(t, c.ok, ok, "left %v", c.left)
		assert.Equal(t, c.level, level, "left %v", c.left)
	}
	level, ok := Level(t0.Add(days(10)), t0, []int{7, 30}) // order of the slice does not matter
	assert.True(t, ok)
	assert.Equal(t, 30, level)
}

func TestDueTable(t *testing.T) {
	th := DefaultThresholds
	cases := []struct {
		name  string
		left  time.Duration
		sent  []int
		want  int
		isDue bool
	}{
		{"nothing reached", days(90), nil, 0, false},
		{"first threshold", days(59), nil, 60, true},
		{"already sent at this level", days(59), []int{60}, 0, false},
		{"next level after an earlier one", days(29), []int{60}, 30, true},
		{"a more urgent one was sent: never the less urgent", days(29), []int{7}, 0, false},
		{"catch-up: only the most urgent reached level", days(13), []int{60}, 14, true},
		{"catch-up with nothing sent", days(0.5), nil, 1, true},
		{"expired after the last threshold", -time.Hour, []int{60, 30, 14, 7, 1}, Expired, true},
		{"expired sent once", -days(3), []int{1, Expired}, 0, false},
		{"expired with nothing sent", -days(30), nil, Expired, true},
	}
	for _, c := range cases {
		got, ok := Due(t0.Add(c.left), t0, th, c.sent)
		assert.Equal(t, c.isDue, ok, c.name)
		assert.Equal(t, c.want, got, c.name)
	}
}

// Review Focus 2: hourly ticks over 70 days send each threshold once, in order, and the expired notice once.
func TestHourlyTicksSendEachThresholdOnce(t *testing.T) {
	expires := t0.Add(days(65))
	var sent []int
	for now := t0; now.Before(expires.Add(days(5))); now = now.Add(time.Hour) {
		if level, ok := Due(expires, now, DefaultThresholds, sent); ok {
			sent = append(sent, level)
		}
	}
	assert.Equal(t, []int{60, 30, 14, 7, 1, Expired}, sent)
}

// Review Focus 2: Alice down from 31 to 13 days before the expiry sends the 14-day notice only (L-16's rule).
func TestDowntimeSendsOnlyTheMostUrgent(t *testing.T) {
	expires := t0.Add(days(70))
	var sent []int
	tick := func(now time.Time) {
		if level, ok := Due(expires, now, DefaultThresholds, sent); ok {
			sent = append(sent, level)
		}
	}
	for now := t0; now.Before(expires.Add(-days(31))); now = now.Add(time.Hour) {
		tick(now)
	}
	require.Equal(t, []int{60}, sent)
	for now := expires.Add(-days(13)); now.Before(expires.Add(days(1))); now = now.Add(time.Hour) {
		tick(now)
	}
	assert.Equal(t, []int{60, 14, 7, 1, Expired}, sent, "30 is never sent after the downtime")
}

// Review Focus 2: editing thresholds mid-series never resends a level and never sends a less urgent one; a new,
// more urgent level is sent once.
func TestThresholdEditsNeverResend(t *testing.T) {
	expires := t0.Add(days(40))
	sent := []int{60}                                               // sent at 55 days left
	_, ok := Due(expires, t0.Add(days(1)), []int{90, 60, 30}, sent) // 39 days left: level 60, already sent
	assert.False(t, ok, "adding 90 (less urgent) sends nothing")
	level, ok := Due(expires, t0.Add(days(1)), []int{90, 60, 45, 30}, sent) // level 45, more urgent than 60
	require.True(t, ok)
	assert.Equal(t, 45, level)
	sent = append(sent, level)
	_, ok = Due(expires, t0.Add(days(2)), []int{90, 60, 45, 30}, sent)
	assert.False(t, ok, "45 is not sent twice")
	_, ok = Due(expires, t0.Add(days(3)), []int{60, 30}, sent)
	assert.False(t, ok, "removing 45 again sends 60 not again")
}

func TestDaysLeft(t *testing.T) {
	assert.Equal(t, 7, DaysLeft(t0.Add(days(7)), t0))
	assert.Equal(t, 7, DaysLeft(t0.Add(days(7)-time.Hour), t0))
	assert.Equal(t, 1, DaysLeft(t0.Add(time.Second), t0))
	assert.Equal(t, 0, DaysLeft(t0, t0))
	assert.Equal(t, 0, DaysLeft(t0.Add(-days(2)), t0))
}

func TestBucketOf(t *testing.T) {
	cases := map[time.Duration]Bucket{
		-time.Second: BucketExpired, 0: BucketExpired, time.Second: Bucket7, days(7): Bucket7,
		days(7) + time.Second: Bucket30, days(30): Bucket30, days(30) + time.Second: Bucket60, days(60): Bucket60,
		days(60) + time.Second: BucketLater,
	}
	for left, want := range cases {
		assert.Equal(t, want, BucketOf(t0.Add(left), t0), "left %v", left)
	}
}

func TestHorizon(t *testing.T) {
	assert.Equal(t, days(60), Horizon(DefaultThresholds))
	assert.Equal(t, days(365), Horizon([]int{1, 365, 7}))
	assert.Equal(t, time.Duration(0), Horizon(nil))
}
