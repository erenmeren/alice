package clock_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

func TestOffsetShiftsNowOnly(t *testing.T) {
	start := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	base := clock.NewFake(start)
	o := clock.NewOffset(base)
	var _ clock.Clock = o

	assert.Equal(t, start, o.Now())
	o.Advance(31 * time.Minute)
	assert.Equal(t, start.Add(31*time.Minute), o.Now())
	o.Advance(-time.Minute)
	assert.Equal(t, start.Add(30*time.Minute), o.Now())

	ch := o.After(time.Second)
	base.Advance(time.Second)
	select {
	case <-ch:
	default:
		t.Fatal("After must fire on the base clock")
	}
	assert.Equal(t, start.Add(30*time.Minute+time.Second), o.Now())

	o.Reset()
	assert.Equal(t, start.Add(time.Second), o.Now())
}

func TestOffsetIsSafeForConcurrentUse(t *testing.T) {
	o := clock.NewOffset(clock.NewFake(time.Unix(0, 0)))
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() { defer wg.Done(); o.Advance(time.Second) }()
		go func() { defer wg.Done(); _ = o.Now() }()
	}
	wg.Wait()
	assert.Equal(t, time.Unix(50, 0).UTC(), o.Now())
}

func TestOffsetElapsedAddsForwardAdvancesOnly(t *testing.T) {
	start := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	base := clock.NewFake(start)
	o := clock.NewOffset(base)
	var m clock.Monotonic = o

	base.Advance(time.Minute)
	assert.Equal(t, time.Minute, m.Elapsed())
	o.Advance(48 * time.Hour)
	assert.Equal(t, 48*time.Hour+time.Minute, o.Elapsed(), "a demo-clock advance is also uptime (not a clock jump)")
	o.Advance(-5 * time.Hour)
	assert.Equal(t, 48*time.Hour+time.Minute, o.Elapsed(), "moving back never lowers uptime")
	assert.True(t, o.Now().Equal(start.Add(43*time.Hour+time.Minute)))

	o.JumpWall(10 * 24 * time.Hour)
	assert.Equal(t, 48*time.Hour+time.Minute, o.Elapsed(), "a wall-only jump is not uptime")
	assert.True(t, o.Now().Equal(start.Add(10*24*time.Hour+43*time.Hour+time.Minute)))

	o.Reset()
	assert.True(t, o.Now().Equal(start.Add(time.Minute)))
	assert.Equal(t, 48*time.Hour+time.Minute, o.Elapsed(), "Reset keeps uptime monotonic")
}

func TestOffsetOverNonMonotonicBaseCountsAdvancesOnly(t *testing.T) {
	o := clock.NewOffset(plainClock{})
	o.Advance(time.Hour)
	assert.Equal(t, time.Hour, o.Elapsed())
}

// plainClock is a Clock without Elapsed.
type plainClock struct{}

func (plainClock) Now() time.Time                       { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
func (plainClock) After(time.Duration) <-chan time.Time { return make(chan time.Time) }
func (plainClock) NewTicker(time.Duration) clock.Ticker { return nil }
