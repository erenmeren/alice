package clock_test

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

func recv(t *testing.T, ch <-chan time.Time) (time.Time, bool) {
	t.Helper()
	select {
	case v := <-ch:
		return v, true
	default:
		return time.Time{}, false
	}
}

func TestRealReturnsUTC(t *testing.T) {
	var c clock.Clock = clock.Real{}
	assert.Equal(t, time.UTC, c.Now().Location())
}

func TestRealAfterFires(t *testing.T) {
	var c clock.Clock = clock.Real{}
	select {
	case <-c.After(time.Millisecond):
	case <-time.After(5 * time.Second):
		t.Fatal("Real.After did not fire")
	}
}

func TestRealTickerTicksAndStops(t *testing.T) {
	var c clock.Clock = clock.Real{}
	tk := c.NewTicker(time.Millisecond)
	select {
	case <-tk.C():
	case <-time.After(5 * time.Second):
		t.Fatal("Real ticker did not tick")
	}
	tk.Stop()
}

func TestFakeSetAndAdvance(t *testing.T) {
	start := time.Date(2026, 9, 29, 12, 0, 0, 0, time.FixedZone("TRT", 3*3600))
	f := clock.NewFake(start)
	var c clock.Clock = f

	assert.True(t, c.Now().Equal(start))
	assert.Equal(t, time.UTC, c.Now().Location())

	f.Advance(90 * time.Minute)
	assert.True(t, c.Now().Equal(start.Add(90*time.Minute)))

	later := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Set(later)
	assert.True(t, c.Now().Equal(later))
}

func TestFakeAfterFiresOnAdvance(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	ch := f.After(time.Minute)

	f.Advance(59 * time.Second)
	_, ok := recv(t, ch)
	assert.False(t, ok, "must not fire early")

	f.Advance(time.Second)
	v, ok := recv(t, ch)
	require.True(t, ok, "must fire at deadline")
	assert.True(t, v.Equal(start.Add(time.Minute)))
}

func TestFakeAdvanceToNextTimer(t *testing.T) {
	start := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	assert.False(t, f.AdvanceToNextTimer(), "nothing pending: nothing moves")
	assert.Equal(t, start, f.Now())

	late, early := f.After(7*time.Second), f.After(2*time.Second)
	tk := f.NewTicker(time.Second)
	defer tk.Stop()
	require.True(t, f.AdvanceToNextTimer())
	assert.Equal(t, start.Add(2*time.Second), f.Now(), "to the earliest deadline, exactly")
	got, ok := recv(t, early)
	require.True(t, ok)
	assert.Equal(t, start.Add(2*time.Second), got)
	_, ok = recv(t, late)
	assert.False(t, ok, "the later timer is still pending")
	_, ok = recv(t, tk.C())
	assert.True(t, ok, "a ticker due on the way ticks")
	require.True(t, f.AdvanceToNextTimer())
	assert.Equal(t, start.Add(7*time.Second), f.Now())
	_, ok = recv(t, late)
	assert.True(t, ok)
	assert.False(t, f.AdvanceToNextTimer(), "a ticker alone is not a pending timer")
	assert.Equal(t, 7*time.Second, f.Elapsed(), "the moves count as uptime")

	// After a backward step a pending timer lies ahead again; it is reached in one move.
	ch := f.After(time.Second)
	f.Set(start)
	require.True(t, f.AdvanceToNextTimer())
	assert.Equal(t, start.Add(8*time.Second), f.Now())
	_, ok = recv(t, ch)
	assert.True(t, ok)
}

func TestFakeAfterFiresOnSet(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	ch := f.After(time.Hour)

	f.Set(start.Add(-time.Hour))
	_, ok := recv(t, ch)
	assert.False(t, ok, "moving backwards must not fire")

	f.Set(start.Add(2 * time.Hour))
	_, ok = recv(t, ch)
	assert.True(t, ok)
}

func TestFakeAfterNonPositiveFiresImmediately(t *testing.T) {
	f := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	_, ok := recv(t, f.After(0))
	assert.True(t, ok)
}

func TestFakeAfterFiresOnce(t *testing.T) {
	f := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	ch := f.After(time.Second)
	f.Advance(time.Second)
	_, ok := recv(t, ch)
	require.True(t, ok)
	f.Advance(time.Hour)
	_, ok = recv(t, ch)
	assert.False(t, ok)
}

func TestFakeTickerTicksEachPeriod(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	tk := f.NewTicker(time.Minute)
	defer tk.Stop()

	f.Advance(30 * time.Second)
	_, ok := recv(t, tk.C())
	assert.False(t, ok)

	f.Advance(30 * time.Second)
	v, ok := recv(t, tk.C())
	require.True(t, ok)
	assert.True(t, v.Equal(start.Add(time.Minute)))

	f.Advance(time.Minute)
	v, ok = recv(t, tk.C())
	require.True(t, ok)
	assert.True(t, v.Equal(start.Add(2*time.Minute)))
}

func TestFakeTickerMultipleTicksDropsLikeTimeTicker(t *testing.T) {
	f := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	tk := f.NewTicker(time.Minute)
	defer tk.Stop()

	f.Advance(10 * time.Minute) // must not block although 10 ticks are due
	_, ok := recv(t, tk.C())
	require.True(t, ok)
	_, ok = recv(t, tk.C())
	assert.False(t, ok, "channel buffer is 1; extra ticks are dropped")

	f.Advance(time.Minute)
	_, ok = recv(t, tk.C())
	assert.True(t, ok, "ticker keeps its schedule after a burst")
}

func TestFakeTickerStop(t *testing.T) {
	f := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	tk := f.NewTicker(time.Minute)
	tk.Stop()
	tk.Stop() // idempotent
	f.Advance(time.Hour)
	_, ok := recv(t, tk.C())
	assert.False(t, ok)
}

func TestFakeTickerPanicsOnNonPositivePeriod(t *testing.T) {
	f := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	assert.Panics(t, func() { f.NewTicker(0) })
}

func TestFakeConcurrentUse(t *testing.T) {
	f := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	tk := f.NewTicker(time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				f.Advance(time.Second)
				_ = f.Now()
				_ = f.After(time.Second)
				select {
				case <-tk.C():
				default:
				}
			}
		}()
	}
	wg.Wait()
	tk.Stop()
	assert.True(t, f.Now().Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(800*time.Second)))
}

// Carry from Phase 0/1: a long advance must not loop once per tick (a year of
// one-millisecond ticks is 3e10 iterations).
func TestFakeLongAdvanceIsFast(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	tk := f.NewTicker(time.Millisecond)
	defer tk.Stop()
	timer := f.After(24 * time.Hour)

	done := make(chan struct{})
	go func() {
		f.Advance(365 * 24 * time.Hour)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Advance over a year with a 1 ms ticker did not return within 2 s")
	}
	v, ok := recv(t, tk.C())
	require.True(t, ok)
	assert.True(t, v.Equal(start.Add(365*24*time.Hour)), "the ticker delivers its latest due tick, got %s", v)
	_, ok = recv(t, tk.C())
	assert.False(t, ok, "one tick per move")
	fired, ok := recv(t, timer)
	require.True(t, ok)
	assert.True(t, fired.Equal(start.Add(24*time.Hour)), "a timer fires with its own deadline")

	f.Advance(time.Millisecond)
	v, ok = recv(t, tk.C())
	require.True(t, ok, "the ticker keeps its schedule after a long move")
	assert.True(t, v.Equal(start.Add(365*24*time.Hour+time.Millisecond)))
}

func TestFakeTickerWithOffsetPhaseDeliversLatestDueTick(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	tk := f.NewTicker(time.Hour)
	defer tk.Stop()
	f.Advance(150 * time.Minute) // ticks due at +1h and +2h
	v, ok := recv(t, tk.C())
	require.True(t, ok)
	assert.True(t, v.Equal(start.Add(2*time.Hour)))
	f.Advance(30 * time.Minute) // +3h
	v, ok = recv(t, tk.C())
	require.True(t, ok)
	assert.True(t, v.Equal(start.Add(3*time.Hour)))
}

func TestRealElapsedGrows(t *testing.T) {
	var m clock.Monotonic = clock.Real{}
	a := m.Elapsed()
	time.Sleep(2 * time.Millisecond)
	assert.Greater(t, m.Elapsed(), a)
}

func TestFakeElapsedCountsOnlyForwardMoves(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	var m clock.Monotonic = f
	assert.Zero(t, m.Elapsed())
	f.Advance(time.Hour)
	assert.Equal(t, time.Hour, f.Elapsed())
	f.Set(start) // backwards: the wall clock moves, uptime does not
	assert.Equal(t, time.Hour, f.Elapsed())
	assert.True(t, f.Now().Equal(start))
	f.Set(start.Add(90 * time.Minute))
	assert.Equal(t, 2*time.Hour+30*time.Minute, f.Elapsed())
}

func TestFakeJumpWallMovesOnlyTheWallClock(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	timer := f.After(2 * time.Hour)
	tk := f.NewTicker(time.Hour)
	defer tk.Stop()

	f.JumpWall(72 * time.Hour)
	assert.True(t, f.Now().Equal(start.Add(72*time.Hour)))
	assert.Zero(t, f.Elapsed())
	_, ok := recv(t, timer)
	assert.False(t, ok, "a wall-clock jump fires nothing")
	_, ok = recv(t, tk.C())
	assert.False(t, ok)

	f.Advance(time.Hour)
	_, ok = recv(t, tk.C())
	assert.True(t, ok, "the ticker still ticks after its period of uptime")
	_, ok = recv(t, timer)
	assert.False(t, ok)
	f.Advance(time.Hour)
	_, ok = recv(t, timer)
	assert.True(t, ok, "the timer fires after its remaining duration")
	assert.Equal(t, 2*time.Hour, f.Elapsed())

	f.JumpWall(-100 * time.Hour)
	assert.True(t, f.Now().Equal(start.Add(-26*time.Hour)))
	assert.Equal(t, 2*time.Hour, f.Elapsed())
}

func TestFakeBlockUntilWaitsForRegistrations(t *testing.T) {
	f := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	done := make(chan struct{})
	go func() {
		f.BlockUntil(1, 1)
		close(done)
	}()
	tk := f.NewTicker(time.Hour)
	defer tk.Stop()
	select {
	case <-done:
		t.Fatal("BlockUntil returned before the timer was registered")
	default:
	}
	ch := f.After(time.Minute)
	<-done
	f.Advance(time.Minute)
	<-ch
	f.BlockUntil(0, 1) // the ticker is still registered
}

// TestRealElapsedCountsSuspend: uptime comes from a clock that keeps counting while the host or virtual machine is
// suspended (CLOCK_BOOTTIME on Linux), so a long suspend is not a forward wall-clock jump for the license time guard.
func TestRealElapsedCountsSuspend(t *testing.T) {
	var mu sync.Mutex
	boot, ok := 100*time.Second, true
	restore := clock.SetBootClock(func() (time.Duration, bool) {
		mu.Lock()
		defer mu.Unlock()
		return boot, ok
	})
	defer restore()
	var m clock.Monotonic = clock.Real{}
	assert.Less(t, m.Elapsed(), time.Second)

	mu.Lock()
	boot += 72 * time.Hour // suspended for three days: the process's monotonic clock did not move
	mu.Unlock()
	assert.GreaterOrEqual(t, m.Elapsed(), 72*time.Hour, "suspended time counts as uptime")

	mu.Lock()
	ok = false // the boot clock fails: the process clock is used, and uptime never goes back
	mu.Unlock()
	assert.GreaterOrEqual(t, m.Elapsed(), 72*time.Hour, "uptime never decreases")
}

func TestRealElapsedWithoutABootClock(t *testing.T) {
	restore := clock.SetBootClock(func() (time.Duration, bool) { return 0, false })
	defer restore()
	var m clock.Monotonic = clock.Real{}
	a := m.Elapsed()
	time.Sleep(2 * time.Millisecond)
	assert.Greater(t, m.Elapsed(), a, "the process's monotonic clock is the fallback")
}

func TestBootClockOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("CLOCK_BOOTTIME is Linux only")
	}
	now, ok := clock.BootTime()
	require.True(t, ok)
	assert.Positive(t, now)
}
