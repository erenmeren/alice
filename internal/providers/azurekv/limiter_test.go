package azurekv

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

// runCalls starts n calls on l, each holding its slot until hold is closed, and advances the clock
// in 100 ms steps until all have finished; it returns the clock time they took and the peak count.
func runCalls(t *testing.T, clk *clock.Fake, l *vaultLimiter, n int, work func()) (time.Duration, int32) {
	t.Helper()
	start := clk.Now()
	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := l.acquire(context.Background())
			if !assert.NoError(t, err) {
				return
			}
			cur := running.Add(1)
			for p := peak.Load(); cur > p && !peak.CompareAndSwap(p, cur); p = peak.Load() {
			}
			work()
			running.Add(-1)
			rel()
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for {
		select {
		case <-done:
			return clk.Now().Sub(start), peak.Load()
		case <-time.After(time.Millisecond):
			clk.Advance(100 * time.Millisecond)
		}
	}
}

func TestPerVaultLimiter(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	a := newVaultLimiter(clk, VaultRate, VaultConcurrency)
	b := newVaultLimiter(clk, VaultRate, VaultConcurrency)

	// 20 calls at 5 per second with a burst of 5: the first five go at once, the other fifteen are
	// spread over three seconds; never more than four run at the same time.
	took, peak := runCalls(t, clk, a, 20, func() { time.Sleep(time.Millisecond) })
	assert.GreaterOrEqual(t, took, 2900*time.Millisecond)
	assert.LessOrEqual(t, took, 3200*time.Millisecond)
	assert.LessOrEqual(t, peak, int32(VaultConcurrency))

	// Another vault in the same instant does not wait for A's backlog.
	var wg sync.WaitGroup
	for range 30 {
		wg.Go(func() { // a backlog on A: 30 more reservations
			rel, err := a.acquire(context.Background())
			if err == nil {
				rel()
			}
		})
	}
	require.Eventually(t, func() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.tat.After(clk.Now().Add(3 * time.Second)) },
		5*time.Second, time.Millisecond)
	rel, err := b.acquire(context.Background())
	require.NoError(t, err, "B is not delayed by A")
	rel()
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	for done := false; !done; { // advance until every queued caller has had its turn
		select {
		case <-finished:
			done = true
		case <-time.After(time.Millisecond):
			clk.Advance(time.Second)
		}
	}
}

func TestLimiterWaitHonoursContext(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	l := newVaultLimiter(clk, VaultRate, VaultConcurrency)
	for range VaultRate { // use the burst
		rel, err := l.acquire(context.Background())
		require.NoError(t, err)
		rel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := l.acquire(ctx); errc <- err }()
	clk.BlockUntil(1, 0)
	cancel()
	assert.ErrorIs(t, <-errc, context.Canceled)

	// All concurrency slots busy: a further caller waits for a slot and honours the context.
	l2 := newVaultLimiter(clk, VaultRate, 1)
	rel, err := l2.acquire(context.Background())
	require.NoError(t, err)
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { _, err := l2.acquire(ctx2); errc <- err }()
	time.Sleep(10 * time.Millisecond)
	cancel2()
	assert.ErrorIs(t, <-errc, context.Canceled)
	rel()
}

func TestForgetTargetDropsTheLimiter(t *testing.T) {
	p := New(Options{})
	clk := clock.NewFake(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	ta, tb := uuid.New(), uuid.New()
	la := p.limiterFor(ta, "a.vault.azure.net", clk)
	lb := p.limiterFor(tb, "b.vault.azure.net", clk)
	p.ForgetTarget(ta)
	assert.NotSame(t, la, p.limiterFor(ta, "a.vault.azure.net", clk), "A's limiter was dropped with its only target")
	assert.Same(t, lb, p.limiterFor(tb, "b.vault.azure.net", clk), "B keeps its limiter")
	p.ForgetTarget(uuid.New()) // unknown target: nothing happens
}

// Two targets can name the same vault: forgetting one must not give the other a fresh limiter (that
// would double the allowed rate on the vault).
func TestForgetTargetKeepsALimiterAnotherTargetShares(t *testing.T) {
	p := New(Options{})
	clk := clock.NewFake(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	t1, t2 := uuid.New(), uuid.New()
	l := p.limiterFor(t1, "a.vault.azure.net", clk)
	assert.Same(t, l, p.limiterFor(t2, "a.vault.azure.net", clk))
	p.ForgetTarget(t1)
	assert.Same(t, l, p.limiterFor(t2, "a.vault.azure.net", clk), "t2 still shares it")
	p.ForgetTarget(t2)
	assert.NotSame(t, l, p.limiterFor(t1, "a.vault.azure.net", clk), "no target remained")
	// A target that moves to another vault leaves the first one's claim.
	p.limiterFor(t1, "b.vault.azure.net", clk)
	p.ForgetTarget(t2)
	assert.NotContains(t, p.users["a.vault.azure.net"], t1)
}

// acquiresWithoutWaiting reports whether one acquire on l returns while the fake clock stands still.
func acquiresWithoutWaiting(t *testing.T, l *vaultLimiter) bool {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		rel, err := l.acquire(context.Background())
		if err == nil {
			rel()
		}
		errc <- err
	}()
	select {
	case err := <-errc:
		require.NoError(t, err)
		return true
	case <-time.After(time.Second):
		return false // still waiting for the fake clock; the goroutine ends with the test binary
	}
}

// A clock that steps backwards (an NTP step, the e2e POST /test/reset) moves the schedule back with it: the
// next call does not wait for the difference between the old schedule and the new "now", and the step grants no
// extra request either (the burst that was used stays used).
func TestLimiterShiftsItsScheduleWhenTheClockStepsBackwards(t *testing.T) {
	for name, back := range map[string]time.Duration{"small": 300 * time.Millisecond, "large": 72 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			clk := clock.NewFake(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
			l := newVaultLimiter(clk, VaultRate, VaultConcurrency)
			for range VaultRate { // use the burst: the schedule now runs one second ahead of the clock
				rel, err := l.acquire(context.Background())
				require.NoError(t, err)
				rel()
			}
			clk.Set(clk.Now().Add(-back))
			took, _ := runCalls(t, clk, l, VaultRate, func() {})
			assert.GreaterOrEqual(t, took, 900*time.Millisecond, "no fresh burst: the step grants nothing extra")
			assert.LessOrEqual(t, took, 1300*time.Millisecond, "no wait for the difference: the calls wait only for their own slots")
		})
	}
}

// The e2e reset: the vault was idle, then the clock goes back days. The schedule is in the past either way, so
// the whole burst is there at once and nobody waits.
func TestLimiterAfterAnIdleVaultAndABackwardStep(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	l := newVaultLimiter(clk, VaultRate, VaultConcurrency)
	for range VaultRate {
		rel, err := l.acquire(context.Background())
		require.NoError(t, err)
		rel()
	}
	clk.Advance(time.Hour)
	rel, err := l.acquire(context.Background())
	require.NoError(t, err)
	rel()
	clk.Set(clk.Now().Add(-72 * time.Hour))
	for range VaultRate - 1 {
		require.True(t, acquiresWithoutWaiting(t, l), "nobody waits for the 72 hours")
	}
}

// A forward jump grants no more than the configured burst.
func TestLimiterForwardJumpGrantsNoExtraBurst(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	l := newVaultLimiter(clk, VaultRate, VaultConcurrency)
	for range VaultRate {
		rel, err := l.acquire(context.Background())
		require.NoError(t, err)
		rel()
	}
	clk.Set(clk.Now().Add(24 * time.Hour))
	for range VaultRate { // the configured burst goes at once
		require.True(t, acquiresWithoutWaiting(t, l))
	}
	took, _ := runCalls(t, clk, l, 2*VaultRate, func() {})
	assert.GreaterOrEqual(t, took, 1900*time.Millisecond, "beyond the burst the calls are spaced again")
}

// Callers racing a backwards step never see an unbounded wait, and the concurrency cap holds.
func TestLimiterBackwardStepWithConcurrentCallers(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	l := newVaultLimiter(clk, VaultRate, VaultConcurrency)
	for range VaultRate {
		rel, err := l.acquire(context.Background())
		require.NoError(t, err)
		rel()
	}
	clk.Set(clk.Now().Add(-48 * time.Hour))
	took, peak := runCalls(t, clk, l, 20, func() { time.Sleep(time.Millisecond) })
	// The burst used before the step stays used: 20 slots at 5 per second, not 48 hours.
	assert.GreaterOrEqual(t, took, 3900*time.Millisecond)
	assert.LessOrEqual(t, took, 4300*time.Millisecond)
	assert.LessOrEqual(t, peak, int32(VaultConcurrency))
}
