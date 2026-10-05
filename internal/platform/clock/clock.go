// Package clock abstracts time so that time-dependent logic (licenses,
// sessions, certificate expiry) can be tested deterministically.
package clock

import (
	"sort"
	"sync"
	"time"
)

// Clock is the time source injected into time-dependent code. All times it
// returns are in UTC.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
	NewTicker(d time.Duration) Ticker
}

// Ticker mirrors the parts of time.Ticker that Alice uses.
type Ticker interface {
	// C returns the channel on which ticks are delivered.
	C() <-chan time.Time
	// Stop turns the ticker off. No more ticks are sent after Stop returns.
	Stop()
}

// Monotonic measures elapsed process time ("uptime"). It never decreases and is not
// affected when someone changes the wall clock (spec R26 compares the two).
type Monotonic interface {
	Elapsed() time.Duration
}

// Real is the production clock.
type Real struct{}

// Now returns the current wall-clock time in UTC.
func (Real) Now() time.Time { return time.Now().UTC() }

// After waits for d and then sends the current UTC time on the returned channel.
func (Real) After(d time.Duration) <-chan time.Time {
	src := time.After(d)
	out := make(chan time.Time, 1)
	go func() { out <- (<-src).UTC() }()
	return out
}

// processStart carries Go's monotonic clock reading, so Real.Elapsed ignores wall-clock changes.
var processStart = time.Now()

// Elapsed returns the monotonic time since the process started.
func (Real) Elapsed() time.Duration { return time.Since(processStart) }

// NewTicker returns a Ticker backed by time.Ticker.
func (Real) NewTicker(d time.Duration) Ticker {
	t := time.NewTicker(d)
	out := make(chan time.Time, 1)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		for {
			select {
			case v := <-t.C:
				select {
				case out <- v.UTC():
				default:
				}
			case <-done:
				return
			}
		}
	}()
	return &realTicker{t: t, c: out, stop: func() { once.Do(func() { t.Stop(); close(done) }) }}
}

type realTicker struct {
	t    *time.Ticker
	c    chan time.Time
	stop func()
}

func (r *realTicker) C() <-chan time.Time { return r.c }
func (r *realTicker) Stop()               { r.stop() }

// Fake is a manually controlled clock for tests. It is safe for concurrent
// use. Set and Advance fire due timers and tickers deterministically; forward
// moves also count as uptime (Elapsed), JumpWall moves only the wall clock.
type Fake struct {
	mu      sync.Mutex
	cond    *sync.Cond // signalled when a timer or ticker is registered; on mu
	now     time.Time
	elapsed time.Duration
	timers  []*fakeTimer
	tickers []*fakeTicker
}

type fakeTimer struct {
	at time.Time
	ch chan time.Time
}

type fakeTicker struct {
	f       *Fake
	period  time.Duration
	next    time.Time
	ch      chan time.Time
	stopped bool
}

// NewFake returns a Fake set to t.
func NewFake(t time.Time) *Fake {
	f := &Fake{now: t.UTC()}
	f.cond = sync.NewCond(&f.mu)
	return f
}

// BlockUntil waits until at least timers pending timers (After) and tickers tickers are
// registered, so a test can advance the clock exactly when the code under test waits on it,
// without sleeping. Fired timers are no longer pending.
func (f *Fake) BlockUntil(timers, tickers int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for len(f.timers) < timers || len(f.tickers) < tickers {
		f.cond.Wait()
	}
}

// signal wakes BlockUntil. The caller holds f.mu.
func (f *Fake) signal() {
	if f.cond != nil {
		f.cond.Broadcast()
	}
}

// Now returns the fake's current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Set moves the fake to t and fires everything that became due.
// Moving backwards fires nothing.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.moveTo(t.UTC())
}

// Advance moves the fake forward (or backward for negative d) and fires
// everything that became due.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.moveTo(f.now.Add(d))
}

// AdvanceToNextTimer moves the fake forward to the earliest pending After deadline and fires it (with every other
// timer and ticker due by then), and reports true; with no pending timer it changes nothing and reports false. A
// test that drives code waiting on the fake moves time exactly by what the code waits for, whatever the machine's
// load, instead of by a fixed step per wall-clock interval. Tickers alone do not count as pending.
func (f *Fake) AdvanceToNextTimer() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.timers) == 0 {
		return false
	}
	next := f.timers[0].at
	for _, tm := range f.timers[1:] {
		if tm.at.Before(next) {
			next = tm.at
		}
	}
	if !next.After(f.now) { // due already (a backward Set moved now before it): fire it where now is
		next = f.now.Add(time.Nanosecond)
	}
	f.moveTo(next)
	return true
}

// Elapsed returns the fake uptime: the sum of all forward moves made by Set and Advance.
func (f *Fake) Elapsed() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.elapsed
}

// JumpWall moves only the wall clock by d, like an administrator setting the system
// time: Elapsed does not change, nothing fires, and pending timers and tickers keep
// their remaining durations (Go timers use the monotonic clock too).
func (f *Fake) JumpWall(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	for _, tm := range f.timers {
		tm.at = tm.at.Add(d)
	}
	for _, tk := range f.tickers {
		tk.next = tk.next.Add(d)
	}
}

// After returns a channel that receives the fake time once d has elapsed on
// the fake clock. A non-positive d fires immediately.
func (f *Fake) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- f.now
		return ch
	}
	f.timers = append(f.timers, &fakeTimer{at: f.now.Add(d), ch: ch})
	f.signal()
	return ch
}

// NewTicker returns a Ticker that ticks every d of fake time. It panics if d
// is not positive, like time.NewTicker.
func (f *Fake) NewTicker(d time.Duration) Ticker {
	if d <= 0 {
		panic("clock: non-positive interval for NewTicker")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTicker{f: f, period: d, next: f.now.Add(d), ch: make(chan time.Time, 1)}
	f.tickers = append(f.tickers, t)
	f.signal()
	return t
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }

func (t *fakeTicker) Stop() {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	t.stopped = true
	for i, x := range t.f.tickers {
		if x == t {
			t.f.tickers = append(t.f.tickers[:i], t.f.tickers[i+1:]...)
			break
		}
	}
}

// moveTo sets now to target. Moving forward counts as uptime, fires every due
// timer once (in deadline order) and gives every due ticker one tick carrying its
// latest due time: like time.Ticker with a slow receiver, missed ticks are dropped.
// The ticker schedule is advanced arithmetically, so the cost does not depend on
// how many periods the move spans. The caller must hold f.mu.
func (f *Fake) moveTo(target time.Time) {
	if !target.After(f.now) {
		f.now = target
		return
	}
	f.elapsed += target.Sub(f.now)
	sort.SliceStable(f.timers, func(i, j int) bool { return f.timers[i].at.Before(f.timers[j].at) })
	n := len(f.timers)
	remaining := f.timers[:0]
	for _, tm := range f.timers {
		if tm.at.After(target) {
			remaining = append(remaining, tm)
			continue
		}
		tm.ch <- tm.at // buffered (1) and fires once, never blocks
	}
	for i := len(remaining); i < n; i++ {
		f.timers[i] = nil // drop references to fired timers
	}
	f.timers = remaining
	for _, tk := range f.tickers {
		if tk.next.After(target) {
			continue
		}
		last := tk.next.Add(target.Sub(tk.next) / tk.period * tk.period)
		select {
		case tk.ch <- last:
		default: // the receiver has not taken the previous tick yet
		}
		tk.next = last.Add(tk.period)
	}
	f.now = target
}
