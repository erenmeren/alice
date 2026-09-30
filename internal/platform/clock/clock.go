// Package clock abstracts time so that time-dependent logic (licenses,
// sessions, certificate expiry) can be tested deterministically.
package clock

import (
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
// use. Set and Advance fire due timers and tickers deterministically.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
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
func NewFake(t time.Time) *Fake { return &Fake{now: t.UTC()} }

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

// moveTo sets now to target, firing due events in chronological order.
// The caller must hold f.mu.
func (f *Fake) moveTo(target time.Time) {
	if !target.After(f.now) {
		f.now = target
		return
	}
	for {
		var at time.Time
		found := false
		for _, tm := range f.timers {
			if !tm.at.After(target) && (!found || tm.at.Before(at)) {
				at, found = tm.at, true
			}
		}
		for _, tk := range f.tickers {
			if !tk.next.After(target) && (!found || tk.next.Before(at)) {
				at, found = tk.next, true
			}
		}
		if !found {
			break
		}
		f.now = at
		remaining := f.timers[:0]
		for _, tm := range f.timers {
			if tm.at.After(at) {
				remaining = append(remaining, tm)
				continue
			}
			tm.ch <- at // buffered (1) and fires once, never blocks
		}
		f.timers = remaining
		for _, tk := range f.tickers {
			if tk.next.After(at) {
				continue
			}
			select {
			case tk.ch <- at:
			default: // drop, like time.Ticker with a slow receiver
			}
			tk.next = tk.next.Add(tk.period)
		}
	}
	f.now = target
}
