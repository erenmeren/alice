package clock

import (
	"sync"
	"time"
)

// Offset is a clock shifted by an adjustable offset from a base clock. Only the
// test-only e2e build uses it (POST /test/clock); release builds use Real.
// Timers and tickers are not shifted: they measure durations on the base clock.
//
// A forward Advance models "time passes" (the demo clock), so it also counts as
// uptime in Elapsed. JumpWall models an administrator changing the system clock:
// only Now moves. Elapsed never decreases.
type Offset struct {
	mu   sync.Mutex
	base Clock
	off  time.Duration // added to the base wall time
	up   time.Duration // added to the base uptime
}

// NewOffset returns an Offset with a zero offset.
func NewOffset(base Clock) *Offset { return &Offset{base: base} }

// Now returns the base time plus the offset.
func (o *Offset) Now() time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.base.Now().Add(o.off)
}

// After delegates to the base clock.
func (o *Offset) After(d time.Duration) <-chan time.Time { return o.base.After(d) }

// NewTicker delegates to the base clock.
func (o *Offset) NewTicker(d time.Duration) Ticker { return o.base.NewTicker(d) }

// Elapsed returns the base clock's uptime (zero if it has none) plus every forward Advance.
func (o *Offset) Elapsed() time.Duration {
	o.mu.Lock()
	defer o.mu.Unlock()
	var base time.Duration
	if m, ok := o.base.(Monotonic); ok {
		base = m.Elapsed()
	}
	return base + o.up
}

// Advance moves Now forward by d (backward for negative d). A forward move is also uptime.
func (o *Offset) Advance(d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.off += d
	if d > 0 {
		o.up += d
	}
}

// JumpWall moves Now by d without adding uptime (a wall-clock change).
func (o *Offset) JumpWall(d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.off += d
}

// Reset sets the wall offset back to zero. Uptime is kept: it never decreases.
func (o *Offset) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.off = 0
}
