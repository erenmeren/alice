package clock

import (
	"sync"
	"time"
)

// Offset is a clock shifted by an adjustable offset from a base clock. Only the
// test-only e2e build uses it (POST /test/clock); release builds use Real.
// Timers and tickers are not shifted: they measure durations on the base clock.
type Offset struct {
	mu   sync.Mutex
	base Clock
	off  time.Duration
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

// Advance moves Now forward by d (backward for negative d).
func (o *Offset) Advance(d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.off += d
}

// Reset sets the offset back to zero.
func (o *Offset) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.off = 0
}
