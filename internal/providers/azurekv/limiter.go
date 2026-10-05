package azurekv

import (
	"context"
	"sync"
	"time"

	"alice/internal/platform/clock"
)

// vaultLimiter keeps the traffic to one vault under VaultRate requests per second (burst VaultRate)
// and VaultConcurrency requests at a time, so one busy vault's polling never starves another's
// (F-44). It is a generic cell rate limiter on the injected clock: each caller reserves the next
// slot and waits for it.
type vaultLimiter struct {
	clk      clock.Clock
	interval time.Duration
	burst    time.Duration // how far ahead of "now" the schedule may run before callers wait
	slots    chan struct{}

	mu   sync.Mutex
	tat  time.Time // theoretical arrival time of the next request
	last time.Time // the latest "now" a caller saw, to notice a clock that stepped backwards
}

func newVaultLimiter(clk clock.Clock, rate, concurrency int) *vaultLimiter {
	iv := time.Second / time.Duration(rate)
	return &vaultLimiter{clk: clk, interval: iv, burst: time.Duration(rate) * iv, slots: make(chan struct{}, concurrency)}
}

// acquire waits for a rate slot and a concurrency slot; release frees the latter. It returns the
// context's error when ctx ends first.
func (l *vaultLimiter) acquire(ctx context.Context) (release func(), err error) {
	if err := ctx.Err(); err != nil { // a ready slot must not win a race against an ended context
		return nil, err
	}
	l.mu.Lock()
	now := l.clk.Now()
	if l.tat.Before(now) || now.Before(l.last) {
		// A clock that stepped backwards (an NTP step, the e2e reset) would leave the schedule
		// in the future and make the next caller wait for the difference: start a fresh window.
		l.tat = now
	}
	l.last = now
	l.tat = l.tat.Add(l.interval)
	wait := l.tat.Add(-l.burst).Sub(now)
	l.mu.Unlock()
	if wait > 0 {
		select {
		case <-l.clk.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	select {
	case l.slots <- struct{}{}:
		return func() { <-l.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
