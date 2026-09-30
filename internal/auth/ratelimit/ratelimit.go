// Package ratelimit provides in-memory limiters for a single Alice process
// (R20): token buckets for request rates and a failure lockout for guessing
// attacks. State resets on restart by design.
package ratelimit

import (
	"net/netip"
	"sync"
	"time"

	"alice/internal/platform/clock"
)

// maxKeys bounds memory: at most this many keys are tracked per limiter.
const maxKeys = 10_000

// IPKey is the per-address key for limiters and lockouts. IPv4-mapped IPv6
// addresses count as IPv4, and IPv6 addresses are grouped by /64, the
// smallest block a single customer usually controls, so rotating through one
// network's addresses does not escape a limit. An invalid address maps to
// "unknown".
func IPKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return "unknown"
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip.String()
	}
	p, err := ip.Prefix(64)
	if err != nil {
		return "unknown"
	}
	return p.String()
}

// Limiter is a set of token buckets, one per key. Each bucket holds up to
// limit tokens and refills at limit per period.
type Limiter struct {
	mu      sync.Mutex
	clock   clock.Clock
	limit   float64
	per     time.Duration
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter allowing limit requests per period per key (bursts up to limit).
func New(c clock.Clock, limit int, per time.Duration) *Limiter {
	return &Limiter{clock: c, limit: float64(limit), per: per, buckets: map[string]*bucket{}}
}

// Allow takes one token for key. When none is left it returns false and how
// long until the next token (rounded up to whole seconds, at least 1 s).
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxKeys {
			l.evict(now)
		}
		b = &bucket{tokens: l.limit, last: now}
		l.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.limit * float64(l.per))
	return false, ceilSecond(wait)
}

// Reset forgets every key.
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = map[string]*bucket{}
}

func (l *Limiter) refill(b *bucket, now time.Time) {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(l.limit, b.tokens+elapsed.Seconds()*l.limit/l.per.Seconds())
		b.last = now
	}
}

// evict drops buckets that have refilled completely (idle keys); if none, the
// least recently used one. The caller holds l.mu.
func (l *Limiter) evict(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, b := range l.buckets {
		l.refill(b, now)
		if b.tokens >= l.limit {
			delete(l.buckets, k)
			continue
		}
		if oldestKey == "" || b.last.Before(oldest) {
			oldestKey, oldest = k, b.last
		}
	}
	if len(l.buckets) >= maxKeys && oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}

// Lockout locks a key for lockFor after maxFailures failures within window.
type Lockout struct {
	mu          sync.Mutex
	clock       clock.Clock
	maxFailures int
	window      time.Duration
	lockFor     time.Duration
	entries     map[string]*entry
}

type entry struct {
	failures    int
	first       time.Time // start of the current failure window
	lockedUntil time.Time
}

// NewLockout returns a lockout tracker.
func NewLockout(c clock.Clock, maxFailures int, window, lockFor time.Duration) *Lockout {
	return &Lockout{clock: c, maxFailures: maxFailures, window: window, lockFor: lockFor, entries: map[string]*entry{}}
}

// Locked reports whether key is locked and for how much longer (rounded up to seconds).
func (l *Lockout) Locked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return false, 0
	}
	now := l.clock.Now()
	if now.Before(e.lockedUntil) {
		return true, ceilSecond(e.lockedUntil.Sub(now))
	}
	return false, 0
}

// Fail records a failure and reports whether this failure locked the key.
func (l *Lockout) Fail(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= maxKeys {
			l.evict(now)
		}
		e = &entry{first: now}
		l.entries[key] = e
	}
	if now.Before(e.lockedUntil) {
		return false
	}
	if !e.lockedUntil.IsZero() || now.Sub(e.first) >= l.window {
		*e = entry{first: now} // previous lock or window is over: start counting again
	}
	e.failures++
	if e.failures >= l.maxFailures {
		e.lockedUntil = now.Add(l.lockFor)
		return true
	}
	return false
}

// Succeed clears the failures of key.
func (l *Lockout) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Reset forgets every key.
func (l *Lockout) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = map[string]*entry{}
}

// evict drops expired entries; if none, the oldest. The caller holds l.mu.
func (l *Lockout) evict(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, e := range l.entries {
		if !now.Before(e.lockedUntil) && now.Sub(e.first) >= l.window {
			delete(l.entries, k)
			continue
		}
		if oldestKey == "" || e.first.Before(oldest) {
			oldestKey, oldest = k, e.first
		}
	}
	if len(l.entries) >= maxKeys && oldestKey != "" {
		delete(l.entries, oldestKey)
	}
}

func ceilSecond(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	s := (d + time.Second - 1) / time.Second
	return s * time.Second
}
