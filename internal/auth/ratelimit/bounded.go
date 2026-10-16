package ratelimit

import (
	"sync"
	"time"

	"alice/internal/platform/clock"
)

// BoundedLockout locks a key for lockFor after maxFailures failures within window, like Lockout, for keys an attacker
// can choose (a sign-in name at a directory). Unlike Lockout it never forgets a key that still matters: a key that is
// locked, or whose failure window is still open, is never evicted, so neither many addresses nor many made-up names can
// push a victim's failures out of the table. Only keys whose lock and window are over are dropped to make room. When the
// table holds capacity keys that all still matter, Allow refuses every NEW key until the earliest of them expires (it
// fails closed); keys already in the table are answered as usual. That is a deliberate trade: an attacker who fills the
// table (capacity distinct names, each failed once within the window) keeps people who have no entry yet from signing
// in for at most window, but can never make Alice the means of locking a directory account. The table can exceed
// capacity by the attempts in flight between Allow and Fail.
type BoundedLockout struct {
	mu          sync.Mutex
	clock       clock.Clock
	maxFailures int
	window      time.Duration
	lockFor     time.Duration
	capacity    int
	entries     map[string]*entry
	nextExpiry  time.Time // when the table was found full of live keys: the earliest time one of them expires
}

// NewBoundedLockout returns a lockout of at most capacity keys (see BoundedLockout).
func NewBoundedLockout(c clock.Clock, maxFailures int, window, lockFor time.Duration, capacity int) *BoundedLockout {
	return &BoundedLockout{clock: c, maxFailures: maxFailures, window: window, lockFor: lockFor, capacity: capacity,
		entries: map[string]*entry{}}
}

// live reports whether e still matters at now: locked, or inside its failure window.
func (l *BoundedLockout) live(e *entry, now time.Time) bool {
	return now.Before(e.lockedUntil) || now.Sub(e.first) < l.window
}

// expiry is when e stops mattering.
func (l *BoundedLockout) expiry(e *entry) time.Time {
	end := e.first.Add(l.window)
	if e.lockedUntil.After(end) {
		return e.lockedUntil
	}
	return end
}

// Allow reports whether an attempt for key may go ahead. It is false, with how long to wait (rounded up to seconds),
// while key is locked, and for a key that is not in the table while the table is full of live keys. Allow never adds
// a key: Fail does.
func (l *BoundedLockout) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	if e, ok := l.entries[key]; ok {
		if now.Before(e.lockedUntil) {
			return false, ceilSecond(e.lockedUntil.Sub(now))
		}
		return true, 0
	}
	if len(l.entries) < l.capacity {
		return true, 0
	}
	if now.Before(l.nextExpiry) {
		return false, ceilSecond(l.nextExpiry.Sub(now))
	}
	l.dropExpired(now)
	if len(l.entries) < l.capacity {
		return true, 0
	}
	return false, ceilSecond(l.nextExpiry.Sub(now))
}

// dropExpired deletes the keys whose lock and window are over and records when the earliest remaining key expires.
// The caller holds l.mu.
func (l *BoundedLockout) dropExpired(now time.Time) {
	var next time.Time
	for k, e := range l.entries {
		if !l.live(e, now) {
			delete(l.entries, k)
			continue
		}
		if exp := l.expiry(e); next.IsZero() || exp.Before(next) {
			next = exp
		}
	}
	l.nextExpiry = next
}

// Fail records a failure of key and reports whether it locked the key. A failure while the key is locked changes
// nothing; after a lock or a window is over the count starts again.
func (l *BoundedLockout) Fail(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.capacity {
			l.dropExpired(now)
		}
		e = &entry{first: now}
		l.entries[key] = e
	}
	if now.Before(e.lockedUntil) {
		return false
	}
	if !e.lockedUntil.IsZero() || now.Sub(e.first) >= l.window {
		*e = entry{first: now}
	}
	e.failures++
	if e.failures >= l.maxFailures {
		e.lockedUntil = now.Add(l.lockFor)
		return true
	}
	return false
}

// Succeed forgets key (a successful sign-in clears its failures).
func (l *BoundedLockout) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Reset forgets every key.
func (l *BoundedLockout) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = map[string]*entry{}
	l.nextExpiry = time.Time{}
}

// Len is the number of keys in the table.
func (l *BoundedLockout) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
