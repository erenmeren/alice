package ratelimit

import (
	"sync"
	"time"

	"alice/internal/platform/clock"
)

// BoundedLockout locks a key for lockFor after maxFailures failures within window, like Lockout, for keys an attacker
// can choose (a sign-in name, or an account, at a directory). Every attempt reserves a slot before it starts (Reserve)
// and settles it exactly once (Reservation.Fail, Succeed or Release): a key whose failures plus attempts in flight
// reach maxFailures is answered as locked, so parallel attempts cannot get past the limit by all starting before the
// first one fails.
//
// Unlike Lockout it never forgets a key that still matters: a key that is locked, still counting failures inside its
// window, or has an attempt in flight is never evicted, so neither many addresses nor many made-up names can push a
// victim's failures out of the table. Only keys whose lock and window are over are dropped to make room. When the table
// holds capacity keys that all still matter, Reserve refuses every NEW key until the earliest of them expires (it fails
// closed; OnFull is told); keys already in the table are answered as usual. That is a deliberate trade: an attacker
// who fills the table (capacity distinct names, each failed once within the window) keeps people who have no entry yet
// from signing in for at most window, but can never make Alice the means of guessing a directory account's password
// more than maxFailures times per lock.
type BoundedLockout struct {
	mu          sync.Mutex
	clock       clock.Clock
	maxFailures int
	window      time.Duration
	lockFor     time.Duration
	capacity    int
	entries     map[string]*boundedEntry
	nextExpiry  time.Time // when the table was found full of live keys: the earliest time one of them expires
	// OnFull, when set, is called (without the lock held) each time Reserve refuses a new key because the table is full.
	OnFull func()
}

type boundedEntry struct {
	failures    int
	first       time.Time // start of the current failure window
	lockedUntil time.Time
	inflight    int // reserved slots not yet settled
}

// inflightRetry is the Retry-After of a key refused only because its remaining attempts are in flight.
const inflightRetry = time.Second

// NewBoundedLockout returns a lockout of at most capacity keys (see BoundedLockout).
func NewBoundedLockout(c clock.Clock, maxFailures int, window, lockFor time.Duration, capacity int) *BoundedLockout {
	return &BoundedLockout{clock: c, maxFailures: maxFailures, window: window, lockFor: lockFor, capacity: capacity,
		entries: map[string]*boundedEntry{}}
}

// live reports whether e still matters at now: locked, inside its failure window with failures, or in flight.
func (l *BoundedLockout) live(e *boundedEntry, now time.Time) bool {
	return e.inflight > 0 || now.Before(e.lockedUntil) || (e.failures > 0 && now.Sub(e.first) < l.window)
}

// expiry is when e stops mattering if nothing more happens (an entry in flight is never dropped anyway).
func (l *BoundedLockout) expiry(e *boundedEntry) time.Time {
	end := e.first.Add(l.window)
	if e.lockedUntil.After(end) {
		return e.lockedUntil
	}
	return end
}

// refresh starts the count again once e's lock or window is over. The caller holds l.mu.
func (l *BoundedLockout) refresh(e *boundedEntry, now time.Time) {
	if now.Before(e.lockedUntil) {
		return
	}
	if !e.lockedUntil.IsZero() || now.Sub(e.first) >= l.window {
		e.failures, e.first, e.lockedUntil = 0, now, time.Time{}
	}
}

// Reservation is one reserved attempt of a key. Exactly one of Fail, Succeed and Release counts; the others, and every
// later call, do nothing, so a deferred Release settles an attempt that no other path settled. The zero value and a nil
// *Reservation are a settled attempt.
type Reservation struct {
	l   *BoundedLockout
	key string
	e   *boundedEntry
	mu  sync.Mutex
	set bool
}

// Reserve reserves an attempt for key. It is false, with how long to wait (rounded up to seconds), while key is locked,
// while its failures and attempts in flight already reach maxFailures, and for a key that is not in the table while the
// table is full of live keys. A refused attempt reserves nothing.
func (l *BoundedLockout) Reserve(key string) (*Reservation, bool, time.Duration) {
	res, ok, retry, full := l.reserve(key)
	if full && l.OnFull != nil {
		l.OnFull()
	}
	return res, ok, retry
}

func (l *BoundedLockout) reserve(key string) (res *Reservation, ok bool, retry time.Duration, full bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	e, found := l.entries[key]
	if !found {
		if len(l.entries) >= l.capacity {
			if now.Before(l.nextExpiry) {
				return nil, false, ceilSecond(l.nextExpiry.Sub(now)), true
			}
			l.dropExpired(now)
			if len(l.entries) >= l.capacity {
				return nil, false, ceilSecond(l.nextExpiry.Sub(now)), true
			}
		}
		e = &boundedEntry{first: now}
		l.entries[key] = e
	}
	l.refresh(e, now)
	switch {
	case now.Before(e.lockedUntil):
		return nil, false, ceilSecond(e.lockedUntil.Sub(now)), false
	case e.failures+e.inflight >= l.maxFailures:
		return nil, false, inflightRetry, false
	}
	e.inflight++
	return &Reservation{l: l, key: key, e: e}, true, 0, false
}

// dropExpired deletes the keys that no longer matter and records when the earliest remaining key expires. The caller
// holds l.mu.
func (l *BoundedLockout) dropExpired(now time.Time) {
	var next time.Time
	for k, e := range l.entries {
		if !l.live(e, now) {
			delete(l.entries, k)
			continue
		}
		if e.inflight > 0 {
			continue
		}
		if exp := l.expiry(e); next.IsZero() || exp.Before(next) {
			next = exp
		}
	}
	if next.IsZero() {
		next = now.Add(inflightRetry) // every key is in flight: look again in a second
	}
	l.nextExpiry = next
}

// settle runs fn on the reservation's entry once, under the lockout's lock, after taking the attempt out of flight.
// An entry the table no longer holds (after Reset) is left alone. reports whether this call settled it.
func (r *Reservation) settle(fn func(e *boundedEntry, now time.Time)) bool {
	if r == nil || r.l == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.set {
		return false
	}
	r.set = true
	l := r.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries[r.key] != r.e {
		return true
	}
	r.e.inflight--
	now := l.clock.Now()
	fn(r.e, now)
	if !l.live(r.e, now) {
		delete(l.entries, r.key)
	}
	return true
}

// Fail settles the attempt as a failure and reports whether it locked the key.
func (r *Reservation) Fail() bool {
	var locked bool
	r.settle(func(e *boundedEntry, now time.Time) {
		if now.Before(e.lockedUntil) {
			return
		}
		l := r.l
		l.refresh(e, now)
		if e.failures == 0 {
			e.first = now
		}
		e.failures++
		if e.failures >= l.maxFailures {
			e.lockedUntil = now.Add(l.lockFor)
			locked = true
		}
	})
	return locked
}

// Succeed settles the attempt as a success: the key's failures are cleared (a lock that another attempt set while this
// one was in flight stays).
func (r *Reservation) Succeed() {
	r.settle(func(e *boundedEntry, now time.Time) {
		if now.Before(e.lockedUntil) {
			return
		}
		e.failures, e.first, e.lockedUntil = 0, now, time.Time{}
	})
}

// Release settles the attempt without counting it: it never reached the password check (the directory could not be
// used, the request ended, another key refused it).
func (r *Reservation) Release() {
	r.settle(func(*boundedEntry, time.Time) {})
}

// Locked reports whether key is locked now (tests and diagnostics; it reserves nothing).
func (l *BoundedLockout) Locked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	return ok && l.clock.Now().Before(e.lockedUntil)
}

// LockedUntil reports whether key is locked now and until when (it reserves nothing).
func (l *BoundedLockout) LockedUntil(key string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || !l.clock.Now().Before(e.lockedUntil) {
		return time.Time{}, false
	}
	return e.lockedUntil, true
}

// Clear forgets one key, its lock and its failures (an Administrator's unlock), and reports whether it was locked.
// Reservations of the key taken before it settle as no-ops, as after Reset.
func (l *BoundedLockout) Clear(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return false
	}
	delete(l.entries, key)
	return l.clock.Now().Before(e.lockedUntil)
}

// Reset forgets every key; reservations taken before it settle as no-ops.
func (l *BoundedLockout) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = map[string]*boundedEntry{}
	l.nextExpiry = time.Time{}
}

// Len is the number of keys in the table.
func (l *BoundedLockout) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
