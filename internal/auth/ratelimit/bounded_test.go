package ratelimit

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

func reserve(t *testing.T, l *BoundedLockout, key string) *Reservation {
	t.Helper()
	r, ok, _ := l.Reserve(key)
	require.True(t, ok, "reserve %s", key)
	return r
}

func failN(t *testing.T, l *BoundedLockout, key string, n int) {
	t.Helper()
	for range n {
		reserve(t, l, key).Fail()
	}
}

func TestBoundedLockoutLocksAfterFailuresAndExpires(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewBoundedLockout(c, 3, 30*time.Minute, 45*time.Minute, 100)
	r := reserve(t, l, "k")
	r.Release()
	assert.Zero(t, l.Len(), "a released attempt of a new key leaves nothing")
	assert.False(t, reserve(t, l, "k").Fail())
	assert.False(t, reserve(t, l, "k").Fail())
	assert.True(t, reserve(t, l, "k").Fail(), "the third failure locks")
	assert.True(t, l.Locked("k"))
	_, ok, retry := l.Reserve("k")
	assert.False(t, ok, "a locked key never reserves")
	assert.Equal(t, 45*time.Minute, retry)
	c.Advance(45*time.Minute - time.Second)
	_, ok, _ = l.Reserve("k")
	assert.False(t, ok, "still locked a second before the end")
	c.Advance(time.Second)
	r = reserve(t, l, "k")
	assert.False(t, r.Fail(), "the count starts again after a lock")

	// Failures outside the window do not add up; Succeed and Reset forget them.
	failN(t, l, "w", 1)
	c.Advance(30 * time.Minute)
	failN(t, l, "w", 1)
	assert.False(t, reserve(t, l, "w").Fail(), "two failures in the new window")
	reserve(t, l, "w").Succeed()
	failN(t, l, "w", 2)
	reserve(t, l, "w").Release()
	l.Reset()
	assert.Zero(t, l.Len())
}

// Attempts in flight count: with 2 failures, only one more attempt may start; a settled reservation does nothing twice.
func TestBoundedLockoutReservesInFlightAttempts(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewBoundedLockout(c, 3, 30*time.Minute, 45*time.Minute, 100)
	a, b, d := reserve(t, l, "k"), reserve(t, l, "k"), reserve(t, l, "k")
	_, ok, retry := l.Reserve("k")
	assert.False(t, ok, "3 attempts in flight: the 4th waits")
	assert.Equal(t, time.Second, retry)
	a.Fail()
	a.Fail()
	a.Succeed()
	a.Release()
	_, ok, _ = l.Reserve("k")
	assert.False(t, ok, "1 failure + 2 in flight")
	b.Release()
	e := reserve(t, l, "k")
	d.Fail()
	assert.True(t, e.Fail(), "3 failures: locked")
	e.Release()
	assert.True(t, l.Locked("k"))
	var nilRes *Reservation
	nilRes.Release()
	nilRes.Succeed()
	assert.False(t, nilRes.Fail())
	(&Reservation{}).Release()

	// A success while another attempt locked the key keeps the lock; Reset turns old reservations into no-ops.
	l.Reset()
	x, y := reserve(t, l, "s"), reserve(t, l, "s")
	failN(t, l, "s", 1)
	x.Fail()
	y.Succeed()
	assert.Zero(t, l.Len(), "the success cleared both failures and nothing is in flight")
	failN(t, l, "s", 2)
	z, last := reserve(t, l, "s"), reserve(t, l, "t")
	l.Reset()
	z.Fail()
	last.Succeed()
	assert.Zero(t, l.Len())
}

// Concurrent reservations of one key never exceed the limit.
func TestBoundedLockoutConcurrentReservations(t *testing.T) {
	l := NewBoundedLockout(clock.NewFake(t0), 3, 30*time.Minute, 45*time.Minute, 100)
	var mu sync.Mutex
	var got []*Reservation
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, ok, _ := l.Reserve("k"); ok {
				mu.Lock()
				got = append(got, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assert.Len(t, got, 3)
	for _, r := range got {
		r.Fail()
	}
	assert.True(t, l.Locked("k"))
}

// A full table never drops a locked key, a counting one or one in flight; it drops expired keys, and refuses new keys
// while every key still matters (fail closed, OnFull told), never the keys already in it.
func TestBoundedLockoutNeverEvictsLiveKeys(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewBoundedLockout(c, 3, 30*time.Minute, 45*time.Minute, 3)
	var full int
	l.OnFull = func() { full++ }
	failN(t, l, "victim", 3)
	failN(t, l, "a", 1)
	c.Advance(time.Minute)
	failN(t, l, "b", 1)
	require.Equal(t, 3, l.Len())
	_, ok, retry := l.Reserve("new")
	assert.False(t, ok, "full of live keys: a new key is refused")
	assert.Equal(t, 29*time.Minute, retry, "until the earliest window ends ('a')")
	assert.Equal(t, 1, full)
	reserve(t, l, "b").Release()
	_, ok, _ = l.Reserve("victim")
	assert.False(t, ok)
	for i := range 50 {
		_, _, _ = l.Reserve("flood-" + strconv.Itoa(i))
	}
	assert.True(t, l.Locked("victim"), "the locked key survived the flood")
	assert.Equal(t, 51, full)

	// Once the windows are over, the expired keys make room; the locked key stays until its lock ends.
	l.Reset()
	failN(t, l, "victim", 3)
	failN(t, l, "a", 1)
	failN(t, l, "b", 1)
	c.Advance(31 * time.Minute)
	reserve(t, l, "new").Release()
	assert.Equal(t, 1, l.Len(), "'a' and 'b' expired and were dropped")
	assert.True(t, l.Locked("victim"), "the lock (45 minutes) outlives its window (30)")
	failN(t, l, "c", 1)
	failN(t, l, "d", 1)
	_, ok, retry = l.Reserve("e")
	assert.False(t, ok)
	assert.Equal(t, 14*time.Minute, retry, "the victim's lock ends first")
	_, ok, _ = l.Reserve("e")
	assert.False(t, ok, "the cached expiry answers without a scan")
	reserve(t, l, "c").Succeed()
	reserve(t, l, "e").Release()

	// A table whose keys are all in flight is not emptied: new keys wait a second.
	l.Reset()
	r1, r2, r3 := reserve(t, l, "p"), reserve(t, l, "q"), reserve(t, l, "r")
	_, ok, retry = l.Reserve("s")
	assert.False(t, ok)
	assert.Equal(t, time.Second, retry)
	r1.Release()
	r2.Release()
	r3.Release()
	reserve(t, l, "s").Release()
}

// LockedUntil reports a lock and its end; Clear forgets one key (its lock and its failures) and nothing else, and an
// attempt in flight on the cleared key settles as a no-op.
func TestBoundedLockoutLockedUntilAndClear(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewBoundedLockout(c, 3, 30*time.Minute, 45*time.Minute, 100)
	_, locked := l.LockedUntil("k")
	assert.False(t, locked, "an unknown key")
	failN(t, l, "k", 2)
	_, locked = l.LockedUntil("k")
	assert.False(t, locked, "counting is not locked")
	assert.False(t, l.Clear("k"), "it was not locked")
	failN(t, l, "k", 2)
	_, locked = l.LockedUntil("k")
	assert.False(t, locked, "Clear forgot the failures")
	failN(t, l, "k", 1)
	until, locked := l.LockedUntil("k")
	require.True(t, locked)
	assert.Equal(t, t0.Add(45*time.Minute), until)
	failN(t, l, "other", 3)

	failN(t, l, "other2", 2)
	inflight := reserve(t, l, "other2")
	assert.True(t, l.Clear("k"))
	assert.False(t, l.Locked("k"))
	assert.False(t, reserve(t, l, "k").Fail(), "a cleared key starts from nothing")
	assert.True(t, l.Locked("other"), "another key keeps its lock")
	assert.False(t, l.Clear("other2"))
	assert.False(t, inflight.Fail(), "an attempt in flight on a cleared key counts nothing")
	_, locked = l.LockedUntil("other2")
	assert.False(t, locked)
	c.Advance(45 * time.Minute)
	_, locked = l.LockedUntil("other")
	assert.False(t, locked, "a lock that ended")
}
