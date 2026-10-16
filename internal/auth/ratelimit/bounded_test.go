package ratelimit

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

func TestBoundedLockoutLocksAfterFailuresAndExpires(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewBoundedLockout(c, 3, 30*time.Minute, 45*time.Minute, 100)
	ok, _ := l.Allow("k")
	assert.True(t, ok)
	assert.Zero(t, l.Len(), "Allow adds nothing")
	assert.False(t, l.Fail("k"))
	assert.False(t, l.Fail("k"))
	assert.True(t, l.Fail("k"), "the third failure locks")
	ok, retry := l.Allow("k")
	assert.False(t, ok)
	assert.Equal(t, 45*time.Minute, retry)
	assert.False(t, l.Fail("k"), "a failure while locked changes nothing")
	c.Advance(45*time.Minute - time.Second)
	ok, _ = l.Allow("k")
	assert.False(t, ok, "still locked a second before the end")
	c.Advance(time.Second)
	ok, _ = l.Allow("k")
	assert.True(t, ok)
	assert.False(t, l.Fail("k"), "the count starts again after a lock")

	// Failures outside the window do not add up; Succeed and Reset forget the key.
	l.Fail("w")
	c.Advance(30 * time.Minute)
	l.Fail("w")
	assert.False(t, l.Fail("w"), "two failures in the new window")
	l.Succeed("w")
	l.Fail("w")
	l.Fail("w")
	ok, _ = l.Allow("w")
	assert.True(t, ok, "Succeed cleared the earlier failures")
	l.Reset()
	assert.Zero(t, l.Len())
}

// A full table never drops a locked key or one whose window is open; it drops expired keys, and refuses new keys while
// every key still matters (fail closed), never the keys already in it.
func TestBoundedLockoutNeverEvictsLiveKeys(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewBoundedLockout(c, 3, 30*time.Minute, 45*time.Minute, 3)
	for range 3 {
		l.Fail("victim")
	}
	l.Fail("a")
	c.Advance(time.Minute)
	l.Fail("b")
	require.Equal(t, 3, l.Len())
	ok, retry := l.Allow("new")
	assert.False(t, ok, "full of live keys: a new key is refused")
	assert.Equal(t, 29*time.Minute, retry, "until the earliest window ends ('a')")
	ok, _ = l.Allow("b")
	assert.True(t, ok, "a key in the table is answered as usual")
	ok, _ = l.Allow("victim")
	assert.False(t, ok)
	// A flood of new names cannot push the victim out.
	for i := range 50 {
		l.Fail("flood-" + strconv.Itoa(i))
	}
	ok, _ = l.Allow("victim")
	assert.False(t, ok, "the locked key survived the flood")

	// Once the windows are over, the expired keys make room; the locked key stays until its lock ends.
	l.Reset()
	for range 3 {
		l.Fail("victim")
	}
	l.Fail("a")
	l.Fail("b")
	c.Advance(31 * time.Minute)
	ok, _ = l.Allow("new")
	assert.True(t, ok, "'a' and 'b' expired and were dropped")
	assert.Equal(t, 1, l.Len())
	ok, _ = l.Allow("victim")
	assert.False(t, ok, "the lock (45 minutes) outlives its window (30)")
	l.Fail("c")
	l.Fail("d")
	ok, retry = l.Allow("e")
	assert.False(t, ok)
	assert.Equal(t, 14*time.Minute, retry, "the victim's lock ends first")
	ok, _ = l.Allow("e")
	assert.False(t, ok, "the cached expiry answers without a scan")
	l.Succeed("c")
	ok, _ = l.Allow("e")
	assert.True(t, ok, "room again")
	c.Advance(14 * time.Minute)
	l.Fail("e")
	l.Fail("f")
	assert.Equal(t, 3, l.Len(), "the victim's expired lock made room for f")
}
