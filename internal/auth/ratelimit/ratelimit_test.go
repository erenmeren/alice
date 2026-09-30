package ratelimit

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

var t0 = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func TestLimiterBurstThenRefill(t *testing.T) {
	c := clock.NewFake(t0)
	l := New(c, 10, time.Minute)
	for i := range 10 {
		ok, _ := l.Allow("ip:10.0.0.1")
		require.True(t, ok, "request %d", i+1)
	}
	ok, retry := l.Allow("ip:10.0.0.1")
	assert.False(t, ok)
	assert.Equal(t, 6*time.Second, retry, "one token every 6 s")

	c.Advance(5 * time.Second)
	ok, retry = l.Allow("ip:10.0.0.1")
	assert.False(t, ok)
	assert.Equal(t, time.Second, retry)

	c.Advance(time.Second)
	ok, _ = l.Allow("ip:10.0.0.1")
	assert.True(t, ok)

	c.Advance(10 * time.Minute) // refill never exceeds the bucket size
	for range 10 {
		ok, _ = l.Allow("ip:10.0.0.1")
		assert.True(t, ok)
	}
	ok, _ = l.Allow("ip:10.0.0.1")
	assert.False(t, ok)
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	l := New(clock.NewFake(t0), 1, time.Minute)
	ok, _ := l.Allow("a")
	assert.True(t, ok)
	ok, _ = l.Allow("a")
	assert.False(t, ok)
	ok, _ = l.Allow("b")
	assert.True(t, ok, "another key has its own bucket")
}

func TestLimiterReset(t *testing.T) {
	l := New(clock.NewFake(t0), 1, time.Minute)
	l.Allow("a")
	ok, _ := l.Allow("a")
	require.False(t, ok)
	l.Reset()
	ok, _ = l.Allow("a")
	assert.True(t, ok)
}

func TestLimiterBoundsMemory(t *testing.T) {
	c := clock.NewFake(t0)
	l := New(c, 5, time.Minute)
	for i := range maxKeys + 500 {
		l.Allow(fmt.Sprintf("ip:%d", i))
	}
	assert.LessOrEqual(t, len(l.buckets), maxKeys)
	c.Advance(time.Hour) // every bucket is full again, so all are evictable
	l.Allow("fresh")
	assert.Len(t, l.buckets, 1)
}

func TestLockoutLocksAfterMaxFailures(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewLockout(c, 5, 15*time.Minute, 15*time.Minute)
	for i := range 4 {
		assert.False(t, l.Fail("10.0.0.9"), "failure %d", i+1)
		locked, _ := l.Locked("10.0.0.9")
		assert.False(t, locked)
	}
	assert.True(t, l.Fail("10.0.0.9"), "fifth failure locks")
	locked, retry := l.Locked("10.0.0.9")
	assert.True(t, locked)
	assert.Equal(t, 15*time.Minute, retry)
	assert.False(t, l.Fail("10.0.0.9"), "failures while locked do not extend the lock")

	locked, _ = l.Locked("10.0.0.10")
	assert.False(t, locked, "other keys are unaffected")

	c.Advance(15*time.Minute - time.Second)
	locked, retry = l.Locked("10.0.0.9")
	assert.True(t, locked)
	assert.Equal(t, time.Second, retry)
	c.Advance(time.Second)
	locked, _ = l.Locked("10.0.0.9")
	assert.False(t, locked)
	assert.False(t, l.Fail("10.0.0.9"), "counting starts again after the lock")
}

func TestLockoutWindowForgetsOldFailures(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewLockout(c, 5, 15*time.Minute, 15*time.Minute)
	for range 4 {
		l.Fail("k")
	}
	c.Advance(15 * time.Minute)
	assert.False(t, l.Fail("k"), "the window expired, so this is failure 1")
	for range 3 {
		assert.False(t, l.Fail("k"))
	}
	assert.True(t, l.Fail("k"))
}

func TestLockoutSucceedAndReset(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewLockout(c, 5, 15*time.Minute, 15*time.Minute)
	for range 4 {
		l.Fail("k")
	}
	l.Succeed("k")
	for range 4 {
		assert.False(t, l.Fail("k"), "success cleared the earlier failures")
	}
	assert.True(t, l.Fail("k"))
	l.Reset()
	locked, _ := l.Locked("k")
	assert.False(t, locked)
}

func TestLockoutBoundsMemory(t *testing.T) {
	c := clock.NewFake(t0)
	l := NewLockout(c, 5, time.Minute, time.Minute)
	for i := range maxKeys + 500 {
		l.Fail(fmt.Sprintf("ip:%d", i))
	}
	assert.LessOrEqual(t, len(l.entries), maxKeys)
}
