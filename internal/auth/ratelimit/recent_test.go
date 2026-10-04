package ratelimit

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

func TestRecentRemembersForItsLifetimeOnly(t *testing.T) {
	c := clock.NewFake(t0)
	r := NewRecent(c, 5*time.Minute, 10)
	assert.False(t, r.Contains("cred"))
	r.Add("cred")
	assert.True(t, r.Contains("cred"))
	assert.False(t, r.Contains("other"))

	c.Advance(5*time.Minute - time.Second)
	assert.True(t, r.Contains("cred"))
	r.Add("cred") // validated again: the lifetime starts over
	c.Advance(5*time.Minute - time.Second)
	assert.True(t, r.Contains("cred"))
	c.Advance(time.Second)
	assert.False(t, r.Contains("cred"), "an entry is at most the lifetime old")
}

func TestRecentRemoveAndReset(t *testing.T) {
	r := NewRecent(clock.NewFake(t0), time.Minute, 10)
	r.Add("a")
	r.Add("b")
	r.Remove("a")
	assert.False(t, r.Contains("a"))
	assert.True(t, r.Contains("b"))
	r.Reset()
	assert.False(t, r.Contains("b"))
}

func TestRecentIgnoresEmptyCredentials(t *testing.T) {
	r := NewRecent(clock.NewFake(t0), time.Minute, 10)
	r.Add("")
	assert.False(t, r.Contains(""))
	assert.Empty(t, r.seen)
}

// The set is bounded: expired entries go first, then the least recently validated one.
func TestRecentBoundsItsSize(t *testing.T) {
	c := clock.NewFake(t0)
	r := NewRecent(c, time.Minute, 3)
	r.Add("old")
	c.Advance(10 * time.Second)
	r.Add("b")
	r.Add("c")
	r.Add("d")
	assert.Len(t, r.seen, 3)
	assert.False(t, r.Contains("old"), "the oldest entry was evicted")
	assert.True(t, r.Contains("b") && r.Contains("c") && r.Contains("d"))

	c.Advance(55 * time.Second) // b, c and d expire at 70 s
	r.Add("e")
	c.Advance(10 * time.Second)
	r.Add("f")
	assert.LessOrEqual(t, len(r.seen), 3)
	assert.True(t, r.Contains("e") && r.Contains("f"))

	big := NewRecent(c, time.Minute, 100)
	for i := range 1000 {
		big.Add(fmt.Sprintf("cred-%d", i))
	}
	assert.Len(t, big.seen, 100)
}

// What is kept is a keyed hash with a per-process random key: neither the credential nor its
// plain SHA-256 (the value stored in the database) is in memory, and two processes disagree.
func TestRecentStoresOnlyAKeyedHash(t *testing.T) {
	c := clock.NewFake(t0)
	r1, r2 := NewRecent(c, time.Minute, 10), NewRecent(c, time.Minute, 10)
	r1.Add("cred")
	r2.Add("cred")
	require.Len(t, r1.seen, 1)
	plain := sha256.Sum256([]byte("cred"))
	for k := range r1.seen {
		assert.NotEqual(t, plain, k)
		_, same := r2.seen[k]
		assert.False(t, same, "each process has its own key")
	}
	assert.NotEqual(t, r1.key, [32]byte{})
}

func TestRecentIsSafeForConcurrentUse(t *testing.T) {
	r := NewRecent(clock.NewFake(t0), time.Minute, 50)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				cred := fmt.Sprintf("c-%d-%d", g, i%60)
				r.Add(cred)
				r.Contains(cred)
				if i%7 == 0 {
					r.Remove(cred)
				}
			}
		})
	}
	wg.Wait()
	assert.LessOrEqual(t, len(r.seen), 50)
}
