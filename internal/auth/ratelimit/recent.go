package ratelimit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"

	"alice/internal/platform/clock"
)

// Recent remembers, for a short lifetime, credentials (session cookies, setup cookies, API
// tokens) that a lookup accepted or that this process just issued (AUD-16). Membership only lets
// a request past the per-address block on failing credentials; it never authenticates: the
// normal lookup still runs and alone decides who the caller is, so a credential revoked since it
// was remembered is refused as usual (and forgotten by the caller).
//
// Only HMAC-SHA256 of a credential under a key drawn at random when the set is created is kept:
// a memory dump yields no credential, nor the plain SHA-256 the database stores, and nobody can
// precompute entries. The set holds at most max entries; adding to a full set drops the expired
// entries and, when none expired, the least recently validated one.
type Recent struct {
	mu    sync.Mutex
	clock clock.Clock
	key   [32]byte
	ttl   time.Duration
	max   int
	seen  map[[32]byte]time.Time // keyed hash -> last validated
}

// NewRecent returns an empty set whose entries live ttl after their last Add.
func NewRecent(c clock.Clock, ttl time.Duration, maxEntries int) *Recent {
	r := &Recent{clock: c, ttl: ttl, max: maxEntries, seen: map[[32]byte]time.Time{}}
	_, _ = rand.Read(r.key[:]) // crypto/rand.Read never fails (Go 1.24+)
	return r
}

func (r *Recent) sum(credential string) [32]byte {
	m := hmac.New(sha256.New, r.key[:])
	m.Write([]byte(credential))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// Add remembers credential as validated now. An empty credential is ignored.
func (r *Recent) Add(credential string) {
	if credential == "" {
		return
	}
	h := r.sum(credential)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock.Now()
	if _, ok := r.seen[h]; !ok && len(r.seen) >= r.max {
		r.evict(now)
	}
	r.seen[h] = now
}

// Contains reports whether credential was validated less than the lifetime ago.
func (r *Recent) Contains(credential string) bool {
	if credential == "" {
		return false
	}
	h := r.sum(credential)
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.seen[h]
	if !ok {
		return false
	}
	if r.clock.Now().Sub(at) >= r.ttl {
		delete(r.seen, h)
		return false
	}
	return true
}

// Remove forgets credential (it failed a lookup, or its session ended).
func (r *Recent) Remove(credential string) {
	if credential == "" {
		return
	}
	h := r.sum(credential)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.seen, h)
}

// Reset forgets every entry.
func (r *Recent) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = map[[32]byte]time.Time{}
}

// evict drops expired entries; if none, the least recently validated one. The caller holds r.mu.
func (r *Recent) evict(now time.Time) {
	var oldestKey [32]byte
	var oldest time.Time
	found := false
	for k, at := range r.seen {
		if now.Sub(at) >= r.ttl {
			delete(r.seen, k)
			continue
		}
		if !found || at.Before(oldest) {
			oldestKey, oldest, found = k, at, true
		}
	}
	if len(r.seen) >= r.max && found {
		delete(r.seen, oldestKey)
	}
}
