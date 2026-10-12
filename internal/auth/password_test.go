package auth

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testParams keep unit tests fast; production parameters are asserted separately.
var testParams = Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestProductionParametersMatchSpec(t *testing.T) {
	assert.Equal(t, Argon2Params{MemoryKiB: 65536, Time: 3, Threads: 2, SaltLen: 16, KeyLen: 32}, PasswordParams)
	enc, err := NewHasher(PasswordParams, 1).Hash(context.Background(), "correct horse battery staple")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(enc, "$argon2id$v=19$m=65536,t=3,p=2$"), enc)
	parts := strings.Split(enc, "$")
	require.Len(t, parts, 6)
	assert.Len(t, parts[4], 22, "16-byte salt, unpadded base64")
	assert.Len(t, parts[5], 43, "32-byte key, unpadded base64")
}

func TestHashAndVerify(t *testing.T) {
	ctx := context.Background()
	h := NewHasher(testParams, 2)
	enc, err := h.Hash(ctx, "İzmir-ığdır-2026")
	require.NoError(t, err)

	ok, rehash, err := h.Verify(ctx, enc, "İzmir-ığdır-2026")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, rehash)

	ok, _, err = h.Verify(ctx, enc, "izmir-ığdır-2026")
	require.NoError(t, err)
	assert.False(t, ok)

	enc2, err := h.Hash(ctx, "İzmir-ığdır-2026")
	require.NoError(t, err)
	assert.NotEqual(t, enc, enc2, "every hash uses a fresh salt")
}

func TestVerifyFlagsWeakerParametersForRehash(t *testing.T) {
	ctx := context.Background()
	weak, err := NewHasher(testParams, 1).Hash(ctx, "secret-password-1")
	require.NoError(t, err)
	stronger := NewHasher(Argon2Params{MemoryKiB: 128, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}, 1)
	ok, rehash, err := stronger.Verify(ctx, weak, "secret-password-1")
	require.NoError(t, err)
	assert.True(t, ok, "old hashes keep working")
	assert.True(t, rehash)
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	h := NewHasher(testParams, 1)
	for _, enc := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=18$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=64,t=1,p=0$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=64,t=1,p=1$!!!$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$",
		// I-8: the parameters are exactly "v=19" and "m=<n>,t=<n>,p=<n>", nothing before, between or after.
		"$argon2id$v=19junk$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=64,t=1,p=1junk$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=64,t=1,p=1,x=2$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=64, t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=+64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$t=1,m=64,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=+19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=4294967296,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=64,t=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
	} {
		ok, _, err := h.Verify(context.Background(), enc, "x")
		assert.Error(t, err, enc)
		assert.False(t, ok, enc)
	}
}

func TestDummyVerifyDoesComparableWork(t *testing.T) {
	h := NewHasher(Argon2Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 1)
	ctx := context.Background()
	enc, err := h.Hash(ctx, "some-password-x")
	require.NoError(t, err)
	start := time.Now()
	_, _, _ = h.Verify(ctx, enc, "wrong-password-x")
	realDur := time.Since(start)
	start = time.Now()
	h.DummyVerify(ctx, "wrong-password-x")
	dummy := time.Since(start)
	assert.Greater(t, dummy, realDur/4, "dummy verification must not be much cheaper than a real one")
}

// TestVerifyBoundsConcurrency runs many parallel Verify calls (under -race) and
// samples how many semaphore slots are held: Verify itself must take a slot, and
// never more than maxConcurrent at once.
func TestVerifyBoundsConcurrency(t *testing.T) {
	ctx := context.Background()
	h := NewHasher(Argon2Params{MemoryKiB: 4 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 2)
	enc, err := h.Hash(ctx, "parallel-password-1")
	require.NoError(t, err)

	var peak atomic.Int32
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n := int32(len(h.sem)); n > peak.Load() { //nolint:gosec // G115: len <= 2
				peak.Store(n)
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()

	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pw := "parallel-password-1"
			if i%2 == 1 {
				pw = "wrong-password-xyz"
			}
			ok, _, err := h.Verify(ctx, enc, pw)
			assert.NoError(t, err)
			assert.Equal(t, i%2 == 0, ok)
		}()
	}
	wg.Wait()
	close(stop)
	<-sampled

	assert.Equal(t, int32(2), peak.Load(), "Verify takes a slot, and never more than two are held")
}

func TestVerifyAndHashHonourCancelledContextWhenSaturated(t *testing.T) {
	h := NewHasher(testParams, 1)
	enc, err := h.Hash(context.Background(), "whatever-password")
	require.NoError(t, err)

	require.NoError(t, h.acquire(context.Background()))
	defer h.release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = h.Hash(ctx, "whatever-password")
	assert.ErrorIs(t, err, context.Canceled)
	ok, _, err := h.Verify(ctx, enc, "whatever-password")
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, ok)
}

func TestDummyVerifyWaitsForASlot(t *testing.T) {
	h := NewHasher(testParams, 1)
	require.NoError(t, h.acquire(context.Background()))
	done := make(chan struct{})
	go func() {
		h.DummyVerify(context.Background(), "x")
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("DummyVerify ran while the semaphore was saturated")
	case <-time.After(50 * time.Millisecond):
	}
	h.release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DummyVerify did not run after a slot was released")
	}
}
