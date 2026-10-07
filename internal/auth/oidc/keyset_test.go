package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signRS256(t *testing.T, key *rsa.PrivateKey, kid, alg string, payload string) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	input := b64(hdr) + "." + b64([]byte(payload))
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	require.NoError(t, err)
	return input + "." + b64(sig)
}

func jwk(kid string, k *rsa.PrivateKey) map[string]string {
	return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64(k.N.Bytes()), "e": b64(new(big.Int).SetInt64(int64(k.E)).Bytes())}
}

func jwksServer(t *testing.T, keys map[string]*rsa.PrivateKey, hits *atomic.Int32, huge bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		var out []map[string]string
		for kid, k := range keys {
			out = append(out, jwk(kid, k))
		}
		if huge {
			_, _ = w.Write([]byte(`{"keys":[` + strings.Repeat(`{"kty":"oct","k":"AAAA"},`, 60000) + `{}]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": out})
	}))
}

// O-11: an unknown kid refetches the JWKS at most once per minute; O-01: only RS256, ES256 and PS256 are accepted.
func TestJWKSRefetchIsRateLimited(t *testing.T) {
	k1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	k2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var hits atomic.Int32
	keys := map[string]*rsa.PrivateKey{"k1": k1}
	srv := jwksServer(t, keys, &hits, false)
	defer srv.Close()
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	ks := newKeySet(srv.Client(), srv.URL, clk)
	ctx := context.Background()
	payload, err := ks.VerifySignature(ctx, signRS256(t, k1, "k1", "RS256", `{"sub":"a"}`))
	require.NoError(t, err)
	assert.Equal(t, `{"sub":"a"}`, string(payload))
	assert.Equal(t, int32(1), hits.Load())
	_, err = ks.VerifySignature(ctx, signRS256(t, k1, "k1", "RS256", `{}`))
	require.NoError(t, err)
	assert.Equal(t, int32(1), hits.Load(), "a known kid is served from the cache")
	keys["k2"] = k2 // the provider rotates
	for i := 0; i < 5; i++ {
		_, err = ks.VerifySignature(ctx, signRS256(t, k2, "k2", "RS256", `{}`))
	}
	assert.Error(t, err, "within a minute of the last fetch an unknown kid does not refetch")
	assert.Equal(t, int32(1), hits.Load())
	clk.Advance(JWKSRefetchEvery)
	_, err = ks.VerifySignature(ctx, signRS256(t, k2, "k2", "RS256", `{}`))
	require.NoError(t, err, "after a minute one refetch finds the new key")
	assert.Equal(t, int32(2), hits.Load())

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err = ks.VerifySignature(ctx, signRS256(t, other, "k1", "RS256", `{}`))
	assert.Error(t, err, "signed by a key that is not in the set")
	for _, alg := range []string{"none", "HS256", "RS512"} {
		_, err = ks.VerifySignature(ctx, signRS256(t, k1, "k1", alg, `{}`))
		assert.Error(t, err, alg)
	}
	_, err = ks.VerifySignature(ctx, "not.a.jws")
	assert.Error(t, err)
}

func TestJWKSSizeIsBounded(t *testing.T) {
	var hits atomic.Int32
	srv := jwksServer(t, nil, &hits, true)
	defer srv.Close()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	ks := newKeySet(limitedClient(srv.Client()), srv.URL, clock.NewFake(time.Now()))
	_, err := ks.VerifySignature(context.Background(), signRS256(t, k, "k1", "RS256", `{}`))
	assert.Error(t, err, "a JWKS beyond 1 MiB or 50 keys is refused")

	many := map[string]*rsa.PrivateKey{}
	for i := range maxKeys + 1 {
		many["k"+strings.Repeat("x", i)] = k
	}
	srv2 := jwksServer(t, many, &hits, false)
	defer srv2.Close()
	ks = newKeySet(limitedClient(srv2.Client()), srv2.URL, clock.NewFake(time.Now()))
	_, err = ks.VerifySignature(context.Background(), signRS256(t, k, "k", "RS256", `{}`))
	assert.Error(t, err, "more than 50 keys")
}

// cachedJWKS serves the keys with the given cache headers; keys can be withdrawn between requests.
type cachedJWKS struct {
	mu      sync.Mutex
	keys    map[string]*rsa.PrivateKey
	headers map[string]string
	status  int
	hits    atomic.Int32
}

func (c *cachedJWKS) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	c.hits.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.headers {
		w.Header().Set(k, v)
	}
	if c.status != 0 {
		w.WriteHeader(c.status)
		return
	}
	out := []map[string]string{}
	for kid, k := range c.keys {
		out = append(out, jwk(kid, k))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": out})
}

// S-2: the key set expires by the answer's cache headers, clamped to [5 minutes, 24 hours], 1 hour without
// them; a key the provider withdrew stops verifying at the expiry.
func TestJWKSExpiresByCacheHeaders(t *testing.T) {
	k1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	start := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name    string
		headers map[string]string
		life    time.Duration
	}{
		{"max-age", map[string]string{"Cache-Control": "public, max-age=600"}, 10 * time.Minute},
		{"short max-age is raised to 5 minutes", map[string]string{"Cache-Control": "max-age=10"}, 5 * time.Minute},
		{"no-store is 5 minutes", map[string]string{"Cache-Control": "no-store"}, 5 * time.Minute},
		{"long max-age is cut to 24 hours", map[string]string{"Cache-Control": "max-age=864000"}, 24 * time.Hour},
		{"Expires against Date", map[string]string{"Expires": "Wed, 07 Oct 2026 11:00:00 GMT", "Date": "Wed, 07 Oct 2026 09:00:00 GMT"}, 2 * time.Hour},
		{"a bad max-age is ignored", map[string]string{"Cache-Control": "max-age=soon"}, time.Hour},
		{"no header: 1 hour", nil, time.Hour},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := &cachedJWKS{keys: map[string]*rsa.PrivateKey{"k1": k1}, headers: c.headers}
			hs := httptest.NewServer(srv)
			defer hs.Close()
			clk := clock.NewFake(start)
			ks := newKeySet(hs.Client(), hs.URL, clk)
			ctx := context.Background()
			tok := signRS256(t, k1, "k1", "RS256", `{}`)
			_, err := ks.VerifySignature(ctx, tok)
			require.NoError(t, err)
			clk.Advance(c.life - time.Second)
			_, err = ks.VerifySignature(ctx, tok)
			require.NoError(t, err)
			assert.Equal(t, int32(1), srv.hits.Load(), "cached until the expiry")
			clk.Advance(time.Second)
			_, err = ks.VerifySignature(ctx, tok)
			require.NoError(t, err)
			assert.Equal(t, int32(2), srv.hits.Load(), "a known kid refetches at the expiry")

			srv.mu.Lock()
			delete(srv.keys, "k1") // the provider withdraws the key
			srv.mu.Unlock()
			_, err = ks.VerifySignature(ctx, tok)
			require.NoError(t, err, "still cached")
			clk.Advance(c.life)
			_, err = ks.VerifySignature(ctx, tok)
			assert.Error(t, err, "a withdrawn key stops verifying at the expiry")
			assert.Equal(t, int32(3), srv.hits.Load())
		})
	}
}

// S-2: when the refetch at expiry fails, the expired keys are not used (fail closed); the next try waits a minute.
func TestJWKSExpiredAndUnreachableFailsClosed(t *testing.T) {
	k1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	srv := &cachedJWKS{keys: map[string]*rsa.PrivateKey{"k1": k1}}
	hs := httptest.NewServer(srv)
	defer hs.Close()
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	ks := newKeySet(hs.Client(), hs.URL, clk)
	ctx := context.Background()
	tok := signRS256(t, k1, "k1", "RS256", `{}`)
	_, err = ks.VerifySignature(ctx, tok)
	require.NoError(t, err)
	srv.mu.Lock()
	srv.status = http.StatusServiceUnavailable
	srv.mu.Unlock()
	clk.Advance(time.Hour)
	var probe fetchProbe
	_, err = ks.VerifySignature(withFetchProbe(ctx, &probe), tok)
	assert.Error(t, err)
	assert.True(t, probe.failed, "M-1: the caller learns the key set could not be read")
	probe = fetchProbe{}
	_, err = ks.VerifySignature(withFetchProbe(ctx, &probe), tok)
	assert.Error(t, err)
	assert.True(t, probe.failed, "still unreadable within the refetch minute")
	assert.Equal(t, int32(2), srv.hits.Load(), "no second fetch within a minute")
	srv.mu.Lock()
	srv.status = 0
	srv.mu.Unlock()
	clk.Advance(JWKSRefetchEvery)
	_, err = ks.VerifySignature(ctx, tok)
	require.NoError(t, err)
}
