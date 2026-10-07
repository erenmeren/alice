package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"alice/internal/platform/clock"
)

const maxKeys = 50

// Bounds of the key set's lifetime (S-2): the answer's cache headers, clamped; one hour without them.
const (
	minKeySetLife     = 5 * time.Minute
	maxKeySetLife     = 24 * time.Hour
	defaultKeySetLife = time.Hour
)

var errSignature = errors.New("oidc: the ID token's signature does not verify")

var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256}

// keySet is a bounded JWKS cache that implements go-oidc's KeySet (SEC-012, O-01, O-11, S-2): compact JWS only,
// signed with RS256, ES256 or PS256 by a public key of the provider's JWKS. The keys expire by the JWKS answer's
// cache headers (between 5 minutes and 24 hours, 1 hour without them), so a key the provider withdrew stops
// verifying at the expiry; an unknown key ID refetches at most once per JWKSRefetchEvery; the JWKS is at most
// MaxResponseBytes (the client's bound) and maxKeys keys. When the refetch at expiry fails, the expired keys are
// not used.
type keySet struct {
	client *http.Client
	url    string
	clock  clock.Clock

	mu      sync.Mutex
	keys    []jose.JSONWebKey
	expires time.Time
	fetched time.Time
}

func newKeySet(client *http.Client, url string, clk clock.Clock) *keySet {
	return &keySet{client: client, url: url, clock: clk}
}

// VerifySignature returns the payload of jwt when one of the provider's keys verifies it.
func (k *keySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(jwt, allowedAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, errSignature
	}
	keys, err := k.keysFor(ctx, jws.Signatures[0].Header.KeyID)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if payload, err := jws.Verify(key.Key); err == nil {
			return payload, nil
		}
	}
	return nil, errSignature
}

func match(keys []jose.JSONWebKey, kid string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for _, key := range keys {
		if kid == "" || key.KeyID == kid {
			out = append(out, key)
		}
	}
	return out
}

func (k *keySet) keysFor(ctx context.Context, kid string) ([]jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.clock.Now()
	live := now.Before(k.expires)
	if live {
		if m := match(k.keys, kid); len(m) > 0 {
			return m, nil
		}
	}
	if !k.fetched.IsZero() && now.Sub(k.fetched) < JWKSRefetchEvery {
		return nil, errSignature
	}
	k.fetched = now
	keys, life, err := k.fetch(ctx)
	if err != nil {
		if !live {
			k.keys = nil // fail closed: expired keys are not used
		}
		return nil, err
	}
	k.keys, k.expires = keys, now.Add(life)
	if m := match(keys, kid); len(m) > 0 {
		return m, nil
	}
	return nil, errSignature
}

// fetch reads the JWKS and returns its public signing keys and how long they may be cached.
func (k *keySet) fetch(ctx context.Context) ([]jose.JSONWebKey, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, 0, err
	}
	res, err := k.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("oidc: read the key set: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("oidc: the key set answered %d", res.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		return nil, 0, fmt.Errorf("oidc: the key set is not valid: %w", err)
	}
	if len(set.Keys) > maxKeys {
		return nil, 0, errors.New("oidc: the key set has too many keys")
	}
	var keys []jose.JSONWebKey
	for _, key := range set.Keys {
		if key.Valid() && key.IsPublic() && (key.Use == "" || key.Use == "sig") {
			keys = append(keys, key)
		}
	}
	return keys, cacheLife(res.Header), nil
}

// cacheLife is the lifetime the answer's headers give: Cache-Control max-age (no-store and no-cache count as 0),
// else Expires minus Date; clamped to [minKeySetLife, maxKeySetLife]; defaultKeySetLife without either.
func cacheLife(h http.Header) time.Duration {
	life, found := time.Duration(0), false
	for d := range strings.SplitSeq(h.Get("Cache-Control"), ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(d), "=")
		switch {
		case strings.EqualFold(name, "max-age"):
			if n, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64); err == nil && n >= 0 {
				life, found = time.Duration(min(n, int64(maxKeySetLife/time.Second)))*time.Second, true
			}
		case strings.EqualFold(name, "no-store"), strings.EqualFold(name, "no-cache"):
			if !found {
				life, found = 0, true
			}
		}
	}
	if !found {
		exp, errE := http.ParseTime(h.Get("Expires"))
		date, errD := http.ParseTime(h.Get("Date"))
		if errE != nil || errD != nil {
			return defaultKeySetLife
		}
		life = exp.Sub(date)
	}
	return min(max(life, minKeySetLife), maxKeySetLife)
}
