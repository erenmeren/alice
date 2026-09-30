// Package auth implements local authentication: password hashing and policy,
// TOTP, recovery codes, sessions, users and API tokens.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are Argon2id cost parameters.
type Argon2Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	SaltLen   uint32
	KeyLen    uint32
}

// PasswordParams are the production parameters for passwords (SEC-001).
var PasswordParams = Argon2Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2, SaltLen: 16, KeyLen: 32}

// RecoveryCodeParams are lighter parameters for recovery codes: the codes carry
// 80 bits of randomness, so brute force is infeasible regardless of cost, and
// a login may verify up to ten of them (SEC-008).
var RecoveryCodeParams = Argon2Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

var errMalformedHash = errors.New("auth: malformed password hash")

// Hasher hashes and verifies secrets with Argon2id. A semaphore bounds how many
// hashes run at once so concurrent logins cannot exhaust memory (R-07).
type Hasher struct {
	params Argon2Params
	sem    chan struct{}
}

// NewHasher returns a hasher that runs at most maxConcurrent hashes at a time
// (values below 1 mean 1).
func NewHasher(p Argon2Params, maxConcurrent int) *Hasher {
	return &Hasher{params: p, sem: make(chan struct{}, max(1, maxConcurrent))}
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// concurrency is how many hashes may run at once.
func (h *Hasher) concurrency() int { return cap(h.sem) }

// Hash returns the PHC string "$argon2id$v=19$m=<KiB>,t=<time>,p=<threads>$<salt>$<key>"
// with unpadded standard base64 for salt and key.
func (h *Hasher) Hash(ctx context.Context, secret string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	salt := make([]byte, h.params.SaltLen)
	_, _ = rand.Read(salt) // never returns an error since Go 1.24
	key := argon2.IDKey([]byte(secret), salt, h.params.Time, h.params.MemoryKiB, h.params.Threads, h.params.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		h.params.MemoryKiB, h.params.Time, h.params.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify checks secret against an encoded hash in constant time. needsRehash is
// true when the stored parameters are weaker than the hasher's (SEC-005).
func (h *Hasher) Verify(ctx context.Context, encoded, secret string) (ok, needsRehash bool, err error) {
	p, salt, want, err := decodePHC(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	// Lengths come from decodePHC and are bounded, so the uint32 conversion is safe.
	got := argon2.IDKey([]byte(secret), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want))) //nolint:gosec // G115: len(want) <= 1024
	ok = subtle.ConstantTimeCompare(got, want) == 1
	needsRehash = p.MemoryKiB < h.params.MemoryKiB || p.Time < h.params.Time || p.Threads < h.params.Threads ||
		uint32(len(want)) < h.params.KeyLen //nolint:gosec // G115: len(want) <= 1024
	return ok, needsRehash, nil
}

// DummyVerify spends the same work as Verify for an unknown user, so response
// time does not reveal whether an account exists (SEC-004).
func (h *Hasher) DummyVerify(ctx context.Context, secret string) {
	if err := h.acquire(ctx); err != nil {
		return
	}
	defer h.release()
	salt := make([]byte, h.params.SaltLen)
	_ = argon2.IDKey([]byte(secret), salt, h.params.Time, h.params.MemoryKiB, h.params.Threads, h.params.KeyLen)
}

// maxDecodeMemoryKiB caps the memory an encoded hash may ask for (1 GiB), so a
// corrupted row cannot make verification exhaust memory.
const maxDecodeMemoryKiB = 1024 * 1024

func decodePHC(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	var p Argon2Params
	var threads uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &threads); err != nil {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	if p.MemoryKiB == 0 || p.MemoryKiB > maxDecodeMemoryKiB || p.Time == 0 || p.Time > 100 || threads == 0 || threads > 255 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	p.Threads = uint8(threads)
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 1024 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 1024 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	return p, salt, key, nil
}
