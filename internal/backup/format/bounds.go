package format

import (
	"bytes"
	"fmt"
	"regexp"
	"time"
)

// KDF bounds of the wrapped key in a backup header (C7, §25.6): a hostile header never makes Argon2 allocate more
// than 256 MiB or run more than 10 passes.
const (
	MinKDFMemoryKiB = 8192
	MaxKDFMemoryKiB = 262144
	MaxKDFTime      = 10
	MaxKDFThreads   = 16
)

// Field lengths in bytes.
const (
	keyLen        = 32 // X25519 public keys
	saltLen       = 16
	wrapNonceLen  = 12
	wrappedKeyLen = 48 // a 32-byte private key plus the GCM tag
	prefixLen     = 4
)

var (
	kindPattern    = regexp.MustCompile(`^(auto|manual|pre-restore|pre-upgrade-[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?)$`)
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
)

// checkMeta validates the clear metadata. Messages name the field, never its value.
func checkMeta(m Meta) error {
	if m.AliceVersion != "dev" && !versionPattern.MatchString(m.AliceVersion) {
		return fmt.Errorf("%w: alice_version is not a version", ErrHeader)
	}
	if !kindPattern.MatchString(m.Kind) {
		return fmt.Errorf("%w: kind is not a backup kind", ErrHeader)
	}
	if m.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at is missing", ErrHeader)
	}
	return nil
}

// checkHeader applies every C7 bound. Messages never contain key material.
func checkHeader(h Header) error {
	if err := checkMeta(h.Meta); err != nil {
		return err
	}
	w := h.WrappedKey
	if w.Version != 2 {
		return fmt.Errorf("%w: wrapped key version %d", ErrHeader, w.Version)
	}
	for _, f := range []struct {
		name string
		b    []byte
		n    int
	}{
		{"recipient", h.Recipient, keyLen},
		{"ephemeral", h.Ephemeral, keyLen},
		{"wrapped_key.public_key", w.PublicKey, keyLen},
		{"wrapped_key.sender_public_key", w.SenderPublicKey, keyLen},
		{"wrapped_key.salt", w.Salt, saltLen},
		{"wrapped_key.nonce", w.Nonce, wrapNonceLen},
		{"wrapped_key.ciphertext", w.Ciphertext, wrappedKeyLen},
		{"nonce_prefix", h.NoncePrefix, prefixLen},
	} {
		if len(f.b) != f.n {
			return fmt.Errorf("%w: %s is %d bytes, not %d", ErrHeader, f.name, len(f.b), f.n)
		}
	}
	if !bytes.Equal(w.PublicKey, h.Recipient) {
		return fmt.Errorf("%w: the wrapped key is not the recipient's", ErrHeader)
	}
	if bytes.Equal(w.SenderPublicKey, h.Recipient) {
		return fmt.Errorf("%w: the sender key is the recipient key", ErrHeader)
	}
	k := w.KDF
	if k.MemoryKiB < MinKDFMemoryKiB || k.MemoryKiB > MaxKDFMemoryKiB {
		return fmt.Errorf("%w: kdf memory %d KiB", ErrHeader, k.MemoryKiB)
	}
	if k.Time < 1 || k.Time > MaxKDFTime {
		return fmt.Errorf("%w: kdf time %d", ErrHeader, k.Time)
	}
	if k.Threads < 1 || k.Threads > MaxKDFThreads {
		return fmt.Errorf("%w: kdf threads %d", ErrHeader, k.Threads)
	}
	if h.ChunkSize != ChunkSize {
		return fmt.Errorf("%w: chunk size %d", ErrHeader, h.ChunkSize)
	}
	return nil
}

// parseCreatedAt reads the RFC 3339 time of the header.
func parseCreatedAt(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: created_at is not an RFC 3339 time", ErrHeader)
	}
	return t.UTC(), nil
}
