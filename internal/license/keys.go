package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// KeyStatus says whether licenses signed with a key are trusted (spec §16.7).
type KeyStatus string

// Key statuses. Retired keys are simply not embedded any more.
const (
	KeyActive  KeyStatus = "active"
	KeyRevoked KeyStatus = "revoked"
)

// PublicKey is one vendor license verification key.
type PublicKey struct {
	ID     string
	Key    ed25519.PublicKey
	Status KeyStatus
	// RevokedFrom, for a revoked key, is the first issued_at that is no longer trusted
	// (licenses issued before it stay valid). Zero means nothing signed with it is trusted.
	RevokedFrom time.Time
}

// KeySet is the set of keys a binary trusts, by key ID.
type KeySet struct{ keys map[string]PublicKey }

// NewKeySet builds a key set (a later key with the same ID replaces an earlier one).
func NewKeySet(keys ...PublicKey) KeySet {
	ks := KeySet{keys: make(map[string]PublicKey, len(keys))}
	for _, k := range keys {
		ks.keys[k.ID] = k
	}
	return ks
}

// Len returns the number of keys.
func (k KeySet) Len() int { return len(k.keys) }

// Keys returns the keys sorted by ID.
func (k KeySet) Keys() []PublicKey {
	out := make([]PublicKey, 0, len(k.keys))
	for _, pk := range k.keys {
		out = append(out, pk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Fingerprint identifies a public key for people: "SHA256:" and 64 hex digits. The
// release process compares it with the vendor's recorded fingerprint (spec §19.2).
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

type keySetFile struct {
	Keys []keyEntry `json:"keys"`
}

type keyEntry struct {
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"` // standard base64 of the 32-byte Ed25519 key
	Status      string `json:"status"`
	RevokedFrom string `json:"revoked_from,omitempty"`
}

// testKeyIDPrefix is reserved for publicly derivable test keys (licensetest.KeyID): a key set
// file is a production key set, so it never lists one.
const testKeyIDPrefix = "vk-test-"

// ParseKeySet reads the embedded key set file {"keys": [...]}. Key IDs starting with
// "vk-test-" are refused, and public keys must be canonical standard base64.
func ParseKeySet(data []byte) (KeySet, error) {
	var f keySetFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return KeySet{}, fmt.Errorf("license: key set: %w", err)
	}
	if f.Keys == nil {
		return KeySet{}, errors.New("license: key set: the keys list is missing")
	}
	ks := KeySet{keys: make(map[string]PublicKey, len(f.Keys))}
	for _, e := range f.Keys {
		if !keyIDPattern.MatchString(e.KeyID) {
			return KeySet{}, fmt.Errorf("license: key set: key ID %q is not valid", e.KeyID)
		}
		if strings.HasPrefix(e.KeyID, testKeyIDPrefix) {
			return KeySet{}, fmt.Errorf("license: key set: key ID %q is reserved for test keys", e.KeyID)
		}
		if _, dup := ks.keys[e.KeyID]; dup {
			return KeySet{}, fmt.Errorf("license: key set: key ID %q appears twice", e.KeyID)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(e.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return KeySet{}, fmt.Errorf("license: key set: key %q is not a base64 Ed25519 public key", e.KeyID)
		}
		k := PublicKey{ID: e.KeyID, Key: ed25519.PublicKey(raw), Status: KeyStatus(e.Status)}
		switch k.Status {
		case KeyActive:
			if e.RevokedFrom != "" {
				return KeySet{}, fmt.Errorf("license: key set: active key %q has revoked_from", e.KeyID)
			}
		case KeyRevoked:
			if e.RevokedFrom != "" {
				t, err := time.Parse(time.RFC3339, e.RevokedFrom)
				if err != nil {
					return KeySet{}, fmt.Errorf("license: key set: revoked_from of %q is not RFC 3339", e.KeyID)
				}
				k.RevokedFrom = t.UTC()
			}
		default:
			return KeySet{}, fmt.Errorf("license: key set: key %q has unknown status %q", e.KeyID, e.Status)
		}
		ks.keys[k.ID] = k
	}
	return ks, nil
}

// EncodeKeySet renders keys in the key set file format (used by licensectl keyset).
func EncodeKeySet(keys ...PublicKey) ([]byte, error) {
	f := keySetFile{Keys: []keyEntry{}}
	for _, k := range NewKeySet(keys...).Keys() {
		e := keyEntry{KeyID: k.ID, PublicKey: base64.StdEncoding.EncodeToString(k.Key), Status: string(k.Status)}
		if k.Status == KeyRevoked && !k.RevokedFrom.IsZero() {
			e.RevokedFrom = formatTime(k.RevokedFrom)
		}
		f.Keys = append(f.Keys, e)
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Verify checks the signature of f against keys (spec §16.3 steps 2-3): an unknown key ID
// is ErrUnknownKey, a wrong signature an *InvalidError with Problem "signature", and a
// license from a revoked key (issued at or after its cutoff) ErrRevokedKey.
func Verify(f File, keys KeySet) error {
	pk, ok := keys.keys[f.KeyID]
	if !ok || len(pk.Key) != ed25519.PublicKeySize {
		return ErrUnknownKey
	}
	if !ed25519.Verify(pk.Key, SignedBytes(f.Payload), f.Signature) {
		return invalid("signature")
	}
	if pk.Status == KeyRevoked && (pk.RevokedFrom.IsZero() || !f.Payload.IssuedAt.Before(pk.RevokedFrom)) {
		return ErrRevokedKey
	}
	return nil
}

// Check parses raw, verifies its signature and validates the payload: spec §16.3 steps
// 1, 2, 3 and 5. Step 4 (the installation ID) is checked by Service, which knows it. A file in a
// newer format is ErrUnsupportedFormat only when its signature verifies (AUD-19, see checkNewer).
func Check(raw []byte, keys KeySet) (File, error) {
	f, err := ParseFile(raw)
	var inv *InvalidError
	if errors.As(err, &inv) && inv.Problem == ProblemNewerFormat {
		return File{}, checkNewer(raw, keys)
	}
	if err != nil {
		return File{}, err
	}
	if err := Verify(f, keys); err != nil {
		return File{}, err
	}
	if err := f.Payload.Validate(); err != nil {
		return File{}, err
	}
	return f, nil
}
