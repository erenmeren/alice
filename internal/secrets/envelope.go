package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
)

// KeySize is the size in bytes of the master key and of every DEK (AES-256).
const KeySize = 32

const nonceSize = 12

// ErrDecrypt is returned for every decryption failure. It never says why,
// so it cannot be used as an oracle.
var ErrDecrypt = errors.New("secrets: decryption failed")

// ErrMasterKeyMismatch means the master key file does not belong to this database.
var ErrMasterKeyMismatch = errors.New("the master key does not match this database")

// HKDF info labels for sub-keys (SEC-043). The master key itself is never used as a MAC key.
const (
	LabelHWM       = "alice/hwm/v1"
	LabelJob       = "alice/job/v1"
	LabelAuditHMAC = "alice/audit-hmac/v1"
	LabelCSRF      = "alice/csrf/v1"
)

const keyCheckPlaintext = "alice-master-key-check-v1"

// Location names the database cell a secret lives in. It is bound into the
// AEAD additional data, so a ciphertext copied to another row or column
// fails to decrypt (SEC-041).
type Location struct {
	Table, RowID, Column string
}

func (l Location) payloadAAD() []byte {
	return []byte(l.Table + "/" + l.RowID + "/" + l.Column)
}

func (l Location) wrapAAD(version int) []byte {
	return []byte(l.Table + "/" + l.RowID + "/" + l.Column + "/" + strconv.Itoa(version))
}

// Envelope is the stored form of one secret (the *_ct, *_nonce,
// *_wrapped_dek and *_key_version columns).
type Envelope struct {
	Ciphertext []byte
	Nonce      []byte // 12 bytes
	WrappedDEK []byte // 12-byte nonce || AES-256-GCM(dek)
	KeyVersion int
}

// Keyring holds the current master key.
type Keyring struct {
	version int
	key     []byte
}

// NewKeyring returns a keyring for a 32-byte master key with the given version (>= 1).
func NewKeyring(version int, key []byte) (*Keyring, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secrets: master key must be %d bytes, got %d", KeySize, len(key))
	}
	if version < 1 {
		return nil, fmt.Errorf("secrets: master key version must be at least 1, got %d", version)
	}
	return &Keyring{version: version, key: append([]byte(nil), key...)}, nil
}

// Version returns the master key version used for new envelopes.
func (k *Keyring) Version() int { return k.version }

// Seal encrypts plaintext with a fresh random DEK and wraps the DEK with the master key.
func (k *Keyring) Seal(loc Location, plaintext []byte) (Envelope, error) {
	dek := make([]byte, KeySize)
	rand.Read(dek)
	defer clear(dek)

	ct, nonce, err := seal(dek, plaintext, loc.payloadAAD())
	if err != nil {
		return Envelope{}, err
	}
	wct, wnonce, err := seal(k.key, dek, loc.wrapAAD(k.version))
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Ciphertext: ct,
		Nonce:      nonce,
		WrappedDEK: append(wnonce, wct...),
		KeyVersion: k.version,
	}, nil
}

// Open unwraps the DEK and decrypts the payload. Any mismatch (tampered
// bytes, other location, unknown key version) returns ErrDecrypt.
func (k *Keyring) Open(loc Location, env Envelope) (Plaintext, error) {
	if env.KeyVersion != k.version || len(env.WrappedDEK) <= nonceSize || len(env.Nonce) != nonceSize {
		return Plaintext{}, ErrDecrypt
	}
	dek, err := open(k.key, env.WrappedDEK[:nonceSize], env.WrappedDEK[nonceSize:], loc.wrapAAD(env.KeyVersion))
	if err != nil {
		return Plaintext{}, ErrDecrypt
	}
	defer clear(dek)
	if len(dek) != KeySize {
		return Plaintext{}, ErrDecrypt
	}
	pt, err := open(dek, env.Nonce, env.Ciphertext, loc.payloadAAD())
	if err != nil {
		return Plaintext{}, ErrDecrypt
	}
	return NewPlaintext(pt), nil
}

// Derive returns a 32-byte sub-key: HKDF-SHA256(master key, no salt, info=label).
func (k *Keyring) Derive(label string) []byte {
	out, err := hkdf.Key(sha256.New, k.key, nil, label, KeySize)
	if err != nil {
		panic("secrets: hkdf failed: " + err.Error()) // impossible for a 32-byte output
	}
	return out
}

func (k *Keyring) keyCheckAAD() []byte {
	return []byte("master_key_versions/" + strconv.Itoa(k.version) + "/key_check")
}

// KeyCheck returns a sealed known constant, stored in master_key_versions.key_check
// so a later start can tell whether the key file belongs to this database.
func (k *Keyring) KeyCheck() ([]byte, error) {
	ct, nonce, err := seal(k.key, []byte(keyCheckPlaintext), k.keyCheckAAD())
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// VerifyKeyCheck returns ErrMasterKeyMismatch unless check was made by KeyCheck with this key and version.
func (k *Keyring) VerifyKeyCheck(check []byte) error {
	if len(check) <= nonceSize {
		return ErrMasterKeyMismatch
	}
	pt, err := open(k.key, check[:nonceSize], check[nonceSize:], k.keyCheckAAD())
	if err != nil || string(pt) != keyCheckPlaintext {
		return ErrMasterKeyMismatch
	}
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	return cipher.NewGCM(block)
}

func seal(key, plaintext, aad []byte) (ct, nonce []byte, err error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, nonceSize)
	rand.Read(nonce)
	return g.Seal(nil, nonce, plaintext, aad), nonce, nil
}

func open(key, nonce, ct, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != g.NonceSize() {
		return nil, ErrDecrypt
	}
	return g.Open(nil, nonce, ct, aad)
}
