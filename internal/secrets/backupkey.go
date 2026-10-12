package secrets

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// KDFParams are the Argon2id parameters that turn the recovery passphrase
// into the key-wrapping key. They are stored next to the wrapped key.
type KDFParams struct {
	MemoryKiB uint32 `json:"memory_kib"`
	Time      uint32 `json:"time"`
	Threads   uint8  `json:"threads"`
}

// BackupKDF is the production setting from SEC-048 (m=64 MiB, t=3, p=4).
var BackupKDF = KDFParams{MemoryKiB: 64 * 1024, Time: 3, Threads: 4}

// maxKDFMemoryKiB bounds Argon2 memory so a hostile stored value cannot exhaust memory (1 GiB).
const maxKDFMemoryKiB = 1024 * 1024

// BackupKeyVersion is the only version of the wrapped backup key (R43 row 41). Version 1 had no sender key and was
// never released.
const BackupKeyVersion = 2

// backupKeyAAD prefixes the AAD of the wrapped key: "alice/backup-key/v2" || public_key || sender_public_key.
const backupKeyAAD = "alice/backup-key/v2"

const x25519KeySize = 32

// WrappedBackupKey is the X25519 backup key pair: the public key in clear,
// the private key only wrapped by the recovery passphrase (R4, SEC-048).
// Neither the passphrase nor a passphrase-derived key is ever stored.
//
// SenderPublicKey is the public half of the installation's sender key S (R43 row 41). The wrap binds it, so the
// passphrase authenticates it: someone who does not know the passphrase cannot make a file the passphrase opens
// without S's private half, which never leaves the installation. A passphrase holder can: the passphrase unwraps R's
// private half, and R_priv*S_pub equals S_priv*R_pub (KI-14).
type WrappedBackupKey struct {
	Version         int       `json:"version"`
	PublicKey       []byte    `json:"public_key"`
	KDF             KDFParams `json:"kdf"`
	Salt            []byte    `json:"salt"`
	Nonce           []byte    `json:"nonce"`
	Ciphertext      []byte    `json:"ciphertext"`
	SenderPublicKey []byte    `json:"sender_public_key"`
}

// NewBackupKey generates the recipient key pair R and the sender key pair S, wraps R's private key with AES-256-GCM
// under Argon2id(passphrase) bound to both public keys, and returns the record and S's private key. It stores
// nothing: the caller keeps S as a master-key envelope (setting secret backup.sender).
func NewBackupKey(passphrase []byte, p KDFParams) (WrappedBackupKey, *ecdh.PrivateKey, error) {
	if err := p.validate(); err != nil {
		return WrappedBackupKey{}, nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return WrappedBackupKey{}, nil, fmt.Errorf("generate backup key: %w", err)
	}
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return WrappedBackupKey{}, nil, fmt.Errorf("generate backup sender key: %w", err)
	}
	privBytes := priv.Bytes()
	defer clear(privBytes)
	w, err := wrapBackupKey(passphrase, p, privBytes, priv.PublicKey().Bytes(), sender.PublicKey().Bytes())
	if err != nil {
		return WrappedBackupKey{}, nil, err
	}
	return w, sender, nil
}

// MaxPassphraseRunes is the longest passphrase in runes after NFKC, the same limit setup enforces.
const MaxPassphraseRunes = 1024

// maxPassphraseBytes bounds the raw input before it is normalised: 16 bytes per allowed rune leaves room for any
// decomposed or compatibility spelling of a passphrase within MaxPassphraseRunes.
const maxPassphraseBytes = 16 * MaxPassphraseRunes

var errPassphraseLength = errors.New("secrets: the recovery passphrase is empty or longer than 1,024 characters")

// normalizePassphrase returns a new buffer with the NFKC form of the passphrase (the form setup checks, SEC-002), so
// the same text typed composed or decomposed derives the same key. NFKC is idempotent: a passphrase setup already
// normalised is unchanged. The caller clears the result; the input is never modified.
func normalizePassphrase(passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 || len(passphrase) > maxPassphraseBytes {
		return nil, errPassphraseLength
	}
	pp := norm.NFKC.Append(make([]byte, 0, len(passphrase)), passphrase...)
	if utf8.RuneCount(pp) > MaxPassphraseRunes {
		clear(pp)
		return nil, errPassphraseLength
	}
	return pp, nil
}

// wrapBackupKey seals priv under Argon2id(NFKC(passphrase)) with the v2 AAD.
func wrapBackupKey(passphrase []byte, p KDFParams, priv, pub, senderPub []byte) (WrappedBackupKey, error) {
	pp, err := normalizePassphrase(passphrase)
	if err != nil {
		return WrappedBackupKey{}, err
	}
	defer clear(pp)
	return sealBackupKey(pp, p, priv, pub, senderPub)
}

// sealBackupKey seals priv under Argon2id of the passphrase bytes as given.
func sealBackupKey(passphrase []byte, p KDFParams, priv, pub, senderPub []byte) (WrappedBackupKey, error) {
	if err := p.validate(); err != nil {
		return WrappedBackupKey{}, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return WrappedBackupKey{}, fmt.Errorf("generate backup key salt: %w", err)
	}
	kek := argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, KeySize)
	defer clear(kek)
	ct, nonce, err := seal(kek, priv, backupKeyAD(pub, senderPub))
	if err != nil {
		return WrappedBackupKey{}, err
	}
	return WrappedBackupKey{Version: BackupKeyVersion, PublicKey: bytes.Clone(pub), KDF: p, Salt: salt, Nonce: nonce,
		Ciphertext: ct, SenderPublicKey: bytes.Clone(senderPub)}, nil
}

func backupKeyAD(pub, senderPub []byte) []byte {
	ad := make([]byte, 0, len(backupKeyAAD)+len(pub)+len(senderPub))
	return append(append(append(ad, backupKeyAAD...), pub...), senderPub...)
}

// Unwrap recovers the recipient private key. The passphrase is passed as typed: Unwrap applies the same NFKC step as
// the wrap, so callers never normalise (an empty or over-long passphrase is ErrDecrypt). Only version 2 is accepted.
// A wrong passphrase, any modified field
// (including either public key) or a wrapped key whose public half is not PublicKey returns ErrDecrypt. A successful
// Unwrap therefore also authenticates SenderPublicKey.
func (w WrappedBackupKey) Unwrap(passphrase []byte) (*ecdh.PrivateKey, error) {
	if w.Version != BackupKeyVersion || len(w.Salt) == 0 || len(w.PublicKey) != x25519KeySize ||
		len(w.SenderPublicKey) != x25519KeySize {
		return nil, ErrDecrypt
	}
	if err := w.KDF.validate(); err != nil {
		return nil, err
	}
	pp, err := normalizePassphrase(passphrase)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer clear(pp)
	kek := argon2.IDKey(pp, w.Salt, w.KDF.Time, w.KDF.MemoryKiB, w.KDF.Threads, KeySize)
	defer clear(kek)
	raw, err := open(kek, w.Nonce, w.Ciphertext, backupKeyAD(w.PublicKey, w.SenderPublicKey))
	if err != nil {
		return nil, ErrDecrypt
	}
	defer clear(raw)
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, ErrDecrypt
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), w.PublicKey) {
		return nil, ErrDecrypt
	}
	return priv, nil
}

func (p KDFParams) validate() error {
	if p.MemoryKiB == 0 || p.Time == 0 || p.Threads == 0 {
		return fmt.Errorf("secrets: backup key KDF parameters must be positive")
	}
	if p.MemoryKiB > maxKDFMemoryKiB {
		return fmt.Errorf("secrets: backup key KDF memory %d KiB exceeds the 1 GiB limit", p.MemoryKiB)
	}
	return nil
}
