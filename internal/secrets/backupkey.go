package secrets

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
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

const backupKeyAAD = "alice/backup-key/v1"

// WrappedBackupKey is the X25519 backup key pair: the public key in clear,
// the private key only wrapped by the recovery passphrase (R4, SEC-048).
// Neither the passphrase nor a passphrase-derived key is ever stored.
type WrappedBackupKey struct {
	Version    int       `json:"version"`
	PublicKey  []byte    `json:"public_key"`
	KDF        KDFParams `json:"kdf"`
	Salt       []byte    `json:"salt"`
	Nonce      []byte    `json:"nonce"`
	Ciphertext []byte    `json:"ciphertext"`
}

// NewBackupKey generates an X25519 key pair and wraps the private key with
// AES-256-GCM under Argon2id(passphrase).
func NewBackupKey(passphrase []byte, p KDFParams) (WrappedBackupKey, error) {
	if err := p.validate(); err != nil {
		return WrappedBackupKey{}, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return WrappedBackupKey{}, fmt.Errorf("generate backup key: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return WrappedBackupKey{}, fmt.Errorf("generate backup key salt: %w", err)
	}
	kek := argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, KeySize)
	defer clear(kek)

	pub := priv.PublicKey().Bytes()
	privBytes := priv.Bytes()
	defer clear(privBytes)
	ct, nonce, err := seal(kek, privBytes, append([]byte(backupKeyAAD), pub...))
	if err != nil {
		return WrappedBackupKey{}, err
	}
	return WrappedBackupKey{Version: 1, PublicKey: pub, KDF: p, Salt: salt, Nonce: nonce, Ciphertext: ct}, nil
}

// Unwrap recovers the private key. A wrong passphrase or any modified field returns ErrDecrypt.
func (w WrappedBackupKey) Unwrap(passphrase []byte) (*ecdh.PrivateKey, error) {
	if w.Version != 1 || len(w.Salt) == 0 || len(w.PublicKey) != 32 {
		return nil, ErrDecrypt
	}
	if err := w.KDF.validate(); err != nil {
		return nil, err
	}
	kek := argon2.IDKey(passphrase, w.Salt, w.KDF.Time, w.KDF.MemoryKiB, w.KDF.Threads, KeySize)
	defer clear(kek)
	raw, err := open(kek, w.Nonce, w.Ciphertext, append([]byte(backupKeyAAD), w.PublicKey...))
	if err != nil {
		return nil, ErrDecrypt
	}
	defer clear(raw)
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
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
