// Package keymat holds the SSH key material Alice generates (spec §13.5, SEC-046): key generation,
// the OpenSSH private-key file of the audited download, authorized_keys lines and comments, and the
// signer of a test login. Nothing here logs, and no value of this package prints a private key.
package keymat

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"golang.org/x/crypto/ssh"

	"alice/internal/secrets"
)

// KeyType is a key Alice can generate.
type KeyType string

// Key types (spec §13.5; R41 row 3). Ed25519 is the default.
const (
	Ed25519   KeyType = "ed25519"
	RSA3072   KeyType = "rsa-3072"
	RSA4096   KeyType = "rsa-4096"
	ECDSAP256 KeyType = "ecdsa-p256"
)

// Passphrase and from= bounds of the download and the deploy options.
const (
	MinPassphrase  = 12
	MaxPassphrase  = 1024
	MaxFromEntries = 16
)

// Errors carry no input.
var (
	ErrKeyType    = errors.New("keymat: unknown key type")
	ErrPassphrase = errors.New("keymat: the passphrase must be 12 to 1024 bytes")
	ErrFromOption = errors.New("keymat: from= must list IP addresses or networks")
	ErrLine       = errors.New("keymat: the authorized_keys line is not valid")
	ErrKeyData    = errors.New("keymat: the stored private key cannot be read")
)

// KeyTypes lists the generatable types in the order the UI offers them.
func KeyTypes() []KeyType { return []KeyType{Ed25519, RSA3072, RSA4096, ECDSAP256} }

// Valid reports whether t is one of KeyTypes.
func (t KeyType) Valid() bool {
	switch t {
	case Ed25519, RSA3072, RSA4096, ECDSAP256:
		return true
	}
	return false
}

// TypeOf maps a stored algorithm and size back to its type; anything else is Ed25519 (the default
// a rotation then uses).
func TypeOf(algorithm string, bits int) KeyType {
	switch {
	case algorithm == "rsa" && bits == 3072:
		return RSA3072
	case algorithm == "rsa" && bits == 4096:
		return RSA4096
	case algorithm == "ecdsa" && bits == 256:
		return ECDSAP256
	default:
		return Ed25519
	}
}

// Material is a freshly generated key. PKCS8 is the only clear private part; the caller zeroes it.
type Material struct {
	PKCS8           secrets.Plaintext
	PublicKey       string
	Fingerprint     string
	Algorithm       string
	Bits            int
	PublicKeySHA256 string
}

// onHold sees each clear-key buffer this package owns, when it is created (tests only; nil in
// production). A test keeps the slice and asserts it is zero once the owner returned or released.
var onHold func([]byte)

func hold(b []byte) {
	if onHold != nil {
		onHold(b)
	}
}

func (m Material) String() string               { return "keymat.Material{" + m.Fingerprint + "}" }
func (m Material) GoString() string             { return m.String() }
func (m Material) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, m.String()) }
func (m Material) MarshalJSON() ([]byte, error) { return json.Marshal(m.String()) }
func (m Material) LogValue() slog.Value         { return slog.StringValue(m.String()) }

// Generate creates a key of type t. An Ed25519 seed is read from rnd (crypto/rand when nil), so a
// test can fix it. RSA and ECDSA keys come from the standard library, which since Go 1.24 reads
// its own randomness and ignores rnd unless GODEBUG=cryptocustomrand=1 is set.
func Generate(rnd io.Reader, t KeyType) (Material, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	var priv crypto.Signer
	switch t {
	case Ed25519:
		seed := make([]byte, ed25519.SeedSize)
		defer clear(seed)
		if _, err := io.ReadFull(rnd, seed); err != nil {
			return Material{}, fmt.Errorf("keymat: read randomness: %w", err)
		}
		hold(seed)
		k := ed25519.NewKeyFromSeed(seed)
		defer clear(k)
		hold(k)
		priv = k
	case RSA3072, RSA4096:
		bits := 3072
		if t == RSA4096 {
			bits = 4096
		}
		k, err := rsa.GenerateKey(rnd, bits)
		if err != nil {
			return Material{}, fmt.Errorf("keymat: generate an RSA key: %w", err)
		}
		priv = k
	case ECDSAP256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rnd)
		if err != nil {
			return Material{}, fmt.Errorf("keymat: generate an ECDSA key: %w", err)
		}
		priv = k
	default:
		return Material{}, ErrKeyType
	}
	m, err := publicParts(priv)
	if err != nil {
		return Material{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Material{}, ErrKeyData
	}
	m.PKCS8 = secrets.NewPlaintext(der)
	return m, nil
}

// PublicOf returns the authorized_keys public key and fingerprint of a stored key.
func PublicOf(pkcs8 secrets.Plaintext) (publicKey, fingerprint string, err error) {
	priv, err := parse(pkcs8)
	if err != nil {
		return "", "", err
	}
	defer wipe(priv)
	m, err := publicParts(priv)
	if err != nil {
		return "", "", err
	}
	return m.PublicKey, m.Fingerprint, nil
}

func publicParts(priv crypto.Signer) (Material, error) {
	pub := priv.Public()
	sshPub, errSSH := ssh.NewPublicKey(pub)
	spki, errPKIX := x509.MarshalPKIXPublicKey(pub)
	if errSSH != nil || errPKIX != nil {
		return Material{}, ErrKeyData // cannot happen for a key this package created or parsed
	}
	sum := sha256.Sum256(spki)
	m := Material{PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		Fingerprint: ssh.FingerprintSHA256(sshPub), PublicKeySHA256: hex.EncodeToString(sum[:])}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		m.Algorithm, m.Bits = "ed25519", 256
	case *rsa.PublicKey:
		m.Algorithm, m.Bits = "rsa", k.N.BitLen()
	case *ecdsa.PublicKey:
		m.Algorithm, m.Bits = "ecdsa", k.Curve.Params().BitSize
	default:
		return Material{}, ErrKeyData
	}
	return m, nil
}

// parse reads a stored PKCS #8 key of one of the three algorithms.
func parse(pkcs8 secrets.Plaintext) (crypto.Signer, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8.Bytes())
	if err != nil {
		return nil, ErrKeyData
	}
	switch s := k.(type) {
	case ed25519.PrivateKey:
		hold(s)
		return s, nil
	case *rsa.PrivateKey:
		return s, nil
	case *ecdsa.PrivateKey:
		return s, nil
	}
	return nil, ErrKeyData
}

// wipe clears what can be cleared of a parsed key: an Ed25519 key's bytes. The limbs of RSA and
// ECDSA keys (big.Int) cannot be (known limitation P4-04).
func wipe(k crypto.Signer) {
	if e, ok := k.(ed25519.PrivateKey); ok {
		clear(e)
	}
}
