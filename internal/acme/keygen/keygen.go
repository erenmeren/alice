// Package keygen makes the private key and the certificate signing request of an ACME order. It is pure: no
// database, file, network or clock. Keys come from crypto/rand (the standard library ignores any other
// source since Go 1.26), so nothing here is replaceable by a test reader.
//
// Secret handling (plan amendment A10). The key's PKCS#8 DER is a secrets.Plaintext: it renders as
// "[redacted]" in every fmt, JSON and slog path and is zeroed by Key.Zero. The *ecdsa.PrivateKey or
// *rsa.PrivateKey behind Key.Signer cannot be zeroed (Go keeps the scalar in big.Int and internal
// representations the caller cannot reach); callers keep a Key, and its Signer, only for the order that needs
// it and drop it afterwards. Key itself redacts on every format verb, so printing a Key never prints the
// signer.
package keygen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"alice/internal/secrets"
)

// KeyPolicy is the key type of an ACME certificate; the values are acme_certificates.key_type's.
type KeyPolicy string

// The key policies (plan design row 7): ECDSA P-256 is the default.
const (
	ECDSAP256 KeyPolicy = "ecdsa_p256"
	ECDSAP384 KeyPolicy = "ecdsa_p384"
	RSA2048   KeyPolicy = "rsa_2048"
	RSA3072   KeyPolicy = "rsa_3072"
	RSA4096   KeyPolicy = "rsa_4096"

	Default = ECDSAP256
)

// ReasonKeyPolicyNotAllowed is the stable reason of ErrKeyPolicy (ALC-ACM-0011; equal to
// acme.ReasonKeyPolicyNotAllowed, checked by a test).
const ReasonKeyPolicyNotAllowed = "acme.key_policy_not_allowed"

// Errors. None carries input.
var (
	// ErrKeyPolicy: the key type is not one of the policies (or a key is not of one).
	ErrKeyPolicy = errors.New("keygen: the key type is not allowed")
	// ErrNames: the names of a signing request are empty, blank, duplicated or not ASCII.
	ErrNames = errors.New("keygen: the names of the signing request are not valid")
	// ErrKey: a key cannot be generated, encoded or parsed.
	ErrKey = errors.New("keygen: the key cannot be used")
)

// Policies lists every policy, the default first.
func Policies() []KeyPolicy { return []KeyPolicy{ECDSAP256, ECDSAP384, RSA2048, RSA3072, RSA4096} }

// ParseKeyPolicy returns the policy named s (exactly one of Policies); anything else is ErrKeyPolicy.
func ParseKeyPolicy(s string) (KeyPolicy, error) {
	p := KeyPolicy(s)
	if _, _, ok := p.params(); !ok {
		return "", ErrKeyPolicy
	}
	return p, nil
}

// params are the algorithm ("ecdsa" | "rsa") and size (curve bits, modulus bits) of p.
func (p KeyPolicy) params() (string, int, bool) {
	switch p {
	case ECDSAP256:
		return "ecdsa", 256, true
	case ECDSAP384:
		return "ecdsa", 384, true
	case RSA2048:
		return "rsa", 2048, true
	case RSA3072:
		return "rsa", 3072, true
	case RSA4096:
		return "rsa", 4096, true
	}
	return "", 0, false
}

// Algorithm returns what managed_private_keys stores of a key of p: algorithm "ecdsa" (bits 256 or 384) or
// "rsa" (2048, 3072 or 4096). ErrKeyPolicy for an unknown policy.
func (p KeyPolicy) Algorithm() (algorithm string, bits int, err error) {
	a, b, ok := p.params()
	if !ok {
		return "", 0, ErrKeyPolicy
	}
	return a, b, nil
}

// PolicyOf classifies a public key: ErrKeyPolicy unless it is ECDSA P-256 or P-384 or RSA of exactly 2048,
// 3072 or 4096 bits.
func PolicyOf(pub crypto.PublicKey) (KeyPolicy, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return ECDSAP256, nil
		case elliptic.P384():
			return ECDSAP384, nil
		}
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048:
			return RSA2048, nil
		case 3072:
			return RSA3072, nil
		case 4096:
			return RSA4096, nil
		}
	}
	return "", ErrKeyPolicy
}

// Key is a generated or opened private key. DER is its PKCS#8 encoding (the caller zeroes it with Zero once
// it is sealed); Signer is the parsed key (cannot be zeroed, see the package comment). Every format of a Key
// is "keygen.Key{[redacted]}".
type Key struct {
	DER    secrets.Plaintext
	Signer crypto.Signer
	Policy KeyPolicy
}

// Zero overwrites the DER. The Signer stays usable.
func (k *Key) Zero() {
	if k != nil {
		k.DER.Zero()
	}
}

// PublicKeySHA256 is the lower-case hex SHA-256 of the key's PKIX public key, as certs.KeyInfoOf and
// managed_private_keys.public_key_sha256 have it.
func (k *Key) PublicKeySHA256() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(k.Signer.Public())
	if err != nil {
		return "", ErrKey
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

const redactedKey = "keygen.Key{[redacted]}"

// String implements fmt.Stringer.
func (*Key) String() string { return redactedKey }

// GoString implements fmt.GoStringer.
func (*Key) GoString() string { return redactedKey }

// Format renders every verb as redacted.
func (*Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedKey) }

// LogValue implements slog.LogValuer.
func (*Key) LogValue() slog.Value { return slog.StringValue(redactedKey) }

// MarshalJSON never encodes the key.
func (*Key) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedKey + `"`), nil }

// Generate makes a new key of policy p (crypto/rand). ErrKeyPolicy for an unknown policy.
func Generate(p KeyPolicy) (*Key, error) {
	alg, bits, ok := p.params()
	if !ok {
		return nil, ErrKeyPolicy
	}
	var (
		signer crypto.Signer
		err    error
	)
	if alg == "ecdsa" {
		curve := elliptic.P256()
		if bits == 384 {
			curve = elliptic.P384()
		}
		signer, err = ecdsa.GenerateKey(curve, rand.Reader)
	} else {
		signer, err = rsa.GenerateKey(rand.Reader, bits)
	}
	if err != nil {
		return nil, ErrKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, ErrKey
	}
	return &Key{DER: secrets.NewPlaintext(der), Signer: signer, Policy: p}, nil
}

// ParsePKCS8 opens a PKCS#8 key (a sealed pending key after unsealing). The key must be of one of the
// policies (ErrKeyPolicy); the DER is not copied: the returned Key's DER is der, still the caller's to zero.
func ParsePKCS8(der secrets.Plaintext) (*Key, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der.Bytes())
	if err != nil {
		return nil, ErrKey
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, ErrKeyPolicy
	}
	p, err := PolicyOf(signer.Public())
	if err != nil {
		return nil, err
	}
	return &Key{DER: der, Signer: signer, Policy: p}, nil
}

// maxCommonName is the X.509 upper bound of a common name (ub-common-name, RFC 5280).
const maxCommonName = 64

// NewCSR makes the DER signing request of signer for names: every name is a DNS SAN, in the order given; the
// common name is the first name that is not a wildcard and fits in 64 characters, or empty (RFC 8555 needs
// none). The signature is SHA-256 based for P-256 and RSA keys and SHA-384 for P-384 (the hash that matches
// the curve). Names must be non-empty, ASCII (IDNs in their xn-- form), without blanks, unique ignoring case;
// their syntax is the caller's (acme.NormalizeNames), this only refuses what would make a malformed request.
func NewCSR(signer crypto.Signer, names []string) ([]byte, error) {
	if signer == nil {
		return nil, ErrKey
	}
	p, err := PolicyOf(signer.Public())
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, ErrNames
	}
	seen := make(map[string]bool, len(names))
	cn := ""
	for _, n := range names {
		if !asciiName(n) || seen[asciiLower(n)] {
			return nil, ErrNames
		}
		seen[asciiLower(n)] = true
		if cn == "" && !strings.HasPrefix(n, "*.") && len(n) <= maxCommonName {
			cn = n
		}
	}
	alg := x509.SHA256WithRSA
	switch p {
	case ECDSAP256:
		alg = x509.ECDSAWithSHA256
	case ECDSAP384:
		alg = x509.ECDSAWithSHA384
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		DNSNames:           append([]string(nil), names...),
		SignatureAlgorithm: alg,
	}, signer)
	if err != nil {
		return nil, ErrKey
	}
	return der, nil
}

// asciiName: 1..253 printable ASCII characters, no blank.
func asciiName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for i := 0; i < len(n); i++ {
		if n[i] <= 0x20 || n[i] >= 0x7f {
			return false
		}
	}
	return true
}

// asciiLower lower-cases ASCII letters only (names are ASCII here; no locale rules).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
