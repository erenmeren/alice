package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"time"

	"alice/internal/secrets"
)

// CSRRequest is a request for a new key and signing request.
type CSRRequest struct {
	CommonName string
	SANs       []string
	KeyType    string // "ecdsa-p256" | "rsa-3072" | "rsa-4096"
}

// ValidDNSName accepts 1..253 bytes of lower-case ASCII labels (1..63 of
// [a-z0-9-], not starting or ending with "-"), with an optional leading "*." label.
func ValidDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	rest := s
	if len(s) > 2 && s[:2] == "*." {
		rest = s[2:]
	}
	start := 0
	for i := 0; i <= len(rest); i++ {
		if i < len(rest) && rest[i] != '.' {
			continue
		}
		label := rest[start:i]
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for j := 0; j < len(label); j++ {
			c := label[j]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
		start = i + 1
	}
	return true
}

func generateKey(rnd io.Reader, keyType string) (crypto.Signer, error) {
	switch keyType {
	case "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rnd)
	case "rsa-3072":
		return rsa.GenerateKey(rnd, 3072)
	case "rsa-4096":
		return rsa.GenerateKey(rnd, 4096)
	}
	return nil, ErrUnsupportedKey
}

// NewCSR generates a key and a signing request for it. The common name is also
// the first SAN.
func NewCSR(rnd io.Reader, r CSRRequest) (csrPEM string, keyDER secrets.Plaintext, info KeyInfo, err error) {
	if !ValidDNSName(r.CommonName) {
		return "", secrets.Plaintext{}, KeyInfo{}, invalid("the common name is not a valid DNS name")
	}
	names := []string{r.CommonName}
	seen := map[string]bool{r.CommonName: true}
	for _, s := range r.SANs {
		if !ValidDNSName(s) {
			return "", secrets.Plaintext{}, KeyInfo{}, invalid("a subject alternative name is not a valid DNS name")
		}
		if !seen[s] {
			seen[s] = true
			names = append(names, s)
		}
	}
	key, err := generateKey(rnd, r.KeyType)
	if err != nil {
		return "", secrets.Plaintext{}, KeyInfo{}, err
	}
	csr, err := x509.CreateCertificateRequest(rnd, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: r.CommonName},
		DNSNames: names,
	}, key)
	if err != nil {
		return "", secrets.Plaintext{}, KeyInfo{}, invalid("the signing request cannot be created")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", secrets.Plaintext{}, KeyInfo{}, ErrUnsupportedKey
	}
	keyDER = secrets.NewPlaintext(der)
	info, err = KeyInfoOf(keyDER)
	if err != nil {
		keyDER.Zero()
		return "", secrets.Plaintext{}, KeyInfo{}, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), keyDER, info, nil
}

// ValidateSigned checks a certificate a CA issued for a signing request of
// Alice: it must carry the request's key, and pass the signature, key and
// validity rules of uploads. It returns the chain ordered from the leaf and
// whether it is complete.
func ValidateSigned(certPEM []byte, key KeyInfo, now time.Time, roots *x509.CertPool) (Parsed, bool, error) {
	all, err := certificatesOf(certPEM)
	if err != nil {
		return Parsed{}, false, err
	}
	var leaf *x509.Certificate
	idx := -1
	for i, c := range all {
		if describe(c, nil).PublicKeySHA256 == key.PublicKeySHA256 {
			leaf, idx = c, i
			break
		}
	}
	if leaf == nil {
		return Parsed{}, false, ErrCSRMismatch
	}
	if err := checkPublicKey(leaf.PublicKey); err != nil {
		return Parsed{}, false, err
	}
	others := append(append([]*x509.Certificate(nil), all[:idx]...), all[idx+1:]...)
	p := describe(leaf, orderChain(leaf, others))
	if err := checkLeaf(p, now); err != nil {
		return Parsed{}, false, err
	}
	return p, ChainComplete(p, roots, now), nil
}
