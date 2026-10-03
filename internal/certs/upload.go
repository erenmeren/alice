package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/secrets"
)

// Upload is what a person hands Alice: PEM certificate and key, or a PFX.
type Upload struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	PFX            []byte
	PFXPassword    string
}

// Validated is an accepted upload. PrivateKeyDER is PKCS#8 and redacts itself
// when printed; the caller zeroes it.
type Validated struct {
	Parsed
	PrivateKeyDER secrets.Plaintext
	ChainComplete bool
	Warnings      []string // "not_yet_valid", "chain_incomplete"
}

// KeyInfo is what Alice keeps about a private key besides the key itself.
type KeyInfo struct {
	Algorithm       string // "rsa" | "ecdsa"
	Bits            int
	PublicKeySHA256 string
}

// ValidateUpload checks an upload and returns the leaf, its ordered chain and
// the key as PKCS#8. Errors never contain input.
func ValidateUpload(u Upload, now time.Time, roots *x509.CertPool) (Validated, error) {
	if len(u.PFX) > MaxInputSize || len(u.CertificatePEM) > MaxInputSize || len(u.PrivateKeyPEM) > MaxInputSize {
		return Validated{}, ErrTooLarge
	}
	var (
		all []*x509.Certificate
		key any
		err error
	)
	if len(u.PFX) > 0 {
		if len(u.CertificatePEM) > 0 || len(u.PrivateKeyPEM) > 0 {
			return Validated{}, invalid("give either a PFX or PEM fields, not both")
		}
		all, key, err = decodePFX(u.PFX, u.PFXPassword)
	} else {
		all, key, err = decodePEMPair(u.CertificatePEM, u.PrivateKeyPEM)
	}
	if err != nil {
		return Validated{}, err
	}
	signer, err := checkPrivateKey(key)
	if err != nil {
		return Validated{}, err
	}

	leafIdx := -1
	for i, c := range all {
		if samePublicKey(c.PublicKey, signer.Public()) {
			leafIdx = i
			break
		}
	}
	if leafIdx < 0 {
		return Validated{}, ErrKeyMismatch
	}
	others := append(append([]*x509.Certificate(nil), all[:leafIdx]...), all[leafIdx+1:]...)
	p := describe(all[leafIdx], orderChain(all[leafIdx], others))
	if err := checkLeaf(p, now); err != nil {
		return Validated{}, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Validated{}, ErrUnsupportedKey
	}
	v := Validated{Parsed: p, PrivateKeyDER: secrets.NewPlaintext(der), ChainComplete: ChainComplete(p, roots, now)}
	if now.Before(p.NotBefore) {
		v.Warnings = append(v.Warnings, "not_yet_valid")
	}
	if !v.ChainComplete {
		v.Warnings = append(v.Warnings, "chain_incomplete")
	}
	return v, nil
}

// checkLeaf applies the signature and validity rules shared by uploads and
// signed signing requests: no weak signature on the leaf or on a chain
// certificate that is not a root, and no expired leaf.
func checkLeaf(p Parsed, now time.Time) error {
	if weakSignature(p.Leaf) {
		return ErrWeak
	}
	for _, c := range p.Chain {
		if !selfSigned(c) && weakSignature(c) {
			return ErrWeak
		}
	}
	if !now.Before(p.NotAfter) {
		return ErrExpired
	}
	return nil
}

// checkPublicKey accepts RSA of at least 2048 bits and ECDSA on P-256 or P-384.
func checkPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return ErrWeak
		}
		return nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return nil
		}
	}
	return ErrUnsupportedKey
}

func checkPrivateKey(key any) (crypto.Signer, error) {
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	if err := checkPublicKey(s.Public()); err != nil {
		return nil, err
	}
	return s, nil
}

func samePublicKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

func decodePFX(data []byte, password string) ([]*x509.Certificate, any, error) {
	key, leaf, cas, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		// A wrong password and a damaged file are indistinguishable to the person
		// uploading, and the message must not carry anything from the file.
		return nil, nil, ErrPFXPassword
	}
	if len(cas)+1 > maxCertificates {
		return nil, nil, invalid("too many certificates")
	}
	return append([]*x509.Certificate{leaf}, cas...), key, nil
}

func decodePEMPair(certPEM, keyPEM []byte) ([]*x509.Certificate, any, error) {
	all, err := certificatesOf(certPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	return all, key, nil
}

// parsePrivateKeyPEM finds the single private key in data. Password-protected
// keys are refused before any decryption is attempted.
func parsePrivateKeyPEM(data []byte) (any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrNoKey
	}
	buf := normalize(data)
	defer clear(buf)
	var (
		blocks []*pem.Block
		parsed any
	)
	defer func() {
		for _, b := range blocks {
			clear(b.Bytes)
		}
	}()
	for rest := buf; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		blocks = append(blocks, b)
		if b.Headers["Proc-Type"] == "4,ENCRYPTED" || b.Type == "ENCRYPTED PRIVATE KEY" {
			return nil, ErrKeyEncrypted
		}
	}
	found := 0
	for _, b := range blocks {
		var err error
		switch b.Type {
		case "PRIVATE KEY":
			parsed, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		case "RSA PRIVATE KEY":
			parsed, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			parsed, err = x509.ParseECPrivateKey(b.Bytes)
		default:
			continue // EC PARAMETERS, certificates pasted along, ...
		}
		if err != nil {
			return nil, invalid("the private key cannot be parsed")
		}
		found++
	}
	if found != 1 {
		return nil, invalid("expected exactly one private key")
	}
	return parsed, nil
}

// KeyInfoOf describes a PKCS#8 private key without exposing it.
func KeyInfoOf(der secrets.Plaintext) (KeyInfo, error) {
	key, err := x509.ParsePKCS8PrivateKey(der.Bytes())
	if err != nil {
		return KeyInfo{}, invalid("the private key cannot be parsed")
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return KeyInfo{}, ErrUnsupportedKey
	}
	alg, bits := algorithmOf(s.Public())
	if alg != "rsa" && alg != "ecdsa" {
		return KeyInfo{}, ErrUnsupportedKey
	}
	pub, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return KeyInfo{}, ErrUnsupportedKey
	}
	return KeyInfo{Algorithm: alg, Bits: bits, PublicKeySHA256: fingerprint(pub)}, nil
}

// KeyPEM encodes a PKCS#8 DER key as a "PRIVATE KEY" PEM block.
func KeyPEM(der secrets.Plaintext) (secrets.Plaintext, error) {
	if len(der.Bytes()) == 0 {
		return secrets.Plaintext{}, errors.New("certs: empty key")
	}
	return secrets.NewPlaintext(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der.Bytes()})), nil
}
