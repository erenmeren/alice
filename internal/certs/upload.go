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
	Warnings      []string // "not_yet_valid", "chain_incomplete", "chain_certificate_expired"
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

	leafIdx := pickLeaf(all, now, func(c *x509.Certificate) bool { return samePublicKey(c.PublicKey, signer.Public()) })
	if leafIdx < 0 {
		return Validated{}, ErrKeyMismatch
	}
	others := append(append([]*x509.Certificate(nil), all[:leafIdx]...), all[leafIdx+1:]...)
	chain, ok := orderChain(all[leafIdx], others, now)
	if !ok {
		return Validated{}, invalid("the chain has too many candidate issuers to order")
	}
	p := describe(all[leafIdx], chain)
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
	if anyExpired(others, signer.Public(), now) {
		v.Warnings = append(v.Warnings, "chain_certificate_expired")
	}
	return v, nil
}

// pickLeaf returns the index of the certificate in all that match selects and
// that suits best: valid now, then valid later, then expired; the latest NotAfter
// breaks ties. A file may hold the expired old certificate of a reused key
// before the renewed one. -1 when none matches.
func pickLeaf(all []*x509.Certificate, now time.Time, match func(*x509.Certificate) bool) int {
	rank := func(c *x509.Certificate) int {
		switch {
		case validAt(c, now):
			return 2
		case now.Before(c.NotBefore):
			return 1
		}
		return 0
	}
	best := -1
	for i, c := range all {
		if !match(c) {
			continue
		}
		if best < 0 || rank(c) > rank(all[best]) || (rank(c) == rank(all[best]) && c.NotAfter.After(all[best].NotAfter)) {
			best = i
		}
	}
	return best
}

// anyExpired reports whether one of the uploaded certificates other than the
// leaf has expired. Such an upload is accepted (old bundles carry a harmless
// expired cross-sign) but flagged. An expired certificate of the leaf's own key
// (the old certificate of a reused key, left in the file) is not a chain
// certificate and is not counted.
func anyExpired(others []*x509.Certificate, leafKey crypto.PublicKey, now time.Time) bool {
	for _, c := range others {
		if !now.Before(c.NotAfter) && !samePublicKey(c.PublicKey, leafKey) {
			return true
		}
	}
	return false
}

// checkLeaf applies the signature and validity rules shared by uploads and
// signed signing requests: no weak signature on the leaf or on a chain
// certificate that is not a root, and no expired leaf.
func checkLeaf(p Parsed, now time.Time) error {
	if weakSignature(p.Leaf) {
		return ErrWeak
	}
	for i, c := range p.Chain {
		// A root's own signature is never used to trust it, so it is exempt: the last certificate
		// of the path when it names itself as issuer. (Its signature cannot always be checked: many
		// roots are signed with SHA-1, which Go refuses to verify.) A certificate that names itself
		// but sits inside the path was trusted through its signature and is not exempt. A last
		// certificate that names itself but whose self-signature does not verify gains nothing from
		// the exemption: ChainComplete adds the last certificate as a root only when it is verifiably
		// self-signed, so such a chain counts as incomplete (unless a trusted root issued it).
		root := i == len(p.Chain)-1 && bytes.Equal(c.RawIssuer, c.RawSubject)
		if !root && weakSignature(c) {
			return ErrWeak
		}
	}
	if !now.Before(p.NotAfter) {
		return ErrExpired
	}
	return nil
}

// checkPublicKey accepts RSA of 2048 to 16384 bits and ECDSA on P-256 or P-384.
func checkPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		switch bits := k.N.BitLen(); {
		case bits < 2048:
			return ErrWeak
		case bits > maxRSABits:
			return ErrUnsupportedKey
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
	if err := checkPFXIterations(data); err != nil {
		return nil, nil, err
	}
	key, leaf, cas, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		// A wrong password and a damaged file are indistinguishable to the person
		// uploading, and the message must not carry anything from the file.
		return nil, nil, ErrPFXPassword
	}
	if len(cas)+1 > maxCertificates {
		return nil, nil, invalid("too many certificates")
	}
	for _, c := range append([]*x509.Certificate{leaf}, cas...) {
		if err := checkCertificateKeySize(c); err != nil {
			return nil, nil, err
		}
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
// keys are refused before any decryption is attempted; a second key block is
// refused without being parsed.
func parsePrivateKeyPEM(data []byte) (any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrNoKey
	}
	buf := normalize(data)
	defer clear(buf)
	var (
		blocks []*pem.Block
		parsed any
		found  int
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
		var parse func([]byte) (any, error)
		switch b.Type {
		case "PRIVATE KEY":
			parse = func(d []byte) (any, error) { return x509.ParsePKCS8PrivateKey(d) }
		case "RSA PRIVATE KEY":
			parse = func(d []byte) (any, error) { return x509.ParsePKCS1PrivateKey(d) }
		case "EC PRIVATE KEY":
			parse = func(d []byte) (any, error) { return x509.ParseECPrivateKey(d) }
		default:
			continue // EC PARAMETERS, certificates pasted along, ...
		}
		if found++; found > 1 {
			return nil, invalid("expected exactly one private key")
		}
		if len(b.Bytes) > maxKeyDER {
			return nil, ErrUnsupportedKey // larger than any key Alice accepts: never parsed
		}
		var err error
		if parsed, err = parse(b.Bytes); err != nil {
			return nil, invalid("the private key cannot be parsed")
		}
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
