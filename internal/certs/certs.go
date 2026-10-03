// Package certs is the pure validation core for certificates: it parses PEM
// chains (discovered files and uploads), checks keys, PFX files and signing
// requests, and refuses weak or unsupported material. It touches no database,
// no network and no file.
package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxInputSize bounds every PEM field and a PFX file.
const MaxInputSize = 256 << 10

// maxRSABits is the largest RSA modulus Alice accepts: OpenSSL (and so Nginx) refuses larger
// ones, and parsing a private key costs roughly the square of its size.
const maxRSABits = 16384

// maxKeyDER bounds a private key block before it is parsed: a 16384-bit RSA key in PKCS#8 is about
// 9.4 KiB, every key Alice accepts is smaller.
const maxKeyDER = 16 << 10

// maxCertificates bounds how many certificates one input may carry, so that
// ordering a hostile chain stays cheap.
const maxCertificates = 32

// Refusals. Callers match them with errors.Is; none of them carries input.
var (
	ErrInvalid        = errors.New("certs: not a certificate Alice can read")
	ErrKeyMismatch    = errors.New("certs: the private key does not belong to any of the certificates")
	ErrExpired        = errors.New("certs: the certificate has expired")
	ErrKeyEncrypted   = errors.New("certs: the private key is protected with a password")
	ErrPFXPassword    = errors.New("certs: the PFX password is wrong or the file is damaged")
	ErrWeak           = errors.New("certs: weak key or signature")
	ErrUnsupportedKey = errors.New("certs: only RSA (2048 to 16384 bits) and ECDSA (P-256, P-384) keys are supported")
	ErrNoKey          = errors.New("certs: no private key was given")
	ErrTooLarge       = errors.New("certs: the input is larger than 256 KiB")
	ErrCSRMismatch    = errors.New("certs: the certificate was not issued for this signing request's key")
)

// Parsed describes a leaf certificate and the certificates after it.
type Parsed struct {
	Leaf            *x509.Certificate
	Chain           []*x509.Certificate // after the leaf, in issuing order
	PEMChain        string              // leaf then chain, re-encoded as CERTIFICATE blocks
	Fingerprint     string              // hex SHA-256 of the leaf DER
	Algorithm       string              // "rsa" | "ecdsa" | "ed25519" | "other"
	Bits            int                 // RSA modulus bits, ECDSA curve bits (256, 384)
	PublicKeySHA256 string              // hex SHA-256 of the leaf's PKIX public key
	SubjectCN       string
	Subject, Issuer string   // RFC 2253 strings
	Serial          string   // the serial number as upper-case hex without separators
	SANs            []string // DNS names then IP addresses, as text
	NotBefore       time.Time
	NotAfter        time.Time
	SelfSigned      bool
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalid, reason) }

// normalize strips a UTF-8 byte order mark and turns CRLF into LF. It always
// returns a copy.
func normalize(data []byte) []byte {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

// certificatesOf returns every CERTIFICATE block of data in file order.
func certificatesOf(data []byte) ([]*x509.Certificate, error) {
	if len(data) > MaxInputSize {
		return nil, ErrTooLarge
	}
	var out []*x509.Certificate
	// The field may also hold a pasted private key: the normalised copy and every block that is not
	// a certificate are cleared (a parsed certificate keeps only its own decoded block).
	buf := normalize(data)
	defer clear(buf)
	for rest := buf; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			clear(b.Bytes)
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, invalid("a certificate block cannot be parsed")
		}
		if len(out) == maxCertificates {
			return nil, invalid("too many certificates")
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, invalid("no certificate found")
	}
	return out, nil
}

// ContainsPrivateKey reports whether data has a PEM private key block (PRIVATE KEY, RSA/EC/
// ENCRYPTED PRIVATE KEY, …). It reads only the BEGIN lines: nothing is decoded or copied. It takes
// a string so a caller holding pasted text (which may be a key) does not make a byte copy of it
// that nobody clears.
func ContainsPrivateKey(data string) bool {
	const begin, dashes = "-----BEGIN ", "-----"
	for rest := data; ; {
		i := strings.Index(rest, begin)
		if i < 0 {
			return false
		}
		rest = rest[i+len(begin):]
		end := strings.Index(rest, dashes)
		if end < 0 {
			return false
		}
		typ := rest[:end]
		if typ == "PRIVATE KEY" || strings.HasSuffix(typ, " PRIVATE KEY") {
			return true
		}
		rest = rest[end:]
	}
}

// ParseChainPEM reads the CERTIFICATE blocks of data and ignores every other
// block. The first certificate is the leaf; the rest keep their file order.
func ParseChainPEM(data []byte) (Parsed, error) {
	all, err := certificatesOf(data)
	if err != nil {
		return Parsed{}, err
	}
	return describe(all[0], all[1:]), nil
}

func describe(leaf *x509.Certificate, chain []*x509.Certificate) Parsed {
	p := Parsed{
		Leaf:        leaf,
		Chain:       chain,
		Fingerprint: fingerprint(leaf.Raw),
		SubjectCN:   leaf.Subject.CommonName,
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		Serial:      fmt.Sprintf("%X", leaf.SerialNumber),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		SelfSigned:  selfSigned(leaf),
	}
	p.Algorithm, p.Bits = algorithmOf(leaf.PublicKey)
	spki := leaf.RawSubjectPublicKeyInfo
	if der, err := x509.MarshalPKIXPublicKey(leaf.PublicKey); err == nil {
		spki = der // canonical, and what KeyInfoOf hashes
	}
	p.PublicKeySHA256 = fingerprint(spki)
	p.SANs = append(p.SANs, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		p.SANs = append(p.SANs, ip.String())
	}
	var buf bytes.Buffer
	for _, c := range append([]*x509.Certificate{leaf}, chain...) {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}) // a bytes.Buffer never fails
	}
	p.PEMChain = buf.String()
	return p
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func algorithmOf(pub any) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "rsa", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ecdsa", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "ed25519", 256
	}
	return "other", 0
}

// selfSigned reports whether c names itself as issuer and carries a valid
// signature of its own key. It checks the signature directly: CheckSignatureFrom
// would refuse a self-signed leaf that is not marked as a CA.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}
