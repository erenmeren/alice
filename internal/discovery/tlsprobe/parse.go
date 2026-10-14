package tlsprobe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"alice/internal/platform/validate"
)

// Bounds of what ParsePresentedChain keeps of one certificate (the discovery_certificates CHECKs):
// at most MaxSANs subject alternative names (DNS names, then IP addresses), each at most
// maxSANBytes bytes, so the stored list stays under 64 KiB; names at most maxNameBytes bytes.
const (
	MaxSANs      = 256
	maxSANBytes  = 253
	maxNameBytes = 1024
)

// maxSignatureCheckBits: the self-signed check verifies a signature only with an RSA key of at most
// this many bits (the bound internal/certs applies before it checks any signature); a larger key is
// never used and the certificate counts as not self-signed.
const maxSignatureCheckBits = 16384

// Certificate is one parsed certificate of a presented chain. Nothing in it says the certificate is
// valid or trusted: it describes what was presented.
type Certificate struct {
	Raw                []byte    // the DER as presented
	FingerprintSHA256  string    // lower-case hex SHA-256 of the DER (certificates.fingerprint_sha256)
	SubjectCN          string    // valid UTF-8 without NUL, at most 1024 bytes
	IssuerCN           string    // likewise
	DNSNames           []string  // capped with IPAddresses at MaxSANs, each at most 253 bytes
	IPAddresses        []string  // as text
	SANsTruncated      bool      // the certificate has more SANs (or longer ones) than are kept
	NotBefore          time.Time // UTC
	NotAfter           time.Time // UTC
	KeyAlgorithm       string    // "rsa" | "ecdsa" | "ed25519" | "other" (internal/certs' names)
	KeyBits            int       // RSA modulus bits, ECDSA curve bits, 256 for Ed25519, 0 otherwise
	SelfSigned         bool      // issuer = subject and the certificate's own key verifies its signature
	IsCA               bool      // basic constraints CA
	Serial             string    // upper-case hex without separators (internal/certs' format)
	SignatureAlgorithm string    // Go's name, e.g. "SHA256-RSA", "SHA1-RSA", "ECDSA-SHA256"
}

// Chain is a parsed presented chain, leaf first, in the order presented.
type Chain struct {
	Certificates []Certificate
}

// Leaf is the first certificate.
func (c Chain) Leaf() Certificate { return c.Certificates[0] }

// ParsePresentedChain parses a chain CapturePresentedChain returned (or any untrusted DER list). An
// empty chain or a certificate that cannot be parsed (or whose validity dates are outside the years
// 1 to 9999 or reversed) is malformed; a chain over the limits is chain_too_large, checked before
// anything is parsed. It never panics and keeps no more than the bounds above.
func ParsePresentedChain(der [][]byte) (Chain, error) {
	if len(der) == 0 {
		return Chain{}, &Error{Code: CodeMalformed}
	}
	if !chainWithinLimits(der) {
		return Chain{}, &Error{Code: CodeChainTooLarge}
	}
	out := Chain{Certificates: make([]Certificate, 0, len(der))}
	for _, d := range der {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return Chain{}, &Error{Code: CodeMalformed}
		}
		if !validate.CertificateTimes(c.NotBefore, c.NotAfter) || c.NotAfter.Before(c.NotBefore) {
			return Chain{}, &Error{Code: CodeMalformed}
		}
		out.Certificates = append(out.Certificates, describe(c))
	}
	return out, nil
}

func describe(c *x509.Certificate) Certificate {
	sum := sha256.Sum256(c.Raw)
	out := Certificate{
		Raw:                slices.Clone(c.Raw),
		FingerprintSHA256:  hex.EncodeToString(sum[:]),
		SubjectCN:          cleanText(c.Subject.CommonName, maxNameBytes),
		IssuerCN:           cleanText(c.Issuer.CommonName, maxNameBytes),
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
		IsCA:               c.IsCA,
		Serial:             fmt.Sprintf("%X", c.SerialNumber),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
	}
	out.KeyAlgorithm, out.KeyBits = keyAlgorithm(c.PublicKey)
	out.SelfSigned = selfSigned(c)
	kept := 0
	keep := func(s string) (string, bool) {
		if kept == MaxSANs {
			out.SANsTruncated = true
			return "", false
		}
		kept++
		clean := cleanText(s, maxSANBytes)
		if clean != s {
			out.SANsTruncated = true
		}
		return clean, true
	}
	for _, n := range c.DNSNames {
		if s, ok := keep(n); ok {
			out.DNSNames = append(out.DNSNames, s)
		}
	}
	for _, ip := range c.IPAddresses {
		if s, ok := keep(ip.String()); ok {
			out.IPAddresses = append(out.IPAddresses, s)
		}
	}
	return out
}

// keyAlgorithm names a public key as internal/certs does.
func keyAlgorithm(pub any) (string, int) {
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

// selfSigned is internal/certs' definition: the certificate names itself as issuer and carries a
// valid signature of its own key (checked directly: CheckSignatureFrom would refuse a self-signed leaf
// that is not marked as a CA). An RSA key over maxSignatureCheckBits is not used.
func selfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	if k, ok := c.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() > maxSignatureCheckBits {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// cleanText makes s storable text: invalid UTF-8 and NUL become U+FFFD, and the result is cut to at
// most limit bytes on a character boundary.
func cleanText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "�")
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
