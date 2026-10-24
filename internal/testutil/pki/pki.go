// Package pki generates certificates, keys, PFX files and signing requests at
// test time, so no key or certificate fixture is ever committed. Every crypto
// failure panics: this is a test helper and nothing here touches the disk.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // SHA-384 and SHA-512 for IssueRawValidity
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// KeyType names a key algorithm and size.
type KeyType string

// Key types. RSA1024, ECDSA521 and Ed25519 exist for refusal tests.
const (
	RSA1024  KeyType = "rsa1024" // weak, for refusal tests
	RSA2048  KeyType = "rsa2048"
	RSA3072  KeyType = "rsa3072"
	RSA4096  KeyType = "rsa4096"
	ECDSA256 KeyType = "ecdsa256"
	ECDSA384 KeyType = "ecdsa384"
	ECDSA521 KeyType = "ecdsa521" // unsupported curve
	Ed25519  KeyType = "ed25519"  // unsupported key type
)

// CA is a root and an intermediate signed by it.
type CA struct {
	Root, Intermediate       *x509.Certificate
	RootKey, IntermediateKey crypto.Signer
	RootPEM, IntermediatePEM []byte
}

// Opts describes a leaf certificate.
type Opts struct {
	CommonName string
	SANs       []string
	KeyType    KeyType       // default ECDSA256
	NotBefore  time.Time     // default now-1h
	NotAfter   time.Time     // default now+90d
	Key        crypto.Signer // reuse a key (CSR completion tests)
	// The revocation addresses a leaf names (revocation check tests, R64): the OCSP responders (AIA) and the CRL
	// distribution points.
	OCSPServer            []string
	CRLDistributionPoints []string
}

// Leaf is an issued certificate with its key.
type Leaf struct {
	Cert         *x509.Certificate
	Key          crypto.Signer
	CertPEM      []byte // leaf only
	FullchainPEM []byte // leaf + intermediate
	KeyPEM       []byte // PKCS#8 "PRIVATE KEY"
}

func must[T any](v T, err error) T {
	if err != nil {
		panic("pki: " + err.Error())
	}
	return v
}

// NewKey generates a key of the given type.
func NewKey(kt KeyType) crypto.Signer {
	switch kt {
	case RSA1024:
		return must(rsa.GenerateKey(rand.Reader, 1024)) //nolint:gosec // G403: a deliberately weak key for refusal tests
	case RSA2048:
		return must(rsa.GenerateKey(rand.Reader, 2048))
	case RSA3072:
		return must(rsa.GenerateKey(rand.Reader, 3072))
	case RSA4096:
		return must(rsa.GenerateKey(rand.Reader, 4096))
	case ECDSA384:
		return must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	case ECDSA521:
		return must(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
	case Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return must(priv, err)
	case ECDSA256, "":
		return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	}
	panic("pki: unknown key type " + string(kt))
}

func serial() *big.Int {
	return must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)))
}

func ski(pub crypto.PublicKey) []byte {
	der := must(x509.MarshalPKIXPublicKey(pub))
	sum := sha256.Sum256(der)
	return sum[:20]
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func sign(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	der := must(x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer))
	return must(x509.ParseCertificate(der))
}

// NewCA builds a root and an intermediate, both valid from now-1h.
func NewCA(name string, kt KeyType, now time.Time) *CA {
	rootKey, interKey := NewKey(kt), NewKey(kt)
	start := now.Add(-time.Hour)
	rootTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name + " Root"},
		NotBefore:             start,
		NotAfter:              start.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski(rootKey.Public()),
	}
	root := sign(rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	interTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name + " Intermediate"},
		NotBefore:             start,
		NotAfter:              start.AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski(interKey.Public()),
	}
	inter := sign(interTmpl, root, interKey.Public(), rootKey)
	return &CA{Root: root, Intermediate: inter, RootKey: rootKey, IntermediateKey: interKey,
		RootPEM: pemOf(root), IntermediatePEM: pemOf(inter)}
}

func leafTemplate(o Opts, pub crypto.PublicKey, now time.Time) *x509.Certificate {
	nb, na := o.NotBefore, o.NotAfter
	if nb.IsZero() {
		nb = now.Add(-time.Hour)
	}
	if na.IsZero() {
		na = now.AddDate(0, 0, 90)
	}
	usage := x509.KeyUsageDigitalSignature
	if _, ok := pub.(*rsa.PublicKey); ok {
		usage |= x509.KeyUsageKeyEncipherment
	}
	t := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: o.CommonName},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     usage,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId: ski(pub),

		OCSPServer:            o.OCSPServer,
		CRLDistributionPoints: o.CRLDistributionPoints,
	}
	for _, s := range o.SANs {
		if ip := net.ParseIP(s); ip != nil {
			t.IPAddresses = append(t.IPAddresses, ip)
		} else {
			t.DNSNames = append(t.DNSNames, s)
		}
	}
	return t
}

// Issue signs a leaf with the intermediate.
func (ca *CA) Issue(o Opts, now time.Time) Leaf {
	key := o.Key
	if key == nil {
		key = NewKey(o.KeyType)
	}
	cert := sign(leafTemplate(o, key.Public(), now), ca.Intermediate, key.Public(), ca.IntermediateKey)
	return newLeaf(cert, key, ca.IntermediatePEM)
}

// IssueForCSR signs a leaf for a signing request with the intermediate: the request's public key,
// common name and DNS names. The requester holds the key, so Key is nil and KeyPEM empty.
func (ca *CA) IssueForCSR(r *x509.CertificateRequest, now time.Time) Leaf {
	cert := sign(leafTemplate(Opts{CommonName: r.Subject.CommonName, SANs: r.DNSNames}, r.PublicKey, now), ca.Intermediate,
		r.PublicKey, ca.IntermediateKey)
	certPEM := pemOf(cert)
	return Leaf{Cert: cert, CertPEM: certPEM, FullchainPEM: append(append([]byte{}, certPEM...), ca.IntermediatePEM...)}
}

// SelfSigned returns a self-signed leaf.
func SelfSigned(cn string, kt KeyType, now time.Time) Leaf {
	key := NewKey(kt)
	tmpl := leafTemplate(Opts{CommonName: cn, SANs: []string{cn}}, key.Public(), now)
	return newLeaf(sign(tmpl, tmpl, key.Public(), key), key, nil)
}

func newLeaf(cert *x509.Certificate, key crypto.Signer, chainPEM []byte) Leaf {
	certPEM := pemOf(cert)
	full := append(append([]byte{}, certPEM...), chainPEM...)
	return Leaf{
		Cert: cert, Key: key, CertPEM: certPEM, FullchainPEM: full,
		KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: must(x509.MarshalPKCS8PrivateKey(key))}),
	}
}

// KeyPEMPKCS1 encodes an RSA key as "RSA PRIVATE KEY".
func KeyPEMPKCS1(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// KeyPEMSEC1 encodes an ECDSA key as "EC PRIVATE KEY".
func KeyPEMSEC1(k *ecdsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: must(x509.MarshalECPrivateKey(k))})
}

// EncryptedKeyPEM returns a PEM block marked as legacy-encrypted. The content
// is random: Alice must refuse it before trying to decrypt.
func EncryptedKeyPEM(_ Leaf) []byte {
	body := make([]byte, 256)
	must(rand.Read(body))
	return pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00112233445566778899AABBCCDDEEFF"},
		Bytes:   body,
	})
}

// PFX encodes the leaf, its key and the intermediate with the Modern profile.
func PFX(l Leaf, ca *CA, password string) []byte {
	return must(pkcs12.Modern.Encode(l.Key, l.Cert, []*x509.Certificate{ca.Intermediate}, password))
}

// CSRFor builds and parses a signing request.
func CSRFor(cn string, sans []string, key crypto.Signer) *x509.CertificateRequest {
	der := must(x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: sans,
	}, key))
	return must(x509.ParseCertificateRequest(der))
}

// Fingerprint is the hex SHA-256 of the certificate DER.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// GeneralizedTime is a raw X.509 GeneralizedTime for IssueRawValidity, e.g. "99991231235959-2359"
// (a zone offset Go's parser accepts, though RFC 5280 asks for "Z").
func GeneralizedTime(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagGeneralizedTime, Bytes: []byte(s)}
}

// UTCTime is a raw X.509 UTCTime for IssueRawValidity, e.g. "650101000000Z" (1965).
func UTCTime(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTCTime, Bytes: []byte(s)}
}

// IssueRawValidity is Issue with the validity written as the given raw times. x509.CreateCertificate
// always writes UTC, so the leaf's TBSCertificate is re-encoded with the new validity and signed again
// with the intermediate, using the hash of the signature algorithm Issue chose.
func (ca *CA) IssueRawValidity(o Opts, notBefore, notAfter asn1.RawValue, now time.Time) Leaf {
	leaf := ca.Issue(o, now)
	var outer struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	must(asn1.Unmarshal(leaf.Cert.Raw, &outer))
	var fields []asn1.RawValue
	must(asn1.Unmarshal(outer.TBS.FullBytes, &fields))
	if len(fields) != 8 { // version, serial, signature, issuer, validity, subject, key, extensions
		panic("pki: unexpected TBSCertificate layout")
	}
	fields[4] = asn1.RawValue{FullBytes: must(asn1.Marshal([]asn1.RawValue{notBefore, notAfter}))}
	tbs := must(asn1.Marshal(fields))
	h := crypto.SHA256
	switch leaf.Cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		h = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		h = crypto.SHA512
	}
	d := h.New()
	_, _ = d.Write(tbs) // a hash never fails
	sig := must(ca.IntermediateKey.Sign(rand.Reader, d.Sum(nil), h))
	der := must(asn1.Marshal(struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, outer.SigAlg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}}))
	return newLeaf(must(x509.ParseCertificate(der)), leaf.Key, ca.IntermediatePEM)
}
