package fakeacme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: a key identifier (RFC 5280 4.2.1.2 method 1), not a security hash
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"alice/internal/platform/clock"
)

// authority is a CA certificate with its key.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// pki holds the fake's two independent trust chains: the TLS CA (signs the server certificate; its
// certificate is the one Alice trusts) and the issuing chain (root, intermediate and the
// intermediates of alternate chains) the leaves it issues come from.
type pki struct {
	tlsCA   *authority
	tlsCert tls.Certificate
	root    *authority
	inter   *authority
	alts    []*authority
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func serialNumber() *big.Int {
	b := randBytes(16)
	b[0] &= 0x7f // positive and below 2^127: the DER content equals Bytes()
	b[0] |= 0x10 // never a short serial
	return new(big.Int).SetBytes(b)
}

func keyID(pub *ecdsa.PublicKey) []byte {
	raw, _ := pub.Bytes() // a P-256 key built here always encodes
	sum := sha1.Sum(raw)  //nolint:gosec // G401: a key identifier, not a security hash
	return sum[:]
}

// newAuthority creates a CA certificate, self-signed when parent is nil.
func newAuthority(cn string, parent *authority, now time.Time, life time.Duration) (*authority, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber(), Subject: pkix.Name{CommonName: cn, Organization: []string{"Alice fake ACME"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(life),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		SubjectKeyId: keyID(&key.PublicKey),
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: key}, nil
}

func newPKI(now time.Time, alternates int, names []string) (*pki, error) {
	p := &pki{}
	var err error
	const tenYears = 10 * 365 * 24 * time.Hour
	if p.tlsCA, err = newAuthority("Alice fake ACME TLS CA", nil, clock.Real{}.Now(), tenYears); err != nil {
		return nil, err
	}
	if p.root, err = newAuthority("Alice fake ACME root", nil, now, tenYears); err != nil {
		return nil, err
	}
	if p.inter, err = newAuthority("Alice fake ACME intermediate", p.root, now, tenYears); err != nil {
		return nil, err
	}
	for i := range alternates {
		a, err := newAuthority(fmt.Sprintf("Alice fake ACME alternate intermediate %d", i+1), p.root, now, tenYears)
		if err != nil {
			return nil, err
		}
		p.alts = append(p.alts, a)
	}
	return p, p.makeTLS(names)
}

// makeTLS issues the server certificate from the TLS CA on the real clock (the TLS client under
// test uses it).
func (p *pki) makeTLS(names []string) error {
	key, err := newKey()
	if err != nil {
		return err
	}
	now := clock.Real{}.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber(), Subject: pkix.Name{CommonName: "fakeacme"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.tlsCA.cert, &key.PublicKey, p.tlsCA.key)
	if err != nil {
		return err
	}
	p.tlsCert = tls.Certificate{Certificate: [][]byte{der, p.tlsCA.cert.Raw}, PrivateKey: key}
	return nil
}

func (p *pki) clientTLS() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(p.tlsCA.cert)
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func (p *pki) tlsCAPEM() []byte { return pemOf(p.tlsCA.cert) }
func (p *pki) rootPEM() []byte  { return pemOf(p.root.cert) }

// issued is a leaf with the chains it can be downloaded as (index 0 is the default chain).
type issued struct {
	id      string
	account string
	leaf    *x509.Certificate
	chains  [][]byte
	// revokedAt and reason: the certificate was revoked (RFC 8555 section 7.6) at that time for that RFC 5280 reason.
	revokedAt time.Time
	reason    int
}

// issue signs a leaf for the CSR's key and names. The chains are leaf+intermediate (the root is
// left out, as public CAs do), one per intermediate.
func (p *pki) issue(names []string, pub any, now time.Time, life time.Duration) (*issued, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber(), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(life),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    names, BasicConstraintsValid: true,
	}
	if len(names) > 0 {
		tmpl.Subject = pkix.Name{CommonName: names[0]}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.inter.cert, pub, p.inter.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	out := &issued{leaf: leaf}
	for _, ca := range append([]*authority{p.inter}, p.alts...) {
		out.chains = append(out.chains, append(pemOf(leaf), pemOf(ca.cert)...))
	}
	return out, nil
}

// ariID is the RFC 9773 certificate identifier: base64url(AKI keyIdentifier) "." base64url(serial).
func ariID(c *x509.Certificate) string {
	return b64(c.AuthorityKeyId) + "." + b64(c.SerialNumber.Bytes())
}
