package tlscert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"slices"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// Upload is a certificate an Administrator uploads: a PEM chain and a PEM key, or a PFX and its password.
// Hosts are the names Alice is reached by (ALICE_TLS_HOSTS and the request's host), for the name_mismatch warning.
type Upload struct {
	CertPEM, KeyPEM, PFX, PFXPassword []byte
	Hosts                             []string
}

// Info describes a certificate without its key.
type Info struct {
	Subject           string
	DNSNames          []string
	IPs               []string
	NotBefore         time.Time
	NotAfter          time.Time
	FingerprintSHA256 string   // lower-case hex of the leaf's DER
	Temporary         bool     // Alice's own self-signed certificate
	Warnings          []string // a customer certificate's name_mismatch, chain_incomplete, expires_soon; nil otherwise
}

// Refusals of an upload (ALC-TLS-0001..0005). They never quote the upload.
var (
	ErrKeyMismatch = errors.New("tlscert: the private key does not belong to the certificate")
	ErrNotValidNow = errors.New("tlscert: the certificate is not valid now or for at least one more day")
	ErrWeakKey     = errors.New("tlscert: the certificate key must be RSA with at least 2048 bits or ECDSA P-256 or P-384")
	ErrPFXPassword = errors.New("tlscert: the PFX password is wrong")
	ErrUnreadable  = errors.New("tlscert: the upload is not a certificate chain with one private key")
)

// Warnings of an accepted upload.
const (
	WarnNameMismatch    = "name_mismatch"
	WarnChainIncomplete = "chain_incomplete"
	WarnExpiresSoon     = "expires_soon"
)

const (
	maxUpload     = 1 << 20
	minValidAhead = 24 * time.Hour
	soonWindow    = 30 * 24 * time.Hour
	minRSABits    = 2048
)

// systemRoots is replaced by tests.
var systemRoots = x509.SystemCertPool

// ParseUpload validates an upload (R43 row 15): exactly one of PEM or PFX, one private key that belongs to one of
// the certificates (the leaf), a leaf valid at now and for at least one more day, an RSA ≥ 2048 or ECDSA P-256/P-384
// key. It returns the pair with the chain ordered leaf first (certificates that are not on the leaf's issuer path
// are dropped) and the warnings name_mismatch, chain_incomplete and expires_soon.
func ParseUpload(u Upload, now time.Time) (tls.Certificate, Info, []string, error) {
	certs, key, err := decode(u)
	if err != nil {
		return tls.Certificate{}, Info{}, nil, err
	}
	leaf := matching(certs, key)
	if leaf == nil {
		return tls.Certificate{}, Info{}, nil, ErrKeyMismatch
	}
	if now.Before(leaf.NotBefore) || now.Add(minValidAhead).After(leaf.NotAfter) {
		return tls.Certificate{}, Info{}, nil, ErrNotValidNow
	}
	if !strongKey(leaf.PublicKey) {
		return tls.Certificate{}, Info{}, nil, ErrWeakKey
	}
	chain := order(leaf, certs)
	c := tls.Certificate{PrivateKey: key, Leaf: leaf}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.Raw)
	}
	info := infoOf(leaf)
	info.Warnings = warnings(chain, u.Hosts, now)
	return c, info, info.Warnings, nil
}

// decode reads the certificates and the one private key of u.
func decode(u Upload) ([]*x509.Certificate, crypto.Signer, error) {
	hasPEM, hasPFX := len(u.CertPEM)+len(u.KeyPEM) > 0, len(u.PFX) > 0
	switch {
	case hasPEM == hasPFX, len(u.CertPEM)+len(u.KeyPEM) > maxUpload, len(u.PFX) > maxUpload:
		return nil, nil, ErrUnreadable
	case hasPFX:
		k, leaf, cas, err := pkcs12.DecodeChain(u.PFX, string(u.PFXPassword))
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, nil, ErrPFXPassword
		}
		signer, ok := k.(crypto.Signer)
		if err != nil || !ok || leaf == nil {
			return nil, nil, ErrUnreadable
		}
		return append([]*x509.Certificate{leaf}, cas...), signer, nil
	}
	var certs []*x509.Certificate
	var key crypto.Signer
	for _, text := range [][]byte{u.CertPEM, u.KeyPEM} {
		rest := text
		for {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				break
			}
			if _, encrypted := b.Headers["Proc-Type"]; encrypted {
				return nil, nil, ErrUnreadable
			}
			if b.Type == "CERTIFICATE" {
				x, err := x509.ParseCertificate(b.Bytes)
				if err != nil {
					return nil, nil, ErrUnreadable
				}
				certs = append(certs, x)
				continue
			}
			k, err := parseKey(b)
			if err != nil || key != nil {
				return nil, nil, ErrUnreadable
			}
			key = k
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, nil, ErrUnreadable
		}
	}
	if len(certs) == 0 {
		return nil, nil, ErrUnreadable
	}
	return certs, key, nil
}

func parseKey(b *pem.Block) (crypto.Signer, error) {
	var (
		k   any
		err error
	)
	switch b.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return nil, ErrUnreadable
	}
	if err != nil {
		return nil, ErrUnreadable
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, ErrUnreadable
	}
	return s, nil
}

// matching returns the certificate whose public key is key's.
func matching(certs []*x509.Certificate, key crypto.Signer) *x509.Certificate {
	if key == nil {
		return nil
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil
	}
	for _, c := range certs {
		if pub.Equal(c.PublicKey) {
			return c
		}
	}
	return nil
}

func strongKey(pub any) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= minRSABits
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384()
	case ed25519.PublicKey:
		return false // browsers do not accept Ed25519 server certificates
	}
	return false
}

// order follows the issuer path from the leaf through the uploaded certificates.
func order(leaf *x509.Certificate, certs []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}
	used := map[*x509.Certificate]bool{leaf: true}
	for cur := leaf; !bytes.Equal(cur.RawIssuer, cur.RawSubject); {
		i := slices.IndexFunc(certs, func(c *x509.Certificate) bool {
			return !used[c] && bytes.Equal(c.RawSubject, cur.RawIssuer) && cur.CheckSignatureFrom(c) == nil
		})
		if i < 0 {
			break
		}
		cur = certs[i]
		used[cur] = true
		chain = append(chain, cur)
	}
	return chain
}

func warnings(chain []*x509.Certificate, hosts []string, now time.Time) []string {
	var w []string
	leaf := chain[0]
	if len(hosts) > 0 && !slices.ContainsFunc(hosts, func(h string) bool { return h != "" && leaf.VerifyHostname(h) == nil }) {
		w = append(w, WarnNameMismatch)
	}
	roots, err := systemRoots()
	if err != nil {
		roots = x509.NewCertPool()
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		w = append(w, WarnChainIncomplete)
	}
	if leaf.NotAfter.Sub(now) < soonWindow {
		w = append(w, WarnExpiresSoon)
	}
	return w
}

func infoOf(leaf *x509.Certificate) Info {
	sum := sha256.Sum256(leaf.Raw)
	in := Info{Subject: leaf.Subject.String(), DNSNames: leaf.DNSNames, NotBefore: leaf.NotBefore.UTC(),
		NotAfter: leaf.NotAfter.UTC(), FingerprintSHA256: hex.EncodeToString(sum[:])} // Temporary is set by load (isTemporary)
	for _, ip := range leaf.IPAddresses {
		in.IPs = append(in.IPs, ip.String())
	}
	return in
}
