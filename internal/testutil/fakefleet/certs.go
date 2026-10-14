package fakefleet

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: the SHA-1 server signs its leaf with SHA-1 on purpose
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"alice/internal/testutil/pki"
)

// material is what one server presents.
type material struct {
	chain [][]byte                    // the default chain (nil: a raw server that presents none)
	cert  *tls.Certificate            // the default certificate
	bySNI map[string]*tls.Certificate // lower-case SNI name -> certificate
	names []string                    // the SNI names, sorted
	tls   *tls.Config                 // nil for raw servers
}

// materials builds certificates lazily: RSA keys and the many-name certificates only for the kinds served.
type materials struct {
	ca  *pki.CA
	o   Options
	now time.Time

	legacy    *legacyCA // RSA intermediate for the SHA-1 leaf
	sharedKey crypto.Signer
}

type legacyCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newMaterials(ca *pki.CA, o Options) *materials { return &materials{ca: ca, o: o, now: o.Now} }

func (m *materials) leaf(name string, mod func(*pki.Opts)) pki.Leaf {
	o := pki.Opts{CommonName: name, SANs: []string{name}, Key: m.key()}
	if mod != nil {
		mod(&o)
	}
	return m.ca.Issue(o, m.now)
}

// key is one ECDSA key shared by the leaves (the fleet tests certificates, not keys).
func (m *materials) key() crypto.Signer {
	if m.sharedKey == nil {
		m.sharedKey = pki.NewKey(pki.ECDSA256)
	}
	return m.sharedKey
}

func certOf(chain [][]byte, key crypto.Signer, leaf *x509.Certificate) *tls.Certificate {
	return &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}
}

func (m *materials) withIntermediate(l pki.Leaf) *tls.Certificate {
	return certOf([][]byte{l.Cert.Raw, m.ca.Intermediate.Raw}, l.Key, l.Cert)
}

func baseConfig(c *tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{*c}, MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true}
}

// build returns the material of one kind.
func (m *materials) build(k Kind, host string) (*material, error) {
	day := 24 * time.Hour
	single := func(c *tls.Certificate, mod func(*tls.Config)) *material {
		cfg := baseConfig(c)
		if mod != nil {
			mod(cfg)
		}
		return &material{chain: c.Certificate, cert: c, tls: cfg}
	}
	switch k {
	case KindValid:
		return single(m.withIntermediate(m.leaf(host, nil)), nil), nil
	case KindExpired:
		return single(m.withIntermediate(m.leaf(host, func(o *pki.Opts) {
			o.NotBefore, o.NotAfter = m.now.Add(-90*day), m.now.Add(-day)
		})), nil), nil
	case KindNotYetValid:
		return single(m.withIntermediate(m.leaf(host, func(o *pki.Opts) {
			o.NotBefore, o.NotAfter = m.now.Add(day), m.now.Add(90*day)
		})), nil), nil
	case KindSelfSigned:
		l := pki.SelfSigned(host, pki.ECDSA256, m.now)
		return single(certOf([][]byte{l.Cert.Raw}, l.Key, l.Cert), nil), nil
	case KindWrongOrder:
		l := m.leaf(host, nil)
		return single(certOf([][]byte{l.Cert.Raw, m.ca.Root.Raw, m.ca.Intermediate.Raw}, l.Key, l.Cert), nil), nil
	case KindMissingIntermediate:
		l := m.leaf(host, nil)
		return single(certOf([][]byte{l.Cert.Raw}, l.Key, l.Cert), nil), nil
	case KindSNI:
		names := []string{"alpha.sni." + m.o.Domain, "beta.sni." + m.o.Domain}
		return m.sniMaterial(host, names), nil
	case KindManySNI:
		names := make([]string, m.o.ManySNINames)
		for i := range names {
			names[i] = fmt.Sprintf("sni-%03d.%s", i, host)
		}
		return m.sniMaterial(host, names), nil
	case KindTLS10, KindTLS12, KindTLS13:
		v := map[Kind]uint16{KindTLS10: tls.VersionTLS10, KindTLS12: tls.VersionTLS12, KindTLS13: tls.VersionTLS13}[k]
		return single(m.withIntermediate(m.leaf(host, nil)), func(c *tls.Config) { c.MinVersion, c.MaxVersion = v, v }), nil
	case KindRSAKeyExchange:
		l := m.leaf(host, func(o *pki.Opts) { o.Key = pki.NewKey(pki.RSA2048) })
		return single(m.withIntermediate(l), func(c *tls.Config) {
			c.MaxVersion = tls.VersionTLS12
			c.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA}
		}), nil
	case KindSHA1:
		c, err := m.sha1Leaf(host)
		if err != nil {
			return nil, err
		}
		return single(c, nil), nil
	case KindHugeChain:
		l := m.leaf(host, nil)
		chain := make([][]byte, m.o.HugeChainCerts)
		chain[0] = l.Cert.Raw
		for i := 1; i < len(chain); i++ {
			chain[i] = m.ca.Intermediate.Raw // the same bytes, shared: memory stays small
		}
		// TLS 1.2: the Certificate message is in clear text, so a test can count what was sent.
		return single(certOf(chain, l.Key, l.Cert), func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }), nil
	case KindMalformed:
		c, err := m.negativeSerialLeaf(host)
		if err != nil {
			return nil, err
		}
		return single(c, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }), nil
	}
	// The raw kinds (slow-loris, giant-chain, reset, plaintext) present no certificate.
	return &material{}, nil
}

func (m *materials) sniMaterial(host string, names []string) *material {
	def := m.withIntermediate(m.leaf(host, nil))
	mat := &material{chain: def.Certificate, cert: def, bySNI: map[string]*tls.Certificate{}, names: names}
	for _, n := range names {
		mat.bySNI[n] = m.withIntermediate(m.leaf(n, nil))
	}
	cfg := baseConfig(def)
	cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c, ok := mat.bySNI[lowerASCII(h.ServerName)]; ok {
			return c, nil
		}
		return def, nil
	}
	mat.tls = cfg
	return mat
}

var (
	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// sha1Leaf issues the leaf from an RSA intermediate (signed by the fleet root) with sha1WithRSAEncryption.
// x509.CreateCertificate is not trusted to write SHA-1, so the leaf is re-signed by hand.
func (m *materials) sha1Leaf(host string) (*tls.Certificate, error) {
	if m.legacy == nil {
		key, ok := pki.NewKey(pki.RSA2048).(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("fakefleet: not an RSA key")
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1001), Subject: pkix.Name{CommonName: "Fakefleet Legacy SHA-1 Intermediate"},
			NotBefore: m.now.Add(-time.Hour), NotAfter: m.now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca.Root, key.Public(), m.ca.RootKey)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		m.legacy = &legacyCA{cert: cert, key: key}
	}
	l := m.leaf(host, nil)
	der, err := resign(l.Cert.Raw, m.legacy.cert, oidSHA1WithRSA, func(tbs []byte) ([]byte, error) {
		sum := sha1.Sum(tbs) //nolint:gosec // G401: SHA-1 on purpose
		return rsa.SignPKCS1v15(rand.Reader, m.legacy.key, crypto.SHA1, sum[:])
	}, nil)
	if err != nil {
		return nil, err
	}
	return certOf([][]byte{der, m.legacy.cert.Raw}, l.Key, nil), nil
}

// negativeSerialLeaf is a leaf whose serial number is -4242 (RFC 5280 requires a positive one), signed
// correctly by the intermediate. Go's parser refuses it; the server presents it raw.
func (m *materials) negativeSerialLeaf(host string) (*tls.Certificate, error) {
	l := m.leaf(host, nil)
	der, err := resign(l.Cert.Raw, m.ca.Intermediate, oidSHA256WithECDSA, func(tbs []byte) ([]byte, error) {
		sum := sha256.Sum256(tbs)
		return m.ca.IntermediateKey.Sign(rand.Reader, sum[:], crypto.SHA256)
	}, func(fields []asn1.RawValue) error {
		neg, err := asn1.Marshal(big.NewInt(-4242))
		if err != nil {
			return err
		}
		fields[1] = asn1.RawValue{FullBytes: neg}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return certOf([][]byte{der, m.ca.Intermediate.Raw}, l.Key, nil), nil
}

// resign rewrites a certificate: its issuer becomes issuer's subject, its signature algorithm sigAlg,
// mod may change the TBSCertificate fields, and sign signs the new TBSCertificate.
func resign(der []byte, issuer *x509.Certificate, sigAlg asn1.ObjectIdentifier, sign func([]byte) ([]byte, error),
	mod func([]asn1.RawValue) error) ([]byte, error) {
	var outer struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, err
	}
	var fields []asn1.RawValue
	if _, err := asn1.Unmarshal(outer.TBS.FullBytes, &fields); err != nil {
		return nil, err
	}
	if len(fields) != 8 { // version, serial, signature, issuer, validity, subject, key, extensions
		return nil, fmt.Errorf("fakefleet: unexpected TBSCertificate layout")
	}
	alg := pkix.AlgorithmIdentifier{Algorithm: sigAlg} // ECDSA identifiers carry no parameters
	if sigAlg.Equal(oidSHA1WithRSA) {
		alg.Parameters = asn1.NullRawValue // RSA ones carry NULL
	}
	algDER, err := asn1.Marshal(alg)
	if err != nil {
		return nil, err
	}
	fields[2] = asn1.RawValue{FullBytes: algDER}
	fields[3] = asn1.RawValue{FullBytes: issuer.RawSubject}
	if mod != nil {
		if err := mod(fields); err != nil {
			return nil, err
		}
	}
	tbs, err := asn1.Marshal(fields)
	if err != nil {
		return nil, err
	}
	sig, err := sign(tbs)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, asn1.RawValue{FullBytes: algDER}, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
