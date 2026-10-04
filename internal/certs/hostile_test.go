package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pki"
)

// selfSignedLookingRSA is a certificate whose subject equals its issuer, whose public key is an RSA
// "key" with a modulus of modBytes bytes and e = 2^31-1 (the largest exponent Go verifies with), marked as a CA,
// and whose signature has the modulus's length, so that a self-signature check is attempted with
// that key. No private key is needed (adapted from the independent audit of 2026-10-04, AUD-04).
func selfSignedLookingRSA(t *testing.T, modBytes int, subject string) []byte {
	t.Helper()
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	name := pkix.Name{CommonName: subject}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: name, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"big.example.test"}, IsCA: true, BasicConstraintsValid: true}
	parent := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: name}
	n := make([]byte, modBytes)
	_, _ = rand.Read(n)
	n[0] |= 0x80
	n[len(n)-1] |= 1
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 1<<31 - 1}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	sig := make([]byte, modBytes)
	_, _ = rand.Read(sig)
	sig[0] = 0 // below the modulus
	var outer struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	out, err := asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: c.RawTBSCertificate}, outer.Alg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: out})
}

// AUD-04(b): a certificate file found on a server is parsed with the same RSA bound as an upload,
// before any signature is verified with its key. A 753,664-bit modulus (the largest that fits the
// helper's 256 KiB file bound) used to cost about 22 s of CPU per file; it is now refused at once,
// as the leaf and as a chain certificate, by every parser.
func TestHugeRSACertificateIsRefusedBeforeAnySignatureCheck(t *testing.T) {
	huge := selfSignedLookingRSA(t, 92<<10, "big.example.test")
	require.LessOrEqual(t, len(huge), MaxInputSize, "fits the helper's file bound")
	leaf := pki.NewCA("Hostile", pki.ECDSA256, now).Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	asChain := append(append([]byte{}, leaf.CertPEM...), huge...)

	start := time.Now()
	_, err := ParseChainPEM(huge)
	require.ErrorIs(t, err, ErrUnsupportedKey)
	_, err = ParseServedChain(huge, now)
	require.ErrorIs(t, err, ErrUnsupportedKey)
	_, err = ParseServedChain(asChain, now)
	require.ErrorIs(t, err, ErrUnsupportedKey, "a chain certificate with such a key is refused too")
	_, err = ValidateUpload(Upload{CertificatePEM: asChain, PrivateKeyPEM: leaf.KeyPEM}, now, nil)
	require.ErrorIs(t, err, ErrUnsupportedKey)
	assert.Less(t, time.Since(start), 2*time.Second, "no signature was checked with the huge key")
}

// sameNameChain is n CA certificates that all name "Same" as subject and issuer, with two keys that
// alternate: certificate i has key i%2 and is signed by the other key, so each is a valid issuer of
// every certificate of the other key, and none is self-signed (W2 review, minor 2: about 950
// signature checks before the bound).
func sameNameChain(t *testing.T, n int) []*x509.Certificate {
	t.Helper()
	keys := []*ecdsa.PrivateKey{mustECKey(t), mustECKey(t)}
	name := pkix.Name{CommonName: "Same"}
	var out []*x509.Certificate
	for i := range n {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 10)), Subject: name, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		parent := &x509.Certificate{Subject: name}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, keys[i%2].Public(), keys[(i+1)%2])
		require.NoError(t, err)
		c, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		out = append(out, c)
	}
	return out
}

func mustECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

// The worst file the bounds allow (32 certificates, every one an issuer candidate of half the
// others) costs at most maxChainSignatureChecks signature checks; the search then gives up and the
// chain is unresolved (a discovered file keeps its leaf alone; an upload is refused).
func TestOrderingTheWorstChainIsBounded(t *testing.T) {
	all := sameNameChain(t, maxCertificates)
	s := &chainSearch{at: now, self: map[*x509.Certificate]bool{}}
	_, _ = s.extend(all[0], all[1:])
	assert.LessOrEqual(t, s.checks, maxChainSignatureChecks)
	assert.True(t, s.cut, "the alternating chain needs more checks than the bound")

	var file []byte
	for _, c := range all {
		file = append(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	p, err := ParseServedChain(file, now)
	require.NoError(t, err)
	assert.True(t, p.ChainUnresolved)
	assert.Empty(t, p.Chain)
	assert.False(t, ChainComplete(p, x509.NewCertPool(), now))

	// A short chain of the same shape is ordered within the bound.
	short := sameNameChain(t, 4)
	path, ok := orderChain(short[0], short[1:], now)
	assert.True(t, ok)
	assert.Len(t, path, 3)
}

// W2 review, minor 6: two issuers with the same name and key; only the second leads to a root in the
// input. The search tries it after the first fails.
func TestOrderChainBacktracksToTheIssuerThatReachesARoot(t *testing.T) {
	interKey, leafKey := mustECKey(t), mustECKey(t)
	rootA, rootAKey := selfSignedCA(t, "Root A")
	rootB, rootBKey := selfSignedCA(t, "Root B")
	interName := pkix.Name{CommonName: "Shared Intermediate"}
	issue := func(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, serial int64) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: interName,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}, parent, interKey.Public(), parentKey)
		require.NoError(t, err)
		c, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return c
	}
	viaA, viaB := issue(rootA, rootAKey, 2), issue(rootB, rootBKey, 3)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "www.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}, viaA, leafKey.Public(), interKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	path, ok := orderChain(leaf, []*x509.Certificate{viaA, viaB, rootB}, now)
	require.True(t, ok)
	require.Len(t, path, 2)
	assert.Equal(t, viaB.Raw, path[0].Raw, "the issuer whose root is in the input")
	assert.Equal(t, rootB.Raw, path[1].Raw)
	// Without any root the first issuer is kept.
	path, ok = orderChain(leaf, []*x509.Certificate{viaA, viaB}, now)
	require.True(t, ok)
	assert.Equal(t, []*x509.Certificate{viaA}, path)
}

func selfSignedCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := mustECKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c, k
}

// A discovered file is stored as the path from its first certificate (the one Nginx serves) to the
// root: certificates of the file that are not on that path are dropped and the path is in issuing
// order, whatever the file's order (B1-I1).
func TestParseServedChainKeepsTheOrderedPathOnly(t *testing.T) {
	ca := pki.NewCA("Served", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	junk := pki.SelfSigned("unrelated.example.test", pki.ECDSA256, now)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})
	file := append(append(append(append([]byte{}, leaf.CertPEM...), rootPEM...), junk.CertPEM...), ca.IntermediatePEM...)

	p, err := ParseServedChain(file, now)
	require.NoError(t, err)
	assert.Equal(t, leaf.Cert.Raw, p.Leaf.Raw, "the first certificate is the leaf")
	require.Len(t, p.Chain, 2)
	assert.Equal(t, ca.Intermediate.Raw, p.Chain[0].Raw, "issuing order, not file order")
	assert.Equal(t, ca.Root.Raw, p.Chain[1].Raw)
	assert.Equal(t, string(leaf.CertPEM)+string(ca.IntermediatePEM)+string(rootPEM), p.PEMChain)
	assert.NotContains(t, p.PEMChain, string(junk.CertPEM))

	// ParseChainPEM keeps describing the file as it is.
	all, err := ParseChainPEM(file)
	require.NoError(t, err)
	assert.Len(t, all.Chain, 3)
}
