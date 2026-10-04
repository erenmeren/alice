package certs

import (
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

// The largest key Alice accepts stays cheap even in the worst file the bounds allow: 32 certificates
// that all name the same subject and issuer (every one a candidate issuer of every other) with
// 16384-bit moduli and the largest exponent.
func TestWorstChainWithinTheBoundsStaysCheap(t *testing.T) {
	one := selfSignedLookingRSA(t, maxRSABits/8, "same.example.test")
	var file []byte
	for range maxCertificates {
		file = append(file, one...)
	}
	start := time.Now()
	p, err := ParseServedChain(file, now)
	require.NoError(t, err)
	_ = ChainComplete(p, x509.NewCertPool(), now)
	assert.Less(t, time.Since(start), 5*time.Second)
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
