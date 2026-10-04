package certs

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pki"
)

func TestParseChainPEMTakesCertificatesOnly(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	mixed := append(append([]byte{}, l.FullchainPEM...), l.KeyPEM...)
	p, err := ParseChainPEM(mixed)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(l.Cert), p.Fingerprint, "the first CERTIFICATE block is the leaf")
	assert.NotContains(t, p.PEMChain, "PRIVATE KEY")
	_, err = ParseChainPEM(l.KeyPEM)
	assert.ErrorIs(t, err, ErrInvalid)
}

// §22.6 "SHA-1 signature": the leaf and every intermediate are checked by algorithm.
func TestWeakSignatureAlgorithms(t *testing.T) {
	for alg, weak := range map[x509.SignatureAlgorithm]bool{
		x509.MD5WithRSA: true, x509.SHA1WithRSA: true, x509.ECDSAWithSHA1: true, x509.DSAWithSHA1: true, x509.DSAWithSHA256: true,
		x509.UnknownSignatureAlgorithm: true, x509.SHA256WithRSA: false, x509.ECDSAWithSHA384: false, x509.SHA256WithRSAPSS: false, x509.PureEd25519: false,
	} {
		assert.Equal(t, weak, weakSignature(&x509.Certificate{SignatureAlgorithm: alg}), alg.String())
	}
}

func TestSANMatches(t *testing.T) {
	sans := []string{"www.example.test", "*.shop.example.test"}
	for name, want := range map[string]bool{
		"www.example.test": true, "WWW.Example.TEST": true, "a.shop.example.test": true, "shop.example.test": false,
		"a.b.shop.example.test": false, "example.test": false, "": false,
	} {
		assert.Equal(t, want, SANMatches(sans, name), name)
	}
}

func TestChainCompleteWithSystemRootsOrSelfSigned(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	p, err := ParseChainPEM(l.FullchainPEM)
	require.NoError(t, err)
	assert.False(t, ChainComplete(p, x509.NewCertPool(), now), "the root is neither uploaded nor trusted")
	assert.True(t, ChainComplete(p, rootsOf(ca), now))
	self := pki.SelfSigned("self.example.test", pki.ECDSA256, now)
	ps, err := ParseChainPEM(self.CertPEM)
	require.NoError(t, err)
	assert.True(t, ps.SelfSigned)
	assert.True(t, ChainComplete(ps, x509.NewCertPool(), now), "a self-signed certificate is its own chain")
}

// The weak-signature rule is wired into the upload path: the leaf and every
// chain certificate except a self-signed root.
func TestCheckLeafSignatureRules(t *testing.T) {
	future := now.AddDate(1, 0, 0)
	cert := func(alg x509.SignatureAlgorithm, subject, issuer string) *x509.Certificate {
		return &x509.Certificate{SignatureAlgorithm: alg, NotAfter: future, RawSubject: []byte(subject), RawIssuer: []byte(issuer)}
	}
	good := cert(x509.SHA256WithRSA, "leaf", "inter")
	assert.NoError(t, checkLeaf(Parsed{Leaf: good, NotAfter: future}, now))
	assert.ErrorIs(t, checkLeaf(Parsed{Leaf: cert(x509.SHA1WithRSA, "leaf", "inter"), NotAfter: future}, now), ErrWeak)
	assert.ErrorIs(t, checkLeaf(Parsed{Leaf: cert(x509.UnknownSignatureAlgorithm, "leaf", "inter"), NotAfter: future}, now), ErrWeak)
	weakInter := cert(x509.SHA1WithRSA, "inter", "root")
	assert.ErrorIs(t, checkLeaf(Parsed{Leaf: good, Chain: []*x509.Certificate{weakInter}, NotAfter: future}, now), ErrWeak)
	sha1Root := cert(x509.SHA1WithRSA, "root", "root")
	assert.NoError(t, checkLeaf(Parsed{Leaf: good, Chain: []*x509.Certificate{cert(x509.SHA256WithRSA, "inter", "root"), sha1Root}, NotAfter: future}, now),
		"a root's own signature does not matter")
	// A certificate that names itself but is inside the path was trusted through its (weak) signature.
	assert.ErrorIs(t, checkLeaf(Parsed{Leaf: good, Chain: []*x509.Certificate{sha1Root, cert(x509.SHA256WithRSA, "root", "other")}, NotAfter: future}, now),
		ErrWeak, "only the last certificate of the path is exempt")
	assert.ErrorIs(t, checkLeaf(Parsed{Leaf: good, NotAfter: now}, now), ErrExpired)
}
