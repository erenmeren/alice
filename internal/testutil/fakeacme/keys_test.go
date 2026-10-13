package fakeacme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

func TestOtherCurvesAndKeySizes(t *testing.T) {
	s := start(t, Options{})
	// A P-384 account key signs ES384; a P-521 one ES512.
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		c := &acme.Client{Key: k, DirectoryURL: s.DirectoryURL(), HTTPClient: s.HTTPClient(), RetryBackoff: fastRetry}
		register(t, c)
		_, err = c.AuthorizeOrder(ctx(t), idents("a.example.test"))
		assert.NoError(t, err, curve.Params().Name)
	}

	c := newClient(t, s)
	register(t, c)
	o := ready(t, s, c, "k.example.test")
	csr := func(key any, cn string, sans ...string) []byte {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: sans}, key)
		require.NoError(t, err)
		return der
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	_, _, err = c.CreateOrderCert(ctx(t), o.FinalizeURL, csr(small, "k.example.test", "k.example.test"), true)
	assert.Equal(t, "urn:ietf:params:acme:error:badPublicKey", problemOf(t, err).ProblemType)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	_, _, err = c.CreateOrderCert(ctx(t), o.FinalizeURL, csr(p521, "k.example.test", "k.example.test"), true)
	assert.Equal(t, "urn:ietf:params:acme:error:badPublicKey", problemOf(t, err).ProblemType)
	// A common name that is not among the SANs.
	_, _, err = c.CreateOrderCert(ctx(t), o.FinalizeURL, csr(testKey(t), "other.example.test", "k.example.test"), true)
	assert.Equal(t, "urn:ietf:params:acme:error:badCSR", problemOf(t, err).ProblemType)
	// An IP SAN.
	ipCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"k.example.test"},
		IPAddresses: nil, EmailAddresses: []string{"a@b.test"}}, testKey(t))
	require.NoError(t, err)
	_, _, err = c.CreateOrderCert(ctx(t), o.FinalizeURL, ipCSR, true)
	assert.Equal(t, "urn:ietf:params:acme:error:badCSR", problemOf(t, err).ProblemType)
	// A CSR with a common name and no SANs is read as that one name, and an ECDSA P-384 key is fine.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csr(p384, "k.example.test"), true)
	require.NoError(t, err)
	assert.Equal(t, []string{"k.example.test"}, parseLeaf(t, der).DNSNames)
}
