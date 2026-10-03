package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pki"
)

func TestNewCSRAndValidateSigned(t *testing.T) {
	for _, kt := range []string{"ecdsa-p256", "rsa-3072", "rsa-4096"} {
		t.Run(kt, func(t *testing.T) {
			csrPEM, der, info, err := NewCSR(rand.Reader, CSRRequest{CommonName: "www.example.test", SANs: []string{"example.test"}, KeyType: kt})
			require.NoError(t, err)
			defer der.Zero()
			b, _ := pem.Decode([]byte(csrPEM))
			require.NotNil(t, b)
			require.Equal(t, "CERTIFICATE REQUEST", b.Type)
			csr, err := x509.ParseCertificateRequest(b.Bytes)
			require.NoError(t, err)
			require.NoError(t, csr.CheckSignature())
			assert.Equal(t, []string{"www.example.test", "example.test"}, csr.DNSNames, "the common name is also a SAN")
			key, err := x509.ParsePKCS8PrivateKey(der.Bytes())
			require.NoError(t, err)
			ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
			signed := ca.Issue(pki.Opts{CommonName: "www.example.test", Key: key.(crypto.Signer)}, now)
			p, complete, err := ValidateSigned(signed.FullchainPEM, info, now, rootsOf(ca))
			require.NoError(t, err)
			assert.True(t, complete)
			assert.Equal(t, info.PublicKeySHA256, p.PublicKeySHA256)
			other := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
			_, _, err = ValidateSigned(other.FullchainPEM, info, now, rootsOf(ca))
			assert.ErrorIs(t, err, ErrCSRMismatch)
		})
	}
	_, _, _, err := NewCSR(rand.Reader, CSRRequest{CommonName: "bad name", KeyType: "ecdsa-p256"})
	assert.ErrorIs(t, err, ErrInvalid)
	_, _, _, err = NewCSR(rand.Reader, CSRRequest{CommonName: "x.example.test", KeyType: "rsa-1024"})
	assert.ErrorIs(t, err, ErrUnsupportedKey)
}

func TestKeyPEMIsPKCS8(t *testing.T) {
	_, der, _, err := NewCSR(rand.Reader, CSRRequest{CommonName: "x.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	p, err := KeyPEM(der)
	require.NoError(t, err)
	defer p.Zero()
	b, _ := pem.Decode(p.Bytes())
	require.NotNil(t, b)
	assert.Equal(t, "PRIVATE KEY", b.Type)
	assert.Equal(t, "[redacted]", fmt.Sprint(p), "the key never prints")
}

func TestValidDNSName(t *testing.T) {
	for in, want := range map[string]bool{"www.example.test": true, "*.example.test": true, "*.com": false, "*.": false, "a-b.c": true, "localhost": true,
		"": false, "bad name": false, "a..b": false, "-a.b": false, "a.b-": false, "*.*.b": false, "a.*.b": false,
		"ÖRNEK.com": false, strings.Repeat("a", 64) + ".b": false} {
		assert.Equal(t, want, ValidDNSName(in), in)
	}
}

func TestValidateSignedRefusesExpiredAndWeak(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	_, der, info, err := NewCSR(rand.Reader, CSRRequest{CommonName: "www.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	defer der.Zero()
	key, err := x509.ParsePKCS8PrivateKey(der.Bytes())
	require.NoError(t, err)
	old := ca.Issue(pki.Opts{CommonName: "www.example.test", Key: key.(crypto.Signer),
		NotBefore: now.AddDate(0, -3, 0), NotAfter: now.Add(-time.Hour)}, now)
	_, _, err = ValidateSigned(old.FullchainPEM, info, now, rootsOf(ca))
	assert.ErrorIs(t, err, ErrExpired)

	weakKey := pki.NewKey(pki.RSA1024)
	pub, err := x509.MarshalPKIXPublicKey(weakKey.Public())
	require.NoError(t, err)
	weakInfo := KeyInfo{Algorithm: "rsa", Bits: 1024, PublicKeySHA256: fingerprint(pub)}
	rsaCA := pki.NewCA("Alice RSA", pki.RSA2048, now)
	w := rsaCA.Issue(pki.Opts{CommonName: "www.example.test", Key: weakKey}, now)
	_, _, err = ValidateSigned(w.FullchainPEM, weakInfo, now, rootsOf(rsaCA))
	assert.ErrorIs(t, err, ErrWeak)
	_, _, err = ValidateSigned([]byte("nonsense"), info, now, rootsOf(ca))
	assert.ErrorIs(t, err, ErrInvalid)
}
