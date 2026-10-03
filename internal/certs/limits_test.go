package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// rsaPublicOfBits is an RSA public key with a modulus of exactly bits bits (not a real key: only
// its size matters to the checks).
func rsaPublicOfBits(t *testing.T, bits int) *rsa.PublicKey {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	require.NoError(t, err)
	n.SetBit(n, bits-1, 1).SetBit(n, 0, 1)
	return &rsa.PublicKey{N: n, E: 65537}
}

// OpenSSL refuses RSA moduli above 16384 bits, so Alice never stores one as good; parsing a key's
// cost grows with its size, so an oversized private key block is refused before it is parsed.
func TestRSAKeySizeIsCapped(t *testing.T) {
	require.NoError(t, checkPublicKey(rsaPublicOfBits(t, 16384)))
	require.ErrorIs(t, checkPublicKey(rsaPublicOfBits(t, 16385)), ErrUnsupportedKey)
	assert.Contains(t, ErrUnsupportedKey.Error(), "16384", "the refusal says the limit")

	// A signed certificate for a too large key.
	ca := pki.NewCA("Big", pki.ECDSA256, now)
	pub := rsaPublicOfBits(t, 16400)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "big.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 0, 30)}, ca.Intermediate, pub, ca.IntermediateKey)
	require.NoError(t, err)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	spki, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	_, _, err = ValidateSigned(leafPEM, KeyInfo{Algorithm: "rsa", Bits: 16400, PublicKeySHA256: fingerprint(spki)}, now, nil)
	require.ErrorIs(t, err, ErrUnsupportedKey)

	// An uploaded key block larger than any key Alice accepts is refused unparsed, quickly.
	l := ca.Issue(pki.Opts{CommonName: "a.example.test"}, now)
	huge := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: make([]byte, 64<<10)})
	start := time.Now()
	_, err = ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: huge}, now, nil)
	require.ErrorIs(t, err, ErrUnsupportedKey)
	assert.Less(t, time.Since(start), time.Second)
	for _, typ := range []string{"RSA PRIVATE KEY", "EC PRIVATE KEY"} {
		_, err = ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: typ,
			Bytes: make([]byte, maxKeyDER+1)})}, now, nil)
		require.ErrorIs(t, err, ErrUnsupportedKey, typ)
	}
	// The largest real keys stay below the bound: a 16384-bit RSA key in PKCS#8 is about 9.4 KiB.
	k := pki.NewKey(pki.RSA4096).(*rsa.PrivateKey)
	der, err = x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	assert.Less(t, len(der)*4, maxKeyDER, "four times a 4096-bit key fits")
	_, err = KeyInfoOf(secrets.NewPlaintext(der))
	require.NoError(t, err)
}

func TestContainsPrivateKey(t *testing.T) {
	l := pki.NewCA("K", pki.ECDSA256, now).Issue(pki.Opts{CommonName: "a.example.test"}, now)
	begin := "-----BEGIN "
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{string(l.FullchainPEM), false},
		{string(l.FullchainPEM) + string(l.KeyPEM), true},
		{string(l.KeyPEM) + string(l.FullchainPEM), true},
		{begin + "RSA PRIVATE KEY-----\nAAAA\n", true},
		{begin + "EC PRIVATE KEY-----", true},
		{begin + "ENCRYPTED PRIVATE KEY-----", true},
		{"text " + begin + "PRIVATE KEY----- more", true},
		{begin + "PUBLIC KEY-----", false},
		{begin + "CERTIFICATE-----\n" + begin, false},
		{"PRIVATE KEY-----", false},
		{"", false},
	} {
		assert.Equal(t, tc.want, ContainsPrivateKey(tc.in), "%.60q", tc.in)
	}
	assert.False(t, ContainsPrivateKey(strings.Repeat(begin, 10000)))
}
