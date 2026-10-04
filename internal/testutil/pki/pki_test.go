package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func TestIssueBuildsAVerifiableChain(t *testing.T) {
	ca := NewCA("Alice Test", ECDSA256, now)
	l := ca.Issue(Opts{CommonName: "www.example.test", SANs: []string{"www.example.test", "example.test"}}, now)
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca.Root)
	inter.AddCert(ca.Intermediate)
	_, err := l.Cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, DNSName: "example.test"})
	require.NoError(t, err)
	b, _ := pem.Decode(l.KeyPEM)
	require.NotNil(t, b)
	assert.Equal(t, "PRIVATE KEY", b.Type)
	blocks := 0
	for rest := l.FullchainPEM; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		blocks++
	}
	assert.Equal(t, 2, blocks)
	assert.Len(t, Fingerprint(l.Cert), 64)
}

func TestKeyTypesAndValidity(t *testing.T) {
	ca := NewCA("Alice Test", RSA2048, now)
	for _, kt := range []KeyType{RSA1024, RSA2048, RSA3072, ECDSA256, ECDSA384, ECDSA521, Ed25519} {
		l := ca.Issue(Opts{CommonName: "x.example.test", KeyType: kt}, now)
		assert.NotNil(t, l.Key, kt)
	}
	exp := ca.Issue(Opts{CommonName: "old.example.test", NotBefore: now.AddDate(0, -3, 0), NotAfter: now.AddDate(0, 0, -1)}, now)
	assert.True(t, exp.Cert.NotAfter.Before(now))
}

func TestPFXRoundTrip(t *testing.T) {
	ca := NewCA("Alice Test", ECDSA256, now)
	l := ca.Issue(Opts{CommonName: "www.example.test"}, now)
	key, cert, cas, err := pkcs12.DecodeChain(PFX(l, ca, "pw"), "pw")
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, l.Cert.Raw, cert.Raw)
	require.Len(t, cas, 1)
	_, _, _, err = pkcs12.DecodeChain(PFX(l, ca, "pw"), "wrong")
	assert.Error(t, err)
}

func TestEncryptedKeyPEMIsMarked(t *testing.T) {
	ca := NewCA("Alice Test", RSA2048, now)
	b, _ := pem.Decode(EncryptedKeyPEM(ca.Issue(Opts{CommonName: "x", KeyType: RSA2048}, now)))
	require.NotNil(t, b)
	assert.Equal(t, "4,ENCRYPTED", b.Headers["Proc-Type"])
}

func TestIssueForCSRSignsTheRequestsKey(t *testing.T) {
	ca := NewCA("Alice Test", ECDSA256, now)
	key := NewKey(RSA2048)
	r := CSRFor("www.example.test", []string{"www.example.test", "example.test"}, key)
	l := ca.IssueForCSR(r, now)
	assert.Nil(t, l.Key, "the requester keeps the key")
	assert.Empty(t, l.KeyPEM)
	assert.True(t, l.Cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()))
	assert.Equal(t, "www.example.test", l.Cert.Subject.CommonName)
	assert.Equal(t, []string{"www.example.test", "example.test"}, l.Cert.DNSNames)
	assert.NotZero(t, l.Cert.KeyUsage&x509.KeyUsageKeyEncipherment, "an RSA leaf as Issue makes it")
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca.Root)
	inter.AddCert(ca.Intermediate)
	_, err := l.Cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, DNSName: "example.test"})
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte{}, l.CertPEM...), ca.IntermediatePEM...), l.FullchainPEM)
}

// IssueRawValidity writes the validity as given: a GeneralizedTime with a zone offset reads, in
// UTC, a day outside years 0000-9999; the certificate still verifies against the intermediate.
func TestIssueRawValidity(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for _, kt := range []KeyType{ECDSA256, ECDSA384, RSA2048} {
		ca := NewCA("Raw", kt, now)
		l := ca.IssueRawValidity(Opts{CommonName: "raw.example.test"}, GeneralizedTime("00000101000000+2359"), GeneralizedTime("99991231235959-2359"), now)
		assert.True(t, l.Cert.NotBefore.Equal(time.Date(-1, 12, 31, 0, 1, 0, 0, time.UTC)), l.Cert.NotBefore.UTC())
		assert.True(t, l.Cert.NotAfter.Equal(time.Date(10000, 1, 1, 23, 58, 59, 0, time.UTC)), l.Cert.NotAfter.UTC())
		require.NoError(t, l.Cert.CheckSignatureFrom(ca.Intermediate), kt)
		l = ca.IssueRawValidity(Opts{CommonName: "old.example.test"}, UTCTime("600101000000Z"), UTCTime("650101000000Z"), now)
		assert.Equal(t, 1965, l.Cert.NotAfter.Year())
	}
}
