package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pki"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func rootsOf(ca *pki.CA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Root)
	return p
}

// Review Focus 4: uploads as people really have them.
func TestValidateUploadTable(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	rsaCA := pki.NewCA("Alice RSA", pki.RSA2048, now)
	good := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	other := ca.Issue(pki.Opts{CommonName: "other.example.test"}, now)
	expired := ca.Issue(pki.Opts{CommonName: "old.example.test", NotBefore: now.AddDate(0, -3, 0), NotAfter: now.Add(-24 * time.Hour)}, now)
	future := ca.Issue(pki.Opts{CommonName: "soon.example.test", NotBefore: now.Add(48 * time.Hour), NotAfter: now.AddDate(0, 3, 0)}, now)
	weak := rsaCA.Issue(pki.Opts{CommonName: "weak.example.test", KeyType: pki.RSA1024}, now)
	p521 := ca.Issue(pki.Opts{CommonName: "p521.example.test", KeyType: pki.ECDSA521}, now)
	ed := ca.Issue(pki.Opts{CommonName: "ed.example.test", KeyType: pki.Ed25519}, now)
	crlf := bytes.ReplaceAll(good.FullchainPEM, []byte("\n"), []byte("\r\n"))
	bom := append([]byte("\xef\xbb\xbf"), good.FullchainPEM...)
	reversed := append(append([]byte{}, ca.IntermediatePEM...), good.CertPEM...)
	withRoot := append(append([]byte{}, good.FullchainPEM...), ca.RootPEM...)
	rsaLeaf := ca.Issue(pki.Opts{CommonName: "rsa.example.test", KeyType: pki.RSA2048}, now)
	rsaKey, ok := rsaLeaf.Key.(*rsa.PrivateKey)
	require.True(t, ok)
	ecParams := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}})
	withParams := append(append([]byte{}, ecParams...), pki.KeyPEMSEC1(mustEC(t, good))...)
	twoKeys := append(append([]byte{}, good.KeyPEM...), other.KeyPEM...)

	for _, tc := range []struct {
		name     string
		in       Upload
		err      error
		complete bool
		warnings []string
	}{
		{"fullchain and key", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"CRLF line endings", Upload{CertificatePEM: crlf, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"UTF-8 BOM", Upload{CertificatePEM: bom, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"chain before the leaf", Upload{CertificatePEM: reversed, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"root included", Upload{CertificatePEM: withRoot, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"leaf only", Upload{CertificatePEM: good.CertPEM, PrivateKeyPEM: good.KeyPEM}, nil, false, []string{"chain_incomplete"}},
		{"SEC1 key", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: pki.KeyPEMSEC1(mustEC(t, good))}, nil, true, nil},
		{"PKCS#1 RSA key", Upload{CertificatePEM: rsaLeaf.FullchainPEM, PrivateKeyPEM: pki.KeyPEMPKCS1(rsaKey)}, nil, true, nil},
		{"EC PARAMETERS before the key", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: withParams}, nil, true, nil},
		{"PFX with password", Upload{PFX: pki.PFX(good, ca, "pw"), PFXPassword: "pw"}, nil, true, nil},
		{"PFX with empty password", Upload{PFX: pki.PFX(good, ca, ""), PFXPassword: ""}, nil, true, nil},
		{"not yet valid", Upload{CertificatePEM: future.FullchainPEM, PrivateKeyPEM: future.KeyPEM}, nil, true, []string{"not_yet_valid"}},
		{"key of another certificate", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: other.KeyPEM}, ErrKeyMismatch, false, nil},
		{"expired", Upload{CertificatePEM: expired.FullchainPEM, PrivateKeyPEM: expired.KeyPEM}, ErrExpired, false, nil},
		{"PFX wrong password", Upload{PFX: pki.PFX(good, ca, "pw"), PFXPassword: "nope"}, ErrPFXPassword, false, nil},
		{"encrypted PEM key", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: pki.EncryptedKeyPEM(weak)}, ErrKeyEncrypted, false, nil},
		{"RSA 1024", Upload{CertificatePEM: weak.FullchainPEM, PrivateKeyPEM: weak.KeyPEM}, ErrWeak, false, nil},
		{"P-521", Upload{CertificatePEM: p521.FullchainPEM, PrivateKeyPEM: p521.KeyPEM}, ErrUnsupportedKey, false, nil},
		{"Ed25519", Upload{CertificatePEM: ed.FullchainPEM, PrivateKeyPEM: ed.KeyPEM}, ErrUnsupportedKey, false, nil},
		{"two private keys", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: twoKeys}, ErrInvalid, false, nil},
		{"no key", Upload{CertificatePEM: good.FullchainPEM}, ErrNoKey, false, nil},
		{"garbage", Upload{CertificatePEM: []byte("hello"), PrivateKeyPEM: good.KeyPEM}, ErrInvalid, false, nil},
		{"a key in the certificate field", Upload{CertificatePEM: good.KeyPEM, PrivateKeyPEM: good.KeyPEM}, ErrInvalid, false, nil},
		{"too large", Upload{CertificatePEM: bytes.Repeat([]byte("a"), MaxInputSize+1), PrivateKeyPEM: good.KeyPEM}, ErrTooLarge, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ValidateUpload(tc.in, now, rootsOf(ca))
			if tc.err != nil {
				require.True(t, errors.Is(err, tc.err), "got %v", err)
				return
			}
			require.NoError(t, err)
			defer v.PrivateKeyDER.Zero()
			want := pki.Fingerprint(good.Cert)
			if tc.name == "PKCS#1 RSA key" {
				want = pki.Fingerprint(rsaLeaf.Cert)
			}
			assert.Equal(t, true, want == v.Fingerprint || tc.name == "not yet valid")
			assert.Equal(t, tc.complete, v.ChainComplete)
			assert.Equal(t, tc.warnings, v.Warnings)
			assert.True(t, strings.HasPrefix(v.PEMChain, "-----BEGIN CERTIFICATE-----\n"), "re-encoded, leaf first")
			assert.NotContains(t, v.PEMChain, "PRIVATE KEY")
		})
	}
}

func TestValidatedFieldsOfAnRSALeaf(t *testing.T) {
	ca := pki.NewCA("Alice RSA", pki.RSA2048, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test", "10.0.0.5"}, KeyType: pki.RSA3072}, now)
	v, err := ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: l.KeyPEM}, now, rootsOf(ca))
	require.NoError(t, err)
	defer v.PrivateKeyDER.Zero()
	assert.Equal(t, "rsa", v.Algorithm)
	assert.Equal(t, 3072, v.Bits)
	assert.Equal(t, "www.example.test", v.SubjectCN)
	assert.Equal(t, []string{"www.example.test", "10.0.0.5"}, v.SANs)
	assert.Len(t, v.Chain, 1)
	assert.Len(t, v.PublicKeySHA256, 64)
	assert.Regexp(t, `^[0-9A-F]+$`, v.Serial)
	info, err := KeyInfoOf(v.PrivateKeyDER)
	require.NoError(t, err)
	assert.Equal(t, KeyInfo{Algorithm: "rsa", Bits: 3072, PublicKeySHA256: v.PublicKeySHA256}, info)
}

func mustEC(t *testing.T, l pki.Leaf) *ecdsa.PrivateKey {
	t.Helper()
	k, ok := l.Key.(*ecdsa.PrivateKey)
	require.True(t, ok)
	return k
}

// SEC-044: errors and the validated value never render key material.
func TestNothingPrintsTheKey(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	other := ca.Issue(pki.Opts{CommonName: "other.example.test"}, now)
	v, err := ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: l.KeyPEM}, now, rootsOf(ca))
	require.NoError(t, err)
	out := fmt.Sprintf("%v %+v %#v", v, v, v)
	marker := "PRIVATE" + " KEY"
	assert.NotContains(t, out, marker)
	assert.NotContains(t, out, string(l.KeyPEM[40:80]))
	_, err = ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: other.KeyPEM}, now, rootsOf(ca))
	assert.NotContains(t, err.Error(), string(other.KeyPEM[40:80]))
	v.PrivateKeyDER.Zero()
	assert.Equal(t, make([]byte, len(v.PrivateKeyDER.Bytes())), v.PrivateKeyDER.Bytes(), "Zero clears the key")
}

func TestValidateUploadRefusesMixedAndOversizedSources(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	_, err := ValidateUpload(Upload{PFX: pki.PFX(l, ca, "pw"), PFXPassword: "pw", CertificatePEM: l.FullchainPEM}, now, rootsOf(ca))
	assert.ErrorIs(t, err, ErrInvalid, "a PFX and PEM fields together")
	_, err = ValidateUpload(Upload{PFX: bytes.Repeat([]byte("a"), MaxInputSize+1)}, now, rootsOf(ca))
	assert.ErrorIs(t, err, ErrTooLarge)
	_, err = ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: bytes.Repeat([]byte("a"), MaxInputSize+1)}, now, rootsOf(ca))
	assert.ErrorIs(t, err, ErrTooLarge)
	_, err = ValidateUpload(Upload{}, now, rootsOf(ca))
	assert.ErrorIs(t, err, ErrInvalid, "nothing at all")
	many := bytes.Repeat(l.CertPEM, maxCertificates+1)
	_, err = ValidateUpload(Upload{CertificatePEM: many, PrivateKeyPEM: l.KeyPEM}, now, rootsOf(ca))
	assert.ErrorIs(t, err, ErrInvalid, "too many certificates")
	enc := pki.EncryptedKeyPEM(l)
	_, err = ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: append(append([]byte{}, l.KeyPEM...), enc...)}, now, rootsOf(ca))
	assert.ErrorIs(t, err, ErrKeyEncrypted, "an encrypted block next to a good one")
}

func TestValidateUploadDropsAnUnrelatedIntermediate(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	other := pki.NewCA("Alice Other", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	// An intermediate of another CA is not on the path and is dropped.
	v, err := ValidateUpload(Upload{CertificatePEM: append(append([]byte{}, l.FullchainPEM...), other.IntermediatePEM...), PrivateKeyPEM: l.KeyPEM}, now, rootsOf(ca))
	require.NoError(t, err)
	defer v.PrivateKeyDER.Zero()
	assert.Len(t, v.Chain, 1)
	assert.True(t, v.ChainComplete)
}

// A reused key: the expired old certificate before the renewed one must not decide.
func TestValidateUploadPrefersTheValidCertificateOfAReusedKey(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	key := pki.NewKey(pki.ECDSA256)
	old := ca.Issue(pki.Opts{CommonName: "www.example.test", Key: key, NotBefore: now.AddDate(0, -6, 0), NotAfter: now.Add(-24 * time.Hour)}, now)
	renewed := ca.Issue(pki.Opts{CommonName: "www.example.test", Key: key}, now)
	in := append(append([]byte{}, old.CertPEM...), renewed.FullchainPEM...)
	v, err := ValidateUpload(Upload{CertificatePEM: in, PrivateKeyPEM: renewed.KeyPEM}, now, rootsOf(ca))
	require.NoError(t, err)
	defer v.PrivateKeyDER.Zero()
	assert.Equal(t, pki.Fingerprint(renewed.Cert), v.Fingerprint)
	_, err = ValidateUpload(Upload{CertificatePEM: old.CertPEM, PrivateKeyPEM: old.KeyPEM}, now, rootsOf(ca))
	assert.ErrorIs(t, err, ErrExpired, "still refused when none is valid")
}

func TestValidateUploadAcceptsACASelfSignedCertificate(t *testing.T) {
	self := pki.NewCA("Alice Self", pki.ECDSA256, now)
	v, err := ValidateUpload(Upload{CertificatePEM: self.RootPEM, PrivateKeyPEM: pki.KeyPEMSEC1(mustEC(t, pki.Leaf{Key: self.RootKey}))}, now, x509.NewCertPool())
	require.NoError(t, err)
	defer v.PrivateKeyDER.Zero()
	assert.True(t, v.SelfSigned)
	assert.True(t, v.ChainComplete)
}

// Chain certificates are not refused when expired, but they are reported and
// they keep the chain from being complete unless another valid path exists.
func TestChainCertificateValidity(t *testing.T) {
	fresh := pki.Opts{CommonName: "www.example.test", NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 0, 90)}

	t.Run("all valid", func(t *testing.T) {
		ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
		l := ca.Issue(fresh, now)
		v, err := ValidateUpload(Upload{CertificatePEM: append(append([]byte{}, l.FullchainPEM...), ca.RootPEM...), PrivateKeyPEM: l.KeyPEM}, now, x509.NewCertPool())
		require.NoError(t, err)
		defer v.PrivateKeyDER.Zero()
		assert.True(t, v.ChainComplete)
		assert.Empty(t, v.Warnings)
	})

	t.Run("expired intermediate with its root", func(t *testing.T) {
		ca := pki.NewCA("Alice Old", pki.ECDSA256, now.AddDate(-6, 0, 0)) // intermediate ended a year ago
		l := ca.Issue(fresh, now)
		for _, roots := range []*x509.CertPool{x509.NewCertPool(), rootsOf(ca)} {
			v, err := ValidateUpload(Upload{CertificatePEM: append(append([]byte{}, l.FullchainPEM...), ca.RootPEM...), PrivateKeyPEM: l.KeyPEM}, now, roots)
			require.NoError(t, err)
			assert.False(t, v.ChainComplete, "a self-signed last certificate does not make it complete")
			assert.Equal(t, []string{"chain_incomplete", "chain_certificate_expired"}, v.Warnings)
			v.PrivateKeyDER.Zero()
		}
	})

	t.Run("expired cross-sign beside a valid path", func(t *testing.T) {
		ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
		other := pki.NewCA("Alice Other", pki.ECDSA256, now)
		l := ca.Issue(fresh, now)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(77), Subject: ca.Intermediate.Subject,
			NotBefore: now.AddDate(-3, 0, 0), NotAfter: now.AddDate(-1, 0, 0),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			SubjectKeyId: ca.Intermediate.SubjectKeyId,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, other.Root, ca.IntermediateKey.Public(), other.RootKey)
		require.NoError(t, err)
		cross := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		for _, in := range [][]byte{
			bytes.Join([][]byte{l.CertPEM, cross, ca.IntermediatePEM, ca.RootPEM}, nil),
			bytes.Join([][]byte{l.CertPEM, ca.IntermediatePEM, cross, ca.RootPEM}, nil),
		} {
			v, err := ValidateUpload(Upload{CertificatePEM: in, PrivateKeyPEM: l.KeyPEM}, now, rootsOf(ca))
			require.NoError(t, err)
			assert.True(t, v.ChainComplete)
			assert.Equal(t, []string{"chain_certificate_expired"}, v.Warnings)
			v.PrivateKeyDER.Zero()
		}
	})
}
