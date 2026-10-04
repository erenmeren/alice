package certs

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

func TestExportPFXRoundTrips(t *testing.T) {
	ca := pki.NewCA("Export CA", pki.ECDSA256, now)
	for _, kt := range []pki.KeyType{pki.ECDSA256, pki.ECDSA384, pki.RSA2048} {
		leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}, KeyType: kt}, now)
		v, err := ValidateUpload(Upload{CertificatePEM: leaf.FullchainPEM, PrivateKeyPEM: leaf.KeyPEM}, now, rootsOf(ca))
		require.NoError(t, err, kt)
		keep := bytes.Clone(v.PrivateKeyDER.Bytes())

		pfx, err := ExportPFX(v.PrivateKeyDER, v.Parsed)
		require.NoError(t, err, kt)
		assert.Equal(t, keep, v.PrivateKeyDER.Bytes(), "%s: the key argument is not modified", kt)
		assert.IsType(t, secrets.Plaintext{}, pfx)
		assert.NotContains(t, fmt.Sprintf("%v %+v %#v %s", pfx, pfx, pfx, pfx), "0")

		key, got, chain, err := pkcs12.DecodeChain(pfx.Bytes(), "")
		require.NoError(t, err, kt)
		assert.True(t, got.Equal(leaf.Cert), kt)
		require.Len(t, chain, 1, "%s: the intermediate, no root", kt)
		assert.True(t, chain[0].Equal(ca.Intermediate), kt)
		der, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		assert.Equal(t, keep, der, "%s: the same key", kt)

		// The same file goes back through the vault-secret reader.
		back, err := ParseKVSecret(ContentTypePKCS12, []byte(b64(pfx.Bytes())), now, rootsOf(ca))
		require.NoError(t, err, kt)
		assert.Equal(t, v.Fingerprint, back.Fingerprint, kt)
		back.PrivateKeyDER.Zero()
		pfx.Zero()
		v.PrivateKeyDER.Zero()
	}
}

func TestExportPFXDropsASelfSignedRootButNeverTheLeaf(t *testing.T) {
	ca := pki.NewCA("Export CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	v, err := ValidateUpload(Upload{CertificatePEM: append(append([]byte{}, leaf.FullchainPEM...), ca.RootPEM...), PrivateKeyPEM: leaf.KeyPEM}, now, rootsOf(ca))
	require.NoError(t, err)
	require.Len(t, v.Chain, 2, "the upload kept the root")
	pfx, err := ExportPFX(v.PrivateKeyDER, v.Parsed)
	require.NoError(t, err)
	_, _, chain, err := pkcs12.DecodeChain(pfx.Bytes(), "")
	require.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Len(t, v.Chain, 2, "the argument is not modified")

	ss := pki.SelfSigned("self.example.test", pki.ECDSA256, now)
	vs, err := ValidateUpload(Upload{CertificatePEM: ss.CertPEM, PrivateKeyPEM: ss.KeyPEM}, now, nil)
	require.NoError(t, err)
	pfx, err = ExportPFX(vs.PrivateKeyDER, vs.Parsed)
	require.NoError(t, err)
	_, got, chain, err := pkcs12.DecodeChain(pfx.Bytes(), "")
	require.NoError(t, err)
	assert.True(t, got.Equal(ss.Cert), "a self-signed leaf is exported as the leaf")
	assert.Empty(t, chain)
}

func TestExportPFXRefusals(t *testing.T) {
	ca := pki.NewCA("Export CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	other := ca.Issue(pki.Opts{CommonName: "other.example.test"}, now)
	v, err := ValidateUpload(Upload{CertificatePEM: leaf.FullchainPEM, PrivateKeyPEM: leaf.KeyPEM}, now, nil)
	require.NoError(t, err)
	vo, err := ValidateUpload(Upload{CertificatePEM: other.FullchainPEM, PrivateKeyPEM: other.KeyPEM}, now, nil)
	require.NoError(t, err)
	rsa1024 := ca.Issue(pki.Opts{CommonName: "w", KeyType: pki.RSA1024}, now)
	weakDER := mustPKCS8(t, rsa1024.Key)
	canary := secrets.NewPlaintext(append([]byte("CANARY-"), bytes.Repeat([]byte{0x41}, 40)...))

	for name, tc := range map[string]struct {
		key secrets.Plaintext
		p   Parsed
		err error
	}{
		"not PKCS #8":             {secrets.NewPlaintext(pki.KeyPEMSEC1(mustEC(t, leaf))), v.Parsed, ErrInvalid},
		"empty key":               {secrets.Plaintext{}, v.Parsed, ErrInvalid},
		"garbage":                 {canary, v.Parsed, ErrInvalid},
		"the key of another leaf": {vo.PrivateKeyDER, v.Parsed, ErrKeyMismatch},
		"a weak key":              {weakDER, v.Parsed, ErrWeak},
		"no leaf":                 {v.PrivateKeyDER, Parsed{}, ErrInvalid},
		"too many certificates":   {v.PrivateKeyDER, withChainOf(v.Parsed, maxCertificates+1), ErrInvalid},
	} {
		pfx, err := ExportPFX(tc.key, tc.p)
		require.ErrorIs(t, err, tc.err, name)
		assert.Empty(t, pfx.Bytes(), name)
		assert.NotContains(t, err.Error(), "CANARY", name)
		assert.NotContains(t, fmt.Sprintf("%+v", err), "CANARY", name)
	}
}

func withChainOf(p Parsed, n int) Parsed {
	p.Chain = make([]*x509.Certificate, n)
	for i := range p.Chain {
		p.Chain[i] = p.Leaf
	}
	return p
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestExportPFXKeepsTheRSAKeyUsable(t *testing.T) {
	ca := pki.NewCA("Export CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "rsa.example.test", KeyType: pki.RSA2048}, now)
	v, err := ValidateUpload(Upload{CertificatePEM: leaf.FullchainPEM, PrivateKeyPEM: leaf.KeyPEM}, now, nil)
	require.NoError(t, err)
	pfx, err := ExportPFX(v.PrivateKeyDER, v.Parsed)
	require.NoError(t, err)
	key, _, _, err := pkcs12.DecodeChain(pfx.Bytes(), "")
	require.NoError(t, err)
	assert.True(t, key.(*rsa.PrivateKey).Equal(leaf.Key))
}
