package certs

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/azureid"
	"alice/internal/testutil/pki"
)

func TestParseClientCertificate(t *testing.T) {
	ca := pki.NewCA("SP CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "alice-sp", KeyType: pki.RSA2048}, now)
	for name, u := range map[string]Upload{
		"pem pair":             {CertificatePEM: leaf.FullchainPEM, PrivateKeyPEM: leaf.KeyPEM},
		"pem leaf only":        {CertificatePEM: leaf.CertPEM, PrivateKeyPEM: leaf.KeyPEM},
		"pfx with password":    {PFX: pki.PFX(leaf, ca, "pw"), PFXPassword: "pw"},
		"pfx without password": {PFX: pki.PFX(leaf, ca, "")},
	} {
		c, err := ParseClientCertificate(u, now, nil)
		require.NoError(t, err, name)
		assert.Equal(t, leaf.Cert.Raw, c.CertificateDER, name)
		assert.Equal(t, azureid.ThumbprintOf(leaf.Cert.Raw), c.Thumbprint, name)
		assert.True(t, azureid.ValidThumbprint(c.Thumbprint), name)
		assert.True(t, leaf.Cert.NotAfter.Equal(c.NotAfter), name)
		assert.True(t, leaf.Cert.NotBefore.Equal(c.NotBefore), name)
		key, err := x509.ParsePKCS8PrivateKey(c.PrivateKeyDER.Bytes())
		require.NoError(t, err, "%s: the key is PKCS #8", name)
		assert.IsType(t, &rsa.PrivateKey{}, key, name)
		assert.Equal(t, leaf.Key.Public(), key.(*rsa.PrivateKey).Public(), name)
		assert.NotContains(t, fmt.Sprintf("%v %+v %#v", c, c, c), "MII", name)
		c.PrivateKeyDER.Zero()
		assert.Equal(t, make([]byte, len(c.PrivateKeyDER.Bytes())), c.PrivateKeyDER.Bytes(), name)
	}
}

func TestParseClientCertificateRefusals(t *testing.T) {
	ca := pki.NewCA("SP CA", pki.ECDSA256, now)
	rsaLeaf := ca.Issue(pki.Opts{CommonName: "alice-sp", KeyType: pki.RSA2048}, now)
	other := ca.Issue(pki.Opts{CommonName: "other", KeyType: pki.RSA2048}, now)
	ec := ca.Issue(pki.Opts{CommonName: "alice-ec", KeyType: pki.ECDSA256}, now)
	weak := ca.Issue(pki.Opts{CommonName: "weak", KeyType: pki.RSA1024}, now)
	expired := ca.Issue(pki.Opts{CommonName: "old", KeyType: pki.RSA2048, NotBefore: now.AddDate(0, -3, 0), NotAfter: now.AddDate(0, 0, -1)}, now)
	for name, tc := range map[string]struct {
		u    Upload
		want error
	}{
		"ecdsa pair":         {Upload{CertificatePEM: ec.FullchainPEM, PrivateKeyPEM: ec.KeyPEM}, ErrClientCertKey},
		"ecdsa pfx":          {Upload{PFX: pki.PFX(ec, ca, "")}, ErrClientCertKey},
		"expired":            {Upload{CertificatePEM: expired.FullchainPEM, PrivateKeyPEM: expired.KeyPEM}, ErrExpired},
		"key mismatch":       {Upload{CertificatePEM: rsaLeaf.FullchainPEM, PrivateKeyPEM: other.KeyPEM}, ErrKeyMismatch},
		"rsa 1024":           {Upload{CertificatePEM: weak.CertPEM, PrivateKeyPEM: weak.KeyPEM}, ErrWeak},
		"wrong pfx password": {Upload{PFX: pki.PFX(rsaLeaf, ca, "pw"), PFXPassword: "other"}, ErrPFXPassword},
		"no key":             {Upload{CertificatePEM: rsaLeaf.FullchainPEM}, ErrNoKey},
		"nothing":            {Upload{}, ErrInvalid},
		"too large":          {Upload{PFX: make([]byte, MaxInputSize+1)}, ErrTooLarge},
	} {
		c, err := ParseClientCertificate(tc.u, now, nil)
		require.ErrorIs(t, err, tc.want, name)
		assert.Empty(t, c.PrivateKeyDER.Bytes(), "%s: no key comes back with an error", name)
		assert.Empty(t, c.CertificateDER, name)
	}
}

// The ECDSA refusal is the one path that parsed a key and then refuses it: the PKCS #8 copy made
// for the result is cleared before the error returns (the caller never sees it to clear it).
func TestParseClientCertificateClearsTheKeyItRefuses(t *testing.T) {
	ca := pki.NewCA("SP CA", pki.ECDSA256, now)
	ec := ca.Issue(pki.Opts{CommonName: "alice-ec", KeyType: pki.ECDSA256}, now)
	var kept []byte
	_, err := parseClientCertificate(Upload{CertificatePEM: ec.FullchainPEM, PrivateKeyPEM: ec.KeyPEM}, now, nil, func(der []byte) { kept = der })
	require.ErrorIs(t, err, ErrClientCertKey)
	require.NotEmpty(t, kept, "the refused key was parsed before it was refused")
	assert.Equal(t, make([]byte, len(kept)), kept)
}

func TestClientCertificateDatesFollowTheUploadRules(t *testing.T) {
	ca := pki.NewCA("SP CA", pki.ECDSA256, now)
	future := ca.Issue(pki.Opts{CommonName: "future", KeyType: pki.RSA2048, NotBefore: now.Add(48 * time.Hour), NotAfter: now.AddDate(1, 0, 0)}, now)
	c, err := ParseClientCertificate(Upload{CertificatePEM: future.CertPEM, PrivateKeyPEM: future.KeyPEM}, now, nil)
	require.NoError(t, err, "a certificate that is not valid yet is read; NotBefore says so")
	assert.True(t, c.NotBefore.After(now))
	c.PrivateKeyDER.Zero()
}
