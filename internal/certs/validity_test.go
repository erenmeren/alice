package certs

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// AUD-13 fix round 2: a certificate whose NotBefore or NotAfter lies, in UTC, outside
// 0001-01-01T00:00:00Z … 9999-12-31T23:59:59Z cannot be shown or stored as a time Alice's API can
// encode, so it is not a certificate Alice handles: every way a certificate comes in (a PEM upload,
// a PFX upload, a signed request, a file found on a server, its leaf or a chain certificate) refuses
// it as unreadable (ErrInvalid, ALC-CRT-0001), like a block that does not parse. The ends themselves,
// "99991231235959Z" (RFC 5280's "no expiry") included, are fine.
func TestCertificatesOutsideYears1To9999AreRefused(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	ca := pki.NewCA("Edge", pki.ECDSA256, now)
	g, u := pki.GeneralizedTime, pki.UTCTime
	issue := func(nb, na asn1.RawValue) pki.Leaf {
		return ca.IssueRawValidity(pki.Opts{CommonName: "edge.example.test", SANs: []string{"edge.example.test"}}, nb, na, now)
	}
	refused := map[string]pki.Leaf{
		"NotAfter 10000-01-01T23:58:59Z (offset -23:59)": issue(g("20260101000000Z"), g("99991231235959-2359")),
		"NotBefore -0001-12-31T00:01Z (offset +23:59)":   issue(g("00000101000000+2359"), g("20300101000000Z")),
		"both in year 0": issue(g("00000101000000Z"), g("00001231235959Z")),
		"NotAfter 10000-01-01T00:00:00Z (offset -00:01)": issue(g("20260101000000Z"), g("99991231235959-0001")),
	}
	for name, l := range refused {
		_, err := ParseChainPEM(l.FullchainPEM)
		assert.ErrorIs(t, err, ErrInvalid, name)
		_, err = ParseServedChain(l.FullchainPEM, now)
		assert.ErrorIs(t, err, ErrInvalid, name)
		_, err = ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: l.KeyPEM}, now, x509.NewCertPool())
		assert.ErrorIs(t, err, ErrInvalid, name)
		_, err = ValidateUpload(Upload{PFX: pki.PFX(l, ca, "pw"), PFXPassword: "pw"}, now, x509.NewCertPool())
		assert.ErrorIs(t, err, ErrInvalid, name)
		info, err := KeyInfoOf(mustPKCS8(t, l.Key))
		require.NoError(t, err)
		_, _, err = ValidateSigned(l.FullchainPEM, info, now, x509.NewCertPool())
		assert.ErrorIs(t, err, ErrInvalid, name)
		// As a chain certificate behind a good leaf, it makes the file unreadable like any block
		// that does not parse.
		good := ca.Issue(pki.Opts{CommonName: "good.example.test"}, now)
		_, err = ParseServedChain(append(append([]byte{}, good.CertPEM...), l.CertPEM...), now)
		assert.ErrorIs(t, err, ErrInvalid, name)
	}

	for name, l := range map[string]pki.Leaf{
		"NotAfter 9999-12-31T23:59:59Z":  issue(g("20260101000000Z"), g("99991231235959Z")),
		"NotBefore 0001-01-01T00:00:00Z": issue(g("00010101000000Z"), g("20300101000000Z")),
		"UTCTime 1965":                   issue(u("600101000000Z"), u("650101000000Z")),
	} {
		p, err := ParseServedChain(l.FullchainPEM, now)
		require.NoError(t, err, name)
		assert.True(t, p.NotAfter.Equal(l.Cert.NotAfter), name)
		if l.Cert.NotAfter.After(now) {
			_, err = ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: l.KeyPEM}, now, x509.NewCertPool())
			assert.NoError(t, err, name)
		}
	}
}

func mustPKCS8(t *testing.T, k crypto.Signer) secrets.Plaintext {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	return secrets.NewPlaintext(der)
}
