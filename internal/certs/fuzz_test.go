package certs

import (
	"crypto/x509"
	"testing"

	"alice/internal/testutil/pki"
)

// §25.6 FuzzParseCertificateUpload: hostile PEM/PFX/DER never panics, never takes unbounded
// memory, and never accepts a pair whose key does not match.
func FuzzParseCertificateUpload(f *testing.F) {
	ca := pki.NewCA("Alice Fuzz", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	f.Add(l.FullchainPEM, l.KeyPEM, []byte(nil), "")
	f.Add([]byte(nil), []byte(nil), pki.PFX(l, ca, "pw"), "pw")
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), l.KeyPEM, []byte(nil), "")
	f.Add(l.Cert.Raw, l.KeyPEM, []byte(nil), "")
	f.Fuzz(func(t *testing.T, cert, key, pfx []byte, pw string) {
		v, err := ValidateUpload(Upload{CertificatePEM: cert, PrivateKeyPEM: key, PFX: pfx, PFXPassword: pw}, now, x509.NewCertPool())
		if err != nil {
			return
		}
		defer v.PrivateKeyDER.Zero()
		info, err := KeyInfoOf(v.PrivateKeyDER)
		if err != nil || info.PublicKeySHA256 != v.PublicKeySHA256 {
			t.Fatalf("accepted a key that does not match the leaf")
		}
	})
}
