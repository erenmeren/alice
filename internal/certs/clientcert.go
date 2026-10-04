package certs

import (
	"crypto/x509"
	"time"

	"alice/internal/platform/azureid"
	"alice/internal/secrets"
)

// ClientCertificate is a service principal's sign-in certificate (spec §11.3). PrivateKeyDER is
// the caller's to zero.
type ClientCertificate struct {
	CertificateDER []byte            // the leaf
	PrivateKeyDER  secrets.Plaintext // PKCS #8 RSA
	Thumbprint     string            // hex SHA-1 (what Azure shows as the certificate's thumbprint)
	NotBefore      time.Time
	NotAfter       time.Time
}

// ParseClientCertificate validates an upload as a sign-in certificate: ValidateUpload (key match,
// expiry, key and signature strength, size and iteration bounds, date range), then an RSA key (MSAL
// signs PS256; ErrClientCertKey otherwise). Errors never contain input and no key comes back with
// one. A certificate that is not valid yet is read: NotBefore tells the caller.
func ParseClientCertificate(u Upload, now time.Time, roots *x509.CertPool) (ClientCertificate, error) {
	return parseClientCertificate(u, now, roots, nil)
}

// parseClientCertificate is ParseClientCertificate; observe (a test hook) sees the key copy that is
// cleared when the certificate is refused for its key type.
func parseClientCertificate(u Upload, now time.Time, roots *x509.CertPool, observe func(der []byte)) (ClientCertificate, error) {
	v, err := ValidateUpload(u, now, roots)
	if err != nil {
		return ClientCertificate{}, err
	}
	if v.Algorithm != "rsa" {
		if observe != nil {
			observe(v.PrivateKeyDER.Bytes())
		}
		v.PrivateKeyDER.Zero()
		return ClientCertificate{}, ErrClientCertKey
	}
	return ClientCertificate{CertificateDER: v.Leaf.Raw, PrivateKeyDER: v.PrivateKeyDER,
		Thumbprint: azureid.ThumbprintOf(v.Leaf.Raw), NotBefore: v.NotBefore, NotAfter: v.NotAfter}, nil
}
