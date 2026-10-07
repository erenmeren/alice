package notify

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"time"
)

// CertInfo describes a server certificate for the Administrator.
type CertInfo struct {
	Fingerprint string    // lower-case hex SHA-256 of the leaf DER
	Subject     string    // the leaf's subject, one line
	NotAfter    time.Time // UTC
}

// CertError is a certificate Alice did not accept; it carries the leaf the server presented (F-62).
type CertError struct{ Cert CertInfo }

// Error never carries the server's text.
func (e *CertError) Error() string { return "notify: the mail server's certificate is not trusted" }

// Unwrap makes errors.Is match ErrSMTPUntrusted and ErrSMTPTLS.
func (e *CertError) Unwrap() []error { return []error{ErrSMTPUntrusted, ErrSMTPTLS} }

func fingerprintOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func infoOf(c *x509.Certificate) CertInfo {
	return CertInfo{Fingerprint: fingerprintOf(c), Subject: oneLine(c.Subject.String()), NotAfter: c.NotAfter.UTC()}
}

// pinnedTLS accepts exactly the leaf whose SHA-256 is pin: the Administrator's "trust this certificate" (F-62, R42
// row 10). The chain and the name are not checked — the pin is the trust decision, made with step-up and audited.
// Nothing is sent before VerifyConnection passed.
func pinnedTLS(host, pin string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // G402: VerifyConnection accepts only the leaf whose SHA-256 is the pin an Administrator set (F-62)
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrSMTPTLS
			}
			leaf := cs.PeerCertificates[0]
			if subtle.ConstantTimeCompare([]byte(fingerprintOf(leaf)), []byte(pin)) != 1 {
				return &CertError{Cert: infoOf(leaf)}
			}
			return nil
		},
	}
}
