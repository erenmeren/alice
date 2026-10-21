package providers

import "crypto/x509"

// SetSystemCertPool replaces the system pool loader for a test and returns a function restoring it.
func SetSystemCertPool(f func() (*x509.CertPool, error)) (restore func()) {
	old := systemCertPool
	systemCertPool = f
	return func() { systemCertPool = old }
}
