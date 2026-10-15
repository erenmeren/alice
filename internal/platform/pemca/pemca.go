// Package pemca checks the optional PEM authority bundle an Administrator gives for an outbound TLS connection (an
// identity provider, a directory): the certificates Alice trusts besides the system roots for that one connection.
package pemca

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
)

// Limits of a bundle.
const (
	MaxBytes = 64 << 10
	MaxCerts = 20
)

// Valid accepts "" or 1 to MaxCerts PEM CERTIFICATE blocks that parse, within MaxBytes, and nothing else (no other
// block type, no text after the last block).
func Valid(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > MaxBytes {
		return false
	}
	rest, n := []byte(s), 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" || n == MaxCerts {
			return false
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return false
		}
		n++
	}
	return n > 0 && len(bytes.TrimSpace(rest)) == 0
}

// Pool is the system roots (an empty pool when they cannot be read) plus the bundle's certificates. ok is false when
// a non-empty bundle adds no certificate.
func Pool(bundle string) (pool *x509.CertPool, ok bool) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if bundle != "" && !roots.AppendCertsFromPEM([]byte(bundle)) {
		return roots, false
	}
	return roots, true
}
