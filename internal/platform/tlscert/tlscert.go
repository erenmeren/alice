// Package tlscert manages Alice's temporary self-signed HTTPS certificate.
// A certificate supplied by the customer is never modified.
package tlscert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Organization names the certificates that Alice generates itself. It describes them; it does not decide
// ownership, which only the mark in tls.key does (markType).
const Organization = "Alice temporary certificate"

// markType is the PEM block Alice writes after the private key in tls.key when it generates the temporary
// certificate: its bytes are the SHA-256 of that certificate's DER. A pair is Alice's temporary one only when
// this mark names the live leaf. Install re-encodes an upload's key without it (encodePair), so no upload can
// carry it, and it travels with tls.key through the replace protocol, backups and restores. Go and OpenSSL
// read the first private key block of the file and skip this one.
const markType = "ALICE TEMPORARY CERTIFICATE"

const (
	validity    = 90 * 24 * time.Hour
	renewBefore = 7 * 24 * time.Hour
)

// EnsureSelfSigned returns the certificate in dir, creating or renewing
// Alice's own temporary certificate when needed. A directory an interrupted replacement left behind must be
// repaired first (NewStore does).
func EnsureSelfSigned(dir string, hosts []string, now time.Time) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	certExists, keyExists := exists(certPath), exists(keyPath)

	switch {
	case certExists && keyExists:
		c, keyPEM, err := loadPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("the HTTPS certificate in %s could not be loaded: %w", dir, err)
		}
		if !isTemporary(c.Leaf, keyPEM) || now.Before(c.Leaf.NotAfter.Add(-renewBefore)) {
			return c, nil
		}
	case certExists != keyExists:
		return tls.Certificate{}, fmt.Errorf("only one of tls.crt and tls.key exists in %s; add the missing file or remove both so Alice can create a temporary certificate", dir)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("create key directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: directory needs the execute bit
		return tls.Certificate{}, fmt.Errorf("secure key directory: %w", err)
	}
	certPEM, keyPEM, err := generateTemporary(hosts, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	// The .new/.prev protocol of Store.Renew, so a crash between the two renames leaves a pair the next start's
	// repair finishes or undoes instead of a new key beside the old certificate (review-fixes L-2).
	if err := replacePair(dir, certPEM, keyPEM, ensureHook); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ServerConfig returns the TLS settings required by SEC-031.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{ // TLS 1.2 only; TLS 1.3 suites are not configurable and are all acceptable.
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		Certificates: []tls.Certificate{cert},
	}
}

// loadPair reads and parses the pair; it also returns the key file's text, which holds Alice's mark.
func loadPair(certPath, keyPath string) (tls.Certificate, []byte, error) {
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // G304: a fixed name in the key directory
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // G304: a fixed name in the key directory
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return c, keyPEM, nil
}

// generateTemporary creates Alice's temporary certificate and its key, the key file carrying the mark.
func generateTemporary(hosts []string, now time.Time) (certPEM, keyPEM []byte, err error) {
	certPEM, keyPEM, err = generate(Organization, hosts, now.Add(-time.Hour), now.Add(validity))
	if err != nil {
		return nil, nil, err
	}
	b, _ := pem.Decode(certPEM)
	sum := sha256.Sum256(b.Bytes)
	return certPEM, append(keyPEM, pem.EncodeToMemory(&pem.Block{Type: markType, Bytes: sum[:]})...), nil
}

// isTemporary reports whether keyPEM carries Alice's mark for leaf.
func isTemporary(leaf *x509.Certificate, keyPEM []byte) bool {
	sum := sha256.Sum256(leaf.Raw)
	for rest := keyPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return false
		}
		if b.Type == markType && bytes.Equal(b.Bytes, sum[:]) {
			return true
		}
	}
}

func generate(org string, hosts []string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{org}, CommonName: "Alice"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return !errors.Is(err, os.ErrNotExist)
}

// ensureHook (tests) stops EnsureSelfSigned at a stage, as a crash would.
var ensureHook func(stage string) error
