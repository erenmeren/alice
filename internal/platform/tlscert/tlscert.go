// Package tlscert manages Alice's temporary self-signed HTTPS certificate.
// A certificate supplied by the customer is never modified.
package tlscert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"slices"
	"time"
)

// Organization marks certificates that Alice generated itself.
const Organization = "Alice temporary certificate"

const (
	validity    = 90 * 24 * time.Hour
	renewBefore = 7 * 24 * time.Hour
)

// EnsureSelfSigned returns the certificate in dir, creating or renewing
// Alice's own temporary certificate when needed.
func EnsureSelfSigned(dir string, hosts []string, now time.Time) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	certExists, keyExists := exists(certPath), exists(keyPath)

	switch {
	case certExists && keyExists:
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("the HTTPS certificate in %s could not be loaded: %w", dir, err)
		}
		l, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("the HTTPS certificate in %s is not valid: %w", dir, err)
		}
		if !slices.Contains(l.Subject.Organization, Organization) || now.Before(l.NotAfter.Add(-renewBefore)) {
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
	certPEM, keyPEM, err := generate(Organization, hosts, now.Add(-time.Hour), now.Add(validity))
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writeAtomic(keyPath, keyPEM, 0o400); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
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

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := bytes.NewReader(data).WriteTo(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return !errors.Is(err, os.ErrNotExist)
}
