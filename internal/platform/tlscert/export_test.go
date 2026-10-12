package tlscert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// GenerateForTest exposes certificate generation with a custom organization to tests.
func GenerateForTest(t *testing.T, org string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	c, k, err := generate(org, []string{"localhost"}, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// Install stages for SetInstallHook.
const (
	StageKeyWritten     = stageKeyWritten
	StageFilesWritten   = stageFilesWritten
	StageBetweenRenames = stageBetweenRenames
)

// SetInstallHook calls f at each Install stage; a non-nil error stops Install there without any cleanup, as a
// crash would.
func SetInstallHook(s *Store, f func(stage string) error) { s.hook = f }

// SetSystemRootsForTest makes the given certificates the only system roots until restore is called.
func SetSystemRootsForTest(roots ...*x509.Certificate) (restore func()) {
	saved := systemRoots
	systemRoots = func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		for _, r := range roots {
			p.AddCert(r)
		}
		return p, nil
	}
	return func() { systemRoots = saved }
}

// SelfSignForTest issues a self-signed certificate for an existing key, without Alice's mark.
func SelfSignForTest(t *testing.T, key crypto.PrivateKey, org string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("not a signer")
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{Organization: []string{org}, CommonName: "Alice"},
		NotBefore: notBefore, NotAfter: notAfter, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// SetEnsureHook calls f at each stage of EnsureSelfSigned's write; a non-nil error stops it there without any
// cleanup, as a crash would. The returned function removes the hook.
func SetEnsureHook(f func(stage string) error) (restore func()) {
	ensureHook = f
	return func() { ensureHook = nil }
}
