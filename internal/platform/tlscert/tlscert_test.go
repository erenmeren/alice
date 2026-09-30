package tlscert_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/tlscert"
)

var t0 = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func leaf(t *testing.T, c tls.Certificate) *x509.Certificate {
	t.Helper()
	l, err := x509.ParseCertificate(c.Certificate[0])
	require.NoError(t, err)
	return l
}

func TestGeneratesCertificateWithHostsAndSafePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	c, err := tlscert.EnsureSelfSigned(dir, []string{"localhost", "127.0.0.1", "alice.example.com", "localhost"}, t0)
	require.NoError(t, err)

	l := leaf(t, c)
	assert.Equal(t, []string{"localhost", "alice.example.com"}, l.DNSNames)
	require.Len(t, l.IPAddresses, 1)
	assert.True(t, l.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
	assert.Equal(t, []string{tlscert.Organization}, l.Subject.Organization)
	assert.Equal(t, t0.Add(90*24*time.Hour), l.NotAfter)
	assert.Equal(t, x509.ECDSA, l.PublicKeyAlgorithm)

	st, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), st.Mode().Perm())
	st, err = os.Stat(filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o400), st.Mode().Perm())
}

func TestReusesValidCertificate(t *testing.T) {
	dir := t.TempDir()
	first, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)
	require.NoError(t, err)
	second, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0.Add(30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, leaf(t, first).SerialNumber, leaf(t, second).SerialNumber)
}

func TestRegeneratesOwnCertificateNearExpiry(t *testing.T) {
	dir := t.TempDir()
	first, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)
	require.NoError(t, err)
	later := t0.Add(84 * 24 * time.Hour) // 6 days before expiry
	second, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, later)
	require.NoError(t, err)
	assert.NotEqual(t, leaf(t, first).SerialNumber, leaf(t, second).SerialNumber)
	assert.Equal(t, later.Add(90*24*time.Hour), leaf(t, second).NotAfter)
	st, err := os.Stat(filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o400), st.Mode().Perm())
}

func TestNeverOverwritesUserCertificateEvenWhenExpired(t *testing.T) {
	dir := t.TempDir()
	// Simulate a user-supplied certificate: generate one, then re-sign it without the Alice marker.
	userCert, userKey := writeForeignCertificate(t, dir, t0.Add(-100*24*time.Hour), t0.Add(-1*time.Hour))
	c, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)
	require.NoError(t, err)
	assert.Equal(t, userCert, readFile(t, filepath.Join(dir, "tls.crt")))
	assert.Equal(t, userKey, readFile(t, filepath.Join(dir, "tls.key")))
	assert.NotEqual(t, []string{tlscert.Organization}, leaf(t, c).Subject.Organization)
}

func TestRefusesWhenOnlyOneFileExists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("x"), 0o644))
	_, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)
	require.Error(t, err)
	_, statErr := os.Stat(filepath.Join(dir, "tls.key"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestServerConfig(t *testing.T) {
	c, err := tlscert.EnsureSelfSigned(t.TempDir(), []string{"localhost"}, t0)
	require.NoError(t, err)
	cfg := tlscert.ServerConfig(c)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Equal(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}, cfg.CurvePreferences)
	for _, id := range cfg.CipherSuites {
		name := tls.CipherSuiteName(id)
		assert.Regexp(t, `^TLS_ECDHE_(ECDSA|RSA)_WITH_(AES_\d+_GCM_SHA\d+|CHACHA20_POLY1305_SHA256)$`, name)
	}
	assert.Len(t, cfg.Certificates, 1)
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}

// writeForeignCertificate writes a self-signed certificate that Alice did not generate.
func writeForeignCertificate(t *testing.T, dir string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	certPEM, keyPEM = tlscert.GenerateForTest(t, "Customer Corp", notBefore, notAfter)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600))
	return certPEM, keyPEM
}
