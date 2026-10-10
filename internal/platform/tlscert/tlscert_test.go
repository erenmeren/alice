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

func TestRegeneratesExpiredOwnCertificate(t *testing.T) {
	dir := t.TempDir()
	first, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)
	require.NoError(t, err)
	later := t0.Add(100 * 24 * time.Hour) // 10 days after expiry
	second, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, later)
	require.NoError(t, err)
	assert.NotEqual(t, leaf(t, first).SerialNumber, leaf(t, second).SerialNumber)
	assert.Equal(t, later.Add(90*24*time.Hour), leaf(t, second).NotAfter)
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
	assert.Equal(t, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}, cfg.CipherSuites)
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

func TestRefusesCorruptCertificateFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("not a certificate"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), []byte("not a key"), 0o600))

	_, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not be loaded")
	assert.Equal(t, []byte("not a certificate"), readFile(t, filepath.Join(dir, "tls.crt")), "a broken pair is never overwritten")
}

func TestRefusesMismatchedCertificateAndKey(t *testing.T) {
	dir := t.TempDir()
	certA, _ := tlscert.GenerateForTest(t, "Other", t0.Add(-time.Hour), t0.Add(24*time.Hour))
	_, keyB := tlscert.GenerateForTest(t, "Other", t0.Add(-time.Hour), t0.Add(24*time.Hour))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), certA, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), keyB, 0o600))

	_, err := tlscert.EnsureSelfSigned(dir, nil, t0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not be loaded")
}

func TestFailsWhenKeyDirectoryCannotBeCreated(t *testing.T) {
	// A dangling symlink is neither a usable directory nor creatable.
	link := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing"), link))

	_, err := tlscert.EnsureSelfSigned(link, []string{"localhost"}, t0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "create key directory")
}

func TestFailsWhenCertificateTargetIsADirectory(t *testing.T) {
	dir := t.TempDir()
	// A directory named tls.key counts as an existing key, so only tls.crt is
	// missing and Alice refuses instead of replacing it.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "tls.key"), 0o700))

	_, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one of tls.crt and tls.key exists")
}
