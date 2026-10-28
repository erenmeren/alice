//go:build windows

package main

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the store's thumbprint
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/testutil/pki"
)

// thumbprint is the lower-case hex SHA-1 of a certificate, as the helper reports it.
func thumbprint(c *x509.Certificate) string {
	s := sha1.Sum(c.Raw) //nolint:gosec // the store's thumbprint
	return hex.EncodeToString(s[:])
}

// importCertificate adds a certificate without its key to LocalMachine\<store> (PowerShell's
// Import-Certificate, from the test only) and removes it when the test ends.
func importCertificate(t *testing.T, store string, c *x509.Certificate) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "alice-w1.cer")
	require.NoError(t, os.WriteFile(file, c.Raw, 0o600))
	thumb := thumbprint(c)
	t.Cleanup(func() { removeCertificate(t, store, thumb, false) })
	powershellEnv(t, map[string]string{"ALICE_W1_FILE": file, "ALICE_W1_STORE": store},
		`Import-Certificate -FilePath $env:ALICE_W1_FILE -CertStoreLocation "Cert:\LocalMachine\$env:ALICE_W1_STORE" | Out-Null`)
	return thumb
}

// importLeafWithKey imports a leaf and its key into LocalMachine\My through a PFX (Import-PfxCertificate,
// non-exportable, as an administrator would) and removes both when the test ends.
func importLeafWithKey(t *testing.T, leaf pki.Leaf) string {
	t.Helper()
	return importPFXLeaf(t, leaf, "")
}

// importLeafExportable is importLeafWithKey with an exportable key (Import-PfxCertificate -Exportable).
func importLeafExportable(t *testing.T, leaf pki.Leaf) string {
	t.Helper()
	return importPFXLeaf(t, leaf, " -Exportable")
}

func importPFXLeaf(t *testing.T, leaf pki.Leaf, flags string) string {
	t.Helper()
	pw := make([]byte, 16)
	_, err := rand.Read(pw)
	require.NoError(t, err)
	password := hex.EncodeToString(pw)
	pfx, err := pkcs12.Modern2023.Encode(leaf.Key, leaf.Cert, nil, password)
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "alice-w1.pfx")
	require.NoError(t, os.WriteFile(file, pfx, 0o600))
	thumb := thumbprint(leaf.Cert)
	t.Cleanup(func() { removeCertificate(t, "My", thumb, true) })
	powershellEnv(t, map[string]string{"ALICE_W1_FILE": file, "ALICE_W1_PASSWORD": password},
		`$pw = ConvertTo-SecureString -String $env:ALICE_W1_PASSWORD -AsPlainText -Force; `+
			`Import-PfxCertificate -FilePath $env:ALICE_W1_FILE -CertStoreLocation Cert:\LocalMachine\My -Password $pw`+flags+` | Out-Null`)
	return thumb
}

func removeCertificate(t *testing.T, store, thumb string, withKey bool) {
	t.Helper()
	// withKey deletes the key too when the certificate has one (a copy without its key is removed alone).
	script := `$p = "Cert:\LocalMachine\$env:ALICE_W1_STORE\$env:ALICE_W1_THUMB"; if (Test-Path $p) { Remove-Item -Path $p }`
	if withKey {
		script = `$p = "Cert:\LocalMachine\$env:ALICE_W1_STORE\$env:ALICE_W1_THUMB"; if (Test-Path $p) { ` +
			`if ((Get-Item -Path $p).HasPrivateKey) { Remove-Item -Path $p -DeleteKey } else { Remove-Item -Path $p } }`
	}
	if _, err := runPowershell(map[string]string{"ALICE_W1_STORE": store, "ALICE_W1_THUMB": thumb}, script); err != nil {
		t.Logf("cleanup of %s\\%s: %v", store, thumb, err)
	}
}

func TestRealCertificateFacts(t *testing.T) {
	requireReal(t)
	now := time.Now()
	ca := pki.NewCA("alice-w1", pki.RSA2048, now)
	leaf := ca.Issue(pki.Opts{CommonName: "alice-w1-cert.test", SANs: []string{"alice-w1-cert.test"}, KeyType: pki.RSA2048}, now)
	importCertificate(t, "CA", ca.Intermediate)
	thumb := importLeafWithKey(t, leaf)

	c, found, err := certificate("My", thumb, now)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), c.SHA256)
	assert.Equal(t, base64.StdEncoding.EncodeToString(leaf.Cert.Raw), c.DER)
	assert.Equal(t, leaf.Cert.NotAfter.UTC().Format(time.RFC3339), c.NotAfter)
	// The root is in no store: the machine's chain ends at the intermediate, which is kept.
	require.NotEmpty(t, c.Chain)
	assert.Equal(t, base64.StdEncoding.EncodeToString(ca.Intermediate.Raw), c.Chain[0])
	assert.True(t, c.HasKey)
	assert.Equal(t, "Microsoft Software Key Storage Provider", c.KeyProvider, "W0 F4: a PFX import lands in the software KSP")
	assert.False(t, c.KeyExportable, "Import-PfxCertificate without -Exportable")
	require.NotNil(t, c.KeyUsableBySystem, "the key's DACL is readable by an elevated administrator")
	assert.True(t, *c.KeyUsableBySystem, "W0 F4: the key DACL grants SYSTEM")
	assert.Empty(t, c.KeyProblem)

	// A certificate without its key.
	bare := ca.Issue(pki.Opts{CommonName: "alice-w1-nokey.test", SANs: []string{"alice-w1-nokey.test"}}, now)
	bareThumb := importCertificate(t, "My", bare.Cert)
	c, found, err = certificate("My", bareThumb, now)
	require.NoError(t, err)
	require.True(t, found)
	assert.False(t, c.HasKey)
	assert.Equal(t, "key_missing", c.KeyProblem)
	assert.Nil(t, c.KeyUsableBySystem)

	// A hash the store does not hold, and a store that does not exist.
	absent := make([]byte, sha1.Size)
	_, err = rand.Read(absent)
	require.NoError(t, err)
	_, found, err = certificate("My", hex.EncodeToString(absent), now)
	require.NoError(t, err)
	assert.False(t, found)
	_, found, err = certificate("alice-w1-no-such-store", thumb, now)
	require.NoError(t, err)
	assert.False(t, found)
}

// A FILETIME past 2262 (where Filetime.Nanoseconds overflows) converts without wrapping.
func TestFiletimeBeyond2262(t *testing.T) {
	ft := func(at time.Time) windows.Filetime {
		ticks := uint64(at.Unix()+11644473600)*10_000_000 + uint64(at.Nanosecond()/100) //nolint:gosec // test values after 1601
		return windows.Filetime{LowDateTime: uint32(ticks), HighDateTime: uint32(ticks >> 32)}
	}
	for _, at := range []time.Time{
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 22, 9, 30, 15, 123456700, time.UTC),
		time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		assert.True(t, at.Equal(filetime(ft(at))), "%s -> %s", at, filetime(ft(at)))
	}
	assert.False(t, filetime(ft(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC))).Before(time.Now()),
		"a certificate valid until 9999 is not expired")
}

func TestRealExpiredInStore(t *testing.T) {
	requireReal(t)
	now := time.Now()
	before, err := expiredInStore("My", now)
	require.NoError(t, err)
	ca := pki.NewCA("alice-w1-expired", pki.ECDSA256, now)
	old := ca.Issue(pki.Opts{CommonName: "alice-w1-expired.test", NotBefore: now.Add(-48 * time.Hour),
		NotAfter: now.Add(-24 * time.Hour)}, now)
	importCertificate(t, "My", old.Cert)
	after, err := expiredInStore("My", now)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, after, before+1)

	n, err := expiredInStore("alice-w1-no-such-store", now)
	require.NoError(t, err)
	assert.Zero(t, n, "a store that does not exist has no expired certificates")
}
