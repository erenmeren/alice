package issuer_test

import (
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
)

// The license key and the release key are separate (spec §16.7, SEC-107, S-12): a key file says
// what it signs, licensectl's license commands refuse a release key and the release commands refuse
// a license key, and the purpose is bound to the encrypted key so it cannot be edited away.
func TestKeyPurposeSeparatesLicenseAndReleaseKeys(t *testing.T) {
	relPriv, relPub, err := issuer.GenerateReleaseKey("rk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	block, _ := pem.Decode(relPriv)
	require.NotNil(t, block)
	assert.Equal(t, "release", block.Headers["Alice-Key-Purpose"])
	assert.Equal(t, "rk-2026-01", block.Headers["Key-Id"])

	// A license signature never comes from a release key.
	_, err = issuer.OpenKey(relPriv, []byte(testWords))
	require.ErrorIs(t, err, issuer.ErrWrongPurpose)
	_, err = issuer.OpenKey(relPriv, []byte("wrong wrong wrong wrong wrong wrong"))
	require.ErrorIs(t, err, issuer.ErrWrongPurpose, "the purpose is checked before the passphrase")

	rk, err := issuer.OpenReleaseKey(relPriv, []byte(testWords))
	require.NoError(t, err)
	defer rk.Zero()
	assert.Equal(t, issuer.PurposeRelease, rk.Purpose())
	assert.Equal(t, "rk-2026-01", rk.KeyID())
	_, err = rk.Issue(license.Payload{})
	require.ErrorIs(t, err, issuer.ErrWrongPurpose, "a release key never issues a license")
	sig, err := rk.SignRelease([]byte("SHA256SUMS content\n"))
	require.NoError(t, err)
	id, pub, err := issuer.ParseReleasePublicKey(relPub)
	require.NoError(t, err)
	assert.Equal(t, "rk-2026-01", id)
	assert.True(t, ed25519.Verify(pub, []byte("SHA256SUMS content\n"), sig))
	assert.True(t, strings.HasPrefix(string(relPub), "key-id: rk-2026-01\n-----BEGIN PUBLIC KEY-----\n"), string(relPub))
	assert.Regexp(t, `^[0-9a-f]{64}$`, issuer.ReleaseFingerprint(pub))

	// A release signature never comes from a license key; every existing key file (no purpose
	// header) is a license key.
	licPriv, _, err := issuer.GenerateKey("vk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	block, _ = pem.Decode(licPriv)
	_, has := block.Headers["Alice-Key-Purpose"]
	assert.False(t, has, "license key files keep their format")
	_, err = issuer.OpenReleaseKey(licPriv, []byte(testWords))
	require.ErrorIs(t, err, issuer.ErrWrongPurpose)
	lk, err := issuer.OpenKey(licPriv, []byte(testWords))
	require.NoError(t, err)
	assert.Equal(t, issuer.PurposeLicense, lk.Purpose())
	_, err = lk.SignRelease([]byte("x"))
	require.ErrorIs(t, err, issuer.ErrWrongPurpose)

	// The purpose is part of what the encryption authenticates: removing the header or the block
	// type does not turn a release key into a license key.
	stripped := strings.Replace(string(relPriv), "Alice-Key-Purpose: release\n", "", 1)
	stripped = strings.ReplaceAll(stripped, "ALICE RELEASE SIGNING KEY", "ALICE LICENSE SIGNING KEY")
	stripped = strings.Replace(stripped, "Key-Id: rk-2026-01", "Key-Id: vk-2026-01", 1) // passes the license ID check
	_, err = issuer.OpenKey([]byte(stripped), []byte(testWords))
	require.ErrorIs(t, err, issuer.ErrWrongPassphrase, "the AAD (purpose) mismatch fails the decryption")
	// A release header on a license block (or the other way round) is not a key file.
	mixed := strings.ReplaceAll(string(relPriv), "ALICE RELEASE SIGNING KEY", "ALICE LICENSE SIGNING KEY")
	_, err = issuer.OpenReleaseKey([]byte(mixed), []byte(testWords))
	require.ErrorIs(t, err, issuer.ErrBadKeyFile)

	// Key IDs: release keys are rk-YYYY-NN, license keys vk-YYYY-NN.
	_, _, err = issuer.GenerateReleaseKey("vk-2026-01", []byte(testWords), fastKDF)
	require.ErrorIs(t, err, issuer.ErrBadReleaseKeyID)
	_, _, err = issuer.GenerateReleaseKey("rk-test-01", []byte(testWords), fastKDF)
	require.ErrorIs(t, err, issuer.ErrBadReleaseKeyID, "test release keys are never passphrase key files")
	_, _, err = issuer.GenerateKey("rk-2026-01", []byte(testWords), fastKDF)
	require.ErrorIs(t, err, issuer.ErrBadKeyID)
	_, _, err = issuer.GenerateReleaseKey("rk-2026-01", []byte("too weak"), fastKDF)
	require.ErrorIs(t, err, issuer.ErrWeakPassphrase)
}

func TestReleaseKeyPairFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "release")
	privPath, pubPath, err := issuer.WriteReleaseKeyPair(dir, "rk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "rk-2026-01.key"), privPath)
	assert.Equal(t, filepath.Join(dir, "rk-2026-01.pem"), pubPath)
	info, err := os.Stat(privPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	info, err = os.Stat(pubPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	_, _, err = issuer.WriteReleaseKeyPair(dir, "rk-2026-01", []byte(testWords), fastKDF)
	require.ErrorIs(t, err, issuer.ErrKeyExists)
	_, _, err = issuer.WriteReleaseKeyPair(dir, "bad", []byte(testWords), fastKDF)
	require.ErrorIs(t, err, issuer.ErrBadReleaseKeyID)
}

func TestReleasePublicKeyParsing(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	for _, id := range []string{"rk-2026-01", "rk-test-01"} {
		raw, err := issuer.EncodeReleasePublicKey(id, pub)
		require.NoError(t, err)
		gotID, got, err := issuer.ParseReleasePublicKey(raw)
		require.NoError(t, err)
		assert.Equal(t, id, gotID)
		assert.Equal(t, pub, got)
	}
	_, err = issuer.EncodeReleasePublicKey("vk-2026-01", pub)
	require.ErrorIs(t, err, issuer.ErrBadReleaseKeyID)
	good, err := issuer.EncodeReleasePublicKey("rk-2026-01", pub)
	require.NoError(t, err)
	for name, bad := range map[string]string{
		"no key-id line":  strings.SplitN(string(good), "\n", 2)[1],
		"license key id":  strings.Replace(string(good), "rk-2026-01", "vk-2026-01", 1),
		"not PEM":         "key-id: rk-2026-01\nhello\n",
		"trailing block":  string(good) + string(good),
		"private key":     "key-id: rk-2026-01\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"garbage payload": "key-id: rk-2026-01\n-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
	} {
		_, _, err := issuer.ParseReleasePublicKey([]byte(bad))
		assert.ErrorIs(t, err, issuer.ErrBadKeyFile, name)
	}
	assert.True(t, issuer.IsReleaseKeyID("rk-2026-01", false))
	assert.False(t, issuer.IsReleaseKeyID("rk-test-01", false))
	assert.True(t, issuer.IsReleaseKeyID("rk-test-01", true))
	assert.True(t, issuer.IsReleaseKeyID("rk-2026-01", true))
	assert.False(t, issuer.IsReleaseKeyID("vk-2026-01", true))
}
