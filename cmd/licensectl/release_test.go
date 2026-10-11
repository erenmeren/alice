package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
)

func makeReleaseKey(t *testing.T, dir, id string) (keyPath, pubPath string) {
	t.Helper()
	code, out, errOut := ctl(t, "", answers(t, testWords, testWords), "release-keygen", "--out", dir, "--key-id", id)
	require.Equal(t, 0, code, errOut)
	assert.Regexp(t, `Fingerprint \(SHA-256\): [0-9a-f]{64}\n`, out)
	return filepath.Join(dir, id+".key"), filepath.Join(dir, id+".pem")
}

// S-12: release IDs are rk-YYYY-NN, keygen never overwrites, and the release key never lands in the
// license key directory (or in deploy/release/keys, which is committed).
func TestReleaseKeygenRefusesOverwriteAndLicenseIDs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "release")
	keyPath, pubPath := makeReleaseKey(t, dir, "rk-2026-01")
	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	raw, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(raw), "key-id: rk-2026-01\n"))

	code, _, errOut := ctl(t, "", answers(t, testWords, testWords), "release-keygen", "--out", dir, "--key-id", "rk-2026-01")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "never overwrites")

	other := t.TempDir()
	for _, id := range []string{"vk-2026-01", "rk-test-01", "rk-26-01"} {
		code, _, errOut = ctl(t, "", answers(t), "release-keygen", "--out", other, "--key-id", id)
		assert.Equal(t, 2, code, id)
		assert.Contains(t, errOut, "rk-2026-01", id)
	}

	licenseDir := t.TempDir()
	makeKey(t, licenseDir)
	code, _, errOut = ctl(t, "", answers(t), "release-keygen", "--out", licenseDir, "--key-id", "rk-2026-02")
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "license key directory")
	assert.NoFileExists(t, filepath.Join(licenseDir, "rk-2026-02.key"))

	repoKeys := filepath.Join(t.TempDir(), "deploy", "release", "keys")
	code, _, errOut = ctl(t, "", answers(t), "release-keygen", "--out", repoKeys, "--key-id", "rk-2026-02")
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "deploy/release/keys")
	assert.NoDirExists(t, repoKeys)

	code, _, errOut = ctl(t, "", answers(t, "too short"), "release-keygen", "--out", other, "--key-id", "rk-2026-02")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "6 words")
	code, _, errOut = ctl(t, "", answers(t, testWords, testWords+" x"), "release-keygen", "--out", other, "--key-id", "rk-2026-02")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "differ")
	assert.NoFileExists(t, filepath.Join(other, "rk-2026-02.key"))

	// licensectl issue refuses a release key, release-sign refuses a license key.
	inst := license.NewInstallationID()
	code, _, errOut = ctl(t, "yes\n", answers(t, testWords), "issue", "--key", keyPath, "--installation", inst,
		"--customer", "Test Company", "--targets", "10", "--out", filepath.Join(t.TempDir(), "x.alicelic"))
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "another purpose")
	file := filepath.Join(t.TempDir(), "SHA256SUMS")
	require.NoError(t, os.WriteFile(file, []byte("x\n"), 0o644))
	code, _, errOut = ctl(t, "", answers(t, testWords), "release-sign", "--key", filepath.Join(licenseDir, issuer.PrivateKeyFile), file)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "another purpose")
	assert.NoFileExists(t, file+".sig")
}

func TestReleaseSignAsksOnceAndSignsEachFile(t *testing.T) {
	keyPath, pubPath := makeReleaseKey(t, filepath.Join(t.TempDir(), "k"), "rk-2026-01")
	files := t.TempDir()
	a, b := filepath.Join(files, "SHA256SUMS"), filepath.Join(files, "alice-1.0.0.tar.gz.sha256")
	require.NoError(t, os.WriteFile(a, []byte("aaa  install.sh\n"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("bbb  alice-1.0.0.tar.gz\n"), 0o644))

	code, out, errOut := ctl(t, "", answers(t, testWords), "release-sign", "--key", keyPath, a, b)
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "rk-2026-01")
	_, pub := readPub(t, pubPath)
	for _, f := range []string{a, b} {
		data, err := os.ReadFile(f)
		require.NoError(t, err)
		sig, err := os.ReadFile(f + ".sig")
		require.NoError(t, err)
		require.Len(t, sig, ed25519.SignatureSize, "a raw 64-byte signature (C5)")
		assert.True(t, ed25519.Verify(pub, data, sig))
		assert.Contains(t, out, f+".sig")

		code, vout, _ := ctl(t, "", nil, "release-verify", "--pub", pubPath, f, f+".sig")
		assert.Equal(t, 0, code)
		assert.Contains(t, vout, "OK")
	}
	code, vout, _ := ctl(t, "", nil, "release-verify", "--pub", pubPath, a, b+".sig")
	assert.Equal(t, 1, code)
	assert.Contains(t, vout, "SIGNATURE INVALID")

	// An existing signature is never overwritten, and nothing is asked before that is known.
	code, _, errOut = ctl(t, "", answers(t), "release-sign", "--key", keyPath, a)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "already exists")
	// A wrong passphrase signs nothing.
	c := filepath.Join(files, "other")
	require.NoError(t, os.WriteFile(c, []byte("c\n"), 0o644))
	code, _, errOut = ctl(t, "", answers(t, "amber canyon violet orbit lantern loud"), "release-sign", "--key", keyPath, c)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "wrong passphrase")
	assert.NoFileExists(t, c+".sig")
	// Only checksum files are signed, never a tarball.
	big := filepath.Join(files, "big")
	require.NoError(t, os.WriteFile(big, make([]byte, 2<<20), 0o644))
	code, _, errOut = ctl(t, "", answers(t), "release-sign", "--key", keyPath, big)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "checksum")
	// A key file others can read is refused.
	require.NoError(t, os.Chmod(keyPath, 0o640))
	code, _, errOut = ctl(t, "", answers(t), "release-sign", "--key", keyPath, c)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "chmod 600")
	code, _, _ = ctl(t, "", answers(t), "release-sign", "--key", keyPath)
	assert.Equal(t, 2, code)
}

func readPub(t *testing.T, path string) (string, ed25519.PublicKey) {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	id, pub, err := issuer.ParseReleasePublicKey(raw)
	require.NoError(t, err)
	return id, pub
}

// C5: the host scripts verify with exactly this OpenSSL command. This machine and every CI runner
// have OpenSSL 3; without it the test fails, it never skips.
func TestOpenSSLVerifiesReleaseSignatures(t *testing.T) {
	_, err := exec.LookPath("openssl")
	require.NoError(t, err, "OpenSSL 3 is required for this test")
	keyPath, pubPath := makeReleaseKey(t, filepath.Join(t.TempDir(), "k"), "rk-2026-01")
	file := filepath.Join(t.TempDir(), "SHA256SUMS")
	require.NoError(t, os.WriteFile(file, []byte("0123  install.sh\n4567  alicectl\n"), 0o644))
	code, _, errOut := ctl(t, "", answers(t, testWords), "release-sign", "--key", keyPath, file)
	require.Equal(t, 0, code, errOut)

	verify := func() (string, error) {
		out, err := exec.Command("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pubPath, "-rawin",
			"-in", file, "-sigfile", file+".sig").CombinedOutput() //nolint:gosec // test paths
		return string(out), err
	}
	out, err := verify()
	require.NoError(t, err, out)
	assert.Contains(t, out, "Signature Verified Successfully")

	// The fingerprint licensectl prints is the one install.sh computes with OpenSSL.
	der, err := exec.Command("openssl", "pkey", "-pubin", "-in", pubPath, "-outform", "DER").Output() //nolint:gosec // test path
	require.NoError(t, err)
	_, pub := readPub(t, pubPath)
	assert.Equal(t, issuer.ReleaseFingerprint(pub), sha256Hex(der))

	data, err := os.ReadFile(file)
	require.NoError(t, err)
	data[0] ^= 1
	require.NoError(t, os.WriteFile(file, data, 0o644))
	out, err = verify()
	require.Error(t, err, "one changed byte fails: %s", out)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
