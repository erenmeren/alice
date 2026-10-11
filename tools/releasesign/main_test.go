package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license/issuer"
)

func runTool(args ...string) (int, string) {
	var out bytes.Buffer
	code := run(args, &out, &out)
	return code, out.String()
}

func TestGenerateAndSign(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "release-test-key")
	code, out := runTool("generate", dir)
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "TEST")

	// The private key is unencrypted (a throw-away key for test packages) and readable only by its owner.
	keyPath := filepath.Join(dir, "test-release.key")
	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	raw, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	priv, ok := k.(ed25519.PrivateKey)
	require.True(t, ok)

	pubRaw, err := os.ReadFile(filepath.Join(dir, "rk-test-01.pem"))
	require.NoError(t, err)
	id, pub, err := issuer.ParseReleasePublicKey(pubRaw)
	require.NoError(t, err)
	assert.Equal(t, "rk-test-01", id)
	assert.Equal(t, priv.Public(), pub)

	// generate never overwrites a key.
	code, out = runTool("generate", dir)
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "already exists")

	files := t.TempDir()
	a, b := filepath.Join(files, "SHA256SUMS"), filepath.Join(files, "alice-1.0.0-rc.1.tar.gz.sha256")
	require.NoError(t, os.WriteFile(a, []byte("aa  x\n"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("bb  y\n"), 0o644))
	code, out = runTool("sign", keyPath, a, b)
	require.Equal(t, 0, code, out)
	for _, f := range []string{a, b} {
		data, err := os.ReadFile(f)
		require.NoError(t, err)
		sig, err := os.ReadFile(f + ".sig")
		require.NoError(t, err)
		assert.Len(t, sig, ed25519.SignatureSize)
		assert.True(t, ed25519.Verify(pub, data, sig))
	}
	code, out = runTool("sign", keyPath, a)
	assert.Equal(t, 1, code, "an existing signature is never overwritten")
	assert.Contains(t, out, "already exists")

	// The tool never writes a test key where the production public keys are committed.
	repoKeys := filepath.Join(t.TempDir(), "deploy", "release", "keys")
	require.NoError(t, os.MkdirAll(repoKeys, 0o755))
	code, out = runTool("generate", repoKeys)
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "deploy/release/keys")
	assert.NoFileExists(t, filepath.Join(repoKeys, "test-release.key"))
	assert.NoFileExists(t, filepath.Join(repoKeys, "rk-test-01.pem"))
	code, out = runTool("generate", filepath.Join(repoKeys, "..", "keys"))
	assert.Equal(t, 1, code, out)

	// Usage errors.
	for _, args := range [][]string{nil, {"generate"}, {"sign", keyPath}, {"other"}} {
		code, _ = runTool(args...)
		assert.Equal(t, 2, code, args)
	}
	// A key file that is not an Ed25519 PKCS#8 key is refused.
	bad := filepath.Join(files, "bad.key")
	require.NoError(t, os.WriteFile(bad, []byte("not a key"), 0o600))
	code, _ = runTool("sign", bad, a+"x")
	assert.Equal(t, 1, code)
}
