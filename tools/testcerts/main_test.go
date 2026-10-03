package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWritesAGoodAndABrokenPair(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pack")
	require.NoError(t, run([]string{"-out", dir, "-name", "www.example.test"}, os.Stdout))
	for _, f := range []string{"ca.pem", "good.pem", "good.key", "good.pfx", "broken.pem", "broken.key"} {
		st, err := os.Stat(filepath.Join(dir, f))
		require.NoError(t, err, f)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), f)
	}
	_, err := tls.LoadX509KeyPair(filepath.Join(dir, "good.pem"), filepath.Join(dir, "good.key"))
	assert.NoError(t, err, "the good pair belongs together")
	_, err = tls.LoadX509KeyPair(filepath.Join(dir, "broken.pem"), filepath.Join(dir, "broken.key"))
	assert.Error(t, err, "the broken pair does not")
	assert.Error(t, run([]string{"-out", dir, "-name", "www.example.test"}, os.Stdout), "an existing directory is refused")
}
