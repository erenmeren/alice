//go:build integration

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

const words = "amber canyon violet orbit lantern quiet"

func TestIssueJourney(t *testing.T) {
	d := vpgtest.New(t)
	// The CLI connects as the migration role (a superuser); role separation has its own tests.
	getenv := func(k string) string {
		if k == "VENDOR_DATABASE_URL" {
			return d.OwnerURL
		}
		return ""
	}
	dir := t.TempDir()
	priv, _, err := issuer.GenerateKey("vk-2026-01", []byte(words), issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1})
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, priv, 0o600))
	ask := func(string) ([]byte, error) { return []byte(words), nil }

	do := func(args ...string) (string, string, int) {
		var out, errOut bytes.Buffer
		code := run(args, getenv, &out, &errOut, ask, clock.Real{})
		return out.String(), errOut.String(), code
	}

	_, e, code := do("migrate")
	require.Equal(t, 0, code, e)
	out, e, code := do("customer", "add", "--name", "Acme Ltd")
	require.Equal(t, 0, code, e)
	cust := regexp.MustCompile(`\d+`).FindString(out)
	inst := license.NewInstallationID()
	out, e, code = do("request", "add", "--customer", cust, "--installation", inst, "--targets", "5")
	require.Equal(t, 0, code, e)
	reqID := regexp.MustCompile(`\d+`).FindString(out)

	out, e, code = do("request", "show", reqID)
	require.Equal(t, 0, code, e)
	hash := regexp.MustCompile(`[0-9a-f]{64}`).FindString(out)
	require.NotEmpty(t, hash)
	assert.Contains(t, out, "Acme Ltd")
	assert.Contains(t, out, inst)

	// A wrong hash is refused and nothing is written.
	outPath := filepath.Join(dir, "out.json")
	_, e, code = do("issue", "--request", reqID, "--hash", strings.Repeat("0", 64), "--key", keyPath, "--out", outPath)
	assert.Equal(t, 1, code)
	assert.Contains(t, e, "changed")
	assert.NoFileExists(t, outPath)

	_, e, code = do("issue", "--request", reqID, "--hash", hash, "--key", keyPath, "--out", outPath)
	require.Equal(t, 0, code, e)
	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	f, err := license.ParseFile(raw)
	require.NoError(t, err)
	assert.Equal(t, inst, f.Payload.InstallationID)
	info, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the license file is not world readable")

	out, e, code = do("audit-verify")
	require.Equal(t, 0, code, e)
	assert.Contains(t, out, "OK")

	// An existing output file is never overwritten, and nothing is issued for it.
	idB, _, _ := do("request", "add", "--customer", cust, "--installation", license.NewInstallationID(), "--targets", "2")
	reqB := regexp.MustCompile(`\d+`).FindString(idB)
	showB, _, _ := do("request", "show", reqB)
	hashB := regexp.MustCompile(`[0-9a-f]{64}`).FindString(showB)
	_, e, code = do("issue", "--request", reqB, "--hash", hashB, "--key", keyPath, "--out", outPath)
	assert.Equal(t, 1, code)
	assert.Contains(t, e, "exists")
	list, _, _ := do("request", "list", "--status", "open")
	assert.Contains(t, list, "Acme Ltd")
}
