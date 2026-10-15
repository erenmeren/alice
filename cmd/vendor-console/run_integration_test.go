//go:build integration

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

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

type journey struct {
	t       *testing.T
	getenv  func(string) string
	keyPath string
	dir     string
}

func newJourney(t *testing.T) *journey {
	t.Helper()
	d := vpgtest.New(t)
	j := &journey{t: t, dir: t.TempDir(), getenv: func(k string) string {
		if k == "VENDOR_DATABASE_URL" {
			return d.OwnerURL
		}
		return ""
	}}
	priv, _, err := issuer.GenerateKey("vk-2026-01", []byte(words), issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1})
	require.NoError(t, err)
	j.keyPath = filepath.Join(j.dir, "key.pem")
	require.NoError(t, os.WriteFile(j.keyPath, priv, 0o600))
	_, e, code := j.do(clock.Real{}, "migrate")
	require.Equal(t, 0, code, e)
	return j
}

func (j *journey) do(clk clock.Clock, args ...string) (string, string, int) {
	ask := func(string) ([]byte, error) { return []byte(words), nil }
	var out, errOut bytes.Buffer
	code := run(args, j.getenv, &out, &errOut, ask, clk)
	return out.String(), errOut.String(), code
}

func (j *journey) request(clk clock.Clock, from string) (reqID, hash string) {
	j.t.Helper()
	out, e, code := j.do(clk, "customer", "add", "--name", "Acme "+from)
	require.Equal(j.t, 0, code, e)
	cust := regexp.MustCompile(`\d+`).FindString(out)
	args := []string{"request", "add", "--customer", cust, "--installation", license.NewInstallationID(), "--targets", "5"}
	if from != "" {
		args = append(args, "--from", from)
	}
	out, e, code = j.do(clk, args...)
	require.Equal(j.t, 0, code, e)
	reqID = regexp.MustCompile(`\d+`).FindString(out)
	out, e, code = j.do(clk, "request", "show", reqID)
	require.Equal(j.t, 0, code, e)
	return reqID, regexp.MustCompile(`[0-9a-f]{64}`).FindString(out)
}

func TestExportReproducesTheIssuedFile(t *testing.T) {
	j := newJourney(t)
	clk := clock.Real{}
	reqID, hash := j.request(clk, "")
	first := filepath.Join(j.dir, "first.json")
	out, e, code := j.do(clk, "issue", "--request", reqID, "--hash", hash, "--key", j.keyPath, "--out", first)
	require.Equal(t, 0, code, e)
	licenseID := regexp.MustCompile(`LIC-\d+-\d+`).FindString(out)
	require.NotEmpty(t, licenseID)

	again := filepath.Join(j.dir, "again.json")
	_, e, code = j.do(clk, "license", "export", "--id", licenseID, "--out", again)
	require.Equal(t, 0, code, e)
	a, err := os.ReadFile(first)
	require.NoError(t, err)
	b, err := os.ReadFile(again)
	require.NoError(t, err)
	assert.Equal(t, a, b)

	_, e, code = j.do(clk, "license", "export", "--id", "LIC-2026-000000", "--out", filepath.Join(j.dir, "none.json"))
	assert.Equal(t, 1, code)
	assert.Contains(t, e, "not found")
}

func TestAnUnwritableOutputPathFailsBeforeAnythingIsIssued(t *testing.T) {
	j := newJourney(t)
	clk := clock.Real{}
	reqID, hash := j.request(clk, "")
	_, e, code := j.do(clk, "issue", "--request", reqID, "--hash", hash, "--key", j.keyPath,
		"--out", filepath.Join(j.dir, "no-such-dir", "x.json"))
	assert.Equal(t, 1, code)
	assert.NotEmpty(t, e)
	list, _, _ := j.do(clk, "request", "list", "--status", "open")
	assert.Contains(t, list, reqID+"  open")
}

func TestAFailedIssueLeavesNoFileBehind(t *testing.T) {
	j := newJourney(t)
	clk := clock.Real{}
	reqID, _ := j.request(clk, "")
	out := filepath.Join(j.dir, "x.json")
	_, _, code := j.do(clk, "issue", "--request", reqID, "--hash", strings.Repeat("0", 64), "--key", j.keyPath, "--out", out)
	assert.Equal(t, 1, code)
	assert.NoFileExists(t, out, "the reserved output file is removed when nothing was issued")
}

func TestAStaleStartDateTellsTheSignerWhatToDoAndACancelClosesIt(t *testing.T) {
	j := newJourney(t)
	monday := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	fake := clock.NewFake(monday)
	reqID, hash := j.request(fake, "2026-10-12")

	fake.Advance(72 * time.Hour) // signed on Thursday
	_, e, code := j.do(fake, "issue", "--request", reqID, "--hash", hash, "--key", j.keyPath,
		"--out", filepath.Join(j.dir, "late.json"))
	assert.Equal(t, 1, code)
	assert.Contains(t, e, "new request")

	_, e, code = j.do(fake, "request", "cancel", reqID)
	require.Equal(t, 0, code, e)
	list, _, _ := j.do(fake, "request", "list", "--status", "cancelled")
	assert.Contains(t, list, reqID+"  cancelled")
}
