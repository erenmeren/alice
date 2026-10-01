package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
)

const testWords = "amber canyon violet orbit lantern quiet"

var testClock = clock.NewFake(time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC))

func TestMain(m *testing.M) {
	issuer.KeyKDF = issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1} // throw-away test keys only
	os.Exit(m.Run())
}

// answers returns the given passphrases in turn; asking for more fails the test.
func answers(t *testing.T, list ...string) prompter {
	return func(string) ([]byte, error) {
		require.NotEmpty(t, list, "licensectl asked for a passphrase it should not need")
		a := list[0]
		list = list[1:]
		return []byte(a), nil
	}
}

func ctl(t *testing.T, stdin string, ask prompter, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errOut, ask, testClock)
	assert.NotContains(t, out.String()+errOut.String(), "amber canyon", "the passphrase is never printed")
	return code, out.String(), errOut.String()
}

func makeKey(t *testing.T, dir string) {
	t.Helper()
	code, out, errOut := ctl(t, "", answers(t, testWords, testWords), "keygen", "--out", dir, "--key-id", "vk-2026-01")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "Fingerprint: SHA256:")
}

func keysetOf(t *testing.T, dir string) license.KeySet {
	t.Helper()
	code, out, errOut := ctl(t, "", nil, "keyset", "--pub", filepath.Join(dir, issuer.PublicKeyFile))
	require.Equal(t, 0, code, errOut)
	ks, err := license.ParseKeySet([]byte(strings.SplitN(out, "\nFingerprint", 2)[0]))
	require.NoError(t, err)
	return ks
}

func TestKeygen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vendor")
	makeKey(t, dir)
	info, err := os.Stat(filepath.Join(dir, issuer.PrivateKeyFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	code, _, errOut := ctl(t, "", answers(t, testWords, testWords), "keygen", "--out", dir, "--key-id", "vk-2026-01")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "never overwrites")

	other := t.TempDir()
	code, _, errOut = ctl(t, "", answers(t, "too short"), "keygen", "--out", other, "--key-id", "vk-2026-01")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "6 words")
	code, _, errOut = ctl(t, "", answers(t, testWords, testWords+" x"), "keygen", "--out", other, "--key-id", "vk-2026-01")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "differ")
	assert.NoFileExists(t, filepath.Join(other, issuer.PrivateKeyFile))
	code, _, errOut = ctl(t, "", answers(t, testWords, testWords), "keygen", "--out", other, "--key-id", "vk-test-01")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "vk-2026-01")
	assert.NoFileExists(t, filepath.Join(other, issuer.PrivateKeyFile))
}

func issueArgs(dir, installation, out string, extra ...string) []string {
	return append([]string{"issue", "--key", filepath.Join(dir, issuer.PrivateKeyFile), "--installation", installation,
		"--customer", "Test Company", "--targets", "10", "--out", out}, extra...)
}

// §26.4: a license issued by licensectl verifies in the server; one signed with another key does not.
func TestIssuedLicenseVerifiesWithItsKeyOnly(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	id := license.NewInstallationID()
	out := filepath.Join(t.TempDir(), "alice-license-test-20261001.alicelic")
	code, stdout, errOut := ctl(t, "yes\n", answers(t, testWords), issueArgs(dir, id, out)...)
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, stdout, "Customer:      Test Company")
	assert.Contains(t, stdout, `Type "yes" to sign:`)

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	f, err := license.Check(raw, keysetOf(t, dir))
	require.NoError(t, err)
	assert.Equal(t, id, f.Payload.InstallationID)
	assert.Equal(t, 10, f.Payload.MaxTargets)
	assert.True(t, f.Payload.ValidUntil.Equal(time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)))

	otherDir := t.TempDir()
	makeKey(t, otherDir)
	_, err = license.Check(raw, keysetOf(t, otherDir))
	assert.ErrorIs(t, err, license.ErrInvalid, "same key ID, different key")

	code, stdout, _ = ctl(t, "", nil, "ledger-verify", "--pub", filepath.Join(dir, issuer.PublicKeyFile))
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "Ledger OK: 1 license")
}

// Review Focus 4: a mistyped installation ID is refused before the key is even opened.
func TestIssueRejectsMistypedInstallationID(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	id := license.NewInstallationID()
	n := len(id)
	typo := id[:n-1] + map[bool]string{true: "1", false: "0"}[id[n-1] == '0'] // corrupt the check character
	out := filepath.Join(t.TempDir(), "x.alicelic")
	code, _, errOut := ctl(t, "yes\n", answers(t), issueArgs(dir, typo, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "check each character")
	assert.NoFileExists(t, out)
}

func TestIssueNeedsYesAndTheRightPassphrase(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	id := license.NewInstallationID()
	out := filepath.Join(t.TempDir(), "x.alicelic")
	code, stdout, _ := ctl(t, "no\n", answers(t, testWords), issueArgs(dir, id, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "Nothing was signed.")
	assert.NoFileExists(t, out)
	assert.NoFileExists(t, filepath.Join(dir, issuer.LedgerFile))

	code, _, errOut := ctl(t, "yes\n", answers(t, "amber canyon violet orbit lantern loud"), issueArgs(dir, id, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "wrong passphrase")

	require.NoError(t, os.WriteFile(out, []byte("x"), 0o600))
	code, _, errOut = ctl(t, "yes\n", answers(t), issueArgs(dir, id, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "already exists")
}

// §19.2 step 4: a correction license names the license it replaces and may start earlier. The
// replaced license must be in the signed ledger; a shorter term needs --shorten.
func TestCorrectionLicense(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	id := license.NewInstallationID()
	files := t.TempDir()
	code, _, errOut := ctl(t, "yes\n", answers(t, testWords),
		issueArgs(dir, id, filepath.Join(files, "orig.alicelic"), "--license-id", "LIC-2026-000001")...)
	require.Equal(t, 0, code, errOut)

	fixArgs := issueArgs(dir, id, filepath.Join(files, "fix.alicelic"), "--replaces", "LIC-2026-000001", "--from", "2026-09-01")
	code, stdout, errOut := ctl(t, "yes\n", answers(t, testWords), fixArgs...)
	assert.Equal(t, 1, code, "2026-09-01 + 12 months ends before the original's 2027-10-01")
	assert.Contains(t, errOut, "--shorten")
	assert.NotContains(t, stdout, `Type "yes"`, "refused before asking to sign")
	assert.NoFileExists(t, filepath.Join(files, "fix.alicelic"))

	code, _, errOut = ctl(t, "yes\n", answers(t, testWords), append(fixArgs, "--shorten")...)
	require.Equal(t, 0, code, errOut)
	raw, err := os.ReadFile(filepath.Join(files, "fix.alicelic"))
	require.NoError(t, err)
	f, err := license.Check(raw, keysetOf(t, dir))
	require.NoError(t, err)
	assert.Equal(t, "LIC-2026-000001", f.Payload.Replaces)
	assert.True(t, f.Payload.IssuedAt.Equal(f.Payload.ValidFrom))

	code, _, errOut = ctl(t, "yes\n", answers(t, testWords),
		issueArgs(dir, id, filepath.Join(files, "x.alicelic"), "--replaces", "LIC-2026-999999")...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "not in the ledger")
	code, _, errOut = ctl(t, "yes\n", answers(t, testWords),
		issueArgs(dir, id, filepath.Join(files, "y.alicelic"), "--license-id", "LIC-2026-000001")...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "already issued")

	code, stdout, _ = ctl(t, "", nil, "ledger-verify", "--pub", filepath.Join(dir, issuer.PublicKeyFile))
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "Ledger OK: 2 licenses")
}

// A changed ledger is detected before anything is signed, and ledger-verify reports it.
func TestBrokenLedgerStopsIssuing(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	id := license.NewInstallationID()
	code, _, errOut := ctl(t, "yes\n", answers(t, testWords), issueArgs(dir, id, filepath.Join(t.TempDir(), "a.alicelic"))...)
	require.Equal(t, 0, code, errOut)
	ledger := filepath.Join(dir, issuer.LedgerFile)
	raw, err := os.ReadFile(ledger)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(ledger, bytes.Replace(raw, []byte(",10,"), []byte(",99,"), 1), 0o600))

	out := filepath.Join(t.TempDir(), "b.alicelic")
	code, stdout, errOut := ctl(t, "yes\n", answers(t, testWords), issueArgs(dir, id, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "ledger was changed")
	assert.NotContains(t, stdout, `Type "yes"`)
	assert.NoFileExists(t, out)

	code, stdout, _ = ctl(t, "", nil, "ledger-verify", "--pub", filepath.Join(dir, issuer.PublicKeyFile))
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "LEDGER BROKEN")
}

func TestInspectAndVerify(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	out := filepath.Join(t.TempDir(), "x.alicelic")
	code, _, errOut := ctl(t, "yes\n", answers(t, testWords), issueArgs(dir, license.NewInstallationID(), out, "--license-id", "LIC-2026-000123")...)
	require.Equal(t, 0, code, errOut)

	code, stdout, _ := ctl(t, "", nil, "inspect", out)
	require.Equal(t, 0, code)
	for _, want := range []string{"license_id:      LIC-2026-000123", "customer:        Test Company", "max_targets:     10", "format:          1"} {
		assert.Contains(t, stdout, want)
	}
	pub := filepath.Join(dir, issuer.PublicKeyFile)
	code, stdout, _ = ctl(t, "", nil, "verify", "--pub", pub, out)
	assert.Equal(t, 0, code)
	assert.Equal(t, "OK\n", stdout)

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	tampered := filepath.Join(t.TempDir(), "t.alicelic")
	changed := bytes.Replace(raw, []byte(`"max_targets": 10`), []byte(`"max_targets": 1000`), 1)
	require.NotEqual(t, raw, changed)
	require.NoError(t, os.WriteFile(tampered, changed, 0o600))
	code, stdout, _ = ctl(t, "", nil, "verify", "--pub", pub, tampered)
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "SIGNATURE INVALID")

	code, _, errOut = ctl(t, "", nil, "inspect", pub)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "Not a readable license file")
}

func TestUsage(t *testing.T) {
	code, _, errOut := ctl(t, "", nil)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "keygen")
	code, _, _ = ctl(t, "", nil, "frobnicate")
	assert.Equal(t, 2, code)
	code, _, _ = ctl(t, "", nil, "issue", "--key", "k")
	assert.Equal(t, 2, code, "missing required flags")
	code, stdout, _ := ctl(t, "", nil, "help")
	assert.Equal(t, 0, code)
	assert.True(t, strings.HasPrefix(stdout, "Usage: licensectl <command> [flags]"))
	for _, args := range [][]string{{"keygen"}, {"inspect"}, {"verify", "x"}, {"keyset"}, {"ledger-verify"}} {
		code, _, _ = ctl(t, "", nil, args...)
		assert.Equal(t, 2, code, args)
	}
}

// The ledger is written before the license file: when the ledger cannot be updated, no signed
// file is left behind.
func TestIssueWritesNothingWithoutALedgerRow(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	out := filepath.Join(t.TempDir(), "x.alicelic")
	ledgerDir := filepath.Join(t.TempDir(), "missing")
	code, _, errOut := ctl(t, "yes\n", answers(t, testWords),
		issueArgs(dir, license.NewInstallationID(), out, "--ledger", filepath.Join(ledgerDir, issuer.LedgerFile))...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "ledger could not be updated")
	assert.NoFileExists(t, out)
}
