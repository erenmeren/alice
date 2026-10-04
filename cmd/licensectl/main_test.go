package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/license/licensetest"
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

	head, err := issuer.VerifyLedgerHead(filepath.Join(dir, issuer.LedgerFile), keysetOf(t, dir).Keys()[0].Key)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Ledger rows: 1\nChain head:  "+head.Chain+"\n", "the vendor writes the head down")

	code, stdout, _ = ctl(t, "", nil, "ledger-verify", "--pub", filepath.Join(dir, issuer.PublicKeyFile))
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "Ledger OK: 1 license")
	assert.Contains(t, stdout, "Chain head:  "+head.Chain)
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
	assert.Contains(t, errOut, "lock the ledger")
	assert.NoFileExists(t, out)
}

// Fix round 1: two licensectl runs issuing at the same time both end up in a valid ledger, and
// the same license ID issued twice at the same time is recorded once; the other run fails cleanly.
func TestConcurrentIssuing(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	id := license.NewInstallationID()
	files := t.TempDir()
	issueBoth := func(ids ...string) []int {
		codes := make([]int, len(ids))
		var wg sync.WaitGroup
		for i, licID := range ids {
			// Each run writes its own file, so the ledger is the only state the two runs share.
			outFile := filepath.Join(files, licID+"-"+strconv.Itoa(i)+".alicelic")
			wg.Go(func() {
				var out, errOut bytes.Buffer
				codes[i] = run(issueArgs(dir, id, outFile, "--license-id", licID),
					strings.NewReader("yes\n"), &out, &errOut, func(string) ([]byte, error) { return []byte(testWords), nil }, testClock)
				if codes[i] != 0 {
					assert.Contains(t, errOut.String(), "already issued", "the only acceptable failure")
				}
			})
		}
		wg.Wait()
		return codes
	}
	assert.Equal(t, []int{0, 0}, issueBoth("LIC-2026-000001", "LIC-2026-000002"))
	n, err := issuer.VerifyLedger(filepath.Join(dir, issuer.LedgerFile), keysetOf(t, dir).Keys()[0].Key)
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	codes := issueBoth("LIC-2026-000003", "LIC-2026-000003")
	assert.ElementsMatch(t, []int{0, 1}, codes, "one run wins, the other is refused")
	n, err = issuer.VerifyLedger(filepath.Join(dir, issuer.LedgerFile), keysetOf(t, dir).Keys()[0].Key)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
}

// hookReader runs hook once, on the first read (while licensectl waits for "yes").
type hookReader struct {
	hook func()
	r    io.Reader
}

func (h *hookReader) Read(p []byte) (int, error) {
	if h.hook != nil {
		h.hook()
		h.hook = nil
	}
	return h.r.Read(p)
}

// The check against the ledger is repeated under the lock after "yes": a row another run added
// while this one waited for confirmation (the same license ID) makes it refuse to record.
func TestIssueRechecksTheLedgerAfterConfirmation(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	keyPEM, err := os.ReadFile(filepath.Join(dir, issuer.PrivateKeyFile))
	require.NoError(t, err)
	k, err := issuer.OpenKey(keyPEM, []byte(testWords))
	require.NoError(t, err)
	id := license.NewInstallationID()
	ledger := filepath.Join(dir, issuer.LedgerFile)
	stdin := &hookReader{r: strings.NewReader("yes\n"), hook: func() {
		require.NoError(t, issuer.AppendLedger(ledger, k, issuer.LedgerEntry{LicenseID: "LIC-2026-000777", Customer: "Other",
			InstallationID: id, IssuedAt: testClock.Now(), ValidFrom: testClock.Now(), ValidUntil: testClock.Now(), MaxTargets: 1}))
	}}
	out := filepath.Join(t.TempDir(), "x.alicelic")
	var stdout, stderr bytes.Buffer
	code := run(issueArgs(dir, id, out, "--license-id", "LIC-2026-000777"), stdin, &stdout, &stderr, answers(t, testWords), testClock)
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "already issued")
	assert.NoFileExists(t, out)
	n, err := issuer.VerifyLedger(ledger, k.Public())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the other run's row")
}

// inspect reads an unsigned file: control characters in it never reach the terminal raw, and
// the payload rules are reported.
func TestInspectEscapesControlCharacters(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	out := filepath.Join(t.TempDir(), "x.alicelic")
	code, _, errOut := ctl(t, "yes\n", answers(t, testWords), issueArgs(dir, license.NewInstallationID(), out)...)
	require.Equal(t, 0, code, errOut)
	code, stdout, _ := ctl(t, "", nil, "inspect", out)
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "payload rules:   OK")

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	evil := bytes.Replace(raw, []byte(`"customer": "Test Company"`), []byte(`"customer": "\u001b]0;owned\u0007\u001b[2JTest\u202e"`), 1)
	require.NotEqual(t, raw, evil)
	path := filepath.Join(t.TempDir(), "evil.alicelic")
	require.NoError(t, os.WriteFile(path, evil, 0o600))
	code, stdout, _ = ctl(t, "", nil, "inspect", path)
	require.Equal(t, 0, code)
	assert.NotContains(t, stdout, "\x1b")
	assert.NotContains(t, stdout, "\a")
	assert.NotContains(t, stdout, "\u202e")
	assert.Contains(t, stdout, `customer:        "\x1b]0;owned\a\x1b[2JTest\u202e"`)
	assert.Contains(t, stdout, "payload rules:   NOT VALID")

	big := filepath.Join(t.TempDir(), "big.alicelic")
	require.NoError(t, os.WriteFile(big, bytes.Repeat([]byte(" "), license.MaxFileSize+10), 0o600))
	code, _, errOut = ctl(t, "", nil, "inspect", big)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "too_large")
	code, stdout, _ = ctl(t, "", nil, "verify", "--pub", filepath.Join(dir, issuer.PublicKeyFile), big)
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "SIGNATURE INVALID")
}

func TestLedgerVerifyNeedsALedger(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	pub := filepath.Join(dir, issuer.PublicKeyFile)
	code, stdout, errOut := ctl(t, "", nil, "ledger-verify", "--pub", pub)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut+stdout, "no ledger")
	assert.NotContains(t, stdout, "Ledger OK")
	code, _, _ = ctl(t, "", nil, "ledger-verify", "--pub", pub, "--ledger", filepath.Join(dir, "other.csv"))
	assert.Equal(t, 1, code)
}

func TestIssueRefusesAnOpenKeyFileAndZeroMonths(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	id := license.NewInstallationID()
	out := filepath.Join(t.TempDir(), "x.alicelic")
	keyPath := filepath.Join(dir, issuer.PrivateKeyFile)
	require.NoError(t, os.Chmod(keyPath, 0o644))
	code, _, errOut := ctl(t, "yes\n", answers(t), issueArgs(dir, id, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "chmod 600")
	assert.NoFileExists(t, out)
	require.NoError(t, os.Chmod(keyPath, 0o600))

	code, _, errOut = ctl(t, "yes\n", answers(t), issueArgs(dir, id, out, "--months", "0")...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "--months")
	assert.NoFileExists(t, out)
}

func TestCorrectionForAnotherInstallationIsRefused(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir)
	files := t.TempDir()
	code, _, errOut := ctl(t, "yes\n", answers(t, testWords),
		issueArgs(dir, license.NewInstallationID(), filepath.Join(files, "a.alicelic"), "--license-id", "LIC-2026-000001")...)
	require.Equal(t, 0, code, errOut)
	code, _, errOut = ctl(t, "yes\n", answers(t, testWords),
		issueArgs(dir, license.NewInstallationID(), filepath.Join(files, "b.alicelic"), "--replaces", "LIC-2026-000001")...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "another installation")
}

// AUD-19: a license in a newer format is named as such only when its signature verifies; what
// licensectl issues is unchanged (format 1, checked in TestInspectAndVerify).
func TestNewerFormatIsReportedOnlyWhenSigned(t *testing.T) {
	der, err := x509.MarshalPKIXPublicKey(licensetest.PublicKey())
	require.NoError(t, err)
	dir := t.TempDir()
	pub := filepath.Join(dir, "test.pub")
	require.NoError(t, os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Key-Id": "vk-2026-09"}, Bytes: der}), 0o600))
	p := licensetest.Payload(license.NewInstallationID(), testClock.Now(), testClock.Now().AddDate(1, 0, 0), 10)
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, raw, 0o600))
		return path
	}
	newer := write("newer.alicelic", licensetest.SignFormatWith(licensetest.PrivateKey(), "vk-2026-09", p, 2, map[string]any{"seats": 5}, nil))
	code, stdout, _ := ctl(t, "", nil, "verify", "--pub", pub, newer)
	assert.Equal(t, 1, code)
	assert.Equal(t, "SIGNATURE OK, NEWER FORMAT (this licensectl cannot check the rest; use a newer licensectl)\n", stdout)
	code, _, errOut := ctl(t, "", nil, "inspect", newer)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "newer format than this licensectl reads")

	raw, err := os.ReadFile(newer)
	require.NoError(t, err)
	forged := write("forged.alicelic", bytes.Replace(raw, []byte(`"seats": 5`), []byte(`"seats": 500`), 1))
	code, stdout, _ = ctl(t, "", nil, "verify", "--pub", pub, forged)
	assert.Equal(t, 1, code)
	assert.Equal(t, "SIGNATURE INVALID (invalid_signature)\n", stdout)

	code, stdout, _ = ctl(t, "", nil, "verify", "--pub", pub, write("current.alicelic", licensetest.SignWith(licensetest.PrivateKey(), "vk-2026-09", p)))
	assert.Equal(t, 0, code)
	assert.Equal(t, "OK\n", stdout)
}
