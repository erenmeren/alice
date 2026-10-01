package issuer_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
)

// Throw-away test keys only: weak KDF parameters keep the tests fast.
var fastKDF = issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

const testWords = "amber canyon violet orbit lantern quiet"

func TestPassphraseRules(t *testing.T) {
	assert.NoError(t, issuer.CheckPassphrase([]byte(testWords)))
	assert.NoError(t, issuer.CheckPassphrase([]byte("amber-canyon-violet-orbit-lantern-quiet")))
	for _, weak := range []string{"", "short", "one two three four five", "a b c d e f g h", "correcthorsebatterystaple-longpassword"} {
		assert.ErrorIs(t, issuer.CheckPassphrase([]byte(weak)), issuer.ErrWeakPassphrase, weak)
	}
}

func TestKeyFileRoundTripAndProtection(t *testing.T) {
	priv, pub, err := issuer.GenerateKey("vk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	assert.Contains(t, string(priv), "-----BEGIN ALICE LICENSE SIGNING KEY-----")
	assert.Contains(t, string(priv), "Kdf: argon2id")
	assert.Contains(t, string(pub), "-----BEGIN PUBLIC KEY-----")

	k, err := issuer.OpenKey(priv, []byte(testWords))
	require.NoError(t, err)
	assert.Equal(t, "vk-2026-01", k.KeyID())
	pk, err := issuer.ReadPublicKey(pub)
	require.NoError(t, err)
	assert.Equal(t, pk.Key, k.Public())
	assert.Equal(t, "vk-2026-01", pk.ID)

	_, err = issuer.OpenKey(priv, []byte("amber canyon violet orbit lantern loud"))
	assert.ErrorIs(t, err, issuer.ErrWrongPassphrase)
	for name, bad := range map[string]string{
		"other key id": strings.Replace(string(priv), "Key-Id: vk-2026-01", "Key-Id: vk-2026-02", 1),
		"weaker kdf":   strings.Replace(string(priv), "Kdf-Params: m=64,t=1,p=1", "Kdf-Params: m=64,t=1,p=2", 1),
		"huge kdf":     strings.Replace(string(priv), "Kdf-Params: m=64,t=1,p=1", "Kdf-Params: m=99999999,t=1,p=1", 1),
		"over 1 GiB":   strings.Replace(string(priv), "Kdf-Params: m=64,t=1,p=1", "Kdf-Params: m=1048577,t=1,p=1", 1),
		"trailing":     string(priv) + "x",
	} {
		_, err := issuer.OpenKey([]byte(bad), []byte(testWords))
		assert.Error(t, err, name)
	}
	_, err = issuer.OpenKey(pub, []byte(testWords))
	assert.ErrorIs(t, err, issuer.ErrBadKeyFile)
	_, err = issuer.ReadPublicKey(priv)
	assert.ErrorIs(t, err, issuer.ErrBadKeyFile)

	js, err := json.Marshal(k)
	require.NoError(t, err)
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("key", "k", k)
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), fmt.Sprintf("%x", k), string(js), logged.String()} {
		assert.Contains(t, s, "[redacted]")
	}
	_, _, err = issuer.GenerateKey("key1", []byte(testWords), fastKDF)
	assert.ErrorIs(t, err, issuer.ErrBadKeyID)
	_, _, err = issuer.GenerateKey("vk-test-01", []byte(testWords), fastKDF)
	assert.ErrorIs(t, err, issuer.ErrBadKeyID, "the public test key ID is never a vendor key")
	_, _, err = issuer.GenerateKey("vk-2026-01", []byte("too weak"), fastKDF)
	assert.ErrorIs(t, err, issuer.ErrWeakPassphrase)

	k.Zero()
	assert.NotEqual(t, pk.Key, k.Public(), "Zero overwrites the private key")
}

func TestWriteKeyPairNeverOverwrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vendor")
	privPath, pubPath, err := issuer.WriteKeyPair(dir, "vk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	info, err := os.Stat(privPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	before, err := os.ReadFile(privPath)
	require.NoError(t, err)
	_, _, err = issuer.WriteKeyPair(dir, "vk-2026-01", []byte(testWords), fastKDF)
	assert.ErrorIs(t, err, issuer.ErrKeyExists)
	after, err := os.ReadFile(privPath)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.FileExists(t, pubPath)
}

var now = time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)

// mistype corrupts the check character (the last symbol), which the check must always catch.
func mistype(id string) string {
	n := len(id)
	repl := "0"
	if id[n-1] == '0' {
		repl = "1"
	}
	return id[:n-1] + repl
}

func TestBuildPayload(t *testing.T) {
	id := license.NewInstallationID()
	p, err := issuer.BuildPayload(issuer.Request{Installation: " " + id + " ", Customer: "Örnek Bankası A.Ş.", Targets: 100}, now)
	require.NoError(t, err)
	assert.Equal(t, id, p.InstallationID)
	assert.True(t, p.ValidFrom.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)), "today, 00:00 UTC")
	assert.True(t, p.ValidUntil.Equal(time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)), "12 months")
	assert.True(t, p.IssuedAt.Equal(now.Truncate(time.Second)))
	assert.Regexp(t, `^LIC-2026-\d{6}$`, p.LicenseID)
	assert.Equal(t, []string{}, p.Features)

	nfd := "O\u0308rnek" // "O" followed by a combining diaeresis (NFD)
	p, err = issuer.BuildPayload(issuer.Request{Installation: id, Customer: nfd, Targets: 1, From: "2026-10-15", Months: 3,
		Features: []string{" ha ", ""}, LicenseID: "LIC-X-1"}, now)
	require.NoError(t, err)
	assert.Equal(t, "Örnek", p.Customer, "customer names are NFC-normalized")
	assert.True(t, p.ValidUntil.Equal(time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)))
	assert.Equal(t, []string{"ha"}, p.Features)
	assert.Equal(t, "LIC-X-1", p.LicenseID)

	fix, err := issuer.BuildPayload(issuer.Request{Installation: id, Customer: "C", Targets: 1, From: "2026-09-01", Replaces: "LIC-X-1"}, now)
	require.NoError(t, err, "a correction license may start in the past (R7)")
	assert.True(t, fix.IssuedAt.Equal(fix.ValidFrom), "its issued_at is set to valid_from so §16.3 accepts it")

	rfc, err := issuer.BuildPayload(issuer.Request{Installation: id, Customer: "C", Targets: 1, From: "2026-10-01T12:00:00+03:00"}, now)
	require.NoError(t, err)
	assert.True(t, rfc.ValidFrom.Equal(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)))

	for name, req := range map[string]issuer.Request{
		"typo in the ID":    {Installation: mistype(id), Customer: "C", Targets: 1},
		"no customer":       {Installation: id, Targets: 1},
		"zero targets":      {Installation: id, Customer: "C"},
		"backdated renewal": {Installation: id, Customer: "C", Targets: 1, From: "2026-09-01"},
		"bad date":          {Installation: id, Customer: "C", Targets: 1, From: "01.10.2026"},
		"61 months":         {Installation: id, Customer: "C", Targets: 1, Months: 61},
		"negative months":   {Installation: id, Customer: "C", Targets: 1, Months: -1},
	} {
		_, err := issuer.BuildPayload(req, now)
		assert.Error(t, err, name)
	}
	_, err = issuer.BuildPayload(issuer.Request{Installation: mistype(id), Customer: "C", Targets: 1}, now)
	assert.ErrorContains(t, err, "check each character")
}

func openTestKey(t *testing.T) *issuer.SigningKey {
	t.Helper()
	priv, _, err := issuer.GenerateKey("vk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	k, err := issuer.OpenKey(priv, []byte(testWords))
	require.NoError(t, err)
	return k
}

// The canonical payload is what is signed: a decomposed (NFD) customer name is signed in NFC
// even when the payload did not come from BuildPayload.
func TestIssueSignsNFC(t *testing.T) {
	k := openTestKey(t)
	p, err := issuer.BuildPayload(issuer.Request{Installation: license.NewInstallationID(), Customer: "C", Targets: 1}, now)
	require.NoError(t, err)
	p.Customer = "O\u0308rnek Bankas\u0131 A.S\u0327."
	raw, err := k.Issue(p)
	require.NoError(t, err)
	f, err := license.Check(raw, license.NewKeySet(license.PublicKey{ID: k.KeyID(), Key: k.Public(), Status: license.KeyActive}))
	require.NoError(t, err)
	assert.Equal(t, "Örnek Bankası A.Ş.", f.Payload.Customer)
}

func entry(id, replaces string, until time.Time) issuer.LedgerEntry {
	return issuer.LedgerEntry{
		LicenseID: id, Customer: "Örnek, \"Bank\"", InstallationID: "ALICE-X",
		IssuedAt: now, ValidFrom: now, ValidUntil: until, MaxTargets: 10, Replaces: replaces, FileSHA256: "ab",
	}
}

func TestLedgerIsChainedAndSigned(t *testing.T) {
	k := openTestKey(t)
	path := filepath.Join(t.TempDir(), issuer.LedgerFile)
	n, err := issuer.VerifyLedger(path, k.Public())
	require.NoError(t, err, "no ledger yet")
	assert.Zero(t, n)
	for i := range 3 {
		require.NoError(t, issuer.AppendLedger(path, k, entry(fmt.Sprintf("LIC-%d", i), "", now.AddDate(1, 0, 0))))
	}
	n, err = issuer.VerifyLedger(path, k.Public())
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	entries, err := issuer.ReadLedger(path, k.Public())
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, entry("LIC-1", "", now.AddDate(1, 0, 0)), entries[1])

	other := openTestKey(t)
	_, err = issuer.VerifyLedger(path, other.Public())
	require.ErrorIs(t, err, issuer.ErrLedgerBroken, "signed by another key")

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Len(t, lines, 4, "header + 3 rows")
	for name, broken := range map[string]string{
		"edited row":     strings.Replace(string(raw), "LIC-1", "LIC-9", 1),
		"removed row":    strings.Join([]string{lines[0], lines[1], lines[3]}, "\n") + "\n",
		"reordered":      strings.Join([]string{lines[0], lines[2], lines[1], lines[3]}, "\n") + "\n",
		"short row":      strings.Join([]string{lines[0], lines[1], lines[2], "LIC-3,x"}, "\n") + "\n",
		"only short row": "LIC-3\n",
		"bad header":     strings.Replace(string(raw), "license_id", "id", 1),
		"bad csv":        string(raw) + "\"unterminated\n",
	} {
		require.NoError(t, os.WriteFile(path, []byte(broken), 0o600))
		_, err := issuer.VerifyLedger(path, k.Public())
		assert.ErrorIs(t, err, issuer.ErrLedgerBroken, name)
		err = issuer.AppendLedger(path, k, entry("LIC-NEXT", "", now))
		assert.ErrorIs(t, err, issuer.ErrLedgerBroken, "append never extends a broken ledger: "+name)
	}
}

// Correction licenses (R7, review carry-in from Task 5): the replaced license must be in the
// signed ledger, a correction may not shorten its term without --shorten, and replace chains
// may not form a cycle (every license in the cycle would be superseded).
func TestCheckAgainstLedger(t *testing.T) {
	year := now.AddDate(1, 0, 0)
	ledger := []issuer.LedgerEntry{
		entry("LIC-A", "", year),
		entry("LIC-B", "LIC-FUTURE", year), // names an ID that was never issued (only possible by hand)
	}
	pay := func(id, replaces string, until time.Time) license.Payload {
		return license.Payload{LicenseID: id, Replaces: replaces, InstallationID: "ALICE-X", ValidFrom: now, ValidUntil: until}
	}
	assert.NoError(t, issuer.CheckAgainstLedger(ledger, pay("LIC-N", "", year), false))
	assert.NoError(t, issuer.CheckAgainstLedger(ledger, pay("LIC-N", "LIC-A", year), false), "same term")
	assert.NoError(t, issuer.CheckAgainstLedger(ledger, pay("LIC-N", "LIC-A", year.AddDate(0, 1, 0)), false), "longer term")
	assert.ErrorIs(t, issuer.CheckAgainstLedger(ledger, pay("LIC-N", "LIC-A", year.Add(-time.Second)), false), issuer.ErrShortensTerm)
	assert.NoError(t, issuer.CheckAgainstLedger(ledger, pay("LIC-N", "LIC-A", year.AddDate(0, -1, 0)), true), "--shorten")
	assert.ErrorIs(t, issuer.CheckAgainstLedger(ledger, pay("LIC-N", "LIC-NOPE", year), true), issuer.ErrUnknownReplaced)
	assert.ErrorIs(t, issuer.CheckAgainstLedger(ledger, pay("LIC-A", "", year), false), issuer.ErrDuplicateLicenseID)
	assert.ErrorIs(t, issuer.CheckAgainstLedger(ledger, pay("LIC-FUTURE", "LIC-B", year), true), issuer.ErrReplaceCycle)
	other := pay("LIC-N", "LIC-A", year)
	other.InstallationID = "ALICE-Y"
	assert.ErrorIs(t, issuer.CheckAgainstLedger(ledger, other, true), issuer.ErrOtherInstallation,
		"a correction is valid for the same installation only (§19.2 step 4)")

	// A cycle already in a hand-edited ledger does not hang the walk.
	loop := []issuer.LedgerEntry{entry("LIC-C", "LIC-D", year), entry("LIC-D", "LIC-C", year)}
	assert.NoError(t, issuer.CheckAgainstLedger(loop, pay("LIC-N", "LIC-C", year), false))
}

func TestKeyFileErrorPaths(t *testing.T) {
	priv, pub, err := issuer.GenerateKey("vk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	k, err := issuer.OpenKey(priv, []byte(testWords))
	require.NoError(t, err)
	assert.Contains(t, k.String(), "[redacted]")
	assert.Contains(t, k.GoString(), "[redacted]")

	header := func(name, value string) string {
		lines := strings.Split(string(priv), "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, name+": ") {
				lines[i] = name + ": " + value
			}
		}
		return strings.Join(lines, "\n")
	}
	for name, bad := range map[string]string{
		"not PEM":        "hello",
		"bad key id":     header("Key-Id", "key1"),
		"other kdf":      header("Kdf", "scrypt"),
		"bad kdf params": header("Kdf-Params", "fast"),
		"zero threads":   header("Kdf-Params", "m=64,t=1,p=0"),
		"bad salt":       header("Salt", "!!!"),
		"short salt":     header("Salt", "AAAA"),
		"short nonce":    header("Nonce", "AAAA"),
		"short public":   header("Public-Key", "AAAA"),
	} {
		_, err := issuer.OpenKey([]byte(bad), []byte(testWords))
		assert.ErrorIs(t, err, issuer.ErrBadKeyFile, name)
	}

	der := strings.Join(strings.Split(string(pub), "\n")[3:], "\n") // drop the BEGIN line, the header and the blank line
	for name, bad := range map[string]string{
		"not PEM":     "hello",
		"no key id":   "-----BEGIN PUBLIC KEY-----\n" + der,
		"bad DER":     "-----BEGIN PUBLIC KEY-----\nKey-Id: vk-2026-01\n\nAAAA\n-----END PUBLIC KEY-----\n",
		"not ed25519": ecdsaPublicPEM,
	} {
		_, err := issuer.ReadPublicKey([]byte(bad))
		assert.ErrorIs(t, err, issuer.ErrBadKeyFile, name)
	}

	p, err := issuer.BuildPayload(issuer.Request{Installation: license.NewInstallationID(), Customer: "C", Targets: 1}, now)
	require.NoError(t, err)
	p.MaxTargets = 0
	_, err = k.Issue(p)
	assert.ErrorIs(t, err, license.ErrInvalid, "Issue validates like the server does")
}

// An ECDSA P-256 public key in PKIX form: a valid PUBLIC KEY that is not Ed25519.
const ecdsaPublicPEM = `-----BEGIN PUBLIC KEY-----
Key-Id: vk-2026-01

MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----
`

func TestWriteErrorPaths(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, issuer.PublicKeyFile), []byte("x"), 0o600))
	_, _, err := issuer.WriteKeyPair(dir, "vk-2026-01", []byte(testWords), fastKDF)
	assert.ErrorIs(t, err, issuer.ErrKeyExists, "an existing public key file is not replaced either")
	assert.NoFileExists(t, filepath.Join(dir, issuer.PrivateKeyFile))

	_, _, err = issuer.WriteKeyPair(t.TempDir(), "vk-2026-01", []byte("weak"), fastKDF)
	assert.ErrorIs(t, err, issuer.ErrWeakPassphrase)
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, _, err = issuer.WriteKeyPair(filepath.Join(file, "sub"), "vk-2026-01", []byte(testWords), fastKDF)
	assert.Error(t, err, "the directory cannot be created under a file")

	assert.ErrorIs(t, issuer.WriteNew(file, []byte("y"), 0o600), issuer.ErrKeyExists)
	assert.Error(t, issuer.WriteNew(filepath.Join(file, "sub"), []byte("y"), 0o600))
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing"), link))
	assert.ErrorIs(t, issuer.WriteNew(link, []byte("y"), 0o600), issuer.ErrKeyExists, "a dangling symlink is not followed")
}

func TestLedgerErrorPaths(t *testing.T) {
	k := openTestKey(t)
	_, err := issuer.ReadLedger(filepath.Join(t.TempDir(), issuer.LedgerFile), nil)
	assert.ErrorIs(t, err, issuer.ErrLedgerBroken, "no public key")

	_, err = issuer.VerifyLedger(t.TempDir(), k.Public())
	assert.ErrorContains(t, err, "read the ledger", "a directory is not a ledger")
	assert.ErrorContains(t, issuer.AppendLedger(t.TempDir(), k, entry("LIC-1", "", now)), "read the ledger")
	assert.Error(t, issuer.AppendLedger(filepath.Join(t.TempDir(), "missing", issuer.LedgerFile), k, entry("LIC-1", "", now)))

	blank := filepath.Join(t.TempDir(), issuer.LedgerFile)
	require.NoError(t, os.WriteFile(blank, []byte("\n\n"), 0o600))
	require.NoError(t, issuer.AppendLedger(blank, k, entry("LIC-1", "", now)), "blank lines are not a ledger yet")
	raw, err := os.ReadFile(blank)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(raw), "license_id,"), "the header is the first line")
	n, err := issuer.VerifyLedger(blank, k.Public())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

// Fix round 1: concurrent appends are serialized by the ledger lock, so the chain stays intact.
func TestConcurrentAppendsAreSerialized(t *testing.T) {
	k := openTestKey(t)
	path := filepath.Join(t.TempDir(), issuer.LedgerFile)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			assert.NoError(t, issuer.AppendLedger(path, k, entry(fmt.Sprintf("LIC-%d", i), "", now)))
		})
	}
	wg.Wait()
	head, err := issuer.VerifyLedgerHead(path, k.Public())
	require.NoError(t, err)
	assert.Equal(t, 8, head.Rows)
}

// Record re-checks the license against the ledger while holding the lock, so a row another
// licensectl added after the first check (here: the same license ID) is never duplicated.
func TestRecordRechecksUnderTheLock(t *testing.T) {
	k := openTestKey(t)
	path := filepath.Join(t.TempDir(), issuer.LedgerFile)
	p, err := issuer.BuildPayload(issuer.Request{Installation: license.NewInstallationID(), Customer: "C", Targets: 1, LicenseID: "LIC-1"}, now)
	require.NoError(t, err)
	raw, err := k.Issue(p)
	require.NoError(t, err)

	l, err := issuer.LockLedger(path)
	require.NoError(t, err)
	head, err := l.Record(k, p, raw, false)
	require.NoError(t, err)
	assert.Equal(t, 1, head.Rows)
	assert.Regexp(t, `^[0-9a-f]{64}$`, head.Chain)
	_, err = l.Record(k, p, raw, false)
	assert.ErrorIs(t, err, issuer.ErrDuplicateLicenseID)
	require.NoError(t, l.Unlock())

	entries, err := issuer.ReadLedger(path, k.Public())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	sum := sha256.Sum256(raw)
	assert.Equal(t, hex.EncodeToString(sum[:]), entries[0].FileSHA256)
	got, err := issuer.VerifyLedgerHead(path, k.Public())
	require.NoError(t, err)
	assert.Equal(t, head, got)

	_, err = issuer.LockLedger(filepath.Join(t.TempDir(), "missing", issuer.LedgerFile))
	assert.Error(t, err)
}

// Files the vendor's account may not read or write are reported, never skipped.
func TestPermissionFaults(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	k := openTestKey(t)

	unreadable := filepath.Join(t.TempDir(), issuer.LedgerFile)
	require.NoError(t, issuer.AppendLedger(unreadable, k, entry("LIC-1", "", now)))
	require.NoError(t, os.Chmod(unreadable, 0o000))
	_, err := issuer.VerifyLedgerHead(unreadable, k.Public())
	require.ErrorContains(t, err, "read the ledger")

	readOnly := filepath.Join(t.TempDir(), issuer.LedgerFile)
	require.NoError(t, issuer.AppendLedger(readOnly, k, entry("LIC-1", "", now)))
	require.NoError(t, os.Chmod(readOnly, 0o400))
	require.Error(t, issuer.AppendLedger(readOnly, k, entry("LIC-2", "", now)))
	n, err := issuer.VerifyLedger(readOnly, k.Public())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "nothing was appended")

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, _, err = issuer.WriteKeyPair(dir, "vk-2026-01", []byte(testWords), fastKDF)
	require.Error(t, err, "the key directory is not writable")
	assert.NoFileExists(t, filepath.Join(dir, issuer.PublicKeyFile))
}

func TestLedgerChecksNeedAValidKeyAndLedger(t *testing.T) {
	k := openTestKey(t)
	_, err := issuer.VerifyLedgerHead(filepath.Join(t.TempDir(), issuer.LedgerFile), nil)
	require.ErrorIs(t, err, issuer.ErrLedgerBroken)

	broken := filepath.Join(t.TempDir(), issuer.LedgerFile)
	require.NoError(t, os.WriteFile(broken, []byte("not,a,ledger\n"), 0o600))
	l, err := issuer.LockLedger(broken)
	require.NoError(t, err)
	defer func() { _ = l.Unlock() }()
	p, err := issuer.BuildPayload(issuer.Request{Installation: license.NewInstallationID(), Customer: "C", Targets: 1}, now)
	require.NoError(t, err)
	_, err = l.Record(k, p, []byte("file"), false)
	require.ErrorIs(t, err, issuer.ErrLedgerBroken, "a broken ledger is never extended")
}
