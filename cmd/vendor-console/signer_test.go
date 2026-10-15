package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
	"alice/internal/vconsole/sign/openpgp"
	"alice/internal/vconsole/sign/openpgp/openpgptest"
)

const (
	testKeyID = "vk-2026-01"
	goodPIN   = "482915"
)

// testCard is a simulated YubiKey ready to sign licenses (forced PIN, touch on), wired into
// openCard, and a public key file for its key.
type testCard struct {
	sim     *openpgptest.Sim
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	pubPath string
	dir     string
	opened  int
}

func newTestCard(t *testing.T, change func(*openpgptest.Options)) *testCard {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	o := openpgptest.Options{Key: priv, PIN: goodPIN, PW1SingleUse: true, UIF: openpgptest.UIFOn}
	if change != nil {
		change(&o)
	}
	c := &testCard{sim: openpgptest.New(o), priv: priv, pub: pub, dir: t.TempDir()}
	c.pubPath = writeCardPub(t, c.dir, "card.pub", testKeyID, pub)
	old := openCard
	openCard = func(string) (openpgp.Card, error) { c.opened++; return c.sim, nil }
	t.Cleanup(func() { openCard = old })
	return c
}

func writeCardPub(t *testing.T, dir, name, keyID string, pub ed25519.PublicKey) string {
	t.Helper()
	raw, err := encodePublicKey(keyID, pub)
	require.NoError(t, err)
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, raw, 0o644))
	return p
}

// setProductKeys replaces this build's key set for one test.
func setProductKeys(t *testing.T, keys ...license.PublicKey) {
	t.Helper()
	old := productKeys
	productKeys = func() license.KeySet { return license.NewKeySet(keys...) }
	t.Cleanup(func() { productKeys = old })
}

// session runs one command with stdin, a PIN prompt that writes its prompt into stderr (so the
// order of everything shown is visible) and answers pin.
type session struct {
	code        int
	out, errOut string
	prompts     int
}

func runSession(getenv func(string) string, stdin io.Reader, pin string, args ...string) session {
	var out, errOut bytes.Buffer
	var mu sync.Mutex
	var s session
	ask := func(prompt string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		s.prompts++
		errOut.WriteString(prompt)
		return []byte(pin), nil
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	s.code = runWith(args, getenv, &out, &errOut, ask, clock.Real{}, console{in: stdin, secret: withContext(ask)})
	mu.Lock()
	defer mu.Unlock()
	s.out, s.errOut = out.String(), errOut.String()
	return s
}

func TestOpenPGPNeedsKeyIDAndPub(t *testing.T) {
	c := newTestCard(t, nil)
	out := filepath.Join(c.dir, "lic.json")
	base := []string{"issue", "--request", "1", "--hash", strings.Repeat("a", 64), "--out", out}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no key ID", []string{"--signer", "openpgp", "--pub", c.pubPath}, "--key-id"},
		{"no public key", []string{"--signer", "openpgp", "--key-id", testKeyID}, "--pub"},
		{"both", []string{"--signer", "openpgp", "--key-id", testKeyID, "--pub", c.pubPath, "--keyset", c.pubPath}, "one of them"},
		{"key file with a card", []string{"--signer", "openpgp", "--key", "k.pem", "--key-id", testKeyID, "--pub", c.pubPath}, "--key belongs"},
		{"card flags with the file signer", []string{"--key", "k.pem", "--key-id", testKeyID}, "--key-id"},
		{"yes with the file signer", []string{"--key", "k.pem", "--yes"}, "--yes"},
		{"unknown signer", []string{"--signer", "piv"}, "file or openpgp"},
		{"wrong key ID in the file", []string{"--signer", "openpgp", "--key-id", "vk-2026-02", "--pub", c.pubPath}, "holds key ID"},
	} {
		s := runSession(nil, strings.NewReader(""), goodPIN, append(append([]string{}, base...), tc.args...)...)
		assert.Equal(t, 2, s.code, tc.name)
		assert.Contains(t, s.errOut, tc.want, tc.name)
		assert.NoFileExists(t, out, tc.name)
	}
	assert.Zero(t, c.opened, "the card is not touched for a usage error")
	assert.Empty(t, c.sim.Commands())
}

func TestWrongKeyOnCardExitsBeforeThePINPrompt(t *testing.T) {
	c := newTestCard(t, nil)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherPub := writeCardPub(t, c.dir, "other.pub", testKeyID, other)
	out := filepath.Join(c.dir, "lic.json")
	s := runSession(nil, strings.NewReader("y\n"), goodPIN, "issue", "--signer", "openpgp", "--key-id", testKeyID, "--pub", otherPub,
		"--not-in-key-set", "--request", "1", "--hash", strings.Repeat("a", 64), "--out", out)
	assert.Equal(t, 1, s.code)
	assert.Contains(t, s.errOut, "not the key set's key")
	assert.Zero(t, s.prompts, "no PIN prompt for a card with the wrong key")
	assert.NotContains(t, s.errOut, dbEnv, "refused before the database")
	assert.Zero(t, c.sim.Count(0x20), "no VERIFY was sent")
	assert.True(t, c.sim.Closed())
	assert.NoFileExists(t, out)
}

func TestCardChecksBeforeThePINPrompt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*openpgptest.Options)
		prep   func(*openpgptest.Sim)
		want   string
	}{
		{"PIN not forced", func(o *openpgptest.Options) { o.PW1SingleUse = false }, nil, "not forced"},
		{"no touch", func(o *openpgptest.Options) { o.UIF = openpgptest.UIFOff }, nil, "touch"},
		{"last try", nil, func(s *openpgptest.Sim) { s.SetRetries(1) }, "one PIN try left"},
		{"blocked", nil, func(s *openpgptest.Sim) { s.SetRetries(0) }, "blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCard(t, tc.change)
			if tc.prep != nil {
				tc.prep(c.sim)
			}
			s := runSession(nil, strings.NewReader("y\n"), goodPIN, "issue", "--signer", "openpgp", "--key-id", testKeyID, "--pub", c.pubPath,
				"--not-in-key-set", "--request", "1", "--hash", strings.Repeat("a", 64), "--out", filepath.Join(c.dir, "lic.json"))
			assert.Equal(t, 1, s.code)
			assert.Contains(t, s.errOut, tc.want)
			assert.Zero(t, s.prompts)
			assert.Zero(t, c.sim.Count(0x20))
		})
	}
}

func TestIssueTiesTheKeyToThisBuildsKeySet(t *testing.T) {
	args := func(c *testCard, extra ...string) []string {
		return append([]string{"issue", "--signer", "openpgp", "--key-id", testKeyID, "--pub", c.pubPath,
			"--request", "1", "--hash", strings.Repeat("a", 64), "--out", filepath.Join(c.dir, "lic.json")}, extra...)
	}
	t.Run("not listed needs the flag", func(t *testing.T) {
		c := newTestCard(t, nil)
		setProductKeys(t)
		s := runSession(nil, strings.NewReader(""), goodPIN, args(c)...)
		assert.Equal(t, 2, s.code)
		assert.Contains(t, s.errOut, "WARNING: key ID vk-2026-01 is not in this build's key set")
		assert.Contains(t, s.errOut, "--not-in-key-set")
		assert.Zero(t, c.opened, "refused before the card")
		assert.NotContains(t, s.errOut, dbEnv, "refused before the database")

		s = runSession(nil, strings.NewReader(""), goodPIN, args(c, "--not-in-key-set")...)
		assert.Contains(t, s.errOut, "WARNING")
		assert.Contains(t, s.errOut, dbEnv, "with the flag it goes on (to the database, absent here)")
	})
	t.Run("different key refused", func(t *testing.T) {
		c := newTestCard(t, nil)
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		setProductKeys(t, license.PublicKey{ID: testKeyID, Key: other, Status: license.KeyActive})
		s := runSession(nil, strings.NewReader(""), goodPIN, args(c, "--not-in-key-set")...)
		assert.Equal(t, 1, s.code)
		assert.Contains(t, s.errOut, "different public key")
		assert.Zero(t, c.opened)
	})
	t.Run("revoked refused", func(t *testing.T) {
		c := newTestCard(t, nil)
		setProductKeys(t, license.PublicKey{ID: testKeyID, Key: c.pub, Status: license.KeyRevoked})
		s := runSession(nil, strings.NewReader(""), goodPIN, args(c, "--not-in-key-set")...)
		assert.Equal(t, 1, s.code)
		assert.Contains(t, s.errOut, "revoked")
		assert.Zero(t, c.opened)
	})
	t.Run("listed and active", func(t *testing.T) {
		c := newTestCard(t, nil)
		setProductKeys(t, license.PublicKey{ID: testKeyID, Key: c.pub, Status: license.KeyActive})
		s := runSession(nil, strings.NewReader(""), goodPIN, args(c)...)
		assert.NotContains(t, s.errOut, "WARNING")
		assert.Contains(t, s.errOut, dbEnv, "goes on to the database")
		assert.Zero(t, s.prompts)
	})
}

func TestIssueWithAKeySetFile(t *testing.T) {
	c := newTestCard(t, nil)
	ks, err := license.EncodeKeySet(license.PublicKey{ID: testKeyID, Key: c.pub, Status: license.KeyActive})
	require.NoError(t, err)
	ksPath := filepath.Join(c.dir, "production.json")
	require.NoError(t, os.WriteFile(ksPath, ks, 0o644))
	s := runSession(nil, strings.NewReader(""), goodPIN, "issue", "--signer", "openpgp", "--key-id", testKeyID, "--keyset", ksPath,
		"--not-in-key-set", "--request", "1", "--hash", strings.Repeat("a", 64), "--out", filepath.Join(c.dir, "lic.json"))
	assert.Contains(t, s.errOut, dbEnv, "the key set entry is accepted and the card checks pass")

	s = runSession(nil, strings.NewReader(""), goodPIN, "issue", "--signer", "openpgp", "--key-id", "vk-2026-09", "--keyset", ksPath,
		"--not-in-key-set", "--request", "1", "--hash", strings.Repeat("a", 64), "--out", filepath.Join(c.dir, "lic.json"))
	assert.Equal(t, 2, s.code)
	assert.Contains(t, s.errOut, "no key ID vk-2026-09")
}

func TestConfirmationShowsEveryFieldOfThePayload(t *testing.T) {
	p := license.Payload{LicenseID: "LIC-2026-123456", Customer: "Acme Ltd", InstallationID: license.NewInstallationID(),
		IssuedAt: time.Date(2026, 10, 15, 9, 1, 2, 0, time.UTC), ValidFrom: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC),
		ValidUntil: time.Date(2027, 4, 15, 0, 0, 0, 0, time.UTC), MaxTargets: 25, Features: []string{"alpha", "beta"},
		Format: 1, Replaces: "LIC-2026-000001"}
	var w bytes.Buffer
	writeConfirmation(&w, p, strings.Repeat("ab", 32), testKeyID, "12345678")
	got := w.String()
	for _, want := range []string{"Acme Ltd", p.InstallationID, "targets          25", "2026-10-15T00:00:00Z", "2027-04-15T00:00:00Z",
		"months           6", "alpha,beta", "LIC-2026-000001", "LIC-2026-123456", "2026-10-15T09:01:02Z", "format           1",
		testKeyID, "12345678", "SHA-256 of the signed bytes: " + strings.Repeat("ab", 32)} {
		assert.Contains(t, got, want)
	}
	// A test against forgetting a field added to the payload later: the display must be extended with it.
	assert.Equal(t, 10, reflect.TypeFor[license.Payload]().NumField(), "a new payload field must be added to the confirmation display")
}

func TestReadAnswer(t *testing.T) {
	for in, want := range map[string]string{"y\n": "y", "yes\nrest": "yes", "n\n": "n", "": "", "no newline": "no newline"} {
		got, err := readAnswer(context.Background(), strings.NewReader(in))
		require.NoError(t, err)
		assert.Equal(t, want, got, in)
	}
	// Nothing past the line is consumed: the PIN prompt reads the terminal itself.
	r := strings.NewReader("y\nsecret")
	_, err := readAnswer(context.Background(), r)
	require.NoError(t, err)
	rest, _ := io.ReadAll(r)
	assert.Equal(t, "secret", string(rest))

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = readAnswer(ctx, pr)
	assert.ErrorIs(t, err, context.DeadlineExceeded, "an unanswered question gives up with the context")
}

func TestPINPromptHonoursTheContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	blocked := withContext(func(string) ([]byte, error) { <-release; return []byte(goodPIN), nil })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := blocked(ctx, "PIN: ")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
	_, err = withContext(nil)(context.Background(), "PIN: ")
	assert.Error(t, err)
}

func TestSignerInfoPrintsFingerprintAndMatch(t *testing.T) {
	c := newTestCard(t, func(o *openpgptest.Options) { o.SigCount = 7 })
	setProductKeys(t)
	s := runSession(nil, nil, goodPIN, "signer", "info", "--key-id", testKeyID, "--pub", c.pubPath)
	require.Equal(t, 0, s.code, s.errOut)
	for _, want := range []string{"card serial          12345678", "signature algorithm  ed25519", "PIN tries left       3",
		"PIN policy           forced", "touch policy         on", "signature counter    7", "max command length   2048",
		"command chaining     yes", license.Fingerprint(c.pub), "matches key set      yes", "in this build's key set: no"} {
		assert.Contains(t, s.out, want)
	}
	assert.Zero(t, s.prompts, "no PIN for info")
	assert.Zero(t, c.sim.Count(0x20))

	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := writeCardPub(t, c.dir, "other.pub", testKeyID, other)
	s = runSession(nil, nil, goodPIN, "signer", "info", "--key-id", testKeyID, "--pub", otherPub)
	require.Equal(t, 0, s.code, s.errOut)
	assert.Contains(t, s.out, "matches key set      NO")

	setProductKeys(t, license.PublicKey{ID: testKeyID, Key: other, Status: license.KeyActive})
	s = runSession(nil, nil, goodPIN, "signer", "info", "--key-id", testKeyID)
	assert.Contains(t, s.out, "in this build's key set: DIFFERENT KEY")
	setProductKeys(t, license.PublicKey{ID: testKeyID, Key: c.pub, Status: license.KeyRevoked})
	s = runSession(nil, nil, goodPIN, "signer", "info", "--key-id", testKeyID)
	assert.Contains(t, s.out, "in this build's key set: revoked")
	setProductKeys(t, license.PublicKey{ID: testKeyID, Key: c.pub, Status: license.KeyActive})
	s = runSession(nil, nil, goodPIN, "signer", "info", "--key-id", testKeyID)
	assert.Contains(t, s.out, "in this build's key set: yes")
}

func TestSignerInfoReportsAWeakCard(t *testing.T) {
	newTestCard(t, func(o *openpgptest.Options) {
		o.PW1SingleUse, o.UIF, o.NoExtLenInfo, o.NoHistorical = false, openpgptest.UIFOff, true, true
	})
	s := runSession(nil, nil, goodPIN, "signer", "info")
	require.Equal(t, 0, s.code, s.errOut)
	assert.Contains(t, s.out, "NOT forced: signing will be refused")
	assert.Contains(t, s.out, "off (signing will be refused unless --allow-no-touch)")
	assert.Contains(t, s.out, "max command length   unknown")
	assert.Contains(t, s.out, "command chaining     unknown")
}

func TestSignerInfoWritesAPublicKeyFileLicensectlReads(t *testing.T) {
	c := newTestCard(t, nil)
	out := filepath.Join(c.dir, "vk-2026-01.pub")
	s := runSession(nil, nil, goodPIN, "signer", "info", "--key-id", testKeyID, "--out", out)
	require.Equal(t, 0, s.code, s.errOut)
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	k, err := issuer.ReadPublicKey(raw) // what licensectl keyset and verify-licenses --pub read
	require.NoError(t, err)
	assert.Equal(t, testKeyID, k.ID)
	assert.Equal(t, c.pub, k.Key)
	fi, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm())

	s = runSession(nil, nil, goodPIN, "signer", "info", "--key-id", testKeyID, "--out", out)
	assert.Equal(t, 1, s.code, "an existing file is never overwritten")

	s = runSession(nil, nil, goodPIN, "signer", "info", "--out", filepath.Join(c.dir, "x.pub"))
	assert.Equal(t, 2, s.code, "--out needs --key-id")
	s = runSession(nil, nil, goodPIN, "signer", "info", "--key-id", "not-a-key-id", "--out", filepath.Join(c.dir, "y.pub"))
	assert.Equal(t, 2, s.code)
	assert.NoFileExists(t, filepath.Join(c.dir, "y.pub"))
}

func TestPublicKeyFileIsByteForByteWhatLicensectlWrites(t *testing.T) {
	_, pubPEM, err := issuer.GenerateKey(testKeyID, []byte("amber canyon violet orbit lantern quiet"), issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1})
	require.NoError(t, err)
	k, err := issuer.ReadPublicKey(pubPEM)
	require.NoError(t, err)
	mine, err := encodePublicKey(k.ID, k.Key)
	require.NoError(t, err)
	assert.Equal(t, string(pubPEM), string(mine))
}

func TestSignerTestSignsOnlyTheFixedText(t *testing.T) {
	c := newTestCard(t, nil)
	setProductKeys(t)
	s := runSession(nil, nil, goodPIN, "signer", "test", "--key-id", testKeyID, "--pub", c.pubPath)
	require.Equal(t, 0, s.code, s.errOut)
	assert.Contains(t, s.out, "smoke test OK")
	assert.Equal(t, smokeText, string(c.sim.LastSigned()))
	assert.Equal(t, 1, s.prompts)
	assert.Contains(t, s.errOut, "not a license")
	assert.Contains(t, s.errOut, "signs nothing but licenses")
	assert.Contains(t, s.errOut, "WARNING: key ID vk-2026-01 is not in this build's key set")
	// Order: the text and warning, then the PIN prompt, then the touch notice.
	iText, iPIN, iTouch := strings.Index(s.errOut, smokeText), strings.Index(s.errOut, "PIN of the YubiKey"), strings.Index(s.errOut, "Touch the YubiKey now")
	assert.True(t, iText >= 0 && iText < iPIN && iPIN < iTouch, s.errOut)
	assert.True(t, c.sim.Closed())

	s = runSession(nil, nil, goodPIN, "signer", "test", "--key-id", testKeyID, "--pub", c.pubPath, "--max-size")
	require.Equal(t, 0, s.code, s.errOut)
	signed := c.sim.LastSigned()
	assert.Len(t, signed, smokeMaxSize)
	assert.True(t, bytes.HasPrefix(signed, []byte(smokeText)))
}

func TestSmokeTestMessagesNeverParseAsALicense(t *testing.T) {
	p := license.Payload{}
	prefix := license.SignedBytes(p)[:len(license.SignedBytes(p))-len(license.CanonicalPayload(p))]
	require.NotEmpty(t, prefix)
	ks := license.NewKeySet(license.PublicKey{ID: testKeyID, Key: make(ed25519.PublicKey, ed25519.PublicKeySize), Status: license.KeyActive})
	for _, m := range [][]byte{smokeMessage(false), smokeMessage(true)} {
		_, err := license.ParseFile(m)
		assert.Error(t, err)
		_, err = license.Check(m, ks)
		assert.Error(t, err)
		assert.False(t, bytes.HasPrefix(m, prefix), "a license signature is over the signing prefix; the smoke text never starts with it")
	}
}

func TestSignerTestMaxSizeOnACardWithoutChainingIsRefusedBeforeThePIN(t *testing.T) {
	c := newTestCard(t, func(o *openpgptest.Options) { o.NoChaining = true })
	s := runSession(nil, nil, goodPIN, "signer", "test", "--key-id", testKeyID, "--pub", c.pubPath, "--max-size")
	assert.Equal(t, 1, s.code)
	assert.Contains(t, s.errOut, "no command chaining")
	assert.Zero(t, s.prompts)
}

func TestSignerTestRefusesTheWrongKeyBeforeThePIN(t *testing.T) {
	c := newTestCard(t, nil)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := writeCardPub(t, c.dir, "other.pub", testKeyID, other)
	s := runSession(nil, nil, goodPIN, "signer", "test", "--key-id", testKeyID, "--pub", otherPub)
	assert.Equal(t, 1, s.code)
	assert.Contains(t, s.errOut, "not the key set's key")
	assert.Zero(t, s.prompts)

	setProductKeys(t, license.PublicKey{ID: testKeyID, Key: other, Status: license.KeyActive})
	s = runSession(nil, nil, goodPIN, "signer", "test", "--key-id", testKeyID, "--pub", c.pubPath)
	assert.Equal(t, 1, s.code)
	assert.Contains(t, s.errOut, "different public key")
}

func TestWrongPINShowsTriesLeftAndExits1(t *testing.T) {
	c := newTestCard(t, nil)
	s := runSession(nil, nil, "999999", "signer", "test", "--key-id", testKeyID, "--pub", c.pubPath)
	assert.Equal(t, 1, s.code)
	assert.Contains(t, s.errOut, "wrong PIN (2 tries left)")
	assert.Contains(t, s.errOut, "run the command again")
	assert.Equal(t, 1, s.prompts, "a wrong PIN is never asked again")
	assert.Equal(t, 1, c.sim.Count(0x20), "one VERIFY")
	assert.Equal(t, 2, c.sim.Retries())
	assert.Empty(t, c.sim.LastSigned())
}

func TestPINNeverAppearsInOutput(t *testing.T) {
	for _, pin := range []string{goodPIN, "731904"} {
		c := newTestCard(t, nil)
		s := runSession(nil, nil, pin, "signer", "test", "--key-id", testKeyID, "--pub", c.pubPath)
		assert.NotContains(t, s.out, pin)
		assert.NotContains(t, s.errOut, pin)
	}
}

func TestCardRemovedOrMissingIsAPlainError(t *testing.T) {
	old := openCard
	openCard = func(string) (openpgp.Card, error) { return nil, errors.New("pcsc: no card in the reader") }
	t.Cleanup(func() { openCard = old })
	s := runSession(nil, nil, goodPIN, "signer", "info")
	assert.Equal(t, 1, s.code)
	assert.Contains(t, s.errOut, "no card in the reader")
}

func TestNoPCSCBuildMessageIsAUsageError(t *testing.T) {
	c := newTestCard(t, nil)
	openCard = func(string) (openpgp.Card, error) { return nil, errNoPCSC }
	// A database URL is set: had the command reached the database, the error would name it.
	getenv := func(k string) string {
		if k == dbEnv {
			return "postgres://nobody@127.0.0.1:1/none?sslmode=disable"
		}
		return ""
	}
	for _, args := range [][]string{
		{"issue", "--signer", "openpgp", "--key-id", testKeyID, "--pub", c.pubPath, "--not-in-key-set", "--request", "1",
			"--hash", strings.Repeat("a", 64), "--out", filepath.Join(c.dir, "lic.json")},
		{"signer", "info"},
		{"signer", "test", "--key-id", testKeyID, "--pub", c.pubPath},
	} {
		s := runSession(getenv, nil, goodPIN, args...)
		assert.Equal(t, 2, s.code, args)
		assert.Contains(t, s.errOut, errNoPCSC.Error(), args)
		assert.NotContains(t, s.errOut, "database", args)
		assert.NoFileExists(t, filepath.Join(c.dir, "lic.json"))
	}
}
