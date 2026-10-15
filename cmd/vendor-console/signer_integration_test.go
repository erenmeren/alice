//go:build integration

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/vconsole/sign/openpgp/openpgptest"
)

// cardJourney is a migrated database with one open request and a simulated YubiKey.
type cardJourney struct {
	*journey
	card          *testCard
	reqID, hash   string
	installation  string
	licenseOut    string
	issueBaseArgs []string
}

func newCardJourney(t *testing.T, change func(*openpgptest.Options)) *cardJourney {
	t.Helper()
	j := newJourney(t)
	c := newTestCard(t, change)
	setProductKeys(t)
	clk := clock.Real{}
	out, e, code := j.do(clk, "customer", "add", "--name", "Acme Ltd")
	require.Equal(t, 0, code, e)
	cust := regexp.MustCompile(`\d+`).FindString(out)
	inst := license.NewInstallationID()
	out, e, code = j.do(clk, "request", "add", "--customer", cust, "--installation", inst, "--targets", "5",
		"--months", "6", "--features", "alpha,beta")
	require.Equal(t, 0, code, e)
	reqID := regexp.MustCompile(`\d+`).FindString(out)
	out, e, code = j.do(clk, "request", "show", reqID)
	require.Equal(t, 0, code, e)
	cj := &cardJourney{journey: j, card: c, reqID: reqID, hash: regexp.MustCompile(`[0-9a-f]{64}`).FindString(out),
		installation: inst, licenseOut: filepath.Join(j.dir, "lic.json")}
	cj.issueBaseArgs = []string{"issue", "--signer", "openpgp", "--key-id", testKeyID, "--pub", c.pubPath, "--not-in-key-set",
		"--request", reqID, "--hash", cj.hash, "--out", cj.licenseOut}
	return cj
}

func (cj *cardJourney) issue(stdin io.Reader, pin string, extra ...string) session {
	return runSession(cj.getenv, stdin, pin, append(append([]string{}, cj.issueBaseArgs...), extra...)...)
}

func (cj *cardJourney) requestStatus(t *testing.T) string {
	t.Helper()
	out, e, code := cj.do(clock.Real{}, "request", "show", cj.reqID)
	require.Equal(t, 0, code, e)
	return regexp.MustCompile(`status\s+(\S+)`).FindStringSubmatch(out)[1]
}

func TestIssueOpenPGPShowsEveryFieldBeforeThePINPrompt(t *testing.T) {
	cj := newCardJourney(t, nil)
	s := cj.issue(strings.NewReader("y\n"), goodPIN)
	require.Equal(t, 0, s.code, s.errOut)
	raw, err := os.ReadFile(cj.licenseOut)
	require.NoError(t, err)
	f, err := license.ParseFile(raw)
	require.NoError(t, err)
	p := f.Payload
	sum := sha256.Sum256(license.SignedBytes(p))
	assert.Equal(t, license.SignedBytes(p), cj.card.sim.LastSigned(), "the card received exactly the signed bytes")

	e := s.errOut
	idx := func(sub string) int {
		i := strings.Index(e, sub)
		assert.GreaterOrEqual(t, i, 0, "missing %q in:\n%s", sub, e)
		return i
	}
	display := idx("The YubiKey will sign this license")
	for _, field := range []string{"Acme Ltd", cj.installation, "targets          5", p.ValidFrom.Format(time.RFC3339),
		p.ValidUntil.Format(time.RFC3339), "months           6", "alpha,beta", "replaces         (none)", p.LicenseID,
		p.IssuedAt.Format(time.RFC3339), "key ID           " + testKeyID, "card serial      12345678"} {
		assert.Greater(t, idx(field), display, field)
	}
	digest := idx("SHA-256 of the signed bytes: " + hex.EncodeToString(sum[:]))
	question := idx("Sign this license? [y/N]")
	pinPrompt := idx("PIN of the YubiKey 12345678 (3 tries left): ")
	touch := idx("Touch the YubiKey now...")
	assert.True(t, display < digest && digest < question && question < pinPrompt && pinPrompt < touch, e)
	assert.Equal(t, 1, s.prompts)
	assert.Equal(t, "signed", cj.requestStatus(t))
}

func TestAnswerNoAbortsWithoutPINPrompt(t *testing.T) {
	for _, answer := range []string{"n\n", "\n", "", "sure\n"} {
		cj := newCardJourney(t, nil)
		s := cj.issue(strings.NewReader(answer), goodPIN)
		assert.Equal(t, 1, s.code, answer)
		assert.Contains(t, s.errOut, "SHA-256 of the signed bytes", answer)
		assert.Contains(t, s.errOut, "not confirmed: nothing was signed and the request stays open", answer)
		assert.Zero(t, s.prompts, answer)
		assert.Zero(t, cj.card.sim.Count(0x20), answer)
		assert.Equal(t, "open", cj.requestStatus(t), answer)
		assert.NoFileExists(t, cj.licenseOut, answer)
		assert.True(t, cj.card.sim.Closed(), "the card is released")
	}
}

func TestYesFlagSkipsTheQuestionButStillPrints(t *testing.T) {
	cj := newCardJourney(t, nil)
	s := cj.issue(strings.NewReader(""), goodPIN, "--yes")
	require.Equal(t, 0, s.code, s.errOut)
	assert.Contains(t, s.errOut, "SHA-256 of the signed bytes")
	assert.Contains(t, s.errOut, cj.installation)
	assert.NotContains(t, s.errOut, "Sign this license?")
	assert.Equal(t, 1, s.prompts)
	assert.FileExists(t, cj.licenseOut)
}

func TestIssueWrongPINShowsTriesLeftAndExits1(t *testing.T) {
	cj := newCardJourney(t, nil)
	s := cj.issue(strings.NewReader("y\n"), "999999")
	assert.Equal(t, 1, s.code)
	assert.Contains(t, s.errOut, "wrong PIN (2 tries left)")
	assert.Equal(t, 1, s.prompts, "never asked again")
	assert.Equal(t, 1, cj.card.sim.Count(0x20))
	assert.Equal(t, "open", cj.requestStatus(t))
	assert.NoFileExists(t, cj.licenseOut)
	assert.NotContains(t, s.errOut, "999999")
	assert.NotContains(t, s.out, "999999")

	// The operator runs it again with the right PIN (same card, its counter at 2); the prompt shows the tries left.
	s = cj.issue(strings.NewReader("y\n"), goodPIN)
	require.Equal(t, 0, s.code, s.errOut)
	assert.Contains(t, s.errOut, "(2 tries left)")
	assert.NotContains(t, s.errOut, goodPIN)
	assert.NotContains(t, s.out, goodPIN)
}

func TestTheInteractiveStepHasOneTimeLimit(t *testing.T) {
	old := interactiveLimit
	interactiveLimit = 300 * time.Millisecond
	t.Cleanup(func() { interactiveLimit = old })

	t.Run("an unanswered question", func(t *testing.T) {
		cj := newCardJourney(t, nil)
		pr, pw := io.Pipe()
		defer func() { _ = pw.Close() }()
		start := time.Now()
		done := make(chan session, 1)
		go func() { done <- cj.issue(pr, goodPIN) }()
		var s session
		select {
		case s = <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("the unanswered question was not given up")
		}
		assert.Equal(t, 1, s.code)
		assert.Contains(t, s.errOut, "not confirmed and signed within")
		assert.Less(t, time.Since(start), 30*time.Second)
		assert.Zero(t, s.prompts)
		assert.True(t, cj.card.sim.Closed(), "the card connection is closed")
		assert.Equal(t, "open", cj.requestStatus(t), "the row lock was released and nothing recorded")
	})
	t.Run("a touch that never comes", func(t *testing.T) {
		cj := newCardJourney(t, func(o *openpgptest.Options) {
			o.Touch = func() bool { time.Sleep(time.Second); return true }
		})
		s := cj.issue(strings.NewReader("y\n"), goodPIN)
		assert.Equal(t, 1, s.code)
		assert.Contains(t, s.errOut, "not confirmed and signed within")
		assert.Contains(t, s.errOut, "Touch the YubiKey now")
		assert.True(t, cj.card.sim.Closed())
		assert.Equal(t, "open", cj.requestStatus(t))
		assert.NoFileExists(t, cj.licenseOut)
		out, _, _ := cj.do(clock.Real{}, "verify-licenses", "--pub", cj.card.pubPath)
		assert.Contains(t, out, "checked 0", "no license was recorded")
	})
}

func TestIssueWithTheSimulatedCardRecordsALicenseThatVerifiesAgainstTheKeySet(t *testing.T) {
	cj := newCardJourney(t, nil)
	s := cj.issue(strings.NewReader("yes\n"), goodPIN)
	require.Equal(t, 0, s.code, s.errOut)
	licenseID := regexp.MustCompile(`LIC-\d+-\d+`).FindString(s.out)
	require.NotEmpty(t, licenseID)
	raw, err := os.ReadFile(cj.licenseOut)
	require.NoError(t, err)
	f, err := license.Check(raw, license.NewKeySet(license.PublicKey{ID: testKeyID, Key: cj.card.pub, Status: license.KeyActive}))
	require.NoError(t, err)
	assert.Equal(t, cj.installation, f.Payload.InstallationID)
	assert.Equal(t, testKeyID, f.KeyID)

	// license export returns the same file; verify-licenses with the card's public key file passes.
	again := filepath.Join(cj.dir, "again.json")
	_, e, code := cj.do(clock.Real{}, "license", "export", "--id", licenseID, "--out", again)
	require.Equal(t, 0, code, e)
	b, err := os.ReadFile(again)
	require.NoError(t, err)
	assert.Equal(t, raw, b)
	out, e, code := cj.do(clock.Real{}, "verify-licenses", "--pub", cj.card.pubPath)
	require.Equal(t, 0, code, e)
	assert.Contains(t, out, "checked 1, problems 0")

	// The same through a public key file written by signer info --out.
	infoPub := filepath.Join(cj.dir, "from-card.pub")
	s = runSession(cj.getenv, nil, goodPIN, "signer", "info", "--key-id", testKeyID, "--out", infoPub)
	require.Equal(t, 0, s.code, s.errOut)
	out, e, code = cj.do(clock.Real{}, "verify-licenses", "--pub", infoPub)
	require.Equal(t, 0, code, e)
	assert.Contains(t, out, "checked 1, problems 0")

	out, e, code = cj.do(clock.Real{}, "audit-verify")
	require.Equal(t, 0, code, e)
	assert.Contains(t, out, "OK")
}
