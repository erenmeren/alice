//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/sign/openpgp"
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
	t.Run("a late touch after the limit", func(t *testing.T) {
		cj := newCardJourney(t, func(o *openpgptest.Options) {
			o.Touch = func() bool { time.Sleep(time.Second); return true }
		})
		s := cj.issue(strings.NewReader("y\n"), goodPIN)
		assert.Equal(t, 1, s.code)
		// The simulated card signs once the late touch comes, after the limit: it made a signature.
		assert.Contains(t, s.errOut, "the card made a signature (its signature counter went up) but no license was recorded")
		assert.Contains(t, s.errOut, "Touch the YubiKey now")
		assert.True(t, cj.card.sim.Closed())
		assert.Equal(t, "open", cj.requestStatus(t))
		assert.NoFileExists(t, cj.licenseOut)
		out, _, _ := cj.do(clock.Real{}, "verify-licenses", "--pub", cj.card.pubPath)
		assert.Contains(t, out, "checked 0", "no license was recorded")
	})
	t.Run("no touch at all", func(t *testing.T) {
		cj := newCardJourney(t, func(o *openpgptest.Options) {
			o.Touch = func() bool { return false } // the card gives up waiting (its own touch timeout)
		})
		before := cj.card.sim.SigCount()
		s := cj.issue(strings.NewReader("y\n"), goodPIN)
		assert.Equal(t, 1, s.code)
		assert.Contains(t, s.errOut, "Touch the YubiKey now")
		assert.Contains(t, s.errOut, "not touched in time")
		assert.NotContains(t, s.errOut, "the card made a signature")
		assert.Equal(t, before, cj.card.sim.SigCount(), "the signature counter is unchanged")
		assert.Empty(t, cj.card.sim.LastSigned())
		assert.Equal(t, "open", cj.requestStatus(t))
		assert.NoFileExists(t, cj.licenseOut)
		assert.Equal(t, "checked 0", cj.licenseCount(t))
	})
}

// A license whose signed bytes are longer than the size the smoke test proved is refused after
// the confirmation display (which shows the size) and before the PIN prompt.
func TestIssueRefusesALicenseLongerThanTheProvenSize(t *testing.T) {
	cj := newCardJourney(t, nil)
	features := make([]string, 20)
	for i := range features {
		features[i] = fmt.Sprintf("feature-%02d-%s", i, strings.Repeat("x", 50))
	}
	clk := clock.Real{}
	out, e, code := cj.do(clk, "request", "add", "--customer", "1", "--installation", license.NewInstallationID(), "--targets", "5",
		"--months", "6", "--features", strings.Join(features, ","))
	require.Equal(t, 0, code, e)
	reqID := regexp.MustCompile(`\d+`).FindString(out)
	out, e, code = cj.do(clk, "request", "show", reqID)
	require.Equal(t, 0, code, e)
	hash := regexp.MustCompile(`[0-9a-f]{64}`).FindString(out)
	s := runSession(cj.getenv, strings.NewReader("y\n"), goodPIN, "issue", "--signer", "openpgp", "--key-id", testKeyID,
		"--pub", cj.card.pubPath, "--not-in-key-set", "--request", reqID, "--hash", hash, "--out", cj.licenseOut)
	assert.Equal(t, 1, s.code)
	size := regexp.MustCompile(`signed bytes: (\d+) bytes`).FindStringSubmatch(s.errOut)
	require.Len(t, size, 2, s.errOut)
	assert.Contains(t, s.errOut, "the license's signed bytes are "+size[1]+" bytes")
	assert.Contains(t, s.errOut, fmt.Sprintf("the smoke test proved %d bytes", sign.MaxSignedBytes))
	assert.Zero(t, s.prompts, "no PIN prompt")
	assert.Zero(t, cj.card.sim.Count(0x20))
	assert.NoFileExists(t, cj.licenseOut)
	out, e, code = cj.do(clk, "request", "show", reqID)
	require.Equal(t, 0, code, e)
	assert.Regexp(t, `status\s+open`, out)
}

// Ctrl-C after the touch notice: the card may have signed if the key was touched, so the message
// does not claim that nothing was signed.
func TestCancelAfterTheTouchNoticeDoesNotClaimNothingWasSigned(t *testing.T) {
	var cancel context.CancelFunc
	oldCtx := interruptContext
	interruptContext = func(ctx context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel = context.WithCancel(ctx)
		return ctx, cancel
	}
	t.Cleanup(func() { interruptContext = oldCtx })
	cj := newCardJourney(t, func(o *openpgptest.Options) {
		o.Touch = func() bool { cancel(); time.Sleep(50 * time.Millisecond); return false }
	})
	s := cj.issue(strings.NewReader("y\n"), goodPIN)
	assert.Equal(t, 1, s.code)
	assert.Contains(t, s.errOut, "Touch the YubiKey now")
	assert.Contains(t, s.errOut, "signing cancelled: no license was recorded; if the key was touched its signature counter may have gone up")
	assert.NotContains(t, s.errOut, "nothing was signed")
	assert.Equal(t, "open", cj.requestStatus(t))
	assert.NoFileExists(t, cj.licenseOut)
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

// hookedCard calls after with every command and the card's answer.
type hookedCard struct {
	*openpgptest.Sim
	after func(apdu, resp []byte)
}

func (h hookedCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	resp, err := h.Sim.Transmit(ctx, apdu)
	if err == nil && h.after != nil {
		h.after(apdu, resp)
	}
	return resp, err
}

// cancelWhen makes the command's interrupt context cancel right after the card answers a command
// for which when is true with 9000 (as if the operator pressed Ctrl-C at that moment).
func (cj *cardJourney) cancelWhen(t *testing.T, when func(apdu []byte) bool) {
	t.Helper()
	var cancel context.CancelFunc
	oldCtx, oldOpen := interruptContext, openCard
	interruptContext = func(ctx context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel = context.WithCancel(ctx)
		return ctx, cancel
	}
	openCard = func(string) (openpgp.Card, error) {
		return hookedCard{Sim: cj.card.sim, after: func(apdu, resp []byte) {
			if when(apdu) && len(resp) >= 2 && resp[len(resp)-2] == 0x90 && resp[len(resp)-1] == 0x00 {
				cancel()
			}
		}}, nil
	}
	t.Cleanup(func() { interruptContext, openCard = oldCtx, oldOpen })
}

func (cj *cardJourney) licenseCount(t *testing.T) string {
	t.Helper()
	out, e, code := cj.do(clock.Real{}, "verify-licenses", "--pub", cj.card.pubPath)
	require.Contains(t, []int{0, 1}, code, e)
	return regexp.MustCompile(`checked \d+`).FindString(out)
}

func TestCancelAfterTheCardSignedSaysTheCounterWentUp(t *testing.T) {
	cj := newCardJourney(t, nil)
	// The last part of PSO:CDS (CLA 00, INS 2A) answered with the signature.
	cj.cancelWhen(t, func(apdu []byte) bool { return apdu[0] == 0x00 && apdu[1] == 0x2A })
	s := cj.issue(strings.NewReader("y\n"), goodPIN, "--license-id", "LIC-2026-424242")
	assert.Equal(t, 1, s.code)
	assert.NotEmpty(t, cj.card.sim.LastSigned(), "the card did sign")
	assert.Contains(t, s.errOut, "the card made a signature (its signature counter went up) but no license was recorded by this command")
	assert.Contains(t, s.errOut, "vendor-console request show "+cj.reqID)
	assert.Contains(t, s.errOut, "license export --id LIC-2026-424242")
	assert.Contains(t, s.errOut, "differ by one")
	assert.NotContains(t, s.errOut, "nothing was signed")
	assert.Equal(t, "checked 0", cj.licenseCount(t))
	assert.Equal(t, "open", cj.requestStatus(t))
	assert.NoFileExists(t, cj.licenseOut)
}

func TestCancelBeforeTheCardSignedKeepsTheOldWording(t *testing.T) {
	cj := newCardJourney(t, nil)
	cj.cancelWhen(t, func(apdu []byte) bool { return apdu[1] == 0x20 }) // right after VERIFY
	s := cj.issue(strings.NewReader("y\n"), goodPIN)
	assert.Equal(t, 1, s.code)
	assert.Empty(t, cj.card.sim.LastSigned())
	assert.Contains(t, s.errOut, "signing cancelled: nothing was signed or recorded")
	assert.NotContains(t, s.errOut, "signature counter")
	assert.Equal(t, "checked 0", cj.licenseCount(t))
	assert.Equal(t, "open", cj.requestStatus(t))
	assert.NoFileExists(t, cj.licenseOut)
}

func TestCommitOutcomeUnknownTellsTheOperatorToCheck(t *testing.T) {
	cj := newCardJourney(t, nil)
	_, err := cj.d.Owner.Exec(context.Background(), `
		CREATE FUNCTION t_fail_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'commit refused'; END $$;
		CREATE CONSTRAINT TRIGGER t_fail_commit AFTER UPDATE ON license_requests DEFERRABLE INITIALLY DEFERRED
			FOR EACH ROW EXECUTE FUNCTION t_fail_commit();`)
	require.NoError(t, err)
	s := cj.issue(strings.NewReader("y\n"), goodPIN, "--license-id", "LIC-2026-515151")
	assert.Equal(t, 1, s.code)
	assert.Contains(t, s.errOut, "did not confirm the commit")
	assert.Contains(t, s.errOut, "may or may not be recorded")
	assert.Contains(t, s.errOut, "vendor-console request show "+cj.reqID)
	assert.Contains(t, s.errOut, "license export --id LIC-2026-515151")
	assert.NoFileExists(t, cj.licenseOut)
}
