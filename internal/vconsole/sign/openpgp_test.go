package sign_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/sign/openpgp"
	"alice/internal/vconsole/sign/openpgp/openpgptest"
)

var _ sign.Signer = (*sign.OpenPGPSigner)(nil)

const cardKeyID = "vk-2026-07"

// recorder keeps the order of what the signer does: "ask" (AskPIN), "verify" (a VERIFY with a
// PIN reaches the card), "touch" (NotifyTouch), "sign" (the last PSO:CDS part reaches the card).
type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func (r *recorder) count(e string) int {
	n := 0
	for _, x := range r.list() {
		if x == e {
			n++
		}
	}
	return n
}

// hookCard sits between the applet and the simulator. It records events, can replace the
// card's signature (a broken or hostile card) and can hang in the signing command until it is
// closed (a card waiting for a touch that does not come).
type hookCard struct {
	sim       *openpgptest.Sim
	rec       *recorder
	replace   func(sig []byte) []byte
	block     bool
	closeOnce sync.Once
	closed    chan struct{}
	closes    int
	mu        sync.Mutex
}

func newHookCard(sim *openpgptest.Sim, rec *recorder) *hookCard {
	return &hookCard{sim: sim, rec: rec, closed: make(chan struct{})}
}

func (c *hookCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	select {
	case <-c.closed:
		return nil, errors.New("card closed")
	default:
	}
	finalSign := len(apdu) > 4 && apdu[0] == 0x00 && apdu[1] == 0x2A
	if len(apdu) > 5 && apdu[1] == 0x20 {
		c.rec.add("verify")
	}
	if finalSign {
		c.rec.add("sign")
		if c.block {
			// Only Close ends the wait, as with a card waiting for a touch. The bound only keeps a
			// broken signer from hanging the test run; the tests fail on the elapsed time.
			select {
			case <-c.closed:
				return nil, errors.New("card closed")
			case <-time.After(3 * time.Second):
				return nil, errors.New("touch wait was never cancelled")
			}
		}
	}
	resp, err := c.sim.Transmit(ctx, apdu)
	if err != nil || !finalSign || c.replace == nil || len(resp) != ed25519.SignatureSize+2 {
		return resp, err
	}
	return append(c.replace(resp[:ed25519.SignatureSize]), 0x90, 0x00), nil
}

func (c *hookCard) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	// The card is closed before the blocked signing command is released, as with a real card
	// whose touch wait ends because it was closed: an Issue that returns has a closed card.
	err := c.sim.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

func (c *hookCard) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// goodCard is a card the signer accepts: an Ed25519 key, the PIN asked for every signature and a
// touch required.
func goodCard(t *testing.T, change func(*openpgptest.Options)) (*openpgptest.Sim, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	o := openpgptest.Options{Key: key, PW1SingleUse: true, UIF: openpgptest.UIFOn}
	if change != nil {
		change(&o)
	}
	return openpgptest.New(o), key
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

type pinLog struct {
	mu    sync.Mutex
	tries []int
	bufs  [][]byte
}

func (l *pinLog) asks() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tries)
}

func options(expected ed25519.PublicKey, rec *recorder, pins *pinLog, pin string) sign.OpenPGPOptions {
	return sign.OpenPGPOptions{
		KeyID:    cardKeyID,
		Expected: expected,
		AskPIN: func(_ context.Context, tries int) ([]byte, error) {
			rec.add("ask")
			b := []byte(pin)
			pins.mu.Lock()
			pins.tries = append(pins.tries, tries)
			pins.bufs = append(pins.bufs, b)
			pins.mu.Unlock()
			return b, nil
		},
		NotifyTouch: func() { rec.add("touch") },
	}
}

type fixture struct {
	sim  *openpgptest.Sim
	key  ed25519.PrivateKey
	card *hookCard
	rec  *recorder
	pins *pinLog
	opts sign.OpenPGPOptions
}

func newFixture(t *testing.T, change func(*openpgptest.Options)) *fixture {
	t.Helper()
	sim, key := goodCard(t, change)
	rec, pins := &recorder{}, &pinLog{}
	return &fixture{sim: sim, key: key, card: newHookCard(sim, rec), rec: rec, pins: pins,
		opts: options(pub(key), rec, pins, openpgptest.DefaultPIN)}
}

func (f *fixture) signer(t *testing.T) *sign.OpenPGPSigner {
	t.Helper()
	s, err := sign.NewOpenPGPSigner(context.Background(), f.card, f.opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIssueProducesAFileTheProductAccepts(t *testing.T) {
	f := newFixture(t, nil)
	s := f.signer(t)
	assert.Equal(t, cardKeyID, s.KeyID())
	assert.Equal(t, pub(f.key), s.Public())

	raw, err := s.Issue(context.Background(), payload())
	require.NoError(t, err)
	ks := license.NewKeySet(license.PublicKey{ID: cardKeyID, Key: pub(f.key), Status: license.KeyActive})
	lf, err := license.Check(raw, ks)
	require.NoError(t, err)
	assert.Equal(t, cardKeyID, lf.KeyID)
	assert.Equal(t, "Acme Ltd", lf.Payload.Customer)
	assert.Equal(t, []int{3}, f.pins.tries, "the prompt is told the tries left")
}

func TestThePINBufferIsZeroed(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.signer(t).Issue(context.Background(), payload())
	require.NoError(t, err)
	require.Len(t, f.pins.bufs, 1)
	assert.Equal(t, make([]byte, len(openpgptest.DefaultPIN)), f.pins.bufs[0])

	f = newFixture(t, nil)
	f.opts = options(pub(f.key), f.rec, f.pins, "999999")
	_, err = f.signer(t).Issue(context.Background(), payload())
	require.Error(t, err)
	assert.Equal(t, make([]byte, 6), f.pins.bufs[0], "zeroed after a wrong PIN too")
}

// refusedBeforePrompt runs NewOpenPGPSigner and expects target, with no PIN asked and no VERIFY
// sent. It returns the error text.
func refusedBeforePrompt(t *testing.T, f *fixture, target error) string {
	t.Helper()
	_, err := sign.NewOpenPGPSigner(context.Background(), f.card, f.opts)
	require.ErrorIs(t, err, target)
	assert.Zero(t, f.pins.asks(), "no PIN prompt")
	assert.Zero(t, f.rec.count("verify"), "no VERIFY")
	return err.Error()
}

func TestWrongKeyOnCardIsRefusedBeforeThePINPrompt(t *testing.T) {
	f := newFixture(t, nil)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	f.opts.Expected = pub(other)
	msg := refusedBeforePrompt(t, f, sign.ErrWrongCardKey)
	assert.Contains(t, msg, cardKeyID)
	assert.Contains(t, msg, license.Fingerprint(pub(f.key)))
	assert.Contains(t, msg, license.Fingerprint(pub(other)))
	assert.Equal(t, 1, f.card.closeCount(), "a refused card is closed")
}

func TestNoSignatureKeyIsRefused(t *testing.T) {
	f := newFixture(t, func(o *openpgptest.Options) { o.Key = nil })
	refusedBeforePrompt(t, f, openpgp.ErrNoKey)
}

func TestNonEd25519KeyIsRefused(t *testing.T) {
	f := newFixture(t, func(o *openpgptest.Options) { o.AlgAttr = []byte{0x01, 0x08, 0x00, 0x00, 0x20, 0x00} }) // RSA 2048
	refusedBeforePrompt(t, f, openpgp.ErrNotEd25519)
}

func TestBlockedPINIsRefusedBeforeThePINPrompt(t *testing.T) {
	f := newFixture(t, nil)
	f.sim.SetRetries(0)
	refusedBeforePrompt(t, f, openpgp.ErrPINBlocked)
}

func TestOneTryLeftIsRefusedUnlessLastPINTry(t *testing.T) {
	f := newFixture(t, nil)
	f.sim.SetRetries(1)
	refusedBeforePrompt(t, f, sign.ErrLastPINTry)

	f = newFixture(t, nil)
	f.sim.SetRetries(1)
	f.opts.LastPINTry = true
	raw, err := f.signer(t).Issue(context.Background(), payload())
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.Equal(t, []int{1}, f.pins.tries)
}

// The tries left are read again in Issue: a wrong PIN in an earlier Issue counts.
func TestOneTryLeftAfterAnEarlierWrongPINIsRefusedInIssue(t *testing.T) {
	f := newFixture(t, nil)
	f.sim.SetRetries(2)
	f.opts = options(pub(f.key), f.rec, f.pins, "999999")
	s := f.signer(t)
	_, err := s.Issue(context.Background(), payload())
	var pe *openpgp.PINError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, 1, pe.TriesLeft)

	_, err = s.Issue(context.Background(), payload())
	require.ErrorIs(t, err, sign.ErrLastPINTry)
	assert.Equal(t, 1, f.pins.asks(), "no second prompt")
	assert.Equal(t, 1, f.sim.Retries())
}

func TestNoTouchPolicyIsRefusedUnlessAllowed(t *testing.T) {
	for _, change := range []func(*openpgptest.Options){
		func(o *openpgptest.Options) { o.UIF = openpgptest.UIFOff },
		func(o *openpgptest.Options) { o.NoUIF = true },
	} {
		f := newFixture(t, change)
		refusedBeforePrompt(t, f, sign.ErrNoTouch)

		f = newFixture(t, change)
		f.opts.AllowNoTouch = true
		_, err := f.signer(t).Issue(context.Background(), payload())
		require.NoError(t, err)
		assert.Zero(t, f.rec.count("touch"), "no touch notice when the card does not want one")
	}
	for _, uif := range []byte{openpgptest.UIFOn, openpgptest.UIFFixed} {
		f := newFixture(t, func(o *openpgptest.Options) { o.UIF = uif })
		_, err := f.signer(t).Issue(context.Background(), payload())
		require.NoError(t, err, "touch policy %d", uif)
		assert.Equal(t, 1, f.rec.count("touch"))
	}
}

// A cached touch policy lets a second signature through without a touch for about 15 seconds:
// refused unless --allow-no-touch, and with it the card may still wait for a touch, so the
// notice is shown.
func TestCachedTouchPolicyIsRefusedUnlessAllowed(t *testing.T) {
	for _, uif := range []byte{openpgptest.UIFCached, openpgptest.UIFCachedFixed} {
		f := newFixture(t, func(o *openpgptest.Options) { o.UIF = uif })
		msg := refusedBeforePrompt(t, f, sign.ErrNoTouch)
		assert.Contains(t, msg, "cached")
		assert.Contains(t, msg, "15 seconds")

		f = newFixture(t, func(o *openpgptest.Options) { o.UIF = uif })
		f.opts.AllowNoTouch = true
		_, err := f.signer(t).Issue(context.Background(), payload())
		require.NoError(t, err, "touch policy %d", uif)
		assert.Equal(t, 1, f.rec.count("touch"), "the card may still wait for a touch")
	}
}

// Signed bytes over MaxMessage (the size the smoke test proved) are refused before the PIN.
func TestSignedBytesOverTheProvenSizeAreRefusedBeforeThePrompt(t *testing.T) {
	p := payload()
	signed, _, err := sign.PayloadDigest(p)
	require.NoError(t, err)

	f := newFixture(t, nil)
	f.opts.MaxMessage = len(signed) - 1
	_, err = f.signer(t).Issue(context.Background(), p)
	require.ErrorIs(t, err, sign.ErrOverProvenSize)
	var se *sign.SizeLimitError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, len(signed), se.Length)
	assert.Equal(t, len(signed)-1, se.Limit)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d bytes", len(signed)))
	assert.Contains(t, err.Error(), fmt.Sprintf("the smoke test proved %d bytes", len(signed)-1))
	assert.Zero(t, f.pins.asks(), "no PIN prompt")
	assert.Zero(t, f.rec.count("verify"))
	assert.Zero(t, f.sim.Count(0x2A))

	f = newFixture(t, nil)
	f.opts.MaxMessage = len(signed)
	_, err = f.signer(t).Issue(context.Background(), p)
	require.NoError(t, err, "exactly the limit is allowed")

	f = newFixture(t, nil) // 0 is no limit
	_, err = f.signer(t).Issue(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, 1024, sign.MaxSignedBytes)
}

func TestThePINBufferIsZeroedWhenAskPINFails(t *testing.T) {
	f := newFixture(t, nil)
	var buf []byte
	f.opts.AskPIN = func(context.Context, int) ([]byte, error) {
		buf = []byte("4829") // a partly typed PIN
		return buf, errors.New("terminal gone")
	}
	_, err := f.signer(t).Issue(context.Background(), payload())
	require.ErrorContains(t, err, "terminal gone")
	assert.Equal(t, make([]byte, 4), buf)
	assert.Zero(t, f.rec.count("verify"))
}

// Times with fractions of a second and other time zones: both signers sign the same bytes and the
// product accepts both files with the same payload.
func TestFractionalAndNonUTCTimesAgreeWithTheFileSigner(t *testing.T) {
	zone := time.FixedZone("UTC+3", 3*3600)
	p := payload()
	p.IssuedAt = time.Date(2026, 10, 15, 12, 30, 45, 987654321, zone)
	p.ValidFrom = time.Date(2026, 10, 15, 3, 0, 0, 500, zone)
	p.ValidUntil = time.Date(2027, 10, 15, 3, 0, 0, 999999999, zone)
	f := newFixture(t, nil)
	raw1, err := f.signer(t).Issue(context.Background(), p)
	require.NoError(t, err)
	fs := newSigner(t, "vk-2026-01")
	raw2, err := fs.Issue(context.Background(), p)
	require.NoError(t, err)

	f1, err := license.Check(raw1, license.NewKeySet(license.PublicKey{ID: cardKeyID, Key: pub(f.key), Status: license.KeyActive}))
	require.NoError(t, err)
	f2, err := sign.Verify(raw2, fs)
	require.NoError(t, err)
	assert.Equal(t, license.SignedBytes(f2.Payload), license.SignedBytes(f1.Payload))
	assert.Equal(t, license.SignedBytes(f1.Payload), f.sim.LastSigned())
	signed, _, err := sign.PayloadDigest(p)
	require.NoError(t, err)
	assert.Equal(t, signed, f.sim.LastSigned(), "the digest shown before the PIN is over the bytes the card signs")
}

// A cancel that lands after VERIFY and before the signature command: no touch notice is shown
// (the command line words a cancel before the notice as "nothing was signed").
func TestCancelAfterVerifyShowsNoTouchNotice(t *testing.T) {
	f := newFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	card := &cancelAfterVerify{hookCard: f.card, cancel: cancel}
	s, err := sign.NewOpenPGPSigner(context.Background(), card, f.opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	_, err = s.Issue(ctx, payload())
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, f.rec.count("touch"))
	assert.Zero(t, f.sim.Count(0x2A))
}

// cancelAfterVerify cancels right after the card answers VERIFY with a PIN.
type cancelAfterVerify struct {
	*hookCard
	cancel context.CancelFunc
}

func (c *cancelAfterVerify) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	resp, err := c.hookCard.Transmit(ctx, apdu)
	if len(apdu) > 5 && apdu[1] == 0x20 {
		c.cancel()
	}
	return resp, err
}

func TestUnforcedPINIsRefusedBeforeThePrompt(t *testing.T) {
	f := newFixture(t, func(o *openpgptest.Options) { o.PW1SingleUse = false })
	assert.Contains(t, refusedBeforePrompt(t, f, openpgp.ErrPINNotForced), "forcesig")
}

// A card that says it has no command chaining cannot take a license (longer than one short
// APDU): refused before the PIN, by the same rule the applet's Sign applies.
func TestMessageLongerThanTheCardLimitIsRefusedBeforeThePrompt(t *testing.T) {
	p := payload()
	f := newFixture(t, func(o *openpgptest.Options) { o.NoChaining = true })
	s := f.signer(t)
	_, err := s.Issue(context.Background(), p)
	var tl *openpgp.MessageTooLongError
	require.ErrorAs(t, err, &tl)
	assert.Equal(t, 255, tl.Limit)
	signed, _, err := sign.PayloadDigest(p)
	require.NoError(t, err)
	assert.Equal(t, len(signed), tl.Length)
	assert.Zero(t, f.pins.asks())
	assert.Zero(t, f.rec.count("verify"))
	assert.Zero(t, f.sim.Count(0x2A))
}

// DO 7F66 bounds one extended-length command, not a chained message: a small stated limit alone
// is no reason to refuse (the applet chains and the card decides).
func TestStatedCommandLengthAloneDoesNotRefuse(t *testing.T) {
	f := newFixture(t, func(o *openpgptest.Options) { o.MaxCommandLength = 100 })
	_, err := f.signer(t).Issue(context.Background(), payload())
	require.NoError(t, err)
}

func TestInvalidPayloadIsRefusedBeforeThePrompt(t *testing.T) {
	f := newFixture(t, nil)
	p := payload()
	p.MaxTargets = 0
	_, err := f.signer(t).Issue(context.Background(), p)
	require.Error(t, err)
	assert.Zero(t, f.pins.asks())
}

func TestWrongPINReturnsPINErrorWithTriesLeftAndGivesNoFile(t *testing.T) {
	f := newFixture(t, nil)
	f.opts = options(pub(f.key), f.rec, f.pins, "999999")
	raw, err := f.signer(t).Issue(context.Background(), payload())
	assert.Nil(t, raw)
	var pe *openpgp.PINError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, 2, pe.TriesLeft)
	assert.Equal(t, 1, f.rec.count("verify"), "never retried")
	assert.Zero(t, f.rec.count("touch"))
	assert.Zero(t, f.rec.count("sign"))
}

func TestNotifyTouchIsCalledOnceBeforeSigning(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.signer(t).Issue(context.Background(), payload())
	require.NoError(t, err)
	assert.Equal(t, []string{"ask", "verify", "touch", "sign"}, f.rec.list())
}

func TestGarbageSignatureFromTheCardGivesNoFile(t *testing.T) {
	f := newFixture(t, nil)
	f.card.replace = func([]byte) []byte {
		b := make([]byte, ed25519.SignatureSize)
		_, _ = rand.Read(b)
		return b
	}
	raw, err := f.signer(t).Issue(context.Background(), payload())
	assert.Nil(t, raw)
	require.ErrorIs(t, err, sign.ErrBadCardSignature)
}

func TestSignatureFromAnotherKeyGivesNoFile(t *testing.T) {
	f := newFixture(t, nil)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	f.card.replace = func([]byte) []byte { return ed25519.Sign(other, f.sim.LastSigned()) }
	raw, err := f.signer(t).Issue(context.Background(), payload())
	assert.Nil(t, raw)
	require.ErrorIs(t, err, sign.ErrBadCardSignature)
}

func TestTruncatingCardGivesNoFile(t *testing.T) {
	p := payload()
	f := newFixture(t, func(o *openpgptest.Options) { o.TruncateAt = 255 })
	raw, err := f.signer(t).Issue(context.Background(), p)
	assert.Nil(t, raw)
	require.ErrorIs(t, err, sign.ErrBadCardSignature)
	signed, _, err := sign.PayloadDigest(p)
	require.NoError(t, err)
	require.Greater(t, len(signed), 255, "the payload must be longer than the truncation for this test")
	assert.Equal(t, signed, f.sim.LastReceived(), "the card received everything and signed only a part")
}

func TestCancelDuringTouchWaitReturnsPromptly(t *testing.T) {
	f := newFixture(t, nil)
	f.card.block = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.opts.NotifyTouch = func() {
		f.rec.add("touch")
		go func() { time.Sleep(50 * time.Millisecond); cancel() }() // the operator gives up
	}
	s := f.signer(t)
	start := time.Now()
	raw, err := s.Issue(ctx, payload())
	assert.Less(t, time.Since(start), time.Second)
	assert.Nil(t, raw)
	require.ErrorIs(t, err, context.Canceled)
	assert.True(t, f.sim.Closed(), "the card was closed to end the wait")

	_, err = s.Issue(context.Background(), payload())
	require.ErrorIs(t, err, sign.ErrSignerClosed)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "Close is idempotent")
}

func TestTwoMinuteLimit(t *testing.T) {
	f := newFixture(t, nil)
	f.card.block = true
	s := f.signer(t)
	assert.Equal(t, 2*time.Minute, sign.Timeout(s))
	sign.SetTimeout(s, 100*time.Millisecond)
	start := time.Now()
	raw, err := s.Issue(context.Background(), payload())
	assert.Less(t, time.Since(start), time.Second)
	assert.Nil(t, raw)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.True(t, f.sim.Closed())
}

func TestCancelledContextAsksNothing(t *testing.T) {
	f := newFixture(t, nil)
	s := f.signer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Issue(ctx, payload())
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, f.pins.asks())
}

func TestPayloadDigestMatchesTheBytesSentToTheCard(t *testing.T) {
	p := payload()
	f := newFixture(t, nil)
	_, err := f.signer(t).Issue(context.Background(), p)
	require.NoError(t, err)
	signed, digest, err := sign.PayloadDigest(p)
	require.NoError(t, err)
	sum := sha256.Sum256(f.sim.LastSigned())
	assert.Equal(t, hex.EncodeToString(sum[:]), digest)
	assert.Equal(t, signed, f.sim.LastSigned())

	bad := payload()
	bad.MaxTargets = 0
	_, _, err = sign.PayloadDigest(bad)
	assert.Error(t, err)
}

func TestIssueMatchesWhatTheProductWouldSign(t *testing.T) {
	p := payload()
	f := newFixture(t, nil)
	raw1, err := f.signer(t).Issue(context.Background(), p)
	require.NoError(t, err)
	fs := newSigner(t, "vk-2026-01")
	raw2, err := fs.Issue(context.Background(), p)
	require.NoError(t, err)

	want := license.SignedBytes(issuer.NormalizePayload(p))
	assert.Equal(t, want, f.sim.LastSigned())
	f1, err := license.ParseFile(raw1)
	require.NoError(t, err)
	f2, err := license.ParseFile(raw2)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pub(f.key), want, f1.Signature))
	assert.True(t, ed25519.Verify(fs.Public(), want, f2.Signature))

	// Same encoding byte for byte once the key ID and the signature are swapped.
	f1.KeyID, f1.Signature = f2.KeyID, f2.Signature
	again, err := license.EncodeFile(f1)
	require.NoError(t, err)
	assert.Equal(t, string(raw2), string(again))
}

func TestFreeTextIsNormalizedLikeTheFileSigner(t *testing.T) {
	p := payload()
	p.Customer = "Örnek Bankasi"
	f := newFixture(t, nil)
	raw1, err := f.signer(t).Issue(context.Background(), p)
	require.NoError(t, err)
	fs := newSigner(t, "vk-2026-01")
	raw2, err := fs.Issue(context.Background(), p)
	require.NoError(t, err)

	f1, err := license.ParseFile(raw1)
	require.NoError(t, err)
	f2, err := license.ParseFile(raw2)
	require.NoError(t, err)
	assert.Equal(t, "Örnek Bankasi", f1.Payload.Customer)
	assert.Equal(t, f2.Payload.Customer, f1.Payload.Customer)
	assert.Equal(t, license.SignedBytes(f2.Payload), f.sim.LastSigned())
}

func TestNewRefusesIncompleteOptions(t *testing.T) {
	for name, change := range map[string]func(*sign.OpenPGPOptions){
		"no key ID":    func(o *sign.OpenPGPOptions) { o.KeyID = "" },
		"no key":       func(o *sign.OpenPGPOptions) { o.Expected = nil },
		"no PIN entry": func(o *sign.OpenPGPOptions) { o.AskPIN = nil },
	} {
		f := newFixture(t, nil)
		change(&f.opts)
		_, err := sign.NewOpenPGPSigner(context.Background(), f.card, f.opts)
		assert.Error(t, err, name)
		assert.Zero(t, f.sim.Count(0xA4), "%s: the card is not even selected", name)
	}
}

func TestSerialComesFromTheCardChecks(t *testing.T) {
	f := newFixture(t, nil)
	assert.Equal(t, "12345678", f.signer(t).Serial())
}

func TestSignedSaysWhetherTheCardMadeASignature(t *testing.T) {
	f := newFixture(t, nil)
	s := f.signer(t)
	assert.False(t, s.Signed())
	_, err := s.Issue(context.Background(), payload())
	require.NoError(t, err)
	assert.True(t, s.Signed())

	// A wrong PIN: the card signed nothing.
	f = newFixture(t, nil)
	f.opts = options(pub(f.key), f.rec, f.pins, "999999")
	s = f.signer(t)
	_, err = s.Issue(context.Background(), payload())
	require.Error(t, err)
	assert.False(t, s.Signed())

	// A garbage signature gives no file, but the card did sign (its counter went up).
	f = newFixture(t, nil)
	f.card.replace = func([]byte) []byte { return make([]byte, ed25519.SignatureSize) }
	s = f.signer(t)
	_, err = s.Issue(context.Background(), payload())
	require.ErrorIs(t, err, sign.ErrBadCardSignature)
	assert.True(t, s.Signed())

	// A cancel during the touch wait: nothing signed.
	f = newFixture(t, nil)
	f.card.block = true
	ctx, cancel := context.WithCancel(context.Background())
	f.opts.NotifyTouch = func() { go func() { time.Sleep(20 * time.Millisecond); cancel() }() }
	s = f.signer(t)
	_, err = s.Issue(ctx, payload())
	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, s.Signed())
}
