package sign_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	c.closeOnce.Do(func() { close(c.closed) })
	return c.sim.Close()
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
	for _, uif := range []byte{openpgptest.UIFFixed, openpgptest.UIFCached, openpgptest.UIFCachedFixed} {
		f := newFixture(t, func(o *openpgptest.Options) { o.UIF = uif })
		_, err := f.signer(t).Issue(context.Background(), payload())
		require.NoError(t, err, "touch policy %d", uif)
		assert.Equal(t, 1, f.rec.count("touch"))
	}
}

func TestUnforcedPINIsRefusedBeforeThePrompt(t *testing.T) {
	f := newFixture(t, func(o *openpgptest.Options) { o.PW1SingleUse = false })
	assert.Contains(t, refusedBeforePrompt(t, f, openpgp.ErrPINNotForced), "forcesig")
}

func TestMessageLongerThanTheCardLimitIsRefusedBeforeThePrompt(t *testing.T) {
	p := payload()
	f := newFixture(t, func(o *openpgptest.Options) { o.MaxCommandLength = 100 })
	s := f.signer(t)
	_, err := s.Issue(context.Background(), p)
	var tl *openpgp.MessageTooLongError
	require.ErrorAs(t, err, &tl)
	assert.Equal(t, 100, tl.Limit)
	signed, _, err := sign.PayloadDigest(p)
	require.NoError(t, err)
	assert.Equal(t, len(signed), tl.Length)
	assert.Zero(t, f.pins.asks())
	assert.Zero(t, f.rec.count("verify"))
	assert.Zero(t, f.sim.Count(0x2A))
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
