package openpgp_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/sign/openpgp"
	"alice/internal/vconsole/sign/openpgp/openpgptest"
)

const goodPIN = "123456"

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k
}

func open(t *testing.T, sim *openpgptest.Sim) *openpgp.Applet {
	t.Helper()
	a, err := openpgp.Open(context.Background(), sim)
	require.NoError(t, err)
	return a
}

func pin(s string) []byte { return []byte(s) }

func TestInfoReadsSerialAlgorithmRetriesAndUIF(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t), Serial: 0x12345678, UIF: openpgptest.UIFOn, SigCount: 7})
	a := open(t, sim)
	info, err := a.Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "12345678", info.Serial)
	assert.Len(t, info.AID, 16)
	assert.Equal(t, []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}, info.AID[:6])
	assert.Equal(t, "ed25519", info.SigAlg)
	assert.Equal(t, 3, info.PW1Retries)
	assert.False(t, info.PW1Blocked)
	assert.Equal(t, "on", info.SigUIF)
	assert.Equal(t, 7, info.SigCount)

	sim.SetRetries(0)
	info, err = a.Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, info.PW1Retries)
	assert.True(t, info.PW1Blocked)
}

func TestInfoUIFValuesAndUnsupported(t *testing.T) {
	for uif, want := range map[byte]string{0: "off", 1: "on", 2: "fixed", 3: "cached", 4: "cached-fixed", 9: "unknown:09"} {
		a := open(t, openpgptest.New(openpgptest.Options{Key: newKey(t), UIF: uif}))
		info, err := a.Info(context.Background())
		require.NoError(t, err)
		assert.Equal(t, want, info.SigUIF, "uif %d", uif)
	}
	// Not in DO 6E and GET DATA 00D6 answers 6A88: an older card without touch support.
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t), NoUIF: true})
	info, err := open(t, sim).Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "unsupported", info.SigUIF)
	assert.Equal(t, 1, sim.CountGetData(0x00D6), "falls back to GET DATA 00D6 once")

	// Not in DO 6E but readable with GET DATA 00D6.
	sim = openpgptest.New(openpgptest.Options{Key: newKey(t), UIF: openpgptest.UIFFixed, UIFOnlyByGetData: true})
	info, err = open(t, sim).Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "fixed", info.SigUIF)
}

func TestInfoAlgorithmVariants(t *testing.T) {
	oid := []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}
	cases := []struct {
		name string
		attr []byte
		want string
	}{
		{"oid only", append([]byte{0x16}, oid...), "ed25519"},
		{"oid with import format ff", append(append([]byte{0x16}, oid...), 0xFF), "ed25519"},
		{"rsa 2048", []byte{0x01, 0x08, 0x00, 0x00, 0x20, 0x00}, "other:010800002000"},
		{"eddsa other curve", []byte{0x16, 0x2B, 0x65, 0x71}, "other:162b6571"},
		{"empty", []byte{}, "none"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			info, err := open(t, openpgptest.New(openpgptest.Options{AlgAttr: c.attr})).Info(context.Background())
			require.NoError(t, err)
			assert.Equal(t, c.want, info.SigAlg)
		})
	}
}

// A DO 6E longer than 256 bytes needs a three-byte BER length (82 xx xx) and arrives over GET RESPONSE.
func TestInfoWithLongApplicationData(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t), ExtraAppData: 400})
	info, err := open(t, sim).Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ed25519", info.SigAlg)
	assert.Positive(t, sim.Count(0xC0), "GET RESPONSE used")
}

func TestOpenRefusesAnotherApplet(t *testing.T) {
	_, err := openpgp.Open(context.Background(), openpgptest.New(openpgptest.Options{WrongApplet: true}))
	require.ErrorIs(t, err, openpgp.ErrNoApplet)
}

func TestPublicKeyIsTheSimulatorKey(t *testing.T) {
	k := newKey(t)
	sim := openpgptest.New(openpgptest.Options{Key: k})
	pub, err := open(t, sim).PublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, k.Public(), pub)
	for _, c := range sim.Commands() {
		if c.INS == 0x47 {
			assert.Equal(t, byte(0x81), c.P1, "read the existing key, never generate")
		}
	}
}

func TestEmptySlotGivesErrNoKey(t *testing.T) {
	_, err := open(t, openpgptest.New(openpgptest.Options{})).PublicKey(context.Background())
	require.ErrorIs(t, err, openpgp.ErrNoKey)
}

// An all-zero fingerprint is not an empty slot: the key read decides.
func TestZeroFingerprintStillReadsTheKey(t *testing.T) {
	k := newKey(t)
	sim := openpgptest.New(openpgptest.Options{Key: k, ZeroFingerprint: true})
	pub, err := open(t, sim).PublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, k.Public(), pub)
}

func TestNonEd25519SlotGivesErrNotEd25519(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t), AlgAttr: []byte{0x01, 0x08, 0x00, 0x00, 0x20, 0x00}})
	_, err := open(t, sim).PublicKey(context.Background())
	require.ErrorIs(t, err, openpgp.ErrNotEd25519)
	assert.Zero(t, sim.Count(0x47), "the key is not read when the algorithm is wrong")
}

func TestVerifyPINRightAndWrong(t *testing.T) {
	for _, yubi := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrong pin answers 6982=%v", yubi), func(t *testing.T) {
			sim := openpgptest.New(openpgptest.Options{Key: newKey(t), WrongPIN63Cx: !yubi})
			a := open(t, sim)
			require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))

			var pe *openpgp.PINError
			err := a.VerifyPIN(context.Background(), pin("654321"))
			require.ErrorAs(t, err, &pe)
			assert.ErrorIs(t, err, openpgp.ErrWrongPIN)
			assert.Equal(t, 2, pe.TriesLeft)

			err = a.VerifyPIN(context.Background(), pin("654321"))
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, 1, pe.TriesLeft)

			err = a.VerifyPIN(context.Background(), pin("654321"))
			require.ErrorIs(t, err, openpgp.ErrPINBlocked)
			assert.Equal(t, 4, sim.Count(0x20), "the good VERIFY and three wrong ones")

			before := sim.Count(0x20)
			err = a.VerifyPIN(context.Background(), pin(goodPIN))
			require.ErrorIs(t, err, openpgp.ErrPINBlocked)
			assert.Equal(t, before, sim.Count(0x20), "no VERIFY is sent to a blocked PIN")
		})
	}
}

func TestVerifyPINDoesNotRetryAutomatically(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t)})
	a := open(t, sim)
	for i := 1; i <= 2; i++ {
		_ = a.VerifyPIN(context.Background(), pin("000000"))
		assert.Equal(t, i, sim.Count(0x20), "exactly one VERIFY per call")
	}
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	assert.Equal(t, 3, sim.Count(0x20))
}

func TestVerifyPINRefusesLocallyWithoutSpendingATry(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t)})
	a := open(t, sim)
	require.Error(t, a.VerifyPIN(context.Background(), pin("12345")), "shorter than the minimum of 6")
	require.Error(t, a.VerifyPIN(context.Background(), bytes.Repeat([]byte("1"), 200)), "longer than the card maximum")
	assert.Zero(t, sim.Count(0x20))
	assert.Equal(t, 3, sim.Retries())

	kdf := openpgptest.New(openpgptest.Options{Key: newKey(t), KDF: true})
	err := open(t, kdf).VerifyPIN(context.Background(), pin(goodPIN))
	require.ErrorIs(t, err, openpgp.ErrKDFUnsupported)
	assert.Zero(t, kdf.Count(0x20), "a raw PIN is never sent to a card that expects a KDF hash")
}

func TestSignProducesAValidSignature(t *testing.T) {
	k := newKey(t)
	sim := openpgptest.New(openpgptest.Options{Key: k})
	a := open(t, sim)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	msg := []byte("alice license payload")
	sig, err := a.Sign(context.Background(), msg)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(k.Public().(ed25519.PublicKey), msg, sig))
	assert.Equal(t, msg, sim.LastSigned())
}

func TestSignLongMessageUsesChaining(t *testing.T) {
	k := newKey(t)
	sim := openpgptest.New(openpgptest.Options{Key: k})
	a := open(t, sim)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	msg := bytes.Repeat([]byte("0123456789"), 70)
	sig, err := a.Sign(context.Background(), msg)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(k.Public().(ed25519.PublicKey), msg, sig))

	var pso []openpgptest.Command
	for _, c := range sim.Commands() {
		if c.INS == 0x2A {
			pso = append(pso, c)
		}
	}
	require.Len(t, pso, 3)
	total := 0
	for i, c := range pso {
		total += c.Lc
		assert.Equal(t, byte(0x9E), c.P1)
		assert.Equal(t, byte(0x9A), c.P2)
		if i < len(pso)-1 {
			assert.Equal(t, byte(0x10), c.CLA, "chained command %d", i)
			assert.Equal(t, 255, c.Lc)
			assert.Equal(t, -1, c.Le, "no Le on a chained command")
		} else {
			assert.Equal(t, byte(0x00), c.CLA)
			assert.Equal(t, 256, c.Le, "Le 00 on the last command")
		}
	}
	assert.Equal(t, 700, total)
	assert.Equal(t, msg, sim.LastSigned())
}

func TestSignWithResponseChunking(t *testing.T) {
	k := newKey(t)
	sim := openpgptest.New(openpgptest.Options{Key: k, Chunk: 20})
	a := open(t, sim)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	msg := []byte("chunked")
	sig, err := a.Sign(context.Background(), msg)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(k.Public().(ed25519.PublicKey), msg, sig))
	assert.GreaterOrEqual(t, sim.Count(0xC0), 3, "64 bytes in 20-byte pieces")
}

func TestWrongLeIsReissued(t *testing.T) {
	k := newKey(t)
	sim := openpgptest.New(openpgptest.Options{Key: k, StrictLe: true})
	a := open(t, sim)
	info, err := a.Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ed25519", info.SigAlg)
	pub, err := a.PublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, k.Public(), pub)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	_, err = a.Sign(context.Background(), []byte("m"))
	require.NoError(t, err)
}

// Without a VERIFY in this session, Sign is refused locally: nothing is sent to the card.
func TestSignRefusedBeforeVerify(t *testing.T) {
	for _, uif := range []byte{openpgptest.UIFOff, openpgptest.UIFOn} {
		sim := openpgptest.New(openpgptest.Options{Key: newKey(t), UIF: uif})
		a := open(t, sim)
		n := len(sim.Commands())
		_, err := a.Sign(context.Background(), []byte("m"))
		require.ErrorIs(t, err, openpgp.ErrNotVerified)
		assert.NotErrorIs(t, err, openpgp.ErrTouchNeeded)
		assert.Len(t, sim.Commands(), n, "nothing sent")
	}
}

// In single-use mode one VERIFY covers one Sign; the second Sign is refused locally.
func TestPINIsValidForOneSignature(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t), PW1SingleUse: true})
	a := open(t, sim)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	_, err := a.Sign(context.Background(), []byte("one"))
	require.NoError(t, err)
	n := len(sim.Commands())
	_, err = a.Sign(context.Background(), []byte("two"))
	require.ErrorIs(t, err, openpgp.ErrNotVerified)
	assert.Len(t, sim.Commands(), n, "refused without sending")
}

// The YubiKey factory setting keeps PW1 valid for several signatures: Info reports it and
// RequireForcedPIN refuses it with instructions.
func TestPINNotForcedIsReported(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t)})
	a := open(t, sim)
	info, err := a.Info(context.Background())
	require.NoError(t, err)
	assert.True(t, info.PW1ValidForSeveral)
	err = a.RequireForcedPIN(context.Background())
	require.ErrorIs(t, err, openpgp.ErrPINNotForced)
	assert.Contains(t, err.Error(), "forcesig")
	assert.Contains(t, err.Error(), "gpg --card-edit")

	// The card signs again without a VERIFY, and the applet mirrors that.
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	_, err = a.Sign(context.Background(), []byte("one"))
	require.NoError(t, err)
	_, err = a.Sign(context.Background(), []byte("two"))
	require.NoError(t, err)

	single := open(t, openpgptest.New(openpgptest.Options{Key: newKey(t), PW1SingleUse: true}))
	info, err = single.Info(context.Background())
	require.NoError(t, err)
	assert.False(t, info.PW1ValidForSeveral)
	require.NoError(t, single.RequireForcedPIN(context.Background()))
}

// Any Sign failure asks for a new VERIFY, even in multi mode.
func TestSignErrorResetsVerification(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t), UIF: openpgptest.UIFOn, Touch: func() bool { return false }})
	a := open(t, sim)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	_, err := a.Sign(context.Background(), []byte("m"))
	require.ErrorIs(t, err, openpgp.ErrTouchNeeded)
	n := sim.Count(0x2A)
	_, err = a.Sign(context.Background(), []byte("m"))
	require.ErrorIs(t, err, openpgp.ErrNotVerified)
	assert.Equal(t, n, sim.Count(0x2A))
}

func TestInfoReportsLengthLimitAndChaining(t *testing.T) {
	info, err := open(t, openpgptest.New(openpgptest.Options{Key: newKey(t)})).Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2048, info.MaxCommandLength)
	assert.Equal(t, "yes", info.CommandChaining)

	info, err = open(t, openpgptest.New(openpgptest.Options{Key: newKey(t), NoExtLenInfo: true, NoHistorical: true})).Info(context.Background())
	require.NoError(t, err)
	assert.Zero(t, info.MaxCommandLength, "unknown")
	assert.Equal(t, "unknown", info.CommandChaining)
}

// Only a message that cannot be delivered at all is refused locally: it needs chaining and the
// card says it has none.
func TestSignWithoutChainingTooLongIsRefusedBeforeSending(t *testing.T) {
	k := newKey(t)
	sim := openpgptest.New(openpgptest.Options{Key: k, NoChaining: true})
	a := open(t, sim)
	info, err := a.Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "no", info.CommandChaining)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	_, err = a.Sign(context.Background(), bytes.Repeat([]byte{1}, 300))
	require.ErrorIs(t, err, openpgp.ErrMessageTooLong)
	var te *openpgp.MessageTooLongError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, 255, te.Limit)
	assert.Equal(t, 300, te.Length)
	assert.Zero(t, sim.Count(0x2A), "nothing sent")

	// A message that fits one APDU is signed.
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	msg := bytes.Repeat([]byte{2}, 255)
	sig, err := a.Sign(context.Background(), msg)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(k.Public().(ed25519.PublicKey), msg, sig))
}

// With chaining supported (whatever 7F66 says about one command) or not stated, a long message
// goes out chained and is signed.
func TestSignChainsWhenChainingIsSupportedOrUnknown(t *testing.T) {
	for name, o := range map[string]openpgptest.Options{
		"chaining yes, max command 255": {MaxCommandLength: 255},
		"chaining unknown":              {NoHistorical: true},
		"chaining unknown, no 7F66":     {NoHistorical: true, NoExtLenInfo: true},
	} {
		t.Run(name, func(t *testing.T) {
			k := newKey(t)
			o.Key = k
			sim := openpgptest.New(o)
			a := open(t, sim)
			require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
			msg := bytes.Repeat([]byte("0123456789"), 70)
			sig, err := a.Sign(context.Background(), msg)
			require.NoError(t, err)
			assert.True(t, ed25519.Verify(k.Public().(ed25519.PublicKey), msg, sig))
			assert.Equal(t, 3, sim.Count(0x2A), "sent chained")
			assert.Equal(t, msg, sim.LastReceived())
		})
	}
}

// DO 7F66 outside DO 6E is read with its own GET DATA; 6A88 there means unknown.
func TestMaxCommandLengthByGetData(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t), ExtLenOnlyByGetData: true, MaxCommandLength: 1024})
	info, err := open(t, sim).Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1024, info.MaxCommandLength)
	assert.Equal(t, 1, sim.CountGetData(0x7F66))

	sim = openpgptest.New(openpgptest.Options{Key: newKey(t), NoExtLenInfo: true})
	info, err = open(t, sim).Info(context.Background())
	require.NoError(t, err)
	assert.Zero(t, info.MaxCommandLength)
	assert.Equal(t, 1, sim.CountGetData(0x7F66))

	// Inside DO 6E: no extra GET DATA.
	sim = openpgptest.New(openpgptest.Options{Key: newKey(t)})
	_, err = open(t, sim).Info(context.Background())
	require.NoError(t, err)
	assert.Zero(t, sim.CountGetData(0x7F66))
}

func TestCardRefusingLengthSaysWhichPart(t *testing.T) {
	cases := []struct {
		name        string
		o           openpgptest.Options
		part, parts int
		sw          uint16
		where       string
	}{
		{"buffer full in the middle", openpgptest.Options{MaxMessage: 400}, 2, 3, 0x6700, "middle part (2 of 3)"},
		{"no chaining", openpgptest.Options{RefuseChaining: true}, 1, 3, 0x6884, "first part (1 of 3)"},
		{"buffer full at the end", openpgptest.Options{MaxMessage: 600}, 3, 3, 0x6700, "last part (3 of 3)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.o.Key = newKey(t)
			sim := openpgptest.New(c.o)
			a := open(t, sim)
			require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
			_, err := a.Sign(context.Background(), bytes.Repeat([]byte{1}, 700))
			require.ErrorIs(t, err, openpgp.ErrCardRefusedLength)
			var le *openpgp.LengthRefusedError
			require.ErrorAs(t, err, &le)
			assert.Equal(t, c.part, le.Part)
			assert.Equal(t, c.parts, le.Parts)
			assert.Equal(t, c.sw, le.SW)
			assert.Contains(t, err.Error(), c.where)
			assert.Equal(t, c.part, sim.Count(0x2A), "never retried")
		})
	}
	a, _ := verifiedApplet(t, []byte{0x6A, 0x80})
	_, err := a.Sign(context.Background(), []byte("short"))
	require.ErrorIs(t, err, openpgp.ErrCardRefusedLength)
	assert.Contains(t, err.Error(), "only part (1 of 1)")
}

// A card that silently signs a truncated input returns a signature; Sign passes it on (checking
// it is the signer's job) and it does not verify over the full message.
func TestTruncatingCardSignatureDoesNotVerify(t *testing.T) {
	k := newKey(t)
	sim := openpgptest.New(openpgptest.Options{Key: k, TruncateAt: 255})
	a := open(t, sim)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	msg := bytes.Repeat([]byte("license "), 60)
	sig, err := a.Sign(context.Background(), msg)
	require.NoError(t, err)
	assert.Equal(t, msg, sim.LastReceived(), "the full message reached the card")
	pub := k.Public().(ed25519.PublicKey)
	assert.False(t, ed25519.Verify(pub, msg, sig))
	assert.True(t, ed25519.Verify(pub, msg[:255], sig))
}

// verifiedApplet is an applet on a scripted card that has passed VerifyPIN; resp follows.
func verifiedApplet(t *testing.T, resp ...[]byte) (*openpgp.Applet, *scripted) {
	t.Helper()
	c4 := []byte{0xC4, 0x07, 0x00, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03}
	app := append([]byte{0x6E, byte(len(c4) + 2), 0x73, byte(len(c4))}, c4...)
	card := &scripted{resp: append([][]byte{append(app, 0x90, 0x00), {0x90, 0x00}}, resp...)}
	a := openpgp.NewApplet(card, nil)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	card.sent = nil
	return a, card
}

func TestTouchNotGivenGivesErrTouchNeeded(t *testing.T) {
	for _, sw := range []uint16{0x6982, 0x6985} {
		touched := 0
		sim := openpgptest.New(openpgptest.Options{Key: newKey(t), UIF: openpgptest.UIFOn, TouchTimeoutSW: sw,
			Touch: func() bool { touched++; return false }})
		a := open(t, sim)
		require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
		_, err := a.Sign(context.Background(), []byte("m"))
		require.ErrorIs(t, err, openpgp.ErrTouchNeeded, "sw %04X", sw)
		assert.Equal(t, 1, touched)
	}

	k := newKey(t)
	sim := openpgptest.New(openpgptest.Options{Key: k, UIF: openpgptest.UIFOn, Touch: func() bool { return true }})
	a := open(t, sim)
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	sig, err := a.Sign(context.Background(), []byte("m"))
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(k.Public().(ed25519.PublicKey), []byte("m"), sig))
}

// cancelCard cancels the context after n transmissions and records every transmission after that.
type cancelCard struct {
	inner  openpgp.Card
	n      int
	cancel context.CancelFunc
	sent   int
	after  int
}

func (c *cancelCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	c.sent++
	if c.sent > c.n {
		c.after++
	}
	r, err := c.inner.Transmit(ctx, apdu)
	if c.sent == c.n {
		c.cancel()
	}
	return r, err
}
func (c *cancelCard) Close() error { return c.inner.Close() }

func TestContextCancelStopsBeforeTransmit(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t)})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := openpgp.Open(ctx, sim)
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, sim.Commands())

	a := open(t, sim)
	n := len(sim.Commands())
	p := pin(goodPIN)
	require.ErrorIs(t, a.VerifyPIN(ctx, p), context.Canceled)
	assert.Equal(t, make([]byte, len(p)), p, "zeroed on the cancel path too")
	_, err = a.Sign(ctx, []byte("m"))
	require.ErrorIs(t, err, context.Canceled)
	_, err = a.Info(ctx)
	require.ErrorIs(t, err, context.Canceled)
	_, err = a.PublicKey(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Len(t, sim.Commands(), n, "nothing sent")

	// Cancelled between the chained parts of a long PSO: nothing more goes out.
	require.NoError(t, a.VerifyPIN(context.Background(), pin(goodPIN)))
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	cc := &cancelCard{inner: sim, n: 1 << 30, cancel: cancel2}
	a3 := openpgp.NewApplet(cc, mustAID(t, a))
	require.NoError(t, a3.VerifyPIN(context.Background(), pin(goodPIN)))
	cc.sent, cc.n = 0, 1
	_, err = a3.Sign(ctx2, bytes.Repeat([]byte{1}, 600))
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, cc.sent)
	assert.Zero(t, cc.after)
}

func mustAID(t *testing.T, a *openpgp.Applet) []byte {
	t.Helper()
	info, err := a.Info(context.Background())
	require.NoError(t, err)
	return info.AID
}

func TestPINIsZeroedAfterVerify(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t)})
	a := open(t, sim)
	for _, s := range []string{goodPIN, "999999", "1"} {
		p := pin(s)
		_ = a.VerifyPIN(context.Background(), p)
		assert.Equal(t, make([]byte, len(p)), p)
	}
	sim.SetRetries(0)
	p := pin(goodPIN)
	_ = a.VerifyPIN(context.Background(), p)
	assert.Equal(t, make([]byte, len(p)), p, "zeroed on the blocked path")
}

// scripted is a card that answers from a fixed list (by call order) and fails past its end.
type scripted struct {
	resp [][]byte
	i    int
	sent [][]byte
}

func (s *scripted) Transmit(_ context.Context, apdu []byte) ([]byte, error) {
	s.sent = append(s.sent, append([]byte(nil), apdu...))
	if s.i >= len(s.resp) {
		return nil, errors.New("scripted: no more responses")
	}
	r := s.resp[s.i]
	s.i++
	return r, nil
}
func (s *scripted) Close() error { return nil }

func TestErrorsNeverContainThePIN(t *testing.T) {
	const distinctive = "739182"
	hexPIN := fmt.Sprintf("%x", distinctive)
	hexPINUpper := fmt.Sprintf("%X", distinctive)
	check := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		msg := fmt.Sprintf("%v %+v %#v", err, err, err)
		for _, bad := range []string{distinctive, hexPIN, hexPINUpper} {
			assert.NotContains(t, msg, bad)
		}
	}
	paths := []openpgptest.Options{
		{Key: newKey(t)},                     // wrong PIN, 6982 (YubiKey)
		{Key: newKey(t), WrongPIN63Cx: true}, // wrong PIN, 63Cx
		{Key: newKey(t), KDF: true},          // KDF refused
	}
	for _, o := range paths {
		a := open(t, openpgptest.New(o))
		check(t, a.VerifyPIN(context.Background(), pin(distinctive)))
	}
	blocked := openpgptest.New(openpgptest.Options{Key: newKey(t)})
	blocked.SetRetries(0)
	check(t, open(t, blocked).VerifyPIN(context.Background(), pin(distinctive)))

	// Odd status words and transport failures on the VERIFY itself.
	c4 := []byte{0xC4, 0x07, 0x00, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03}
	app := append([]byte{0x6E, byte(len(c4) + 2), 0x73, byte(len(c4))}, c4...)
	for _, sw := range [][]byte{{0x67, 0x00}, {0x6A, 0x80}, {0x6F, 0x00}, {0x90}} {
		card := &scripted{resp: [][]byte{append(append([]byte(nil), app...), 0x90, 0x00), sw}}
		a := openpgp.NewApplet(card, nil)
		check(t, a.VerifyPIN(context.Background(), pin(distinctive)))
	}
	card := &scripted{resp: [][]byte{append(append([]byte(nil), app...), 0x90, 0x00)}}
	check(t, openpgp.NewApplet(card, nil).VerifyPIN(context.Background(), pin(distinctive)))
}

func TestMalformedResponsesAreRejected(t *testing.T) {
	ok := []byte{0x90, 0x00}
	with := func(b ...[]byte) []byte {
		var out []byte
		for _, x := range b {
			out = append(out, x...)
		}
		return out
	}
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00}
	ed := []byte{0xC1, 0x0A, 0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}
	appData := func(inner []byte) []byte {
		return with([]byte{0x6E, byte(len(inner) + 2), 0x73, byte(len(inner))}, inner)
	}

	t.Run("open", func(t *testing.T) {
		for name, resp := range map[string][][]byte{
			"empty select response":   {{}},
			"one byte":                {{0x90}},
			"aid missing status":      {ok, aid},
			"aid too short":           {ok, with(aid[:8], ok)},
			"aid wrong prefix":        {ok, with([]byte{0xA0, 0, 0, 0, 3, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, ok)},
			"aid tlv truncated":       {ok, with([]byte{0x4F, 0x10, 0xD2, 0x76}, ok)},
			"get response runs away":  {ok, {0x61, 0x10}, {0x61, 0x10}, {0x61, 0x10}},
			"select answers 6D00":     {{0x6D, 0x00}},
			"get data answers 6E00":   {ok, {0x6E, 0x00}},
			"transport error at once": {},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := openpgp.Open(context.Background(), &scripted{resp: resp})
				require.Error(t, err)
			})
		}
	})

	t.Run("get response is capped", func(t *testing.T) {
		resp := [][]byte{ok}
		for range 1000 {
			resp = append(resp, with(bytes.Repeat([]byte{0x4F}, 255), []byte{0x61, 0x00}))
		}
		card := &scripted{resp: resp}
		_, err := openpgp.Open(context.Background(), card)
		require.ErrorIs(t, err, openpgp.ErrMalformed)
		assert.Less(t, card.i, 1000)
	})

	t.Run("info", func(t *testing.T) {
		for name, data := range map[string][]byte{
			"truncated 6E":             {0x6E, 0x20, 0x73},
			"length 81 truncated":      {0x6E, 0x81},
			"length 82 truncated":      {0x6E, 0x82, 0x01},
			"oversize length 83":       {0x6E, 0x83, 0x00, 0x00, 0x05, 0x73, 0x03, 0xC4, 0x01, 0x00},
			"oversize length 84":       {0x6E, 0x84, 0xFF, 0xFF, 0xFF, 0xFF},
			"indefinite length":        {0x6E, 0x80, 0x00, 0x00},
			"length past end":          {0x6E, 0x82, 0xFF, 0xFF, 0x73, 0x00},
			"tag runs off the end":     {0x7F},
			"multi-byte tag unbounded": {0x5F, 0xFF, 0xFF, 0xFF, 0xFF},
			"short C4":                 appData(with(ed, []byte{0xC4, 0x03, 0x00, 0x7F, 0x7F})),
			"missing C4":               appData(ed),
			"7F66 not two integers":    appData(with(ed, []byte{0xC4, 0x07, 0, 0x7F, 0x7F, 0x7F, 3, 0, 3}, []byte{0x7F, 0x66, 0x03, 0x02, 0x01, 0x08})),
		} {
			t.Run(name, func(t *testing.T) {
				card := &scripted{resp: [][]byte{with(data, ok), with([]byte{0x7A, 0x05, 0x93, 0x03, 0, 0, 1}, ok), {0x6A, 0x88}}}
				_, err := openpgp.NewApplet(card, aid).Info(context.Background())
				require.Error(t, err)
			})
		}
		card := &scripted{resp: [][]byte{
			with(appData(with(ed, []byte{0xC4, 0x07, 0, 0x7F, 0x7F, 0x7F, 3, 0, 3})), ok),
			with([]byte{0x7A, 0x04, 0x93, 0x02, 0, 1}, ok), // counter not 3 bytes
		}}
		_, err := openpgp.NewApplet(card, aid).Info(context.Background())
		require.Error(t, err)
	})

	t.Run("public key", func(t *testing.T) {
		pub := bytes.Repeat([]byte{7}, 32)
		app := with(appData(with(ed, []byte{0xC4, 0x07, 0, 0x7F, 0x7F, 0x7F, 3, 0, 3})), ok)
		for name, data := range map[string][]byte{
			"inner length 31":       with([]byte{0x7F, 0x49, 0x21, 0x86, 0x1F}, pub[:31]),
			"inner length 33 no 40": with([]byte{0x7F, 0x49, 0x23, 0x86, 0x21, 0x00}, pub),
			"inner overruns outer":  with([]byte{0x7F, 0x49, 0x10, 0x86, 0x20}, pub),
			"no 86":                 with([]byte{0x7F, 0x49, 0x22, 0x87, 0x20}, pub),
			"not 7F49":              with([]byte{0x7F, 0x48, 0x22, 0x86, 0x20}, pub),
			"empty":                 {},
		} {
			t.Run(name, func(t *testing.T) {
				card := &scripted{resp: [][]byte{app, with(data, ok)}}
				_, err := openpgp.NewApplet(card, aid).PublicKey(context.Background())
				require.Error(t, err)
			})
		}
		// The 0x40 native-point prefix some cards put before an EdDSA key is accepted.
		card := &scripted{resp: [][]byte{app, with([]byte{0x7F, 0x49, 0x23, 0x86, 0x21, 0x40}, pub, ok)}}
		got, err := openpgp.NewApplet(card, aid).PublicKey(context.Background())
		require.NoError(t, err)
		assert.Equal(t, ed25519.PublicKey(pub), got)
	})

	t.Run("sign", func(t *testing.T) {
		for name, resp := range map[string][]byte{
			"short signature":  with(bytes.Repeat([]byte{1}, 63), ok),
			"long signature":   with(bytes.Repeat([]byte{1}, 65), ok),
			"no status":        {0x01},
			"wrong length":     {0x67, 0x00},
			"unsupported":      {0x6D, 0x00},
			"class not served": {0x6E, 0x00},
		} {
			t.Run(name, func(t *testing.T) {
				a, _ := verifiedApplet(t, resp)
				_, err := a.Sign(context.Background(), []byte("m"))
				require.Error(t, err)
			})
		}
	})
}

func TestStatusErrorsAreReadable(t *testing.T) {
	card := &scripted{resp: [][]byte{{0x6A, 0x82}}}
	_, err := openpgp.Open(context.Background(), card)
	require.ErrorIs(t, err, openpgp.ErrNoApplet)
	var se *openpgp.StatusError
	a, _ := verifiedApplet(t, []byte{0x6D, 0x00})
	_, err = a.Sign(context.Background(), []byte("m"))
	require.ErrorAs(t, err, &se)
	assert.Equal(t, uint16(0x6D00), se.SW)
	assert.True(t, strings.Contains(err.Error(), "6D00"))
}

func TestCloseClosesTheCard(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t)})
	a := open(t, sim)
	require.NoError(t, a.Close())
	assert.True(t, sim.Closed())
}

func TestSimulatorRejectsMalformedCommands(t *testing.T) {
	sim := openpgptest.New(openpgptest.Options{Key: newKey(t)})
	sw := func(apdu ...byte) uint16 {
		r, err := sim.Transmit(context.Background(), apdu)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(r), 2)
		return uint16(r[len(r)-2])<<8 | uint16(r[len(r)-1])
	}
	assert.Equal(t, uint16(0x6700), sw(0x00, 0xA4))
	assert.Equal(t, uint16(0x6700), sw(0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2))
	assert.Equal(t, uint16(0x6E00), sw(0x80, 0xCA, 0x00, 0x6E, 0x00))
	assert.Equal(t, uint16(0x9000), sw(0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01))
	assert.Equal(t, uint16(0x6D00), sw(0x00, 0x99, 0x00, 0x00))
	assert.Equal(t, uint16(0x6A88), sw(0x00, 0xCA, 0x01, 0x23, 0x00))
	assert.Equal(t, uint16(0x6A86), sw(0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00, 0x00), "never generates a key")
}

// A 6Cxx answer to PSO:CDS is not answered by signing again (that would spend a single-use PIN).
func TestSignIsNotReissuedOn6C(t *testing.T) {
	a, card := verifiedApplet(t, []byte{0x6C, 0x40}, bytes.Repeat([]byte{1}, 66))
	_, err := a.Sign(context.Background(), []byte("m"))
	var se *openpgp.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, uint16(0x6C40), se.SW)
	assert.Len(t, card.sent, 1)
}

// A card that wants PW1 as a format 2 PIN block is refused before VERIFY.
func TestFormat2PINBlockIsRefused(t *testing.T) {
	c4 := []byte{0xC4, 0x07, 0x00, 0x88, 0x7F, 0x7F, 0x03, 0x00, 0x03}
	app := append([]byte{0x6E, byte(len(c4) + 2), 0x73, byte(len(c4))}, c4...)
	card := &scripted{resp: [][]byte{append(app, 0x90, 0x00)}}
	err := openpgp.NewApplet(card, nil).VerifyPIN(context.Background(), pin(goodPIN))
	require.ErrorIs(t, err, openpgp.ErrPINFormat)
	assert.Len(t, card.sent, 1, "only the GET DATA")
}
