package sign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/vconsole/sign/openpgp"
)

// Errors of the OpenPGP card signer. The card errors (openpgp.ErrNoKey, openpgp.ErrNotEd25519,
// openpgp.ErrPINBlocked, openpgp.ErrPINNotForced, *openpgp.PINError, *openpgp.MessageTooLongError,
// ...) are returned as they are, so the command line can name the problem.
var (
	ErrWrongCardKey     = errors.New("sign: the key on the card is not the key set's key for this key ID")
	ErrLastPINTry       = errors.New("sign: the card has one PIN try left; signing is refused unless the last try is allowed explicitly")
	ErrNoTouch          = errors.New("sign: the card does not require a touch to sign; signing is refused unless that is allowed explicitly")
	ErrBadCardSignature = errors.New("sign: the card's signature does not verify with the expected key; no license was produced")
	ErrSignerClosed     = errors.New("sign: the card signer is closed")
	// ErrOverProvenSize: the signed bytes are longer than OpenPGPOptions.MaxMessage, the size the
	// smoke test proved the card takes. A *SizeLimitError wraps it with the numbers.
	ErrOverProvenSize = errors.New("sign: the license is longer than the size the smoke test proved")
)

// MaxSignedBytes is the longest signing input the vendor console sends to a card: the length of
// the `signer test --max-size` text, the size the hardware smoke test proves. Licenses whose
// signed bytes are longer are refused before the PIN prompt. Raise it only after a smoke test
// with the larger size passed on the real card.
const MaxSignedBytes = 1024

// SizeLimitError is a license refused before the PIN prompt because its signed bytes are longer
// than the proven size.
type SizeLimitError struct{ Length, Limit int }

func (e *SizeLimitError) Error() string {
	return fmt.Sprintf("sign: the license's signed bytes are %d bytes, more than the limit of %d bytes (the smoke test proved %d bytes); "+
		"nothing was sent to the card. Shorten the license (customer name, features) or raise the limit after a smoke test with a larger size",
		e.Length, e.Limit, e.Limit)
}

// Unwrap makes errors.Is(err, ErrOverProvenSize) hold.
func (e *SizeLimitError) Unwrap() error { return ErrOverProvenSize }

// openPGPTimeout bounds one Issue from the PIN prompt to the verified file (spec: the signing
// step has a 2 minute limit).
const openPGPTimeout = 2 * time.Minute

// shortAPDUData is the data field of one short command APDU: a longer message needs command
// chaining (the applet's rule in Sign; extended-length APDUs are not used).
const shortAPDUData = 255

// OpenPGPOptions configure an OpenPGPSigner.
type OpenPGPOptions struct {
	KeyID    string            // key ID written into licenses; must exist in the key set
	Expected ed25519.PublicKey // public key from the key set for KeyID
	// AskPIN reads the PIN; tries is the number of tries the card has left. The returned buffer
	// is handed to the card and zeroed after use, also when AskPIN returns an error with it. Only
	// our own buffers are cleared: the terminal library, pcscd or WinSCard may keep copies.
	AskPIN func(ctx context.Context, tries int) ([]byte, error)
	// NotifyTouch is called right before the signature command when the card may wait for a
	// touch (touch policy on, fixed, cached or cached-fixed).
	NotifyTouch func()
	LastPINTry  bool // allow VERIFY when one try is left
	// AllowNoTouch allows a card whose touch policy is not on or fixed: off, unsupported, cached
	// or cached-fixed (cached lets a second signature through without a touch for about 15
	// seconds after one).
	AllowNoTouch bool
	// MaxMessage is the longest signed bytes Issue sends to the card (0 is no limit); the command
	// line sets it to MaxSignedBytes. Longer licenses are refused before the PIN prompt.
	MaxMessage int
}

// OpenPGPSigner signs licenses with the Ed25519 signature key of an OpenPGP card (a YubiKey).
// It owns the card: Close closes it. It is not meant for concurrent Issue calls.
type OpenPGPSigner struct {
	o       OpenPGPOptions
	applet  *openpgp.Applet
	timeout time.Duration

	serial string      // card serial from the checks in NewOpenPGPSigner
	signed atomic.Bool // the card has returned a signature in some Issue

	mu     sync.Mutex
	closed bool
}

// NewOpenPGPSigner opens the OpenPGP application on card and checks, before any PIN prompt, that
// the card can sign licenses for o.KeyID: an Ed25519 signature key equal to o.Expected, a PIN that
// is not blocked and has more than one try left (unless o.LastPINTry), a touch required (unless
// o.AllowNoTouch) and the PIN asked for every signature. On any error the card is closed.
func NewOpenPGPSigner(ctx context.Context, card openpgp.Card, o OpenPGPOptions) (*OpenPGPSigner, error) {
	switch {
	case o.KeyID == "":
		_ = card.Close()
		return nil, errors.New("sign: no key ID")
	case len(o.Expected) != ed25519.PublicKeySize:
		_ = card.Close()
		return nil, errors.New("sign: no expected public key for the card")
	case o.AskPIN == nil:
		_ = card.Close()
		return nil, errors.New("sign: no way to ask for the PIN")
	}
	applet, err := openpgp.Open(ctx, card)
	if err != nil {
		_ = card.Close()
		return nil, err
	}
	s := &OpenPGPSigner{o: o, applet: applet, timeout: openPGPTimeout}
	info, err := s.preflight(ctx)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	s.serial = info.Serial
	return s, nil
}

// preflight runs every check that needs no PIN. Issue runs it again: a wrong PIN in an earlier
// Issue, or another program, may have changed the card since NewOpenPGPSigner.
func (s *OpenPGPSigner) preflight(ctx context.Context) (openpgp.Info, error) {
	pub, err := s.applet.PublicKey(ctx)
	if err != nil {
		return openpgp.Info{}, err
	}
	if !bytes.Equal(pub, s.o.Expected) {
		return openpgp.Info{}, fmt.Errorf("%w: key ID %s expects key %s, the card holds key %s",
			ErrWrongCardKey, s.o.KeyID, license.Fingerprint(s.o.Expected), license.Fingerprint(pub))
	}
	info, err := s.applet.Info(ctx)
	if err != nil {
		return openpgp.Info{}, err
	}
	switch {
	case info.PW1Blocked:
		return openpgp.Info{}, openpgp.ErrPINBlocked
	case info.PW1Retries <= 1 && !s.o.LastPINTry:
		return openpgp.Info{}, ErrLastPINTry
	case !info.TouchRequired() && !s.o.AllowNoTouch:
		return openpgp.Info{}, NoTouchError(info.SigUIF)
	}
	if err := s.applet.RequireForcedPIN(ctx); err != nil {
		return openpgp.Info{}, err
	}
	return info, nil
}

// NoTouchError is ErrNoTouch with the card's touch policy, and for a cached policy what it lets
// through.
func NoTouchError(uif string) error {
	if uif == "cached" || uif == "cached-fixed" {
		return fmt.Errorf("%w (touch policy: %s: after one touched signature the card signs again without a touch "+
			"for about 15 seconds, so a second signature could go through untouched)", ErrNoTouch, uif)
	}
	return fmt.Errorf("%w (touch policy: %s)", ErrNoTouch, uif)
}

// KeyID returns the key ID written into every license.
func (s *OpenPGPSigner) KeyID() string { return s.o.KeyID }

// Serial returns the card's serial number (8 hex digits), for the confirmation display and the
// PIN prompt.
func (s *OpenPGPSigner) Serial() string { return s.serial }

// Signed reports whether the card has returned a signature in an Issue call, even one that then
// failed (a bad signature, a cancel, the time limit). The card's signature counter went up then,
// so a caller that records nothing must say so.
func (s *OpenPGPSigner) Signed() bool { return s.signed.Load() }

// Public returns the verification key (the one checked against the card).
func (s *OpenPGPSigner) Public() ed25519.PublicKey { return s.o.Expected }

// Close closes the card. It may be called more than once.
func (s *OpenPGPSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.applet.Close()
}

func (s *OpenPGPSigner) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// prepare returns the payload as the product's issuer signs it, after the checks license.Sign
// and license.ParseFile make, so a payload the product would refuse never reaches the PIN prompt.
func prepare(keyID string, p license.Payload) (license.Payload, []byte, error) {
	p = issuer.NormalizePayload(p)
	if err := p.Validate(); err != nil {
		return license.Payload{}, nil, err
	}
	// A dry run of the file with a zero signature: key ID syntax and encoding are checked by the
	// product's own parser before the card is used.
	dry, err := license.EncodeFile(license.File{Format: p.Format, KeyID: keyID, Payload: p, Signature: make([]byte, ed25519.SignatureSize)})
	if err != nil {
		return license.Payload{}, nil, err
	}
	if _, err := license.ParseFile(dry); err != nil {
		return license.Payload{}, nil, err
	}
	return p, license.SignedBytes(p), nil
}

// PayloadDigest returns the bytes a signer signs for p (the product's signed bytes of the
// normalized payload) and their SHA-256 in hex, for the confirmation shown before the PIN.
func PayloadDigest(p license.Payload) (signed []byte, sha256hex string, err error) {
	p = issuer.NormalizePayload(p)
	if err := p.Validate(); err != nil {
		return nil, "", err
	}
	signed = license.SignedBytes(p)
	sum := sha256.Sum256(signed)
	return signed, hex.EncodeToString(sum[:]), nil
}

// Issue signs p on the card: it asks for the PIN once (never retrying a wrong one), waits for the
// touch, verifies the card's signature against the expected key and checks the finished file as
// the product would. Any failure returns no file. Cancelling ctx, or the 2 minute limit, closes
// the card (which ends a pending touch wait) and makes the signer unusable.
func (s *OpenPGPSigner) Issue(ctx context.Context, p license.Payload) ([]byte, error) {
	if s.isClosed() {
		return nil, ErrSignerClosed
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()

	raw, err := s.issue(ctx, p)
	if ctxErr := ctx.Err(); ctxErr != nil {
		// Whatever the card said after it was closed, the cause is the cancel or the limit.
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return nil, fmt.Errorf("sign: signing took longer than %s: %w", s.timeout, ctxErr)
		}
		return nil, ctxErr
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *OpenPGPSigner) issue(ctx context.Context, p license.Payload) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, signed, err := prepare(s.o.KeyID, p)
	if err != nil {
		return nil, err
	}
	info, err := s.preflight(ctx)
	if err != nil {
		return nil, err
	}
	// The applet's Sign would refuse this without sending anything; finding out after the PIN
	// would spend a VERIFY for nothing. Info.MaxCommandLength (DO 7F66) bounds one extended-length
	// command, not a chained message, so it is not a reason to refuse.
	if info.CommandChaining == "no" && len(signed) > shortAPDUData {
		return nil, &openpgp.MessageTooLongError{Length: len(signed), Limit: shortAPDUData}
	}
	// Longer than the smoke test proved the card takes: refused before the PIN as well.
	if s.o.MaxMessage > 0 && len(signed) > s.o.MaxMessage {
		return nil, &SizeLimitError{Length: len(signed), Limit: s.o.MaxMessage}
	}

	pin, err := s.o.AskPIN(ctx, info.PW1Retries)
	if err != nil {
		clear(pin)
		return nil, err
	}
	if err := s.applet.VerifyPIN(ctx, pin); err != nil { // VerifyPIN zeroes our copy of the PIN
		return nil, err
	}
	// A cancel that came during VERIFY ends here, before the touch notice: nothing was signed.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if info.MayWaitForTouch() && s.o.NotifyTouch != nil {
		s.o.NotifyTouch()
	}
	sig, err := s.applet.Sign(ctx, signed)
	if err != nil {
		return nil, err
	}
	s.signed.Store(true)
	// The card is not trusted to have signed what it was sent with the key it showed: a
	// truncating or substituted signature ends here.
	if !ed25519.Verify(s.o.Expected, signed, sig) {
		return nil, ErrBadCardSignature
	}
	raw, err := license.EncodeFile(license.File{Format: p.Format, KeyID: s.o.KeyID, Payload: p, Signature: sig})
	if err != nil {
		return nil, err
	}
	if _, err := Verify(raw, s); err != nil {
		return nil, fmt.Errorf("sign: the signed license does not pass the product's check: %w", err)
	}
	return raw, nil
}
