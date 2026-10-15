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
)

// openPGPTimeout bounds one Issue from the PIN prompt to the verified file (spec: the signing
// step has a 2 minute limit).
const openPGPTimeout = 2 * time.Minute

// OpenPGPOptions configure an OpenPGPSigner.
type OpenPGPOptions struct {
	KeyID    string            // key ID written into licenses; must exist in the key set
	Expected ed25519.PublicKey // public key from the key set for KeyID
	// AskPIN reads the PIN; tries is the number of tries the card has left. The returned buffer
	// is handed to the card and zeroed after use.
	AskPIN func(ctx context.Context, tries int) ([]byte, error)
	// NotifyTouch is called right before the signature command when the card requires a touch.
	NotifyTouch  func()
	LastPINTry   bool // allow VERIFY when one try is left
	AllowNoTouch bool // allow signing when touch is not required
}

// OpenPGPSigner signs licenses with the Ed25519 signature key of an OpenPGP card (a YubiKey).
// It owns the card: Close closes it. It is not meant for concurrent Issue calls.
type OpenPGPSigner struct {
	o       OpenPGPOptions
	applet  *openpgp.Applet
	timeout time.Duration

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
	if _, err := s.preflight(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
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
	case !touchRequired(info.SigUIF) && !s.o.AllowNoTouch:
		return openpgp.Info{}, fmt.Errorf("%w (touch policy: %s)", ErrNoTouch, info.SigUIF)
	}
	if err := s.applet.RequireForcedPIN(ctx); err != nil {
		return openpgp.Info{}, err
	}
	return info, nil
}

func touchRequired(uif string) bool {
	switch uif {
	case "on", "fixed", "cached", "cached-fixed":
		return true
	}
	return false
}

// KeyID returns the key ID written into every license.
func (s *OpenPGPSigner) KeyID() string { return s.o.KeyID }

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
	if info.MaxCommandLength > 0 && len(signed) > info.MaxCommandLength {
		return nil, &openpgp.MessageTooLongError{Length: len(signed), Limit: info.MaxCommandLength}
	}

	pin, err := s.o.AskPIN(ctx, info.PW1Retries)
	if err != nil {
		clear(pin)
		return nil, err
	}
	if err := s.applet.VerifyPIN(ctx, pin); err != nil { // VerifyPIN zeroes pin
		return nil, err
	}
	if touchRequired(info.SigUIF) && s.o.NotifyTouch != nil {
		s.o.NotifyTouch()
	}
	sig, err := s.applet.Sign(ctx, signed)
	if err != nil {
		return nil, err
	}
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
