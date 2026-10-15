package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/vconsole/issue"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/sign/openpgp"
)

// interactiveLimit bounds the interactive signing step, from the confirmation display to the
// verified signature, with the signer's own limit (2 minutes). Issue holds the request row
// locked inside its transaction during this step, so an operator who walks away must not keep
// it (or the open transaction) for longer. A variable so tests need not wait for it.
var interactiveLimit = 2 * time.Minute

// cardTimeout bounds `signer info` and the card checks before a PIN prompt.
const cardTimeout = 30 * time.Second

// smokeText is, with its --max-size form, the only message other than a license that the
// vendor console signs with the license key (gpg's self-certification when the key is generated
// with gpg is the other exception, outside this program). It is not JSON and does not start with
// the product's signing prefix, so its signature can never verify as a license.
const smokeText = "alice-vendor-console smoke test: not a license"

// smokeMaxSize is the --max-size message length: sign.MaxSignedBytes, the longest signed bytes
// `issue` sends to the card. A passing --max-size test proves that size on the real card; a
// license above it is refused until the constant is raised after a larger smoke test.
const smokeMaxSize = sign.MaxSignedBytes

func smokeMessage(maxSize bool) []byte {
	if !maxSize {
		return []byte(smokeText)
	}
	b := []byte(smokeText + " (largest license size test) ")
	return append(b, bytes.Repeat([]byte("."), smokeMaxSize-len(b))...)
}

// productKeys is the key set compiled into this build, the one the product's own builds trust;
// tests replace it.
var productKeys = license.EmbeddedKeys

// What this build's key set says about a key ID and public key.
const (
	keySetYes       = "yes"
	keySetNo        = "no"
	keySetDifferent = "DIFFERENT KEY"
	keySetRevoked   = "revoked"
)

func productKeyState(id string, pub ed25519.PublicKey) string {
	for _, k := range productKeys().Keys() {
		if k.ID != id {
			continue
		}
		if !bytes.Equal(k.Key, pub) {
			return keySetDifferent
		}
		if k.Status != license.KeyActive {
			return keySetRevoked
		}
		return keySetYes
	}
	return keySetNo
}

// checkProductKeySet ties the key the card must hold to this build's key set (the signer's own
// final check only uses the key the operator named). A key ID listed with another key, or
// revoked, is refused. A key ID not listed yet (the normal state until a release embeds it) is a
// warning; issue then needs --not-in-key-set. ok is false when the command must stop with code.
func (c *cli) checkProductKeySet(k license.PublicKey, isIssue, notInKeySet bool) (code int, ok bool) {
	switch productKeyState(k.ID, k.Key) {
	case keySetYes:
		return 0, true
	case keySetDifferent:
		return c.fail(fmt.Errorf("key ID %s is in this build's key set with a different public key than %s; refusing (check the --pub or --keyset file)",
			k.ID, license.Fingerprint(k.Key))), false
	case keySetRevoked:
		return c.fail(fmt.Errorf("key ID %s is revoked in this build's key set; refusing", k.ID)), false
	}
	_, _ = fmt.Fprintf(c.err, "WARNING: key ID %s is not in this build's key set: customers' Alice builds will not accept what it signs "+
		"until a release that includes this key is shipped.\n", k.ID)
	if isIssue && !notInKeySet {
		return c.usageErr("refusing to issue a license with a key this build's key set does not list; pass --not-in-key-set to issue it anyway"), false
	}
	return 0, true
}

// loadCardKey returns the public key the card must hold: the --pub file (whose key ID must be
// keyID) or the active entry keyID of the --keyset file.
func loadCardKey(keyID, pubPath, keysetPath string) (license.PublicKey, error) {
	if pubPath != "" {
		ks, err := loadKeySet([]string{pubPath}, "")
		if err != nil {
			return license.PublicKey{}, err
		}
		k := ks.Keys()[0]
		if k.ID != keyID {
			return license.PublicKey{}, fmt.Errorf("%s holds key ID %s, not %s", pubPath, k.ID, keyID)
		}
		return k, nil
	}
	ks, err := loadKeySet(nil, keysetPath)
	if err != nil {
		return license.PublicKey{}, err
	}
	for _, k := range ks.Keys() {
		if k.ID == keyID {
			if k.Status != license.KeyActive {
				return license.PublicKey{}, fmt.Errorf("key ID %s is %s in %s", keyID, k.Status, keysetPath)
			}
			return k, nil
		}
	}
	return license.PublicKey{}, fmt.Errorf("%s has no key ID %s", keysetPath, keyID)
}

// encodePublicKey writes a public key file byte for byte as licensectl genkey does
// (issuer.GenerateKey): a PKIX "PUBLIC KEY" PEM block with the Key-Id header. issuer.ReadPublicKey
// (licensectl keyset, verify-licenses --pub) reads it; that check refuses a malformed key ID.
func encodePublicKey(keyID string, pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Key-Id": keyID}, Bytes: der})
	k, err := issuer.ReadPublicKey(out)
	if err != nil || k.ID != keyID || !bytes.Equal(k.Key, pub) {
		return nil, fmt.Errorf("key ID %q cannot go into a public key file (expected vk-YYYY-NN)", keyID)
	}
	return out, nil
}

// openTheCard connects to the card; a build without the yubikey tag is a usage error (code 2).
func (c *cli) openTheCard(reader string) (openpgp.Card, int, bool) {
	card, err := openCard(reader)
	if errors.Is(err, errNoPCSC) {
		return nil, c.usageErr("%v", err), false
	}
	if err != nil {
		return nil, c.fail(err), false
	}
	return card, 0, true
}

// openPGPIssue is `issue --signer openpgp`.
type openPGPIssue struct {
	params                                  issue.Params
	out                                     string
	keyID, pub, keyset, reader              string
	lastTry, allowNoTouch, yes, notInKeySet bool
}

func (c *cli) issueOpenPGP(o openPGPIssue) int {
	if !pcscBuilt {
		return c.usageErr("%v", errNoPCSC)
	}
	key, err := loadCardKey(o.keyID, o.pub, o.keyset)
	if err != nil {
		return c.usageErr("%v", err)
	}
	if code, ok := c.checkProductKeySet(key, true, o.notInKeySet); !ok {
		return code
	}
	// Ctrl-C cancels: the signer closes the card (ending a touch wait) and the transaction rolls back.
	ctx, stop := interruptContext(context.Background())
	defer stop()
	card, code, ok := c.openTheCard(o.reader)
	if !ok {
		return code
	}
	out, err := reserveOutput(o.out)
	if err != nil {
		_ = card.Close()
		return c.fail(err)
	}
	defer out.discard()
	var s *sign.OpenPGPSigner
	touchShown := false // the touch notice was printed: from then on the card may have signed
	cctx, ccancel := context.WithTimeout(ctx, cardTimeout)
	s, err = sign.NewOpenPGPSigner(cctx, card, sign.OpenPGPOptions{
		KeyID: key.ID, Expected: key.Key,
		AskPIN: func(ctx context.Context, tries int) ([]byte, error) {
			return c.con.secret(ctx, fmt.Sprintf("PIN of the YubiKey %s (%d tries left): ", s.Serial(), tries))
		},
		NotifyTouch: func() {
			touchShown = true
			_, _ = fmt.Fprintln(c.err, "Touch the YubiKey now...")
		},
		LastPINTry:   o.lastTry,
		AllowNoTouch: o.allowNoTouch,
		MaxMessage:   sign.MaxSignedBytes,
	})
	ccancel()
	if err != nil { // the card checks before any PIN prompt; the card is closed
		return c.signErr(err, false)
	}
	defer func() { _ = s.Close() }()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()

	// The transaction gets the interactive limit plus generous time for its database work; the
	// interactive step (question, PIN, touch) has its own limit, which ends when the card is done
	// so that it never cancels the writes that record a signature the card already made.
	tctx, tcancel := context.WithTimeout(ctx, interactiveLimit+dbAllowance)
	defer tcancel()
	step := &interactiveStep{}
	defer step.end()
	licenseID := o.params.LicenseID
	p := o.params
	p.Confirm = func(pl license.Payload, sum string) error {
		// From here the request row is locked.
		step.start(tctx)
		licenseID = pl.LicenseID
		writeConfirmation(c.err, pl, len(license.SignedBytes(pl)), sum, key.ID, s.Serial())
		if o.yes {
			return nil
		}
		_, _ = fmt.Fprint(c.err, "Sign this license? [y/N] ")
		ans, err := readAnswer(step.ctx, c.con.in)
		if err != nil {
			return err
		}
		if ans = strings.TrimSpace(ans); strings.EqualFold(ans, "y") || strings.EqualFold(ans, "yes") {
			return nil
		}
		return issue.ErrNotConfirmed
	}
	res, err := issue.Issue(tctx, pool, stepSigner{OpenPGPSigner: s, step: step}, p, c.clk.Now())
	switch {
	case err == nil:
		return c.deliver(out, res)
	case errors.Is(err, issue.ErrOutcomeUnknown):
		return c.fail(fmt.Errorf("the card signed and the license was written, but the database did not confirm the commit (%w): "+
			"the license may or may not be recorded. Before retrying, run: vendor-console request show %d; if it shows as signed, "+
			"get the file with: vendor-console license export --id %s --out FILE", err, p.RequestID, licenseID))
	case s.Signed():
		return c.fail(fmt.Errorf("the card made a signature (its signature counter went up) but no license was recorded by this command (%w). "+
			"Check: vendor-console request show %d; if the request shows as signed, use: vendor-console license export --id %s --out FILE. "+
			"The card's signature counter and the number of licenses will differ by one", err, p.RequestID, licenseID))
	case step.expired():
		return c.fail(fmt.Errorf("the license was not confirmed and signed within %s; nothing was signed or recorded and the card "+
			"connection is closed; run the command again", interactiveLimit))
	}
	return c.signErr(err, touchShown)
}

// dbAllowance is the time the issue transaction may take beyond the interactive step.
const dbAllowance = time.Minute

// interruptContext is canceled by Ctrl-C; tests replace it to cancel at a chosen moment.
var interruptContext = func(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt)
}

// interactiveStep is the limit of the interactive part of an issue: from the confirmation
// display to the card's answer. It starts in Confirm and ends when the signer returns.
type interactiveStep struct {
	ctx      context.Context
	cancel   context.CancelFunc
	ended    bool
	deadline bool
}

func (st *interactiveStep) start(parent context.Context) {
	st.ctx, st.cancel = context.WithTimeout(parent, interactiveLimit)
}

func (st *interactiveStep) end() {
	if st.cancel == nil || st.ended {
		return
	}
	st.deadline = errors.Is(st.ctx.Err(), context.DeadlineExceeded)
	st.ended = true
	st.cancel()
}

// expired reports whether the interactive limit ran out.
func (st *interactiveStep) expired() bool {
	if st.ended {
		return st.deadline
	}
	return st.ctx != nil && errors.Is(st.ctx.Err(), context.DeadlineExceeded)
}

// stepSigner runs the card signer under the interactive step's limit and ends the step when the
// card is done; the transaction goes on under its own context.
type stepSigner struct {
	*sign.OpenPGPSigner
	step *interactiveStep
}

func (b stepSigner) Issue(ctx context.Context, p license.Payload) ([]byte, error) {
	if b.step.ctx != nil {
		ctx = b.step.ctx
	}
	raw, err := b.OpenPGPSigner.Issue(ctx, p)
	b.step.end()
	return raw, err
}

// signErr words the failures of a card signing. afterTouch is true once the touch notice was
// shown: from then on a cancel may have come after the card signed (a touch and a lost answer),
// so it is not worded as "nothing was signed".
func (c *cli) signErr(err error, afterTouch bool) int {
	var pinErr *openpgp.PINError
	switch {
	case errors.As(err, &pinErr):
		left := "the card did not say how many tries are left"
		if pinErr.TriesLeft >= 0 {
			left = fmt.Sprintf("%d tries left", pinErr.TriesLeft)
		}
		return c.fail(fmt.Errorf("wrong PIN (%s). Nothing was signed; the PIN is never asked again automatically: run the command again to retry", left))
	case errors.Is(err, issue.ErrNotConfirmed):
		return c.fail(errors.New("not confirmed: nothing was signed and the request stays open"))
	case (errors.Is(err, context.Canceled) || errors.Is(err, sign.ErrSignerClosed)) && afterTouch:
		return c.fail(errors.New("signing cancelled: no license was recorded; if the key was touched its signature counter may have gone up"))
	case errors.Is(err, context.Canceled), errors.Is(err, sign.ErrSignerClosed):
		return c.fail(errors.New("signing cancelled: nothing was signed or recorded and the card connection is closed"))
	case errors.Is(err, context.DeadlineExceeded):
		return c.fail(fmt.Errorf("signing did not finish within its time limit: nothing was recorded and the card connection is closed; run the command again (%w)", err))
	case errors.Is(err, openpgp.ErrPINBlocked):
		return c.fail(fmt.Errorf("%w: nothing was signed; unblock it with the admin PIN or the reset code (gpg --card-edit or ykman) first", err))
	case errors.Is(err, openpgp.ErrTouchNeeded):
		return c.fail(errors.New("the YubiKey was not touched in time: nothing was signed; run the command again"))
	}
	return c.fail(err)
}

// writeConfirmation prints every field of the payload exactly as it will be signed, the key ID
// and card, the length of the signed bytes and their SHA-256.
func writeConfirmation(w io.Writer, p license.Payload, size int, sum, keyID, serial string) {
	none := func(s string) string {
		if s == "" {
			return "(none)"
		}
		return termSafe(s)
	}
	features := make([]string, len(p.Features))
	for i, f := range p.Features {
		features[i] = termSafe(f)
	}
	_, _ = fmt.Fprintf(w, "\nThe YubiKey will sign this license. Check every line against the request and what the customer sent:\n"+
		"  customer         %s\n  installation ID  %s\n  targets          %d\n  valid from       %s\n  valid until      %s\n"+
		"  months           %d\n  features         %s\n  replaces         %s\n  license ID       %s\n  issued at        %s\n"+
		"  format           %d\n  key ID           %s\n  card serial      %s\n"+
		"signed bytes: %d bytes\nSHA-256 of the signed bytes: %s\n",
		termSafe(p.Customer), termSafe(p.InstallationID), p.MaxTargets, p.ValidFrom.UTC().Format(time.RFC3339),
		p.ValidUntil.UTC().Format(time.RFC3339), termMonths(p.ValidFrom, p.ValidUntil), none(strings.Join(features, ",")),
		none(p.Replaces), termSafe(p.LicenseID), p.IssuedAt.UTC().Format(time.RFC3339), p.Format, termSafe(keyID), termSafe(serial), size, sum)
}

// termMonths is the term in calendar months between the dates (the request's months; the
// payload itself carries only the dates).
func termMonths(from, until time.Time) int {
	from, until = from.UTC(), until.UTC()
	return (until.Year()-from.Year())*12 + int(until.Month()) - int(from.Month())
}

// maxAnswer bounds the answer line to the question.
const maxAnswer = 64

// readAnswer reads one line from in, byte by byte (nothing after the line is consumed, so the
// PIN prompt that follows reads the terminal itself). End of input is an empty answer. When ctx
// ends first, ctx.Err() is returned and the read is left behind (the process exits soon after).
func readAnswer(ctx context.Context, in io.Reader) (string, error) {
	if in == nil {
		return "", nil
	}
	type answer struct {
		s   string
		err error
	}
	read := make(chan answer, 1)
	go func() {
		var b []byte
		one := make([]byte, 1)
		for len(b) < maxAnswer {
			n, err := in.Read(one)
			if n == 1 {
				if one[0] == '\n' {
					break
				}
				b = append(b, one[0])
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				read <- answer{err: err}
				return
			}
		}
		read <- answer{s: string(b)}
	}()
	select {
	case a := <-read:
		return a.s, a.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// signerInfo is `signer info`.
func (c *cli) signerInfo(args []string) int {
	fs := c.flags("signer info")
	reader := fs.String("reader", "", "smart card reader name (default: the one YubiKey)")
	keyID := fs.String("key-id", "", "key ID to compare the card's key with")
	pubPath := fs.String("pub", "", "public key file of that key ID")
	keysetPath := fs.String("keyset", "", "key set file holding that key ID")
	outPath := fs.String("out", "", "write the card's public key as a public key file (needs --key-id)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case fs.NArg() != 0:
		return c.usageErr("signer info takes no arguments besides its flags")
	case *pubPath != "" && *keysetPath != "":
		return c.usageErr("signer info takes --pub or --keyset, not both")
	case (*pubPath != "" || *keysetPath != "" || *outPath != "") && *keyID == "":
		return c.usageErr("--pub, --keyset and --out need --key-id")
	case !pcscBuilt:
		return c.usageErr("%v", errNoPCSC)
	}
	var want *license.PublicKey
	if *pubPath != "" || *keysetPath != "" {
		k, err := loadCardKey(*keyID, *pubPath, *keysetPath)
		if err != nil {
			return c.usageErr("%v", err)
		}
		want = &k
	}
	card, code, ok := c.openTheCard(*reader)
	if !ok {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), cardTimeout)
	defer cancel()
	a, err := openpgp.Open(ctx, card)
	if err != nil {
		_ = card.Close()
		return c.fail(err)
	}
	defer func() { _ = a.Close() }()
	info, err := a.Info(ctx)
	if err != nil {
		return c.fail(err)
	}
	pub, err := a.PublicKey(ctx)
	if err != nil && !errors.Is(err, openpgp.ErrNoKey) {
		return c.fail(err)
	}

	readerName := *reader
	if readerName == "" {
		readerName = "(the one YubiKey connected)"
	}
	tries := fmt.Sprint(info.PW1Retries)
	if info.PW1Blocked {
		tries += " (blocked)"
	}
	policy := "forced (the PIN is asked for every signature)"
	if info.PW1ValidForSeveral {
		policy = "NOT forced: signing will be refused (turn on forcesig with gpg --card-edit, admin)"
	}
	touch := info.SigUIF
	switch {
	case info.TouchRequired():
	case info.MayWaitForTouch():
		touch += " (signing will be refused unless --allow-no-touch: a cached touch lets a second signature through without a touch for about 15 seconds)"
	default:
		touch += " (signing will be refused unless --allow-no-touch)"
	}
	maxLen := "unknown"
	if info.MaxCommandLength > 0 {
		maxLen = fmt.Sprint(info.MaxCommandLength)
	}
	w := c.out
	_, _ = fmt.Fprintf(w, "reader               %s\ncard serial          %s\nsignature algorithm  %s\nPIN tries left       %s\n"+
		"PIN policy           %s\ntouch policy         %s\nsignature counter    %d\nmax command length   %s\ncommand chaining     %s\n",
		termSafe(readerName), info.Serial, termSafe(info.SigAlg), tries, policy, termSafe(touch), info.SigCount, maxLen, info.CommandChaining)
	if pub == nil {
		_, _ = fmt.Fprintln(w, "public key           none (the card has no signature key)")
	} else {
		_, _ = fmt.Fprintf(w, "public key           %s\nfingerprint          %s\n", base64.StdEncoding.EncodeToString(pub), license.Fingerprint(pub))
	}
	matches := true
	if want != nil {
		matches = pub != nil && bytes.Equal(pub, want.Key)
		answer := "yes"
		if !matches {
			answer = "NO (key ID " + want.ID + " is " + license.Fingerprint(want.Key) + ")"
		}
		_, _ = fmt.Fprintf(w, "matches key set      %s\n", answer)
	}
	state := ""
	if *keyID != "" && pub != nil {
		state = productKeyState(*keyID, pub)
		_, _ = fmt.Fprintf(w, "in this build's key set: %s\n", state)
	}
	if *outPath != "" {
		switch {
		case pub == nil:
			return c.fail(errors.New("the card has no signature key to write"))
		case !matches:
			return c.fail(errors.New("not writing the public key file: the card's key does not match the key set"))
		case state == keySetDifferent:
			return c.fail(fmt.Errorf("not writing the public key file: this build's key set lists key ID %s with a different key", *keyID))
		case state == keySetRevoked:
			return c.fail(fmt.Errorf("not writing the public key file: key ID %s is revoked in this build's key set", *keyID))
		}
		raw, err := encodePublicKey(*keyID, pub)
		if err != nil {
			return c.usageErr("%v", err)
		}
		if err := issuer.WriteNew(*outPath, raw, 0o644); err != nil {
			if errors.Is(err, issuer.ErrKeyExists) {
				return c.fail(fmt.Errorf("%s already exists: refusing to overwrite", *outPath))
			}
			return c.fail(fmt.Errorf("write %s: %w", *outPath, err))
		}
		_, _ = fmt.Fprintf(w, "wrote %s\n", *outPath)
	}
	if !matches {
		return 1 // scriptable: the card does not hold the named key
	}
	return 0
}

// signerTest is `signer test`: one signature over the fixed smoke-test text, verified.
func (c *cli) signerTest(args []string) int {
	fs := c.flags("signer test")
	reader := fs.String("reader", "", "smart card reader name (default: the one YubiKey)")
	keyID := fs.String("key-id", "", "key ID of the card's key")
	pubPath := fs.String("pub", "", "public key file of that key ID")
	keysetPath := fs.String("keyset", "", "key set file holding that key ID")
	maxSize := fs.Bool("max-size", false, fmt.Sprintf("sign a %d-byte text instead, the longest signed bytes issue sends to the card", smokeMaxSize))
	lastTry := fs.Bool("last-pin-try", false, "allow the PIN prompt when the card has one try left")
	allowNoTouch := fs.Bool("allow-no-touch", false, "allow a card whose touch policy is not on or fixed (off, cached, cached-fixed)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case fs.NArg() != 0:
		return c.usageErr("signer test takes no arguments besides its flags")
	case *keyID == "":
		return c.usageErr("signer test needs --key-id")
	case (*pubPath == "") == (*keysetPath == ""):
		return c.usageErr("signer test needs --pub FILE or --keyset FILE (one of them) for the key ID")
	case !pcscBuilt:
		return c.usageErr("%v", errNoPCSC)
	}
	key, err := loadCardKey(*keyID, *pubPath, *keysetPath)
	if err != nil {
		return c.usageErr("%v", err)
	}
	if code, ok := c.checkProductKeySet(key, false, false); !ok {
		return code
	}
	msg := smokeMessage(*maxSize)
	if *maxSize {
		_, _ = fmt.Fprintf(c.err, "The smoke test signs a %d-byte text starting with:\n  %s\n", len(msg), smokeText)
	} else {
		_, _ = fmt.Fprintf(c.err, "The smoke test signs this text:\n  %s\n", smokeText)
	}
	_, _ = fmt.Fprintln(c.err, "The license key signs nothing but licenses; the smoke-test texts are the vendor console's one exception. "+
		"This text is not a license and the product cannot accept it (its signature can never verify as a license).")

	ctx, stop := interruptContext(context.Background())
	defer stop()
	card, code, ok := c.openTheCard(*reader)
	if !ok {
		return code
	}
	ctx, cancel := context.WithTimeout(ctx, interactiveLimit)
	defer cancel()
	// Closing the card on cancel or the limit ends a pending touch wait.
	defer context.AfterFunc(ctx, func() { _ = card.Close() })()
	defer func() { _ = card.Close() }()
	touchShown := false
	if err := smokeTest(ctx, c, card, key, msg, *lastTry, *allowNoTouch, &touchShown); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return c.signErr(err, touchShown)
	}
	_, _ = fmt.Fprintf(c.out, "smoke test OK (signature verified with key ID %s, %s)\n", key.ID, license.Fingerprint(key.Key))
	return 0
}

// smokeTest runs the signer's checks before the PIN (the right key, PIN not blocked and not on
// its last try, PIN forced, touch required, input deliverable), then asks the PIN once, signs msg
// with the applet directly and verifies the signature.
func smokeTest(ctx context.Context, c *cli, card openpgp.Card, key license.PublicKey, msg []byte, lastTry, allowNoTouch bool, touchShown *bool) error {
	a, err := openpgp.Open(ctx, card)
	if err != nil {
		return err
	}
	pub, err := a.PublicKey(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, key.Key) {
		return fmt.Errorf("%w: key ID %s expects key %s, the card holds key %s", sign.ErrWrongCardKey, key.ID,
			license.Fingerprint(key.Key), license.Fingerprint(pub))
	}
	info, err := a.Info(ctx)
	if err != nil {
		return err
	}
	switch {
	case info.PW1Blocked:
		return openpgp.ErrPINBlocked
	case info.PW1Retries <= 1 && !lastTry:
		return sign.ErrLastPINTry
	case !info.TouchRequired() && !allowNoTouch:
		return sign.NoTouchError(info.SigUIF)
	case info.CommandChaining == "no" && len(msg) > 255:
		return &openpgp.MessageTooLongError{Length: len(msg), Limit: 255}
	}
	if err := a.RequireForcedPIN(ctx); err != nil {
		return err
	}
	pin, err := c.con.secret(ctx, fmt.Sprintf("PIN of the YubiKey %s (%d tries left): ", info.Serial, info.PW1Retries))
	if err != nil {
		clear(pin)
		return err
	}
	if err := a.VerifyPIN(ctx, pin); err != nil { // VerifyPIN zeroes our copy of the PIN
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if info.MayWaitForTouch() {
		*touchShown = true
		_, _ = fmt.Fprintln(c.err, "Touch the YubiKey now...")
	}
	sig, err := a.Sign(ctx, msg)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key.Key, msg, sig) {
		return sign.ErrBadCardSignature
	}
	return nil
}
