package openpgp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrNoApplet    = errors.New("openpgp: the card has no OpenPGP application")
	ErrNoKey       = errors.New("openpgp: the card has no signature key")
	ErrWrongPIN    = errors.New("openpgp: wrong PIN") // a *PINError wraps it with the tries left
	ErrPINBlocked  = errors.New("openpgp: the PIN is blocked")
	ErrTouchNeeded = errors.New("openpgp: the card wants a touch that did not happen")
	ErrNotEd25519  = errors.New("openpgp: the signature key is not Ed25519")
	// ErrNotVerified: PW1 (mode 81) is not verified for this signature. Sign returns it without
	// sending anything when this session has no unused VERIFY, and for a card answering 6982.
	ErrNotVerified = errors.New("openpgp: the PIN must be verified before signing")
	// ErrPINNotForced: the card keeps PW1 verified for several signatures (PW status byte 01), so
	// a program on the same machine could sign again without the PIN until the card is removed.
	ErrPINNotForced = errors.New("openpgp: the card does not ask for the PIN for every signature (signature PIN not forced); " +
		"turn it on with gpg --card-edit, then admin and forcesig (the usual GnuPG commands; check them for the installed version)")
	// ErrMessageTooLong: the input cannot be delivered: it needs command chaining and the card
	// says it has none. A *MessageTooLongError wraps it with the numbers.
	ErrMessageTooLong = errors.New("openpgp: the message is longer than the card accepts")
	// ErrCardRefusedLength: the card refused the signing input or one of its chained parts as too
	// long, malformed or not chainable (6700, 6A80, 6884). A *LengthRefusedError wraps it.
	ErrCardRefusedLength = errors.New("openpgp: the card refused the signing input")
	// ErrKDFUnsupported: the card has a KDF-DO (F9) set up, so it expects a hash of the PIN rather
	// than the PIN itself. Sending the raw PIN would only spend a try, so it is refused.
	ErrKDFUnsupported = errors.New("openpgp: the card uses a PIN key derivation function (KDF-DO), which is not supported")
	// ErrPINFormat: the card expects PW1 as an ISO 9564 format 2 PIN block, which is not supported.
	ErrPINFormat = errors.New("openpgp: the card expects a format 2 PIN block, which is not supported")
)

// PINError is a wrong PIN. TriesLeft is the card's PW1 retry counter after the failure, or -1
// when the card did not say.
type PINError struct{ TriesLeft int }

func (e *PINError) Error() string {
	if e.TriesLeft < 0 {
		return "openpgp: wrong PIN"
	}
	return fmt.Sprintf("openpgp: wrong PIN, %d tries left", e.TriesLeft)
}

// Unwrap makes errors.Is(err, ErrWrongPIN) hold.
func (e *PINError) Unwrap() error { return ErrWrongPIN }

// MessageTooLongError is a message refused before anything was sent.
type MessageTooLongError struct{ Length, Limit int }

func (e *MessageTooLongError) Error() string {
	return fmt.Sprintf("openpgp: the message has %d bytes and the card, which has no command chaining, accepts at most %d", e.Length, e.Limit)
}

// Unwrap makes errors.Is(err, ErrMessageTooLong) hold.
func (e *MessageTooLongError) Unwrap() error { return ErrMessageTooLong }

// LengthRefusedError says which part of a (possibly chained) PSO:CDS the card refused.
type LengthRefusedError struct {
	SW          uint16
	Part, Parts int // 1-based part number and number of parts
	Length      int // message length in bytes
}

func (e *LengthRefusedError) Error() string {
	where := "last"
	switch {
	case e.Parts == 1:
		where = "only"
	case e.Part == 1:
		where = "first"
	case e.Part < e.Parts:
		where = "middle"
	}
	return fmt.Sprintf("openpgp: the card refused the signing input of %d bytes at the %s part (%d of %d): status %04X (%s)",
		e.Length, where, e.Part, e.Parts, e.SW, swText(e.SW))
}

// Unwrap makes errors.Is(err, ErrCardRefusedLength) hold.
func (e *LengthRefusedError) Unwrap() error { return ErrCardRefusedLength }

// aidPrefix is the RID D276000124 plus the application byte 01 (OpenPGP); the version bytes
// that follow in the full AID differ from card to card, so SELECT uses this partial AID.
var aidPrefix = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}

// ed25519OID is 1.3.6.1.4.1.11591.15.1, the OpenPGP curve OID for Ed25519 in DO C1;
// ed25519OIDRFC8410 is 1.3.101.112 (id-Ed25519), which some newer cards report instead.
var (
	ed25519OID        = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}
	ed25519OIDRFC8410 = []byte{0x2B, 0x65, 0x70}
)

const (
	algEdDSA     = 0x16
	minPINLength = 6       // PW1 minimum, specification 3.4 section 4.3
	maxSignInput = 8 << 10 // a license payload is far smaller; bigger inputs are a caller bug
)

// Applet is a selected OpenPGP application on one card. Its methods serialise on a mutex; a
// card has one conversation at a time.
type Applet struct {
	mu       sync.Mutex
	card     Card
	aid      []byte
	verified bool   // PW1 mode 81 verified in this session and not yet used up
	pw1Multi bool   // PW status byte 1 was 01 at the last VERIFY: PW1 stays valid for several signatures
	chaining string // command chaining from the card capabilities at the last VERIFY: yes, no, unknown
}

// NewApplet wraps a card on which the OpenPGP application is already selected. aid may be nil;
// Info then takes it from DO 6E. Open is the usual way in.
func NewApplet(c Card, aid []byte) *Applet {
	return &Applet{card: c, aid: append([]byte(nil), aid...)}
}

// Open selects the OpenPGP application and reads its full AID (DO 4F).
func Open(ctx context.Context, c Card) (*Applet, error) {
	sel := command{ins: 0xA4, p1: 0x04, p2: 0x00, data: aidPrefix, le: -1}
	_, sw, err := exchange(ctx, c, sel, false)
	if err != nil {
		return nil, err
	}
	switch sw {
	case swOK:
	case swNotFound:
		return nil, ErrNoApplet
	default:
		return nil, &StatusError{Op: "select", SW: sw}
	}
	aid, err := getData(ctx, c, 0x004F)
	if err != nil {
		return nil, err
	}
	if len(aid) != 16 || !bytes.HasPrefix(aid, aidPrefix) {
		return nil, fmt.Errorf("%w: DO 4F is not an OpenPGP AID", ErrMalformed)
	}
	return &Applet{card: c, aid: aid}, nil
}

// Close closes the card connection.
func (a *Applet) Close() error { return a.card.Close() }

// getData reads one data object with GET DATA (00 CA tag 00). The card returns the value of the
// object; for a constructed object some cards include the outer tag, which callers unwrap.
func getData(ctx context.Context, c Card, tag uint16) ([]byte, error) {
	data, sw, err := getDataSW(ctx, c, tag)
	if err != nil {
		return nil, err
	}
	if sw != swOK {
		return nil, &StatusError{Op: fmt.Sprintf("get data %04X", tag), SW: sw}
	}
	return data, nil
}

func getDataSW(ctx context.Context, c Card, tag uint16) ([]byte, uint16, error) {
	return exchange(ctx, c, command{ins: 0xCA, p1: byte(tag >> 8), p2: byte(tag & 0xFF), le: 256}, false)
}

// unwrap parses b and, when it is exactly one object with the given tag, returns that object's
// children; otherwise b is taken to be the children already.
func unwrap(b []byte, tag uint32) ([]tlv, error) {
	objs, err := parseTLVs(b)
	if err != nil {
		return nil, err
	}
	if len(objs) == 1 && objs[0].tag == tag {
		return parseTLVs(objs[0].value)
	}
	return objs, nil
}

// appData is the part of DO 6E (application related data) this package uses.
type appData struct {
	aid    []byte // 4F
	extCap []byte // C0 extended capabilities
	sigAlg []byte // C1 algorithm attributes of the signature key
	pw     []byte // C4 PW status bytes
	uif    []byte // D6 user interaction flag for PSO:CDS (YubiKey, specification 3.4)
	hist   []byte // 5F52 historical bytes
	extLen []byte // 7F66 extended length information
	hasExt bool
	hasAlg bool
	hasUIF bool
}

// readAppData reads DO 6E. Its layout is 6E { 4F, 5F52, 7F74, 73 { C0, C1, C2, C3, C4, C5, ... } };
// objects are looked up inside 73 first and at the top level second, for cards that flatten it.
func (a *Applet) readAppData(ctx context.Context) (appData, error) {
	raw, err := getData(ctx, a.card, 0x006E)
	if err != nil {
		return appData{}, err
	}
	top, err := unwrap(raw, 0x6E)
	if err != nil {
		return appData{}, err
	}
	var disc []tlv
	if v, ok := find(top, 0x73); ok {
		if disc, err = parseTLVs(v); err != nil {
			return appData{}, err
		}
	}
	get := func(tag uint32) ([]byte, bool) {
		if v, ok := find(disc, tag); ok {
			return v, true
		}
		return find(top, tag)
	}
	var d appData
	d.aid, _ = get(0x4F)
	d.extCap, _ = get(0xC0)
	d.sigAlg, d.hasAlg = get(0xC1)
	d.uif, d.hasUIF = get(0xD6)
	d.hist, _ = get(0x5F52)
	d.extLen, d.hasExt = get(0x7F66)
	pw, ok := get(0xC4)
	if !ok || len(pw) < 7 {
		return appData{}, fmt.Errorf("%w: DO 6E has no complete PW status (C4)", ErrMalformed)
	}
	d.pw = pw
	return d, nil
}

// pwStatus decodes DO C4. Byte numbers here are zero-based (the specification counts from 1):
// 0 PW1 valid for one (00) or several (01) PSO:CDS; 1..3 maximum lengths of PW1, RC, PW3 (bit 8
// of byte 1 set means PW1 is a format 2 PIN block); 4..6 retry counters of PW1, RC, PW3.
type pwStatus struct {
	multi   bool
	maxLen  int
	format2 bool
	retries int
}

func decodePW(c4 []byte) pwStatus {
	return pwStatus{multi: c4[0] == 0x01, maxLen: int(c4[1] & 0x7F), format2: c4[1]&0x80 != 0, retries: int(c4[4])}
}

// Info describes the card for `signer info` and the checks before signing.
type Info struct {
	AID        []byte // full AID from DO 004F
	Serial     string // 8 hex digits from AID bytes 10..13 (zero-based)
	SigAlg     string // "ed25519", "other:<hex of C1>" or "none"
	PW1Retries int    // PW1 tries left (DO C4 byte 4, zero-based)
	PW1Blocked bool
	SigUIF     string // "off", "on", "fixed", "cached", "cached-fixed", "unsupported" or "unknown:<hex>"
	SigCount   int    // digital signature counter (DO 93 inside DO 7A)
	// PW1ValidForSeveral is PW status byte 01: after one VERIFY the card signs again without the
	// PIN until it is reset or removed ("signature PIN not forced"). See RequireForcedPIN.
	PW1ValidForSeveral bool
	// MaxCommandLength is the maximum length of one command from the extended length information
	// (DO 7F66, from DO 6E or its own GET DATA); 0 when the card does not say. It bounds one
	// extended-length APDU, not a chained message: it is reported, not enforced.
	MaxCommandLength int
	// CommandChaining is "yes" or "no" from the card capabilities in the historical bytes, or
	// "unknown" when they are absent or not in the compact-TLV format.
	CommandChaining string
}

// Info reads DO 6E, the signature counter and the touch policy of the signature key.
func (a *Applet) Info(ctx context.Context) (Info, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.readAppData(ctx)
	if err != nil {
		return Info{}, err
	}
	aid := a.aid
	if len(d.aid) > 0 {
		aid = d.aid
	}
	if len(aid) != 16 || !bytes.HasPrefix(aid, aidPrefix) {
		return Info{}, fmt.Errorf("%w: no OpenPGP AID", ErrMalformed)
	}
	pw := decodePW(d.pw)
	info := Info{
		AID:        append([]byte(nil), aid...),
		Serial:     fmt.Sprintf("%X", aid[10:14]),
		SigAlg:     algName(d.sigAlg, d.hasAlg),
		PW1Retries: pw.retries,
		PW1Blocked: pw.retries == 0,

		PW1ValidForSeveral: pw.multi,
		CommandChaining:    chaining(d.hist),
	}
	if info.SigCount, err = a.sigCounter(ctx); err != nil {
		return Info{}, err
	}
	if info.SigUIF, err = a.sigUIF(ctx, d); err != nil {
		return Info{}, err
	}
	if info.MaxCommandLength, err = a.maxCommandLength(ctx, d); err != nil {
		return Info{}, err
	}
	return info, nil
}

// RequireForcedPIN returns ErrPINNotForced when the card keeps PW1 verified for several
// signatures. The signer refuses such a card: the license key must ask for the PIN every time.
func (a *Applet) RequireForcedPIN(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.readAppData(ctx)
	if err != nil {
		return err
	}
	if decodePW(d.pw).multi {
		return ErrPINNotForced
	}
	return nil
}

// maxCommandLength reads DO 7F66 (specification 3.x): 02 02 <max command length> 02 02 <max
// response length>, from DO 6E when it is there and with GET DATA 7F66 otherwise. Any status
// other than 9000 for that GET DATA (absent object, unknown tag or instruction, ...) is 0,
// unknown; a 9000 answer or a DO 6E object that is malformed is an error.
func (a *Applet) maxCommandLength(ctx context.Context, d appData) (int, error) {
	var objs []tlv
	var err error
	if d.hasExt {
		objs, err = parseTLVs(d.extLen)
	} else {
		raw, sw, gerr := getDataSW(ctx, a.card, 0x7F66)
		if gerr != nil {
			return 0, gerr
		}
		if sw != swOK {
			return 0, nil // the value is only reported: any refusal means the card does not say
		}
		objs, err = unwrap(raw, 0x7F66)
	}
	if err != nil {
		return 0, err
	}
	if len(objs) < 1 || objs[0].tag != 0x02 || len(objs[0].value) != 2 {
		return 0, fmt.Errorf("%w: extended length information (7F66) is not two 2-byte integers", ErrMalformed)
	}
	return int(objs[0].value[0])<<8 | int(objs[0].value[1]), nil
}

// chaining reads the command chaining bit from the card capabilities in the historical bytes
// (ISO 7816-4 compact-TLV after a category indicator 00, whose last three bytes are the status
// indicator; tag 7 length 3, third byte bit 8).
func chaining(hist []byte) string {
	if len(hist) < 4 || hist[0] != 0x00 {
		return "unknown"
	}
	b := hist[1 : len(hist)-3]
	for len(b) > 0 {
		tag, n := b[0]>>4, int(b[0]&0x0F)
		if 1+n > len(b) {
			return "unknown"
		}
		if tag == 0x7 && n == 3 {
			if b[3]&0x80 != 0 {
				return "yes"
			}
			return "no"
		}
		b = b[1+n:]
	}
	return "unknown"
}

// sigCounter reads the digital signature counter, DO 93 (3 bytes) inside the security support
// template DO 7A; 93 is not a GET DATA tag of its own.
func (a *Applet) sigCounter(ctx context.Context) (int, error) {
	raw, err := getData(ctx, a.card, 0x007A)
	if err != nil {
		return 0, err
	}
	objs, err := unwrap(raw, 0x7A)
	if err != nil {
		return 0, err
	}
	v, ok := find(objs, 0x93)
	if !ok || len(v) != 3 {
		return 0, fmt.Errorf("%w: no 3-byte signature counter in DO 7A", ErrMalformed)
	}
	return int(v[0])<<16 | int(v[1])<<8 | int(v[2]), nil
}

// sigUIF returns the touch policy of the signature key from DO D6, taken from DO 6E when the
// card puts it there and read with GET DATA 00D6 otherwise. A card without the object (6A88,
// 6A82, 6B00) has no touch support.
func (a *Applet) sigUIF(ctx context.Context, d appData) (string, error) {
	v, ok := d.uif, d.hasUIF
	if !ok {
		data, sw, err := getDataSW(ctx, a.card, 0x00D6)
		if err != nil {
			return "", err
		}
		switch sw {
		case swOK:
			v = data
		case swDataNotFound, swNotFound, 0x6B00:
			return "unsupported", nil
		default:
			return "", &StatusError{Op: "get data 00D6", SW: sw}
		}
	}
	if len(v) < 1 {
		return "", fmt.Errorf("%w: empty UIF object", ErrMalformed)
	}
	switch v[0] {
	case 0x00:
		return "off", nil
	case 0x01:
		return "on", nil
	case 0x02:
		return "fixed", nil
	case 0x03:
		return "cached", nil
	case 0x04:
		return "cached-fixed", nil
	}
	return fmt.Sprintf("unknown:%02x", v[0]), nil
}

// TouchRequired reports whether the signature key's touch policy makes the card wait for a touch
// before every signature: on or fixed. Cached and cached-fixed are not enough: after one touched
// signature the card signs again without a touch for about 15 seconds.
func (i Info) TouchRequired() bool { return i.SigUIF == "on" || i.SigUIF == "fixed" }

// MayWaitForTouch reports whether the card may wait for a touch before it signs: TouchRequired or
// a cached policy (whose cache may have run out).
func (i Info) MayWaitForTouch() bool { return mayWaitForTouch(i.SigUIF) }

func mayWaitForTouch(uif string) bool {
	switch uif {
	case "on", "fixed", "cached", "cached-fixed":
		return true
	}
	return false
}

// algName names the signature key algorithm from DO C1. EdDSA is algorithm 0x16 followed by
// the curve OID (without the ASN.1 tag and length), optionally followed by an import-format
// byte 0xFF; YubiKeys report the OID only.
func algName(c1 []byte, present bool) string {
	if !present || len(c1) == 0 {
		return "none"
	}
	if isEd25519(c1) {
		return "ed25519"
	}
	return fmt.Sprintf("other:%x", c1)
}

func isEd25519(c1 []byte) bool {
	if len(c1) < 2 || c1[0] != algEdDSA {
		return false
	}
	oid := c1[1:]
	if oid[len(oid)-1] == 0xFF {
		oid = oid[:len(oid)-1]
	}
	return bytes.Equal(oid, ed25519OID) || bytes.Equal(oid, ed25519OIDRFC8410)
}

// PublicKey reads the existing signature key with GENERATE ASYMMETRIC KEY PAIR in its read mode
// (P1 81, control reference template B6 00); it never generates. The answer for EdDSA is
// 7F49 { 86 <32-byte point> }.
func (a *Applet) PublicKey(ctx context.Context) (ed25519.PublicKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.readAppData(ctx)
	if err != nil {
		return nil, err
	}
	if !isEd25519(d.sigAlg) {
		return nil, ErrNotEd25519
	}
	// An all-zero fingerprint (C5) is not proof of an empty slot: keys generated without GnuPG may
	// leave it unset. The key read decides.
	data, sw, err := exchange(ctx, a.card, command{ins: 0x47, p1: 0x81, p2: 0x00, data: []byte{0xB6, 0x00}, le: 256}, false)
	if err != nil {
		return nil, err
	}
	switch sw {
	case swOK:
	case swDataNotFound, swNotFound:
		return nil, ErrNoKey
	default:
		return nil, &StatusError{Op: "read public key", SW: sw}
	}
	objs, err := parseTLVs(data)
	if err != nil {
		return nil, err
	}
	tmpl, ok := find(objs, 0x7F49)
	if !ok {
		return nil, fmt.Errorf("%w: no public key template 7F49", ErrMalformed)
	}
	inner, err := parseTLVs(tmpl)
	if err != nil {
		return nil, err
	}
	pt, ok := find(inner, 0x86)
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: no EdDSA point (86) in 7F49", ErrMalformed)
	case len(pt) == 0:
		return nil, ErrNoKey
	case len(pt) == ed25519.PublicKeySize:
	case len(pt) == ed25519.PublicKeySize+1 && pt[0] == 0x40:
		pt = pt[1:] // the native-point prefix of OpenPGP EdDSA MPIs, which some cards keep
	default:
		return nil, fmt.Errorf("%w: EdDSA point of %d bytes", ErrMalformed, len(pt))
	}
	return ed25519.PublicKey(append([]byte(nil), pt...)), nil
}

// VerifyPIN verifies PW1 for signing (VERIFY 00 20 00 81). It reads the retry counter first and
// refuses a blocked PIN without sending anything; it sends exactly one VERIFY and never retries.
// pin is the raw PIN bytes (UTF-8); this buffer is zeroed before VerifyPIN returns, on every path
// (only our own buffer: the PC/SC layer, pcscd or WinSCard, may keep its own copy of the command).
func (a *Applet) VerifyPIN(ctx context.Context, pin []byte) error {
	defer clear(pin)
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.readAppData(ctx)
	if err != nil {
		return err
	}
	pw := decodePW(d.pw)
	if pw.retries == 0 {
		return ErrPINBlocked
	}
	if pw.format2 {
		return ErrPINFormat
	}
	if err := a.checkKDF(ctx, d); err != nil {
		return err
	}
	maxLen := pw.maxLen
	if maxLen == 0 || maxLen > 127 {
		maxLen = 127
	}
	if len(pin) < minPINLength {
		return fmt.Errorf("openpgp: the PIN must have at least %d characters", minPINLength)
	}
	if len(pin) > maxLen {
		return fmt.Errorf("openpgp: the PIN is longer than the card's maximum of %d bytes", maxLen)
	}

	a.verified = false
	_, sw, err := exchange(ctx, a.card, command{ins: 0x20, p1: 0x00, p2: 0x81, data: pin, le: -1}, true)
	if err != nil {
		return err
	}
	switch {
	case sw == swOK:
		a.verified, a.pw1Multi, a.chaining = true, pw.multi, chaining(d.hist)
		return nil
	case sw&0xFFF0 == 0x63C0:
		return wrongPIN(int(sw & 0x0F))
	case sw == swSecurity:
		// YubiKeys answer a wrong PIN with 6982 rather than 63Cx: the counter tells the tries left.
		// Reading it is GET DATA only; the PIN is not sent again.
		left := -1
		if d2, err := a.readAppData(ctx); err == nil {
			left = decodePW(d2.pw).retries
		}
		return wrongPIN(left)
	case sw == swBlocked:
		return ErrPINBlocked
	}
	return &StatusError{Op: "verify", SW: sw}
}

func wrongPIN(left int) error {
	if left == 0 {
		return ErrPINBlocked
	}
	return &PINError{TriesLeft: left}
}

// checkKDF refuses a card whose KDF-DO (F9) asks for a derived PIN. The extended capabilities
// (C0 byte 1, bit 1, zero-based byte 0) say whether the card knows KDF at all.
func (a *Applet) checkKDF(ctx context.Context, d appData) error {
	if len(d.extCap) == 0 || d.extCap[0]&0x01 == 0 {
		return nil
	}
	data, sw, err := getDataSW(ctx, a.card, 0x00F9)
	if err != nil {
		return err
	}
	switch sw {
	case swOK:
	case swDataNotFound, swNotFound, 0x6B00:
		return nil
	default:
		return &StatusError{Op: "get data 00F9", SW: sw}
	}
	if len(data) == 0 {
		return nil
	}
	objs, err := unwrap(data, 0xF9)
	if err != nil {
		return err
	}
	if alg, ok := find(objs, 0x81); ok && len(alg) == 1 && alg[0] == 0x00 {
		return nil // KDF_NONE
	}
	return ErrKDFUnsupported
}

// Sign computes an Ed25519 signature over message with PSO:COMPUTE DIGITAL SIGNATURE (00 2A 9E
// 9A). For EdDSA the card signs its input as the message (PureEdDSA), so message is sent as is,
// chained in 255-byte parts when it is longer. A successful VerifyPIN in this session must come
// first, and in single-use mode one VerifyPIN covers one Sign: otherwise Sign returns
// ErrNotVerified without sending anything.
//
// Sign refuses locally (*MessageTooLongError, nothing sent) only a message that cannot be
// delivered at all: longer than one short APDU (255 bytes; extended-length APDUs are not used)
// on a card whose capabilities say it has no command chaining. With chaining supported or not
// stated, the message is sent chained and the card's own buffer limit decides; a refusal there is
// a *LengthRefusedError naming the part. Sign returns the card's signature unverified: checking
// it against the public key is the caller's job.
func (a *Applet) Sign(ctx context.Context, message []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(message) == 0 || len(message) > maxSignInput {
		return nil, fmt.Errorf("openpgp: refusing to sign %d bytes (1 to %d)", len(message), maxSignInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !a.verified {
		return nil, ErrNotVerified
	}
	// Whatever happens next, a single-use PW1 is spent and any failure asks for a new VERIFY.
	keep := a.pw1Multi
	a.verified = false
	if a.chaining == "no" && len(message) > chunkSize {
		return nil, &MessageTooLongError{Length: len(message), Limit: chunkSize}
	}
	data, sw, part, parts, err := exchangeChained(ctx, a.card, command{ins: 0x2A, p1: 0x9E, p2: 0x9A, data: message, le: 256, noReissue: true})
	if err != nil {
		return nil, err
	}
	switch sw {
	case swOK:
		if len(data) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%w: signature of %d bytes", ErrMalformed, len(data))
		}
		a.verified = keep
		return data, nil
	case 0x6700, 0x6A80, 0x6884:
		return nil, &LengthRefusedError{SW: sw, Part: part, Parts: parts, Length: len(message)}
	case swSecurity, swConditions:
		// PW1 was verified, so a refusal now is the touch timing out, if the key wants one.
		d, err := a.readAppData(ctx)
		if err != nil {
			return nil, fmt.Errorf("openpgp: the card refused to sign (status %04X) and its touch policy could not be read: %w", sw, err)
		}
		uif, err := a.sigUIF(ctx, d)
		if err != nil {
			return nil, fmt.Errorf("openpgp: the card refused to sign (status %04X) and its touch policy could not be read: %w", sw, err)
		}
		if mayWaitForTouch(uif) {
			return nil, ErrTouchNeeded
		}
		if sw == swSecurity {
			return nil, ErrNotVerified // the card forgot the VERIFY (reset, another program)
		}
	}
	return nil, &StatusError{Op: "sign", SW: sw}
}
