// Package openpgptest is a software OpenPGP card (specification 3.4 subset) for tests only; no
// non-test code imports it. It answers the APDUs the openpgp package sends: SELECT, GET DATA
// (4F, 6E, 7A, C1, C4, D6, F9), GET RESPONSE, GENERATE ASYMMETRIC KEY PAIR in read mode only,
// VERIFY and PSO:COMPUTE DIGITAL SIGNATURE with command chaining, signing with a software Ed25519
// key. It keeps a PIN retry counter, a touch policy with a hook that decides whether the touch
// happens, and can chunk its responses (61xx) or insist on the exact Le (6Cxx).
//
// It records the header, Lc and Le of every command but never the data, so a recorded log holds
// no PIN.
package openpgptest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"sync"
)

// Touch policies for Options.UIF (first byte of DO D6).
const (
	UIFOff         byte = 0x00
	UIFOn          byte = 0x01
	UIFFixed       byte = 0x02
	UIFCached      byte = 0x03
	UIFCachedFixed byte = 0x04
)

// DefaultPIN is PW1 unless Options.PIN says otherwise (the YubiKey factory default).
const DefaultPIN = "123456"

const maxRetries = 3

// Options configure a card. The zero value behaves like a YubiKey 5 with the Ed25519 algorithm
// set and no key: PIN 123456 with 3 tries, PW1 valid for several signatures (the factory
// "signature PIN not forced"), a wrong PIN answered 6982, extended length information saying
// 2048 bytes, command chaining, touch off and no response chunking. Other behaviour is opt-in.
type Options struct {
	Key     ed25519.PrivateKey // the signature key; nil is an empty slot
	AlgAttr []byte             // DO C1 value; nil is Ed25519 (0x16 + OID), empty is an empty object
	PIN     string             // PW1; "" is DefaultPIN
	Serial  uint32             // AID serial number bytes; 0 is 0x12345678
	// PW1SingleUse makes a VERIFY good for one PSO:CDS (PW status byte 00, "forcesig" on).
	PW1SingleUse bool
	// UIF is the touch policy of the signature key. NoUIF removes DO D6 altogether (GET DATA
	// answers 6A88); UIFOnlyByGetData leaves it out of DO 6E but answers GET DATA 00D6.
	UIF              byte
	NoUIF            bool
	UIFOnlyByGetData bool
	// Touch decides whether the owner touches the key during a PSO:CDS that needs it; nil is
	// always. TouchTimeoutSW is the status word for a missed touch (0 is 6982).
	Touch          func() bool
	TouchTimeoutSW uint16
	// WrongPIN63Cx answers a wrong PIN with 63Cx (tries left) instead of the YubiKey's 6982.
	WrongPIN63Cx bool
	// KDF sets up a KDF-DO (F9) with iterated and salted S2K.
	KDF bool
	// WrongApplet answers SELECT of the OpenPGP AID with 6A82.
	WrongApplet bool
	// Chunk is the most data bytes in one response; longer data is sent with 61xx and GET
	// RESPONSE. 0 is 256, the limit of a short APDU.
	Chunk int
	// StrictLe answers GET DATA and the public key read with 6Cxx when Le is not the exact length.
	StrictLe bool
	// ExtraAppData adds a filler object of that many bytes to DO 6E, to make it long.
	ExtraAppData int
	SigCount     int
	// MaxCommandLength is the maximum command length reported in DO 7F66 (0 is 2048);
	// NoExtLenInfo leaves 7F66 out.
	MaxCommandLength int
	NoExtLenInfo     bool
	// MaxMessage is the longest PSO:CDS input the card takes (0 is 4096); the part that goes
	// past it is answered 6700.
	MaxMessage int
	// RefuseChaining answers a chained PSO:CDS part with 6884.
	RefuseChaining bool
	// TruncateAt makes the card silently sign only the first TruncateAt bytes of a longer input.
	TruncateAt int
	// ZeroFingerprint leaves the signature key fingerprint in C5 all zero even with a key.
	ZeroFingerprint bool
}

// Command is one recorded command APDU without its data. Lc is 0 and Le -1 when absent; Le 256
// stands for an encoded 00.
type Command struct {
	CLA, INS, P1, P2 byte
	Lc, Le           int
}

// Sim is the simulated card. It is safe for concurrent use.
type Sim struct {
	mu       sync.Mutex
	o        Options
	aid      []byte
	pin      []byte
	retries  int
	verified bool
	selected bool
	closed   bool
	sigCount int
	chain    []byte
	chaining bool
	pending  []byte
	log      []Command
	signed   []byte
	received []byte
}

// New makes a card.
func New(o Options) *Sim {
	if o.PIN == "" {
		o.PIN = DefaultPIN
	}
	if o.Serial == 0 {
		o.Serial = 0x12345678
	}
	if o.TouchTimeoutSW == 0 {
		o.TouchTimeoutSW = 0x6982
	}
	if o.AlgAttr == nil {
		o.AlgAttr = []byte{0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}
	}
	aid := binary.BigEndian.AppendUint32([]byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06}, o.Serial)
	aid = append(aid, 0x00, 0x00)
	return &Sim{o: o, aid: aid, pin: []byte(o.PIN), retries: maxRetries, sigCount: o.SigCount}
}

// SetRetries sets the PW1 retry counter (0 blocks the PIN).
func (s *Sim) SetRetries(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retries = n
}

// Retries returns the PW1 retry counter.
func (s *Sim) Retries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retries
}

// Commands returns every command received so far.
func (s *Sim) Commands() []Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Command(nil), s.log...)
}

// Count returns how many commands with instruction byte ins were received.
func (s *Sim) Count(ins byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.log {
		if c.INS == ins {
			n++
		}
	}
	return n
}

// CountGetData returns how many GET DATA commands asked for tag.
func (s *Sim) CountGetData(tag uint16) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.log {
		if c.INS == 0xCA && uint16(c.P1)<<8|uint16(c.P2) == tag {
			n++
		}
	}
	return n
}

// LastSigned returns the message of the last successful PSO:CDS, as reassembled from its parts.
func (s *Sim) LastSigned() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.signed...)
}

// LastReceived returns the last complete PSO:CDS input as reassembled from its parts, whether
// or not it was signed (in full).
func (s *Sim) LastReceived() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.received...)
}

// Closed reports whether Close was called.
func (s *Sim) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close ends the session.
func (s *Sim) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed, s.selected, s.verified = true, false, false
	return nil
}

func sw(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

// Transmit answers one command APDU. Malformed commands get status words, never an error.
func (s *Sim) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(apdu) < 4 {
		return sw(0x6700), nil
	}
	c := Command{CLA: apdu[0], INS: apdu[1], P1: apdu[2], P2: apdu[3], Le: -1}
	var data []byte
	switch rest := apdu[4:]; {
	case len(rest) == 0:
	case len(rest) == 1:
		c.Le = leOf(rest[0])
	default:
		c.Lc = int(rest[0])
		switch {
		case c.Lc == 0: // extended length is not offered
			s.log = append(s.log, c)
			return sw(0x6700), nil
		case len(rest) == 1+c.Lc:
		case len(rest) == 2+c.Lc:
			c.Le = leOf(rest[1+c.Lc])
		default:
			s.log = append(s.log, c)
			return sw(0x6700), nil
		}
		data = rest[1 : 1+c.Lc]
	}
	s.log = append(s.log, c)
	if c.INS != 0xC0 {
		s.pending = nil
	}
	if s.chaining && c.INS != 0x2A {
		s.chain, s.chaining = nil, false
	}
	switch {
	case c.CLA != 0x00 && c.CLA != 0x10:
		return sw(0x6E00), nil
	case c.CLA == 0x10 && c.INS != 0x2A:
		return sw(0x6884), nil // command chaining not supported for this instruction
	}
	if c.INS == 0xA4 {
		return s.selectApp(c, data), nil
	}
	if !s.selected {
		return sw(0x6985), nil
	}
	switch c.INS {
	case 0xC0:
		if len(s.pending) == 0 {
			return sw(0x6985), nil
		}
		p := s.pending
		s.pending = nil
		return s.respond(p, c.Le, false), nil
	case 0xCA:
		return s.getData(c), nil
	case 0x20:
		return s.verify(c, data), nil
	case 0x47:
		return s.readKey(c, data), nil
	case 0x2A:
		return s.pso(c, data), nil
	}
	return sw(0x6D00), nil
}

func leOf(b byte) int {
	if b == 0 {
		return 256
	}
	return int(b)
}

func (s *Sim) selectApp(c Command, data []byte) []byte {
	if c.P1 != 0x04 {
		return sw(0x6A86)
	}
	if s.o.WrongApplet || len(data) < 5 || !bytes.HasPrefix(s.aid, data) {
		s.selected = false
		return sw(0x6A82)
	}
	s.selected, s.verified = true, false
	return sw(0x9000)
}

// respond sends data, as much as Le and the chunk size allow, with 61xx for the rest.
// strict applies StrictLe.
func (s *Sim) respond(data []byte, le int, strict bool) []byte {
	if strict && s.o.StrictLe && le >= 0 && len(data) <= 256 && le != len(data) {
		return sw(0x6C00 | uint16(len(data)&0xFF))
	}
	n := len(data)
	chunk := s.o.Chunk
	if chunk <= 0 || chunk > 256 {
		chunk = 256
	}
	n = min(n, chunk)
	if le >= 0 {
		n = min(n, le)
	}
	out := append([]byte(nil), data[:n]...)
	if n < len(data) {
		s.pending = append([]byte(nil), data[n:]...)
		return append(out, 0x61, byte(min(len(s.pending), 256)&0xFF))
	}
	return append(out, 0x90, 0x00)
}

func (s *Sim) getData(c Command) []byte {
	var v []byte
	switch uint16(c.P1)<<8 | uint16(c.P2) {
	case 0x004F:
		v = s.aid
	case 0x006E:
		v = s.appData()
	case 0x007A:
		v = tlv(0x7A, tlv(0x93, s.counter()))
	case 0x00C1:
		v = s.o.AlgAttr
	case 0x00C4:
		v = s.pwStatus()
	case 0x00D6:
		if s.o.NoUIF {
			return sw(0x6A88)
		}
		v = []byte{s.o.UIF, 0x20}
	case 0x00F9:
		alg := byte(0x00)
		if s.o.KDF {
			alg = 0x03 // KDF_ITERSALTED_S2K
		}
		v = tlv(0xF9, tlv(0x81, []byte{alg}))
	default:
		return sw(0x6A88)
	}
	return s.respond(v, c.Le, true)
}

func (s *Sim) counter() []byte {
	n := s.sigCount
	return []byte{byte(n >> 16 & 0xFF), byte(n >> 8 & 0xFF), byte(n & 0xFF)}
}

func (s *Sim) pwStatus() []byte {
	multi := byte(1)
	if s.o.PW1SingleUse {
		multi = 0
	}
	return []byte{multi, 0x7F, 0x7F, 0x7F, byte(s.retries & 0xFF), 0x00, maxRetries}
}

// appData builds DO 6E as a YubiKey 5 lays it out.
func (s *Sim) appData() []byte {
	fpr := make([]byte, 60)
	if s.o.Key != nil && !s.o.ZeroFingerprint {
		for i := range 20 {
			fpr[i] = byte(i + 1)
		}
	}
	extCap := []byte{0x7D, 0x00, 0x0B, 0xFE, 0x08, 0x00, 0x00, 0xFF, 0x00, 0x00}
	cv25519 := []byte{0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}
	var d []byte
	d = append(d, tlv(0xC0, extCap)...)
	d = append(d, tlv(0xC1, s.o.AlgAttr)...)
	d = append(d, tlv(0xC2, cv25519)...)
	d = append(d, tlv(0xC3, s.o.AlgAttr)...)
	d = append(d, tlv(0xC4, s.pwStatus())...)
	d = append(d, tlv(0xC5, fpr)...)
	d = append(d, tlv(0xC6, make([]byte, 60))...)
	d = append(d, tlv(0xCD, make([]byte, 12))...)
	d = append(d, tlv(0xDE, []byte{0x01, 0x02, 0x02, 0x00, 0x03, 0x00})...)
	if !s.o.NoUIF && !s.o.UIFOnlyByGetData {
		d = append(d, tlv(0xD6, []byte{s.o.UIF, 0x20})...)
	}
	if s.o.ExtraAppData > 0 {
		d = append(d, tlv(0x5F7F, make([]byte, s.o.ExtraAppData))...)
	}
	var app []byte
	app = append(app, tlv(0x4F, s.aid)...)
	app = append(app, tlv(0x5F52, []byte{0x00, 0x73, 0x00, 0x00, 0xE0, 0x05, 0x90, 0x00})...)
	if !s.o.NoExtLenInfo {
		maxCmd := s.o.MaxCommandLength
		if maxCmd == 0 {
			maxCmd = 2048
		}
		ext := append(tlv(0x02, binary.BigEndian.AppendUint16(nil, uint16(maxCmd&0xFFFF))), tlv(0x02, []byte{0x08, 0x00})...)
		app = append(app, tlv(0x7F66, ext)...)
	}
	app = append(app, tlv(0x73, d)...)
	return tlv(0x6E, app)
}

func (s *Sim) verify(c Command, data []byte) []byte {
	if c.P1 != 0x00 || (c.P2 != 0x81 && c.P2 != 0x82) {
		return sw(0x6A86)
	}
	if s.retries <= 0 {
		return sw(0x6983)
	}
	if len(data) == 0 { // status query
		if s.verified {
			return sw(0x9000)
		}
		return sw(0x63C0 | uint16(s.retries&0x0F))
	}
	if subtle.ConstantTimeCompare(data, s.pin) == 1 {
		s.retries, s.verified = maxRetries, true
		return sw(0x9000)
	}
	s.retries--
	s.verified = false
	if s.o.WrongPIN63Cx {
		return sw(0x63C0 | uint16(s.retries&0x0F))
	}
	return sw(0x6982)
}

func (s *Sim) readKey(c Command, data []byte) []byte {
	if c.P1 != 0x81 || c.P2 != 0x00 {
		return sw(0x6A86) // generating (P1 80) is never offered
	}
	if !bytes.Equal(data, []byte{0xB6, 0x00}) {
		return sw(0x6A80)
	}
	if s.o.Key == nil {
		return sw(0x6A88)
	}
	pub, _ := s.o.Key.Public().(ed25519.PublicKey)
	return s.respond(tlv(0x7F49, tlv(0x86, pub)), c.Le, true)
}

const maxChain = 4096

func (s *Sim) pso(c Command, data []byte) []byte {
	if c.P1 != 0x9E || c.P2 != 0x9A {
		s.chain, s.chaining = nil, false
		return sw(0x6A86)
	}
	if c.CLA == 0x10 && s.o.RefuseChaining {
		s.chain, s.chaining = nil, false
		return sw(0x6884)
	}
	limit := s.o.MaxMessage
	if limit <= 0 || limit > maxChain {
		limit = maxChain
	}
	if len(s.chain)+len(data) > limit {
		s.chain, s.chaining = nil, false
		return sw(0x6700)
	}
	s.chain = append(s.chain, data...)
	if c.CLA == 0x10 {
		s.chaining = true
		return sw(0x9000)
	}
	msg := s.chain
	s.chain, s.chaining = nil, false
	s.received = append([]byte(nil), msg...)
	if s.o.Key == nil {
		return sw(0x6A88)
	}
	if !s.verified {
		return sw(0x6982)
	}
	if s.o.PW1SingleUse {
		s.verified = false
	}
	if !s.o.NoUIF && s.o.UIF != UIFOff && s.o.Touch != nil && !s.o.Touch() {
		return sw(s.o.TouchTimeoutSW)
	}
	if s.o.TruncateAt > 0 && len(msg) > s.o.TruncateAt {
		msg = msg[:s.o.TruncateAt]
	}
	sig := ed25519.Sign(s.o.Key, msg)
	s.sigCount++
	s.signed = append([]byte(nil), msg...)
	return s.respond(sig, c.Le, false)
}

// tlv encodes one BER-TLV object with a one- or two-byte tag and the shortest length form.
func tlv(tag uint16, v []byte) []byte {
	var b []byte
	if tag > 0xFF {
		b = append(b, byte(tag>>8))
	}
	b = append(b, byte(tag&0xFF))
	switch n := len(v); {
	case n < 0x80:
		b = append(b, byte(n))
	case n <= 0xFF:
		b = append(b, 0x81, byte(n))
	default:
		b = append(b, 0x82, byte(n>>8&0xFF), byte(n&0xFF))
	}
	return append(b, v...)
}
