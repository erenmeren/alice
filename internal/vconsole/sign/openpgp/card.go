// Package openpgp speaks the OpenPGP card application (specification 3.4) at the APDU level, just
// enough to read the Ed25519 signature key of a YubiKey and sign with it: SELECT, GET DATA,
// reading a public key, VERIFY PW1 and PSO:COMPUTE DIGITAL SIGNATURE. The transport (PC/SC) is
// behind the Card interface, so everything here is tested against a software card.
//
// Nothing in this package ever puts a PIN into an error, a log or a panic: error text is built
// from status words and operation names only, never from APDU bytes.
package openpgp

import (
	"context"
	"errors"
	"fmt"
)

// Card is one connected card. Transmit sends one command APDU and returns the full response
// including the two status bytes. Transmit must not keep a reference to apdu after it returns:
// the applet zeroes command buffers that held a PIN. Its errors must not quote APDU bytes either,
// because the applet wraps them.
type Card interface {
	Transmit(ctx context.Context, apdu []byte) ([]byte, error)
	Close() error
}

// ErrMalformed reports a response that does not follow the specification (too short, a bad
// TLV, a missing object, too much GET RESPONSE data).
var ErrMalformed = errors.New("openpgp: malformed card response")

// StatusError is a status word other than 9000 that has no more specific error.
type StatusError struct {
	Op string // "select", "get data 006E", "verify", "sign", ...
	SW uint16
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("openpgp: %s: card status %04X (%s)", e.Op, e.SW, swText(e.SW))
}

func swText(sw uint16) string {
	switch {
	case sw == 0x9000:
		return "ok"
	case sw&0xFFF0 == 0x63C0:
		return fmt.Sprintf("verification failed, %d tries left", sw&0x0F)
	}
	switch sw {
	case 0x6700:
		return "wrong length"
	case 0x6982:
		return "security status not satisfied"
	case 0x6983:
		return "authentication method blocked"
	case 0x6985:
		return "conditions of use not satisfied"
	case 0x6A80:
		return "incorrect data"
	case 0x6A82:
		return "file or application not found"
	case 0x6A86:
		return "incorrect parameters"
	case 0x6A88:
		return "referenced data not found"
	case 0x6B00:
		return "wrong parameters"
	case 0x6D00:
		return "instruction not supported"
	case 0x6E00:
		return "class not supported"
	case 0x6F00:
		return "no precise diagnosis"
	}
	return "unknown"
}

const (
	swOK            = 0x9000
	swSecurity      = 0x6982
	swBlocked       = 0x6983
	swConditions    = 0x6985
	swNotFound      = 0x6A82
	swDataNotFound  = 0x6A88
	maxResponseSize = 64 << 10 // far above anything an OpenPGP card returns; stops a looping 61xx
	chunkSize       = 255      // short APDU data field; longer data goes out with command chaining
)

// command is one short APDU. le < 0 means no Le field; le 256 is encoded as 00.
type command struct {
	cla, ins, p1, p2 byte
	data             []byte
	le               int
	// noReissue turns a 6Cxx answer into an error instead of sending the command again: a second
	// PSO:CDS would sign twice and spend a single-use PW1.
	noReissue bool
}

// encode builds the APDU bytes. len(data) is at most 255 and le at most 256: callers chunk.
func (c command) encode() []byte {
	b := make([]byte, 0, 4+1+len(c.data)+1)
	b = append(b, c.cla, c.ins, c.p1, c.p2)
	if len(c.data) > 0 {
		b = append(b, byte(len(c.data)&0xFF))
		b = append(b, c.data...)
	}
	if c.le >= 0 {
		b = append(b, byte(c.le&0xFF)) // 256 encodes as 00
	}
	return b
}

// transmit sends one APDU and splits the status word off. The context is checked first, so a
// cancelled operation sends nothing more. The returned data is a copy.
func transmit(ctx context.Context, card Card, apdu []byte) ([]byte, uint16, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	r, err := card.Transmit(ctx, apdu)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, ctxErr
		}
		// The transport's error never carries the APDU (PC/SC reports codes), so it is safe to wrap.
		return nil, 0, fmt.Errorf("openpgp: card transmit: %w", err)
	}
	if len(r) < 2 {
		return nil, 0, fmt.Errorf("%w: response shorter than a status word", ErrMalformed)
	}
	sw := uint16(r[len(r)-2])<<8 | uint16(r[len(r)-1])
	return append([]byte(nil), r[:len(r)-2]...), sw, nil
}

// exchange sends c and completes the ISO 7816-4 response handling: 6Cxx (wrong Le) reissues the
// command once with the Le the card asked for, and 61xx (more data) is collected with GET
// RESPONSE until the card stops. wipe zeroes every encoded buffer after it is sent (for VERIFY).
func exchange(ctx context.Context, card Card, c command, wipe bool) ([]byte, uint16, error) {
	send := func(c command) ([]byte, uint16, error) {
		apdu := c.encode()
		data, sw, err := transmit(ctx, card, apdu)
		if wipe {
			clear(apdu)
		}
		return data, sw, err
	}
	data, sw, err := send(c)
	if err != nil {
		return nil, 0, err
	}
	if sw&0xFF00 == 0x6C00 && c.le >= 0 && !c.noReissue {
		c.le = int(sw & 0xFF)
		if c.le == 0 {
			c.le = 256
		}
		if data, sw, err = send(c); err != nil {
			return nil, 0, err
		}
	}
	out := data
	for sw&0xFF00 == 0x6100 {
		le := int(sw & 0xFF)
		if le == 0 {
			le = 256
		}
		more, next, err := transmit(ctx, card, command{ins: 0xC0, le: le}.encode())
		if err != nil {
			return nil, 0, err
		}
		if next != swOK && next&0xFF00 != 0x6100 {
			return nil, 0, &StatusError{Op: "get response", SW: next}
		}
		out = append(out, more...)
		if len(out) > maxResponseSize {
			return nil, 0, fmt.Errorf("%w: response longer than %d bytes", ErrMalformed, maxResponseSize)
		}
		sw = next
	}
	return out, sw, nil
}

// exchangeChained sends data that may be longer than one APDU with command chaining (CLA bit
// 0x10 on every part but the last; only the last part carries Le). Every intermediate part must
// be answered 9000; the first other answer ends the exchange and is returned with the 1-based
// number of the part that got it and the number of parts, so a refusal can say where it happened.
// Nothing is retried.
func exchangeChained(ctx context.Context, card Card, c command) (data []byte, sw uint16, part, parts int, err error) {
	rest := c.data
	parts = max(1, (len(rest)+chunkSize-1)/chunkSize)
	for part = 1; len(rest) > chunkSize; part++ {
		p := command{cla: c.cla | 0x10, ins: c.ins, p1: c.p1, p2: c.p2, data: rest[:chunkSize], le: -1}
		_, sw, err = transmit(ctx, card, p.encode())
		if err != nil {
			return nil, 0, part, parts, err
		}
		if sw != swOK {
			return nil, sw, part, parts, nil
		}
		rest = rest[chunkSize:]
	}
	c.data = rest
	data, sw, err = exchange(ctx, card, c, false)
	return data, sw, part, parts, err
}

// tlv is one BER-TLV data object.
type tlv struct {
	tag         uint32
	constructed bool
	value       []byte
}

// parseTLVs splits b into data objects. Everything is bounds-checked: tags of at most three
// bytes, lengths in the short form or the 81/82 long forms (an OpenPGP card never needs more
// than 65535 bytes), and no value may run past the end of b.
func parseTLVs(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		first := b[0]
		tag := uint32(first)
		n := 1
		if first&0x1F == 0x1F {
			for {
				if n >= len(b) {
					return nil, fmt.Errorf("%w: truncated tag", ErrMalformed)
				}
				if n >= 3 {
					return nil, fmt.Errorf("%w: tag longer than three bytes", ErrMalformed)
				}
				tag = tag<<8 | uint32(b[n])
				n++
				if b[n-1]&0x80 == 0 {
					break
				}
			}
		}
		if n >= len(b) {
			return nil, fmt.Errorf("%w: truncated length", ErrMalformed)
		}
		l := int(b[n])
		n++
		switch {
		case l < 0x80:
		case l == 0x81:
			if n+1 > len(b) {
				return nil, fmt.Errorf("%w: truncated length", ErrMalformed)
			}
			l = int(b[n])
			n++
		case l == 0x82:
			if n+2 > len(b) {
				return nil, fmt.Errorf("%w: truncated length", ErrMalformed)
			}
			l = int(b[n])<<8 | int(b[n+1])
			n += 2
		default:
			return nil, fmt.Errorf("%w: unsupported length form %02X", ErrMalformed, l)
		}
		if l > len(b)-n {
			return nil, fmt.Errorf("%w: value runs past the end", ErrMalformed)
		}
		out = append(out, tlv{tag: tag, constructed: first&0x20 != 0, value: b[n : n+l]})
		b = b[n+l:]
	}
	return out, nil
}

// find returns the value of the first object with tag in objs.
func find(objs []tlv, tag uint32) ([]byte, bool) {
	for _, o := range objs {
		if o.tag == tag {
			return o.value, true
		}
	}
	return nil, false
}
