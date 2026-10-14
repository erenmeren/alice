package fakefleet

import (
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// clientHello is what the fleet reads from a ClientHello: enough to log and to answer.
type clientHello struct {
	serverName string
	suites     []uint16
}

// maxRecord bounds the first record the fleet reads (a TLS record body is at most 2^14 + 2048 bytes).
const maxRecord = 1<<14 + 2048

// readHello reads the first TLS record and parses it as a ClientHello, best effort. It returns the
// bytes it read (to replay to crypto/tls) and what it understood; anything that is not a complete
// handshake record yields an empty clientHello.
func readHello(r io.Reader) ([]byte, clientHello) {
	hdr := make([]byte, 5)
	n, err := io.ReadFull(r, hdr)
	if err != nil {
		return hdr[:n], clientHello{}
	}
	if hdr[0] != 22 {
		return hdr, clientHello{}
	}
	size := int(hdr[3])<<8 | int(hdr[4])
	if size > maxRecord {
		return hdr, clientHello{}
	}
	body := make([]byte, size)
	n, err = io.ReadFull(r, body)
	out := append(hdr, body[:n]...)
	if err != nil {
		return out, clientHello{}
	}
	return out, parseClientHello(body)
}

// parseClientHello parses a handshake message holding a ClientHello (RFC 8446 section 4.1.2).
func parseClientHello(b []byte) clientHello {
	var h clientHello
	s := cryptobyte.String(b)
	var typ uint8
	var msg, random, sid, suites, comp cryptobyte.String
	var version uint16
	if !s.ReadUint8(&typ) || typ != 1 || !s.ReadUint24LengthPrefixed(&msg) ||
		!msg.ReadUint16(&version) || !msg.ReadBytes((*[]byte)(&random), 32) ||
		!msg.ReadUint8LengthPrefixed(&sid) || !msg.ReadUint16LengthPrefixed(&suites) ||
		!msg.ReadUint8LengthPrefixed(&comp) {
		return clientHello{}
	}
	for !suites.Empty() {
		var id uint16
		if !suites.ReadUint16(&id) {
			return clientHello{}
		}
		h.suites = append(h.suites, id)
	}
	var exts cryptobyte.String
	if msg.Empty() || !msg.ReadUint16LengthPrefixed(&exts) {
		return h
	}
	for !exts.Empty() {
		var id uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&data) {
			return h
		}
		if id != 0 { // server_name
			continue
		}
		var list cryptobyte.String
		if !data.ReadUint16LengthPrefixed(&list) {
			return h
		}
		for !list.Empty() {
			var nameType uint8
			var name cryptobyte.String
			if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) {
				return h
			}
			if nameType == 0 && len(name) <= 255 {
				h.serverName = string(name)
				return h
			}
		}
	}
	return h
}
