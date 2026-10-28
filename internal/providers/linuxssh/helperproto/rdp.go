package helperproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The RDP security-layer negotiation (MS-RDPBCGR 2.2.1.1, 2.2.1.2; Windows W6 Ruling 15, F22): the probe of a Remote
// Desktop listener sends an X.224 Connection Request asking for TLS, reads the Connection Confirm and, when the
// server selected a TLS-based protocol, runs the TLS handshake on the same connection. It stops after the handshake:
// no CredSSP, no credentials, no application data. Alice's tlsverify.TLSProber and the Windows helper's tls-probe
// share this code.
const (
	RDPProtocolSSL      uint32 = 1
	RDPProtocolHybrid   uint32 = 2
	RDPProtocolHybridEx uint32 = 8
	MaxRDPConfirm              = 64 // bytes of one TPKT the negotiation reads
)

// RDPConnectionRequest is the client's first message: TPKT (version 3, length 19), the X.224 Connection Request
// TPDU (code 0xE0, no cookie) and RDP_NEG_REQ with requestedProtocols PROTOCOL_SSL | PROTOCOL_HYBRID.
var RDPConnectionRequest = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}

// ErrRDPNoTLS: the server offers no TLS (standard RDP security, or SSL_NOT_ALLOWED_BY_SERVER). ErrRDPNegotiation:
// the answer is no valid Connection Confirm, a failure other than that, or the connection failed.
var (
	ErrRDPNoTLS       = errors.New("rdp negotiation: the server offers no TLS")
	ErrRDPNegotiation = errors.New("rdp negotiation failed")
)

// RDP_NEG_RSP and RDP_NEG_FAILURE types; failure code SSL_NOT_ALLOWED_BY_SERVER.
const (
	rdpNegRsp             = 0x02
	rdpNegFailure         = 0x03
	rdpSSLNotAllowed      = 2
	x224ConnectionConfirm = 0xd0
	x224HeaderLen         = 7 // LI, code, dst-ref, src-ref, class
)

// RDPNegotiate writes RDPConnectionRequest to rw and reads exactly one TPKT (version 3, length 11 to MaxRDPConfirm),
// so the server's TLS bytes after it stay unread. It returns the selected protocol (1, 2 or 8) with a nil error;
// 0, no negotiation data or SSL_NOT_ALLOWED_BY_SERVER is ErrRDPNoTLS, anything else ErrRDPNegotiation. The caller
// sets the connection's deadline.
func RDPNegotiate(rw io.ReadWriter) (selected uint32, err error) {
	if _, err := rw.Write(RDPConnectionRequest); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrRDPNegotiation, err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrRDPNegotiation, err)
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if hdr[0] != 3 || n < 4+x224HeaderLen || n > MaxRDPConfirm {
		return 0, fmt.Errorf("%w: not a connection confirm (tpkt %d, length %d)", ErrRDPNegotiation, hdr[0], n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(rw, body); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrRDPNegotiation, err)
	}
	if int(body[0]) != len(body)-1 || body[1] != x224ConnectionConfirm {
		return 0, fmt.Errorf("%w: not a connection confirm (li %d, code %#x)", ErrRDPNegotiation, body[0], body[1])
	}
	neg := body[x224HeaderLen:]
	if len(neg) == 0 {
		return 0, fmt.Errorf("%w: no negotiation data", ErrRDPNoTLS)
	}
	if len(neg) != 8 || binary.LittleEndian.Uint16(neg[2:]) != 8 {
		return 0, fmt.Errorf("%w: malformed negotiation data", ErrRDPNegotiation)
	}
	v := binary.LittleEndian.Uint32(neg[4:])
	switch {
	case neg[0] == rdpNegRsp && (v == RDPProtocolSSL || v == RDPProtocolHybrid || v == RDPProtocolHybridEx):
		return v, nil
	case neg[0] == rdpNegRsp && v == 0, neg[0] == rdpNegFailure && v == rdpSSLNotAllowed:
		return 0, fmt.Errorf("%w (type %#x, value %d)", ErrRDPNoTLS, neg[0], v)
	}
	return 0, fmt.Errorf("%w: type %#x, value %d", ErrRDPNegotiation, neg[0], v)
}

// RDPConfirm is the 19-byte Connection Confirm with RDP_NEG_RSP selecting selected (the emulator's answer).
func RDPConfirm(selected uint32) []byte { return rdpAnswer(rdpNegRsp, selected) }

// RDPFailure is the 19-byte Connection Confirm with RDP_NEG_FAILURE of code.
func RDPFailure(code uint32) []byte { return rdpAnswer(rdpNegFailure, code) }

func rdpAnswer(typ byte, v uint32) []byte {
	b := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, x224ConnectionConfirm, 0x00, 0x00, 0x00, 0x00, 0x00, typ, 0x00, 0x08, 0x00}
	return binary.LittleEndian.AppendUint32(b, v)
}
