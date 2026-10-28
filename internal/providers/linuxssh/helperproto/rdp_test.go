package helperproto

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rdpConn is the connection of one negotiation: what the client writes and what the server answers.
type rdpConn struct {
	io.Reader
	sent bytes.Buffer
}

func (c *rdpConn) Write(p []byte) (int, error) { return c.sent.Write(p) }

func TestRDPNegotiate(t *testing.T) {
	cut := func(b []byte, n int) []byte { return b[:n] }
	with := func(b []byte, i int, v byte) []byte { b = bytes.Clone(b); b[i] = v; return b }
	short := []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00}
	negLen7 := with(RDPConfirm(2), 13, 7)
	for name, c := range map[string]struct {
		answer   []byte
		selected uint32
		err      error
	}{
		"ssl":                 {RDPConfirm(RDPProtocolSSL), 1, nil},
		"hybrid":              {RDPConfirm(RDPProtocolHybrid), 2, nil},
		"hybrid ex":           {RDPConfirm(RDPProtocolHybridEx), 8, nil},
		"standard security":   {RDPConfirm(0), 0, ErrRDPNoTLS},
		"no negotiation data": {short, 0, ErrRDPNoTLS},
		"ssl not allowed":     {RDPFailure(2), 0, ErrRDPNoTLS},
		"hybrid required":     {RDPFailure(5), 0, ErrRDPNegotiation},
		"tpkt version 2":      {with(RDPConfirm(2), 0, 2), 0, ErrRDPNegotiation},
		"length 10":           {with(RDPConfirm(2), 3, 10), 0, ErrRDPNegotiation},
		"length 65":           {with(RDPConfirm(2), 3, 65), 0, ErrRDPNegotiation},
		"connection request":  {with(RDPConfirm(2), 5, 0xe0), 0, ErrRDPNegotiation},
		"18 of 19 bytes":      {cut(RDPConfirm(2), 18), 0, ErrRDPNegotiation},
		"neg length 7":        {negLen7, 0, ErrRDPNegotiation},
		"no answer":           {nil, 0, ErrRDPNegotiation},
		"x224 length wrong":   {with(RDPConfirm(2), 4, 0x0d), 0, ErrRDPNegotiation},
		"unknown type":        {with(RDPConfirm(2), 11, 0x04), 0, ErrRDPNegotiation},
		"rdstls selected":     {RDPConfirm(4), 0, ErrRDPNegotiation},
		"trailing bytes":      {append(with(with(RDPConfirm(2), 3, 20), 4, 0x0f), 0), 0, ErrRDPNegotiation},
	} {
		t.Run(name, func(t *testing.T) {
			conn := &rdpConn{Reader: bytes.NewReader(c.answer)}
			selected, err := RDPNegotiate(conn)
			assert.Equal(t, RDPConnectionRequest, conn.sent.Bytes())
			assert.Equal(t, c.selected, selected)
			if c.err == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, c.err)
			other := ErrRDPNoTLS
			if errors.Is(c.err, ErrRDPNoTLS) {
				other = ErrRDPNegotiation
			}
			assert.NotErrorIs(t, err, other)
		})
	}
}

// The request is the 19 bytes of F22: TPKT, the X.224 Connection Request, RDP_NEG_REQ asking for SSL and HYBRID.
func TestRDPConnectionRequestBytes(t *testing.T) {
	assert.Len(t, RDPConnectionRequest, 19)
	assert.Equal(t, []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}, RDPConnectionRequest)
	assert.Equal(t, []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00}, RDPConfirm(2))
	assert.Equal(t, []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00}, RDPFailure(5))
	assert.Equal(t, 64, MaxRDPConfirm)
}

// The negotiation reads one TPKT: the server's TLS bytes after the confirm stay for the handshake.
func TestRDPNegotiateReadsOneTPKT(t *testing.T) {
	tlsBytes := []byte{0x16, 0x03, 0x03, 0x00, 0x7a}
	r := bytes.NewReader(append(RDPConfirm(2), tlsBytes...))
	selected, err := RDPNegotiate(&rdpConn{Reader: r})
	require.NoError(t, err)
	assert.Equal(t, RDPProtocolHybrid, selected)
	rest, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, tlsBytes, rest)
}

type failingWriter struct{ io.Reader }

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestRDPNegotiateWriteFails(t *testing.T) {
	_, err := RDPNegotiate(failingWriter{bytes.NewReader(RDPConfirm(2))})
	assert.ErrorIs(t, err, ErrRDPNegotiation)
}
