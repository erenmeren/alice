package nginx

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
)

// Bounds of Alice's own probe.
const (
	defaultProbeDialTimeout      = 5 * time.Second
	defaultProbeHandshakeTimeout = 10 * time.Second
)

// TLSProber probes a TLS endpoint from Alice (spec §12.8, R38 item 6). It sends no application
// data and trusts nothing: the client configuration is helperproto.ProbeTLSConfig (no certificate
// verification, the only place Alice skips it), and only the served leaf's SHA-256 and the number
// of certificates presented are used (spec §12.8 items 3 and 5). Zero timeouts mean 5 s to connect
// and 10 s for the handshake.
type TLSProber struct {
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
}

var _ Prober = TLSProber{}

// Probe connects to host:port and completes a handshake with sni ("" or helperproto.NoSNI: none)
// and keyType (helperproto.ProbeAny, ProbeRSA or ProbeECDSA; see ProbeTLSConfig). A connection
// failure wraps ErrProbeUnreachable, a failed handshake (or an unknown key type, refused before
// dialling) ErrProbeFailed; a cancelled ctx is in the error chain too.
func (p TLSProber) Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error) {
	if keyType != helperproto.ProbeAny && keyType != helperproto.ProbeRSA && keyType != helperproto.ProbeECDSA {
		return Probe{}, fmt.Errorf("%w: unknown key type", ErrProbeFailed)
	}
	if port < 1 || port > 65535 {
		return Probe{}, fmt.Errorf("%w: port out of range", ErrProbeUnreachable)
	}
	dial, handshake := p.DialTimeout, p.HandshakeTimeout
	if dial <= 0 {
		dial = defaultProbeDialTimeout
	}
	if handshake <= 0 {
		handshake = defaultProbeHandshakeTimeout
	}
	conn, err := (&net.Dialer{Timeout: dial}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return Probe{}, fmt.Errorf("%w: %w", ErrProbeUnreachable, err)
	}
	defer func() { _ = conn.Close() }()
	hctx, cancel := context.WithTimeout(ctx, handshake)
	defer cancel()
	tc := tls.Client(conn, helperproto.ProbeTLSConfig(sni, keyType))
	if err := tc.HandshakeContext(hctx); err != nil {
		return Probe{}, fmt.Errorf("%w: %w", ErrProbeFailed, err)
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return Probe{}, fmt.Errorf("%w: no certificate", ErrProbeFailed)
	}
	leaf := cs.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	return Probe{LeafSHA256: hex.EncodeToString(sum[:]), ChainLength: len(cs.PeerCertificates), NotAfter: leaf.NotAfter.UTC()}, nil
}
