package nginx

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"alice/internal/platform/netaddr"
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
// and 10 s for the handshake. The connection goes through netaddr.DialContext: the address host
// resolves to is checked with the target rule on the socket that connects (AUD-25 a).
type TLSProber struct {
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	// resolver resolves host names (nil = the system's); tests set it.
	resolver *net.Resolver
}

var _ Prober = TLSProber{}

// Probe connects to host:port and completes a handshake with sni ("" or helperproto.NoSNI: none)
// and keyType (helperproto.ProbeAny, ProbeRSA or ProbeECDSA; see ProbeTLSConfig). A connection
// failure wraps ErrProbeUnreachable, a failed handshake (or an unknown key type, refused before
// dialling) ErrProbeFailed, an address the target rule refuses ErrProbeNotAllowed (and
// netaddr.ErrNotAllowed; nothing is sent); a cancelled ctx is in the error chain too.
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
	conn, err := netaddr.DialContext(ctx, &net.Dialer{Timeout: dial, Resolver: p.resolver}, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if errors.Is(err, netaddr.ErrNotAllowed) {
		return Probe{}, fmt.Errorf("%w: %w", ErrProbeNotAllowed, err)
	}
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
