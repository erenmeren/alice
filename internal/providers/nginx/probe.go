package nginx

import (
	"context"
	"net"
	"time"

	"alice/internal/providers/tlsverify"
)

// TLSProber probes a TLS endpoint from Alice (spec §12.8, R38 item 6): tlsverify.TLSProber (no
// certificate verification during the handshake, a fresh handshake every probe, the target rule on
// the socket that connects, AUD-25 a) with the same fields. Zero timeouts mean 5 s to connect and
// 10 s for the handshake.
type TLSProber struct {
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	// resolver resolves host names (nil = the system's); tests set it.
	resolver *net.Resolver
}

var _ Prober = TLSProber{}

// Probe is tlsverify.TLSProber.Probe: a connection failure wraps ErrProbeUnreachable, a failed
// handshake (or an unknown key type, refused before dialling) ErrProbeFailed, an address the target
// rule refuses ErrProbeNotAllowed (and netaddr.ErrNotAllowed; nothing is sent); a cancelled ctx is
// in the error chain too.
func (p TLSProber) Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error) {
	return tlsverify.TLSProber{DialTimeout: p.DialTimeout, HandshakeTimeout: p.HandshakeTimeout, Resolver: p.resolver}.Probe(ctx, host, port, sni, keyType)
}
