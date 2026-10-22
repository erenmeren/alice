package nginx

import "alice/internal/providers/tlsverify"

// Prober probes a TLS endpoint from Alice (tlsverify.Prober).
type Prober = tlsverify.Prober

// Probe is one TLS answer (tlsverify.Probe). Chain is the DER of every certificate presented, leaf
// first (R51: its trust is checked against the verification's trust policy; nil when not known).
type Probe = tlsverify.Probe

// The errors of a probe (tlsverify's): ErrProbeUnreachable wraps every connection failure (dial,
// refused, timeout before the handshake); other failures (handshake refused) are ErrProbeFailed.
// ErrProbeNotAllowed is a connection Alice refused to open: the host resolves to an address the
// target rule refuses (netaddr.Allowed, AUD-25 a); it is neither of the others.
var (
	ErrProbeUnreachable = tlsverify.ErrProbeUnreachable
	ErrProbeFailed      = tlsverify.ErrProbeFailed
	ErrProbeNotAllowed  = tlsverify.ErrProbeNotAllowed
)
