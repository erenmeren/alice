package nginx

import (
	"context"
	"errors"
	"time"
)

// Prober probes a TLS endpoint from Alice (Task 11 adds the production implementation, a
// crypto/tls dial).
type Prober interface {
	Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error)
}

// Probe is one TLS answer. Chain is the DER of every certificate presented, leaf first (R51: its
// trust is checked against the verification's trust policy; nil when not known).
type Probe struct {
	LeafSHA256  string
	ChainLength int
	NotAfter    time.Time
	Chain       [][]byte
}

// ErrProbeUnreachable wraps every connection failure of a probe (dial, refused, timeout before the
// handshake); other failures (handshake refused) are ErrProbeFailed. ErrProbeNotAllowed is a
// connection Alice refused to open: the host resolves to an address the target rule refuses
// (netaddr.Allowed, AUD-25 a); it is neither of the others.
var (
	ErrProbeUnreachable = errors.New("nginx: the endpoint cannot be reached")
	ErrProbeFailed      = errors.New("nginx: the TLS handshake failed")
	ErrProbeNotAllowed  = errors.New("nginx: the endpoint's address is not one Alice connects to")
)
