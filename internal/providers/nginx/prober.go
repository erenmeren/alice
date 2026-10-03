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

// Probe is one TLS answer.
type Probe struct {
	LeafSHA256  string
	ChainLength int
	NotAfter    time.Time
}

// ErrProbeUnreachable wraps every connection failure of a probe (dial, refused, timeout before the
// handshake); other failures (handshake refused) are ErrProbeFailed.
var (
	ErrProbeUnreachable = errors.New("nginx: the endpoint cannot be reached")
	ErrProbeFailed      = errors.New("nginx: the TLS handshake failed")
)
