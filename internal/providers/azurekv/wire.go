package azurekv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

	"alice/internal/platform/azureid"
	"alice/internal/platform/netaddr"
)

// wireKind says how the last request of one attempt failed on the wire. The SDKs hide transport
// errors behind text (azidentity keeps only the message of a non-HTTP failure), so the transports
// record what they saw on a per-attempt state carried by the request's context, and the error
// mapping reads it. Nothing here holds Azure text: kinds, a status and a host name.
type wireKind int

const (
	wireNone           wireKind = iota
	wireHostNotAllowed          // refused before anything was sent
	wireRedirect                // the answer was a redirect
	wireAddrRefused             // netaddr refused the connection's address
	wireDNSNotFound             // the name does not exist
	wireTLSUntrusted            // the certificate chain or name was refused
	wireDial                    // the connection was never made
	wireOther                   // a failure after the connection was made
	wireBodyTooLarge            // the answer is larger than Alice reads
	wireBodyRead                // the body ended early or broke
	wireContext                 // the request's context ended
)

type wireState struct {
	mu        sync.Mutex
	host      string
	status    int
	kind      wireKind
	ctxErr    error
	ownVaultC bool // the last answer was a challenge of the vault's own host naming the vault resource
}

type wireKey struct{}

func withWire(ctx context.Context) (context.Context, *wireState) {
	st := &wireState{}
	return context.WithValue(ctx, wireKey{}, st), st
}

func wireOf(ctx context.Context) *wireState {
	st, _ := ctx.Value(wireKey{}).(*wireState)
	return st
}

func (w *wireState) begin(host string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.host, w.status, w.kind, w.ctxErr, w.ownVaultC = host, 0, wireNone, nil, false
	w.mu.Unlock()
}

func (w *wireState) fail(k wireKind) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.kind = k
	w.mu.Unlock()
}

func (w *wireState) failCtx(err error) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.kind, w.ctxErr = wireContext, err
	w.mu.Unlock()
}

func (w *wireState) answered(status int, ownChallenge bool) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.status, w.ownVaultC = status, ownChallenge
	w.mu.Unlock()
}

type wireSnapshot struct {
	host         string
	status       int
	kind         wireKind
	ctxErr       error
	ownChallenge bool
}

func (w *wireState) snapshot() wireSnapshot {
	if w == nil {
		return wireSnapshot{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return wireSnapshot{w.host, w.status, w.kind, w.ctxErr, w.ownVaultC}
}

// kindOf classifies a transport error (the error of http.Client.Do).
func kindOf(err error) wireKind {
	var dns *net.DNSError
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	var op *net.OpError
	switch {
	case errors.Is(err, netaddr.ErrNotAllowed):
		return wireAddrRefused
	case errors.As(err, &dns) && dns.IsNotFound:
		return wireDNSNotFound
	case errors.As(err, &cv), errors.As(err, &ua), errors.As(err, &he), errors.As(err, &ci):
		return wireTLSUntrusted
	case errors.As(err, &op) && op.Op == "dial":
		return wireDial
	default:
		return wireOther
	}
}

// ownChallenge reports a 401 of the vault's own host whose challenge names the vault resource of
// the public cloud and the Entra authority: positive evidence that a challenge error of the SDK is
// the SDK's own host check on a port-qualified host, not a hostile challenge.
func ownChallenge(status int, h http.Header) bool {
	if status != http.StatusUnauthorized {
		return false
	}
	v := h.Get("WWW-Authenticate")
	res := strings.Contains(v, `resource="https://vault.azure.net"`) || strings.Contains(v, `scope="`+azureid.VaultScope+`"`)
	return res && strings.Contains(v, `authorization="https://`+azureid.AuthorityHost+`/`)
}
