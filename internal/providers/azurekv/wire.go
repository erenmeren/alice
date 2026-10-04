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
	// bodyOut: a request that carries a body was handed to the HTTP client in this attempt. It is
	// not reset by begin (each request of the attempt): it answers "may the body have been written".
	bodyOut bool
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

// bodyHandedOn records that req, which carries a body, goes to the HTTP client now.
func (w *wireState) bodyHandedOn(req *http.Request) {
	if w == nil || req.Body == nil || req.Body == http.NoBody { // a body of unknown length (ContentLength 0) is sent chunked: it counts
		return
	}
	w.mu.Lock()
	w.bodyOut = true
	w.mu.Unlock()
}

// noBodySent reports positive evidence that no request body left for the vault in this attempt.
func (w *wireState) noBodySent() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.bodyOut
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

// challengeParams parses the parameters of a WWW-Authenticate challenge as a quoted-string aware
// list: `Bearer name="value", name2=token`. A backslash escapes inside quotes. It returns every
// occurrence of each name, so a duplicated parameter is visible, and false for an unterminated quote.
func challengeParams(h string) (map[string][]string, bool) {
	out := map[string][]string{}
	h = strings.TrimSpace(h)
	if sp := strings.IndexAny(h, " \t"); sp >= 0 && !strings.Contains(h[:sp], "=") {
		h = h[sp:] // the scheme
	}
	for i := 0; i < len(h); {
		for i < len(h) && (h[i] == ' ' || h[i] == '\t' || h[i] == ',') {
			i++
		}
		start := i
		for i < len(h) && h[i] != '=' && h[i] != ' ' && h[i] != ',' {
			i++
		}
		name := h[start:i]
		if i >= len(h) || h[i] != '=' {
			continue // a token without a value
		}
		i++
		var val strings.Builder
		if i < len(h) && h[i] == '"' {
			i++
			for i < len(h) && h[i] != '"' {
				if h[i] == '\\' && i+1 < len(h) {
					i++
				}
				val.WriteByte(h[i])
				i++
			}
			if i >= len(h) {
				return out, false // an unterminated quote
			}
			i++ // the closing quote
		} else {
			for i < len(h) && h[i] != ',' && h[i] != ' ' {
				val.WriteByte(h[i])
				i++
			}
		}
		out[foldASCII(name)] = append(out[foldASCII(name)], val.String())
	}
	return out, true
}

// sdkChallengeValue reproduces how the SDK's challenge policy reads the header (it splits on blanks
// and equal signs, the last occurrence wins, scope before resource), so that evidence is only
// accepted when the SDK and this package read the same resource.
func sdkChallengeValue(h string) string {
	h = strings.ReplaceAll(h, "Bearer ", "")
	vals := map[string]string{}
	for _, part := range strings.Split(h, " ") {
		if sub := strings.Split(part, "="); len(sub) == 2 {
			vals[sub[0]] = strings.TrimSuffix(strings.ReplaceAll(sub[1], "\"", ""), ",")
		}
	}
	if v, ok := vals["scope"]; ok {
		return v
	}
	return vals["resource"]
}

// ownChallenge reports a 401 whose single WWW-Authenticate header carries exactly one authority
// (the Entra login host) and exactly one resource (or scope) naming the vault resource of the public
// cloud, read the same way by this package and by the SDK: positive evidence that a challenge error
// of the SDK is its own host check on a port-qualified host, not a hostile challenge. Anything
// odd (a second header, a duplicated or decoy parameter, other quoting) is not evidence.
func ownChallenge(status int, h http.Header) bool {
	if status != http.StatusUnauthorized || len(h.Values("WWW-Authenticate")) != 1 {
		return false
	}
	raw := h.Get("WWW-Authenticate")
	p, wellFormed := challengeParams(raw)
	if !wellFormed {
		return false
	}
	one := func(name string) (string, bool) {
		v := p[name]
		if len(v) != 1 {
			return "", false
		}
		return v[0], true
	}
	auth, ok := one("authorization")
	if !ok || !strings.HasPrefix(auth, "https://"+azureid.AuthorityHost+"/") {
		return false
	}
	res, hasRes := one("resource")
	scope, hasScope := one("scope")
	if len(p["resource"]) > 1 || len(p["scope"]) > 1 || (!hasRes && !hasScope) {
		return false
	}
	if hasRes && res != "https://vault.azure.net" || hasScope && scope != azureid.VaultScope {
		return false
	}
	sdk := sdkChallengeValue(raw)
	return sdk == "https://vault.azure.net" || sdk == azureid.VaultScope
}
