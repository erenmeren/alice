// Package solver is the contract between the ACME client (internal/acme) and the code that publishes a
// challenge: a DNS-01 TXT record through a DNS hook, or an HTTP-01 token file through the helper. It holds
// the interface, the challenge description and an in-memory solver for tests; the real solvers live in
// their own packages.
//
// The client calls Present once per challenge it chose and CleanUp exactly once for every Present it
// started (successful or not), on success, on failure and after cancellation (with a fresh, bounded
// context), so a solver must make CleanUp safe for a challenge whose Present failed half-way. Present runs
// under the client's per-call deadline.
//
// A wildcard and its base name ("*.example.com" and "example.com") are validated at the same record name,
// "_acme-challenge.example.com", with two different values that must coexist. CleanUp must therefore remove
// only the exact value it is given (DNSName plus DNSValue), never every record of the name.
package solver

import "context"

// Challenge types.
const (
	DNS01  = "dns-01"
	HTTP01 = "http-01"
)

// HTTPPathPrefix is the URL path below which an HTTP-01 token is served (RFC 8555 section 8.3).
const HTTPPathPrefix = "/.well-known/acme-challenge/"

// Challenge is one challenge to publish. It holds no secret: every value is published to the world by
// design (the key authorization proves control of the account key without revealing it).
type Challenge struct {
	// Type is DNS01 or HTTP01.
	Type string `json:"type"`
	// Domain is the identifier being validated, without the "*." of a wildcard.
	Domain string `json:"domain"`
	// Wildcard is true when the order names "*." + Domain.
	Wildcard bool `json:"wildcard,omitempty"`
	// Token is the CA's token (base64url characters only, checked by the client).
	Token string `json:"token"`
	// KeyAuth is the HTTP-01 body (token "." thumbprint); empty for DNS-01.
	KeyAuth string `json:"key_auth,omitempty"`
	// HTTPPath is the HTTP-01 URL path (HTTPPathPrefix + Token); empty for DNS-01.
	HTTPPath string `json:"http_path,omitempty"`
	// DNSName is the DNS-01 record name ("_acme-challenge." + Domain, no trailing dot); empty for HTTP-01.
	DNSName string `json:"dns_name,omitempty"`
	// DNSValue is the DNS-01 TXT value; empty for HTTP-01.
	DNSValue string `json:"dns_value,omitempty"`
}

// Solver publishes and removes challenges.
type Solver interface {
	// Present publishes the challenge and returns when the CA may check it.
	Present(ctx context.Context, ch Challenge) error
	// CleanUp removes what Present published. It is called for every Present, even a failed one.
	CleanUp(ctx context.Context, ch Challenge) error
	// Types lists the challenge types the solver can publish, most preferred first.
	Types() []string
}
