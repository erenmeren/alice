// Package revocation asks the authority that issued a certificate whether it was revoked, by OCSP and by CRL (R64,
// D5). It is pure apart from its guarded HTTP client: certificates in, a Result out; the inventory records it and
// decides what a revocation does.
//
// The addresses come from the certificate (AIA OCSP, CRL distribution points), so an attacker who controls a certificate
// on a managed server chooses them. The fetch refuses every address but http and https on their own ports, connects only
// to addresses netaddr allows and that are not Alice's host (checked when it connects: a name that resolves to loopback
// or to the metadata address is refused), uses no proxy, never follows a redirect, caps every answer and its time, and
// counts its requests against a per-host budget of the run (fetch.go). Only an answer the issuer signed decides (R64
// Ruling 16): an unreachable responder, an invalid or stale answer and an unknown certificate are never a revocation.
package revocation

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"time"

	"alice/internal/platform/clock"
)

// Status is the outcome of one check.
type Status string

// The statuses.
const (
	StatusGood         Status = "good"
	StatusRevoked      Status = "revoked"
	StatusOnHold       Status = "on_hold"       // certificateHold (6): not final
	StatusUnknown      Status = "unknown"       // the responder does not know the certificate
	StatusUnavailable  Status = "unavailable"   // Code says why; never a finding
	StatusNotCheckable Status = "not_checkable" // Code: no issuer or no address
	StatusDeferred     Status = "deferred"      // the run's budget for this host is spent; not recorded
)

// The closed codes of an unavailable or not checkable result (the API registers each as ALC-CRT-0020..0025).
const (
	CodeUnreachable    = "certificate.revocation_unreachable"
	CodeInvalidAnswer  = "certificate.revocation_invalid_answer"
	CodeAddressRefused = "certificate.revocation_address_refused"
	CodeNoIssuer       = "certificate.revocation_no_issuer"
	CodeNoAddress      = "certificate.revocation_no_address"
	CodeTooLarge       = "certificate.revocation_too_large"
)

// Result is the outcome of one check.
type Result struct {
	Status    Status
	Method    string    // "ocsp", "crl" or ""
	RevokedAt time.Time // revoked and on_hold
	Reason    string    // the RFC 5280 name of the reason (revoked and on_hold; "" otherwise)
	Code      string    // unavailable and not_checkable
}

// Limits of the fetch (R64 Ruling 17).
const (
	exchangeTimeout = 10 * time.Second
	maxOCSPAnswer   = 64 << 10
	maxCRLAnswer    = 10 << 20
	maxCachedCRLs   = 16
	// maxCachedCRLBytes: a larger CRL is read and used but not kept for the run (final review M2).
	maxCachedCRLBytes = 1 << 20
	// reasonRemoveFromCRL (8) lifts a hold; it is never a revocation (final review M1).
	reasonRemoveFromCRL = 8
	freshness           = 5 * time.Minute // the clock skew an answer's times are allowed
	userAgent           = "Alice-revocation-check"
)

// Checker holds the guarded HTTP client; each scheduled run takes a Run of it.
type Checker struct {
	clk    clock.Clock
	client *http.Client
}

// New is the production checker: every connection through the guard (netaddr, and never Alice's host).
func New(clk clock.Clock) *Checker { return newChecker(clk, guardedDialer(nil)) }

// newChecker is a checker whose connections dial (the tests' seam).
func newChecker(clk clock.Clock, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Checker {
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		TLSHandshakeTimeout:    exchangeTimeout,
		ResponseHeaderTimeout:  exchangeTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		TLSClientConfig:        tlsConfig(),
	}
	return &Checker{clk: clk, client: &http.Client{Transport: tr, Timeout: exchangeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Run is one scheduled run: a per-host request budget and a CRL cache. Not safe for concurrent use.
type Run struct {
	c       *Checker
	perHost int
	spent   map[string]int
	crls    map[string]crlEntry
}

type crlEntry struct {
	list *x509.RevocationList
	code string
}

// NewRun starts a run that makes at most perHost requests to one host.
func (c *Checker) NewRun(perHost int) *Run {
	return &Run{c: c, perHost: perHost, spent: map[string]int{}, crls: map[string]crlEntry{}}
}

// Check checks leaf, issued by issuer (nil: not checkable), by OCSP and then, when OCSP gave no answer, by CRL.
func (r *Run) Check(ctx context.Context, leaf, issuer *x509.Certificate) Result {
	if issuer == nil || leaf.CheckSignatureFrom(issuer) != nil {
		return Result{Status: StatusNotCheckable, Code: CodeNoIssuer}
	}
	ocspURL, refusedOCSP := firstUsable(leaf.OCSPServer)
	crlURL, refusedCRL := firstUsable(leaf.CRLDistributionPoints)
	if ocspURL == nil && crlURL == nil {
		if refusedOCSP || refusedCRL {
			return Result{Status: StatusNotCheckable, Code: CodeAddressRefused}
		}
		return Result{Status: StatusNotCheckable, Code: CodeNoAddress}
	}
	var res Result
	tried := false
	if ocspURL != nil {
		res, tried = r.checkOCSP(ctx, ocspURL, leaf, issuer), true
		if res.Status != StatusUnavailable && res.Status != StatusUnknown && res.Status != StatusDeferred {
			return res
		}
	}
	if crlURL != nil {
		crl := r.checkCRL(ctx, crlURL, leaf, issuer)
		if !tried || rank(crl) > rank(res) {
			res = crl
		}
	}
	return res
}

// rank orders results by how definite they are: a revocation, then good, unknown, deferred (no answer yet), unavailable.
func rank(r Result) int {
	switch r.Status {
	case StatusRevoked, StatusOnHold:
		return 4
	case StatusGood:
		return 3
	case StatusUnknown:
		return 2
	case StatusDeferred:
		return 1
	}
	return 0
}

// firstUsable is the first address of urls that passes the URL rule (nil when none); refused reports an address that
// failed it (an empty one is no address).
func firstUsable(urls []string) (u *url.URL, refused bool) {
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		if p, ok := usableURL(raw); ok {
			return p, refused
		}
		refused = true
	}
	return nil, refused
}

// reasonName is the RFC 5280 name of a CRL reason code (an unknown code, or removeFromCRL, is unspecified).
func reasonName(code int) string {
	switch code {
	case 1:
		return "keyCompromise"
	case 2:
		return "cACompromise"
	case 3:
		return "affiliationChanged"
	case 4:
		return "superseded"
	case 5:
		return "cessationOfOperation"
	case 6:
		return "certificateHold"
	case 9:
		return "privilegeWithdrawn"
	case 10:
		return "aACompromise"
	}
	return "unspecified"
}

// revokedResult is the result of a revocation listed by method with reason code at (on hold for certificateHold).
func revokedResult(method string, code int, at time.Time) Result {
	status := StatusRevoked
	if code == 6 {
		status = StatusOnHold
	}
	return Result{Status: status, Method: method, RevokedAt: at.UTC(), Reason: reasonName(code)}
}
