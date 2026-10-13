package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"

	"alice/internal/acme/transport"
	"alice/internal/platform/netaddr"
)

// Reasons are the stable error reasons of the ALC-ACM codes registered in internal/api/errors.go. This
// package does not import the API; a test in internal/api checks that every one of them is registered.
const (
	ReasonProviderUnreachable  = "acme.provider_unreachable"
	ReasonDirectoryInvalid     = "acme.directory_invalid"
	ReasonTermsNotAccepted     = "acme.terms_not_accepted"
	ReasonAccountRejected      = "acme.account_rejected"
	ReasonCARateLimited        = "acme.ca_rate_limited"
	ReasonValidationFailedDNS  = "acme.validation_failed_dns"
	ReasonValidationFailedHTTP = "acme.validation_failed_http"
	ReasonHookRefused          = "acme.hook_refused"
	ReasonIdentifierRefused    = "acme.identifier_refused"
	ReasonNotIssuedInTime      = "acme.not_issued_in_time"
	ReasonKeyPolicyNotAllowed  = "acme.key_policy_not_allowed"
	ReasonTLSTrustFailed       = "acme.tls_trust_failed"
	ReasonRolloverUnsupported  = "acme.rollover_unsupported"
	ReasonChallengeUnavailable = "acme.challenge_unavailable"
)

// Reasons lists every reason an *Error of this package can carry.
func Reasons() []string {
	return []string{ReasonProviderUnreachable, ReasonDirectoryInvalid, ReasonTermsNotAccepted, ReasonAccountRejected,
		ReasonCARateLimited, ReasonValidationFailedDNS, ReasonValidationFailedHTTP, ReasonHookRefused, ReasonIdentifierRefused,
		ReasonNotIssuedInTime, ReasonKeyPolicyNotAllowed, ReasonTLSTrustFailed, ReasonRolloverUnsupported, ReasonChallengeUnavailable}
}

// ProblemPrefix is the namespace of RFC 8555 problem types; any other type is dropped.
const ProblemPrefix = "urn:ietf:params:acme:error:"

// MaxRetryAfter caps a CA's Retry-After.
const MaxRetryAfter = 24 * time.Hour

// maxProblemBytes bounds a problem document this package parses itself.
const maxProblemBytes = 64 << 10

// Error is every error this package returns from a CA operation. Its text holds only the reason, the RFC
// 8555 problem type (validated against ProblemPrefix) and the HTTP status: never a CA body, header, URL,
// key or binding secret. Identifier is a DNS name the caller asked for.
type Error struct {
	Reason      string
	ProblemType string // "" or ProblemPrefix + a short alphanumeric name
	Status      int    // the CA's HTTP status, 0 when the CA did not answer
	Identifier  string // the name concerned, when one is
	cause       error  // a sentinel of this package, the standard library or transport, or a *RateLimitedError
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("acme: ")
	b.WriteString(e.Reason)
	if e.Identifier != "" {
		b.WriteString(" for ")
		b.WriteString(e.Identifier)
	}
	if e.ProblemType != "" {
		b.WriteString(" (")
		b.WriteString(e.ProblemType)
		b.WriteString(")")
	}
	if e.Status != 0 {
		b.WriteString(" status ")
		b.WriteString(strconv.Itoa(e.Status))
	}
	if e.cause != nil {
		var rl *RateLimitedError
		if !errors.As(e.cause, &rl) {
			b.WriteString(": ")
			b.WriteString(e.cause.Error())
		}
	}
	return b.String()
}

// Unwrap returns the safe cause (a sentinel or a *RateLimitedError).
func (e *Error) Unwrap() error { return e.cause }

// RetryAfter is the CA's Retry-After for a rate-limited error, 0 otherwise.
func (e *Error) RetryAfter() time.Duration {
	var rl *RateLimitedError
	if errors.As(e.cause, &rl) {
		return rl.RetryAfter
	}
	return 0
}

// RateLimitedError is the cause of a ReasonCARateLimited error: RetryAfter is the CA's Retry-After, capped at
// MaxRetryAfter (0 when the CA gave none).
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return "acme: rate limited by the CA, retry after " + e.RetryAfter.String()
}

// ReasonOf returns the reason of an *Error in err's chain, "" when there is none.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// Sentinels used as safe causes.
var (
	// ErrNoARI is returned by RenewalInfo when the directory has no renewalInfo.
	ErrNoARI = errors.New("acme: the CA does not offer renewal information")
	// ErrTermsNotAccepted is the cause of a registration refused because the terms were not accepted.
	ErrTermsNotAccepted = errors.New("acme: the terms of service were not accepted")
	// ErrEABRequired is the cause of a registration refused because the CA needs a binding and none was given.
	ErrEABRequired = errors.New("acme: the CA requires an external account binding")
	// ErrEABInvalid is a binding whose key id or key is malformed (the key must be base64url).
	ErrEABInvalid = errors.New("acme: the external account binding is malformed")
	// ErrInvalidName is a name that is not a DNS name this client orders.
	ErrInvalidName = errors.New("acme: the name is not a valid DNS name")
	// ErrNoAccount is an operation that needs a registered account.
	ErrNoAccount = errors.New("acme: no account for this key")
	// ErrNoKey is an operation that needs the account key.
	ErrNoKey = errors.New("acme: no account key")
	// ErrCSRMismatch is a CSR whose names are not exactly the order's names.
	ErrCSRMismatch = errors.New("acme: the CSR does not hold exactly the ordered names")
	// ErrChallengeUnavailable is an authorization offering no challenge type the solver publishes.
	ErrChallengeUnavailable = errors.New("acme: no offered challenge type can be published")
	// ErrSolver is the cause of a failed Present (the solver's own error text is not kept).
	ErrSolver = errors.New("acme: the challenge could not be published")
	// ErrBadAnswer is a CA answer that does not follow RFC 8555 (unparsable, wrong certificate, bad token).
	ErrBadAnswer = errors.New("acme: the CA's answer is not valid")
	// ErrRolloverUnsupported is a CA without keyChange.
	ErrRolloverUnsupported = errors.New("acme: the CA does not support account key rollover")
)

// Problem is the safe part of an RFC 8555 problem document.
type Problem struct {
	Type   string // "" unless it is ProblemPrefix + a short alphanumeric name
	Status int
}

// ParseProblem reads a problem document tolerantly: anything unreadable is a zero Problem, and a type outside
// the ACME namespace is dropped. Only the first maxProblemBytes are looked at.
func ParseProblem(b []byte) Problem {
	if len(b) > maxProblemBytes {
		return Problem{}
	}
	var v struct {
		Type   any `json:"type"`
		Status any `json:"status"`
	}
	if json.Unmarshal(b, &v) != nil {
		return Problem{}
	}
	p := Problem{}
	if s, ok := v.Type.(string); ok {
		p.Type = cleanProblemType(s)
	}
	if f, ok := v.Status.(float64); ok && f >= 100 && f <= 599 && f == float64(int(f)) {
		p.Status = int(f)
	}
	return p
}

// cleanProblemType keeps an RFC 8555 problem type whose short name is 1..40 ASCII letters or digits.
func cleanProblemType(s string) string {
	name, ok := strings.CutPrefix(s, ProblemPrefix)
	if !ok {
		// Pre-RFC servers send urn:acme:error:<name>; keep the short name in the RFC namespace.
		name, ok = strings.CutPrefix(s, "urn:acme:error:")
	}
	if !ok || name == "" || len(name) > 40 {
		return ""
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return ""
		}
	}
	return ProblemPrefix + name
}

func shortType(t string) string { return strings.TrimPrefix(t, ProblemPrefix) }

// parseRetryAfter reads a Retry-After value (seconds or an HTTP date) and caps it at MaxRetryAfter.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	var d time.Duration
	if n, err := strconv.ParseInt(v, 10, 64); err == nil || errors.Is(err, strconv.ErrRange) {
		if n <= 0 {
			return 0 // also a negative overflow (ParseInt returns math.MinInt64)
		}
		if n > int64(MaxRetryAfter/time.Second) {
			return MaxRetryAfter
		}
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, 0), MaxRetryAfter)
}

// op says how an error is classified: what a timeout means and what an unauthorized answer means.
type op int

const (
	opAccount op = iota // directory, registration, rollover, deactivation, ARI
	opOrder             // order, authorizations, finalize, download
)

// classify turns any error of the library, the transport or the context into an *Error without copying text
// from the CA. challengeType is the challenge being validated ("" outside validation).
func (c *Client) classify(err error, o op, challengeType, identifier string) error {
	if err == nil {
		return nil
	}
	var mine *Error
	if errors.As(err, &mine) {
		return err
	}
	e := &Error{Identifier: identifier}
	var (
		ae  *xacme.Error
		aze *xacme.AuthorizationError
		oe  *xacme.OrderError
	)
	switch {
	case errors.As(err, &aze):
		e.Reason = validationReason(challengeType)
		for _, sub := range aze.Errors {
			var se *xacme.Error
			if errors.As(sub, &se) {
				t := cleanProblemType(se.ProblemType)
				if e.ProblemType == "" {
					e.ProblemType, e.Status = t, se.StatusCode
				}
				if r := identifierReason(t); r != "" {
					e.Reason, e.ProblemType, e.Status = r, t, se.StatusCode
				}
			}
		}
	case errors.As(err, &oe):
		if oe.Problem == nil {
			e.Reason = ReasonNotIssuedInTime
			e.cause = ErrBadAnswer
			break
		}
		c.fromProblem(e, oe.Problem)
	case errors.As(err, &ae):
		c.fromProblem(e, ae)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		e.Reason = ReasonProviderUnreachable
		if o == opOrder {
			e.Reason = ReasonNotIssuedInTime
		}
		e.cause = context.DeadlineExceeded
		if errors.Is(err, context.Canceled) {
			e.cause = context.Canceled
		}
	case isTLSTrust(err):
		e.Reason, e.cause = ReasonTLSTrustFailed, errTLSTrust
	case errors.Is(err, transport.ErrURLRefused):
		e.Reason, e.cause = ReasonDirectoryInvalid, transport.ErrURLRefused
	case errors.Is(err, transport.ErrTooLarge):
		e.Reason, e.cause = ReasonDirectoryInvalid, transport.ErrTooLarge
	case errors.Is(err, netaddr.ErrNotAllowed):
		e.Reason, e.cause = ReasonProviderUnreachable, netaddr.ErrNotAllowed
	case errors.Is(err, xacme.ErrNoAccount):
		e.Reason, e.cause = ReasonAccountRejected, ErrNoAccount
	default:
		var ne interface{ Timeout() bool }
		if errors.As(err, &ne) && ne.Timeout() {
			e.Reason, e.cause = ReasonProviderUnreachable, errUnreachable
			if o == opOrder {
				e.Reason = ReasonNotIssuedInTime
			}
			break
		}
		var ue *url.Error
		var nop *net.OpError
		if errors.As(err, &ue) || errors.As(err, &nop) {
			e.Reason, e.cause = ReasonProviderUnreachable, errUnreachable
			break
		}
		// Unparsable JSON, a pre-RFC 8555 directory, a malformed certificate chain: the CA does not
		// answer as an ACME CA does.
		e.Reason, e.cause = ReasonDirectoryInvalid, ErrBadAnswer
	}
	return e
}

var (
	errTLSTrust    = errors.New("acme: the CA's TLS certificate is not trusted")
	errUnreachable = errors.New("acme: the CA could not be reached")
)

func isTLSTrust(err error) bool {
	var (
		ua  x509.UnknownAuthorityError
		he  x509.HostnameError
		ci  x509.CertificateInvalidError
		cve *tls.CertificateVerificationError
	)
	return errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) || errors.As(err, &cve)
}

func validationReason(challengeType string) string {
	if challengeType == "dns-01" {
		return ReasonValidationFailedDNS
	}
	return ReasonValidationFailedHTTP
}

func identifierReason(t string) string {
	switch shortType(t) {
	case "rejectedIdentifier", "unsupportedIdentifier", "caa":
		return ReasonIdentifierRefused
	}
	return ""
}

// fromProblem fills e from a CA problem. Only the type and status are kept.
func (c *Client) fromProblem(e *Error, p *xacme.Error) {
	e.ProblemType = cleanProblemType(p.ProblemType)
	e.Status = p.StatusCode
	t := shortType(e.ProblemType)
	if r := identifierReason(e.ProblemType); r != "" {
		e.Reason = r
		return
	}
	switch {
	case t == "rateLimited" || p.StatusCode == http.StatusTooManyRequests:
		var d time.Duration
		if p.Header != nil {
			d = parseRetryAfter(p.Header.Get("Retry-After"), c.now())
		}
		e.Reason, e.cause = ReasonCARateLimited, &RateLimitedError{RetryAfter: d}
	case t == "userActionRequired":
		e.Reason, e.cause = ReasonTermsNotAccepted, ErrTermsNotAccepted
	case t == "externalAccountRequired":
		e.Reason, e.cause = ReasonAccountRejected, ErrEABRequired
	case t == "accountDoesNotExist", t == "invalidContact", t == "unsupportedContact", t == "unauthorized":
		e.Reason = ReasonAccountRejected
	case t == "badCSR", t == "badPublicKey", t == "badSignatureAlgorithm":
		e.Reason = ReasonKeyPolicyNotAllowed
	case t == "dns":
		e.Reason = ReasonValidationFailedDNS
	case t == "connection", t == "incorrectResponse", t == "tls":
		e.Reason = ReasonValidationFailedHTTP
	case t == "orderNotReady":
		e.Reason = ReasonNotIssuedInTime
	case t == "serverInternal", t == "badNonce", p.StatusCode >= 500:
		e.Reason, e.cause = ReasonProviderUnreachable, errUnreachable
	default:
		e.Reason = ReasonDirectoryInvalid
	}
}

// newError is a locally decided error.
func newError(reason string, cause error) *Error { return &Error{Reason: reason, cause: cause} }
