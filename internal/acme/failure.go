package acme

import (
	"context"
	"errors"
	"net"
	"net/http"

	"alice/internal/platform/netaddr"
)

// Classes of an order's failure (owner decision 2026-10-20; docs/superpowers/rulings/acme-renewal-recovery.md). A
// transient failure is an outage that is expected to clear by itself (the CA, its DNS lookups or the DNS hook could not
// be reached or timed out, the CA limited the requests or answered with a server error); a permanent failure needs a
// person (a setting, the account, a refused name, a wrong challenge answer). The renewal planner keeps retrying after
// transient failures and stops after permanent ones (internal/acme/renew).
const (
	ClassTransient = "transient"
	ClassPermanent = "permanent"
)

// ErrHookUnreachable is the cause of a DNS hook call that got no answer (a transport error or a timeout).
var ErrHookUnreachable = errors.New("acme: the DNS hook could not be reached")

// HookError is the *Error of a DNS hook call that failed for identifier: status is the hook's HTTP status (0 when it
// gave none); unreachable says the hook gave no answer. Its text holds no part of the hook's answer.
func HookError(identifier string, status int, unreachable bool) *Error {
	e := &Error{Reason: ReasonHookRefused, Identifier: identifier, Status: status}
	if unreachable {
		e.cause = ErrHookUnreachable
	}
	return e
}

// ErrDNSProviderUnreachable is the cause of a DNS provider call that got no answer (a transport error or a timeout).
var ErrDNSProviderUnreachable = errors.New("acme: the DNS provider could not be reached")

// DNSProviderError is the *Error of a DNS provider API call (R57) that failed for identifier: status is the
// provider's HTTP status (0 when it gave none); unreachable says the provider gave no answer. A 401 or 403 is
// ReasonDNSAuthFailed, anything else ReasonDNSProviderError. Its text holds no part of the provider's answer.
func DNSProviderError(identifier string, status int, unreachable bool) *Error {
	e := &Error{Reason: ReasonDNSProviderError, Identifier: identifier, Status: status}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		e.Reason = ReasonDNSAuthFailed
	}
	if unreachable {
		e.cause = ErrDNSProviderUnreachable
	}
	return e
}

// DNSSignInError is the *Error of a DNS provider sign-in that failed for identifier (a token the identity service
// refused, an assumed role it did not give): ReasonDNSAuthFailed, or ReasonDNSProviderError marked unreachable when
// the identity service gave no answer or answered with a server error.
func DNSSignInError(identifier string, status int, unreachable bool) *Error {
	if unreachable || serverTrouble(status) {
		return DNSProviderError(identifier, status, true)
	}
	return &Error{Reason: ReasonDNSAuthFailed, Identifier: identifier, Status: status}
}

// DNSZoneNotFound is the *Error of a name no zone of the DNS provider's account holds (R57).
func DNSZoneNotFound(identifier string) *Error {
	return &Error{Reason: ReasonDNSZoneNotFound, Identifier: identifier}
}

// FailureClass classifies an order's failure: ClassTransient, ClassPermanent, or "" when err holds no *Error of this
// package and is neither a timeout nor a network error (the caller decides from its own code).
func FailureClass(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if !errors.As(err, &e) {
		if networkTrouble(err) {
			return ClassTransient
		}
		return ""
	}
	if transientError(e) {
		return ClassTransient
	}
	return ClassPermanent
}

// transientError is the classification table of an *Error (the RFC 8555 problem type, the HTTP status, the cause).
func transientError(e *Error) bool {
	switch e.Reason {
	case ReasonCARateLimited, ReasonNotIssuedInTime, ReasonAlreadyReplaced:
		// alreadyReplaced: the order that replaces the certificate at the CA ends there by itself (R50).
		return true
	case ReasonProviderUnreachable:
		// An address the network policy refuses is a setting, not an outage.
		return !errors.Is(e.cause, netaddr.ErrNotAllowed)
	case ReasonHookRefused:
		return errors.Is(e.cause, ErrHookUnreachable) || serverTrouble(e.Status) || networkTrouble(e.cause)
	case ReasonDNSProviderError:
		// A DNS provider that did not answer, timed out, limited the requests or failed itself (R57); a refused
		// request (a 4xx) is a setting.
		return errors.Is(e.cause, ErrDNSProviderUnreachable) || serverTrouble(e.Status) || networkTrouble(e.cause)
	case ReasonValidationFailedDNS, ReasonValidationFailedHTTP:
		switch shortType(e.ProblemType) {
		case "dns", "connection", "serverInternal", "rateLimited", "badNonce":
			// The CA's lookup or connection failed (a DNS server or a website that did not answer), or the CA itself.
			return true
		case "":
			return serverTrouble(e.Status) || networkTrouble(e.cause)
		}
		return serverTrouble(e.Status)
	case ReasonDirectoryInvalid:
		return serverTrouble(e.Status)
	}
	return false
}

// serverTrouble is an HTTP status of an outage: a timeout, a rate limit or a server error.
func serverTrouble(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
}

// networkTrouble reports a timeout or a network error in err's chain.
func networkTrouble(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return true
	}
	var op *net.OpError
	var dns *net.DNSError
	return errors.As(err, &op) || errors.As(err, &dns)
}
