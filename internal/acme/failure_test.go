package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/acme/renew"
	"alice/internal/acme/transport"
	"alice/internal/platform/netaddr"
)

func TestFailureClass(t *testing.T) {
	pt := func(name string) string { return ProblemPrefix + name }
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"not an acme error", errors.New("boom"), ""},
		{"a bare timeout", timeoutErr{}, ClassTransient},
		{"a deadline", context.DeadlineExceeded, ClassTransient},
		{"a refused connection", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, ClassTransient},

		{"rate limited", &Error{Reason: ReasonCARateLimited, ProblemType: pt("rateLimited"), Status: 429, cause: &RateLimitedError{}}, ClassTransient},
		{"CA unreachable", &Error{Reason: ReasonProviderUnreachable, cause: errUnreachable}, ClassTransient},
		{"bad nonce", &Error{Reason: ReasonProviderUnreachable, ProblemType: pt("badNonce"), Status: 400, cause: errUnreachable}, ClassTransient},
		{"CA 503", &Error{Reason: ReasonProviderUnreachable, Status: 503, cause: errUnreachable}, ClassTransient},
		{"address refused by policy", &Error{Reason: ReasonProviderUnreachable, cause: netaddr.ErrNotAllowed}, ClassPermanent},
		{"not issued in time", &Error{Reason: ReasonNotIssuedInTime, cause: context.DeadlineExceeded}, ClassTransient},
		{"order not ready", &Error{Reason: ReasonNotIssuedInTime, ProblemType: pt("orderNotReady"), Status: 403}, ClassTransient},
		{"DNS propagation timeout", &Error{Reason: ReasonNotIssuedInTime, Identifier: "a.example"}, ClassTransient},

		{"validation: dns problem", &Error{Reason: ReasonValidationFailedDNS, ProblemType: pt("dns"), Status: 400}, ClassTransient},
		{"validation: connection", &Error{Reason: ReasonValidationFailedHTTP, ProblemType: pt("connection"), Status: 400}, ClassTransient},
		{"validation: CA server error", &Error{Reason: ReasonValidationFailedHTTP, ProblemType: pt("serverInternal"), Status: 500}, ClassTransient},
		{"validation: unauthorized", &Error{Reason: ReasonValidationFailedDNS, ProblemType: pt("unauthorized"), Status: 403}, ClassPermanent},
		{"validation: incorrect response", &Error{Reason: ReasonValidationFailedHTTP, ProblemType: pt("incorrectResponse"), Status: 403}, ClassPermanent},
		{"validation: tls", &Error{Reason: ReasonValidationFailedHTTP, ProblemType: pt("tls"), Status: 403}, ClassPermanent},
		{"validation: token not served", SolverError(ReasonValidationFailedHTTP, "a.example", errors.New("not served")), ClassPermanent},
		{"validation: publisher timed out", SolverError(ReasonValidationFailedHTTP, "a.example", fmt.Errorf("ssh: %w", timeoutErr{})), ClassTransient},

		{"hook unreachable", HookError("a.example", 0, true), ClassTransient},
		{"hook 503", HookError("a.example", 503, false), ClassTransient},
		{"hook 429", HookError("a.example", 429, false), ClassTransient},
		{"hook 408", HookError("a.example", 408, false), ClassTransient},
		{"hook 401", HookError("a.example", 401, false), ClassPermanent},
		{"hook 404", HookError("a.example", 404, false), ClassPermanent},
		{"hook refused locally", HookError("a.example", 0, false), ClassPermanent},

		{"caa", &Error{Reason: ReasonIdentifierRefused, ProblemType: pt("caa"), Status: 403}, ClassPermanent},
		{"rejected identifier", &Error{Reason: ReasonIdentifierRefused, ProblemType: pt("rejectedIdentifier"), Status: 400}, ClassPermanent},
		{"account unauthorized", &Error{Reason: ReasonAccountRejected, ProblemType: pt("unauthorized"), Status: 403}, ClassPermanent},
		{"EAB required", &Error{Reason: ReasonAccountRejected, ProblemType: pt("externalAccountRequired"), cause: ErrEABRequired}, ClassPermanent},
		{"terms", &Error{Reason: ReasonTermsNotAccepted, cause: ErrTermsNotAccepted}, ClassPermanent},
		{"malformed", &Error{Reason: ReasonDirectoryInvalid, ProblemType: pt("malformed"), Status: 400}, ClassPermanent},
		{"directory 502", &Error{Reason: ReasonDirectoryInvalid, Status: 502}, ClassTransient},
		{"bad CSR", &Error{Reason: ReasonKeyPolicyNotAllowed, ProblemType: pt("badCSR")}, ClassPermanent},
		{"TLS trust", &Error{Reason: ReasonTLSTrustFailed, cause: errTLSTrust}, ClassPermanent},
		{"URL refused", &Error{Reason: ReasonDirectoryInvalid, cause: transport.ErrURLRefused}, ClassPermanent},
		{"name not allowed", &Error{Reason: ReasonNameNotAllowed}, ClassPermanent},
		{"challenge unavailable", &Error{Reason: ReasonChallengeUnavailable, cause: ErrChallengeUnavailable}, ClassPermanent},
		{"wrapped", fmt.Errorf("job: %w", &Error{Reason: ReasonCARateLimited, cause: &RateLimitedError{}}), ClassTransient},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, FailureClass(c.err), c.name)
	}
}

func TestHookErrorText(t *testing.T) {
	assert.Equal(t, "acme: acme.hook_refused for a.example status 401", HookError("a.example", 401, false).Error())
	e := HookError("a.example", 0, true)
	assert.Equal(t, ReasonHookRefused, e.Reason)
	assert.ErrorIs(t, e, ErrHookUnreachable)
	assert.NotContains(t, HookError("a.example", 0, false).Error(), "reached")
}

func TestDNSProviderErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    *Error
		reason string
		class  string
	}{
		{"unreachable", DNSProviderError("a.example", 0, true), ReasonDNSProviderError, ClassTransient},
		{"server error", DNSProviderError("a.example", 503, false), ReasonDNSProviderError, ClassTransient},
		{"rate limited", DNSProviderError("a.example", 429, false), ReasonDNSProviderError, ClassTransient},
		{"bad request", DNSProviderError("a.example", 400, false), ReasonDNSProviderError, ClassPermanent},
		{"unauthorized", DNSProviderError("a.example", 401, false), ReasonDNSAuthFailed, ClassPermanent},
		{"forbidden", DNSProviderError("a.example", 403, false), ReasonDNSAuthFailed, ClassPermanent},
		{"sign-in refused", DNSSignInError("a.example", 400, false), ReasonDNSAuthFailed, ClassPermanent},
		{"sign-in outage", DNSSignInError("a.example", 502, false), ReasonDNSProviderError, ClassTransient},
		{"sign-in unreachable", DNSSignInError("a.example", 0, true), ReasonDNSProviderError, ClassTransient},
		{"no zone", DNSZoneNotFound("a.example"), ReasonDNSZoneNotFound, ClassPermanent},
	}
	for _, c := range cases {
		assert.Equal(t, c.reason, c.err.Reason, c.name)
		assert.Equal(t, c.class, FailureClass(c.err), c.name)
		assert.Equal(t, "a.example", c.err.Identifier, c.name)
	}
	assert.ErrorIs(t, DNSProviderError("a.example", 0, true), ErrDNSProviderUnreachable)
	assert.Equal(t, "acme: acme.dns_auth_failed for a.example status 403", DNSProviderError("a.example", 403, false).Error())
}

func TestClassesMatchTheRenewalPolicy(t *testing.T) {
	assert.Equal(t, renew.ClassTransient, ClassTransient)
	assert.Equal(t, renew.ClassPermanent, ClassPermanent)
	// The code-only fallback: the reasons of outages are transient; the others, also those whose class depends on the
	// problem type or the status (validation, hook, directory), are permanent.
	for _, r := range Reasons() {
		want := ClassPermanent
		if r == ReasonCARateLimited || r == ReasonProviderUnreachable || r == ReasonNotIssuedInTime {
			want = ClassTransient
		}
		assert.Equal(t, want, renew.ClassOfCode(r), r)
	}
}
