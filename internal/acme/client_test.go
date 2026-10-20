package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xacme "golang.org/x/crypto/acme"

	"alice/internal/acme/solver"
	"alice/internal/acme/transport"
	"alice/internal/testutil/fakeacme"
)

// requireReason asserts err is an *Error with the reason.
func requireReason(t *testing.T, err error, reason string) {
	t.Helper()
	_ = reasonErr(t, err, reason)
}

// reasonErr asserts err is an *Error with the reason and returns it.
func reasonErr(t *testing.T, err error, reason string) *Error {
	t.Helper()
	var e *Error
	require.ErrorAs(t, err, &e, "%v", err)
	require.Equal(t, reason, e.Reason, "%v", err)
	return e
}

func TestNewChecksConfig(t *testing.T) {
	hc := &http.Client{}
	for _, u := range []string{"", "http://ca.test/dir", "https:///dir", "https://u:p@ca.test/dir", "::"} {
		_, err := New(Config{DirectoryURL: u, HTTPClient: hc})
		requireReason(t, err, ReasonDirectoryInvalid)
	}
	_, err := New(Config{DirectoryURL: "https://ca.test/dir"})
	requireReason(t, err, ReasonProviderUnreachable)
	c, err := New(Config{DirectoryURL: "https://ca.test/dir", HTTPClient: hc, AccountURL: "https://ca.test/acct/1"})
	require.NoError(t, err)
	assert.Equal(t, DefaultCallTimeout, c.cfg.CallTimeout)
	assert.Equal(t, DefaultOrderTimeout, c.cfg.OrderTimeout)
	assert.Equal(t, DefaultCleanupTimeout, c.cfg.CleanupTimeout)
	assert.Equal(t, "https://ca.test/acct/1", c.AccountURL())
}

func TestDiscover(t *testing.T) {
	s := startFake(t, fakeacme.Options{RequireEAB: true})
	c := newTestClient(t, s)
	d, err := c.Discover(testCtx(t))
	require.NoError(t, err)
	assert.Equal(t, s.Credentials().TermsURL, d.TermsOfService)
	assert.True(t, d.ExternalAccountRequired)
	assert.True(t, d.SupportsRollover())
	assert.True(t, d.SupportsARI())
	n := s.Counters()["directory"]
	_, err = c.Discover(testCtx(t))
	require.NoError(t, err)
	assert.Equal(t, n, s.Counters()["directory"], "cached")

	s2 := startFake(t, fakeacme.Options{NoARI: true, NoKeyChange: true, NoTerms: true})
	d, err = newTestClient(t, s2).Discover(testCtx(t))
	require.NoError(t, err)
	assert.False(t, d.SupportsARI())
	assert.False(t, d.SupportsRollover())
	assert.Empty(t, d.TermsOfService)
	assert.False(t, d.ExternalAccountRequired)
}

func TestDiscoverFailures(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	require.NoError(t, s.Advertise("newOrder", "off"))
	_, err := newTestClient(t, s).Discover(testCtx(t))
	requireReason(t, err, ReasonDirectoryInvalid)
	require.NoError(t, s.Advertise("newOrder", "http://127.0.0.1:1/new-order"))
	_, err = newTestClient(t, s).Discover(testCtx(t))
	requireReason(t, err, ReasonDirectoryInvalid)
	require.NoError(t, s.Advertise("newOrder", ""))

	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "directory", Kind: fakeacme.FaultServerInternal, Times: 1}))
	_, err = newTestClient(t, s).Discover(testCtx(t))
	requireReason(t, err, ReasonProviderUnreachable)

	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "directory", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: time.Minute}))
	_, err = newTestClient(t, s).Discover(testCtx(t))
	e := reasonErr(t, err, ReasonCARateLimited)
	assert.Equal(t, time.Minute, e.RetryAfter())

	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "directory", Kind: fakeacme.FaultGiant, Times: 1}))
	_, err = newTestClient(t, s).Discover(testCtx(t))
	requireReason(t, err, ReasonDirectoryInvalid)

	// The library's own discovery (the second GET) failing.
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "directory", Kind: fakeacme.FaultServerInternal, Times: 1}))
	c := newTestClient(t, s)
	_, err = c.fetchDirectory(testCtx(t))
	requireReason(t, err, ReasonProviderUnreachable)
}

func TestDiscoverUntrustedAndUnreachable(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	hc, err := transport.New("")
	require.NoError(t, err)
	c := newTestClient(t, s, func(c *Config) { c.HTTPClient = hc })
	_, err = c.Discover(testCtx(t))
	requireReason(t, err, ReasonTLSTrustFailed)

	dead := newTestClient(t, s, func(c *Config) { c.DirectoryURL = "https://127.0.0.1:1/directory" })
	_, err = dead.Discover(testCtx(t))
	requireReason(t, err, ReasonProviderUnreachable)

	// The fake holds the answer far past the call budget and, when the client gives up, aborts with no
	// answer at all (no implicit empty 200 that could race the client's deadline), so the only outcome is
	// the deadline whatever the load.
	slow := newTestClient(t, s, func(c *Config) { c.CallTimeout = 100 * time.Millisecond })
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "directory", Kind: fakeacme.FaultSlow, Delay: time.Minute, Times: 1}))
	_, err = slow.Discover(testCtx(t))
	e := reasonErr(t, err, ReasonProviderUnreachable)
	assert.ErrorIs(t, e, context.DeadlineExceeded)
}

func TestRegisterWithoutEAB(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := newTestClient(t, s)
	a, err := c.RegisterAccount(testCtx(t), "mailto:ops@example.test", nil, true)
	require.NoError(t, err)
	assert.NotEmpty(t, a.URL)
	assert.Equal(t, a.URL, c.AccountURL())
	assert.Equal(t, s.Credentials().TermsURL, a.TermsOfService)
	assert.False(t, a.UsedEAB)
	assert.False(t, a.Existing)

	// The same key again: the existing account.
	again, err := c.RegisterAccount(testCtx(t), "", nil, true)
	require.NoError(t, err)
	assert.True(t, again.Existing)
	assert.Equal(t, a.URL, again.URL)

	// A fresh client with the same key finds it.
	look := newTestClient(t, s, func(cfg *Config) { cfg.Key = c.cfg.Key })
	u, err := look.Lookup(testCtx(t))
	require.NoError(t, err)
	assert.Equal(t, a.URL, u)
	_, err = newTestClient(t, s).Lookup(testCtx(t))
	e := reasonErr(t, err, ReasonAccountRejected)
	assert.ErrorIs(t, e, ErrNoAccount)
}

func TestRegisterRefusesUnacceptedTerms(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	_, err := newTestClient(t, s).RegisterAccount(testCtx(t), "", nil, false)
	e := reasonErr(t, err, ReasonTermsNotAccepted)
	assert.ErrorIs(t, e, ErrTermsNotAccepted)
	assert.Zero(t, s.Counters()["new-account"], "no registration request is sent")
	assert.Zero(t, s.Counters()["new-nonce"])
}

func TestRegisterWithoutTermsNeedsNoAcceptance(t *testing.T) {
	s := startFake(t, fakeacme.Options{NoTerms: true})
	c := newTestClient(t, s)
	a, err := c.RegisterAccount(testCtx(t), "", nil, false)
	require.NoError(t, err)
	assert.NotEmpty(t, a.URL)
	assert.Empty(t, a.TermsOfService)
}

func TestRegisterWithEAB(t *testing.T) {
	s := startFake(t, fakeacme.Options{RequireEAB: true})
	cr := s.Credentials()
	c := newTestClient(t, s)
	key := []byte(cr.EABHMAC + "==") // padding is tolerated
	a, err := c.RegisterAccount(testCtx(t), "", &EAB{KID: cr.EABKID, HMACKey: key}, true)
	require.NoError(t, err)
	assert.True(t, a.UsedEAB)
	assert.Equal(t, cr.EABHMAC+"==", string(key), "the caller's buffer is not changed")
}

func TestRegisterEABFailures(t *testing.T) {
	s := startFake(t, fakeacme.Options{RequireEAB: true})
	cr := s.Credentials()

	// Required but missing: refused locally, no registration request.
	_, err := newTestClient(t, s).RegisterAccount(testCtx(t), "", nil, true)
	e := reasonErr(t, err, ReasonAccountRejected)
	assert.ErrorIs(t, e, ErrEABRequired)
	assert.Zero(t, s.Counters()["new-account"])

	// Not base64url, too short, bad KID: refused before any request.
	n := s.Counters()["requests"]
	for _, bad := range []EAB{
		{KID: cr.EABKID, HMACKey: []byte("not base64url!")},
		{KID: cr.EABKID, HMACKey: []byte("+/+/+/+/+/+/+/+/+/+/+/+/")},
		{KID: cr.EABKID, HMACKey: []byte("c2hvcnQ")},
		{KID: cr.EABKID, HMACKey: nil},
		{KID: "", HMACKey: []byte(cr.EABHMAC)},
		{KID: "bad kid", HMACKey: []byte(cr.EABHMAC)},
	} {
		_, err := newTestClient(t, s).RegisterAccount(testCtx(t), "", &bad, true)
		e := reasonErr(t, err, ReasonAccountRejected)
		assert.ErrorIs(t, e, ErrEABInvalid)
	}
	assert.Equal(t, n, s.Counters()["requests"])

	// Well-formed but wrong: the CA refuses.
	wrong := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	_, err = newTestClient(t, s).RegisterAccount(testCtx(t), "", &EAB{KID: cr.EABKID, HMACKey: []byte(wrong)}, true)
	e = reasonErr(t, err, ReasonAccountRejected)
	assert.Equal(t, ProblemPrefix+"unauthorized", e.ProblemType)

	// The CA's requirement without a binding, when the directory did not say so beforehand.
	s2 := startFake(t, fakeacme.Options{})
	c := newTestClient(t, s2)
	_, err = c.Discover(testCtx(t))
	require.NoError(t, err)
	s2.SetExternalAccountRequired(true)
	_, err = c.RegisterAccount(testCtx(t), "", nil, true)
	e = reasonErr(t, err, ReasonAccountRejected)
	assert.ErrorIs(t, e, ErrEABRequired)
}

func TestRegisterContactAndKey(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	for _, bad := range []string{"no-at", "a@b@c", "@x.test", "x@", "a b@x.test", "a@x.test,b@y.test", "a@x.test\r\n"} {
		_, err := newTestClient(t, s).RegisterAccount(testCtx(t), bad, nil, true)
		requireReason(t, err, ReasonAccountRejected)
	}
	_, err := newTestClient(t, s, func(c *Config) { c.Key = nil }).RegisterAccount(testCtx(t), "", nil, true)
	assert.ErrorIs(t, err, ErrNoKey)
	assert.Zero(t, s.Counters()["requests"])
	_, err = newTestClient(t, s, func(c *Config) { c.Key = nil }).Lookup(testCtx(t))
	assert.ErrorIs(t, err, ErrNoKey)
	_, err = newTestClient(t, s, func(c *Config) { c.Key = nil }).Rollover(testCtx(t), p256(t))
	assert.ErrorIs(t, err, ErrNoKey)
	assert.ErrorIs(t, newTestClient(t, s, func(c *Config) { c.Key = nil }).Deactivate(testCtx(t)), ErrNoKey)
	err = newTestClient(t, s, func(c *Config) { c.Key = nil }).TestOrder(testCtx(t), []string{"a.example.test"}, solver.NewMemory())
	assert.ErrorIs(t, err, ErrNoKey)
}

func TestOrderHTTP01(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.HTTP01)
	names := []string{"www.example.test", "Example.TEST"}
	ws.route(s, "www.example.test", "example.test")
	csr, key := csrFor(t, "www.example.test", "example.test")
	var rec recorder
	chain, err := c.Order(testCtx(t), names, csr, ws, rec.opts()...)
	require.NoError(t, err)
	require.Len(t, chain, 2)
	leaf, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"www.example.test", "example.test"}, leaf.DNSNames)
	assert.True(t, key.PublicKey.Equal(leaf.PublicKey))

	require.Len(t, rec.presented, 2)
	assert.ElementsMatch(t, rec.presented, rec.cleaned)
	for _, ch := range rec.presented {
		assert.Equal(t, solver.HTTP01, ch.Type)
		assert.Equal(t, solver.HTTPPathPrefix+ch.Token, ch.HTTPPath)
		assert.True(t, strings.HasPrefix(ch.KeyAuth, ch.Token+"."))
		assert.Empty(t, ch.DNSValue)
	}
	assert.Zero(t, ws.Live(), "every token removed")
	assert.Equal(t, 2, s.Counters()["validations-http-01"])
}

func TestOrderDNS01Wildcard(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	names := []string{"*.example.test", "example.test"}
	csr, _ := csrFor(t, names...)
	var rec recorder
	chain, err := c.Order(testCtx(t), names, csr, ws, rec.opts()...)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)
	assert.ElementsMatch(t, names, leaf.DNSNames)
	require.Len(t, rec.presented, 2)
	wild := 0
	for _, ch := range rec.presented {
		assert.Equal(t, solver.DNS01, ch.Type)
		assert.Equal(t, "example.test", ch.Domain)
		assert.Equal(t, "_acme-challenge.example.test", ch.DNSName)
		assert.NotEmpty(t, ch.DNSValue)
		if ch.Wildcard {
			wild++
		}
	}
	assert.Equal(t, 1, wild)
	assert.ElementsMatch(t, rec.presented, rec.cleaned)
	assert.Empty(t, s.DNSRecords(), "every TXT value removed")
}

func TestWildcardNeedsDNS01(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	s.ClearRequests()
	before := s.Counters()["requests"]
	err := c.TestOrder(testCtx(t), []string{"*.example.test"}, solver.NewMemory(solver.HTTP01))
	e := reasonErr(t, err, ReasonChallengeUnavailable)
	assert.Equal(t, "*.example.test", e.Identifier)
	assert.Equal(t, before, s.Counters()["requests"], "refused before contacting the CA")

	// The CA offers only dns-01 for a plain name and the solver only http-01.
	require.NoError(t, s.SetChallenges(fakeacme.DNS01))
	err = c.TestOrder(testCtx(t), []string{"a.example.test"}, solver.NewMemory(solver.HTTP01))
	requireReason(t, err, ReasonChallengeUnavailable)
	err = c.TestOrder(testCtx(t), []string{"a.example.test"}, nil)
	requireReason(t, err, ReasonChallengeUnavailable)
}

func TestTestOrderStopsBeforeFinalize(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	var rec recorder
	require.NoError(t, c.TestOrder(testCtx(t), []string{"t.example.test"}, ws, rec.opts()...))
	assert.Len(t, rec.presented, 1)
	assert.Len(t, rec.cleaned, 1)
	assert.Zero(t, s.Counters()["finalize"])
	assert.Zero(t, s.Counters()["issued"])
}

func TestRollover(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	oldKey := c.cfg.Key
	acct := c.AccountURL()
	nk := p256(t)
	out, err := c.Rollover(testCtx(t), nk)
	require.NoError(t, err)
	assert.Equal(t, RolloverSwitched, out)
	assert.Equal(t, "switched", out.String())

	// The new key is the account key; the old one no longer is.
	u, err := newTestClient(t, s, func(cfg *Config) { cfg.Key = nk }).Lookup(testCtx(t))
	require.NoError(t, err)
	assert.Equal(t, acct, u)
	_, err = newTestClient(t, s, func(cfg *Config) { cfg.Key = oldKey }).Lookup(testCtx(t))
	requireReason(t, err, ReasonAccountRejected)
	// The client signs with the new key.
	ws := newWebSolver(t, s, solver.DNS01)
	require.NoError(t, c.TestOrder(testCtx(t), []string{"r.example.test"}, ws))

	// A key that already is an account key: the CA refuses, nothing switched.
	other := registered(t, s)
	out, err = c.Rollover(testCtx(t), other.cfg.Key)
	require.Error(t, err)
	assert.Equal(t, RolloverNotSwitched, out)

	// A CA error that leaves the outcome open.
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "key-change", Kind: fakeacme.FaultServerInternal, Times: 1}))
	out, err = c.Rollover(testCtx(t), p256(t))
	requireReason(t, err, ReasonProviderUnreachable)
	assert.Equal(t, RolloverUnknown, out)
	assert.Equal(t, "unknown", out.String())
	assert.Equal(t, "not_switched", RolloverNotSwitched.String())

	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "key-change", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: time.Hour}))
	out, err = c.Rollover(testCtx(t), p256(t))
	requireReason(t, err, ReasonCARateLimited)
	assert.Equal(t, RolloverNotSwitched, out)
}

func TestRolloverUnsupported(t *testing.T) {
	s := startFake(t, fakeacme.Options{NoKeyChange: true})
	c := registered(t, s)
	n := s.Counters()["requests"]
	out, err := c.Rollover(testCtx(t), p256(t))
	requireReason(t, err, ReasonRolloverUnsupported)
	assert.Equal(t, RolloverNotSwitched, out)
	assert.Equal(t, n, s.Counters()["requests"])
}

func TestDeactivate(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	require.NoError(t, c.Deactivate(testCtx(t)))
	err := c.TestOrder(testCtx(t), []string{"d.example.test"}, solver.NewMemory())
	requireReason(t, err, ReasonAccountRejected)
	err = c.Deactivate(testCtx(t))
	requireReason(t, err, ReasonAccountRejected)
}

func TestRateLimitedIsTypedAndNotSlept(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	for _, tc := range []struct{ given, want time.Duration }{{2 * time.Hour, 2 * time.Hour}, {MaxRetryAfter, MaxRetryAfter}, {0, 0}} {
		require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: tc.given}))
		n := s.Counters()["new-order"]
		t0 := time.Now()
		err := c.TestOrder(testCtx(t), []string{"rl.example.test"}, solver.NewMemory())
		assert.Less(t, time.Since(t0), time.Second, "no hidden sleep")
		e := reasonErr(t, err, ReasonCARateLimited)
		var rl *RateLimitedError
		require.ErrorAs(t, err, &rl)
		assert.Equal(t, tc.want, rl.RetryAfter)
		assert.Equal(t, tc.want, e.RetryAfter())
		assert.Equal(t, ProblemPrefix+"rateLimited", e.ProblemType)
		assert.Equal(t, http.StatusTooManyRequests, e.Status)
		assert.Equal(t, n+1, s.Counters()["new-order"], "not retried")
	}
}

func TestBadNonceIsRetried(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultBadNonce, Times: 2}))
	ws := newWebSolver(t, s, solver.DNS01)
	n := s.Counters()["new-order"]
	require.NoError(t, c.TestOrder(testCtx(t), []string{"n.example.test"}, ws))
	assert.Equal(t, n+3, s.Counters()["new-order"])

	// Endless badNonce gives up after a few retries.
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultBadNonce}))
	n = s.Counters()["new-order"]
	err := c.TestOrder(testCtx(t), []string{"n2.example.test"}, ws)
	requireReason(t, err, ReasonProviderUnreachable)
	assert.Equal(t, n+1+badNonceRetries, s.Counters()["new-order"])
}

func TestServerErrorNotRetried(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultServerInternal}))
	n := s.Counters()["new-order"]
	t0 := time.Now()
	err := c.TestOrder(testCtx(t), []string{"e.example.test"}, solver.NewMemory())
	assert.Less(t, time.Since(t0), time.Second)
	e := reasonErr(t, err, ReasonProviderUnreachable)
	assert.Equal(t, http.StatusInternalServerError, e.Status)
	assert.Equal(t, n+1, s.Counters()["new-order"])
}

func TestStuckOrderHitsDeadline(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s, func(cfg *Config) { cfg.CallTimeout = 1500 * time.Millisecond; cfg.OrderTimeout = 3 * time.Second })
	s.SetStuckPending(true)
	ws := newWebSolver(t, s, solver.DNS01)
	var rec recorder
	t0 := time.Now()
	err := c.TestOrder(testCtx(t), []string{"stuck.example.test"}, ws, rec.opts()...)
	assert.Less(t, time.Since(t0), 5*time.Second)
	e := reasonErr(t, err, ReasonNotIssuedInTime)
	assert.ErrorIs(t, e, context.DeadlineExceeded)
	assert.Len(t, rec.cleaned, 1, "cleanup ran after the deadline")
	assert.Empty(t, s.DNSRecords())
}

func TestProcessingOrderHitsDeadline(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s, func(cfg *Config) { cfg.CallTimeout = 1500 * time.Millisecond })
	s.SetProcessingPolls(100)
	ws := newWebSolver(t, s, solver.DNS01)
	csr, _ := csrFor(t, "p.example.test")
	_, err := c.Order(testCtx(t), []string{"p.example.test"}, csr, ws)
	requireReason(t, err, ReasonNotIssuedInTime)
}

func TestCSRMismatchRefusedLocally(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	n := s.Counters()["requests"]
	csr, _ := csrFor(t, "other.example.test")
	for _, bad := range [][]byte{csr, []byte("garbage"), nil} {
		_, err := c.Order(testCtx(t), []string{"a.example.test"}, bad, solver.NewMemory())
		e := reasonErr(t, err, ReasonKeyPolicyNotAllowed)
		assert.ErrorIs(t, e, ErrCSRMismatch)
	}
	sup, _ := csrFor(t, "a.example.test", "b.example.test")
	_, err := c.Order(testCtx(t), []string{"a.example.test"}, sup, solver.NewMemory())
	requireReason(t, err, ReasonKeyPolicyNotAllowed)
	assert.Equal(t, n, s.Counters()["requests"])
}

func TestRejectedIdentifier(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	s.RejectIdentifier("blocked.test")
	err := c.TestOrder(testCtx(t), []string{"www.blocked.test"}, solver.NewMemory())
	e := reasonErr(t, err, ReasonIdentifierRefused)
	assert.Equal(t, ProblemPrefix+"rejectedIdentifier", e.ProblemType)

	// Invalid names never reach the CA.
	n := s.Counters()["requests"]
	for _, bad := range [][]string{nil, {"localhost"}, {"a..b.test"}, {"*.*.a.test"}, {"a.*.test"}, {"169.254.169.254"},
		{"-a.test"}, {"a-.test"}, {"a_b.test"}, {"ünicode.test"}, {"a.test", "A.test"}, {strings.Repeat("a", 64) + ".test"}} {
		err := c.TestOrder(testCtx(t), bad, solver.NewMemory())
		e := reasonErr(t, err, ReasonIdentifierRefused)
		assert.ErrorIs(t, e, ErrInvalidName)
	}
	many := make([]string, MaxNames+1)
	for i := range many {
		many[i] = fmt.Sprintf("n%d.example.test", i)
	}
	err = c.TestOrder(testCtx(t), many, solver.NewMemory())
	requireReason(t, err, ReasonIdentifierRefused)
	assert.Equal(t, n, s.Counters()["requests"])
}

func TestCASuppliedHTTPURLRefused(t *testing.T) {
	for _, field := range []string{"finalize", "authz", "certificate"} {
		t.Run(field, func(t *testing.T) {
			s := startFake(t, fakeacme.Options{})
			c := registered(t, s)
			require.NoError(t, s.Advertise(field, "http://169.254.169.254/latest/meta-data?token=x"))
			ws := newWebSolver(t, s, solver.DNS01)
			csr, _ := csrFor(t, "h.example.test")
			_, err := c.Order(testCtx(t), []string{"h.example.test"}, csr, ws)
			e := reasonErr(t, err, ReasonDirectoryInvalid)
			assert.ErrorIs(t, e, transport.ErrURLRefused)
			assert.NotContains(t, err.Error(), "169.254")
			assert.NotContains(t, err.Error(), "token=")
		})
	}
}

func TestValidationFailureCleansUp(t *testing.T) {
	for _, typ := range []string{solver.HTTP01, solver.DNS01} {
		t.Run(typ, func(t *testing.T) {
			s := startFake(t, fakeacme.Options{})
			c := registered(t, s)
			require.NoError(t, s.FailValidation(typ, true))
			ws := newWebSolver(t, s, typ)
			ws.route(s, "v.example.test")
			var rec recorder
			err := c.TestOrder(testCtx(t), []string{"v.example.test"}, ws, rec.opts()...)
			e := reasonErr(t, err, validationReason(typ))
			assert.Equal(t, "v.example.test", e.Identifier)
			assert.Len(t, rec.presented, 1)
			assert.ElementsMatch(t, rec.presented, rec.cleaned)
			assert.Equal(t, ws.Presented(), ws.CleanedUp())
		})
	}
}

func TestPresentFailureCleansUp(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	m := solver.NewMemory(solver.DNS01)
	m.PresentErr = errors.New("hook said: secret-token-123 is wrong")
	err := c.TestOrder(testCtx(t), []string{"a.example.test", "b.example.test"}, m)
	e := reasonErr(t, err, ReasonHookRefused)
	assert.ErrorIs(t, e, ErrSolver)
	assert.NotContains(t, err.Error(), "secret-token-123")
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", err, err, err), "secret-token-123")
	assert.Len(t, m.Presented(), 1, "stopped at the first failure")
	assert.Equal(t, m.Presented(), m.CleanedUp(), "the failed Present is cleaned up too")

	m2 := solver.NewMemory(solver.HTTP01)
	m2.PresentErr = errors.New("x")
	err = c.TestOrder(testCtx(t), []string{"c.example.test"}, m2)
	requireReason(t, err, ReasonValidationFailedHTTP)

	// A solver's own *Error is kept.
	m3 := solver.NewMemory(solver.DNS01)
	m3.PresentErr = &Error{Reason: ReasonHookRefused, Status: 401}
	err = c.TestOrder(testCtx(t), []string{"d.example.test"}, m3)
	assert.Equal(t, 401, reasonErr(t, err, ReasonHookRefused).Status)

	// A persistence failure in OnPresent stops before Present.
	m4 := solver.NewMemory(solver.DNS01)
	boom := errors.New("db down")
	err = c.TestOrder(testCtx(t), []string{"e.example.test"}, m4, WithOnPresent(func(solver.Challenge) error { return boom }))
	assert.ErrorIs(t, err, boom)
	assert.ErrorIs(t, err, ErrSolver)
	requireReason(t, err, ReasonHookRefused)
	assert.NotContains(t, err.Error(), "db down")
	assert.NotContains(t, fmt.Sprintf("%+v %#v", err, err), "db down")
	assert.Empty(t, m4.Presented())
	assert.Empty(t, m4.CleanedUp())
}

func TestCancelMidOrderCleansUp(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ctx, cancel := context.WithCancel(testCtx(t))
	ws := newWebSolver(t, s, solver.DNS01)
	inner := ws.AfterPresent
	ws.AfterPresent = func(ctx context.Context, ch solver.Challenge) error {
		err := inner(ctx, ch)
		cancel() // e.g. the license locks or the server shuts down
		return err
	}
	var cleanCtxErr error
	innerClean := ws.AfterCleanUp
	ws.AfterCleanUp = func(ctx context.Context, ch solver.Challenge) error {
		cleanCtxErr = ctx.Err()
		_, hasDeadline := ctx.Deadline()
		assert.True(t, hasDeadline, "cleanup is bounded")
		return innerClean(ctx, ch)
	}
	var rec recorder
	csr, _ := csrFor(t, "a.example.test", "b.example.test")
	_, err := c.Order(ctx, []string{"a.example.test", "b.example.test"}, csr, ws, rec.opts()...)
	e := reasonErr(t, err, ReasonNotIssuedInTime)
	assert.ErrorIs(t, e, context.Canceled)
	require.NotEmpty(t, rec.presented)
	assert.ElementsMatch(t, rec.presented, rec.cleaned)
	require.NoError(t, cleanCtxErr, "cleanup runs on a live context")
	assert.Empty(t, s.DNSRecords())
	assert.Zero(t, s.Counters()["issued"])
}

// A hook that never answers costs one call's budget, not the order's.
func TestHungPresentHitsCallDeadline(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s, func(cfg *Config) { cfg.CallTimeout = 300 * time.Millisecond })
	m := solver.NewMemory(solver.DNS01)
	m.AfterPresent = func(ctx context.Context, _ solver.Challenge) error {
		<-ctx.Done()
		return ctx.Err()
	}
	t0 := time.Now()
	err := c.TestOrder(testCtx(t), []string{"hung.example.test"}, m)
	assert.Less(t, time.Since(t0), 5*time.Second)
	e := reasonErr(t, err, ReasonNotIssuedInTime)
	assert.ErrorIs(t, e, context.DeadlineExceeded)
	assert.Equal(t, m.Presented(), m.CleanedUp())
}

func TestConfigNeverPrintsTheKey(t *testing.T) {
	k := p256(t)
	cfg := Config{DirectoryURL: "https://ca.test/dir", Key: k, AccountURL: "https://ca.test/acct/1"}
	raw, err := k.Bytes()
	require.NoError(t, err)
	d := hex.EncodeToString(raw)
	for _, form := range []string{cfg.String(), fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg),
		fmt.Sprintf("%v", &cfg), fmt.Sprintf("%#v", &cfg)} {
		assert.NotContains(t, form, d)
		assert.NotContains(t, form, "D:")
		assert.Contains(t, form, "redacted")
	}
	assert.Contains(t, Config{}.String(), "Key: none")
}

func TestCleanUpErrorIsReported(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	inner := ws.AfterCleanUp
	ws.AfterCleanUp = func(ctx context.Context, ch solver.Challenge) error {
		_ = inner(ctx, ch)
		return errors.New("hook down")
	}
	var got []error
	err := c.TestOrder(testCtx(t), []string{"a.example.test"}, ws, WithOnCleanUp(func(_ solver.Challenge, err error) { got = append(got, err) }))
	require.NoError(t, err, "a failed cleanup does not fail the order")
	require.Len(t, got, 1)
	require.Error(t, got[0])
}

// Errors never carry what a CA, a binding or a key holds (A10).
func TestErrorsCarryNoSecrets(t *testing.T) {
	eabKey := []byte("very-secret-eab-key-0123456789ab")
	s := startFake(t, fakeacme.Options{RequireEAB: true, EABKey: eabKey})
	cr := s.Credentials()
	host := strings.TrimPrefix(s.BaseURL(), "https://")

	var errs []error
	collect := func(err error) {
		require.Error(t, err)
		errs = append(errs, err)
	}
	wrong := base64.RawURLEncoding.EncodeToString([]byte("another-secret-key-0123456789abc"))
	_, err := newTestClient(t, s).RegisterAccount(testCtx(t), "", &EAB{KID: cr.EABKID, HMACKey: []byte(wrong)}, true)
	collect(err)
	_, err = newTestClient(t, s).RegisterAccount(testCtx(t), "", &EAB{KID: cr.EABKID, HMACKey: []byte(cr.EABHMAC + "!")}, true)
	collect(err)
	c := newTestClient(t, s)
	_, err = c.RegisterAccount(testCtx(t), "", &EAB{KID: cr.EABKID, HMACKey: []byte(cr.EABHMAC)}, true)
	require.NoError(t, err)
	for _, f := range []fakeacme.Fault{
		{Endpoint: "new-order", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: time.Hour},
		{Endpoint: "new-order", Kind: fakeacme.FaultServerInternal, Times: 1},
		{Endpoint: "new-order", Kind: fakeacme.FaultBadNonce},
	} {
		require.NoError(t, s.AddFault(f))
		collect(c.TestOrder(testCtx(t), []string{"s.example.test"}, solver.NewMemory()))
		s.ClearFaults()
	}
	s.RejectIdentifier("blocked.test")
	collect(c.TestOrder(testCtx(t), []string{"x.blocked.test"}, solver.NewMemory()))
	require.NoError(t, s.FailValidation(solver.DNS01, true))
	collect(c.TestOrder(testCtx(t), []string{"f.example.test"}, newWebSolver(t, s, solver.DNS01)))

	keyDER, err := x509.MarshalPKCS8PrivateKey(c.cfg.Key)
	require.NoError(t, err)
	secrets := []string{cr.EABHMAC, string(eabKey), wrong, base64.StdEncoding.EncodeToString(keyDER),
		host, "https://", "fake", "injected", "nonce is stale", "on purpose", "configured to fail", "Retry-After"}
	for _, err := range errs {
		for _, form := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
			for _, sec := range secrets {
				assert.NotContains(t, form, sec, "error %q", form)
			}
		}
	}
	eab := EAB{KID: "k", HMACKey: []byte(cr.EABHMAC)}
	for _, form := range []string{eab.String(), fmt.Sprintf("%v", eab), fmt.Sprintf("%+v", eab), fmt.Sprintf("%#v", eab)} {
		assert.NotContains(t, form, cr.EABHMAC)
	}
}

func TestRetryBackoff(t *testing.T) {
	backoff := func(n, code int) time.Duration {
		r := &http.Response{StatusCode: code, Body: http.NoBody}
		defer r.Body.Close()
		return retryBackoff(n, nil, r)
	}
	assert.Positive(t, backoff(1, http.StatusBadRequest))
	assert.Positive(t, backoff(badNonceRetries, http.StatusBadRequest))
	assert.Zero(t, backoff(badNonceRetries+1, http.StatusBadRequest))
	for _, code := range []int{http.StatusTooManyRequests, 500, 501, 502, 503, 504, 200, 201, 302} {
		assert.Zero(t, backoff(1, code), code)
	}
	assert.Zero(t, retryBackoff(1, nil, nil))
}

func TestErrorText(t *testing.T) {
	e := &Error{Reason: ReasonCARateLimited, ProblemType: ProblemPrefix + "rateLimited", Status: 429, Identifier: "a.test",
		cause: &RateLimitedError{RetryAfter: time.Hour}}
	assert.Equal(t, "acme: acme.ca_rate_limited for a.test (urn:ietf:params:acme:error:rateLimited) status 429", e.Error())
	assert.Equal(t, "acme: rate limited by the CA, retry after 1h0m0s", (&RateLimitedError{RetryAfter: time.Hour}).Error())
	assert.Equal(t, "acme: acme.identifier_refused: acme: the name is not a valid DNS name", newError(ReasonIdentifierRefused, ErrInvalidName).Error())
	assert.Zero(t, newError(ReasonIdentifierRefused, nil).RetryAfter())
	assert.Equal(t, ReasonHookRefused, ReasonOf(fmt.Errorf("wrapped: %w", newError(ReasonHookRefused, nil))))
	assert.Empty(t, ReasonOf(errors.New("x")))
	assert.Len(t, Reasons(), 18)
}

func TestClassifyFallbacks(t *testing.T) {
	c := &Client{cfg: Config{Now: time.Now}}
	assert.NoError(t, c.classify(nil, opOrder, "", ""))
	requireReason(t, c.classify(errors.New("acme: invalid response: unexpected EOF"), opOrder, "", ""), ReasonDirectoryInvalid)
	requireReason(t, c.classify(context.DeadlineExceeded, opAccount, "", ""), ReasonProviderUnreachable)
	requireReason(t, c.classify(context.DeadlineExceeded, opOrder, "", ""), ReasonNotIssuedInTime)
	requireReason(t, c.classify(timeoutErr{}, opAccount, "", ""), ReasonProviderUnreachable)
	requireReason(t, c.classify(timeoutErr{}, opOrder, "", ""), ReasonNotIssuedInTime)
	// A Retry-After over the cap from a CA.
	rl := &xacme.Error{StatusCode: 429, ProblemType: ProblemPrefix + "rateLimited", Header: http.Header{"Retry-After": {"259200"}}}
	assert.Equal(t, MaxRetryAfter, reasonErr(t, c.classify(rl, opOrder, "", ""), ReasonCARateLimited).RetryAfter())
	// An invalid order without a problem; an authorization refused for CAA.
	requireReason(t, c.classify(&xacme.OrderError{Status: "invalid"}, opOrder, "", ""), ReasonNotIssuedInTime)
	aze := &xacme.AuthorizationError{Errors: []error{&xacme.Error{StatusCode: 403, ProblemType: ProblemPrefix + "caa"}}}
	requireReason(t, c.classify(aze, opOrder, "dns-01", "a.test"), ReasonIdentifierRefused)
	for typ, want := range map[string]string{"badCSR": ReasonKeyPolicyNotAllowed, "dns": ReasonValidationFailedDNS,
		"connection": ReasonValidationFailedHTTP, "orderNotReady": ReasonNotIssuedInTime, "userActionRequired": ReasonTermsNotAccepted,
		"malformed": ReasonDirectoryInvalid, "invalidContact": ReasonAccountRejected} {
		requireReason(t, c.classify(&xacme.Error{StatusCode: 400, ProblemType: ProblemPrefix + typ}, opOrder, "", ""), want)
	}
	mine := newError(ReasonHookRefused, nil)
	assert.Same(t, mine, c.classify(mine, opOrder, "", ""))
}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "timeout" }
func (timeoutErr) Timeout() bool { return true }

func TestCheckChain(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	csr, key := csrFor(t, "c.example.test")
	chain, err := c.Order(testCtx(t), []string{"c.example.test"}, csr, ws)
	require.NoError(t, err)
	require.NoError(t, checkChain(chain, key.Public(), []string{"c.example.test"}))
	requireReason(t, checkChain(nil, key.Public(), []string{"c.example.test"}), ReasonDirectoryInvalid)
	requireReason(t, checkChain([][]byte{[]byte("x")}, key.Public(), []string{"c.example.test"}), ReasonDirectoryInvalid)
	requireReason(t, checkChain(chain, p256(t).Public(), []string{"c.example.test"}), ReasonDirectoryInvalid)
	requireReason(t, checkChain(chain, key.Public(), []string{"d.example.test"}), ReasonDirectoryInvalid)
	requireReason(t, checkChain([][]byte{chain[0], []byte("x")}, key.Public(), []string{"c.example.test"}), ReasonDirectoryInvalid)
}

func TestValidToken(t *testing.T) {
	assert.True(t, validToken(strings.Repeat("aZ0-_", 4)))
	assert.False(t, validToken("short"))
	assert.False(t, validToken(strings.Repeat("a", 257)))
	assert.False(t, validToken(strings.Repeat("a", 20)+"/../"))
}

// renewalServer serves ARI answers of the test's choosing over TLS, and the fake's directory points at it.
func renewalServer(t *testing.T, s *fakeacme.Server, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	require.NoError(t, s.Advertise("renewalInfo", srv.URL+"/ari/"))
	pemSrv := string(certPEM(srv.Certificate().Raw))
	hc, err := transport.New(string(s.CAPEM()) + pemSrv)
	require.NoError(t, err)
	return newTestClient(t, s, func(c *Config) { c.HTTPClient = hc })
}

func TestRenewalInfo(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	csr, _ := csrFor(t, "ari.example.test")
	chain, err := c.Order(testCtx(t), []string{"ari.example.test"}, csr, ws)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)

	s.SetARIRelative(10*24*time.Hour, 0)
	w, err := c.RenewalInfo(testCtx(t), chain[0])
	require.NoError(t, err)
	assert.Equal(t, leaf.NotAfter.Add(-10*24*time.Hour).UTC().Truncate(time.Second), w.Start)
	assert.Equal(t, 6*time.Hour, w.RetryAfter)

	start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, s.SetARIWindow(start, start.Add(time.Hour)))
	w, err = c.RenewalInfo(testCtx(t), chain[0])
	require.NoError(t, err)
	assert.Equal(t, start, w.Start)
	assert.Equal(t, start.Add(time.Hour), w.End)

	// A certificate the CA does not know: 404 problem.
	other, _ := selfSigned(t)
	_, err = c.RenewalInfo(testCtx(t), other)
	requireReason(t, err, ReasonDirectoryInvalid)
	_, err = c.RenewalInfo(testCtx(t), []byte("not a certificate"))
	requireReason(t, err, ReasonDirectoryInvalid)

	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "ari", Kind: fakeacme.FaultGiant, Times: 1}))
	_, err = c.RenewalInfo(testCtx(t), chain[0])
	requireReason(t, err, ReasonDirectoryInvalid)
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "ari", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: time.Hour}))
	_, err = c.RenewalInfo(testCtx(t), chain[0])
	assert.Equal(t, time.Hour, reasonErr(t, err, ReasonCARateLimited).RetryAfter())
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "ari", Kind: fakeacme.FaultServerInternal, Times: 1}))
	_, err = c.RenewalInfo(testCtx(t), chain[0])
	requireReason(t, err, ReasonProviderUnreachable)
}

func TestRenewalInfoAbsent(t *testing.T) {
	s := startFake(t, fakeacme.Options{NoARI: true})
	c := newTestClient(t, s)
	der, _ := selfSigned(t)
	_, err := c.RenewalInfo(testCtx(t), der)
	assert.ErrorIs(t, err, ErrNoARI)
}

func TestRenewalInfoGarbage(t *testing.T) {
	der, _ := selfSigned(t)
	for name, h := range map[string]http.HandlerFunc{
		"not json":  func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"no window": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"suggestedWindow":{}}`)) },
		"reversed": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"suggestedWindow":{"start":"2030-01-02T00:00:00Z","end":"2030-01-01T00:00:00Z"}}`))
		},
		"year 0001": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"suggestedWindow":{"start":"0001-01-01T00:00:00Z","end":"0001-01-02T00:00:00Z"}}`))
		},
		"over ten years ahead": func(w http.ResponseWriter, _ *http.Request) {
			end := time.Now().Add(MaxARIAhead + 24*time.Hour).UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(`{"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"` + end + `"}}`))
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.test/", http.StatusFound)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := startFake(t, fakeacme.Options{})
			c := renewalServer(t, s, h)
			_, err := c.RenewalInfo(testCtx(t), der)
			requireReason(t, err, ReasonDirectoryInvalid)
		})
	}
	t.Run("ok with date retry-after and extra fields", func(t *testing.T) {
		s := startFake(t, fakeacme.Options{})
		var path string
		c := renewalServer(t, s, func(w http.ResponseWriter, r *http.Request) {
			path = r.URL.Path
			w.Header().Set("Retry-After", time.Now().Add(2*time.Hour).UTC().Format(http.TimeFormat))
			_, _ = w.Write([]byte(`{"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"2030-01-02T00:00:00+00:00","x":1},"explanationURL":"https://e"}`))
		})
		w, err := c.RenewalInfo(testCtx(t), der)
		require.NoError(t, err)
		assert.Equal(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), w.Start)
		assert.InDelta(t, (2 * time.Hour).Seconds(), w.RetryAfter.Seconds(), 5)
		cert, _ := x509.ParseCertificate(der)
		id, _ := CertID(cert)
		assert.Equal(t, "/ari/"+id, path)
	})
	t.Run("slow", func(t *testing.T) {
		s := startFake(t, fakeacme.Options{})
		block := make(chan struct{})
		c := renewalServer(t, s, func(http.ResponseWriter, *http.Request) { <-block })
		t.Cleanup(func() { close(block) }) // runs before the server's Close, which waits for the handler
		c.cfg.CallTimeout = 200 * time.Millisecond
		_, err := c.RenewalInfo(testCtx(t), der)
		requireReason(t, err, ReasonProviderUnreachable)
	})
}

func TestSolverErrorHidesTheCauseText(t *testing.T) {
	secret := errors.New("remote said: token=abc secret body")
	e := SolverError(ReasonValidationFailedHTTP, "a.example.test", secret)
	assert.Equal(t, ReasonValidationFailedHTTP, ReasonOf(e))
	assert.ErrorIs(t, e, secret)
	assert.ErrorIs(t, e, ErrSolver)
	assert.NotContains(t, e.Error(), "secret body")
	assert.Contains(t, e.Error(), "a.example.test")
	plain := SolverError(ReasonChallengeUnavailable, "", nil)
	assert.ErrorIs(t, plain, ErrSolver)
	assert.Equal(t, "acme: acme.challenge_unavailable: "+ErrSolver.Error(), plain.Error())
}
