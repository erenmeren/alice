package fakeacme

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

func ready(t *testing.T, s *Server, c *acme.Client, names ...string) *acme.Order {
	t.Helper()
	o, err := c.AuthorizeOrder(ctx(t), idents(names...))
	require.NoError(t, err)
	solve(t, s, c, nil, o, DNS01)
	o, err = c.WaitOrder(ctx(t), o.URI)
	require.NoError(t, err)
	return o
}

func TestFinalizeRefusesAMismatchingCSR(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	o := ready(t, s, c, "a.example.test")
	for name, names := range map[string][]string{
		"other name":  {"b.example.test"},
		"superset":    {"a.example.test", "b.example.test"},
		"wildcard":    {"*.example.test"},
		"uppercase-x": {"x.example.test"},
	} {
		_, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csrFor(t, testKey(t), names...), true)
		ae := problemOf(t, err)
		assert.Equal(t, "urn:ietf:params:acme:error:badCSR", ae.ProblemType, name)
		assert.Equal(t, http.StatusBadRequest, ae.StatusCode, name)
	}
	assert.Zero(t, s.Counters()["issued"])

	// Garbage CSR, and a CSR signed by another key than the one it names is not a CSR at all.
	_, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, []byte("not a csr"), true)
	assert.Equal(t, "urn:ietf:params:acme:error:badCSR", problemOf(t, err).ProblemType)

	// The right CSR still works afterwards.
	_, _, err = c.CreateOrderCert(ctx(t), o.FinalizeURL, csrFor(t, testKey(t), "a.example.test"), true)
	require.NoError(t, err)
	// And a second finalize is refused: the order is valid now.
	_, _, err = c.CreateOrderCert(ctx(t), o.FinalizeURL, csrFor(t, testKey(t), "a.example.test"), true)
	assert.Equal(t, "urn:ietf:params:acme:error:orderNotReady", problemOf(t, err).ProblemType)
}

func TestFinalizeBeforeValidationIsOrderNotReady(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	o, err := c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	require.NoError(t, err)
	assert.Equal(t, acme.StatusPending, o.Status)
	_, _, err = c.CreateOrderCert(ctx(t), o.FinalizeURL, csrFor(t, testKey(t), "a.example.test"), true)
	assert.Equal(t, "urn:ietf:params:acme:error:orderNotReady", problemOf(t, err).ProblemType)
}

func TestStuckPendingNeverValidates(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	s.SetStuckPending(true)
	o, err := c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	require.NoError(t, err)
	// The record is right, yet the CA never validates.
	az, err := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
	require.NoError(t, err)
	var ch *acme.Challenge
	for _, x := range az.Challenges {
		if x.Type == DNS01 {
			ch = x
		}
	}
	rec, err := c.DNS01ChallengeRecord(ch.Token)
	require.NoError(t, err)
	s.DNSSet("_acme-challenge.a.example.test", rec)
	got, err := c.Accept(ctx(t), ch)
	require.NoError(t, err)
	assert.Equal(t, "processing", got.Status)

	short, cancel := context.WithTimeout(ctx(t), 1500*time.Millisecond)
	defer cancel()
	_, err = c.WaitAuthorization(short, az.URI)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
	cur, err := c.GetOrder(ctx(t), o.URI)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusPending, cur.Status)
	assert.Zero(t, s.Counters()["validations-dns-01"], "no validation was attempted")

	// Accepting again changes nothing; unstuck, a new order validates.
	s.SetStuckPending(false)
	o2 := ready(t, s, c, "b.example.test")
	assert.Equal(t, acme.StatusReady, o2.Status)
}

func TestValidationFailures(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	st := newStub(t)

	// No TXT record at all, then no file at the stub, then a wrong file.
	for _, typ := range []string{DNS01, HTTP01} {
		o, err := c.AuthorizeOrder(ctx(t), idents("fail.example.test"))
		require.NoError(t, err)
		az, err := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
		require.NoError(t, err)
		var ch *acme.Challenge
		for _, x := range az.Challenges {
			if x.Type == typ {
				ch = x
			}
		}
		if typ == HTTP01 {
			s.SetHTTPTarget("fail.example.test", st.addr())
			st.put(c.HTTP01ChallengePath(ch.Token), "wrong")
		}
		_, err = c.Accept(ctx(t), ch)
		require.NoError(t, err)
		_, err = c.WaitAuthorization(ctx(t), az.URI)
		var ae *acme.AuthorizationError
		require.ErrorAs(t, err, &ae, typ)
		_, err = c.WaitOrder(ctx(t), o.URI)
		var oe *acme.OrderError
		require.ErrorAs(t, err, &oe, typ)
		assert.Equal(t, acme.StatusInvalid, oe.Status)
	}
	// An unreachable HTTP-01 target is a connection problem, not a crash.
	s.SetHTTPTarget("fail.example.test", "127.0.0.1:1")
	o, err := c.AuthorizeOrder(ctx(t), idents("fail.example.test"))
	require.NoError(t, err)
	az, err := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
	require.NoError(t, err)
	got, err := c.Accept(ctx(t), az.Challenges[0])
	require.NoError(t, err)
	if got.Type == HTTP01 {
		assert.Equal(t, acme.StatusInvalid, got.Status)
	}

	// validationFails per type: the right record is there, the type is configured to fail.
	require.NoError(t, s.FailValidation(DNS01, true))
	o, err = c.AuthorizeOrder(ctx(t), idents("ok.example.test"))
	require.NoError(t, err)
	az, err = c.GetAuthorization(ctx(t), o.AuthzURLs[0])
	require.NoError(t, err)
	for _, ch := range az.Challenges {
		if ch.Type == DNS01 {
			rec, _ := c.DNS01ChallengeRecord(ch.Token)
			s.DNSSet("_acme-challenge.ok.example.test", rec)
			_, err = c.Accept(ctx(t), ch)
			require.NoError(t, err)
		}
	}
	_, err = c.WaitAuthorization(ctx(t), az.URI)
	var aerr *acme.AuthorizationError
	require.ErrorAs(t, err, &aerr)
	assert.Contains(t, aerr.Error(), "unauthorized")
	require.NoError(t, s.FailValidation(DNS01, false))
	require.Error(t, s.FailValidation("tls-alpn-01", true))
}

func TestRejectedIdentifier(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	s.RejectIdentifier("bad.test")
	for _, n := range []string{"bad.test", "www.bad.test", "*.bad.test"} {
		_, err := c.AuthorizeOrder(ctx(t), idents(n))
		assert.Equal(t, "urn:ietf:params:acme:error:rejectedIdentifier", problemOf(t, err).ProblemType, n)
	}
	_, err := c.AuthorizeOrder(ctx(t), idents("notbad.test"))
	assert.NoError(t, err, "a suffix match is label-wise")
	s.ClearRejected()
	_, err = c.AuthorizeOrder(ctx(t), idents("bad.test"))
	assert.NoError(t, err)
}

func TestOrderRequestChecks(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	_, err := c.AuthorizeOrder(ctx(t), []acme.AuthzID{{Type: "ip", Value: "192.0.2.1"}})
	assert.Equal(t, "urn:ietf:params:acme:error:unsupportedIdentifier", problemOf(t, err).ProblemType)
	for _, bad := range []string{"UPPER.example.test", "nodot", "a..b.test", "-x.example.test", "a_b.example.test"} {
		_, err = c.AuthorizeOrder(ctx(t), idents(bad))
		assert.Equal(t, "urn:ietf:params:acme:error:rejectedIdentifier", problemOf(t, err).ProblemType, bad)
	}
	_, err = c.AuthorizeOrder(ctx(t), idents("a.example.test", "a.example.test"))
	assert.Equal(t, "urn:ietf:params:acme:error:malformed", problemOf(t, err).ProblemType)
	_, err = c.AuthorizeOrder(ctx(t), nil)
	assert.Equal(t, "urn:ietf:params:acme:error:malformed", problemOf(t, err).ProblemType)
}

func TestOrdersBelongToTheirAccount(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	o, err := c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	require.NoError(t, err)
	other := newClient(t, s)
	register(t, other)
	_, err = other.GetOrder(ctx(t), o.URI)
	assert.Equal(t, 403, problemOf(t, err).StatusCode)
	_, err = other.GetAuthorization(ctx(t), o.AuthzURLs[0])
	assert.Equal(t, 404, problemOf(t, err).StatusCode)
	_, err = other.GetOrder(ctx(t), s.BaseURL()+"/acme/order/nope")
	assert.Equal(t, 404, problemOf(t, err).StatusCode)
}

func TestProcessingPolls(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	s.SetProcessingPolls(1)
	o := ready(t, s, c, "a.example.test")
	start := time.Now()
	der, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csrFor(t, testKey(t), "a.example.test"), true)
	require.NoError(t, err)
	assert.Len(t, der, 2)
	assert.GreaterOrEqual(t, time.Since(start), 900*time.Millisecond, "one poll answered processing")
}

func TestLifetimeAndClock(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	require.NoError(t, s.SetLeafLifetime(2*time.Hour))
	require.Error(t, s.SetLeafLifetime(time.Second))
	future := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	s.SetClock(future)
	der, _ := issue(t, s, c, nil, DNS01, "a.example.test")
	leaf := parseLeaf(t, der)
	assert.WithinDuration(t, future.Add(2*time.Hour), leaf.NotAfter, 5*time.Second)
	assert.WithinDuration(t, future, s.Now(), 5*time.Second)
	s.SetClock(time.Time{})
	assert.WithinDuration(t, time.Now(), s.Now(), 5*time.Second)
}

func TestRevokeIsNotImplemented(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	der, _ := issue(t, s, c, nil, DNS01, "a.example.test")
	c.RetryBackoff = func(int, *http.Request, *http.Response) time.Duration { return 0 } // 5xx is retried otherwise
	err := c.RevokeCert(ctx(t), nil, der[0], acme.CRLReasonUnspecified)
	assert.Equal(t, 501, problemOf(t, err).StatusCode)
}
