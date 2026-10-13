package acme

// These tests pin the behaviour of golang.org/x/crypto/acme v0.57.0 that the wrapper relies on (the Task 5
// spike, kept as regression tests): if an upgrade changes one of them, the wrapper must be revisited.

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xacme "golang.org/x/crypto/acme"

	"alice/internal/acme/solver"
	"alice/internal/testutil/fakeacme"
)

func libClient(t *testing.T, s *fakeacme.Server) *xacme.Client {
	t.Helper()
	return &xacme.Client{Key: p256(t), DirectoryURL: s.DirectoryURL(), HTTPClient: guarded(t, s), RetryBackoff: retryBackoff}
}

// The EAB key is raw bytes in the library; CAs hand it out base64url. A key given undecoded is rejected by the CA.
func TestLibraryEABKeyIsRawBytes(t *testing.T) {
	s := startFake(t, fakeacme.Options{RequireEAB: true})
	cr := s.Credentials()
	raw, err := base64.RawURLEncoding.DecodeString(cr.EABHMAC)
	require.NoError(t, err)

	bad := libClient(t, s)
	_, err = bad.Register(testCtx(t), &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: cr.EABKID, Key: []byte(cr.EABHMAC)}}, xacme.AcceptTOS)
	var ae *xacme.Error
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", ae.ProblemType)

	good := libClient(t, s)
	a, err := good.Register(testCtx(t), &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: cr.EABKID, Key: raw}}, xacme.AcceptTOS)
	require.NoError(t, err)
	assert.NotEmpty(t, a.URI)
	assert.NotContains(t, (&xacme.ExternalAccountBinding{KID: "k", Key: raw}).String(), cr.EABHMAC)
}

// The library has no RetryAfter method on *Error (A7 assumed one): the header is kept in Error.Header and
// acme.RateLimit parses it. RetryBackoff is consulted for 429 and 5xx; zero stops at once.
func TestLibraryRateLimitAndNoSleep(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := libClient(t, s)
	_, err := c.Register(testCtx(t), &xacme.Account{}, xacme.AcceptTOS)
	require.NoError(t, err)
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultRateLimited, RetryAfter: 2 * time.Hour}))
	t0 := time.Now()
	_, err = c.AuthorizeOrder(testCtx(t), xacme.DomainIDs("a.example.test"))
	assert.Less(t, time.Since(t0), 2*time.Second)
	d, ok := xacme.RateLimit(err)
	require.True(t, ok)
	assert.Equal(t, 2*time.Hour, d)
	assert.Equal(t, 1, s.Counters()["new-order"])
}

// Rollover changes the client's key on success; DeactivateReg makes later requests fail with unauthorized.
func TestLibraryRolloverAndDeactivate(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := libClient(t, s)
	a, err := c.Register(testCtx(t), &xacme.Account{}, xacme.AcceptTOS)
	require.NoError(t, err)
	nk := p256(t)
	require.NoError(t, c.AccountKeyRollover(testCtx(t), nk))
	assert.Same(t, nk, c.Key)
	// The old key no longer finds the account.
	old := libClient(t, s)
	_, err = old.GetReg(testCtx(t), a.URI)
	assert.ErrorIs(t, err, xacme.ErrNoAccount)

	require.NoError(t, c.DeactivateReg(testCtx(t)))
	_, err = c.AuthorizeOrder(testCtx(t), xacme.DomainIDs("a.example.test"))
	var ae *xacme.Error
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, http.StatusForbidden, ae.StatusCode)
}

// The full order flow with the library's helpers, alternates included.
func TestLibraryOrderFlow(t *testing.T) {
	s := startFake(t, fakeacme.Options{Alternates: 1})
	c := libClient(t, s)
	_, err := c.Register(testCtx(t), &xacme.Account{}, xacme.AcceptTOS)
	require.NoError(t, err)
	ws := newWebSolver(t, s)
	ws.route(s, "www.example.test")

	o, err := c.AuthorizeOrder(testCtx(t), []xacme.AuthzID{{Type: "dns", Value: "www.example.test"}, {Type: "dns", Value: "*.example.test"}})
	require.NoError(t, err)
	require.Len(t, o.AuthzURLs, 2)
	for _, u := range o.AuthzURLs {
		z, err := c.GetAuthorization(testCtx(t), u)
		require.NoError(t, err)
		var ch *xacme.Challenge
		for _, x := range z.Challenges {
			if (z.Wildcard && x.Type == "dns-01") || (!z.Wildcard && x.Type == "http-01") {
				ch = x
			}
		}
		require.NotNil(t, ch, "wildcard=%v", z.Wildcard)
		if z.Wildcard {
			assert.Equal(t, "example.test", z.Identifier.Value, "the authz of a wildcard names the base")
			v, err := c.DNS01ChallengeRecord(ch.Token)
			require.NoError(t, err)
			s.DNSSet("_acme-challenge.example.test", v)
		} else {
			body, err := c.HTTP01ChallengeResponse(ch.Token)
			require.NoError(t, err)
			assert.Equal(t, "/.well-known/acme-challenge/"+ch.Token, c.HTTP01ChallengePath(ch.Token))
			require.NoError(t, ws.Present(testCtx(t), solver.Challenge{Type: solver.HTTP01, Domain: z.Identifier.Value, Token: ch.Token, KeyAuth: body}))
		}
		_, err = c.Accept(testCtx(t), ch)
		require.NoError(t, err)
		_, err = c.WaitAuthorization(testCtx(t), u)
		require.NoError(t, err)
	}
	o, err = c.WaitOrder(testCtx(t), o.URI)
	require.NoError(t, err)
	csr, _ := csrFor(t, "www.example.test", "*.example.test")
	chain, certURL, err := c.CreateOrderCert(testCtx(t), o.FinalizeURL, csr, true)
	require.NoError(t, err)
	require.Len(t, chain, 2, "leaf + intermediate")
	leaf, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"www.example.test", "*.example.test"}, leaf.DNSNames)
	alts, err := c.ListCertAlternates(testCtx(t), certURL)
	require.NoError(t, err)
	assert.Len(t, alts, 1)
}

// badNonce is retried by the library through RetryBackoff (a 400 status reaches it).
func TestLibraryBadNonceGoesThroughBackoff(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	var seen []int
	c := libClient(t, s)
	c.RetryBackoff = func(n int, r *http.Request, res *http.Response) time.Duration {
		seen = append(seen, res.StatusCode)
		return retryBackoff(n, r, res)
	}
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "new-account", Kind: fakeacme.FaultBadNonce, Times: 1}))
	_, err := c.Register(testCtx(t), &xacme.Account{}, xacme.AcceptTOS)
	require.NoError(t, err)
	assert.Equal(t, []int{http.StatusBadRequest}, seen)
	assert.False(t, errors.Is(err, xacme.ErrAccountAlreadyExists))
}
