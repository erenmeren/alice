package fakeacme

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

func TestDirectory(t *testing.T) {
	s := start(t, Options{})
	var d map[string]any
	resp := getJSON(t, s, s.DirectoryURL(), &d)
	assert.NotEmpty(t, resp.Header.Get("Replay-Nonce"))
	for _, k := range []string{"newNonce", "newAccount", "newOrder", "revokeCert", "keyChange", "renewalInfo"} {
		assert.Contains(t, d[k], s.BaseURL(), k)
	}
	meta := d["meta"].(map[string]any)
	assert.Equal(t, s.BaseURL()+"/terms", meta["termsOfService"])
	assert.Equal(t, false, meta["externalAccountRequired"])
	dir, err := newClient(t, s).Discover(ctx(t))
	require.NoError(t, err)
	assert.Equal(t, s.BaseURL()+"/acme/key-change", dir.KeyChangeURL)

	s.SetExternalAccountRequired(true)
	getJSON(t, s, s.DirectoryURL(), &d)
	assert.Equal(t, true, d["meta"].(map[string]any)["externalAccountRequired"])

	n := start(t, Options{NoARI: true, NoKeyChange: true, NoTerms: true})
	d = map[string]any{}
	getJSON(t, n, n.DirectoryURL(), &d)
	assert.NotContains(t, d, "renewalInfo")
	assert.NotContains(t, d, "keyChange")
	assert.NotContains(t, d["meta"], "termsOfService")
}

func TestTermsAreServed(t *testing.T) {
	s := start(t, Options{})
	resp, err := s.HTTPClient().Get(s.BaseURL() + "/terms") //nolint:noctx // test
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
}

func TestRegisterWithTermsAndContact(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	a, err := c.Register(ctx(t), &acme.Account{Contact: []string{"mailto:admin@example.test"}}, acme.AcceptTOS)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusValid, a.Status)
	assert.Equal(t, []string{"mailto:admin@example.test"}, a.Contact)
	assert.Contains(t, a.URI, "/acme/acct/")

	_, err = c.Register(ctx(t), &acme.Account{}, acme.AcceptTOS)
	assert.ErrorIs(t, err, acme.ErrAccountAlreadyExists)

	got, err := c.GetReg(ctx(t), "")
	require.NoError(t, err)
	assert.Equal(t, a.URI, got.URI)

	// Terms not accepted.
	_, err = newClient(t, s).Register(ctx(t), &acme.Account{}, func(string) bool { return false })
	assert.Equal(t, "urn:ietf:params:acme:error:userActionRequired", problemOf(t, err).ProblemType)

	// A contact that is not a mailto: URL.
	_, err = newClient(t, s).Register(ctx(t), &acme.Account{Contact: []string{"tel:+1555"}}, acme.AcceptTOS)
	assert.Equal(t, "urn:ietf:params:acme:error:invalidContact", problemOf(t, err).ProblemType)

	// No terms at all: no agreement is needed.
	n := start(t, Options{NoTerms: true})
	_, err = newClient(t, n).Register(ctx(t), &acme.Account{}, nil)
	assert.NoError(t, err)
}

func TestGetRegOfUnknownKey(t *testing.T) {
	s := start(t, Options{})
	_, err := newClient(t, s).GetReg(ctx(t), "")
	assert.ErrorIs(t, err, acme.ErrNoAccount)
}

func TestExternalAccountBinding(t *testing.T) {
	s := start(t, Options{RequireEAB: true})
	cred := s.Credentials()
	hmacKey := s.opts.EABKey

	// Required and missing.
	_, err := newClient(t, s).Register(ctx(t), &acme.Account{}, acme.AcceptTOS)
	ae := problemOf(t, err)
	assert.Equal(t, "urn:ietf:params:acme:error:externalAccountRequired", ae.ProblemType)

	bind := func(kid string, key []byte) *acme.Account {
		return &acme.Account{ExternalAccountBinding: &acme.ExternalAccountBinding{KID: kid, Key: key}}
	}
	// Wrong key id, wrong HMAC.
	_, err = newClient(t, s).Register(ctx(t), bind("other", hmacKey), acme.AcceptTOS)
	assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", problemOf(t, err).ProblemType)
	_, err = newClient(t, s).Register(ctx(t), bind(cred.EABKID, []byte("0123456789abcdef0123456789abcdef")), acme.AcceptTOS)
	assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", problemOf(t, err).ProblemType)

	// Right credentials.
	a, err := newClient(t, s).Register(ctx(t), bind(cred.EABKID, hmacKey), acme.AcceptTOS)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusValid, a.Status)

	// The credentials are the documented base64url value.
	raw, err := decodeB64(cred.EABHMAC)
	require.NoError(t, err)
	assert.Equal(t, hmacKey, raw)

	// Not required: a binding that is sent is still checked.
	s.SetExternalAccountRequired(false)
	_, err = newClient(t, s).Register(ctx(t), &acme.Account{}, acme.AcceptTOS)
	assert.NoError(t, err)
	_, err = newClient(t, s).Register(ctx(t), bind("other", hmacKey), acme.AcceptTOS)
	assert.Error(t, err)
}

func TestUpdateAndDeactivate(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	a, err := c.UpdateReg(ctx(t), &acme.Account{Contact: []string{"mailto:other@example.test"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"mailto:other@example.test"}, a.Contact)
	_, err = c.UpdateReg(ctx(t), &acme.Account{Contact: []string{"http://x"}})
	assert.Equal(t, "urn:ietf:params:acme:error:invalidContact", problemOf(t, err).ProblemType)

	require.NoError(t, c.DeactivateReg(ctx(t)))
	_, err = c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", problemOf(t, err).ProblemType)
	// The key is still taken: it cannot register again.
	got, err := c.GetReg(ctx(t), "")
	require.NoError(t, err)
	assert.Equal(t, "deactivated", got.Status)
}

func TestKeyRollover(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	a := register(t, c)
	oldKey := c.Key
	newK := testKey(t)
	require.NoError(t, c.AccountKeyRollover(ctx(t), newK))

	// The account answers to the new key only.
	got, err := c.GetReg(ctx(t), "")
	require.NoError(t, err)
	assert.Equal(t, a.URI, got.URI)
	stale := &acme.Client{Key: oldKey, DirectoryURL: s.DirectoryURL(), HTTPClient: s.HTTPClient(), RetryBackoff: fastRetry}
	_, err = stale.GetReg(ctx(t), "")
	assert.ErrorIs(t, err, acme.ErrNoAccount)
	_, err = c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	assert.NoError(t, err)

	// A key that is another account's key is refused (409).
	other := newClient(t, s)
	register(t, other)
	err = c.AccountKeyRollover(ctx(t), other.Key)
	assert.Equal(t, 409, problemOf(t, err).StatusCode)
}

func TestHTTP01Issuance(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	st := newStub(t)
	der, o := issue(t, s, c, st, HTTP01, "www.example.test")
	require.Len(t, der, 2, "leaf and intermediate")
	assert.Equal(t, acme.StatusReady, o.Status)

	leaf, err := x509.ParseCertificate(der[0])
	require.NoError(t, err)
	inter, err := x509.ParseCertificate(der[1])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(s.IssuerRootPEM()))
	pool := x509.NewCertPool()
	pool.AddCert(inter)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, DNSName: "www.example.test"})
	require.NoError(t, err)
	assert.InDelta(t, 90*24, leaf.NotAfter.Sub(leaf.NotBefore).Hours(), 1)
	assert.True(t, contains2(leaf.Issuer.CommonName, "intermediate"))

	// The CA's TLS CA is not the issuing root.
	assert.NotEqual(t, s.CAPEM(), s.IssuerRootPEM())
	cnt := s.Counters()
	assert.Equal(t, 1, cnt["new-order"])
	assert.Equal(t, 1, cnt["finalize"])
	assert.Equal(t, 1, cnt["issued"])
	assert.Equal(t, 1, cnt["validations-http-01"])
}

func TestDNS01Issuance(t *testing.T) {
	s := start(t, Options{LeafLifetime: 24 * 60 * 60 * 1e9})
	c := newClient(t, s)
	register(t, c)
	der, _ := issue(t, s, c, nil, DNS01, "a.example.test", "b.example.test")
	leaf, err := x509.ParseCertificate(der[0])
	require.NoError(t, err)
	assert.Equal(t, []string{"a.example.test", "b.example.test"}, leaf.DNSNames)
	assert.InDelta(t, 24, leaf.NotAfter.Sub(leaf.NotBefore).Hours(), 1)
	assert.Equal(t, 2, s.Counters()["validations-dns-01"])
}

func TestWildcardIsDNS01Only(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	o, err := c.AuthorizeOrder(ctx(t), idents("*.example.test", "example.test"))
	require.NoError(t, err)
	require.Len(t, o.AuthzURLs, 2)
	for i, u := range o.AuthzURLs {
		az, err := c.GetAuthorization(ctx(t), u)
		require.NoError(t, err)
		assert.Equal(t, "example.test", az.Identifier.Value)
		assert.Equal(t, i == 0, az.Wildcard)
		if az.Wildcard {
			require.Len(t, az.Challenges, 1)
			assert.Equal(t, DNS01, az.Challenges[0].Type)
		} else {
			assert.Len(t, az.Challenges, 2)
		}
	}
	// Both authorizations need a TXT value at the same name.
	solve(t, s, c, nil, o, DNS01)
	assert.Len(t, s.DNSRecords()["_acme-challenge.example.test"], 2)
	o, err = c.WaitOrder(ctx(t), o.URI)
	require.NoError(t, err)
	der, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csrFor(t, testKey(t), "*.example.test", "example.test"), true)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der[0])
	require.NoError(t, err)
	assert.Equal(t, []string{"*.example.test", "example.test"}, leaf.DNSNames)

	// Without dns-01 a wildcard cannot be validated at all.
	require.NoError(t, s.SetChallenges(HTTP01))
	_, err = c.AuthorizeOrder(ctx(t), idents("*.other.test"))
	assert.Equal(t, "urn:ietf:params:acme:error:rejectedIdentifier", problemOf(t, err).ProblemType)
}

func TestAlternateChains(t *testing.T) {
	s := start(t, Options{Alternates: 1})
	c := newClient(t, s)
	register(t, c)
	o, err := c.AuthorizeOrder(ctx(t), idents("www.example.test"))
	require.NoError(t, err)
	solve(t, s, c, nil, o, DNS01)
	o, err = c.WaitOrder(ctx(t), o.URI)
	require.NoError(t, err)
	def, certURL, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csrFor(t, testKey(t), "www.example.test"), true)
	require.NoError(t, err)
	alts, err := c.ListCertAlternates(ctx(t), certURL)
	require.NoError(t, err)
	require.Len(t, alts, 1)
	alt, err := c.FetchCert(ctx(t), alts[0], true)
	require.NoError(t, err)
	require.Len(t, alt, 2)
	assert.Equal(t, def[0], alt[0], "the same leaf")
	assert.NotEqual(t, def[1], alt[1], "another intermediate")
	back, err := c.ListCertAlternates(ctx(t), alts[0])
	require.NoError(t, err)
	assert.Contains(t, back, certURL)

	_, err = c.FetchCert(ctx(t), certURL+"/alt/9", true)
	assert.Equal(t, 404, problemOf(t, err).StatusCode)
	_, err = c.FetchCert(ctx(t), certURL+"/alt/x", true)
	assert.Equal(t, 404, problemOf(t, err).StatusCode)
}
