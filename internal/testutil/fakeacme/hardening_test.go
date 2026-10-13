package fakeacme

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

// Identifiers that are addresses are refused like a real CA does, so an order can never name a host
// the fake would then connect to.
func TestNumericIdentifiersAreRejected(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	for _, n := range []string{"169.254.169.254", "127.0.0.1", "10.0.0.1.", "a.1", "*.169.254.169.254", "1.2.3.4"} {
		_, err := c.AuthorizeOrder(ctx(t), idents(n))
		assert.Equal(t, "urn:ietf:params:acme:error:rejectedIdentifier", problemOf(t, err).ProblemType, n)
	}
	_, err := c.AuthorizeOrder(ctx(t), idents("1.example.test"))
	assert.NoError(t, err, "a numeric label below a real TLD is a name")
}

// HTTP-01 dials only names the admin mapped: an unmapped name (or one that resolves to the metadata
// address) fails with a connection problem and the fake never opens a connection.
func TestHTTP01DialsOnlyMappedNames(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	st := newStub(t)

	accept := func(name string) *acme.Challenge {
		o, err := c.AuthorizeOrder(ctx(t), idents(name))
		require.NoError(t, err)
		az, err := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
		require.NoError(t, err)
		for _, ch := range az.Challenges {
			if ch.Type == HTTP01 {
				resp, err := c.HTTP01ChallengeResponse(ch.Token)
				require.NoError(t, err)
				st.put(c.HTTP01ChallengePath(ch.Token), resp)
				got, err := c.Accept(ctx(t), ch)
				require.NoError(t, err)
				return got
			}
		}
		t.Fatal("no http-01 challenge")
		return nil
	}

	got := accept("unmapped.example.test")
	assert.Equal(t, acme.StatusInvalid, got.Status)
	require.NotNil(t, got.Error)
	assert.Equal(t, "urn:ietf:params:acme:error:connection", problemOf(t, got.Error).ProblemType)
	assert.Zero(t, s.Counters()["http-01-dials"], "nothing was dialled")

	// A name explicitly mapped to the metadata address is the admin's own decision; unmapped, it is never reached.
	got = accept("metadata.example.test")
	assert.Equal(t, acme.StatusInvalid, got.Status)
	assert.Zero(t, s.Counters()["http-01-dials"])

	s.SetHTTPTarget("mapped.example.test", st.addr())
	got = accept("mapped.example.test")
	assert.Equal(t, acme.StatusValid, got.Status)
	assert.Equal(t, 1, s.Counters()["http-01-dials"])
}

func TestMalformedJWSStatuses(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	dir, err := c.Discover(ctx(t))
	require.NoError(t, err)
	status, doc := rawPost(t, s, dir.OrderURL, "application/jose+json", signedBody(t, c, dir.OrderURL+"/x", nonceOf(t, s), `{}`))
	assert.Equal(t, 400, status, doc)
}

// POST-as-GET needs an empty payload; a challenge POST needs {}.
func TestPostAsGetAndChallengePayloads(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	o, err := c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	require.NoError(t, err)
	az, err := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
	require.NoError(t, err)
	chURL := az.Challenges[0].URI
	certURL := s.BaseURL() + "/acme/cert/x"

	for _, u := range []string{o.URI, o.AuthzURLs[0], certURL} {
		status, doc := rawPost(t, s, u, "application/jose+json", signedBody(t, c, u, nonceOf(t, s), `{"x":1}`))
		assert.Equal(t, http.StatusBadRequest, status, u)
		assert.Equal(t, "urn:ietf:params:acme:error:malformed", doc["type"], u)
		status, _ = rawPost(t, s, u, "application/jose+json", signedBody(t, c, u, nonceOf(t, s), ``))
		assert.NotEqual(t, http.StatusBadRequest, status, "an empty payload is accepted: %s", u)
	}
	for _, body := range []string{``, `{"a":1}`, `[]`, `nope`} {
		status, doc := rawPost(t, s, chURL, "application/jose+json", signedBody(t, c, chURL, nonceOf(t, s), body))
		assert.Equal(t, http.StatusBadRequest, status, body)
		assert.Equal(t, "urn:ietf:params:acme:error:malformed", doc["type"], body)
	}
	status, _ := rawPost(t, s, chURL, "application/jose+json", signedBody(t, c, chURL, nonceOf(t, s), `{}`))
	assert.Equal(t, http.StatusOK, status)
}
