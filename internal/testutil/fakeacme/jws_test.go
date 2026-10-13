package fakeacme

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

func rawPost(t *testing.T, s *Server, url, contentType string, body []byte) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx(t), http.MethodPost, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	resp, err := s.HTTPClient().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &doc), string(b))
	return resp.StatusCode, doc
}

func TestJWSIsVerified(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	dir, err := c.Discover(ctx(t))
	require.NoError(t, err)
	good := func() []byte {
		return signedBody(t, c, dir.OrderURL, nonceOf(t, s), `{"identifiers":[{"type":"dns","value":"a.example.test"}]}`)
	}

	status, _ := rawPost(t, s, dir.OrderURL, "application/jose+json", good())
	assert.Equal(t, 201, status)

	// Wrong content type.
	status, doc := rawPost(t, s, dir.OrderURL, "application/json", good())
	assert.Equal(t, 415, status)
	assert.Equal(t, "urn:ietf:params:acme:error:malformed", doc["type"])

	// Not a JWS, not JSON.
	status, _ = rawPost(t, s, dir.OrderURL, "application/jose+json", []byte(`{}`))
	assert.Equal(t, 400, status)
	status, _ = rawPost(t, s, dir.OrderURL, "application/jose+json", []byte(`nope`))
	assert.Equal(t, 400, status)

	// A tampered payload breaks the signature.
	var j map[string]string
	require.NoError(t, json.Unmarshal(good(), &j))
	j["payload"] = base64.RawURLEncoding.EncodeToString([]byte(`{"identifiers":[{"type":"dns","value":"evil.example.test"}]}`))
	tampered, _ := json.Marshal(j)
	status, _ = rawPost(t, s, dir.OrderURL, "application/jose+json", tampered)
	assert.Equal(t, 400, status)

	// The signed url must be the request url.
	status, doc = rawPost(t, s, dir.OrderURL+"x", "application/jose+json", good())
	assert.Contains(t, []int{401, 404}, status)
	_ = doc
	other := signedBody(t, c, s.BaseURL()+"/acme/other", nonceOf(t, s), `{}`)
	status, doc = rawPost(t, s, dir.OrderURL, "application/jose+json", other)
	assert.Equal(t, 400, status)
	assert.Contains(t, doc["detail"], "url")

	// An unknown account key id.
	j = map[string]string{}
	require.NoError(t, json.Unmarshal(good(), &j))
	hdr, _ := base64.RawURLEncoding.DecodeString(j["protected"])
	j["protected"] = base64.RawURLEncoding.EncodeToString(bytes.Replace(hdr, []byte("/acme/acct/"), []byte("/acme/acct/zz"), 1))
	unknown, _ := json.Marshal(j)
	status, doc = rawPost(t, s, dir.OrderURL, "application/jose+json", unknown)
	assert.Equal(t, 400, status)
	assert.Equal(t, "urn:ietf:params:acme:error:accountDoesNotExist", doc["type"])
}

func TestJWKAndKIDAreNotInterchangeable(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	dir, err := c.Discover(ctx(t))
	require.NoError(t, err)
	// newAccount with a kid, newOrder with a jwk.
	body := signedBody(t, c, dir.RegURL, nonceOf(t, s), `{"onlyReturnExisting":true}`)
	status, doc := rawPost(t, s, dir.RegURL, "application/jose+json", body)
	assert.Equal(t, 400, status, doc)
	fresh := &acme.Client{Key: testKey(t), DirectoryURL: s.DirectoryURL(), HTTPClient: s.HTTPClient(), RetryBackoff: fastRetry}
	_, err = fresh.AuthorizeOrder(ctx(t), idents("a.example.test"))
	assert.Error(t, err, "an unregistered key cannot order")
}

func TestRSAAccountKeys(t *testing.T) {
	s := start(t, Options{})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	c := &acme.Client{Key: key, DirectoryURL: s.DirectoryURL(), HTTPClient: s.HTTPClient(), RetryBackoff: fastRetry}
	register(t, c)
	der, _ := issue(t, s, c, nil, DNS01, "rsa.example.test")
	assert.Len(t, der, 2)
	// A small RSA key is refused at registration.
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	c2 := &acme.Client{Key: small, DirectoryURL: s.DirectoryURL(), HTTPClient: s.HTTPClient(), RetryBackoff: fastRetry}
	_, err = c2.Register(ctx(t), &acme.Account{}, acme.AcceptTOS)
	assert.Error(t, err)
}

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"a.test", "*.a.test", "x-y.a1.example.test"} {
		_, _, err := checkName(ok)
		assert.NoError(t, err, ok)
	}
	for _, bad := range []string{"", "a", "A.test", "*.", "*.*.a.test", "a.test.", strings.Repeat("a", 64) + ".test", "a b.test"} {
		_, _, err := checkName(bad)
		assert.Error(t, err, bad)
	}
}

func TestParseJWKRejectsBadKeys(t *testing.T) {
	for _, raw := range []string{`nope`, `{"kty":"oct"}`, `{"kty":"EC","crv":"P-1","x":"AA","y":"AA"}`,
		`{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}`, `{"kty":"EC","crv":"P-256","x":"!","y":"AQ"}`,
		`{"kty":"RSA","n":"AQ","e":"AQAB"}`, `{"kty":"RSA","n":"!","e":"AQAB"}`} {
		_, err := parseJWK([]byte(raw))
		assert.Error(t, err, raw)
	}
}
