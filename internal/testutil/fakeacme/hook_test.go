package fakeacme

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

func sign(secret, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return hex.EncodeToString(m.Sum(nil))
}

// callHook posts to the hook like Alice's solver will: bearer token and HMAC of the exact body.
func callHook(t *testing.T, s *Server, method, body, bearer, sig string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx(t), method, s.Credentials().HookURL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if sig != "" {
		req.Header.Set("X-Alice-Signature", sig)
	}
	resp, err := s.HTTPClient().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestHookPresentCleanupAndDNS01Validation(t *testing.T) {
	s := start(t, Options{})
	secret := s.Credentials().HookSecret
	c := newClient(t, s)
	register(t, c)
	o, err := c.AuthorizeOrder(ctx(t), idents("hook.example.test"))
	require.NoError(t, err)
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

	// Present through the hook, with a trailing dot and upper case, signed with the "sha256=" form.
	body := `{"action":"present","fqdn":"_ACME-challenge.hook.example.test.","value":"` + rec + `","ttl":60}`
	assert.Equal(t, 200, callHook(t, s, http.MethodPost, body, secret, "sha256="+sign(secret, body)))
	assert.Equal(t, []string{rec}, s.DNSRecords()["_acme-challenge.hook.example.test"])

	_, err = c.Accept(ctx(t), ch)
	require.NoError(t, err)
	got, err := c.WaitAuthorization(ctx(t), az.URI)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusValid, got.Status)

	// Cleanup removes that value only.
	s.DNSSet("_acme-challenge.hook.example.test", "other")
	body = `{"action":"cleanup","fqdn":"_acme-challenge.hook.example.test","value":"` + rec + `"}`
	assert.Equal(t, 200, callHook(t, s, http.MethodPost, body, secret, sign(secret, body)))
	assert.Equal(t, []string{"other"}, s.DNSRecords()["_acme-challenge.hook.example.test"])
	body = `{"action":"cleanup","fqdn":"_acme-challenge.hook.example.test"}`
	assert.Equal(t, 200, callHook(t, s, http.MethodPost, body, secret, sign(secret, body)))
	assert.Empty(t, s.DNSRecords())
	cnt := s.Counters()
	assert.Equal(t, 1, cnt["hook-present"])
	assert.Equal(t, 2, cnt["hook-cleanup"])
}

func TestHookRefusals(t *testing.T) {
	s := start(t, Options{})
	secret := s.Credentials().HookSecret
	good := `{"action":"present","fqdn":"_acme-challenge.a.test","value":"v"}`
	cases := []struct {
		name         string
		method, body string
		bearer, sig  string
		want         int
	}{
		{"no bearer", "POST", good, "", sign(secret, good), 401},
		{"wrong bearer", "POST", good, "nope", sign(secret, good), 401},
		{"no signature", "POST", good, secret, "", 401},
		{"wrong signature", "POST", good, secret, sign("other", good), 401},
		{"signature of another body", "POST", good, secret, sign(secret, good+" "), 401},
		{"signature not hex", "POST", good, secret, "zz", 401},
		{"GET", "GET", good, secret, sign(secret, good), 405},
		{"unknown action", "POST", `{"action":"drop","fqdn":"a.test","value":"v"}`, secret, "", 400},
		{"empty fqdn", "POST", `{"action":"present","fqdn":"","value":"v"}`, secret, "", 400},
		{"missing value", "POST", `{"action":"present","fqdn":"a.test"}`, secret, "", 400},
		{"bad ttl", "POST", `{"action":"present","fqdn":"a.test","value":"v","ttl":-1}`, secret, "", 400},
		{"not json", "POST", `nope`, secret, "", 400},
		{"too big", "POST", `{"action":"present","fqdn":"a.test","value":"` + strings.Repeat("x", 5000) + `"}`, secret, "", 413},
	}
	for _, tc := range cases {
		sig := tc.sig
		if sig == "" && tc.want >= 400 && tc.want != 401 {
			sig = sign(secret, tc.body) // a valid signature: the refusal is about the content
		}
		assert.Equal(t, tc.want, callHook(t, s, tc.method, tc.body, tc.bearer, sig), tc.name)
	}
	assert.Empty(t, s.DNSRecords(), "nothing refused changed the table")
	assert.Zero(t, s.Counters()["hook-present"])
}

func TestHookFaultsApply(t *testing.T) {
	s := start(t, Options{})
	secret := s.Credentials().HookSecret
	require.NoError(t, s.AddFault(Fault{Endpoint: "hook", Kind: FaultServerInternal, Times: 1}))
	body := `{"action":"present","fqdn":"a.test","value":"v"}`
	assert.Equal(t, 500, callHook(t, s, "POST", body, secret, sign(secret, body)))
	assert.Equal(t, 200, callHook(t, s, "POST", body, secret, sign(secret, body)))
}

func TestHTTP01ThroughTheMapIgnoresRedirects(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	redir := newStubFunc(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere.test/", http.StatusFound)
	})
	s.SetHTTPTarget("r.example.test", redir)
	o, err := c.AuthorizeOrder(ctx(t), idents("r.example.test"))
	require.NoError(t, err)
	az, err := c.GetAuthorization(ctx(t), o.AuthzURLs[0])
	require.NoError(t, err)
	for _, ch := range az.Challenges {
		if ch.Type == HTTP01 {
			got, err := c.Accept(ctx(t), ch)
			require.NoError(t, err)
			assert.Equal(t, acme.StatusInvalid, got.Status)
		}
	}
	// A bare host in the map means port 80 of that host: here nothing listens, a connection error.
	s.SetHTTPTarget("r.example.test", "")
	assert.NotContains(t, s.st.targets, "r.example.test")
}

func TestHookSecretsAreIndependentOfTime(t *testing.T) {
	a, err := New(Options{})
	require.NoError(t, err)
	b, err := New(Options{})
	require.NoError(t, err)
	assert.NotEqual(t, a.Credentials().HookSecret, b.Credentials().HookSecret)
	assert.NotEqual(t, a.Credentials().EABKID, b.Credentials().EABKID)
	assert.NotEqual(t, a.CAPEM(), b.CAPEM())
	assert.True(t, bytes.Contains(a.CAPEM(), []byte("BEGIN CERTIFICATE")))
}
