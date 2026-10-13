package fakeacme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func start(t *testing.T, opts Options) *Server {
	t.Helper()
	s, err := New(opts)
	require.NoError(t, err)
	require.NoError(t, s.Start())
	t.Cleanup(s.Close)
	return s
}

func fastRetry(int, *http.Request, *http.Response) time.Duration { return time.Millisecond }

// noRateRetry is the backoff of Alice's client (plan A7): never sleep on a rate limit.
func noRateRetry(_ int, _ *http.Request, res *http.Response) time.Duration {
	if res != nil && res.StatusCode == http.StatusTooManyRequests {
		return 0
	}
	return time.Millisecond
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func newClient(t *testing.T, s *Server) *acme.Client {
	t.Helper()
	return &acme.Client{Key: testKey(t), DirectoryURL: s.DirectoryURL(), HTTPClient: s.HTTPClient(), RetryBackoff: fastRetry}
}

func register(t *testing.T, c *acme.Client) *acme.Account {
	t.Helper()
	a, err := c.Register(ctx(t), &acme.Account{Contact: []string{"mailto:admin@example.test"}}, acme.AcceptTOS)
	require.NoError(t, err)
	return a
}

func problemOf(t *testing.T, err error) *acme.Error {
	t.Helper()
	var ae *acme.Error
	require.ErrorAs(t, err, &ae)
	return ae
}

// stub is an HTTP-01 target: a web server that serves the key authorizations it is given.
type stub struct {
	srv *httptest.Server
	mu  sync.Mutex
	m   map[string]string
}

func newStub(t *testing.T) *stub {
	t.Helper()
	st := &stub{m: map[string]string{}}
	st.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		body, ok := st.m[r.URL.Path]
		st.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(st.srv.Close)
	return st
}

func (st *stub) put(path, body string) {
	st.mu.Lock()
	st.m[path] = body
	st.mu.Unlock()
}

func (st *stub) addr() string { return st.srv.Listener.Addr().String() }

// solve answers every pending authorization of o with a challenge of type typ and waits for it.
func solve(t *testing.T, s *Server, c *acme.Client, st *stub, o *acme.Order, typ string) {
	t.Helper()
	for _, u := range o.AuthzURLs {
		az, err := c.GetAuthorization(ctx(t), u)
		require.NoError(t, err)
		var ch *acme.Challenge
		for _, x := range az.Challenges {
			if x.Type == typ {
				ch = x
			}
		}
		require.NotNil(t, ch, "no %s challenge for %s", typ, az.Identifier.Value)
		switch typ {
		case HTTP01:
			resp, err := c.HTTP01ChallengeResponse(ch.Token)
			require.NoError(t, err)
			st.put(c.HTTP01ChallengePath(ch.Token), resp)
			s.SetHTTPTarget(az.Identifier.Value, st.addr())
		case DNS01:
			rec, err := c.DNS01ChallengeRecord(ch.Token)
			require.NoError(t, err)
			s.DNSSet("_acme-challenge."+az.Identifier.Value, rec)
		}
		_, err = c.Accept(ctx(t), ch)
		require.NoError(t, err)
		got, err := c.WaitAuthorization(ctx(t), az.URI)
		require.NoError(t, err)
		assert.Equal(t, acme.StatusValid, got.Status)
	}
}

func idents(names ...string) []acme.AuthzID {
	out := make([]acme.AuthzID, len(names))
	for i, n := range names {
		out[i] = acme.AuthzID{Type: "dns", Value: n}
	}
	return out
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey, names ...string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, key)
	require.NoError(t, err)
	return der
}

// issue runs a whole order and returns the DER chain.
func issue(t *testing.T, s *Server, c *acme.Client, st *stub, typ string, names ...string) ([][]byte, *acme.Order) {
	t.Helper()
	o, err := c.AuthorizeOrder(ctx(t), idents(names...))
	require.NoError(t, err)
	solve(t, s, c, st, o, typ)
	o, err = c.WaitOrder(ctx(t), o.URI)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusReady, o.Status)
	der, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csrFor(t, testKey(t), names...), true)
	require.NoError(t, err)
	return der, o
}

// reply is what a test needs of a response whose body getJSON has read and closed.
type reply struct {
	StatusCode int
	Header     http.Header
}

func getJSON(t *testing.T, s *Server, url string, v any) reply {
	t.Helper()
	resp, err := s.HTTPClient().Get(url) //nolint:noctx // test helper against the fake
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if v != nil {
		require.NoError(t, json.Unmarshal(b, v), string(b))
	}
	return reply{StatusCode: resp.StatusCode, Header: resp.Header}
}

func contains2(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}

func decodeB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func parseLeaf(t *testing.T, der [][]byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der[0])
	require.NoError(t, err)
	return c
}

func nonceOf(t *testing.T, s *Server) string {
	t.Helper()
	resp, err := s.HTTPClient().Head(s.BaseURL() + "/acme/new-nonce") //nolint:noctx // test
	require.NoError(t, err)
	_ = resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	require.NotEmpty(t, n)
	return n
}

// signedBody builds a JWS in KID form the way the library does, for tests that replay a request.
func signedBody(t *testing.T, c *acme.Client, url, nonce, payload string) []byte {
	t.Helper()
	a, err := c.GetReg(ctx(t), "")
	require.NoError(t, err)
	hdr := `{"alg":"ES256","kid":"` + a.URI + `","nonce":"` + nonce + `","url":"` + url + `"}`
	protected := base64.RawURLEncoding.EncodeToString([]byte(hdr))
	pl := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sum := sha256.Sum256([]byte(protected + "." + pl))
	r, ss, err := ecdsa.Sign(rand.Reader, c.Key.(*ecdsa.PrivateKey), sum[:])
	require.NoError(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	b, err := json.Marshal(map[string]string{"protected": protected, "payload": pl, "signature": base64.RawURLEncoding.EncodeToString(sig)})
	require.NoError(t, err)
	return b
}

// newStubFunc serves handler on a loopback port and returns its address.
func newStubFunc(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}
