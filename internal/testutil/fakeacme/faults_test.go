package fakeacme

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

func TestBadNonceOnceIsRetriedByTheLibrary(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	require.NoError(t, s.AddFault(Fault{Endpoint: "new-order", Kind: FaultBadNonce, Times: 1}))
	s.ClearRequests()
	_, err := c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	require.NoError(t, err)
	assert.Equal(t, 2, s.Counters()["new-order"], "one refused, one served")
	// The fault is spent.
	_, err = c.AuthorizeOrder(ctx(t), idents("b.example.test"))
	require.NoError(t, err)
	assert.Equal(t, 3, s.Counters()["new-order"])
}

func TestBadNonceIsReallyChecked(t *testing.T) {
	// A replayed JWS is refused as badNonce even without a fault: the nonce is single use.
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	dir, err := c.Discover(ctx(t))
	require.NoError(t, err)
	body := signedBody(t, c, dir.OrderURL, nonceOf(t, s), `{"identifiers":[{"type":"dns","value":"a.example.test"}]}`)
	for i, want := range []int{201, 400} {
		status, doc := rawPost(t, s, dir.OrderURL, "application/jose+json", body)
		assert.Equal(t, want, status, i)
		if want == 400 {
			assert.Equal(t, "urn:ietf:params:acme:error:badNonce", doc["type"])
		}
	}
}

func TestRateLimitedSurfacesWithRetryAfter(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	c.RetryBackoff = noRateRetry
	register(t, c)
	require.NoError(t, s.AddFault(Fault{Endpoint: "new-order", Kind: FaultRateLimited, RetryAfter: 120 * time.Second, Times: 1}))
	_, err := c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	ae := problemOf(t, err)
	assert.Equal(t, 429, ae.StatusCode)
	assert.Equal(t, "urn:ietf:params:acme:error:rateLimited", ae.ProblemType)
	d, ok := acme.RateLimit(err)
	assert.True(t, ok)
	assert.Equal(t, 120*time.Second, d)
	assert.Equal(t, "120", ae.Header.Get("Retry-After"))
	assert.Equal(t, 1, s.Counters()["new-order"], "the library did not retry")
	_, err = c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	assert.NoError(t, err)
}

func TestServerInternalOnceIsRetried(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	require.NoError(t, s.AddFault(Fault{Endpoint: "new-order", Kind: FaultServerInternal, Times: 1}))
	_, err := c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	require.NoError(t, err)
	assert.Equal(t, 2, s.Counters()["new-order"])

	// Without retries the error is the 500 problem.
	c.RetryBackoff = func(int, *http.Request, *http.Response) time.Duration { return 0 }
	require.NoError(t, s.AddFault(Fault{Endpoint: "*", Kind: FaultServerInternal}))
	_, err = c.AuthorizeOrder(ctx(t), idents("b.example.test"))
	assert.Equal(t, 500, problemOf(t, err).StatusCode)
	s.ClearFaults()
	_, err = c.AuthorizeOrder(ctx(t), idents("b.example.test"))
	assert.NoError(t, err)
}

func TestSlowAndGiantFaults(t *testing.T) {
	s := start(t, Options{})
	require.NoError(t, s.AddFault(Fault{Endpoint: "directory", Kind: FaultSlow, Delay: 150 * time.Millisecond, Times: 1}))
	begin := time.Now()
	getJSON(t, s, s.DirectoryURL(), nil)
	assert.GreaterOrEqual(t, time.Since(begin), 150*time.Millisecond)
	begin = time.Now()
	getJSON(t, s, s.DirectoryURL(), nil)
	assert.Less(t, time.Since(begin), 150*time.Millisecond)

	require.NoError(t, s.AddFault(Fault{Endpoint: "directory", Kind: FaultGiant, Times: 1}))
	resp, err := s.HTTPClient().Get(s.DirectoryURL()) //nolint:noctx // test
	require.NoError(t, err)
	n, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Greater(t, n, int64(1<<20), "over the 1 MiB cap Alice's transport enforces")
}

func TestFaultValidation(t *testing.T) {
	s := start(t, Options{})
	for _, f := range []Fault{
		{Endpoint: "nope", Kind: FaultSlow, Delay: time.Second},
		{Endpoint: "*", Kind: "explode"},
		{Endpoint: "*", Kind: FaultSlow},
		{Endpoint: "*", Kind: FaultRateLimited, Times: -1},
		{Endpoint: "*", Kind: FaultRateLimited, RetryAfter: 48 * time.Hour},
	} {
		assert.Error(t, s.AddFault(f), "%+v", f)
	}
}

func TestBadNonceFaultSkipsGETs(t *testing.T) {
	s := start(t, Options{})
	require.NoError(t, s.AddFault(Fault{Endpoint: "*", Kind: FaultBadNonce, Times: 1}))
	resp := getJSON(t, s, s.DirectoryURL(), nil)
	assert.Equal(t, 200, resp.StatusCode, "a GET has no nonce to be bad")
	assert.Len(t, s.st.faults, 1, "and the fault is still armed")
}

func TestAdvertisedURLs(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	require.NoError(t, s.Advertise("newOrder", "http://example.test/new-order"))
	require.NoError(t, s.Advertise("keyChange", "https://169.254.169.254/latest"))
	require.NoError(t, s.Advertise("renewalInfo", "off"))
	var d map[string]any
	getJSON(t, s, s.DirectoryURL(), &d)
	assert.Equal(t, "http://example.test/new-order", d["newOrder"])
	assert.Equal(t, "https://169.254.169.254/latest", d["keyChange"])
	assert.NotContains(t, d, "renewalInfo")
	require.NoError(t, s.Advertise("newOrder", ""))
	require.NoError(t, s.Advertise("keyChange", ""))
	require.NoError(t, s.Advertise("renewalInfo", ""))

	// URLs inside an order.
	for field, url := range map[string]string{"authz": "http://evil.test/authz", "finalize": "http://169.254.169.254/f", "order": "http://evil.test/o"} {
		require.NoError(t, s.Advertise(field, url))
	}
	o, err := c.AuthorizeOrder(ctx(t), idents("a.example.test"))
	require.NoError(t, err)
	assert.Equal(t, "http://evil.test/authz", o.AuthzURLs[0])
	assert.Equal(t, "http://169.254.169.254/f", o.FinalizeURL)
	assert.Equal(t, "http://evil.test/o", o.URI)
	require.Error(t, s.Advertise("bogus", "x"))
}

func TestResetClearsStateKeepsCredentials(t *testing.T) {
	s := start(t, Options{RequireEAB: true})
	cred := s.Credentials()
	s.SetExternalAccountRequired(false)
	c := newClient(t, s)
	register(t, c)
	s.DNSSet("_acme-challenge.x.test", "v")
	s.SetHTTPTarget("x.test", "127.0.0.1:1")
	s.RejectIdentifier("bad.test")
	require.NoError(t, s.AddFault(Fault{Endpoint: "*", Kind: FaultServerInternal}))
	require.NoError(t, s.Advertise("newOrder", "http://x"))
	s.SetStuckPending(true)
	s.SetClock(time.Now().Add(time.Hour))

	s.Reset()
	assert.Equal(t, cred, s.Credentials())
	assert.Empty(t, s.DNSRecords())
	assert.Empty(t, s.Requests())
	assert.Equal(t, 0, s.Counters()["requests"])
	var d map[string]any
	getJSON(t, s, s.DirectoryURL(), &d)
	assert.Equal(t, true, d["meta"].(map[string]any)["externalAccountRequired"], "the Options are back")
	assert.WithinDuration(t, time.Now(), s.Now(), 5*time.Second)
	_, err := c.GetReg(ctx(t), "")
	assert.ErrorIs(t, err, acme.ErrNoAccount)
}

func TestCountersShowTheCAWasNotContacted(t *testing.T) {
	s := start(t, Options{})
	assert.Zero(t, s.Counters()["requests"])
	getJSON(t, s, s.DirectoryURL(), nil)
	assert.Equal(t, 1, s.Counters()["requests"])
	assert.Equal(t, 1, s.Counters()["directory"])
	getJSON(t, s, s.BaseURL()+"/nothing", nil)
	assert.Equal(t, 2, s.Counters()["requests"])
}

func TestRequestLogHasNoBodies(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	log := s.Requests()
	require.NotEmpty(t, log)
	for _, e := range log {
		assert.NotEmpty(t, e.Method)
		assert.NotContains(t, e.Path, "?")
		assert.NotZero(t, e.Status)
	}
	assert.Equal(t, "POST", log[len(log)-1].Method)
	assert.Equal(t, "/acme/new-acct", log[len(log)-1].Path)
	assert.Equal(t, 201, log[len(log)-1].Status)
}
