package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xacme "golang.org/x/crypto/acme"

	"alice/internal/acme/solver"
	"alice/internal/testutil/fakeacme"
)

// outcomes records what WithReplaces reported.
type outcomes struct{ got []string }

func (o *outcomes) replaces(certID, accountURL string, earlier ...string) OrderOption {
	return WithReplaces(Replaces{CertID: certID, AccountURL: accountURL, Earlier: earlier, OnOutcome: func(out string) error {
		o.got = append(o.got, out)
		return nil
	}})
}

// dnsOrder orders names over DNS-01 with opts and returns the leaf.
func dnsOrder(t *testing.T, s *fakeacme.Server, c *Client, names []string, opts ...OrderOption) *x509.Certificate {
	t.Helper()
	csr, _ := csrFor(t, names...)
	chain, err := c.Order(testCtx(t), names, csr, newWebSolver(t, s, solver.DNS01), opts...)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)
	return leaf
}

// A renewal names its predecessor in newOrder (RFC 9773 section 5): base64url(AKI) "." base64url(serial), as the CA's
// renewalInfo knows it; the fake records it.
func TestOrderSendsReplaces(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	names := []string{"www.example.test", "example.test"}
	old := dnsOrder(t, s, c, names)
	assert.Empty(t, s.Replacements(), "a first order names no predecessor")

	id, err := CertID(old)
	require.NoError(t, err)
	var o outcomes
	var url string
	leaf := dnsOrder(t, s, c, names, o.replaces(id, c.AccountURL()), WithOnOrder(func(u string) error { url = u; return nil }))
	assert.NotEqual(t, old.SerialNumber, leaf.SerialNumber)
	assert.Equal(t, []string{ReplacesSent}, o.got)
	assert.NotEmpty(t, url, "the order's URL is recorded after the outcome")
	rs := s.Replacements()
	require.Len(t, rs, 1)
	assert.Equal(t, id, rs[0].CertID, "the identifier the CA's renewalInfo uses")
}

// The field is not sent when the CA has no renewalInfo or the predecessor was ordered with another account (RFC 9773:
// clients SHOULD NOT send it to a CA without ARI; the CA would refuse another account's certificate).
func TestReplacesNotSent(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	names := []string{"a.example.test"}
	old := dnsOrder(t, s, c, names)
	id, err := CertID(old)
	require.NoError(t, err)

	var o outcomes
	dnsOrder(t, s, c, names, o.replaces(id, "https://elsewhere.example/acct/7"))
	assert.Equal(t, []string{ReplacesOtherAccount}, o.got)

	require.NoError(t, s.Advertise("renewalInfo", "off"))
	c2 := registered(t, s) // a fresh client reads the directory again
	old2 := dnsOrder(t, s, c2, names)
	id2, err := CertID(old2)
	require.NoError(t, err)
	o = outcomes{}
	dnsOrder(t, s, c2, names, o.replaces(id2, c2.AccountURL()))
	assert.Equal(t, []string{ReplacesNoARI}, o.got)
	assert.Empty(t, s.Replacements())

	// No option, or an empty identifier: no field and no outcome.
	o = outcomes{}
	dnsOrder(t, s, c2, names, o.replaces("", ""))
	assert.Empty(t, o.got)
}

// alreadyReplaced (RFC 9773 section 7.4): without an earlier order of Alice's to take over, the order is made again
// once without the field, and the outcome says why.
func TestAlreadyReplacedOrdersAgainWithout(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	names := []string{"a.example.test"}
	old := dnsOrder(t, s, c, names)
	id, err := CertID(old)
	require.NoError(t, err)
	var o outcomes
	dnsOrder(t, s, c, names, o.replaces(id, c.AccountURL()))
	require.Len(t, s.Replacements(), 1)

	before := s.Counters()["new-order"]
	o = outcomes{}
	dnsOrder(t, s, c, names, o.replaces(id, c.AccountURL(), s.BaseURL()+"/acme/order/nope"))
	assert.Equal(t, []string{ReplacesAlreadyReplaced}, o.got)
	assert.Equal(t, before+2, s.Counters()["new-order"], "one refused order, one without the field")
	assert.Len(t, s.Replacements(), 1, "the second order carries no replaces")
}

// alreadyReplaced after a lost answer: the CA still holds Alice's earlier order replacing the certificate (pending or
// ready); it is taken over (adopted) instead of ordering anew, and its URL is what WithOnOrder records.
func TestAlreadyReplacedAdoptsTheEarlierOrder(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	names := []string{"a.example.test", "b.example.test"}
	old := dnsOrder(t, s, c, names)
	id, err := CertID(old)
	require.NoError(t, err)

	// The earlier attempt: the CA created the order (validated, ready) and then the answer was lost.
	var earlier string
	var o outcomes
	require.NoError(t, c.TestOrder(testCtx(t), names, newWebSolver(t, s, solver.DNS01), o.replaces(id, c.AccountURL()),
		WithOnOrder(func(u string) error { earlier = u; return nil })))
	require.NotEmpty(t, earlier)

	o = outcomes{}
	var url string
	issued := s.Counters()["issued"]
	csr, _ := csrFor(t, names...)
	_, err = c.Order(testCtx(t), names, csr, newWebSolver(t, s, solver.DNS01), o.replaces(id, c.AccountURL(), earlier),
		WithOnOrder(func(u string) error { url = u; return nil }))
	require.NoError(t, err)
	assert.Equal(t, []string{ReplacesAdopted}, o.got)
	assert.Equal(t, earlier, url)
	assert.Equal(t, issued+1, s.Counters()["issued"])
	assert.Len(t, s.Replacements(), 1, "no new order replaced it")
}

// An earlier order that cannot be taken over (other names, unknown, already valid) is skipped.
func TestAlreadyReplacedSkipsUnusableEarlierOrders(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	names := []string{"a.example.test", "b.example.test"}
	old := dnsOrder(t, s, c, names)
	id, err := CertID(old)
	require.NoError(t, err)
	var valid string
	dnsOrder(t, s, c, names, WithReplaces(Replaces{CertID: id, AccountURL: c.AccountURL()}), WithOnOrder(func(u string) error { valid = u; return nil }))
	var other string
	require.NoError(t, c.TestOrder(testCtx(t), []string{"c.example.test"}, newWebSolver(t, s, solver.DNS01),
		WithOnOrder(func(u string) error { other = u; return nil })))

	var o outcomes
	dnsOrder(t, s, c, names, o.replaces(id, c.AccountURL(), valid, other, "https://127.0.0.1:1/acme/order/gone"))
	assert.Equal(t, []string{ReplacesAlreadyReplaced}, o.got)
}

// A CA that refuses the field itself (malformed, unauthorized) gets the order once more without it.
func TestRefusedReplacesOrdersAgainWithout(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	names := []string{"a.example.test"}
	dnsOrder(t, s, c, names)
	var o outcomes
	dnsOrder(t, s, c, names, o.replaces("AAAA.BBBB", c.AccountURL()))
	assert.Equal(t, []string{ReplacesRefused}, o.got)

	other := registered(t, s)
	theirs := dnsOrder(t, s, other, names)
	id, err := CertID(theirs)
	require.NoError(t, err)
	o = outcomes{}
	dnsOrder(t, s, c, names, o.replaces(id, "")) // the predecessor's account unknown: sent, refused, ordered without
	assert.Equal(t, []string{ReplacesRefused}, o.got)
	assert.Empty(t, s.Replacements())
}

// Other refusals of an order with the field are the order's failure, classified as usual (the field is not retried).
func TestReplacesOrderFailuresAreClassified(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	names := []string{"a.example.test"}
	old := dnsOrder(t, s, c, names)
	id, err := CertID(old)
	require.NoError(t, err)
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: "rateLimited", Times: 1, RetryAfter: time.Minute}))
	var o outcomes
	csr, _ := csrFor(t, names...)
	_, err = c.Order(testCtx(t), names, csr, newWebSolver(t, s, solver.DNS01), o.replaces(id, c.AccountURL()))
	require.Error(t, err)
	assert.Equal(t, ReasonCARateLimited, ReasonOf(err))
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Positive(t, e.RetryAfter())
	assert.Empty(t, o.got, "no order, no outcome")

	// badNonce is retried with the CA's fresh nonce, as the library does.
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: "badNonce", Times: 2}))
	o = outcomes{}
	dnsOrder(t, s, c, names, o.replaces(id, c.AccountURL()))
	assert.Equal(t, []string{ReplacesSent}, o.got)
}

// The hand-written newOrder signs with every account key type Alice creates.
func TestReplacesWithRSAAccountKey(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s, func(cfg *Config) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		cfg.Key = k
	})
	names := []string{"rsa.example.test"}
	old := dnsOrder(t, s, c, names)
	id, err := CertID(old)
	require.NoError(t, err)
	var o outcomes
	dnsOrder(t, s, c, names, o.replaces(id, c.AccountURL()))
	assert.Equal(t, []string{ReplacesSent}, o.got)
}

// alreadyReplaced reaching the caller (a CA that says it to an order without the field) has its own reason and is
// transient: the order that replaces the certificate at the CA expires there by itself.
func TestAlreadyReplacedIsClassified(t *testing.T) {
	c := &Client{cfg: Config{Now: time.Now}}
	err := c.classify(&xacme.Error{StatusCode: http.StatusConflict, ProblemType: ProblemPrefix + "alreadyReplaced"}, opOrder, "", "")
	assert.Equal(t, ReasonAlreadyReplaced, ReasonOf(err))
	assert.Equal(t, ClassTransient, FailureClass(err))
	assert.Contains(t, Reasons(), ReasonAlreadyReplaced)
}
