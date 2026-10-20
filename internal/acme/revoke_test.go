package acme

import (
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver"
	"alice/internal/testutil/fakeacme"
)

// issued orders a certificate for name with a fresh key and returns its leaf DER.
func issued(t *testing.T, s *fakeacme.Server, c *Client, name string) []byte {
	t.Helper()
	ws := newWebSolver(t, s, solver.DNS01)
	csr, _ := csrFor(t, name)
	chain, err := c.Order(testCtx(t), []string{name}, csr, ws)
	require.NoError(t, err)
	return chain[0]
}

func serialOf(t *testing.T, der []byte) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf.SerialNumber.Text(16)
}

func TestRevocationReasons(t *testing.T) {
	assert.Equal(t, []string{"unspecified", "keyCompromise", "affiliationChanged", "superseded", "cessationOfOperation"}, RevocationReasonNames())
	for _, n := range RevocationReasonNames() {
		r, ok := ParseRevocationReason(n)
		require.True(t, ok, n)
		assert.Equal(t, n, r.String())
		assert.True(t, r.Valid())
	}
	for _, n := range []string{"", "keycompromise", "cACompromise", "certificateHold", "removeFromCRL"} {
		_, ok := ParseRevocationReason(n)
		assert.False(t, ok, n)
	}
	assert.Equal(t, RevocationReason(1), RevokeKeyCompromise)
	assert.Equal(t, RevocationReason(5), RevokeCessationOfOperation)
	assert.False(t, RevocationReason(2).Valid())
}

func TestDiscoverRevokeCert(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	d, err := newTestClient(t, s).Discover(testCtx(t))
	require.NoError(t, err)
	assert.True(t, d.SupportsRevocation())
	assert.Equal(t, s.BaseURL()+"/acme/revoke-cert", d.RevokeCert)

	d, err = ParseDirectory([]byte(`{"newNonce":"https://a/n","newAccount":"https://a/a","newOrder":"https://a/o","revokeCert":"http://a/r"}`))
	require.NoError(t, err)
	assert.False(t, d.SupportsRevocation(), "an http revokeCert is dropped")
}

func TestRevoke(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	der := issued(t, s, c, "rv.example.test")

	require.NoError(t, c.Revoke(testCtx(t), der, RevokeKeyCompromise))
	st, ok := s.CertificateStatus(serialOf(t, der))
	require.True(t, ok)
	assert.Equal(t, "revoked", st.Status)
	assert.Equal(t, 1, st.Reason)

	// alreadyRevoked is the end state asked for.
	require.NoError(t, c.Revoke(testCtx(t), der, RevokeSuperseded))
	st, _ = s.CertificateStatus(serialOf(t, der))
	assert.Equal(t, 1, st.Reason, "the first reason stays")
}

func TestRevokeRefusals(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	owner := registered(t, s)
	der := issued(t, s, owner, "rr.example.test")

	// Another account did not order it.
	other := registered(t, s)
	e := reasonErr(t, other.Revoke(testCtx(t), der, RevokeUnspecified), ReasonRevokeUnauthorized)
	assert.Equal(t, http.StatusForbidden, e.Status)
	assert.Equal(t, ClassPermanent, FailureClass(e))

	// A reason Alice does not send: refused before any request.
	n := s.Counters()["requests"]
	requireReason(t, owner.Revoke(testCtx(t), der, RevocationReason(2)), ReasonRevokeReasonRefused)
	requireReason(t, owner.Revoke(testCtx(t), der, RevocationReason(6)), ReasonRevokeReasonRefused)
	assert.Equal(t, n, s.Counters()["requests"])

	// A certificate the CA never issued.
	elsewhere := startFake(t, fakeacme.Options{})
	foreign := issued(t, elsewhere, registered(t, elsewhere), "f.example.test")
	e = reasonErr(t, owner.Revoke(testCtx(t), foreign, RevokeUnspecified), ReasonRevokeUnauthorized)
	assert.Equal(t, http.StatusNotFound, e.Status)

	// No key, no certificate.
	requireReason(t, newTestClient(t, s, func(c *Config) { c.Key = nil }).Revoke(testCtx(t), der, RevokeUnspecified), ReasonAccountRejected)
	requireReason(t, owner.Revoke(testCtx(t), nil, RevokeUnspecified), ReasonRevokeUnauthorized)

	st, _ := s.CertificateStatus(serialOf(t, der))
	assert.Equal(t, "valid", st.Status)
}

func TestRevokeUnsupportedSendsNothing(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	der := issued(t, s, c, "ru.example.test")
	require.NoError(t, s.Advertise("revokeCert", "off"))
	c2 := newTestClient(t, s, func(cfg *Config) { cfg.Key = c.cfg.Key; cfg.AccountURL = c.AccountURL() })
	n := s.Counters()["revoke-cert"]
	requireReason(t, c2.Revoke(testCtx(t), der, RevokeUnspecified), ReasonRevokeUnsupported)
	assert.Equal(t, n, s.Counters()["revoke-cert"])
}

func TestRevokeOutagesAreTransient(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	der := issued(t, s, c, "ro.example.test")

	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "revoke-cert", Kind: fakeacme.FaultServerInternal, Times: 1}))
	e := reasonErr(t, c.Revoke(testCtx(t), der, RevokeKeyCompromise), ReasonProviderUnreachable)
	assert.Equal(t, ClassTransient, FailureClass(e))

	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "revoke-cert", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: 60e9}))
	e = reasonErr(t, c.Revoke(testCtx(t), der, RevokeKeyCompromise), ReasonCARateLimited)
	assert.Equal(t, ClassTransient, FailureClass(e))

	st, _ := s.CertificateStatus(serialOf(t, der))
	assert.Equal(t, "valid", st.Status)
	require.NoError(t, c.Revoke(testCtx(t), der, RevokeKeyCompromise))
}

func TestRevokeErrorCarriesNoCAText(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	owner := registered(t, s)
	der := issued(t, s, owner, "rt.example.test")
	err := registered(t, s).Revoke(testCtx(t), der, RevokeUnspecified)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "requester", "the CA's detail is not kept")
	assert.NotContains(t, err.Error(), s.BaseURL())
}
