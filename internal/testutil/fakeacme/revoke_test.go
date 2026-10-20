package fakeacme

import (
	"crypto/ecdsa"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

// issueWithKey runs a whole order with a CSR of key and returns the DER chain.
func issueWithKey(t *testing.T, s *Server, c *acme.Client, key *ecdsa.PrivateKey, names ...string) [][]byte {
	t.Helper()
	o, err := c.AuthorizeOrder(ctx(t), idents(names...))
	require.NoError(t, err)
	solve(t, s, c, nil, o, DNS01)
	o, err = c.WaitOrder(ctx(t), o.URI)
	require.NoError(t, err)
	der, _, err := c.CreateOrderCert(ctx(t), o.FinalizeURL, csrFor(t, key, names...), true)
	require.NoError(t, err)
	return der
}

func TestRevokeWithTheOrderingAccount(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	der, _ := issue(t, s, c, nil, DNS01, "a.example.test")
	leaf := parseLeaf(t, der)

	st, ok := s.CertificateStatus(leaf.SerialNumber.Text(16))
	require.True(t, ok)
	assert.Equal(t, "valid", st.Status)

	require.NoError(t, c.RevokeCert(ctx(t), nil, der[0], acme.CRLReasonKeyCompromise))
	st, ok = s.CertificateStatus(leaf.SerialNumber.Text(16))
	require.True(t, ok)
	assert.Equal(t, "revoked", st.Status)
	assert.Equal(t, 1, st.Reason)
	assert.False(t, st.RevokedAt.IsZero())
	assert.Equal(t, 1, s.Counters()["revoked"])

	// A second revocation is alreadyRevoked (400); the library treats it as done, the raw answer says so.
	require.NoError(t, c.RevokeCert(ctx(t), nil, der[0], acme.CRLReasonSuperseded))
	assert.Equal(t, 1, s.Counters()["revoked"], "the first reason stays")
	st, _ = s.CertificateStatus(leaf.SerialNumber.Text(16))
	assert.Equal(t, 1, st.Reason)
	assert.Contains(t, s.Requests()[len(s.Requests())-1].Path, "/acme/revoke-cert")
	assert.Equal(t, http.StatusBadRequest, s.Requests()[len(s.Requests())-1].Status)
}

func TestRevokeWithTheCertificateKey(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	key := testKey(t)
	der := issueWithKey(t, s, c, key, "k.example.test")

	// jwk form: signed by the certificate's own key, no account involved.
	other := &acme.Client{Key: testKey(t), DirectoryURL: s.DirectoryURL(), HTTPClient: s.HTTPClient(), RetryBackoff: fastRetry}
	err := other.RevokeCert(ctx(t), testKey(t), der[0], acme.CRLReasonKeyCompromise)
	assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", problemOf(t, err).ProblemType, "a key that is not the certificate's")
	require.NoError(t, other.RevokeCert(ctx(t), key, der[0], acme.CRLReasonKeyCompromise))
	st, _ := s.CertificateStatus(parseLeaf(t, der).SerialNumber.Text(16))
	assert.Equal(t, "revoked", st.Status)
}

func TestRevokeRefusals(t *testing.T) {
	s := start(t, Options{})
	owner := newClient(t, s)
	register(t, owner)
	der, _ := issue(t, s, owner, nil, DNS01, "r.example.test")

	// Another account may not revoke it.
	stranger := newClient(t, s)
	register(t, stranger)
	err := stranger.RevokeCert(ctx(t), nil, der[0], acme.CRLReasonUnspecified)
	p := problemOf(t, err)
	assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", p.ProblemType)
	assert.Equal(t, http.StatusForbidden, p.StatusCode)

	// A reason the CA does not accept (RFC 5280 certificateHold 6, removeFromCRL 8, cACompromise 2, an unknown 7).
	for _, r := range []acme.CRLReasonCode{acme.CRLReasonCACompromise, acme.CRLReasonCertificateHold, 7, acme.CRLReasonRemoveFromCRL,
		acme.CRLReasonPrivilegeWithdrawn, acme.CRLReasonAACompromise} {
		err = owner.RevokeCert(ctx(t), nil, der[0], r)
		assert.Equal(t, "urn:ietf:params:acme:error:badRevocationReason", problemOf(t, err).ProblemType, "reason %d", r)
	}

	// A certificate the CA never issued.
	other := issueElsewhere(t)
	err = owner.RevokeCert(ctx(t), nil, other, acme.CRLReasonUnspecified)
	assert.Equal(t, http.StatusNotFound, problemOf(t, err).StatusCode)

	st, _ := s.CertificateStatus(parseLeaf(t, der).SerialNumber.Text(16))
	assert.Equal(t, "valid", st.Status, "nothing was revoked")
	assert.Zero(t, s.Counters()["revoked"])

	_, ok := s.CertificateStatus("00")
	assert.False(t, ok)
}

// issueElsewhere is a leaf of another fake CA.
func issueElsewhere(t *testing.T) []byte {
	t.Helper()
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	der, _ := issue(t, s, c, nil, DNS01, "x.example.test")
	return der[0]
}

func TestRevocationStatusThroughTheAdminAPI(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	der, _ := issue(t, s, c, nil, DNS01, "adm.example.test")
	serial := parseLeaf(t, der).SerialNumber.Text(16)
	require.NoError(t, c.RevokeCert(ctx(t), nil, der[0], acme.CRLReasonCessationOfOperation))

	out, aerr := s.adminCertificate(func(k string) string { return map[string]string{"serial": serial}[k] })
	require.Nil(t, aerr)
	st := out.(CertStatus)
	assert.Equal(t, "revoked", st.Status)
	assert.Equal(t, 5, st.Reason)
	_, aerr = s.adminCertificate(func(string) string { return "zz" })
	require.NotNil(t, aerr)

	s.Reset()
	_, ok := s.CertificateStatus(serial)
	assert.False(t, ok, "a reset forgets the certificates")
}
