package acme

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver"
	"alice/internal/testutil/fakeacme"
)

// WithOnOrder hands over the order URL before anything is presented; an issued order is downloaded again by
// ResumeOrder (the process stopped after the CA issued, before the certificate was stored).
func TestResumeAnIssuedOrder(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	names := []string{"resume.example.test"}
	csr, key := csrFor(t, names...)
	var url string
	presentedBefore := false
	chain, err := c.Order(testCtx(t), names, csr, ws, WithOnOrder(func(u string) error {
		url = u
		presentedBefore = len(ws.Presented()) > 0
		return nil
	}))
	require.NoError(t, err)
	require.NotEmpty(t, url)
	assert.False(t, presentedBefore, "the URL comes before any challenge")

	finalized := s.Counters()["finalize"]
	again, err := c.ResumeOrder(testCtx(t), url, names, csr)
	require.NoError(t, err)
	assert.Equal(t, chain, again)
	assert.Equal(t, finalized, s.Counters()["finalize"], "an issued order is not finalized again")
	leaf, err := x509.ParseCertificate(again[0])
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(leaf.PublicKey))
}

// A validated order that was never finalized (a crash between the authorizations and the CSR) is finalized.
func TestResumeAReadyOrder(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	names := []string{"ready.example.test"}
	var url string
	require.NoError(t, c.TestOrder(testCtx(t), names, ws, WithOnOrder(func(u string) error { url = u; return nil })))
	csr, key := csrFor(t, names...)
	finalized, presented := s.Counters()["finalize"], len(ws.Presented())
	chain, err := c.ResumeOrder(testCtx(t), url, names, csr)
	require.NoError(t, err)
	assert.Equal(t, finalized+1, s.Counters()["finalize"])
	leaf, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(leaf.PublicKey))
	assert.Len(t, ws.Presented(), presented, "resuming presents nothing")
}

// An order whose challenges were never validated cannot be finished: the caller abandons it. A WithOnOrder
// failure stops the order before anything is presented.
func TestResumeAPendingOrderIsRefused(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	names := []string{"pending.example.test"}
	boom := errors.New("the database is gone")
	var url string
	err := c.TestOrder(testCtx(t), names, ws, WithOnOrder(func(u string) error { url = u; return boom }))
	requireReason(t, err, ReasonDirectoryInvalid)
	assert.ErrorIs(t, err, boom)
	assert.NotContains(t, err.Error(), "database", "the callback's text is not shown")
	assert.Empty(t, ws.Presented(), "nothing was presented")

	csr, _ := csrFor(t, names...)
	_, err = c.ResumeOrder(testCtx(t), url, names, csr)
	requireReason(t, err, ReasonNotIssuedInTime)
	assert.ErrorIs(t, err, ErrOrderNotResumable)

	_, err = c.ResumeOrder(testCtx(t), "", names, csr)
	assert.ErrorIs(t, err, ErrOrderNotResumable)
	other, _ := csrFor(t, "other.example.test")
	_, err = c.ResumeOrder(testCtx(t), url, names, other)
	assert.ErrorIs(t, err, ErrCSRMismatch)
	_, err = c.ResumeOrder(testCtx(t), url, []string{"bad name"}, csr)
	assert.ErrorIs(t, err, ErrInvalidName)
	_, err = newTestClient(t, s, func(c *Config) { c.Key = nil }).ResumeOrder(testCtx(t), url, names, csr)
	assert.ErrorIs(t, err, ErrNoKey)
}

// An issued order answers a resume with a CSR of another key as a CA answer that does not fit (nothing stored).
func TestResumeChecksTheChain(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	names := []string{"chain.example.test"}
	csr, _ := csrFor(t, names...)
	var url string
	_, err := c.Order(testCtx(t), names, csr, ws, WithOnOrder(func(u string) error { url = u; return nil }))
	require.NoError(t, err)
	other, _ := csrFor(t, names...)
	_, err = c.ResumeOrder(testCtx(t), url, names, other)
	requireReason(t, err, ReasonDirectoryInvalid)
	assert.ErrorIs(t, err, ErrBadAnswer)

	// The CA is down: the failure is the CA's, not "not resumable".
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "order", Kind: fakeacme.FaultServerInternal}))
	_, err = c.ResumeOrder(testCtx(t), url, names, csr)
	requireReason(t, err, ReasonProviderUnreachable)
}

// WithBeforeFinalize runs after the authorizations are valid and can stop the order before the CSR is sent.
func TestBeforeFinalizeCanStopTheOrder(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	c := registered(t, s)
	ws := newWebSolver(t, s, solver.DNS01)
	names := []string{"fin.example.test"}
	csr, _ := csrFor(t, names...)
	stop := errors.New("locked")
	validated := 0
	_, err := c.Order(testCtx(t), names, csr, ws, WithBeforeFinalize(func() error {
		validated = s.Counters()["validations-dns-01"]
		return stop
	}))
	requireReason(t, err, ReasonDirectoryInvalid)
	assert.ErrorIs(t, err, stop)
	assert.Equal(t, 1, validated, "called after the authorization was validated")
	assert.Zero(t, s.Counters()["finalize"])
	_, err = c.Order(testCtx(t), names, csr, ws, WithBeforeFinalize(func() error { return nil }))
	require.NoError(t, err)
	assert.Equal(t, 1, s.Counters()["finalize"])
}
