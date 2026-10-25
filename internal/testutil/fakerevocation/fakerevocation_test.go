package fakerevocation_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"alice/internal/platform/clock"
	"alice/internal/testutil/fakerevocation"
	"alice/internal/testutil/pki"
)

func get(t *testing.T, method, url string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(body))
	require.NoError(t, err)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, b
}

// The fake answers signed OCSP responses and CRLs of its CA that the standard parsers accept, and each fault as named.
func TestFakeServesSignedAnswers(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
	ca := pki.NewCA("Fake", pki.ECDSA256, clk.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, clk.Now())
	s := fakerevocation.New(ca, clk)
	base := "http://" + s.Start(t)
	at := clk.Now().Add(-time.Hour).Truncate(time.Second)
	s.Revoke(leaf.Cert.SerialNumber, 1, at)

	req, err := ocsp.CreateRequest(leaf.Cert, ca.Intermediate, &ocsp.RequestOptions{Hash: crypto.SHA1})
	require.NoError(t, err)
	code, body := get(t, http.MethodPost, base+"/ocsp", req)
	require.Equal(t, http.StatusOK, code)
	resp, err := ocsp.ParseResponseForCert(body, leaf.Cert, ca.Intermediate)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, resp.Status)
	assert.Equal(t, 1, resp.RevocationReason)
	assert.True(t, at.Equal(resp.RevokedAt))

	code, body = get(t, http.MethodGet, base+"/crl", nil)
	require.Equal(t, http.StatusOK, code)
	crl, err := x509.ParseRevocationList(body)
	require.NoError(t, err)
	require.NoError(t, crl.CheckSignatureFrom(ca.Intermediate))
	require.Len(t, crl.RevokedCertificateEntries, 1)
	assert.Equal(t, 0, crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.Cert.SerialNumber))

	s.SetCRLPEM(true)
	_, body = get(t, http.MethodGet, base+"/crl", nil)
	blk, _ := pem.Decode(body)
	require.NotNil(t, blk)
	assert.Equal(t, "X509 CRL", blk.Type)
	s.SetCRLPEM(false)

	s.Release(leaf.Cert.SerialNumber)
	s.Hold(leaf.Cert.SerialNumber, at)
	_, body = get(t, http.MethodPost, base+"/ocsp", req)
	resp, err = ocsp.ParseResponseForCert(body, leaf.Cert, ca.Intermediate)
	require.NoError(t, err)
	assert.Equal(t, 6, resp.RevocationReason)

	s.SetFault("/ocsp", fakerevocation.FaultUnknown)
	_, body = get(t, http.MethodPost, base+"/ocsp", req)
	resp, err = ocsp.ParseResponseForCert(body, leaf.Cert, ca.Intermediate)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Unknown, resp.Status)
	s.SetFault("/ocsp", fakerevocation.FaultStale)
	_, body = get(t, http.MethodPost, base+"/ocsp", req)
	resp, err = ocsp.ParseResponseForCert(body, leaf.Cert, ca.Intermediate)
	require.NoError(t, err)
	assert.True(t, resp.NextUpdate.Before(clk.Now()))
	s.SetFault("/ocsp", fakerevocation.FaultWrongSigner)
	_, body = get(t, http.MethodPost, base+"/ocsp", req)
	_, err = ocsp.ParseResponseForCert(body, leaf.Cert, ca.Intermediate)
	require.Error(t, err)

	for f, check := range map[fakerevocation.Fault]func(*x509.RevocationList, error){
		fakerevocation.FaultWrongSigner: func(c *x509.RevocationList, err error) {
			require.NoError(t, err)
			require.Error(t, c.CheckSignatureFrom(ca.Intermediate))
		},
		fakerevocation.FaultOtherIssuer: func(c *x509.RevocationList, err error) {
			require.NoError(t, err)
			require.NoError(t, c.CheckSignatureFrom(ca.Intermediate))
			assert.NotEqual(t, leaf.Cert.RawIssuer, c.RawIssuer)
		},
		fakerevocation.FaultStale: func(c *x509.RevocationList, err error) {
			require.NoError(t, err)
			assert.True(t, c.NextUpdate.Before(clk.Now()))
		},
	} {
		s.SetFault("/crl", f)
		_, body = get(t, http.MethodGet, base+"/crl", nil)
		check(x509.ParseRevocationList(body))
	}

	// The delegated responders: the library accepts each (it checks only that the issuer signed the responder), which is
	// why the checker checks the purpose and the validity itself (final review C1).
	for f, check := range map[fakerevocation.Fault]func(*x509.Certificate){
		fakerevocation.FaultDelegated:        func(c *x509.Certificate) { assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) },
		fakerevocation.FaultDelegatedNoEKU:   func(c *x509.Certificate) { assert.NotContains(t, c.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) },
		fakerevocation.FaultDelegatedExpired: func(c *x509.Certificate) { assert.True(t, c.NotAfter.Before(clk.Now())) },
	} {
		s.SetFault("/ocsp", f)
		_, body = get(t, http.MethodPost, base+"/ocsp", req)
		resp, err = ocsp.ParseResponseForCert(body, leaf.Cert, ca.Intermediate)
		require.NoError(t, err)
		require.NotNil(t, resp.Certificate)
		check(resp.Certificate)
	}
	s.SetFault("/crl", fakerevocation.FaultDeltaCRL)
	_, body = get(t, http.MethodGet, base+"/crl", nil)
	delta, err := x509.ParseRevocationList(body)
	require.NoError(t, err)
	found := false
	for _, e := range delta.Extensions {
		found = found || e.Id.String() == "2.5.29.27"
	}
	assert.True(t, found, "the delta CRL indicator")

	s.SetFault("/crl", fakerevocation.FaultDown)
	code, _ = get(t, http.MethodGet, base+"/crl", nil)
	assert.Equal(t, http.StatusInternalServerError, code)
	s.SetFault("/crl", fakerevocation.FaultGarbage)
	_, body = get(t, http.MethodGet, base+"/crl", nil)
	_, err = x509.ParseRevocationList(body)
	require.Error(t, err)
	s.SetFault("/crl", fakerevocation.FaultHuge)
	_, body = get(t, http.MethodGet, base+"/crl", nil)
	assert.Len(t, body, fakerevocation.HugeSize)
	s.SetFault("/crl", fakerevocation.FaultRedirect)
	code, _ = get(t, http.MethodGet, base+"/crl", nil)
	assert.Equal(t, http.StatusFound, code)
	assert.Zero(t, s.Requests("/target"))
	code, _ = get(t, http.MethodGet, base+"/nothing", nil)
	assert.Equal(t, http.StatusNotFound, code)
	code, _ = get(t, http.MethodPost, base+"/ocsp-bad", nil)
	assert.Equal(t, http.StatusNotFound, code)
	s.SetFault("/ocsp", fakerevocation.FaultNone)
	code, _ = get(t, http.MethodPost, base+"/ocsp", []byte("not a request"))
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Positive(t, s.Requests("/ocsp"))
}
