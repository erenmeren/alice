package azuredns_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/transport"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/fakekv"
)

// A full order with the real ACME client: the fake CA validates DNS-01 against the TXT values the provider published
// in the fake Azure DNS (the fake mirrors its record sets into the CA's DNS table).
func TestIssuanceThroughFakeCA(t *testing.T) {
	f, err := fakeacme.New(fakeacme.Options{})
	require.NoError(t, err)
	require.NoError(t, f.Start())
	t.Cleanup(f.Close)

	w := secretWorld(t, fakekv.Options{DNSSink: f})
	hc, err := transport.New(string(f.CAPEM()))
	require.NoError(t, err)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cl, err := acme.New(acme.Config{DirectoryURL: f.DirectoryURL(), Key: k, HTTPClient: hc, Contact: "admin@example.test"})
	require.NoError(t, err)
	_, err = cl.RegisterAccount(ctx5(t), "", nil, true)
	require.NoError(t, err)

	names := []string{"*.example.test", "example.test"}
	ck, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, ck)
	require.NoError(t, err)

	var presented int
	chain, err := cl.Order(ctx5(t), names, csr, w.solverOf(t),
		acme.WithOnPresent(func(solver.Challenge) error { presented++; return nil }))
	require.NoError(t, err, "the CA found both values")
	assert.NotEmpty(t, chain)
	assert.Equal(t, 2, presented)
	assert.Empty(t, w.s.DNSRecords(), "cleaned up in Azure")
	assert.Empty(t, f.DNSRecords(), "and so in the CA's view")
}
