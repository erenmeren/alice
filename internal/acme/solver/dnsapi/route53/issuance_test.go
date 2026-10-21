package route53

import (
	"context"
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
	"alice/internal/testutil/fakeroute53"
)

func startCA(t *testing.T) *fakeacme.Server {
	t.Helper()
	ca, err := fakeacme.New(fakeacme.Options{})
	require.NoError(t, err)
	require.NoError(t, ca.Start())
	t.Cleanup(ca.Close)
	return ca
}

func registeredClient(t *testing.T, ctx context.Context, ca *fakeacme.Server) *acme.Client {
	t.Helper()
	hc, err := transport.New(string(ca.CAPEM()))
	require.NoError(t, err)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	c, err := acme.New(acme.Config{DirectoryURL: ca.DirectoryURL(), Key: k, HTTPClient: hc, Contact: "admin@example.test"})
	require.NoError(t, err)
	_, err = c.RegisterAccount(ctx, "", nil, true)
	require.NoError(t, err)
	return c
}

func csrFor(t *testing.T, names ...string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, k)
	require.NoError(t, err)
	return der
}

// A whole order through the real ACME client: the fake CA validates DNS-01 against the TXT values the fake Route 53
// mirrors into it, so the certificate is issued only if the provider published the right value at the right name,
// kept the wildcard's and the base name's values side by side and waited for INSYNC; clean-up removes both.
func TestIssuanceThroughFakeCA(t *testing.T) {
	ctx := ctx30(t)
	ca := startCA(t)
	f := startFake(t, fakeroute53.Options{RoleARN: testRole, ExternalID: testExternalID, InsyncAfter: 1, Sink: ca})
	s := newSolver(t, newProvider(t, f, withRole))
	cl := registeredClient(t, ctx, ca)
	names := []string{"*.example.test", "example.test"}
	var presented []string
	chain, err := cl.Order(ctx, names, csrFor(t, names...), s,
		acme.WithOnPresent(func(c solver.Challenge) error { presented = append(presented, c.DNSValue); return nil }))
	require.NoError(t, err)
	require.NotEmpty(t, chain)
	leaf, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)
	assert.ElementsMatch(t, names, leaf.DNSNames)
	assert.Len(t, presented, 2)
	assert.Empty(t, f.Records(), "both values were removed")
	assert.Empty(t, ca.DNSRecords(), "and the CA's view followed")
	assert.Len(t, f.Sessions(), 1)
}

func TestIssuanceFailsWithoutAZone(t *testing.T) {
	ctx := ctx30(t)
	ca := startCA(t)
	f := startFake(t, fakeroute53.Options{Zones: []fakeroute53.Zone{{Name: "example.test", Private: true}}, Sink: ca})
	cl := registeredClient(t, ctx, ca)
	_, err := cl.Order(ctx, []string{"example.test"}, csrFor(t, "example.test"), newSolver(t, newProvider(t, f)))
	require.Error(t, err)
	assert.Equal(t, acme.ReasonDNSZoneNotFound, acme.ReasonOf(err))
	assert.Zero(t, f.Counters()[fakeroute53.OpChange])
}
