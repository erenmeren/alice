package cloudflare_test

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
	fcf "alice/internal/testutil/fakecloudflare"
)

func startCA(t *testing.T) *fakeacme.Server {
	t.Helper()
	f, err := fakeacme.New(fakeacme.Options{})
	require.NoError(t, err)
	require.NoError(t, f.Start())
	t.Cleanup(f.Close)
	return f
}

func registeredClient(t *testing.T, f *fakeacme.Server) *acme.Client {
	t.Helper()
	hc, err := transport.New(string(f.CAPEM()))
	require.NoError(t, err)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	c, err := acme.New(acme.Config{DirectoryURL: f.DirectoryURL(), Key: k, HTTPClient: hc, Contact: "admin@example.test"})
	require.NoError(t, err)
	_, err = c.RegisterAccount(ctx(t), "", nil, true)
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

// TestIssuanceThroughTheFakeCA orders a wildcard and its base name with the real ACME client: the records go
// to the fake Cloudflare, which mirrors them into the fake CA's DNS table, the CA validates both and every record
// is removed afterwards.
func TestIssuanceThroughTheFakeCA(t *testing.T) {
	ca := startCA(t)
	cf := newFake(t, fcf.Options{Zones: []string{"example.test"}, Sink: ca})
	s := solverFor(t, providerFor(t, cf))
	cl := registeredClient(t, ca)
	names := []string{"*.example.test", "example.test"}
	var presented []string
	chain, err := cl.Order(ctx(t), names, csrFor(t, names...), s,
		acme.WithOnPresent(func(c solver.Challenge) error {
			presented = append(presented, c.DNSValue)
			return nil
		}))
	require.NoError(t, err)
	require.NotEmpty(t, chain)
	leaf, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)
	assert.ElementsMatch(t, names, leaf.DNSNames)
	assert.Len(t, presented, 2)
	assert.Empty(t, cf.Records(), "every record was removed")
	assert.Empty(t, ca.DNSRecords())
	assert.Equal(t, 2, cf.Counters()[fcf.OpCreate])
	assert.Equal(t, 2, cf.Counters()[fcf.OpDelete])
}

// TestIssuanceRefusedByAWrongToken: the order fails with the provider's reason before the CA validates anything.
func TestIssuanceRefusedByAWrongToken(t *testing.T) {
	ca := startCA(t)
	cf := newFake(t, fcf.Options{Zones: []string{"example.test"}, Sink: ca})
	wrong := randomWord(20)
	cl := registeredClient(t, ca)
	_, err := cl.Order(ctx(t), []string{"example.test"}, csrFor(t, "example.test"), solverFor(t, providerFor(t, cf, wrong)))
	require.Error(t, err)
	assert.Equal(t, acme.ReasonDNSAuthFailed, acme.ReasonOf(err))
	assertClean(t, err, wrong, cf.Token())
	assert.Empty(t, cf.Records())
}
