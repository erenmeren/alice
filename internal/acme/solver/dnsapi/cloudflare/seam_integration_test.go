//go:build integration

package cloudflare_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver/dnsapi"
	"alice/internal/acme/solver/dnsapi/cloudflare"
	"alice/internal/secrets"
	fcf "alice/internal/testutil/fakecloudflare"
)

// TestThroughTheIntegrationSeam builds the provider the way a harness outside the package does: no mapAddr of its
// own, the fake's CA as BaseRoots and the process-wide mapping of dnsapi. Not parallel (the mapping is global).
func TestThroughTheIntegrationSeam(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	restore := dnsapi.MapAddressesForTest(f.MapAddr)
	defer restore()
	p, err := cloudflare.New(cloudflare.Config{APIToken: secrets.NewPlaintext([]byte(f.Token())), BaseRoots: f.CAPool()})
	require.NoError(t, err)
	s := solverFor(t, p)
	require.NoError(t, s.Present(ctx(t), chal("www.example.com", "seam-value")))
	assert.Equal(t, []string{"seam-value"}, f.TXT("_acme-challenge.www.example.com"))
	require.NoError(t, s.CleanUp(ctx(t), chal("www.example.com", "seam-value")))
	assert.Empty(t, f.Records())

	// The seam's mapping never trusts the system roots.
	_, err = cloudflare.New(cloudflare.Config{APIToken: secrets.NewPlaintext([]byte(f.Token()))})
	assert.ErrorIs(t, err, cloudflare.ErrClient)
}
