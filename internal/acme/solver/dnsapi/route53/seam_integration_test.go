//go:build integration

package route53

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver/dnsapi"
	"alice/internal/testutil/fakeroute53"
)

// The integration seam is how a harness outside this package reaches the fake: a provider built without the
// package's own mapping, with the fake's CA as its BaseRoots, while dnsapi.MapAddressesForTest is in force.
func TestThroughTheIntegrationSeam(t *testing.T) {
	f := startFake(t, fakeroute53.Options{InsyncAfter: 1})
	restore := dnsapi.MapAddressesForTest(f.MapAddr)
	defer restore()
	p, err := New(withMapAddr(fakeConfig(f), nil))
	require.NoError(t, err)
	s := newSolver(t, p)
	require.NoError(t, s.Present(ctx30(t), chal("example.test", "seam-value")))
	_, values, ok := f.RecordSet("_acme-challenge.example.test")
	require.True(t, ok)
	assert.Equal(t, []string{"seam-value"}, values)
	require.NoError(t, s.CleanUp(ctx30(t), chal("example.test", "seam-value")))
	assert.Empty(t, f.Records())
}
