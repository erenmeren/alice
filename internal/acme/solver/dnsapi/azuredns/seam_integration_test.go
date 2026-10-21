//go:build integration

package azuredns_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver/dnsapi"
	"alice/internal/acme/solver/dnsapi/azuredns"
	"alice/internal/secrets"
	"alice/internal/testutil/fakekv"
)

// The integration seam (dnsapi.MapAddressesForTest) reaches the provider without its package's own mapping: every
// client, the managed identity's metadata transport included, maps through it.
func TestIntegrationSeamMapsEveryTransport(t *testing.T) {
	mi := fakekv.UniqueClientID()
	s := fakekv.Start(t, fakekv.Options{DNSZones: []string{"example.test"}, ManagedIdentity: true, MIClientID: mi})
	restore := dnsapi.MapAddressesForTest(s.DialAddr)
	t.Cleanup(restore)

	base := azuredns.Config{SubscriptionID: s.DNSSubscriptionID(), ResourceGroup: s.DNSResourceGroup(), BaseRoots: s.CAPool()}
	secret := base
	secret.Auth, secret.TenantID, secret.ClientID = azuredns.AuthClientSecret, s.TenantID(), s.ClientID()
	secret.ClientSecret = secrets.NewPlaintext([]byte(s.Secret()))
	identity := base
	identity.Auth, identity.ClientID = azuredns.AuthManagedIdentity, mi

	for _, cfg := range []azuredns.Config{secret, identity} {
		p, err := azuredns.New(cfg)
		require.NoError(t, err)
		sv, err := dnsapi.New(dnsapi.Config{Provider: p, AllowedSuffixes: []string{"example.test"}, PropagationWait: -1})
		require.NoError(t, err)
		require.NoError(t, sv.Present(ctx5(t), chal("example.test", "v-"+cfg.Auth)))
		assert.Contains(t, s.DNSRecords()["_acme-challenge.example.test"], "v-"+cfg.Auth)
	}

	noRoots := secret
	noRoots.BaseRoots = nil
	_, err := azuredns.New(noRoots)
	assert.ErrorIs(t, err, dnsapi.ErrMapNeedsRoots, "a mapped client never trusts the system roots")
}
