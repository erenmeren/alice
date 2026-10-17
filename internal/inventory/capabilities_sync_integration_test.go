//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/fake"
)

// withSyncProviders registers the fake nginx provider with the ACME HTTP-01 capability and the fake azurekv one.
func withSyncProviders() harnessOption {
	return func(c *inventory.Config) {
		ssh, _ := c.Registry.Get(providers.KindLinuxSSH)
		reg := providers.NewRegistry()
		reg.Register(ssh)
		reg.Register(fake.New(providers.KindNginx, append(append([]providers.Capability{}, nginxCaps...), providers.CapHTTP01)...))
		reg.Register(fake.New(providers.KindAzureKV, azureCaps...))
		reg.Freeze()
		c.Registry = reg
	}
}

// SyncCapabilities rewrites the stored set of every live target from its registered provider, audits the change once and
// touches neither version nor updated_at (spec §8.1).
func TestSyncCapabilitiesIsIdempotentAndAuditedOnce(t *testing.T) {
	h := newHarness(t, withSyncProviders())
	live := h.seedTarget("live", "nginx", "10.0.0.1")
	deleted := h.seedTarget("gone", "nginx", "10.0.0.2")
	vault := h.seedTarget("vault", "azure_key_vault", "vault-sync.vault.azure.net")
	azure := []string{}
	for _, c := range azureCaps {
		azure = append(azure, string(c))
	}
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET capabilities = '{test_connection}' WHERE id = $1", live)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET capabilities = '{}', deleted_at = now() WHERE id = $1", deleted)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET capabilities = (SELECT array_agg(c ORDER BY c COLLATE \"C\") FROM unnest($2::text[]) c) WHERE id = $1",
		vault, azure)
	require.NoError(t, err)

	type stamp struct {
		version int
		updated time.Time
	}
	read := func() map[string]stamp {
		out := map[string]stamp{}
		for name, id := range map[string]any{"live": live, "gone": deleted, "vault": vault} {
			var s stamp
			require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT version, updated_at FROM targets WHERE id = $1", id).Scan(&s.version, &s.updated))
			out[name] = s
		}
		return out
	}
	before := read()
	caps := func(id any) []string {
		var c []string
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT capabilities FROM targets WHERE id = $1", id).Scan(&c))
		return c
	}

	n, err := h.svc.SyncCapabilities(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	want := []string{}
	for _, c := range append(append([]providers.Capability{}, nginxCaps...), providers.CapHTTP01) {
		want = append(want, string(c))
	}
	assert.ElementsMatch(t, want, caps(live))
	assert.IsIncreasing(t, caps(live), "stored in sorted order")
	assert.Empty(t, caps(deleted), "a deleted target keeps its set")
	assert.Equal(t, 1, h.audits("target.capabilities_synced"))
	details := h.auditDetails("target.capabilities_synced")
	require.Len(t, details, 1)
	assert.Equal(t, "1", details[0]["targets"])
	assert.Equal(t, before, read(), "version and updated_at are untouched")

	n, err = h.svc.SyncCapabilities(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, 1, h.audits("target.capabilities_synced"), "no new audit row")
	assert.Equal(t, before, read())
}
