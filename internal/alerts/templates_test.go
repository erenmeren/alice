package alerts

import (
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTemplateNamesAreValid(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`) // notify's templatePattern
	assert.Len(t, Templates(), 11)
	for _, tpl := range Templates() {
		assert.Regexp(t, pattern, tpl)
	}
	assert.Equal(t, []Kind{KindCertificate, KindKVCertificate, KindKVKey, KindKVCredential, KindDiscoveredCertificate}, Kinds())
	assert.Equal(t, []Kind{KindCertificate, KindKVCertificate, KindKVKey, KindKVCredential}, ManagedKinds(),
		"the Overview's expiring list and counts are the managed kinds only (decision D2)")
	for _, k := range Kinds() {
		for _, level := range []int{0, 7} {
			assert.Contains(t, Templates(), templateFor(k, level), "every kind has its own e-mail per level")
		}
	}
}

// Amendment A7: the ledger's object id of a discovered certificate is a stable uuid (v5) of its fingerprint.
func TestDiscoveredObjectIDIsStable(t *testing.T) {
	fp := "aa" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	id := DiscoveredObjectID(fp)
	assert.Equal(t, uuid.Version(5), id.Version())
	assert.Equal(t, id, DiscoveredObjectID(fp), "the same fingerprint, the same id")
	assert.NotEqual(t, id, DiscoveredObjectID("bb"+fp[2:]))
	assert.Equal(t, uuid.NewSHA1(discoveredNamespace, []byte(fp)), id)
	assert.Equal(t, "8d6c3f3e-0f4b-4d1e-9a51-6a7f2c1e9b40", discoveredNamespace.String(), "the namespace never changes: ledger rows refer to it")
}

// A discovered certificate's notice carries the endpoints, the scopes, the fingerprint and the way to the discovery
// page; the license note in lock is the general one (not the Key Vault one); nothing else of the certificate.
func TestDiscoveredParams(t *testing.T) {
	it := Item{Kind: KindDiscoveredCertificate, Name: "legacy.example.com", Fingerprint: "ab", Endpoints: []string{"10.0.0.5:443"},
		Scopes: []string{"DC"}}
	p := paramsOf(it, it.ExpiresAt, 0, licenseNote{locked: true, url: "https://alice.example.com/license", base: "https://alice.example.com"})
	assert.Equal(t, map[string]string{"name": "legacy.example.com", "expires_at": it.ExpiresAt.UTC().Format(timeLayout), "fingerprint": "ab",
		"endpoints": "10.0.0.5:443", "scopes": "DC", "discovery_url": "https://alice.example.com/discovery?view=unmanaged",
		"license_note": "true", "license_url": "https://alice.example.com/license"}, p)
	p = paramsOf(Item{Kind: KindKVKey, Name: "k", Vault: "v"}, it.ExpiresAt, 0, licenseNote{locked: true, url: "/license"})
	assert.Equal(t, "kv", p["license_note"], "the Key Vault kinds keep their own note")
}
