//go:build releasecheck

package license_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// Release gate (make release-keycheck, R36 item 1): a customer build must embed at
// least one active vendor key and no test key. It fails until the owner commits the
// production public key to internal/license/keys/production.json.
func TestProductionKeySetIsReadyForRelease(t *testing.T) {
	require.False(t, license.TestKeyTrusted, "build without -tags testlicense")
	ks := license.EmbeddedKeys()
	require.Positive(t, ks.Len(), "internal/license/keys/production.json lists no key; see docs/vendor/licensing-vendor.md")
	active := 0
	for _, k := range ks.Keys() {
		assert.NotEqual(t, licensetest.KeyID, k.ID, "the test key ID must never be a production key ID")
		assert.NotEqual(t, licensetest.PublicKey(), k.Key, "the test key must never be a production key")
		if k.Status == license.KeyActive {
			active++
		}
	}
	assert.Positive(t, active, "at least one key must be active")
}
