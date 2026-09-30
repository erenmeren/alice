//go:build !testlicense

package license_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// Spec §22.6: a release build (no testlicense tag) never trusts the test signing key,
// so a test-signed license is refused by the binaries customers run.
func TestReleaseBuildDoesNotTrustTheTestKey(t *testing.T) {
	assert.False(t, license.TestKeyTrusted)
	ks := license.EmbeddedKeys()
	for _, k := range ks.Keys() {
		assert.NotEqual(t, licensetest.KeyID, k.ID)
		assert.NotEqual(t, licensetest.PublicKey(), k.Key)
	}
	_, err := license.Check(signedTestFile(t), ks)
	require.Error(t, err)
	assert.ErrorIs(t, err, license.ErrUnknownKey)
}
