//go:build testlicense

package license_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// The test build (-tags testlicense) trusts the test key next to the production keys.
func TestTestBuildTrustsTheTestKey(t *testing.T) {
	assert.True(t, license.TestKeyTrusted)
	_, err := license.Check(signedTestFile(t), license.EmbeddedKeys())
	require.NoError(t, err)
}
