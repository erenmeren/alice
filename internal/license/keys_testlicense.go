//go:build testlicense

package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
)

//go:embed keys/production.json
var productionKeySet []byte

// TestKeyTrusted is true only in test builds (-tags testlicense, spec §22.6).
const TestKeyTrusted = true

// The test key is derived from a public label; licensetest holds the same derivation.
// It is not a secret, which is exactly why release builds must never trust it.
const (
	testKeyLabel = "alice test license signing key v1"
	testKeyID    = "vk-test-01"
)

// EmbeddedKeys returns the production keys plus the test key.
func EmbeddedKeys() KeySet {
	ks, err := ParseKeySet(productionKeySet)
	if err != nil {
		panic("license: keys/production.json is not a valid key set: " + err.Error())
	}
	seed := sha256.Sum256([]byte(testKeyLabel))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	ks.keys[testKeyID] = PublicKey{ID: testKeyID, Key: pub, Status: KeyActive}
	return ks
}
