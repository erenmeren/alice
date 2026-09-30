//go:build !testlicense

package license

import _ "embed"

//go:embed keys/production.json
var productionKeySet []byte

// TestKeyTrusted is false in release builds: only the vendor's production keys are trusted.
const TestKeyTrusted = false

// EmbeddedKeys returns the vendor's license verification keys compiled into this binary
// (spec §16.7, §19.2). The owner commits them to keys/production.json; while the file
// lists no key, no license verifies (R36 item 1) and make release-keycheck fails.
func EmbeddedKeys() KeySet {
	ks, err := ParseKeySet(productionKeySet)
	if err != nil {
		panic("license: keys/production.json is not a valid key set: " + err.Error())
	}
	return ks
}
