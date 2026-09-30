// Package licensetest signs license files with a fixed, publicly derivable test key,
// for tests and the e2e build (spec §22.6). Release code never imports it: a test in
// cmd/alice checks that the alice binary does not link it, and release builds do not
// trust its key.
package licensetest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"alice/internal/license"
)

// KeyID is the key ID of the test signing key.
const KeyID = "vk-test-01"

// seedLabel must equal testKeyLabel in internal/license/keys_testlicense.go.
const seedLabel = "alice test license signing key v1"

// PrivateKey returns the test signing key.
func PrivateKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(seedLabel))
	return ed25519.NewKeyFromSeed(seed[:])
}

// PublicKey returns the public half of the test key.
func PublicKey() ed25519.PublicKey { return PrivateKey().Public().(ed25519.PublicKey) }

// KeySet returns a key set that trusts only the test key.
func KeySet() license.KeySet {
	return license.NewKeySet(license.PublicKey{ID: KeyID, Key: PublicKey(), Status: license.KeyActive})
}

// Payload returns a valid payload: license LIC-TEST-000001 for "Test Company", issued at validFrom.
func Payload(installationID string, validFrom, validUntil time.Time, maxTargets int) license.Payload {
	from := validFrom.UTC().Truncate(time.Second)
	return license.Payload{
		LicenseID:      "LIC-TEST-000001",
		Customer:       "Test Company",
		InstallationID: installationID,
		IssuedAt:       from,
		ValidFrom:      from,
		ValidUntil:     validUntil.UTC().Truncate(time.Second),
		MaxTargets:     maxTargets,
		Features:       []string{},
		Format:         license.FormatVersion,
	}
}

// Sign signs p with the test key and returns the file bytes. It panics on an invalid payload.
func Sign(p license.Payload) []byte { return SignWith(PrivateKey(), KeyID, p) }

// SignWith signs p with any key (tests of foreign or unknown keys).
func SignWith(priv ed25519.PrivateKey, keyID string, p license.Payload) []byte {
	f, err := license.Sign(priv, keyID, p)
	if err != nil {
		panic("licensetest: " + err.Error())
	}
	raw, err := license.EncodeFile(f)
	if err != nil {
		panic("licensetest: " + err.Error())
	}
	return raw
}
