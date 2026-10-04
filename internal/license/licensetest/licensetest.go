// Package licensetest signs license files with a fixed, publicly derivable test key,
// for tests and the e2e build (spec §22.6). Release code never imports it: a test in
// cmd/alice checks that the alice binary does not link it, and release builds do not
// trust its key.
package licensetest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// SignFormat signs p as a file of the given format with the test key, adding payloadExtra to
// the signed payload and fileExtra to the file object outside it. It produces what this build
// cannot issue: a license in a newer format, or one in the current format with fields it does
// not know (AUD-19). The payload's "format" is set to format; nothing is validated.
func SignFormat(p license.Payload, format int, payloadExtra, fileExtra map[string]any) []byte {
	return SignFormatWith(PrivateKey(), KeyID, p, format, payloadExtra, fileExtra)
}

// SignFormatWith is SignFormat with any key.
func SignFormatWith(priv ed25519.PrivateKey, keyID string, p license.Payload, format int, payloadExtra, fileExtra map[string]any) []byte {
	p.Format = format
	payload := map[string]any{}
	must(json.Unmarshal(license.CanonicalPayload(p), &payload))
	for k, v := range payloadExtra {
		payload[k] = v
	}
	rawPayload, err := json.Marshal(payload)
	must(err)
	signed, err := license.SignedBytesFor(rawPayload)
	must(err)
	file := map[string]any{
		"format":    format,
		"key_id":    keyID,
		"payload":   json.RawMessage(rawPayload),
		"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, signed)),
	}
	for k, v := range fileExtra {
		file[k] = v
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	must(err)
	return raw
}

func must(err error) {
	if err != nil {
		panic("licensetest: " + err.Error())
	}
}
