package license_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

var (
	t0               = time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	otherKey         = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	testInstallation = license.NewInstallationID()
)

func signedTestFile(t *testing.T) []byte {
	t.Helper()
	return licensetest.Sign(licensetest.Payload(testInstallation, t0, t0.AddDate(1, 0, 0), 10))
}

func TestCheckAcceptsAGenuineFile(t *testing.T) {
	f, err := license.Check(signedTestFile(t), licensetest.KeySet())
	require.NoError(t, err)
	assert.Equal(t, licensetest.KeyID, f.KeyID)
	assert.Equal(t, 10, f.Payload.MaxTargets)
	assert.Equal(t, testInstallation, f.Payload.InstallationID)
}

// L-40, L-41, L-42.
func TestCheckRejectsForgeries(t *testing.T) {
	raw := signedTestFile(t)
	f, err := license.ParseFile(raw)
	require.NoError(t, err)
	sig := strings.SplitN(strings.SplitN(string(raw), `"signature": "`, 2)[1], `"`, 2)[0]
	flipped := []byte(sig)
	if flipped[10] == 'A' {
		flipped[10] = 'B'
	} else {
		flipped[10] = 'A'
	}
	otherSigned := licensetest.SignWith(otherKey, licensetest.KeyID, f.Payload)

	for name, bad := range map[string][]byte{
		"payload byte changed (L-40)":  replaceOnce(t, raw, `"max_targets": 10`, `"max_targets": 1000`),
		"customer changed":             replaceOnce(t, raw, `"Test Company"`, `"Test Companx"`),
		"signature byte changed":       replaceOnce(t, raw, sig, string(flipped)),
		"signed by another key (L-42)": otherSigned,
	} {
		_, err := license.Check(bad, licensetest.KeySet())
		var inv *license.InvalidError
		require.ErrorAs(t, err, &inv, name)
		assert.Equal(t, "signature", inv.Problem, name)
		assert.Equal(t, "invalid_signature", license.RejectReason(err), name)
	}

	unknown := licensetest.SignWith(otherKey, "vk-2099-01", f.Payload)
	_, err = license.Check(unknown, licensetest.KeySet())
	assert.ErrorIs(t, err, license.ErrUnknownKey, "a key ID the binary does not embed (§16.3 step 2)")
}

// Review Focus 3: every signed value is covered by the signature.
func TestVerifyRejectsAnyChangeToSignedValues(t *testing.T) {
	f, err := license.ParseFile(signedTestFile(t))
	require.NoError(t, err)
	require.NoError(t, license.Verify(f, licensetest.KeySet()))
	changes := map[string]func(p *license.Payload){
		"license_id":      func(p *license.Payload) { p.LicenseID += "0" },
		"customer":        func(p *license.Payload) { p.Customer += "." },
		"installation_id": func(p *license.Payload) { p.InstallationID = license.NewInstallationID() },
		"issued_at":       func(p *license.Payload) { p.IssuedAt = p.IssuedAt.Add(time.Second) },
		"valid_from":      func(p *license.Payload) { p.ValidFrom = p.ValidFrom.Add(time.Second) },
		"valid_until":     func(p *license.Payload) { p.ValidUntil = p.ValidUntil.Add(time.Second) },
		"max_targets":     func(p *license.Payload) { p.MaxTargets++ },
		"features":        func(p *license.Payload) { p.Features = append(p.Features, "extra") },
		"replaces":        func(p *license.Payload) { p.Replaces = "LIC-OLD" },
	}
	for name, change := range changes {
		g := f
		g.Payload.Features = append([]string(nil), f.Payload.Features...)
		change(&g.Payload)
		err := license.Verify(g, licensetest.KeySet())
		assert.ErrorIs(t, err, license.ErrInvalid, name)
	}
}

func TestRevokedKeys(t *testing.T) {
	raw := signedTestFile(t) // issued_at = t0
	revoked := func(from time.Time) license.KeySet {
		return license.NewKeySet(license.PublicKey{ID: licensetest.KeyID, Key: licensetest.PublicKey(), Status: license.KeyRevoked, RevokedFrom: from})
	}
	_, err := license.Check(raw, revoked(time.Time{}))
	assert.ErrorIs(t, err, license.ErrRevokedKey, "revoked without a cutoff: nothing signed with it is trusted")
	_, err = license.Check(raw, revoked(t0))
	assert.ErrorIs(t, err, license.ErrRevokedKey, "issued at the cutoff")
	_, err = license.Check(raw, revoked(t0.Add(time.Second)))
	assert.NoError(t, err, "issued before the cutoff stays valid (§16.7)")
}

func TestKeySetFileRoundTripAndErrors(t *testing.T) {
	cut := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	raw, err := license.EncodeKeySet(
		license.PublicKey{ID: "vk-2026-01", Key: licensetest.PublicKey(), Status: license.KeyActive},
		license.PublicKey{ID: "vk-2025-01", Key: otherKey.Public().(ed25519.PublicKey), Status: license.KeyRevoked, RevokedFrom: cut},
	)
	require.NoError(t, err)
	ks, err := license.ParseKeySet(raw)
	require.NoError(t, err)
	require.Equal(t, 2, ks.Len())
	keys := ks.Keys()
	assert.Equal(t, "vk-2025-01", keys[0].ID, "sorted by ID")
	assert.Equal(t, license.KeyRevoked, keys[0].Status)
	assert.True(t, keys[0].RevokedFrom.Equal(cut))
	assert.Equal(t, licensetest.PublicKey(), keys[1].Key)
	assert.Regexp(t, `^SHA256:[0-9a-f]{64}$`, license.Fingerprint(keys[1].Key))

	empty, err := license.ParseKeySet([]byte(`{"keys": []}`))
	require.NoError(t, err)
	assert.Zero(t, empty.Len())

	good := `{"key_id":"vk-2026-01","public_key":"` + b64(licensetest.PublicKey()) + `","status":"active"}`
	for name, bad := range map[string]string{
		"not JSON":             `nope`,
		"missing keys":         `{}`,
		"unknown field":        `{"keys":[],"extra":1}`,
		"bad key id":           `{"keys":[{"key_id":"key1","public_key":"` + b64(licensetest.PublicKey()) + `","status":"active"}]}`,
		"short key":            `{"keys":[{"key_id":"vk-2026-01","public_key":"AAAA","status":"active"}]}`,
		"unknown status":       `{"keys":[{"key_id":"vk-2026-01","public_key":"` + b64(licensetest.PublicKey()) + `","status":"retired"}]}`,
		"duplicate id":         `{"keys":[` + good + `,` + good + `]}`,
		"cutoff on active key": `{"keys":[{"key_id":"vk-2026-01","public_key":"` + b64(licensetest.PublicKey()) + `","status":"active","revoked_from":"2027-01-01T00:00:00Z"}]}`,
		"test key id":          `{"keys":[{"key_id":"` + licensetest.KeyID + `","public_key":"` + b64(licensetest.PublicKey()) + `","status":"active"}]}`,
		"other test key id":    `{"keys":[{"key_id":"vk-test-02","public_key":"` + b64(otherKey.Public().(ed25519.PublicKey)) + `","status":"active"}]}`,
		"non-canonical base64": `{"keys":[{"key_id":"vk-2026-01","public_key":"` + nonCanonical(b64(licensetest.PublicKey())) + `","status":"active"}]}`,
	} {
		_, err := license.ParseKeySet([]byte(bad))
		assert.Error(t, err, name)
	}
}

func b64(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

// nonCanonical sets the unused low bits of the last base64 symbol of a 32-byte key: a lenient
// decoder still reads the same key, so the key set file would have two spellings of one key.
func nonCanonical(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alphabet, s[42])
	return s[:42] + string(alphabet[i&^3|1]) + s[43:]
}

func TestRevokedKeyWithoutCutoffRoundTrips(t *testing.T) {
	raw, err := license.EncodeKeySet(license.PublicKey{ID: "vk-2025-01", Key: otherKey.Public().(ed25519.PublicKey), Status: license.KeyRevoked})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "revoked_from")
	ks, err := license.ParseKeySet(raw)
	require.NoError(t, err)
	require.Equal(t, 1, ks.Len())
	k := ks.Keys()[0]
	assert.Equal(t, license.KeyRevoked, k.Status)
	assert.True(t, k.RevokedFrom.IsZero(), "no cutoff: nothing signed with the key is trusted")
	again, err := license.EncodeKeySet(k)
	require.NoError(t, err)
	assert.Equal(t, raw, again)
}

// A key of the wrong length (only possible through NewKeySet) is an unknown key, not a panic
// inside ed25519.Verify.
func TestVerifyWithMalformedKeyIsUnknownKey(t *testing.T) {
	f, err := license.ParseFile(signedTestFile(t))
	require.NoError(t, err)
	for _, key := range []ed25519.PublicKey{nil, licensetest.PublicKey()[:31], append(licensetest.PublicKey(), 0)} {
		ks := license.NewKeySet(license.PublicKey{ID: licensetest.KeyID, Key: key, Status: license.KeyActive})
		assert.NotPanics(t, func() { err = license.Verify(f, ks) })
		assert.ErrorIs(t, err, license.ErrUnknownKey)
	}
}

// Task 22 ruling: after a key compromise the vendor revokes the key with no cutoff, because
// whoever holds the key chooses issued_at. A cutoff would still trust a forged license that
// is backdated before it; no cutoff refuses it.
func TestCompromisedKeyRevokedWithoutCutoffRejectsBackdatedLicenses(t *testing.T) {
	compromisedAt := t0.AddDate(0, 6, 0)
	p := licensetest.Payload(testInstallation, compromisedAt, compromisedAt.AddDate(1, 0, 0), 100000)
	p.IssuedAt = t0.AddDate(-1, 0, 0) // backdated by the attacker
	p.ValidFrom = p.IssuedAt
	forged := licensetest.Sign(p)
	key := license.PublicKey{ID: licensetest.KeyID, Key: licensetest.PublicKey(), Status: license.KeyRevoked}

	withCutoff := key
	withCutoff.RevokedFrom = compromisedAt
	_, err := license.Check(forged, license.NewKeySet(withCutoff))
	require.NoError(t, err, "a cutoff cannot stop a backdated forgery")

	_, err = license.Check(forged, license.NewKeySet(key))
	require.ErrorIs(t, err, license.ErrRevokedKey)
}

func TestKeySetRejectsAMalformedCutoff(t *testing.T) {
	_, err := license.ParseKeySet([]byte(`{"keys":[{"key_id":"vk-2025-01","public_key":"` +
		base64.StdEncoding.EncodeToString(otherKey.Public().(ed25519.PublicKey)) + `","status":"revoked","revoked_from":"yesterday"}]}`))
	require.ErrorContains(t, err, "revoked_from")
}
