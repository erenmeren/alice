package license_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

func TestCanonicalPayloadIsRFC8785(t *testing.T) {
	p := license.Payload{
		LicenseID:      "LIC-2026-000123",
		Customer:       "Örnek \"Bankası\" A.Ş. \\ <&> \u0001\t\n",
		InstallationID: "ALICE-7F3K-9Q2M-XD41-B8TC",
		IssuedAt:       time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC),
		ValidFrom:      time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC),
		ValidUntil:     time.Date(2027, 9, 29, 0, 0, 0, 0, time.UTC),
		MaxTargets:     100,
		Format:         1,
	}
	want := `{"customer":"Örnek \"Bankası\" A.Ş. \\ <&> \u0001\t\n","features":[],"format":1,` +
		`"installation_id":"ALICE-7F3K-9Q2M-XD41-B8TC","issued_at":"2026-09-29T09:00:00Z","license_id":"LIC-2026-000123",` +
		`"max_targets":100,"valid_from":"2026-09-29T00:00:00Z","valid_until":"2027-09-29T00:00:00Z"}`
	assert.Equal(t, want, string(license.CanonicalPayload(p)))

	p.Features = []string{"zeta", "alpha"}
	p.Replaces = "LIC-2026-000100"
	p.IssuedAt = time.Date(2026, 9, 29, 12, 0, 0, 0, time.FixedZone("TRT", 3*3600)) // rendered in UTC
	want = `{"customer":"Örnek \"Bankası\" A.Ş. \\ <&> \u0001\t\n","features":["zeta","alpha"],"format":1,` +
		`"installation_id":"ALICE-7F3K-9Q2M-XD41-B8TC","issued_at":"2026-09-29T09:00:00Z","license_id":"LIC-2026-000123",` +
		`"max_targets":100,"replaces":"LIC-2026-000100","valid_from":"2026-09-29T00:00:00Z","valid_until":"2027-09-29T00:00:00Z"}`
	assert.Equal(t, want, string(license.CanonicalPayload(p)))
	assert.Equal(t, "ALICE-LICENSE-v1\n"+want, string(license.SignedBytes(p)))

	p.Customer = "a\bb\fc\rd\u001f"
	assert.Contains(t, string(license.CanonicalPayload(p)), `"customer":"a\bb\fc\rd\u001f"`, "the short escapes of RFC 8785")
}

// AUD-19: a newer format is verified against the RFC 8785 form of its payload as given, unknown
// members included; for a format 1 payload that form is CanonicalPayload.
func TestCanonicalJSONIsRFC8785(t *testing.T) {
	p := license.Payload{
		LicenseID: "LIC-2026-000123", Customer: "Örnek \"Bankası\" A.Ş. \\ <&> \u0001\t\n€😀",
		InstallationID: "ALICE-7F3K-9Q2M-XD41-B8TC", IssuedAt: time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC),
		ValidFrom: time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2027, 9, 29, 0, 0, 0, 0, time.UTC),
		MaxTargets: 100, Features: []string{"b", "a"}, Format: 1, Replaces: "LIC-1",
	}
	pretty, err := json.MarshalIndent(json.RawMessage(license.CanonicalPayload(p)), "", "   ")
	require.NoError(t, err)
	got, err := license.CanonicalJSON(pretty)
	require.NoError(t, err)
	assert.Equal(t, string(license.CanonicalPayload(p)), string(got))

	for in, want := range map[string]string{
		`{"b":[1,{"z":null,"a":true}],"a":"é\/","€":false,"😀":0}`:                                                          `{"a":"é/","b":[1,{"a":true,"z":null}],"€":false,"😀":0}`,
		`[0, -0, 1.0, 1e0, 100, 1e21, 1e20, 123456789012345680000, 0.000001, 1e-7, 4.5, -2e-3, 1.5e300, 9007199254740993]`: `[0,0,1,1,100,1e+21,100000000000000000000,123456789012345680000,0.000001,1e-7,4.5,-0.002,1.5e+300,9007199254740992]`,
	} {
		got, err := license.CanonicalJSON([]byte(in))
		require.NoError(t, err, in)
		assert.Equal(t, want, string(got), in)
	}
	for _, bad := range []string{`{"a":1,"a":2}`, `{} {}`, `1e400`, `{"a":`, ``, strings.Repeat("[", 17) + strings.Repeat("]", 17)} {
		_, err := license.CanonicalJSON([]byte(bad))
		assert.Error(t, err, bad)
	}
	_, err = license.CanonicalJSON([]byte(strings.Repeat("[", 16) + strings.Repeat("]", 16)))
	assert.NoError(t, err, "16 levels are accepted")
}
