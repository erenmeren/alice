package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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
}
