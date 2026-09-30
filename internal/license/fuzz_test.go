package license_test

import (
	"fmt"
	"testing"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// fuzzInstallation is a fixed valid installation ID: a random one would differ in every
// fuzz worker process, and the workers must agree on which payloads are genuinely signed.
const fuzzInstallation = "ALICE-J9N1-MQN8-N17Z-E7FS"

// FuzzParseLicense (spec §25.6): no input panics, and nothing verifies except a
// genuinely signed payload, however the JSON around it is formatted.
func FuzzParseLicense(f *testing.F) {
	keys := licensetest.KeySet()
	signed := map[string]bool{}
	for i, targets := range []int{1, 10, license.MaxTargetsLimit} {
		p := licensetest.Payload(fuzzInstallation, t0, t0.AddDate(1, 0, 0), targets)
		p.LicenseID = fmt.Sprintf("LIC-FUZZ-%d", i)
		signed[string(license.CanonicalPayload(p))] = true
		f.Add(licensetest.Sign(p))
	}
	for _, seed := range []string{`{"format":1}`, `{"format":99,"x":1}`, `[[[[`, "\xef\xbb\xbf{}", `{"a":1,"a":2}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		file, err := license.Check(raw, keys)
		if err != nil {
			return
		}
		if canon := license.CanonicalPayload(file.Payload); !signed[string(canon)] {
			t.Fatalf("an unsigned payload verified: %s", canon)
		}
	})
}
