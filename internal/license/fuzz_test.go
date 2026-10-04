package license_test

import (
	"bytes"
	"encoding/json"
	"errors"
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
	// AUD-19: genuinely signed files in newer formats, with fields this version does not know.
	newer := map[string]bool{}
	p := licensetest.Payload(fuzzInstallation, t0, t0.AddDate(1, 0, 0), 10)
	for i, extra := range []map[string]any{nil, {"seats": 5}, {"limits": map[string]any{"ratio": 1.5, "tags": []any{"a", nil}}}} {
		raw := licensetest.SignFormat(p, 2+i, extra, map[string]any{"server": "x"})
		newer[string(newerPayload(raw))] = true
		f.Add(raw)
	}
	for _, seed := range []string{`{"format":1}`, `{"format":99,"x":1}`, `[[[[`, "\xef\xbb\xbf{}", `{"a":1,"a":2}`,
		`{"format":2,"key_id":"vk-test-01","payload":{"format":2},"signature":""}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		file, err := license.Check(raw, keys)
		if errors.Is(err, license.ErrUnsupportedFormat) {
			// "Update Alice" only for a payload the test key really signed.
			if canon := newerPayload(raw); !newer[string(canon)] {
				t.Fatalf("an unsigned newer-format payload was reported as newer: %s", canon)
			}
			return
		}
		if err != nil {
			return
		}
		if canon := license.CanonicalPayload(file.Payload); !signed[string(canon)] {
			t.Fatalf("an unsigned payload verified: %s", canon)
		}
	})
}

// newerPayload is the canonical payload of a file in any format ("" when it has none).
func newerPayload(raw []byte) []byte {
	var top struct {
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &top) != nil {
		return nil
	}
	canon, _ := license.CanonicalJSON(top.Payload)
	return canon
}
