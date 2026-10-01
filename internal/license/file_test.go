package license_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// fileTestKey is a throw-away key for format tests (the shared test signer is in licensetest).
var fileTestKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

func samplePayload(t *testing.T) license.Payload {
	t.Helper()
	return license.Payload{
		LicenseID:      "LIC-2026-000123",
		Customer:       "Örnek Bankası A.Ş.",
		InstallationID: license.NewInstallationID(),
		IssuedAt:       time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC),
		ValidFrom:      time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC),
		ValidUntil:     time.Date(2027, 9, 29, 0, 0, 0, 0, time.UTC),
		MaxTargets:     10,
		Features:       []string{},
		Format:         1,
	}
}

func encodeSigned(t *testing.T, p license.Payload) []byte {
	t.Helper()
	f, err := license.Sign(fileTestKey, "vk-2026-01", p)
	require.NoError(t, err)
	raw, err := license.EncodeFile(f)
	require.NoError(t, err)
	return raw
}

// replaceOnce replaces the first from with to and fails the test when from is absent.
func replaceOnce(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	require.Contains(t, string(raw), from)
	return []byte(strings.Replace(string(raw), from, to, 1))
}

func requireInvalid(t *testing.T, raw []byte, problem string) {
	t.Helper()
	_, err := license.ParseFile(raw)
	require.ErrorIs(t, err, license.ErrInvalid)
	var inv *license.InvalidError
	require.ErrorAs(t, err, &inv)
	assert.Equal(t, problem, inv.Problem)
}

func TestEncodeParseRoundTrip(t *testing.T) {
	p := samplePayload(t)
	raw := encodeSigned(t, p)
	assert.Contains(t, string(raw), "\n  \"payload\": {", "files are pretty-printed for people")
	assert.Contains(t, string(raw), "Örnek Bankası", "non-ASCII is written as UTF-8")

	f, err := license.ParseFile(raw)
	require.NoError(t, err)
	assert.Equal(t, 1, f.Format)
	assert.Equal(t, "vk-2026-01", f.KeyID)
	assert.Equal(t, p, f.Payload)
	assert.True(t, ed25519.Verify(fileTestKey.Public().(ed25519.PublicKey), license.SignedBytes(f.Payload), f.Signature))
}

// Review Focus 3: what an email client or editor does to a file must not break it.
func TestParseAcceptsHarmlessReformatting(t *testing.T) {
	p := samplePayload(t)
	raw := encodeSigned(t, p)
	var compact bytes.Buffer
	require.NoError(t, json.Compact(&compact, raw))
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &top))
	reordered := `{"signature":` + string(top["signature"]) + `,"payload":` + string(top["payload"]) +
		`,"key_id":` + string(top["key_id"]) + `,"format":1}`

	for name, variant := range map[string][]byte{
		"CRLF":            bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n")),
		"byte-order mark": append([]byte{0xEF, 0xBB, 0xBF}, raw...),
		"compact":         compact.Bytes(),
		"reordered keys":  []byte(reordered),
		"extra spaces":    bytes.ReplaceAll(raw, []byte(": "), []byte(" :   ")),
	} {
		f, err := license.ParseFile(variant)
		require.NoError(t, err, name)
		assert.Equal(t, p, f.Payload, name)
		assert.Equal(t, string(license.CanonicalPayload(p)), string(license.CanonicalPayload(f.Payload)), name)
	}
}

func TestParseRejectsMalformedFiles(t *testing.T) {
	raw := encodeSigned(t, samplePayload(t))
	tooLarge := append(bytes.TrimRight(raw, "\n}"), []byte(strings.Repeat(" ", license.MaxFileSize)+"}")...)

	cases := map[string]struct {
		raw     []byte
		problem string
	}{
		"empty":                   {nil, "empty"},
		"over 64 KiB":             {tooLarge, "too_large"},
		"not JSON":                {[]byte("garbage"), "not_json"},
		"base64 text":             {[]byte("eyJmb3JtYXQiOjF9"), "not_json"},
		"array":                   {[]byte(`[1]`), "not_json"},
		"two documents":           {append(append([]byte(nil), raw...), raw...), "not_json"},
		"truncated":               {raw[:len(raw)-20], "not_json"},
		"invalid UTF-8":           {replaceOnce(t, raw, "Örnek", "\xffrnek"), "encoding"},
		"extra top-level field":   {replaceOnce(t, raw, `"format": 1,`, `"format": 1, "comment": "x",`), "fields"},
		"extra payload field":     {replaceOnce(t, raw, `"customer":`, `"discount": 1, "customer":`), "fields"},
		"duplicate top-level key": {replaceOnce(t, raw, `"format": 1,`, `"format": 1, "format": 1,`), "duplicate_key"},
		"duplicate payload key":   {replaceOnce(t, raw, `"max_targets": 10,`, `"max_targets": 10, "max_targets": 1000,`), "duplicate_key"},
		"missing signature":       {replaceOnce(t, raw, `"signature":`, `"signature_old":`), "fields"},
		"null payload":            {[]byte(`{"format":1,"key_id":"vk-2026-01","payload":null,"signature":"AA"}`), "missing_field"},
		"missing payload field":   {replaceOnce(t, raw, `"max_targets": 10,`, ``), "missing_field"},
		"number as string":        {replaceOnce(t, raw, `"max_targets": 10`, `"max_targets": "10"`), "fields"},
		"fractional number":       {replaceOnce(t, raw, `"max_targets": 10`, `"max_targets": 10.5`), "fields"},
		"offset timestamp":        {replaceOnce(t, raw, `"2026-09-29T09:00:00Z"`, `"2026-09-29T09:00:00+00:00"`), "timestamp"},
		"fractional timestamp":    {replaceOnce(t, raw, `"2026-09-29T09:00:00Z"`, `"2026-09-29T09:00:00.000Z"`), "timestamp"},
		"inner format differs":    {replaceOnce(t, raw, `"format": 1,`+"\n    \"installation_id\"", `"format": 2,`+"\n    \"installation_id\""), "format"},
		"outer format zero":       {replaceOnce(t, raw, `"format": 1,`+"\n  \"key_id\"", `"format": 0,`+"\n  \"key_id\""), "format"},
		"bad key id":              {replaceOnce(t, raw, `"vk-2026-01"`, `"../../etc"`), "key_id"},
		"short signature":         {[]byte(strings.Replace(string(raw), `"signature": "`, `"signature": "AAAA`, 1)), "signature_encoding"},
		"explicit empty replaces": {replaceOnce(t, raw, `"features": []`, `"features": [], "replaces": ""`), "replaces"},
		"explicit null replaces":  {replaceOnce(t, raw, `"features": []`, `"features": [], "replaces": null`), "replaces"},
		"case-variant duplicate":  {replaceOnce(t, raw, `"max_targets": 10,`, `"max_targets": 10, "MAX_TARGETS": 1000,`), "fields"},
		"case-variant only":       {replaceOnce(t, raw, `"max_targets"`, `"Max_Targets"`), "fields"},
		"case-variant top-level":  {replaceOnce(t, raw, `"key_id"`, `"Key_id"`), "fields"},
		"Kelvin sign key":         {replaceOnce(t, raw, `"key_id"`, "\"\u212aey_id\""), "fields"},
		"long s key":              {replaceOnce(t, raw, `"signature"`, "\"\u017fignature\""), "fields"},
		"deeply nested features":  {replaceOnce(t, raw, `"features": []`, `"features": [[[["x"]]]]`), "too_deep"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { requireInvalid(t, tc.raw, tc.problem) })
	}
}

// L-45: a newer format is not "invalid": the administrator is told to update Alice.
func TestParseReportsNewerFormats(t *testing.T) {
	raw := encodeSigned(t, samplePayload(t))
	newer := replaceOnce(t, raw, `"format": 1,`+"\n  \"key_id\"", `"format": 99,`+"\n  \"key_id\"")
	_, err := license.ParseFile(newer)
	require.ErrorIs(t, err, license.ErrUnsupportedFormat)
	assert.NotErrorIs(t, err, license.ErrInvalid)
}

// L-46, L-47 and the §16.3 step 5 rules.
func TestValidatePayload(t *testing.T) {
	cases := map[string]struct {
		change  func(p *license.Payload)
		problem string // "" = valid
	}{
		"sample":                        {func(*license.Payload) {}, ""},
		"unknown features are accepted": {func(p *license.Payload) { p.Features = []string{"future-edition", "x.y_z"} }, ""},
		"until before from":             {func(p *license.Payload) { p.ValidUntil = p.ValidFrom.Add(-time.Second) }, "validity"},
		"until equals from":             {func(p *license.Payload) { p.ValidUntil = p.ValidFrom }, ""},
		"zero targets":                  {func(p *license.Payload) { p.MaxTargets = 0 }, "max_targets"},
		"negative targets":              {func(p *license.Payload) { p.MaxTargets = -1 }, "max_targets"},
		"100000 targets":                {func(p *license.Payload) { p.MaxTargets = 100000 }, ""},
		"100001 targets":                {func(p *license.Payload) { p.MaxTargets = 100001 }, "max_targets"},
		"above one million targets":     {func(p *license.Payload) { p.MaxTargets = 1_000_001 }, "max_targets"},
		"issued 25 h after valid_from":  {func(p *license.Payload) { p.IssuedAt = p.ValidFrom.Add(25 * time.Hour) }, "issued_at"},
		"issued 24 h after valid_from":  {func(p *license.Payload) { p.IssuedAt = p.ValidFrom.Add(24 * time.Hour) }, ""},
		"issued long before valid_from": {func(p *license.Payload) { p.IssuedAt = p.ValidFrom.AddDate(-1, 0, 0) }, ""},
		"dates before 2000":             {func(p *license.Payload) { p.ValidFrom = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) }, "dates"},
		"bad installation id":           {func(p *license.Payload) { p.InstallationID = "ALICE-0000-0000-0000-0001" }, "installation_id"},
		"non-canonical installation id": {func(p *license.Payload) { p.InstallationID = lowerASCII(p.InstallationID) }, "installation_id"},
		"empty customer":                {func(p *license.Payload) { p.Customer = "" }, "customer"},
		"customer with a newline":       {func(p *license.Payload) { p.Customer = "Bank\nEvil: header" }, "customer"},
		"customer with outer spaces":    {func(p *license.Payload) { p.Customer = " Bank" }, "customer"},
		"customer 200 runes":            {func(p *license.Payload) { p.Customer = strings.Repeat("ş", 200) }, ""},
		"customer 201 runes":            {func(p *license.Payload) { p.Customer = strings.Repeat("ş", 201) }, "customer"},
		"bad license id":                {func(p *license.Payload) { p.LicenseID = "LIC 1" }, "license_id"},
		"replaces itself":               {func(p *license.Payload) { p.Replaces = p.LicenseID }, "replaces"},
		"bad feature":                   {func(p *license.Payload) { p.Features = []string{"Upper"} }, "features"},
		"33 features":                   {func(p *license.Payload) { p.Features = make([]string, 33) }, "features"},
		"invalid UTF-8 customer":        {func(p *license.Payload) { p.Customer = "Bank\xff" }, "customer"},
		"bidi control in customer":      {func(p *license.Payload) { p.Customer = "Bank\u202eevil" }, "customer"},
		"zero-width joiner in customer": {func(p *license.Payload) { p.Customer = "Ban\u200bk" }, "customer"},
		"valid_until after year 9999":   {func(p *license.Payload) { p.ValidUntil = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, "dates"},
		"issued_at after year 9999":     {func(p *license.Payload) { p.IssuedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, "dates"},
		"format 2":                      {func(p *license.Payload) { p.Format = 2 }, "format"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := samplePayload(t)
			tc.change(&p)
			err := p.Validate()
			if tc.problem == "" {
				require.NoError(t, err)
				return
			}
			var inv *license.InvalidError
			require.ErrorAs(t, err, &inv)
			assert.Equal(t, tc.problem, inv.Problem)
		})
	}
}

func TestSignRefusesInvalidPayloads(t *testing.T) {
	p := samplePayload(t)
	p.MaxTargets = 0
	_, err := license.Sign(fileTestKey, "vk-2026-01", p)
	require.ErrorIs(t, err, license.ErrInvalid)
	_, err = license.Sign(fileTestKey, "not a key id", samplePayload(t))
	require.ErrorIs(t, err, license.ErrInvalid)
}

func TestRejectReasonAndSuffix(t *testing.T) {
	assert.Equal(t, "invalid_signature", license.RejectReason(&license.InvalidError{Problem: "signature"}))
	assert.Equal(t, "invalid", license.RejectReason(&license.InvalidError{Problem: "fields"}))
	assert.Equal(t, "wrong_installation", license.RejectReason(&license.WrongInstallationError{Expected: "a", Got: "b"}))
	assert.Equal(t, "unsupported_format", license.RejectReason(license.ErrUnsupportedFormat))
	assert.Equal(t, "older_than_installed", license.RejectReason(license.ErrOlderThanInstalled))
	// The last six characters of the ID itself: group separators are not counted (L-43).
	assert.Equal(t, "41B8TC", license.IDSuffix("ALICE-7F3K-9Q2M-XD41-B8TC"))
	assert.Equal(t, "ABC", license.IDSuffix("ABC"))
	assert.ErrorIs(t, &license.TargetLimitError{Max: 10, Used: 10}, license.ErrTargetLimit)
}

func TestSignNormalizesTimes(t *testing.T) {
	p := samplePayload(t)
	p.IssuedAt = time.Date(2026, 9, 29, 12, 0, 0, 999_000_000, time.FixedZone("TRT", 3*3600))
	f, err := license.Sign(fileTestKey, "vk-2026-01", p)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC), f.Payload.IssuedAt)
	assert.True(t, ed25519.Verify(fileTestKey.Public().(ed25519.PublicKey), license.SignedBytes(f.Payload), f.Signature))
}

func TestReplacesRoundTrips(t *testing.T) {
	p := samplePayload(t)
	p.Replaces = "LIC-2026-000100"
	f, err := license.ParseFile(encodeSigned(t, p))
	require.NoError(t, err)
	assert.Equal(t, p, f.Payload)
}
