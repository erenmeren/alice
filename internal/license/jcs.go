package license

import (
	"sort"
	"strconv"
	"time"
	"unicode/utf16"
)

const hexDigits = "0123456789abcdef"

// appendJCSString appends s as an RFC 8785 string: only '"', '\\' and control
// characters are escaped (\b \t \n \f \r, the others as \u00xx in lower case);
// every other character, including non-ASCII, is written as UTF-8.
func appendJCSString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b = append(b, '\\', '"')
		case c == '\\':
			b = append(b, '\\', '\\')
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\t':
			b = append(b, '\\', 't')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// utf16Less orders object keys by UTF-16 code units (RFC 8785 §3.2.3).
func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// formatTime renders an instant the only way the format allows: RFC 3339, UTC, "Z", whole seconds.
func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// CanonicalPayload returns the RFC 8785 (JCS) form of p: members sorted by key, no
// whitespace, integers in decimal. "replaces" is present only when set (spec §16.2).
func CanonicalPayload(p Payload) []byte {
	type member struct {
		key   string
		value []byte
	}
	str := func(s string) []byte { return appendJCSString(nil, s) }
	features := []byte{'['}
	for i, f := range p.Features {
		if i > 0 {
			features = append(features, ',')
		}
		features = appendJCSString(features, f)
	}
	features = append(features, ']')

	members := []member{
		{"customer", str(p.Customer)},
		{"features", features},
		{"format", []byte(strconv.Itoa(p.Format))},
		{"installation_id", str(p.InstallationID)},
		{"issued_at", str(formatTime(p.IssuedAt))},
		{"license_id", str(p.LicenseID)},
		{"max_targets", []byte(strconv.Itoa(p.MaxTargets))},
		{"valid_from", str(formatTime(p.ValidFrom))},
		{"valid_until", str(formatTime(p.ValidUntil))},
	}
	if p.Replaces != "" {
		members = append(members, member{"replaces", str(p.Replaces)})
	}
	sort.Slice(members, func(i, j int) bool { return utf16Less(members[i].key, members[j].key) })

	out := []byte{'{'}
	for i, m := range members {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendJCSString(out, m.key)
		out = append(out, ':')
		out = append(out, m.value...)
	}
	return append(out, '}')
}
