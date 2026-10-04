package license

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const hexDigits = "0123456789abcdef"

// maxCanonicalDepth bounds the nesting CanonicalJSON accepts (a newer format may nest deeper
// than format 1, but never without bound).
const maxCanonicalDepth = 16

// errNotCanonicalizable is returned by CanonicalJSON for input it cannot put in RFC 8785 form.
var errNotCanonicalizable = errors.New("license: the JSON value cannot be canonicalized")

// CanonicalJSON returns the RFC 8785 (JCS) form of one JSON value of any shape: object members
// sorted by UTF-16 code units, no whitespace, strings re-escaped as in appendJCSString and
// numbers in ECMAScript form. It refuses duplicate object keys, trailing data, nesting deeper
// than maxCanonicalDepth and numbers outside the IEEE 754 double range. For a format 1 payload
// it equals CanonicalPayload; a newer format's payload is verified against it (spec §16.2: the
// signed bytes are the domain separator and the canonical payload, unknown members included).
func CanonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	out, err := appendCanonical(nil, dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errNotCanonicalizable // trailing data after the value
	}
	return out, nil
}

func appendCanonical(b []byte, dec *json.Decoder, depth int) ([]byte, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, errNotCanonicalizable
	}
	switch v := tok.(type) {
	case json.Delim:
		if depth >= maxCanonicalDepth {
			return nil, errNotCanonicalizable
		}
		if v == '[' {
			b = append(b, '[')
			for i := 0; dec.More(); i++ {
				if i > 0 {
					b = append(b, ',')
				}
				if b, err = appendCanonical(b, dec, depth+1); err != nil {
					return nil, err
				}
			}
			if _, err := dec.Token(); err != nil { // the closing ']'
				return nil, errNotCanonicalizable
			}
			return append(b, ']'), nil
		}
		if v != '{' {
			return nil, errNotCanonicalizable
		}
		type member struct {
			key   string
			value []byte
		}
		var members []member
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			key, ok := kt.(string)
			if err != nil || !ok || seen[key] {
				return nil, errNotCanonicalizable
			}
			seen[key] = true
			value, err := appendCanonical(nil, dec, depth+1)
			if err != nil {
				return nil, err
			}
			members = append(members, member{key, value})
		}
		if _, err := dec.Token(); err != nil { // the closing '}'
			return nil, errNotCanonicalizable
		}
		sort.Slice(members, func(i, j int) bool { return utf16Less(members[i].key, members[j].key) })
		b = append(b, '{')
		for i, m := range members {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendJCSString(b, m.key)
			b = append(b, ':')
			b = append(b, m.value...)
		}
		return append(b, '}'), nil
	case string:
		return appendJCSString(b, v), nil
	case json.Number:
		return appendES6Number(b, v)
	case bool:
		return strconv.AppendBool(b, v), nil
	case nil:
		return append(b, "null"...), nil
	}
	return nil, errNotCanonicalizable
}

// appendES6Number appends n as ECMAScript's Number.prototype.toString renders the nearest double
// (RFC 8785 §3.2.2.3): the shortest round-trip digits, plain notation from 1e-6 up to below
// 1e21, exponent notation ("1e+21", "1.5e-7") outside it, and "0" for negative zero.
func appendES6Number(b []byte, n json.Number) ([]byte, error) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, errNotCanonicalizable
	}
	if f == 0 {
		return append(b, '0'), nil
	}
	if f < 0 {
		b = append(b, '-')
		f = -f
	}
	// "d.ddde±x": the shortest digits and the decimal exponent.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expPart, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, err := strconv.Atoi(expPart)
	if err != nil {
		return nil, errNotCanonicalizable
	}
	k, pos := len(digits), exp+1 // the value is 0.digits × 10^pos
	switch {
	case k <= pos && pos <= 21:
		b = append(b, digits...)
		return append(b, strings.Repeat("0", pos-k)...), nil
	case 0 < pos && pos <= 21:
		b = append(b, digits[:pos]...)
		b = append(b, '.')
		return append(b, digits[pos:]...), nil
	case -6 < pos && pos <= 0:
		b = append(b, "0."...)
		b = append(b, strings.Repeat("0", -pos)...)
		return append(b, digits...), nil
	}
	b = append(b, digits[0])
	if k > 1 {
		b = append(b, '.')
		b = append(b, digits[1:]...)
	}
	b = append(b, 'e')
	if pos-1 >= 0 {
		b = append(b, '+')
	}
	return strconv.AppendInt(b, int64(pos-1), 10), nil
}

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
