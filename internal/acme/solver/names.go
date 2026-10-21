package solver

import (
	"errors"
	"strings"
)

// The name rules every DNS-01 solver applies before it sends anything (the hook solver and the DNS provider
// solvers of R57): one rule, so a hook and a provider can never disagree about which names they publish.

// ChallengeLabel is the label a DNS-01 record is published under (RFC 8555 section 8.4).
const ChallengeLabel = "_acme-challenge."

// MaxDNSValueBytes bounds a DNS-01 TXT value a solver accepts (the real value is 43 bytes).
const MaxDNSValueBytes = 512

// ErrSuffix is the error of a suffix list entry that is not a DNS suffix.
var ErrSuffix = errors.New("solver: an allowed suffix is not a DNS suffix")

// NormalizeDomain lower-cases a challenge domain (ASCII only), strips "*." and a trailing dot and checks its
// characters: letters, digits and hyphens in labels of 1 to 63 bytes, no label starting or ending with a hyphen,
// short enough that ChallengeLabel + the domain is a valid name.
func NormalizeDomain(d string) (string, bool) {
	d = strings.TrimSuffix(strings.TrimPrefix(ASCIILower(d), "*."), ".")
	if d == "" || len(d) > 253-len(ChallengeLabel) {
		return "", false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	return d, true
}

// Suffixes is a normalized allow-list of DNS names. "example.com" admits example.com and every name below it;
// ".example.com" admits only the names below it. An empty list admits nothing.
type Suffixes []string

// ParseSuffixes normalizes an allow-list (ErrSuffix for an entry that is not a DNS suffix: a wildcard, a trailing
// dot or an invalid name).
func ParseSuffixes(raw []string) (Suffixes, error) {
	out := make(Suffixes, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		dot := strings.HasPrefix(r, ".")
		d, ok := NormalizeDomain(strings.TrimPrefix(r, "."))
		if !ok || strings.HasPrefix(r, "*") || strings.HasSuffix(r, ".") {
			return nil, ErrSuffix
		}
		if dot {
			d = "." + d
		}
		out = append(out, d)
	}
	return out, nil
}

// Allows reports whether the normalized domain d is admitted.
func (s Suffixes) Allows(d string) bool {
	for _, sf := range s {
		if strings.HasPrefix(sf, ".") {
			if strings.HasSuffix(d, sf) {
				return true
			}
		} else if d == sf || strings.HasSuffix(d, "."+sf) {
			return true
		}
	}
	return false
}

// PrintableValue reports a TXT value of visible ASCII characters only (no space), of 1 to MaxDNSValueBytes bytes.
func PrintableValue(v string) bool {
	if v == "" || len(v) > MaxDNSValueBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// ASCIILower lower-cases ASCII letters only (DNS names are case-insensitive in ASCII, and nothing else is valid in
// them; strings.ToLower is banned in this repository: Turkish İ/ı, Kelvin sign).
func ASCIILower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
