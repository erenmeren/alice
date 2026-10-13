package acme

import (
	"strings"
)

// MaxNames is the most names one order may hold (Let's Encrypt's limit).
const MaxNames = 100

// NormalizeNames checks and lower-cases the names of an order: 1..MaxNames DNS names (ASCII; IDNs in their
// xn-- form), each of 2..127 labels of 1..63 letters, digits or hyphens (no leading or trailing hyphen), at
// most 253 characters, the last label not all digits (no IP addresses), "*." allowed only as the whole first
// label, no duplicates. The error is an *Error with ReasonIdentifierRefused and the offending name.
func NormalizeNames(names []string) ([]string, error) {
	if len(names) == 0 || len(names) > MaxNames {
		return nil, &Error{Reason: ReasonIdentifierRefused, cause: ErrInvalidName}
	}
	out := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		l := asciiLower(strings.TrimSuffix(n, "."))
		if !validName(l) || seen[l] {
			return nil, &Error{Reason: ReasonIdentifierRefused, Identifier: safeIdentifier(n), cause: ErrInvalidName}
		}
		seen[l] = true
		out = append(out, l)
	}
	return out, nil
}

func validName(n string) bool {
	base := strings.TrimPrefix(n, "*.")
	if len(n) > 253 || base == "" {
		return false
	}
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// safeIdentifier keeps a refused name printable and short for an error text.
func safeIdentifier(n string) string {
	var b strings.Builder
	for i := 0; i < len(n) && b.Len() < 64; i++ {
		c := n[i]
		if c >= 0x21 && c < 0x7f {
			b.WriteByte(c)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

// asciiLower lower-cases ASCII letters only (the Turkish dotted/dotless i never matters).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func isWildcard(n string) bool { return strings.HasPrefix(n, "*.") }
