package license

import (
	"crypto/rand"
	"strings"
)

// crockford is the Crockford base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// installationIDLen is the number of symbols: 15 random ones (75 bits) and one check symbol.
const installationIDLen = 16

// NewInstallationID returns a random installation ID "ALICE-XXXX-XXXX-XXXX-XXXX" (spec §16.4, R7).
// The last symbol is a Luhn mod 32 check character, so a mistyped symbol or two swapped
// neighbours are detected when the customer emails the ID to the vendor.
func NewInstallationID() string {
	var raw [installationIDLen - 1]byte
	rand.Read(raw[:])
	vals := make([]int, 0, installationIDLen)
	for _, b := range raw {
		vals = append(vals, int(b&31)) // 256 is a multiple of 32: uniform
	}
	vals = append(vals, luhnCheck(vals))
	return formatID(vals)
}

// ParseInstallationID accepts an ID the way a person may type it — any case, with or
// without the ALICE prefix, dashes or spaces between groups, O for 0 and I or L for 1
// (Crockford decoding) — and returns the canonical form. It returns
// ErrInvalidInstallationID when the length, a symbol or the check character is wrong.
func ParseInstallationID(s string) (string, error) {
	body := strings.TrimSpace(s)
	if len(body) >= 5 && strings.EqualFold(body[:5], "ALICE") {
		body = body[5:]
	}
	vals := make([]int, 0, installationIDLen)
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c == '-' || c == ' ' {
			continue
		}
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		switch c {
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		idx := strings.IndexByte(crockford, c)
		if idx < 0 {
			return "", ErrInvalidInstallationID
		}
		vals = append(vals, idx)
	}
	if len(vals) != installationIDLen || !luhnValid(vals) {
		return "", ErrInvalidInstallationID
	}
	return formatID(vals), nil
}

func formatID(vals []int) string {
	var b strings.Builder
	b.WriteString("ALICE")
	for i, v := range vals {
		if i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(crockford[v])
	}
	return b.String()
}

// luhnCheck computes the Luhn mod 32 check value for body (factor 2 on the rightmost symbol).
func luhnCheck(body []int) int {
	factor, sum := 2, 0
	for i := len(body) - 1; i >= 0; i-- {
		addend := factor * body[i]
		sum += addend/32 + addend%32
		factor = 3 - factor
	}
	return (32 - sum%32) % 32
}

// luhnValid checks a sequence that ends with its check value.
func luhnValid(all []int) bool {
	factor, sum := 1, 0
	for i := len(all) - 1; i >= 0; i-- {
		addend := factor * all[i]
		sum += addend/32 + addend%32
		factor = 3 - factor
	}
	return sum%32 == 0
}
