package auth

import (
	"crypto/rand"
	"strings"
)

// RecoveryCodeCount is how many single-use recovery codes a user gets (SEC-008).
const RecoveryCodeCount = 10

// crockford is Crockford's base32 alphabet (no I, L, O, U), easy to read aloud.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// GenerateRecoveryCodes returns 10 codes of 80 random bits each, formatted as
// "XXXX-XXXX-XXXX-XXXX" in Crockford base32. They are shown once and stored hashed.
func GenerateRecoveryCodes() []string {
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		codes[i] = newRecoveryCode()
	}
	return codes
}

func newRecoveryCode() string {
	var raw [10]byte
	_, _ = rand.Read(raw[:]) // never returns an error since Go 1.24
	// 80 bits = 16 groups of 5 bits.
	var sb strings.Builder
	var acc uint64
	var bits uint
	n := 0
	for _, b := range raw {
		acc = acc<<8 | uint64(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			if n > 0 && n%4 == 0 {
				sb.WriteByte('-')
			}
			sb.WriteByte(crockford[(acc>>bits)&31])
			n++
		}
	}
	return sb.String()
}

// NormalizeRecoveryCode makes typed codes comparable: spaces and dashes are
// removed, ASCII letters upper-cased (byte-wise, locale-independent), and the
// look-alikes O→0, I→1, L→1 mapped as Crockford base32 prescribes.
func NormalizeRecoveryCode(s string) string {
	var sb strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '-' || c == '\t':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		switch c {
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		sb.WriteByte(c)
	}
	return sb.String()
}
