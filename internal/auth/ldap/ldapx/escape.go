package ldapx

import (
	"strings"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

func writeHex(b *strings.Builder, c byte) {
	b.WriteByte('\\')
	b.WriteByte(hexDigits[c>>4])
	b.WriteByte(hexDigits[c&0x0f])
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// EscapeFilter escapes s for use as an assertion value in an RFC 4515 search filter. The characters RFC 4515 names
// ( ) * \ and NUL become \xx, and so do the other ASCII control characters, every byte that is not part of valid
// UTF-8 and the replacement character U+FFFD (go-ldap refuses it in a filter value). Everything else is kept.
// The result contains no byte that can end the value or change the structure of the filter around it.
func EscapeFilter(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError, r < 0x20, r == 0x7f, r == '(', r == ')', r == '*', r == '\\':
			// A RuneError of size 1 is an invalid byte; of size 3 it is U+FFFD itself. Both go out byte by byte.
			for j := range size {
				writeHex(&b, s[i+j])
			}
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// EscapeDN escapes s for use as an attribute value in an RFC 4514 distinguished name. The characters RFC 4514
// section 2.4 requires (" + , ; < > \) get a backslash, as do = (allowed by the "special" production; a lax parser
// cannot then read a new attribute type), a leading # or space and a trailing space. NUL, the other ASCII control
// characters, DEL and bytes that are not part of valid UTF-8 become \xx.
func EscapeDN(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1, r < 0x20, r == 0x7f:
			writeHex(&b, s[i])
		case r == '"', r == '+', r == ',', r == ';', r == '<', r == '>', r == '\\', r == '=',
			r == '#' && i == 0, r == ' ' && (i == 0 || i == len(s)-1):
			b.WriteByte('\\')
			b.WriteByte(s[i])
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}
