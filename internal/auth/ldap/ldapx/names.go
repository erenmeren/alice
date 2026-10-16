package ldapx

import (
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
)

// ErrUniqueID is a unique id attribute value that is empty or longer than MaxUniqueIDBytes.
var ErrUniqueID = errors.New("ldapx: the unique id is empty or too long")

const (
	// MaxUniqueIDBytes bounds the raw unique id: its hex form (2 to 254 characters) is what Alice stores.
	MaxUniqueIDBytes = 127
	// MaxLoginRunes bounds a sign-in name typed by a person.
	MaxLoginRunes = 256
	maxUsername   = 64
	fallbackHex   = 12
)

// UniqueID turns the raw bytes of the unique id attribute (AD objectGUID: 16 binary bytes; OpenLDAP entryUUID: an
// ASCII string) into lower-case hex. The identity of a directory user is this value, never the name.
func UniqueID(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > MaxUniqueIDBytes {
		return "", ErrUniqueID
	}
	return hex.EncodeToString(raw), nil
}

// mappedToNothing are the code points RFC 3454 table B.1 maps to nothing (string preparation, also RFC 4518 2.2): a
// directory ignores them when it compares names, so a name carrying one would be another spelling of the same
// account. Some are format characters (Cf) and refused anyway; the others are combining or Mongolian marks.
var mappedToNothing = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x00ad, Hi: 0x00ad, Stride: 1}, {Lo: 0x034f, Hi: 0x034f, Stride: 1}, {Lo: 0x1806, Hi: 0x1806, Stride: 1},
		{Lo: 0x180b, Hi: 0x180d, Stride: 1}, {Lo: 0x200b, Hi: 0x200d, Stride: 1}, {Lo: 0x2060, Hi: 0x2060, Stride: 1},
		{Lo: 0xfe00, Hi: 0xfe0f, Stride: 1}, {Lo: 0xfeff, Hi: 0xfeff, Stride: 1},
	},
	R32: []unicode.Range32{{Lo: 0xe0100, Hi: 0xe01ef, Stride: 1}},
}

// ValidLoginName reports whether s may be sent to the directory as a sign-in name: valid UTF-8, 1 to MaxLoginRunes
// runes, no control character (which includes NUL), no format character (Cf: soft hyphen, zero-width characters,
// bidi overrides, BOM), no code point RFC 3454 table B.1 maps to nothing (variation selectors, the combining
// grapheme joiner, Mongolian free variation selectors and vowel separator), no line or paragraph separator, and no
// white space at either end (so not all white space). A directory server's string preparation (RFC 4518) maps such
// characters to nothing or to a space, so they would only make another spelling of the same name.
func ValidLoginName(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxLoginRunes {
		return false
	}
	first, _ := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, mappedToNothing) {
			return false
		}
	}
	return true
}

// Username derives an Alice user name from the sign-in name of a directory user: the explicit transliteration
// table, then case folding through golang.org/x/text/cases, then the character set of claims.Username (a-z 0-9 . _
// - @, others dropped; A-Z cannot remain after folding), trimmed of . _ - @ at both ends and cut to 64 bytes. Unlike claims.Username, a result of
// fewer than two characters is not used (Alice user names have at least two). The fallback is "ldap-" and the
// first 12 hex digits of uniqueID (lower-cased; other characters ignored), or "ldap-user" when it has none.
func Username(login, uniqueID string) string {
	folded := cases.Fold().String(Transliterate(login))
	var b strings.Builder
	for _, r := range folded {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == '@':
			b.WriteRune(r)
		}
	}
	s := strings.Trim(b.String(), ".-_@")
	if len(s) > maxUsername {
		s = strings.TrimRight(s[:maxUsername], ".-_@")
	}
	if len(s) >= 2 {
		return s
	}
	return fallbackUsername(uniqueID)
}

func fallbackUsername(uniqueID string) string {
	var b strings.Builder
	for i := 0; i < len(uniqueID) && b.Len() < fallbackHex; i++ {
		c := uniqueID[i]
		switch {
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'):
			b.WriteByte(c)
		case c >= 'A' && c <= 'F':
			b.WriteByte(c + ('a' - 'A'))
		}
	}
	if b.Len() == 0 {
		return "ldap-user"
	}
	return "ldap-" + b.String()
}
