package ldapx

import (
	"strings"
	"unicode/utf8"
)

// translitGroups lists the letters of the table: the lower-case sources, their upper-case partners in the same
// order, and the ASCII replacement of each side. Turkish comes first; the dotless ı and the dotted İ have no partner
// of their own in Turkish (ı pairs with I, İ with i), so they stand alone.
var translitGroups = []struct{ lower, upper, toLower, toUpper string }{
	// Turkish.
	{"ç", "Ç", "c", "C"}, {"ğ", "Ğ", "g", "G"}, {"ö", "Ö", "o", "O"}, {"ş", "Ş", "s", "S"}, {"ü", "Ü", "u", "U"},
	{"ı", "", "i", ""}, {"", "İ", "", "I"},
	// Common Latin accents (Latin-1 Supplement and Latin Extended-A, plus the comma-below letters of Romanian).
	{"àáâãäåāăą", "ÀÁÂÃÄÅĀĂĄ", "a", "A"},
	{"æ", "Æ", "ae", "AE"},
	{"ćĉċč", "ĆĈĊČ", "c", "C"},
	{"ďđð", "ĎĐÐ", "d", "D"},
	{"èéêëēĕėęě", "ÈÉÊËĒĔĖĘĚ", "e", "E"},
	{"ĝġģ", "ĜĠĢ", "g", "G"},
	{"ĥħ", "ĤĦ", "h", "H"},
	{"ìíîïĩīĭį", "ÌÍÎÏĨĪĬĮ", "i", "I"},
	{"ĳ", "Ĳ", "ij", "IJ"},
	{"ĵ", "Ĵ", "j", "J"},
	{"ķ", "Ķ", "k", "K"},
	{"ĺļľŀł", "ĹĻĽĿŁ", "l", "L"},
	{"ñńņňŉ", "ÑŃŅŇ", "n", "N"},
	{"òóôõøōŏő", "ÒÓÔÕØŌŎŐ", "o", "O"},
	{"œ", "Œ", "oe", "OE"},
	{"ŕŗř", "ŔŖŘ", "r", "R"},
	{"śŝšș", "ŚŜŠȘ", "s", "S"},
	{"ß", "ẞ", "ss", "SS"},
	{"ţťŧț", "ŢŤŦȚ", "t", "T"},
	{"ùúûũūŭůűų", "ÙÚÛŨŪŬŮŰŲ", "u", "U"},
	{"ŵ", "Ŵ", "w", "W"},
	{"ýÿŷ", "ÝŸŶ", "y", "Y"},
	{"źżž", "ŹŻŽ", "z", "Z"},
	{"þ", "Þ", "th", "TH"},
}

// translit maps each non-ASCII letter of the table to its ASCII replacement.
var translit = buildTranslit()

func buildTranslit() map[rune]string {
	m := map[rune]string{}
	for _, g := range translitGroups {
		for _, r := range g.lower {
			m[r] = g.toLower
		}
		for _, r := range g.upper {
			m[r] = g.toUpper
		}
	}
	return m
}

// Transliterate replaces the letters of an explicit table (Turkish ç ğ ı İ ö ş ü and their capitals, and the
// common Latin accents) with ASCII, keeping the case: İ becomes I, ı becomes i. Every other character, including
// bytes that are not valid UTF-8, is kept as it is. It never uses a locale-dependent case mapping.
func Transliterate(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if out, ok := translit[r]; ok {
			b.WriteString(out)
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}
