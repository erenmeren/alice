package ldapx

import (
	"strings"
	"testing"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 4515 section 4 examples and the characters it names: ( ) * \ and NUL become \xx.
func TestEscapeFilterRFCExamples(t *testing.T) {
	cases := map[string]string{
		"": "",
		"Parens R Us (for all your parenthetical needs)": `Parens R Us \28for all your parenthetical needs\29`,
		"*":                  `\2a`,
		`C:\MyFile`:          `C:\5cMyFile`,
		"\x00\x00\x00\x04":   `\00\00\00\04`, // control characters are escaped as well (allowed, keeps logs readable)
		"tab\there\x7f":      `tab\09here\7f`,
		"Lu\u010di\u0107":    "Lu\u010di\u0107", // valid UTF-8 stays as it is
		"ada.yilmaz":         "ada.yilmaz",
		"*)(uid=*))(|(uid=*": `\2a\29\28uid=\2a\29\29\28|\28uid=\2a`,
		"admin)(&":           `admin\29\28&`,
		"x\\2a":              `x\5c2a`,
	}
	for in, want := range cases {
		assert.Equal(t, want, EscapeFilter(in), "%q", in)
	}
}

// Bytes that are not valid UTF-8 are escaped one by one, and so is U+FFFD, which go-ldap refuses in a filter value.
func TestEscapeFilterInvalidUTF8(t *testing.T) {
	assert.Equal(t, `a\ffb`, EscapeFilter("a\xffb"))
	assert.Equal(t, `\c3`, EscapeFilter("\xc3"))
	assert.Equal(t, `\e2\82`, EscapeFilter("\xe2\x82"))
	assert.Equal(t, `\ef\bf\bd`, EscapeFilter("\uFFFD"))
	for _, s := range []string{"a\xffb", "\xc3(", "\uFFFD", "ç*\x00"} {
		_, err := ldap.CompileFilter("(cn=" + EscapeFilter(s) + ")")
		require.NoError(t, err, "%q", s)
	}
}

// The escaped value compiles to exactly one equality condition whose value is the original bytes.
func TestEscapeFilterRoundTripsThroughGoLDAP(t *testing.T) {
	for _, s := range []string{"*)(uid=*))(|(uid=*", "a\x00b", "\\", "()", "Çiğdem Öztürk", "a\xff\xfe", "=*~><:"} {
		p, err := ldap.CompileFilter("(cn=" + EscapeFilter(s) + ")")
		require.NoError(t, err, "%q", s)
		require.Equal(t, ldap.FilterEqualityMatch, int(p.Tag), "%q", s)
		require.Len(t, p.Children, 2)
		assert.Equal(t, s, p.Children[1].Data.String(), "%q", s)
	}
}

// RFC 4514 section 2.4: , + " \ < > ; are escaped; a leading # or space and a trailing space are escaped; NUL is
// \00. = is escaped too (allowed by the "special" production) so that a lax parser cannot read a new type.
func TestEscapeDNRFCCases(t *testing.T) {
	cases := map[string]string{
		"":             "",
		"Sales":        "Sales",
		"Smith, John":  `Smith\, John`,
		"a+b":          `a\+b`,
		`say "hi"`:     `say \"hi\"`,
		`back\slash`:   `back\\slash`,
		"<tag>":        `\<tag\>`,
		"a;b":          `a\;b`,
		"a=b":          `a\=b`,
		"#hash":        `\#hash`,
		"mid#hash":     "mid#hash",
		" lead":        `\ lead`,
		"trail ":       `trail\ `,
		"in side":      "in side",
		" ":            `\ `,
		"  ":           `\ \ `,
		"a\x00b":       `a\00b`,
		"Çiğdem":       "Çiğdem",
		"a\xffb":       `a\ffb`,
		",+\"\\<>;=":   `\,\+\"\\\<\>\;\=`,
		"cn=x,dc=evil": `cn\=x\,dc\=evil`,
	}
	for in, want := range cases {
		assert.Equal(t, want, EscapeDN(in), "%q", in)
	}
}

// An escaped value parses back, with go-ldap, to one RDN of one attribute holding the original value.
func TestEscapeDNRoundTripsThroughGoLDAP(t *testing.T) {
	for _, s := range []string{"Smith, John", " lead", "trail ", "  two  ", "#x", "a\x00b", "cn=x,dc=evil", `\`, "x+y=z",
		"Çiğdem Öztürk", "a\xffb", "\"quoted\""} {
		dn, err := ldap.ParseDN("cn=" + EscapeDN(s) + ",dc=example,dc=com")
		require.NoError(t, err, "%q", s)
		require.Len(t, dn.RDNs, 3, "%q", s)
		require.Len(t, dn.RDNs[0].Attributes, 1, "%q", s)
		assert.Equal(t, s, dn.RDNs[0].Attributes[0].Value, "%q", s)
	}
}

// unescapedFilterSpecial reports the first byte of an escaped filter value that would end or change the value.
func unescapedFilterSpecial(s string) (int, bool) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', ')', '*', 0:
			return i, true
		case '\\':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return i, true
			}
			i += 2
		}
	}
	return 0, !utf8.ValidString(s) || strings.ContainsRune(s, utf8.RuneError)
}
