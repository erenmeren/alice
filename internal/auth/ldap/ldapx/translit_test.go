package ldapx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The explicit table keeps the case of the letter: Turkish dotted and dotless i both ways, then common Latin
// accents. Characters outside the table stay as they are.
func TestTransliterate(t *testing.T) {
	cases := map[string]string{
		"çğıöşü":           "cgiosu",
		"ÇĞİÖŞÜ":           "CGIOSU",
		"ı":                "i",
		"I":                "I",
		"İ":                "I",
		"i":                "i",
		"ÇİĞDEM":           "CIGDEM",
		"Şeref Üstün":      "Seref Ustun",
		"Iİıi":             "IIii",
		"Ålesund Ærø":      "Alesund AEro",
		"Straße":           "Strasse",
		"François Lefèvre": "Francois Lefevre",
		"Łódź Žižka":       "Lodz Zizka",
		"Ñoño œuvre":       "Nono oeuvre",
		"Þór Ðóra":         "THor Dora",
		"Ĳssel ĳs":         "IJssel ijs",
		"plain-ascii_1.@":  "plain-ascii_1.@",
		"Ωmega 日本":         "Ωmega 日本",
		"":                 "",
		"a\xffb":           "a\xffb",
	}
	for in, want := range cases {
		assert.Equal(t, want, Transliterate(in), "%q", in)
	}
}

// Every table entry maps to ASCII letters only, and every source is a single non-ASCII rune.
func TestTransliterateTableIsASCII(t *testing.T) {
	for r, out := range translit {
		assert.Greater(t, r, rune(0x7f), "%q", r)
		assert.NotEmpty(t, out)
		for _, c := range out {
			assert.True(t, (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'), "%q -> %q", r, out)
		}
	}
}
