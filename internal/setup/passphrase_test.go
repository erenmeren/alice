package setup_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/unicode/norm"

	"alice/internal/platform/validate"
	"alice/internal/setup"
)

// The strength is rated on the NFKC text the key is derived from, and anything below good is refused
// (review I-1): a compatibility form that NFKC lengthens must not slip through as "tooShort".
func TestCheckPassphraseRatesTheNormalisedText(t *testing.T) {
	cases := []struct {
		name, pass string
		want       error
	}{
		{"ligatures lengthen to one fair word", "ﬃﬃﬃﬃﬃﬄ", setup.ErrPassphraseTooWeak},
		{"square MHz lengthens to a fair word", strings.Repeat("㎒", 6), setup.ErrPassphraseTooWeak},
		{"roman numerals lengthen to a fair word", strings.Repeat("ⅻ", 6), setup.ErrPassphraseTooWeak},
		{"fullwidth letters fold to a fair ASCII word", strings.Repeat("ａ", 16), setup.ErrPassphraseTooWeak},
		{"Turkish dotless i alone is fair", strings.Repeat("ı", 16), setup.ErrPassphraseTooWeak},
		{"Turkish dotted capital I alone is fair", strings.Repeat("İ", 16), setup.ErrPassphraseTooWeak},
		{"Turkish words are good", "ılık İstanbul akşamı ıhlamur", nil},
		{"Turkish mixed classes are good", "İıİı1234abcdABCD", nil},
		{"square MHz lengthens to a good passphrase", strings.Repeat("㎒", 8), nil},
		{"plain fair", "aaaaaaaaaaaaaaaa", setup.ErrPassphraseTooWeak},
		{"plain good", "Abcdefgh12345678", nil},
		{"short after NFKC", "ﬃﬃﬃﬃﬃ", setup.ErrPassphraseTooShort},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := setup.CheckPassphrase(c.pass, c.pass)
			if c.want == nil {
				require.NoError(t, got, "NFKC %q rates %s", norm.NFKC.String(c.pass), setup.PassphraseStrength(norm.NFKC.String(c.pass)))
				return
			}
			require.ErrorIs(t, got, c.want)
		})
	}
}

func TestCheckPassphraseLimitsAndConfirmation(t *testing.T) {
	require.ErrorIs(t, setup.CheckPassphrase("Abcdefgh12345678", "Abcdefgh12345679"), setup.ErrPassphraseMismatch)
	require.NoError(t, setup.CheckPassphrase("Abcdefgh12345678", "Abcdefgh12345678"))
	require.NoError(t, setup.CheckPassphrase("ｱbcdefgh12345678", "アbcdefgh12345678"), "compared after NFKC")
	var v validate.Errors
	assert.ErrorAs(t, setup.CheckPassphrase(strings.Repeat("Ab1 ", 257), strings.Repeat("Ab1 ", 257)), &v)
}
