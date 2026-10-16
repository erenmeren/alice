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
		{"Turkish mixed classes are good", "İıİı1357acegACEG", nil},
		{"square Hz units lengthen to a good passphrase", "㎒㎓㎔㎑2026", nil},
		{"plain fair", "aaaaaaaaaaaaaaaa", setup.ErrPassphraseTooWeak},
		{"plain good", "one two three fo", nil},
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
	require.ErrorIs(t, setup.CheckPassphrase("one two three fo", "one two three fx"), setup.ErrPassphraseMismatch)
	require.NoError(t, setup.CheckPassphrase("one two three fo", "one two three fo"))
	require.NoError(t, setup.CheckPassphrase("ｱkedi Elma 2026 x", "アkedi Elma 2026 x"), "compared after NFKC")
	var v validate.Errors
	assert.ErrorAs(t, setup.CheckPassphrase(strings.Repeat("Ab1 ", 257), strings.Repeat("Ab1 ", 257)), &v)
}
