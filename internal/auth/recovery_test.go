package auth

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

var recoveryRE = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$`)

func TestGenerateRecoveryCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 20 {
		codes := GenerateRecoveryCodes()
		assert.Len(t, codes, 10)
		for _, c := range codes {
			assert.Regexp(t, recoveryRE, c)
			assert.False(t, seen[c], "duplicate recovery code %s", c)
			seen[c] = true
			assert.Equal(t, NormalizeRecoveryCode(c), NormalizeRecoveryCode(NormalizeRecoveryCode(c)))
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	cases := map[string]string{
		"ABCD-EFGH-JKMN-PQRS":   "ABCDEFGHJKMNPQRS",
		"abcd efgh jkmn pqrs":   "ABCDEFGHJKMNPQRS",
		" abcd-EFGH-jkmn-PQRS ": "ABCDEFGHJKMNPQRS",
		"O0O0-IiLl-1111-0000":   "0000111111110000",
		"oooo-iiii-llll-2345":   "0000111111112345",
		"\tAB-CD\t":             "ABCD",
	}
	for in, want := range cases {
		assert.Equal(t, want, NormalizeRecoveryCode(in), "%q", in)
	}
}
