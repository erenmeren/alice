package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPasswordPolicy(t *testing.T) {
	cases := map[string]error{
		strings.Repeat("a", 11) + "Z":  nil,                 // 12 runes
		"kısa-parola":                  ErrPasswordTooShort, // 11 runes, multi-byte
		strings.Repeat("ğ", 12):        nil,                 // 12 runes, 24 bytes
		strings.Repeat("x", 128):       nil,
		strings.Repeat("x", 129):       ErrPasswordTooLong,
		"qwerty123456":                 ErrPasswordBreached,
		"passwordpassword":             ErrPasswordBreached,
		"correct horse battery staple": nil,
	}
	for pw, want := range cases {
		if want == nil {
			assert.NoError(t, CheckPasswordPolicy(pw), pw)
		} else {
			assert.ErrorIs(t, CheckPasswordPolicy(pw), want, pw)
		}
	}
}

func TestPasswordPolicyNormalizesNFKC(t *testing.T) {
	fullwidth := "１２３４５６７８９０１２" // full-width digits normalize to "123456789012"
	assert.Equal(t, "123456789012", NormalizePassword(fullwidth))
	assert.ErrorIs(t, CheckPasswordPolicy(fullwidth), ErrPasswordBreached)
	assert.Equal(t, "fi", NormalizePassword("ﬁ"), "ligatures are decomposed")
}
