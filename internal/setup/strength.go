package setup

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Strength is the rating of a recovery passphrase.
type Strength string

// Ratings, as web/src/pages/setup/strength.ts names them.
const (
	StrengthTooShort Strength = "tooShort"
	StrengthFair     Strength = "fair"
	StrengthGood     Strength = "good"
	StrengthStrong   Strength = "strong"
)

// PassphraseStrength rates p with the rules of web/src/pages/setup/strength.ts, rune for rune, so the
// browser's meter and the server agree (testdata/strength.json drives both tests):
//   - the length is the number of Unicode code points ([...p].length);
//   - the classes are [a-z], [A-Z] and [0-9] (ASCII only) and "other": any rune that is not an ASCII letter
//     or digit and not JavaScript white space (/[^A-Za-z0-9\s]/);
//   - the words are p.trim().split(/\s+/), JavaScript's \s being Unicode Zs plus TAB, LF, VT, FF, CR, U+2028,
//     U+2029 and U+FEFF (and not U+0085, which Go's unicode.IsSpace includes);
//   - score = (length ≥ 20) + (length ≥ 28) + (classes ≥ 3 or words ≥ 4): 2 or more strong, 1 good, 0 fair.
func PassphraseStrength(p string) Strength {
	length := utf8.RuneCountInString(p)
	if length < MinPassphraseLength {
		return StrengthTooShort
	}
	var lower, upper, digit, other bool
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		case !jsSpace(r):
			other = true
		}
	}
	classes := 0
	for _, has := range []bool{lower, upper, digit, other} {
		if has {
			classes++
		}
	}
	words := max(len(strings.FieldsFunc(p, jsSpace)), 1) // "".split(/\s+/) is [""]
	score := 0
	for _, ok := range []bool{length >= 20, length >= 28, classes >= 3 || words >= 4} {
		if ok {
			score++
		}
	}
	switch {
	case score >= 2:
		return StrengthStrong
	case score == 1:
		return StrengthGood
	}
	return StrengthFair
}

// jsSpace reports whether JavaScript's \s matches r (ECMAScript WhiteSpace and LineTerminator).
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', 0x2028, 0x2029, 0xFEFF:
		return true
	}
	return unicode.Is(unicode.Zs, r)
}
