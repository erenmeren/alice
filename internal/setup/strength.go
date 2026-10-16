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
//   - the length is the number of Unicode code points ([...p].length); below 16 is tooShort;
//   - the classes are [a-z], [A-Z] and [0-9] (ASCII only) and "other": any rune that is not an ASCII letter
//     or digit and not JavaScript white space (/[^A-Za-z0-9\s]/), counted on p as typed;
//   - the words are p.trim().split(/\s+/) without empty pieces, JavaScript's \s being Unicode Zs plus TAB,
//     LF, VT, FF, CR, U+2028, U+2029 and U+FEFF (and not U+0085, which Go's unicode.IsSpace includes);
//     distinct is the number of different words (exact comparison);
//   - word cycle: if the words are one shorter list repeated (the smallest period p ≤ len/2 that divides
//     the count), only the first p words are kept; the core is the kept words joined by one space;
//   - rune period: if the core is one shorter run of code points repeated (the smallest period q ≤ n/2
//     that divides the rune count n), only its first q runes are kept;
//   - a run of 3 or more identical runes becomes one rune (a double stays);
//   - a run of 3 or more runes that each step +1, or each step -1, in code point (abc, 123, zyx) becomes
//     its first 2 runes; runs are taken greedily from the left, each as long as it goes;
//   - effective is the rune count of the result; below 16 is fair; otherwise
//     score = (effective ≥ 20) + (effective ≥ 28) + (classes ≥ 3 or distinct ≥ 4): 2 or more strong,
//     1 good, 0 fair.
func PassphraseStrength(p string) Strength {
	if utf8.RuneCountInString(p) < MinPassphraseLength {
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
	words := strings.FieldsFunc(p, jsSpace)
	distinct := map[string]bool{}
	for _, w := range words {
		distinct[w] = true
	}
	if k := period(len(words), func(i, j int) bool { return words[i] == words[j] }); k > 0 {
		words = words[:k]
	}
	core := []rune(strings.Join(words, " "))
	if k := period(len(core), func(i, j int) bool { return core[i] == core[j] }); k > 0 {
		core = core[:k]
	}
	effective := len(collapseSequences(collapseRuns(core)))
	if effective < MinPassphraseLength {
		return StrengthFair
	}
	score := 0
	for _, ok := range []bool{effective >= 20, effective >= 28, classes >= 3 || len(distinct) >= 4} {
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

// period returns the smallest k with 1 ≤ k ≤ n/2 and n % k == 0 such that item i equals item i mod k for
// every i (same(i, j) compares items i and j), or 0 when there is none.
func period(n int, same func(i, j int) bool) int {
next:
	for k := 1; k <= n/2; k++ {
		if n%k != 0 {
			continue
		}
		for i := k; i < n; i++ {
			if !same(i, i%k) {
				continue next
			}
		}
		return k
	}
	return 0
}

// collapseRuns turns every run of 3 or more identical runes into one rune.
func collapseRuns(rs []rune) []rune {
	var out []rune
	for i := 0; i < len(rs); {
		j := i + 1
		for j < len(rs) && rs[j] == rs[i] {
			j++
		}
		if j-i >= 3 {
			out = append(out, rs[i])
		} else {
			out = append(out, rs[i:j]...)
		}
		i = j
	}
	return out
}

// collapseSequences turns every run of 3 or more runes that each step +1 (or each step -1) in code point into
// its first 2 runes, taking the runs greedily from the left, each as long as it goes.
func collapseSequences(rs []rune) []rune {
	var out []rune
	for i := 0; i < len(rs); {
		j := i + 1
		if j < len(rs) && (rs[j]-rs[i] == 1 || rs[j]-rs[i] == -1) {
			step := rs[j] - rs[i]
			for j+1 < len(rs) && rs[j+1]-rs[j] == step {
				j++
			}
			j++ // j is now one past the run
		}
		if j-i >= 3 {
			out = append(out, rs[i], rs[i+1])
			i = j
		} else {
			out = append(out, rs[i]) // a sequence may still start at the next rune ("babc")
			i++
		}
	}
	return out
}

// jsSpace reports whether JavaScript's \s matches r (ECMAScript WhiteSpace and LineTerminator).
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', 0x2028, 0x2029, 0xFEFF:
		return true
	}
	return unicode.Is(unicode.Zs, r)
}
