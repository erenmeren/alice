package solver

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{
		"Example.COM": "example.com", "*.example.com": "example.com", "a-b.example.com.": "a-b.example.com", "x1.y2": "x1.y2",
	}
	for in, want := range ok {
		got, valid := NormalizeDomain(in)
		assert.True(t, valid, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", ".", "a..b", "-a.b", "a-.b", "a_b.c", "ex ample.com", "İ.com", "*.*.a.b",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 120) + "com"} {
		_, valid := NormalizeDomain(in)
		assert.False(t, valid, in)
	}
}

func TestSuffixes(t *testing.T) {
	s, err := ParseSuffixes([]string{" Example.com ", ".sub.test"})
	require.NoError(t, err)
	assert.Equal(t, Suffixes{"example.com", ".sub.test"}, s)
	assert.True(t, s.Allows("example.com"))
	assert.True(t, s.Allows("a.example.com"))
	assert.False(t, s.Allows("badexample.com"))
	assert.False(t, s.Allows("sub.test"))
	assert.True(t, s.Allows("a.sub.test"))
	assert.False(t, Suffixes{}.Allows("example.com"), "an empty list admits nothing")
	for _, bad := range []string{"*.example.com", "example.com.", "", "a..b"} {
		_, err := ParseSuffixes([]string{bad})
		assert.ErrorIs(t, err, ErrSuffix, bad)
	}
	empty, err := ParseSuffixes(nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestPrintableValue(t *testing.T) {
	assert.True(t, PrintableValue("abc_-DEF123"))
	assert.False(t, PrintableValue(""))
	assert.False(t, PrintableValue("a b"))
	assert.False(t, PrintableValue("a\x7f"))
	assert.False(t, PrintableValue(strings.Repeat("a", MaxDNSValueBytes+1)))
	assert.True(t, PrintableValue(strings.Repeat("a", MaxDNSValueBytes)))
}

func TestASCIILower(t *testing.T) {
	assert.Equal(t, "abc-İ", ASCIILower("ABC-İ"))
}
