package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// AUD-13: PostgreSQL text holds valid UTF-8 without NUL; everything else a person can type is storable.
func TestStorableText(t *testing.T) {
	for s, want := range map[string]bool{
		"":                   true,
		"İzmir ığüşöç ĞÜŞÖÇ": true,
		"emoji 🔑 and é":     true, // combining acute accent
		"tab\tnew\nline":     true,
		"�":                  true,
		"a\x00b":             false,
		"\x00":               false,
		"a\xffb":             false,
		"\xed\xa0\x80":       false, // an encoded surrogate is not UTF-8
		"trailing\xc3":       false,
	} {
		assert.Equal(t, want, StorableText(s), "%q", s)
	}
}
