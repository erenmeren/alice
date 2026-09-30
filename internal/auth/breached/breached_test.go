package breached

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmbeddedListShape(t *testing.T) {
	assert.Equal(t, 0, len(list)%8, "file length must be a multiple of 8")
	assert.Greater(t, Len(), 99_000)
	assert.Less(t, Len(), 100_001)
	for i := 1; i < Len(); i++ {
		if at(i-1) >= at(i) {
			t.Fatalf("entries %d and %d are not strictly increasing", i-1, i)
		}
	}
}

func TestContains(t *testing.T) {
	for _, pw := range []string{"123456", "password", "qwerty123456", "passwordpassword", "123456789012", "1q2w3e4r5t6y"} {
		assert.True(t, Contains(pw), pw)
	}
	for _, pw := range []string{"", "correct horse battery staple 42", "Qwerty123456x", "İstanbul-kış-2026"} {
		assert.False(t, Contains(pw), pw)
	}
}
