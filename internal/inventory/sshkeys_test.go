package inventory

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFoldSearchMatchesTurkishCaseVariants(t *testing.T) {
	for in, want := range map[string]string{
		"İZMİR":   "izmir",
		"izmir":   "izmir",
		"IZMIR":   "izmir",
		"Iğdır":   "iğdir",
		"ığdır":   "iğdir",
		"SHA256:": "sha256:",
	} {
		assert.Equal(t, want, foldSearch(in), in)
	}
	assert.Equal(t, `%100\%\_done\\%`, likePattern("100%_done\\"), "wildcards are matched literally")
}

func TestCursorRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 1, 9, 0, 0, 123456000, time.UTC)
	id := uuid.Must(uuid.NewV7())
	c := encodeCursor(at, id)
	gotAt, gotID, err := decodeCursor(c)
	require.NoError(t, err)
	assert.True(t, at.Equal(gotAt))
	assert.Equal(t, id, gotID)
	for _, bad := range []string{"%%%", "bm90LWEtY3Vyc29y", encodeCursor(at, id) + "x"} {
		_, _, err := decodeCursor(bad)
		require.Error(t, err, bad)
	}
}
