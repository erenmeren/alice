package setup_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/setup"
)

// The same file drives web/src/pages/setup/strength.test.ts, so the browser's meter and the server's refusal agree.
func TestPassphraseStrengthVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/strength.json")
	require.NoError(t, err)
	var vectors []struct {
		Passphrase string         `json:"passphrase"`
		Strength   setup.Strength `json:"strength"`
		Note       string         `json:"note"`
	}
	require.NoError(t, json.Unmarshal(raw, &vectors))
	require.GreaterOrEqual(t, len(vectors), 30)
	seen := map[setup.Strength]bool{}
	for _, v := range vectors {
		assert.Equal(t, v.Strength, setup.PassphraseStrength(v.Passphrase), "%q: %s", v.Passphrase, v.Note)
		seen[v.Strength] = true
	}
	assert.Len(t, seen, 4, "every rating is covered")
}
