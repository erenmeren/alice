package linuxssh

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Each preparation guide quotes its profile's sudoers lines "exactly as the setup commands write
// them": its block must be the end of what Sudoers(profile) generates, byte for byte.
func TestPreparationGuideQuotesTheSudoersFile(t *testing.T) {
	for _, tc := range []struct{ guide, alias, profile string }{
		{"nginx-host-preparation.md", "ALICE_NGINX_ONLY", "nginx"},
		{"apache-host-preparation.md", "ALICE_APACHE_ONLY", "apache"},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			doc, err := os.ReadFile("../../../docs/" + tc.guide)
			require.NoError(t, err)
			text := string(doc)
			start := strings.Index(text, "```\nCmnd_Alias "+tc.alias)
			require.GreaterOrEqual(t, start, 0, "the guide quotes the %s block", tc.alias)
			block := text[start+len("```\n"):]
			end := strings.Index(block, "```")
			require.GreaterOrEqual(t, end, 0)
			block = block[:end]
			generated, err := Sudoers(tc.profile)
			require.NoError(t, err)
			require.True(t, strings.HasSuffix(generated, "\n"+block), "the guide's block:\n%s\nis not the end of the generated file:\n%s", block, generated)
		})
	}
}
