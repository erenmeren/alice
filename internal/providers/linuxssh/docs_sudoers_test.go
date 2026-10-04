package linuxssh

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The Nginx preparation guide quotes the nginx profile's sudoers lines "exactly as the setup commands
// write them": its block must be the end of what Sudoers("nginx") generates, byte for byte.
func TestPreparationGuideQuotesTheSudoersFile(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/nginx-host-preparation.md")
	require.NoError(t, err)
	text := string(doc)
	start := strings.Index(text, "```\nCmnd_Alias ALICE_NGINX_ONLY")
	require.GreaterOrEqual(t, start, 0, "the guide quotes the ALICE_NGINX_ONLY block")
	block := text[start+len("```\n"):]
	end := strings.Index(block, "```")
	require.GreaterOrEqual(t, end, 0)
	block = block[:end]
	generated, err := Sudoers("nginx")
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(generated, "\n"+block), "the guide's block:\n%s\nis not the end of the generated file:\n%s", block, generated)
}
