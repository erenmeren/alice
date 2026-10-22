package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The host preparation guide quotes the sshd_config block "exactly as the setup script writes it" for the
// default account: a fenced block equal to MatchBlock with alice, byte for byte.
func TestPreparationGuideQuotesTheMatchBlock(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/windows-host-preparation.md")
	require.NoError(t, err)
	want := "```\n" + strings.ReplaceAll(MatchBlock, "__USER__", DefaultUser) + "```\n"
	require.Contains(t, string(doc), want, "the guide quotes the block the script writes")
}
