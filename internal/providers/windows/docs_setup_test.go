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

// The host preparation guide's "WinRM transport" section quotes the WinRM script's account, listener and firewall lines
// as the script writes them for the default account without an address, so a change to either shows here.
func TestPreparationGuideQuotesTheWinRMScript(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/windows-host-preparation.md")
	require.NoError(t, err)
	script, err := SetupScriptWinRM(DefaultUser, "", true)
	require.NoError(t, err)
	for _, prefix := range []string{
		"$AliceUser = ",
		"$AliceAddress = ",
		"    New-WSManInstance -ResourceURI winrm/config/Listener ",
		"New-NetFirewallRule -Name 'Alice-WinRM-In' ",
	} {
		var line string
		for _, l := range strings.Split(script, "\n") {
			if strings.HasPrefix(l, prefix) {
				line = strings.TrimSpace(l)
				break
			}
		}
		require.NotEmpty(t, line, "the script has a line starting %q", prefix)
		require.Contains(t, string(doc), line, "the guide quotes the script's line")
	}
}
