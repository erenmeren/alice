package api

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roleCommand is one exported command constant of web/src/components/roleCommands.ts: the name, then the
// command as a single-quoted string literal on the next line.
var roleCommand = regexp.MustCompile(`(?m)^export const (CMD_[A-Z_]+) =\s*'([^'\\]*)';`)

// The Azure setup guide quotes the role commands of the access checklist character for character (D41):
// every `az role assignment create` and `az keyvault set-policy` line of docs/azure-setup.md is one of the
// commands RoleGuide shows (roleCommands.ts), and every one of those commands is in the guide.
func TestAzureSetupGuideQuotesTheRoleGuideCommands(t *testing.T) {
	src, err := os.ReadFile("../../web/src/components/roleCommands.ts")
	require.NoError(t, err)
	consts := roleCommand.FindAllStringSubmatch(string(src), -1)
	require.Len(t, consts, 6, "roleCommands.ts exports three role assignments and three access-policy commands")

	ui, err := os.ReadFile("../../web/src/components/RoleGuide.tsx")
	require.NoError(t, err)
	var want []string
	for _, c := range consts {
		// The screen shows the command: RoleGuide uses the constant.
		assert.Regexp(t, `\b`+c[1]+`\b`, string(ui), "RoleGuide.tsx does not use %s", c[1])
		want = append(want, c[2])
	}

	doc, err := os.ReadFile("../../docs/azure-setup.md")
	require.NoError(t, err)
	var got []string
	for _, line := range strings.Split(string(doc), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "az role assignment create") || strings.HasPrefix(line, "az keyvault set-policy") {
			got = append(got, line)
		}
	}
	assert.ElementsMatch(t, want, got, "the role commands of docs/azure-setup.md differ from web/src/components/roleCommands.ts")
}
