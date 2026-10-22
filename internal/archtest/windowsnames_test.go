package archtest

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// windowsReserved are the device names Windows refuses as file names, with or without an extension.
var windowsReserved = map[string]bool{"con": true, "prn": true, "aux": true, "nul": true}

// windowsBadName reports why a single path element cannot be checked out on Windows, or "".
func windowsBadName(elem string) string {
	if strings.ContainsAny(elem, "<>:\"|?*\\") {
		return "holds a character Windows refuses"
	}
	if strings.HasSuffix(elem, " ") || strings.HasSuffix(elem, ".") {
		return "ends in a space or a dot"
	}
	base, _, _ := strings.Cut(elem, ".")
	base = strings.ToLower(strings.TrimRight(base, " ")) //nolint:forbidigo // ASCII device names
	if windowsReserved[base] {
		return "is a reserved device name"
	}
	if len(base) == 4 && (strings.HasPrefix(base, "com") || strings.HasPrefix(base, "lpt")) && base[3] >= '1' && base[3] <= '9' {
		return "is a reserved device name"
	}
	return ""
}

// The repository is checked out on Windows by the Windows job (and by operators): no tracked path
// element may be a reserved device name (internal/api/nul.go once broke a plain checkout) or hold a
// character Windows refuses.
func TestNoWindowsReservedFileNames(t *testing.T) {
	root := moduleRoot(t)
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	require.NoError(t, err, "git ls-files")
	var violations []string
	n := 0
	for _, path := range strings.Split(string(out), "\x00") {
		if path == "" {
			continue
		}
		n++
		for _, elem := range strings.Split(path, "/") {
			if why := windowsBadName(elem); why != "" {
				violations = append(violations, path+": "+elem+" "+why)
			}
		}
	}
	assert.Greater(t, n, 100, "the listing found the tracked files")
	assert.Empty(t, violations)
}

func TestWindowsBadNameRules(t *testing.T) {
	for _, bad := range []string{"nul.go", "NUL", "Nul.test.go", "con", "PRN.txt", "aux.md", "COM1", "com9.go", "lpt5.x",
		"trailing.", "trailing ", "a:b", "a<b", "a>b", `a"b`, "a|b", "a?b", "a*b", `a\b`, "nul .txt"} {
		assert.NotEmpty(t, windowsBadName(bad), bad)
	}
	for _, ok := range []string{"unstorable.go", "null.go", "console.go", "com.go", "com0.go", "com10.go", "lpt.go", "auxiliary.go", "a.b", ".gitignore", "Makefile"} {
		assert.Empty(t, windowsBadName(ok), ok)
	}
}
