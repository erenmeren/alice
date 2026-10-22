//go:build windows

package main

// TestRealRunnerIsClean (W2 Ruling 22) checks that the real tests of this package left nothing behind.
// go test runs a package's tests in the order of their files' names and then of their declarations, so
// this file's name puts it after every other test of the package (the plan's runner_clean_windows_test.go
// would run before stores_*, write_* and others that make fixtures).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealRunnerIsClean(t *testing.T) {
	requireReal(t)

	// No http.sys record on the W2 ports (the helper's own listing, which the W1 twin checks against
	// netsh's records).
	list, err := sslBindings()
	require.NoError(t, err)
	require.NotEmpty(t, list, "positive control: the runner image's own records are listed")
	for _, b := range list {
		assert.False(t, b.Port >= 45330 && b.Port <= 45389, "an http.sys record is left: %+v", b)
	}

	// No alice-w2- certificate in My, WebHosting or CA (by subject or friendly name: the helper names its
	// imports "Alice <first SAN> ...", and every W2 fixture name starts alice-w2-).
	out := powershell(t, `$n = 0
foreach ($s in @('My', 'WebHosting', 'CA')) {
    $p = "Cert:\LocalMachine\$s"
    if (-not (Test-Path -LiteralPath $p)) { continue }
    foreach ($c in Get-ChildItem -LiteralPath $p) {
        $n++
        if ($c.Subject -like '*alice-w2-*' -or $c.FriendlyName -like '*alice-w2-*') { "left $s $($c.Thumbprint) $($c.Subject)" }
    }
}
"count $n"`)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	count := ""
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if c, ok := strings.CutPrefix(l, "count "); ok {
			count = c
			continue
		}
		t.Errorf("a certificate is left: %s", l)
	}
	require.NotEmpty(t, count, "the certificate listing ran: %s", out)
	assert.NotEqual(t, "0", count, "positive control: the machine stores hold the image's own certificates")

	// No alice-w2- site.
	sites, err := exec.Command(appcmdPath(), "list", "site", "/text:name").Output()
	require.NoError(t, err)
	for _, name := range strings.Fields(string(sites)) {
		assert.False(t, strings.HasPrefix(name, "alice-w2-"), "an IIS site is left: %s", name)
	}

	// No test data directory and no fixture web directory.
	left, err := filepath.Glob(`C:\ProgramData\Alice\helper-test-*`)
	require.NoError(t, err)
	assert.Empty(t, left, "test data directories are left")
	_, err = os.Stat(filepath.Join(os.Getenv("SystemDrive")+`\`, "inetpub", "alice-w2-fidelity"))
	assert.ErrorIs(t, err, os.ErrNotExist, "the fixture sites' directory is left")
}
