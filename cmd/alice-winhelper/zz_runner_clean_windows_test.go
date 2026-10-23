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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// packageStart is when this test binary started: every machine key a test of it made is newer.
var packageStart = time.Now()

func TestRealRunnerIsClean(t *testing.T) {
	requireReal(t)

	// No http.sys record on the W2 and W3 ports (the helper's own listing, which the W1 twin checks
	// against netsh's records).
	list, err := sslBindings()
	require.NoError(t, err)
	require.NotEmpty(t, list, "positive control: the runner image's own records are listed")
	for _, b := range list {
		assert.False(t, b.Port >= 45330 && b.Port <= 45398, "an http.sys record is left: %+v", b)
	}

	// No alice-w2- or alice-w3- certificate in My, WebHosting or CA (by subject or friendly name: the
	// helper names its imports "Alice <first SAN> ...", and every W2 and W3 fixture name starts so).
	out := powershell(t, `$n = 0
foreach ($s in @('My', 'WebHosting', 'CA')) {
    $p = "Cert:\LocalMachine\$s"
    if (-not (Test-Path -LiteralPath $p)) { continue }
    foreach ($c in Get-ChildItem -LiteralPath $p) {
        $n++
        if ($c.Subject -like '*alice-w2-*' -or $c.FriendlyName -like '*alice-w2-*' -or
            $c.Subject -like '*alice-w3-*' -or $c.FriendlyName -like '*alice-w3-*') { "left $s $($c.Thumbprint) $($c.Subject)" }
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

	// No machine key made during this run is left: the fixtures' keys go with their certificates
	// (Remove-Item -DeleteKey), the helper's imports with theirs (removeLater), and a key the helper
	// imported again is deleted by ImportPFX itself. Key container names are random, so a key is told by
	// its file's creation time (the image's own keys are older than this test binary).
	assert.Empty(t, machineKeysSince(t, packageStart), "machine keys created during this run are left")

	// No alice-w2- or alice-w3- site.
	sites, err := exec.Command(appcmdPath(), "list", "site", "/text:name").Output()
	require.NoError(t, err)
	require.Contains(t, string(sites), "Default Web Site", "positive control: appcmd lists the image's own site")
	for _, name := range strings.Fields(string(sites)) {
		assert.False(t, strings.HasPrefix(name, "alice-w2-") || strings.HasPrefix(name, "alice-w3-"), "an IIS site is left: %s", name)
	}

	// No test data directory (W2's and W3's alike: C:\ProgramData\Alice\helper-test-<random>) and no
	// fixture web directory.
	left, err := filepath.Glob(`C:\ProgramData\Alice\helper-test-*`)
	require.NoError(t, err)
	assert.Empty(t, left, "test data directories are left")
	for _, dir := range []string{"alice-w2-fidelity", "alice-w3-fidelity"} {
		_, err = os.Stat(filepath.Join(os.Getenv("SystemDrive")+`\`, "inetpub", dir))
		assert.ErrorIs(t, err, os.ErrNotExist, "the fixture sites' directory %s is left", dir)
	}
}
