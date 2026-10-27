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

	// No http.sys record on the W2 and W3 ports nor on W5's (the helper's own listing, which the W1 twin
	// checks against netsh's records; W5's ccs records included).
	list, err := sslBindings()
	require.NoError(t, err)
	require.NotEmpty(t, list, "positive control: the runner image's own records are listed")
	for _, b := range list {
		assert.False(t, b.Port >= 45330 && b.Port <= 45398 || b.Port >= 45480 && b.Port <= 45499, "an http.sys record is left: %+v", b)
	}

	// No alice-w2-, alice-w3- or alice-w5- certificate in My, WebHosting or CA (by subject or friendly
	// name: the helper names its imports "Alice <first SAN> ...", and every W2, W3 and W5 fixture name
	// starts so).
	out := powershell(t, `$n = 0
foreach ($s in @('My', 'WebHosting', 'CA')) {
    $p = "Cert:\LocalMachine\$s"
    if (-not (Test-Path -LiteralPath $p)) { continue }
    foreach ($c in Get-ChildItem -LiteralPath $p) {
        $n++
        if ($c.Subject -like '*alice-w2-*' -or $c.FriendlyName -like '*alice-w2-*' -or
            $c.Subject -like '*alice-w3-*' -or $c.FriendlyName -like '*alice-w3-*' -or
            $c.Subject -like '*alice-w5*' -or $c.FriendlyName -like '*alice-w5*') { "left $s $($c.Thumbprint) $($c.Subject)" }
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

	// No alice-w2-, alice-w3- or alice-w5- site.
	sites, err := exec.Command(appcmdPath(), "list", "site", "/text:name").Output()
	require.NoError(t, err)
	require.Contains(t, string(sites), "Default Web Site", "positive control: appcmd lists the image's own site")
	for _, name := range strings.Fields(string(sites)) {
		assert.False(t, strings.HasPrefix(name, "alice-w2-") || strings.HasPrefix(name, "alice-w3-") || strings.HasPrefix(name, "alice-w5-"),
			"an IIS site is left: %s", name)
	}

	// No test data directory (W2's and W3's alike: C:\ProgramData\Alice\helper-test-<random>) and no
	// fixture web directory.
	left, err := filepath.Glob(`C:\ProgramData\Alice\helper-test-*`)
	require.NoError(t, err)
	assert.Empty(t, left, "test data directories are left")
	for _, dir := range []string{"alice-w2-fidelity", "alice-w3-fidelity", "alice-w5-fidelity", "alice-w5-ccs-site", "alice-w5-ccs-diag"} {
		_, err = os.Stat(filepath.Join(os.Getenv("SystemDrive")+`\`, "inetpub", dir))
		assert.ErrorIs(t, err, os.ErrNotExist, "the fixture sites' directory %s is left", dir)
	}

	// W5: CCS turned off again (the fixtures restore the registry key as they found it, and the runner
	// images have CCS off), no CCS folder (or junction) left, and no alice-w5-ccs account.
	enabled, path, err := centralCertStore()
	require.NoError(t, err)
	assert.False(t, enabled, "the Centralized Certificate Store is left enabled (at %q)", path)
	assert.False(t, strings.HasPrefix(foldASCII(path), `c:\alice-w5-`), "the CCS registry still names a fixture folder: %q", path)
	left, err = filepath.Glob(`C:\alice-w5-ccs-*`)
	require.NoError(t, err)
	assert.Empty(t, left, "CCS fixture folders are left")
	left, err = filepath.Glob(filepath.Join(os.Getenv("SystemDrive")+`\`, "Users", "alice-w5-ccs*"))
	require.NoError(t, err)
	assert.Empty(t, left, "the CCS fixture account's profile is left")
	users := powershell(t, `$u = Get-LocalUser -Name 'alice-w5-ccs' -ErrorAction SilentlyContinue; if ($u) { 'left' } else { 'none' }`)
	assert.Equal(t, "none", strings.TrimSpace(string(users)), "the CCS fixture account alice-w5-ccs is left")
}
