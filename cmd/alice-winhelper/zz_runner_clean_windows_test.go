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
	"slices"
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

	// No http.sys record on the W2 and W3 ports nor on W5's, W6's or W7's (the helper's own listing, which
	// the W1 twin checks against netsh's records; W5's ccs records included; W7's are the WinRM test
	// listeners' 45520-45539).
	list, err := sslBindings()
	require.NoError(t, err)
	require.NotEmpty(t, list, "positive control: the runner image's own records are listed")
	for _, b := range list {
		assert.False(t, b.Port >= 45330 && b.Port <= 45398 || b.Port >= 45480 && b.Port <= 45499 || b.Port >= 45500 && b.Port <= 45519 ||
			b.Port >= 45520 && b.Port <= 45539,
			"an http.sys record is left: %+v", b)
	}

	// No alice-w2-, alice-w3-, alice-w5-, alice-w6- or alice-w7- certificate in My, WebHosting, CA, Remote
	// Desktop or Root (by subject or friendly name: the helper names its imports "Alice <first SAN> ...", and
	// every W2, W3, W5, W6 and W7 fixture name starts so).
	out := powershell(t, `$n = 0
foreach ($s in @('My', 'WebHosting', 'CA', 'Remote Desktop', 'Root')) {
    $p = "Cert:\LocalMachine\$s"
    if (-not (Test-Path -LiteralPath $p)) { continue }
    foreach ($c in Get-ChildItem -LiteralPath $p) {
        $n++
        if ($c.Subject -like '*alice-w2-*' -or $c.FriendlyName -like '*alice-w2-*' -or
            $c.Subject -like '*alice-w3-*' -or $c.FriendlyName -like '*alice-w3-*' -or
            $c.Subject -like '*alice-w5*' -or $c.FriendlyName -like '*alice-w5*' -or
            $c.Subject -like '*alice-w6-*' -or $c.FriendlyName -like '*alice-w6-*' -or
            $c.Subject -like '*alice-w7-*' -or $c.FriendlyName -like '*alice-w7-*') { "left $s $($c.Thumbprint) $($c.Subject)" }
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

	// No alice-w2-, alice-w3-, alice-w5-, alice-w6- or alice-w7- site (W7's is TestRealWinRMProvider's, in
	// internal/providers/windows).
	sites, err := exec.Command(appcmdPath(), "list", "site", "/text:name").Output()
	require.NoError(t, err)
	require.Contains(t, string(sites), "Default Web Site", "positive control: appcmd lists the image's own site")
	for _, name := range strings.Fields(string(sites)) {
		assert.False(t, strings.HasPrefix(name, "alice-w2-") || strings.HasPrefix(name, "alice-w3-") || strings.HasPrefix(name, "alice-w5-") ||
			strings.HasPrefix(name, "alice-w6-") || strings.HasPrefix(name, "alice-w7-"),
			"an IIS site is left: %s", name)
	}

	// No test data directory (W2's and W3's alike: C:\ProgramData\Alice\helper-test-<random>) and no
	// fixture web directory.
	left, err := filepath.Glob(`C:\ProgramData\Alice\helper-test-*`)
	require.NoError(t, err)
	assert.Empty(t, left, "test data directories are left")
	for _, dir := range []string{"alice-w2-fidelity", "alice-w3-fidelity", "alice-w5-fidelity", "alice-w5-ccs-site", "alice-w5-ccs-diag", "alice-w6-fidelity", "alice-w7-provider"} {
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

	// W6: the RDP values as the first RDP fixture found them (fDenyTSConnections, UserAuthentication and
	// SSLCertificateSHA1Hash, absent on the images, F12), and TermService's state as found (the fixture
	// stops a TermService it started).
	now, err := readRDPValues()
	require.NoError(t, err)
	if rdpAsFoundSet {
		assert.Equal(t, rdpAsFound.String(), now.String(), "the RDP values are restored as found")
	} else {
		t.Logf("no RDP fixture ran; the RDP values are %s", now)
	}
	assert.Nil(t, now.Hash, "SSLCertificateSHA1Hash is absent, as on the runner images (F12)")
	if rdpTermServiceFound != "" {
		assert.Equal(t, rdpTermServiceFound, termServiceState(t), "TermService is as the first RDP fixture found it")
	}

	// W7 (internal/providers/windows/winrs and the WinRM setup script's tests in internal/providers/windows, earlier
	// go test runs of the job): no alice-w7 account, no WinRM listener on 45520-45539, no firewall rule Alice WinRM
	// (Alice-WinRM-In, which the setup script's tests remove), no test program directory, and the WinRM and LSA
	// values as the first WinRS fixture found them (it wrote them to the temporary directory, read with the
	// same script).
	left = strings.Fields(string(powershell(t, `Import-Module Microsoft.WSMan.Management
# [ADSI]::Exists throws for an absent account (runner run 1 of W7); Win32_UserAccount answers nothing.
if (@(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND Name='alice-w7'").Count -gt 0) { 'account' }
$n = 0
# Get-WSManInstance is WinRM's own client (Negotiate to the local service): access denied means a W7 test left
# the service refusing it (runner run 2: Negotiate left off).
try {
    foreach ($l in @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate)) {
        $n++
        if ([int]$l.Port -ge 45520 -and [int]$l.Port -le 45539) { "listener:$($l.Address)/$($l.Transport):$($l.Port)" }
    }
    if ($n -eq 0) { 'no-listener-listed' }
} catch {
    'wsman-client-refused'
}
if (@(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Alice*WinRM*' -or $_.DisplayName -like 'Alice WinRM*' }).Count -gt 0) { 'firewall-rule' }
exit 0`)))
	assert.Empty(t, left, "W7 fixtures are left (no-listener-listed: the positive control, the image's 5986 listener, is missing; "+
		"wsman-client-refused: WinRM refuses its own local client, a WinRM setting is left changed)")
	left, err = filepath.Glob(filepath.Join(os.Getenv("ProgramData"), "alice-w7-*"))
	require.NoError(t, err)
	assert.Empty(t, left, "the WinRS tests' program directories are left")
	script, err := os.ReadFile(filepath.Join("..", "..", "internal", "providers", "windows", "winrs", "testdata", "settings.ps1"))
	require.NoError(t, err)
	settings := strings.TrimSpace(strings.ReplaceAll(string(powershell(t, string(script))), "\r\n", "\n"))
	asFound := filepath.Join(os.TempDir(), "alice-w7-settings-as-found.txt")
	if b, err := os.ReadFile(asFound); err == nil {
		want := strings.Split(strings.TrimSpace(string(b)), "\n")
		got := strings.Split(settings, "\n")
		for i := range got {
			got[i] = strings.TrimSpace(got[i])
		}
		slices.Sort(got)
		assert.Equal(t, want, got, "the WinRM and LSA values are restored as the first WinRS fixture found them")
		_ = os.Remove(asFound)
	} else {
		t.Logf("no WinRS fixture ran (%v); the WinRM and LSA values are %s", err, strings.ReplaceAll(settings, "\n", ", "))
	}
}
