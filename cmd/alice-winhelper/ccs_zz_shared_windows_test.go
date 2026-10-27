//go:build windows

package main

// The one CCS folder the real tests of this binary share (ruling W5-11). Run 2 showed that IIS keeps
// the first CCS folder of its lifetime: after Enable-WebCentralCertProvider with another path and a
// refresh of the ccs records, the new folder was never served within 2 minutes. So the first fixture
// that needs CCS enables it once, at C:\alice-w5-ccs-<random> with the alice-w5-ccs account, and every
// test after it uses that folder with its own file names and its own ports.
//
// The shared state is torn down by TestRealCCSSharedFolderRemoved, the last test of this file. The CCS
// tests live in files named ccs_*, so go test runs them one after the other and this file's test right
// after them, long before zz_runner_clean_windows_test.go's TestRealRunnerIsClean, which then checks
// CCS disabled, the folder, the account and its profile gone. TestMain tears down too after the run,
// for a run that filters TestRealCCSSharedFolderRemoved out (it is then a no-op on a torn-down state).

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

// sharedCCS is the package's CCS configuration.
var sharedCCS struct {
	once      sync.Once
	err       error
	folder    string
	password  []byte // IIS's private-key password of the store
	accountPW string // alice-w5-ccs's password
	start     time.Time
	// recordByIIS: appcmd's sslFlags=3 bindings made the http.sys ccs record (else netsh did).
	recordByIIS bool

	mu       sync.Mutex
	cleanups []func(logf func(string, ...any)) // run in reverse by tearDownSharedCCS
}

func addSharedCleanup(f func(logf func(string, ...any))) {
	sharedCCS.mu.Lock()
	defer sharedCCS.mu.Unlock()
	sharedCCS.cleanups = append(sharedCCS.cleanups, f)
}

// tearDownSharedCCS runs the registered cleanups once, newest first.
func tearDownSharedCCS(logf func(string, ...any)) {
	sharedCCS.mu.Lock()
	cs := sharedCCS.cleanups
	sharedCCS.cleanups = nil
	sharedCCS.mu.Unlock()
	for i := len(cs) - 1; i >= 0; i-- {
		cs[i](logf)
	}
}

// requireSharedCCS enables CCS once for the binary and returns its state (the first caller's failure
// fails every caller with the same message, never a skip).
func requireSharedCCS(t *testing.T) {
	t.Helper()
	sharedCCS.once.Do(func() { sharedCCS.err = setUpSharedCCS(t.Logf) })
	require.NoError(t, sharedCCS.err, "the shared CCS fixture")
}

func randomHexErr(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// regKeyFound reports whether the CentralCertProvider key exists.
func regKeyFound() (bool, error) {
	k, err := openKey(keyCentralCert)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_ = k.Close()
	return true, nil
}

// enableCCSAt runs Enable-WebCentralCertProvider for folder with the shared account and password.
func enableCCSAt(folder string) error {
	out, err := runPowershell(map[string]string{"ALICE_W5_FOLDER": folder, "ALICE_W5_ACCOUNT": ccsAccount,
		"ALICE_W5_PW": sharedCCS.accountPW, "ALICE_W5_PK": string(sharedCCS.password)}, `Import-Module WebAdministration
Enable-WebCentralCertProvider -CertStoreLocation $env:ALICE_W5_FOLDER -UserName "$env:COMPUTERNAME\$env:ALICE_W5_ACCOUNT" -Password $env:ALICE_W5_PW -PrivateKeyPassword $env:ALICE_W5_PK`)
	if err != nil {
		return fmt.Errorf("Enable-WebCentralCertProvider: %w: %s", err, out)
	}
	return nil
}

// setUpSharedCCS installs Web-CertProvider when missing (it stays: removing it needs a restart), makes
// the folder and the account, saves the registry key as found, and enables CCS. Each step registers
// its cleanup before it is made.
func setUpSharedCCS(logf func(string, ...any)) error {
	out, err := runPowershell(nil, `Import-Module ServerManager
$f = Get-WindowsFeature -Name Web-CertProvider
if (-not $f) { throw 'this image does not know the Web-CertProvider feature' }
if (-not $f.Installed) {
    $r = Install-WindowsFeature -Name Web-CertProvider
    if (-not $r.Success) { throw "Install-WindowsFeature Web-CertProvider failed (exit code $($r.ExitCode))" }
    'installed'
} else { 'present' }
Import-Module WebAdministration
if (-not (Get-Command Enable-WebCentralCertProvider -ErrorAction SilentlyContinue)) { throw 'WebAdministration has no Enable-WebCentralCertProvider' }`)
	if err != nil {
		return fmt.Errorf("the CCS feature (Install-WindowsFeature Web-CertProvider, WebAdministration): %w: %s", err, out)
	}
	logf("Web-CertProvider: %s", strings.TrimSpace(string(out)))

	suffix, err := randomHexErr(8)
	if err != nil {
		return err
	}
	folder := `C:\alice-w5-ccs-` + suffix
	addSharedCleanup(func(logf func(string, ...any)) { removeFolderLog(logf, folder) })
	if err := os.Mkdir(folder, 0o700); err != nil {
		return err
	}
	pw, err := randomHexErr(16)
	if err != nil {
		return err
	}
	sharedCCS.folder, sharedCCS.password, sharedCCS.accountPW = folder, winhelper.NewPFXPassword(), pw+"Aa1!" // the policy wants upper, lower, digit and symbol

	addSharedCleanup(func(logf func(string, ...any)) {
		if _, err := runPowershell(map[string]string{"ALICE_W5_ACCOUNT": ccsAccount}, `$u = Get-LocalUser -Name $env:ALICE_W5_ACCOUNT -ErrorAction SilentlyContinue
if ($u) {
    Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $u.SID.Value } | Remove-CimInstance
    Remove-LocalUser -Name $env:ALICE_W5_ACCOUNT
}`); err != nil {
			logf("cleanup of the account %s: %v", ccsAccount, err)
		}
	})
	if out, err := runPowershell(map[string]string{"ALICE_W5_ACCOUNT": ccsAccount, "ALICE_W5_PW": sharedCCS.accountPW},
		`$pw = ConvertTo-SecureString -String $env:ALICE_W5_PW -AsPlainText -Force
New-LocalUser -Name $env:ALICE_W5_ACCOUNT -Password $pw -PasswordNeverExpires -AccountNeverExpires -Description 'alice-w5 CCS fixture' | Out-Null
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $env:ALICE_W5_ACCOUNT`); err != nil { // BUILTIN\Users, as net user /add makes it
		return fmt.Errorf("the account: %w: %s", err, out)
	}
	if out, err := exec.Command("icacls", folder, "/grant", ccsAccount+":(OI)(CI)R").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %w: %s", err, out)
	}

	// The registry key as found (after the feature's install, which stays), restored at the end.
	existed, err := regKeyFound()
	if err != nil {
		return err
	}
	saved := ""
	if existed {
		tmp, err := os.CreateTemp("", "alice-w5-ccs-*.reg")
		if err != nil {
			return err
		}
		saved = tmp.Name()
		_ = tmp.Close()
		if out, err := exec.Command("reg", "export", ccsRegKey, saved, "/y").CombinedOutput(); err != nil {
			return fmt.Errorf("reg export: %w: %s", err, out)
		}
	}
	addSharedCleanup(func(logf func(string, ...any)) { restoreCCSRegistry(logf, existed, saved) })
	if err := enableCCSAt(folder); err != nil {
		return err
	}
	sharedCCS.start = time.Now()
	enabled, path, err := centralCertStore()
	switch {
	case err != nil:
		return err
	case !enabled || path != folder:
		return fmt.Errorf("the helper reads CCS enabled %v at %q, not %q", enabled, path, folder)
	}
	// The one site every CCS test serves from, made before any CCS handshake (run 3).
	addSharedCleanup(func(logf func(string, ...any)) { removeCCSSite(logf, ccsSiteName, portCCSShared, ccsSiteDir) })
	byIIS, err := createCCSSite(ccsSiteName, portCCSShared, ccsSiteDir, ccsSiteHosts)
	if err != nil {
		return err
	}
	sharedCCS.recordByIIS = byIIS
	return nil
}

// removeFolderLog removes a fixture folder, retrying while IIS still holds it (its change notification).
func removeFolderLog(logf func(string, ...any), dir string) {
	var err error
	for range 20 {
		if err = os.RemoveAll(dir); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logf("cleanup of %s: %v", dir, err)
}

// restoreCCSRegistry disables CCS and puts the key back as it was found (deleted when there was none).
func restoreCCSRegistry(logf func(string, ...any), existed bool, saved string) {
	if _, err := runPowershell(nil, `Import-Module WebAdministration; Disable-WebCentralCertProvider`); err != nil {
		logf("Disable-WebCentralCertProvider: %v (the key is restored below)", err)
	}
	if out, err := exec.Command("reg", "delete", ccsRegKey, "/f").CombinedOutput(); err != nil {
		if found, _ := regKeyFound(); found {
			logf("reg delete %s: %v %s", ccsRegKey, err, out)
		}
	}
	if existed {
		if out, err := exec.Command("reg", "import", saved).CombinedOutput(); err != nil {
			logf("reg import %s: %v %s", saved, err, out)
		}
		_ = os.Remove(saved)
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	tearDownSharedCCS(func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) })
	os.Exit(code)
}

// TestRealCCSSharedFolderRemoved tears the shared CCS fixture down after the CCS tests (the last test
// of the ccs_* files) and checks it: CCS off, the folder and the account gone.
func TestRealCCSSharedFolderRemoved(t *testing.T) {
	requireReal(t)
	folder := sharedCCS.folder
	tearDownSharedCCS(t.Logf)
	enabled, path, err := centralCertStore()
	require.NoError(t, err)
	assert.False(t, enabled, "CCS is off again (at %q)", path)
	if folder != "" {
		_, err := os.Stat(folder)
		assert.ErrorIs(t, err, os.ErrNotExist, "the shared CCS folder is gone")
	}
	left, err := filepath.Glob(`C:\alice-w5-ccs-*`)
	require.NoError(t, err)
	assert.Empty(t, left)
	users := powershell(t, `$u = Get-LocalUser -Name 'alice-w5-ccs' -ErrorAction SilentlyContinue; if ($u) { 'left' } else { 'none' }`)
	assert.Equal(t, "none", strings.TrimSpace(string(users)), "the account alice-w5-ccs")
}

// ccsSiteHosts are the host headers of the shared site's https bindings on portCCSShared: every host a
// CCS test serves. Run 3: the first port served after CCS was enabled served at once, and the sites
// made after that first serve, each on its own port, were not served within 2 minutes (or only after
// about a minute). So every test serves from this one site, made before the first handshake, as that
// working path did; DIAG measures a site of its own made later (TestRealCCSServedChain).
var ccsSiteHosts = []string{"r.alice-w5.test", "n.alice-w5.test", "nf.alice-w5.test", "good.alice-w5.test", "bad.alice-w5.test",
	"x.alice-w5.test", "exact.alice-w5.test", "up.alice-w5.test", "y.alice-w5.test", "a.b.alice-w5.test", "neg.alice-w5.test",
	"f18a.alice-w5.test", "f18b.alice-w5.test", "f18c.alice-w5.test", "j.alice-w5.test", "s.alice-w5.test", "f.alice-w5.test"}

const (
	ccsSiteName = "alice-w5-ccs"
	ccsSiteDir  = "alice-w5-ccs-site" // under %SystemDrive%\inetpub
)

// ccsSiteDirPath is a fixture site's physical directory.
func ccsSiteDirPath(dir string) string {
	return filepath.Join(os.Getenv("SystemDrive")+`\`, "inetpub", dir)
}

// createCCSSite makes a started IIS site with an sslFlags=3 https binding on port for each host (and
// the plain http binding every fixture site has), and the http.sys ccs:<port> record when IIS made
// none: byIIS reports whether it did. removeCCSSite undoes it (register it first).
func createCCSSite(name string, port int, dir string, hosts []string) (byIIS bool, err error) {
	appcmd := func(args ...string) error {
		if out, err := exec.Command(appcmdPath(), args...).CombinedOutput(); err != nil {
			return fmt.Errorf("appcmd %v: %w: %s", args, err, out)
		}
		return nil
	}
	if err := os.MkdirAll(ccsSiteDirPath(dir), 0o750); err != nil {
		return false, err
	}
	if err := appcmd("add", "site", "/name:"+name, "/id:"+strconv.Itoa(port), "/physicalPath:"+ccsSiteDirPath(dir),
		"/bindings:http/*:"+strconv.Itoa(portCCSSiteHTTP)+":"+name+".invalid"); err != nil {
		return false, err
	}
	for _, h := range hosts {
		if err := appcmd("set", "site", "/site.name:"+name,
			fmt.Sprintf("/+bindings.[protocol='https',bindingInformation='*:%d:%s',sslFlags='3']", port, h)); err != nil {
			return false, err
		}
	}
	_ = exec.Command(appcmdPath(), "start", "site", "/site.name:"+name).Run() // "already started" is not an error here
	state := ""
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		out, _ := exec.Command(appcmdPath(), "list", "site", name, "/text:state").Output()
		if state = strings.TrimSpace(string(out)); state == "Started" {
			break
		}
	}
	if state != "Started" {
		return false, fmt.Errorf("site %s is %q", name, state)
	}
	hasRecord := func() bool {
		list, err := sslBindings()
		if err != nil {
			return false
		}
		_, ok := findBinding(list, winproto.BindingCCS, port)
		return ok
	}
	for deadline := time.Now().Add(10 * time.Second); !byIIS && time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		byIIS = hasRecord()
	}
	if !byIIS {
		if out, err := exec.Command("netsh", "http", "add", "sslcert", "ccs="+strconv.Itoa(port), "appid="+winproto.AppIDIIS).CombinedOutput(); err != nil {
			return false, fmt.Errorf("netsh add ccs=%d: %w: %s", port, err, out)
		}
		if !hasRecord() {
			return false, fmt.Errorf("netsh made no ccs:%d record", port)
		}
	}
	return byIIS, nil
}

// removeCCSSite deletes the ccs record of port, the site and its directory, each when it exists.
func removeCCSSite(logf func(string, ...any), name string, port int, dir string) {
	if list, err := sslBindings(); err == nil {
		if _, ok := findBinding(list, winproto.BindingCCS, port); ok {
			if out, err := exec.Command("netsh", "http", "delete", "sslcert", "ccs="+strconv.Itoa(port)).CombinedOutput(); err != nil {
				logf("cleanup of ccs=%d: %v %s", port, err, out)
			}
		}
	}
	if out, _ := exec.Command(appcmdPath(), "list", "site", name).Output(); len(strings.TrimSpace(string(out))) > 0 {
		if out, err := exec.Command(appcmdPath(), "delete", "site", name).CombinedOutput(); err != nil {
			logf("cleanup of site %s: %v %s", name, err, out)
		}
	}
	removeFolderLog(logf, ccsSiteDirPath(dir))
}

// ccsDiag logs, with the prefix DIAG:, what decides whether port serves from CCS: the http.sys ccs
// record (netsh), the URLs http.sys has registered on the port, the site's and the application pools'
// state, the CentralCertProvider values (never a password: Enabled and CertStoreLocation, and the
// other value names only), and the latest IIS, HTTP and schannel events since CCS was enabled.
func ccsDiag(logf func(string, ...any), port int, site string) {
	run := func(what string, name string, args ...string) {
		out, err := exec.Command(name, args...).CombinedOutput()
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				logf("DIAG: %s: %s", what, l)
			}
		}
		if err != nil {
			logf("DIAG: %s: %v", what, err)
		}
	}
	run("netsh ccs", "netsh", "http", "show", "sslcert", "ccs="+strconv.Itoa(port))
	if out, err := exec.Command("netsh", "http", "show", "servicestate", "view=requestq").CombinedOutput(); err == nil {
		n := 0
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(l, ":"+strconv.Itoa(port)+"/") && n < 20 {
				logf("DIAG: registered URL: %s", strings.TrimSpace(l))
				n++
			}
		}
		logf("DIAG: http.sys URLs on port %d: %d", port, n)
	}
	run("site", appcmdPath(), "list", "site", site)
	run("app pools", appcmdPath(), "list", "apppool")
	out, err := runPowershell(nil, `$k = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider' -ErrorAction SilentlyContinue
if ($k) {
    "Enabled=$($k.GetValue('Enabled')) CertStoreLocation=$($k.GetValue('CertStoreLocation'))"
    "value names: $($k.GetValueNames() -join ',')"
} else { 'no CentralCertProvider key' }`)
	logf("DIAG: CentralCertProvider: %s %v", strings.Join(strings.Fields(string(out)), " "), err)
	ev, err := runPowershell(map[string]string{"ALICE_W5_SINCE": sharedCCS.start.UTC().Format(time.RFC3339)},
		`$since = [DateTime]::Parse($env:ALICE_W5_SINCE, $null, [Globalization.DateTimeStyles]::RoundtripKind)
Get-WinEvent -FilterHashtable @{LogName = 'Application', 'System'; StartTime = $since} -MaxEvents 400 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'IIS|W3SVC|WAS|HttpEvent|HTTP|Schannel|CertificateProvider|CentralCert' } |
    Select-Object -First 10 | ForEach-Object { $m = "$($_.Message)" -replace '\s+', ' '; if ($m.Length -gt 240) { $m = $m.Substring(0, 240) }
        "$($_.TimeCreated.ToString('o')) $($_.LogName) $($_.ProviderName) $($_.Id) $m" }`)
	for _, l := range strings.Split(strings.TrimSpace(string(ev)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			logf("DIAG: event %s", l)
		}
	}
	if err != nil {
		logf("DIAG: events: %v", err)
	}
}
