//go:build windows

package winrs_test

// The fixture of the WinRS real tests (R71 Task 4, F24-F31). It runs only when ALICE_WIN_REAL=1, on a Windows
// runner whose image has the HTTPS listener 0.0.0.0:5986 (F8). Every Windows setting a test changes is recorded
// before the change and restored as found in a t.Cleanup registered before it. The test account alice-w7 has a
// crypto/rand password that is never logged: it reaches PowerShell on the child's stdin, never on a command line.
// Every measured value is logged with the prefix "FACT F2x:" so a run's log can be searched for it.

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the certificate thumbprint Windows names a certificate by
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	ntlmssp "github.com/Azure/go-ntlmssp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/providers/windows/winrs"
)

const (
	account   = "alice-w7"
	imageAddr = "127.0.0.1:5986" // the image's 0.0.0.0:5986 listener (F8), never changed
	// The renewal test listener (F28), on the fixture ports 45520-45539.
	renewPort     = "45520"
	renewAddr     = "127.0.0.1:" + renewPort
	renewHostname = "alice-w7-listener"

	latfpKey     = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	lsaKey       = `SYSTEM\CurrentControlSet\Control\Lsa`
	auditKey     = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
	adminsSID    = "S-1-5-32-544"
	localAdmSID  = "S-1-5-114" // "Local account and member of Administrators group"
	callTimeout  = time.Minute
	maxOutput    = 1 << 20
	asFoundFile  = "alice-w7-settings-as-found.txt" // in os.TempDir(); TestRealRunnerIsClean compares with it
	listenerSels = `@{ Address = 'IP:127.0.0.1'; Transport = 'HTTPS' }`
)

func requireReal(t *testing.T) {
	t.Helper()
	if os.Getenv("ALICE_WIN_REAL") != "1" {
		t.Skip("set ALICE_WIN_REAL=1 to run against this Windows machine")
	}
}

// fact logs a measured value with the prefix the controller searches the run log for.
func fact(t *testing.T, id, format string, args ...any) {
	t.Helper()
	t.Logf("FACT "+id+": "+format, args...)
}

// ---- PowerShell (tests only; copied from internal/providers/windows' setup test) ---------------------------

// powershellEnviron is this process's environment without PSModulePath: Windows PowerShell 5.1 must not load
// pwsh 7's modules (Windows run 1 of W1).
func powershellEnviron() []string {
	out := []string{}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !strings.EqualFold(k, "PSModulePath") {
			out = append(out, kv)
		}
	}
	return out
}

// psRun runs a fixture or check script. Values reach it through $env:, a secret only through stdin (one line).
func psRun(env map[string]string, stdin, script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		// exit 0 at the end: powershell.exe -Command otherwise exits 1 when the last statement left $? false (an error
		// caught or silenced on the way, runner run 1); a terminating error still ends it with 1 before that line.
		"$ErrorActionPreference = 'Stop'; Import-Module Microsoft.WSMan.Management; "+script+"\nexit 0")
	cmd.Env = powershellEnviron()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin + "\r\n")
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return strings.TrimSpace(string(out)), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func ps(t *testing.T, env map[string]string, stdin, script string) string {
	t.Helper()
	out, err := psRun(env, stdin, script)
	require.NoError(t, err, "powershell: %s\nstdout: %s", script, out)
	return out
}

// ---- the settings, as found and restored ----------------------------------------------------------------

// settings reads testdata/settings.ps1's name=value lines.
func settings(t *testing.T) map[string]string {
	t.Helper()
	script, err := os.ReadFile(filepath.Join("testdata", "settings.ps1"))
	require.NoError(t, err)
	m := map[string]string{}
	for _, l := range strings.Split(ps(t, nil, "", string(script)), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			m[k] = v
		}
	}
	require.Contains(t, m, "Service.Auth.Negotiate", "the settings script ran")
	return m
}

var asFoundOnce sync.Once

// recordAsFound writes the settings as the first fixture of this run found them, for TestRealRunnerIsClean.
func recordAsFound(t *testing.T, m map[string]string) {
	asFoundOnce.Do(func() {
		var lines []string // sorted name=value lines, as TestRealRunnerIsClean sorts its own
		for k, v := range m {
			lines = append(lines, k+"="+v)
		}
		slices.Sort(lines)
		require.NoError(t, os.WriteFile(filepath.Join(os.TempDir(), asFoundFile), []byte(strings.Join(lines, "\n")+"\n"), 0o600))
		t.Logf("the settings as found: %s", strings.Join(lines, ", "))
	})
}

// setDWORD sets an HKLM value and restores it as found (deleted when it was absent). The returned function
// restores at once; the cleanup then does nothing.
func setDWORD(t *testing.T, path, name string, v uint32) func() {
	t.Helper()
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.SET_VALUE)
	require.NoError(t, err)
	defer func() { _ = k.Close() }()
	old, _, err := k.GetIntegerValue(name)
	absent := errors.Is(err, registry.ErrNotExist)
	if !absent {
		require.NoError(t, err, "HKLM\\%s %s", path, name)
	}
	restore := sync.OnceFunc(func() {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
		if err == nil {
			if absent {
				err = k.DeleteValue(name)
			} else {
				err = k.SetDWordValue(name, uint32(old)) //nolint:gosec // G115: a DWORD read back
			}
			_ = k.Close()
		}
		if err != nil {
			t.Errorf("restoring HKLM\\%s %s: %v", path, name, err)
		}
	})
	t.Cleanup(restore)
	require.NoError(t, k.SetDWordValue(name, v))
	if absent {
		t.Logf("HKLM\\%s %s set to %d (absent before)", path, name, v)
	} else {
		t.Logf("HKLM\\%s %s set to %d (%d before)", path, name, v, old)
	}
	return restore
}

const wsmanSet = `Set-Item -LiteralPath ('WSMan:\localhost\' + $env:ITEM) -Value $env:VALUE -Force`

// wsmanServiceKey holds the WinRM service's configuration (Service\Auth\* among it).
const wsmanServiceKey = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service`

func regExe(args ...string) (string, error) {
	out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "reg.exe"), args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// setWSMan sets a WSMan: item (Service\Auth\Basic and the like) and restores it as found. The WSMan: drive is
// WinRM's own client, signing in to the local service with Negotiate: with Negotiate off (F30 a), or anything else
// that refuses it, the drive cannot restore anything (runner run 2). So the service's registry key is exported
// before the change, and a restore the drive refuses replaces the key with that export and restarts WinRM.
func setWSMan(t *testing.T, item, value string) func() {
	t.Helper()
	old := ps(t, map[string]string{"ITEM": item}, "", `(Get-Item -LiteralPath ('WSMan:\localhost\' + $env:ITEM)).Value`)
	snapshot := filepath.Join(t.TempDir(), "wsman-service.reg") // removed after the restore below (cleanups run last in, first out)
	out, err := regExe("export", wsmanServiceKey, snapshot, "/y")
	require.NoError(t, err, "reg export: %s", out)
	restore := sync.OnceFunc(func() {
		out, err := psRun(map[string]string{"ITEM": item, "VALUE": old}, "", wsmanSet)
		if err == nil {
			return
		}
		t.Logf("restoring WSMan:\\localhost\\%s through the WSMan: drive failed (%v: %s); restoring %s from its export", item, err, out, wsmanServiceKey)
		if out, err := regExe("delete", wsmanServiceKey, "/f"); err != nil {
			t.Errorf("reg delete %s: %v: %s", wsmanServiceKey, err, out)
		}
		if out, err := regExe("import", snapshot); err != nil {
			t.Errorf("reg import of %s: %v: %s", wsmanServiceKey, err, out)
			return
		}
		if out, err := psRun(nil, "", `Restart-Service -Name WinRM -Force`); err != nil {
			t.Errorf("Restart-Service WinRM: %v: %s", err, out)
			return
		}
		got, err := waitWSMan(item, time.Minute)
		if err != nil || got != old {
			t.Errorf("LOUD: WSMan:\\localhost\\%s is %q after the registry restore and a WinRM restart, not %q as found: %v", item, got, old, err)
			return
		}
		t.Logf("WSMan:\\localhost\\%s restored to %s through the registry and a WinRM restart", item, old)
	})
	t.Cleanup(restore)
	ps(t, map[string]string{"ITEM": item, "VALUE": value}, "", wsmanSet)
	q, _ := regExe("query", wsmanServiceKey)
	t.Logf("WSMan:\\localhost\\%s set to %s (%s before); %s now: %s", item, value, old, wsmanServiceKey, strings.Join(strings.Fields(q), " "))
	return restore
}

// waitWSMan reads a WSMan: item, retrying while the service starts.
func waitWSMan(item string, within time.Duration) (string, error) {
	end := time.Now().Add(within)
	for {
		got, err := psRun(map[string]string{"ITEM": item}, "", `(Get-Item -LiteralPath ('WSMan:\localhost\' + $env:ITEM)).Value`)
		if err == nil || time.Now().After(end) {
			return got, err
		}
		time.Sleep(2 * time.Second)
	}
}

// auditProcessCreation turns on the Process Creation audit subcategory and command lines in 4688, and restores
// the audit policy (auditpol /backup and /restore) and the value as found.
func auditProcessCreation(t *testing.T) {
	t.Helper()
	auditpol := filepath.Join(os.Getenv("SystemRoot"), "System32", "auditpol.exe")
	backup := filepath.Join(t.TempDir(), "audit.csv")
	out, err := exec.Command(auditpol, "/backup", "/file:"+backup).CombinedOutput()
	require.NoError(t, err, "auditpol /backup: %s", out)
	t.Cleanup(func() {
		if out, err := exec.Command(auditpol, "/restore", "/file:"+backup).CombinedOutput(); err != nil {
			t.Errorf("auditpol /restore: %v: %s", err, out)
		}
	})
	out, err = exec.Command(auditpol, "/set", "/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}", "/success:enable").CombinedOutput()
	require.NoError(t, err, "auditpol /set: %s", out)
	setDWORD(t, auditKey, "ProcessCreationIncludeCmdLine_Enabled", 1)
}

// ---- account rights through the LSA (atomic per SID and right: TestRealSetupScript, in another package, may
// run secedit at the same time) ---------------------------------------------------------------------------

var (
	modadvapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy             = modadvapi32.NewProc("LsaOpenPolicy")
	procLsaClose                  = modadvapi32.NewProc("LsaClose")
	procLsaAddAccountRights       = modadvapi32.NewProc("LsaAddAccountRights")
	procLsaRemoveAccountRights    = modadvapi32.NewProc("LsaRemoveAccountRights")
	procLsaEnumerateAccountRights = modadvapi32.NewProc("LsaEnumerateAccountRights")
	procLsaFreeMemory             = modadvapi32.NewProc("LsaFreeMemory")
)

const (
	policyAllAccess          = 0x000F0FFF
	statusObjectNameNotFound = 0xC0000034
)

func withPolicy(f func(policy uintptr) uintptr) error {
	var attrs windows.OBJECT_ATTRIBUTES
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var policy uintptr
	if st, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)), policyAllAccess, uintptr(unsafe.Pointer(&policy))); st != 0 {
		return fmt.Errorf("LsaOpenPolicy: NTSTATUS %#x", st)
	}
	defer func() { _, _, _ = procLsaClose.Call(policy) }()
	if st := f(policy); st != 0 {
		return fmt.Errorf("NTSTATUS %#x", st)
	}
	return nil
}

func accountRights(sid *windows.SID) ([]string, error) {
	var out []string
	err := withPolicy(func(p uintptr) uintptr {
		var rights *windows.NTUnicodeString
		var n uint32
		st, _, _ := procLsaEnumerateAccountRights.Call(p, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&rights)), uintptr(unsafe.Pointer(&n)))
		if uint32(st) == statusObjectNameNotFound { // no right at all
			return 0
		}
		if st == 0 {
			for _, r := range unsafe.Slice(rights, n) {
				out = append(out, r.String())
			}
			_, _, _ = procLsaFreeMemory.Call(uintptr(unsafe.Pointer(rights)))
		}
		return st
	})
	return out, err
}

func changeRight(sid *windows.SID, right string, add bool) error {
	us, err := windows.NewNTUnicodeString(right)
	if err != nil {
		return err
	}
	return withPolicy(func(p uintptr) uintptr {
		var st uintptr
		if add {
			st, _, _ = procLsaAddAccountRights.Call(p, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(us)), 1)
		} else {
			st, _, _ = procLsaRemoveAccountRights.Call(p, uintptr(unsafe.Pointer(sid)), 0, uintptr(unsafe.Pointer(us)), 1)
		}
		return st
	})
}

func holds(t *testing.T, sid *windows.SID, right string) bool {
	t.Helper()
	rights, err := accountRights(sid)
	require.NoError(t, err)
	return slices.Contains(rights, right)
}

// grantRight gives sid the right and takes it back at the end (or when the returned function runs); a right sid
// held already is left alone.
func grantRight(t *testing.T, sid *windows.SID, right string) func() {
	t.Helper()
	if holds(t, sid, right) {
		fact(t, "F31", "%s already holds %s as found (left alone)", sid, right)
		return func() {}
	}
	restore := sync.OnceFunc(func() {
		if err := changeRight(sid, right, false); err != nil {
			t.Errorf("removing %s from %s: %v", right, sid, err)
		}
	})
	t.Cleanup(restore)
	require.NoError(t, changeRight(sid, right, true), "adding %s to %s", right, sid)
	return restore
}

// ---- the account ------------------------------------------------------------------------------------------

const adminsGroup = `$g = (New-Object System.Security.Principal.SecurityIdentifier('` + adminsSID + `')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
$grp = [ADSI]"WinNT://$env:COMPUTERNAME/$g,group"
$member = "WinNT://$env:COMPUTERNAME/$env:ACCOUNT" # the setup script's form
`

func newPassword(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 14)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	return "Aa1!" + hex.EncodeToString(raw) // 32 characters: upper, lower, digit and symbol, within Alice's rule
}

func deleteAccount() (profileLeft string, err error) {
	// Win32_UserAccount answers an absent account with nothing ([ADSI]::Exists and NTAccount.Translate throw, run 1).
	// The account is deleted even when its profile cannot be removed (still loaded for a moment after a sign-in):
	// the profile error is reported after the deletion.
	out, err := psRun(map[string]string{"ACCOUNT": account}, "", `$u = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND Name='$($env:ACCOUNT)'")
if ($u.Count -eq 0) { exit 0 }
$sid = $u[0].SID
$profileError = ''
for ($i = 0; $i -lt 5; $i++) {
    try {
        Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $sid } | Remove-CimInstance
        $profileError = ''
        break
    } catch {
        $profileError = $_.Exception.Message
        Start-Sleep -Seconds 2
    }
}
([ADSI]"WinNT://$env:COMPUTERNAME,computer").Delete('User', $env:ACCOUNT)
if ($profileError) { "profile: $profileError" }`)
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, out)
	}
	return out, nil
}

// setPassword changes alice-w7's password (on the child's stdin).
func setPassword(t *testing.T, pw string) {
	t.Helper()
	ps(t, map[string]string{"ACCOUNT": account}, pw, `$pw = [Console]::In.ReadLine()
([ADSI]"WinNT://$env:COMPUTERNAME/$env:ACCOUNT,user").SetPassword($pw)
Remove-Variable pw`)
}

// administrators adds alice-w7 to Administrators or removes it.
func administrators(t *testing.T, add bool) error {
	t.Helper()
	op := "Remove"
	if add {
		op = "Add"
	}
	out, err := psRun(map[string]string{"ACCOUNT": account}, "", adminsGroup+`$grp.`+op+`($member)`)
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// ---- the fixture --------------------------------------------------------------------------------------------

type fx struct {
	pw        string // alice-w7's password, never logged
	host      string // the computer name (the HOSTNAME\ form, Ruling 6)
	spki      []byte // the SubjectPublicKeyInfo 127.0.0.1:5986 presented first (the test's trust on first use)
	dir       string // the test programs: alice-helper.exe and stdinhash.exe
	helper    string
	stdinhash string
	asFound   map[string]string
	dials     atomic.Int32 // the dials of every client of the fixture
	refused   atomic.Int32 // the handshakes a pin refused
}

// winrmFixture records the settings, creates alice-w7 in Administrators with a random password, builds the
// test programs and pins the image listener's presented SPKI. Everything is undone in t.Cleanup.
func winrmFixture(t *testing.T) *fx {
	t.Helper()
	requireReal(t)
	f := &fx{host: os.Getenv("COMPUTERNAME"), asFound: settings(t)}
	require.NotEmpty(t, f.host)
	recordAsFound(t, f.asFound)

	dir, err := os.MkdirTemp(os.Getenv("ProgramData"), "alice-w7-")
	require.NoError(t, err)
	t.Cleanup(func() {
		for i := 0; ; i++ { // a program a failed call left running may hold its file for a moment
			if err = os.RemoveAll(dir); err == nil || i == 20 {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			t.Errorf("removing %s: %v", dir, err)
		}
	})
	f.dir, f.stdinhash, f.helper = dir, filepath.Join(dir, "stdinhash.exe"), filepath.Join(dir, "alice-helper.exe")
	goBuild(t, f.stdinhash, "./testdata/stdinhash")
	if d := os.Getenv("ALICE_WIN_HELPER_DIR"); d != "" { // the helper the job built
		b, err := os.ReadFile(filepath.Join(d, "alice-winhelper-windows-"+runtime.GOARCH+".exe"))
		require.NoError(t, err, "ALICE_WIN_HELPER_DIR names the built helper")
		require.NoError(t, os.WriteFile(f.helper, b, 0o600))
	} else {
		goBuild(t, f.helper, "alice/cmd/alice-winhelper")
	}

	left, err := deleteAccount()
	require.NoError(t, err, "deleting an alice-w7 account left by an earlier run")
	if left != "" {
		t.Logf("an earlier %s was deleted; its %s", account, left)
	}
	t.Cleanup(func() {
		left, err := deleteAccount()
		if err != nil {
			t.Errorf("deleting %s: %v", account, err)
		} else if left != "" {
			t.Logf("%s is deleted; its %s", account, left)
		}
	})
	f.pw = newPassword(t)
	ps(t, map[string]string{"ACCOUNT": account}, f.pw, `$pw = [Console]::In.ReadLine()
$u = ([ADSI]"WinNT://$env:COMPUTERNAME,computer").Create('User', $env:ACCOUNT)
$u.SetPassword($pw)
$u.SetInfo()
Remove-Variable pw
$u.Put('Description', 'Alice W7 WinRS test (removed by the test)')
$u.Put('UserFlags', ([int]$u.Get('UserFlags')) -bor 0x10000)
$u.SetInfo()`)
	require.NoError(t, administrators(t, true))

	f.spki = waitLeaf(t, imageAddr, nil, 30*time.Second).RawSubjectPublicKeyInfo
	fact(t, "F28", "the image listener %s presents SPKI %s", imageAddr, fingerprint(f.spki))
	return f
}

func goBuild(t *testing.T, out, pkg string) {
	t.Helper()
	b, err := exec.Command("go", "build", "-o", out, pkg).CombinedOutput()
	require.NoError(t, err, "go build %s: %s", pkg, b)
}

// ---- TLS: the test's own pin --------------------------------------------------------------------------------

var errPin = errors.New("the presented SubjectPublicKeyInfo is not the pinned one")

// pinned accepts only a leaf with spki, as tlspin's pin mode does; refused counts the handshakes it refuses.
func pinned(spki []byte, refused *atomic.Int32) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // VerifyConnection below is the check: the pin, as tlspin's
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 && bytes.Equal(cs.PeerCertificates[0].RawSubjectPublicKeyInfo, spki) {
				return nil
			}
			if refused != nil {
				refused.Add(1)
			}
			return errPin
		},
	}
}

// presentedLeaf reads the leaf certificate addr presents (the identity only: nothing is sent).
func presentedLeaf(addr string) (*x509.Certificate, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr,
		&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}) // reads the identity only
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no certificate presented")
	}
	return certs[0], nil
}

// waitLeaf waits until addr presents want (any certificate when want is nil) and returns what it presents.
func waitLeaf(t *testing.T, addr string, want *x509.Certificate, within time.Duration) *x509.Certificate {
	t.Helper()
	end := time.Now().Add(within)
	for {
		got, err := presentedLeaf(addr)
		if err == nil && (want == nil || bytes.Equal(got.Raw, want.Raw)) {
			return got
		}
		if time.Now().After(end) {
			require.FailNow(t, "the listener did not present the expected certificate", "%s: err %v", addr, err)
		}
		time.Sleep(time.Second)
	}
}

// fingerprint is Alice's form of a TLS identity (providers.TLSIdentity): SHA256: and the unpadded base64.
func fingerprint(spki []byte) string {
	if spki == nil {
		return "(none)"
	}
	sum := sha256.Sum256(spki)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ---- the winrs client and its calls -----------------------------------------------------------------------

// client is a winrs.Client as alice-w7 (user as typed), pinned to the image listener, whose Dial counts in f.dials.
func (f *fx) client(t *testing.T, user string) *winrs.Client {
	t.Helper()
	return &winrs.Client{TLS: pinned(f.spki, &f.refused), User: user, Password: f.pw,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			f.dials.Add(1)
			return (&net.Dialer{Timeout: winrs.DefaultDialTimeout}).DialContext(ctx, network, addr)
		}}
}

// helperCall runs the helper's forced-command entry with line, as Alice does (Ruling 4), with the test's copy.
func (f *fx) helperCall(line string) winrs.Call {
	return winrs.Call{Addr: imageAddr, Program: f.helper, Args: []string{"ssh"},
		Env: map[string]string{"SSH_ORIGINAL_COMMAND": line}, Timeout: callTimeout, MaxOutput: maxOutput}
}

// hashCall runs stdinhash with stdin and args.
func (f *fx) hashCall(stdin []byte, args ...string) winrs.Call {
	return winrs.Call{Addr: imageAddr, Program: f.stdinhash, Args: args, Stdin: stdin, Timeout: callTimeout, MaxOutput: maxOutput}
}

func run(c *winrs.Client, call winrs.Call) (winrs.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return c.Run(ctx, call)
}

func decode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal(b, &v), "%s", b)
	return v
}

// ---- a hand-driven WS-Management connection, for what the client cannot show ------------------------------

// rawConn is one pinned HTTPS connection with go-ntlmssp's Negotiator over a RoundTripper that records every
// request on the wire: the Authorization scheme it carried (never the token) and the answer. It counts dials.
// It wraps the Negotiator as winrs does (Ruling 28) and, like winrs, sends credentials only when asked (the
// client asks on Create only).
type rawConn struct {
	url      string
	user, pw string
	tr       *http.Transport
	client   *http.Client
	dials    atomic.Int32
	mu       sync.Mutex
	reqs     []rawReq
}

type rawReq struct {
	auth   string   // the Authorization scheme sent, "" for none
	status int      // 0 when the request failed
	offers []string // the WWW-Authenticate schemes of the answer
}

func (r rawReq) String() string {
	if r.auth == "" {
		r.auth = "none"
	}
	return fmt.Sprintf("auth=%s status=%d offers=%v", r.auth, r.status, r.offers)
}

type recorder struct{ r *rawConn }

func (rec recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	scheme, _, _ := strings.Cut(req.Header.Get("Authorization"), " ")
	resp, err := rec.r.tr.RoundTrip(req)
	q := rawReq{auth: scheme}
	if err == nil {
		q.status = resp.StatusCode
		for _, v := range resp.Header.Values("WWW-Authenticate") {
			s, _, _ := strings.Cut(v, " ")
			q.offers = append(q.offers, s)
		}
	}
	rec.r.mu.Lock()
	rec.r.reqs = append(rec.r.reqs, q)
	rec.r.mu.Unlock()
	return resp, err
}

func newRaw(t *testing.T, addr string, spki []byte, user, pw string) *rawConn {
	t.Helper()
	r := &rawConn{url: "https://" + addr + "/wsman", user: user, pw: pw}
	r.tr = &http.Transport{
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			r.dials.Add(1)
			return (&net.Dialer{Timeout: winrs.DefaultDialTimeout}).DialContext(ctx, network, a)
		},
		TLSClientConfig:     pinned(spki, nil),
		TLSHandshakeTimeout: winrs.DefaultHandshakeTimeout,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	r.client = &http.Client{Transport: ntlmssp.Negotiator{RoundTripper: recorder{r}}, Timeout: 2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(r.close)
	return r
}

func (r *rawConn) close() { r.tr.CloseIdleConnections() }

type rawAnswer struct {
	status int
	header http.Header
	body   []byte
	reqs   []rawReq // the requests this post made on the wire
	err    error
}

// post sends one WS-Management request (through the Negotiator, so one post may be up to three requests).
func (r *rawConn) post(body []byte, creds bool) rawAnswer {
	r.mu.Lock()
	before := len(r.reqs)
	r.mu.Unlock()
	req, err := http.NewRequest(http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return rawAnswer{err: err}
	}
	req.Header.Set("Content-Type", winrs.ContentType)
	if creds {
		req.SetBasicAuth(r.user, r.pw)
	}
	a := rawAnswer{}
	resp, err := r.client.Do(req)
	if err == nil {
		a.status, a.header = resp.StatusCode, resp.Header
		a.body, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}
	a.err = err
	r.mu.Lock()
	a.reqs = slices.Clone(r.reqs[before:])
	r.mu.Unlock()
	return a
}

func (r *rawConn) header() winrs.Header {
	return winrs.Header{To: r.url, MessageID: "uuid:" + uuid.NewString()}
}

func (a rawAnswer) fault() string {
	if fe, ok := winrs.ParseFault(a.body); ok {
		return fmt.Sprintf("fault %d", fe.Code)
	}
	return "no fault"
}

// create creates a shell with the credentials (the NTLM exchange) and returns its id.
func (r *rawConn) create(t *testing.T, idle time.Duration) (string, rawAnswer) {
	t.Helper()
	body, err := winrs.CreateShellRequest(r.header(), nil, idle)
	require.NoError(t, err)
	return r.createBody(t, body)
}

// createBody sends a Create request built by the caller.
func (r *rawConn) createBody(t *testing.T, body []byte) (string, rawAnswer) {
	t.Helper()
	a := r.post(body, true)
	require.NoError(t, a.err)
	require.Equal(t, http.StatusOK, a.status, "Create: %v, %s", a.reqs, a.fault())
	id, err := winrs.ParseShellCreated(a.body)
	require.NoError(t, err)
	return id, a
}

// command starts program with args in the shell and returns the command id.
func (r *rawConn) command(t *testing.T, shell, program string, args ...string) string {
	t.Helper()
	body, err := winrs.CommandRequest(r.header(), shell, program, args)
	require.NoError(t, err)
	a := r.post(body, false)
	require.NoError(t, a.err)
	require.Equal(t, http.StatusOK, a.status, "Command: %v, %s", a.reqs, a.fault())
	id, err := winrs.ParseCommandStarted(a.body)
	require.NoError(t, err)
	return id
}

// receive asks for the command's output until it is done and returns its stdout, stderr and exit code.
func (r *rawConn) receive(shell, cmdID string) (stdout, stderr []byte, code int, err error) {
	const timedOut = 2150858793 // w:TimedOut: no output within the OperationTimeout; asked again
	for end := time.Now().Add(2 * time.Minute); time.Now().Before(end); {
		h := r.header()
		h.OperationTimeout = 20 * time.Second
		body, err := winrs.ReceiveRequest(h, shell, cmdID)
		if err != nil {
			return nil, nil, 0, err
		}
		a := r.post(body, false)
		if a.err != nil {
			return stdout, stderr, 0, a.err
		}
		if fe, ok := winrs.ParseFault(a.body); ok && a.status != http.StatusOK {
			if fe.Code == timedOut {
				continue
			}
			return stdout, stderr, 0, fe
		}
		if a.status != http.StatusOK {
			return stdout, stderr, 0, fmt.Errorf("Receive answered %d", a.status)
		}
		got, err := winrs.ParseReceived(a.body, cmdID)
		if err != nil {
			return stdout, stderr, 0, fmt.Errorf("%w: %.600s", err, a.body)
		}
		stdout, stderr = append(stdout, got.Stdout...), append(stderr, got.Stderr...)
		if got.Done {
			return stdout, stderr, got.ExitCode, nil
		}
	}
	return stdout, stderr, 0, errors.New("the command did not end within 2 minutes")
}

// delete deletes the shell; its answer is logged only.
func (r *rawConn) delete(t *testing.T, shell string) {
	t.Helper()
	body, err := winrs.DeleteRequest(r.header(), shell)
	require.NoError(t, err)
	a := r.post(body, false)
	t.Logf("Delete: status %d, err %v", a.status, a.err)
}

// ---- Windows' records ---------------------------------------------------------------------------------------

type logon struct {
	ID          int
	Time        string
	LogonType   string
	Package     string
	Lm          string
	Domain      string
	Workstation string
	Elevated    string
	Status      string
	SubStatus   string
}

func (l logon) String() string {
	return fmt.Sprintf("%d at %s: type %s, package %s, LmPackageName %q, domain %s, workstation %q, elevated %s, status %s/%s",
		l.ID, l.Time, l.LogonType, l.Package, l.Lm, l.Domain, l.Workstation, l.Elevated, l.Status, l.SubStatus)
}

const sinceScript = `$since = [datetime]::Parse($env:SINCE, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
function Get-Data($e) { $d = @{}; foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = "$($n.'#text')" }; $d }
`

// logons is alice-w7's Security 4624 and 4625 events since t0.
func logons(t *testing.T, t0 time.Time) []logon {
	t.Helper()
	out := ps(t, map[string]string{"SINCE": t0.UTC().Format(time.RFC3339Nano), "ACCOUNT": account}, "", sinceScript+`$out = @()
foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4625; StartTime = $since } -ErrorAction SilentlyContinue)) {
    $d = Get-Data $e
    if ($d['TargetUserName'] -ne $env:ACCOUNT) { continue }
    $out += [pscustomobject]@{ ID = $e.Id; Time = $e.TimeCreated.ToUniversalTime().ToString('o'); LogonType = $d['LogonType']
        Package = $d['AuthenticationPackageName']; Lm = $d['LmPackageName']; Domain = $d['TargetDomainName']
        Workstation = $d['WorkstationName']; Elevated = $d['ElevatedToken']; Status = $d['Status']; SubStatus = $d['SubStatus'] }
}
ConvertTo-Json -Compress -InputObject @($out)`)
	return decode[[]logon](t, []byte(out))
}

// waitLogons waits up to 15 s for an event id of alice-w7 since t0 and returns all of them.
func waitLogons(t *testing.T, t0 time.Time, id int) []logon {
	t.Helper()
	end := time.Now().Add(15 * time.Second)
	for {
		got := logons(t, t0)
		if slices.ContainsFunc(got, func(l logon) bool { return l.ID == id }) || time.Now().After(end) {
			return got
		}
		time.Sleep(2 * time.Second)
	}
}

// winrmEvents is the ids of the Microsoft-Windows-WinRM/Operational events since t0.
func winrmEvents(t *testing.T, t0 time.Time) string {
	t.Helper()
	return ps(t, map[string]string{"SINCE": t0.UTC().Format(time.RFC3339Nano)}, "", sinceScript+
		`$ids = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WinRM/Operational'; StartTime = $since } -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
"$($ids.Count) events, ids [$($ids -join ' ')]"`)
}

// ---- the renewal test listener (F28) ----------------------------------------------------------------------

// listenerCert is a self-signed server certificate for renewHostname (WinRM wants the CN to be the
// listener's Hostname).
func listenerCert(t *testing.T, key *rsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: renewHostname}, DNSNames: []string{renewHostname},
		NotBefore: notBefore, NotAfter: notAfter, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

// importCert puts the certificate and its key in LocalMachine\My (the PFX password on stdin) and removes both
// at the end. It returns the thumbprint.
func importCert(t *testing.T, c *x509.Certificate, key crypto.Signer) string {
	t.Helper()
	pw := newPassword(t)
	pfx, err := pkcs12.LegacyDES.Encode(key, c, nil, pw) // the widest Import-PfxCertificate support; the file is temporary
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "listener.pfx")
	require.NoError(t, os.WriteFile(path, pfx, 0o600))
	thumb := thumbprint(c)
	removeCertLater(t, "My", thumb)
	got := ps(t, map[string]string{"PFX": path}, pw, `$pw = ConvertTo-SecureString -String ([Console]::In.ReadLine()) -AsPlainText -Force
(Import-PfxCertificate -FilePath $env:PFX -CertStoreLocation Cert:\LocalMachine\My -Password $pw).Thumbprint`)
	require.Equal(t, thumb, got)
	return thumb
}

// thumbprint is Windows' name of a certificate: the upper-case hex SHA-1 of its DER.
func thumbprint(c *x509.Certificate) string {
	return fmt.Sprintf("%X", sha1.Sum(c.Raw)) //nolint:gosec // the thumbprint, Windows' name of the certificate
}

// removeCertLater removes a certificate of a LocalMachine store at the end, with its key when it has one; a key
// already gone (several certificates of one key, F28) or a certificate never added is not an error.
func removeCertLater(t *testing.T, store, thumb string) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := psRun(map[string]string{"STORE": store, "THUMB": thumb}, "", `$p = "Cert:\LocalMachine\$env:STORE\$env:THUMB"
if (Test-Path -LiteralPath $p) {
    try { Remove-Item -LiteralPath $p -DeleteKey } catch { Remove-Item -LiteralPath $p }
}`); err != nil {
			t.Errorf("removing the certificate %s from %s: %v: %s", thumb, store, err, out)
		}
	})
}

// testListener creates the HTTPS listener 127.0.0.1:45520 with the certificate and removes it at the end.
func testListener(t *testing.T, thumb string) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := psRun(nil, "", `$l = @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate | Where-Object { $_.Port -eq '`+renewPort+`' })
if ($l.Count -gt 0) { Remove-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet `+listenerSels+` }`); err != nil {
			t.Errorf("removing the test listener: %v: %s", err, out)
		}
		// The http.sys record WinRM made for it, if the removal left it (or setListenerCert made it).
		netsh := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
		if out, err := exec.Command(netsh, "http", "show", "sslcert", "ipport="+renewAddr).CombinedOutput(); err == nil && bytes.Contains(out, []byte(renewPort)) {
			out, err = exec.Command(netsh, "http", "delete", "sslcert", "ipport="+renewAddr).CombinedOutput()
			t.Logf("the http.sys record %s was left after the listener's removal; deleted: %v: %s", renewAddr, err, bytes.TrimSpace(out))
		}
	})
	ps(t, map[string]string{"THUMB": thumb}, "", `New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet `+listenerSels+
		` -ValueSet @{ Hostname = '`+renewHostname+`'; CertificateThumbprint = $env:THUMB; Port = '`+renewPort+`' } | Out-Null`)
}

// setListenerCert points the test listener at another certificate. WinRM may refuse a certificate (an expired
// one): then the listener's http.sys record is updated directly, as a renewal outside WinRM would; it says which.
func setListenerCert(t *testing.T, thumb string) string {
	t.Helper()
	out, err := psRun(map[string]string{"THUMB": thumb}, "", `Set-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet `+listenerSels+
		` -ValueSet @{ CertificateThumbprint = $env:THUMB } | Out-Null`)
	if err == nil {
		return "Set-WSManInstance"
	}
	t.Logf("Set-WSManInstance refused the certificate %s: %v: %s; updating the http.sys record", thumb, err, out)
	netsh := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	b, err := exec.Command(netsh, "http", "update", "sslcert", "ipport="+renewAddr, "certhash="+thumb,
		"appid={afebb9ad-9b97-4a91-9ab5-daf4d59122f6}", "certstorename=MY").CombinedOutput()
	require.NoError(t, err, "netsh http update sslcert: %s", b)
	return "netsh http update sslcert"
}

// ---- small helpers --------------------------------------------------------------------------------------------

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// startWatcher starts a PowerShell loop that waits up to 60 s for a running stdinhash.exe and prints its command
// line, its parent's image and its owner as JSON. It returns once the loop runs; wait reads the answer.
func startWatcher(t *testing.T) (wait func() string) {
	t.Helper()
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		`$ErrorActionPreference = 'Stop'
[Console]::Out.WriteLine('ready'); [Console]::Out.Flush()
$deadline = (Get-Date).AddSeconds(60)
do {
    $p = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='stdinhash.exe'")
    if ($p.Count -gt 0) { break }
    Start-Sleep -Milliseconds 100
} while ((Get-Date) -lt $deadline)
if ($p.Count -eq 0) { 'none'; exit 0 }
$x = $p[0]
# The parent and the owner are read with the program running; a program gone in between leaves them empty.
$parent = $null; $o = $null
try { $parent = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($x.ParentProcessId)" } catch { }
try { $o = Invoke-CimMethod -InputObject $x -MethodName GetOwner } catch { }
[pscustomobject]@{ CommandLine = "$($x.CommandLine)"; Parent = "$($parent.Name)"; ParentCommandLine = "$($parent.CommandLine)"; Owner = "$($o.Domain)\$($o.User)" } | ConvertTo-Json -Compress
exit 0`)
	cmd.Env = powershellEnviron()
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	rd := bufio.NewReader(stdout)
	line, err := rd.ReadString('\n')
	require.NoError(t, err, "the watcher: %s", stderr.String())
	require.Equal(t, "ready", strings.TrimSpace(line))
	return func() string {
		rest, _ := io.ReadAll(rd)
		require.NoError(t, cmd.Wait(), "the watcher: %s", stderr.String())
		return strings.TrimSpace(string(rest))
	}
}
