//go:build windows

package windows

// The WinRM setup script and the provider over real WinRS (R71 Task 7, F32). Every test here runs SetupScriptWinRM on
// this machine (it changes the account alice, the helper under Program Files, the firewall and possibly the token
// policy), so they run only when ALICE_WIN_SETUP=1, as TestRealSetupScript. The script talks to the image's HTTPS
// listener 0.0.0.0:5986 (F8), which is never changed. The firewall rule Alice-WinRM-In, the token policy, the F32
// listener 127.0.0.1:45521, the IIS fixture on 45522 and every certificate a test adds are undone in t.Cleanup. The
// account's password is generated with crypto/rand, reaches PowerShell on stdin only and is never logged. Measured
// values are logged with the prefix "FACT F32:".
//
// This file's name sorts after setup_windows_test.go, so on the runner TestRealSetupScript has made the account alice
// before these tests run (the script's path for an existing local account); run alone, the script creates it.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the certificate thumbprint Windows names a certificate by
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	xwindows "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/tlspin"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/winrs"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

const (
	winrmImageAddr    = "127.0.0.1:5986" // the image's 0.0.0.0:5986 listener (F8)
	winrmF32Port      = "45521"          // the ECDSA listener of F32 (fixture ports 45520-45539)
	winrmF32Addr      = "127.0.0.1:" + winrmF32Port
	winrmF32Host      = "alice-w7-f32" // WinRM wants the listener's Hostname to be its certificate's CN
	winrmListenerSels = `@{ Address = 'IP:127.0.0.1'; Transport = 'HTTPS' }`
	winrmSiteName     = "alice-w7-provider"
	winrmSitePort     = 45522
	winrmFirewallRule = "Alice-WinRM-In"
	winrmPolicyKey    = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	winrmPolicyValue  = "LocalAccountTokenFilterPolicy"
	winrmReadyLine    = "This server is ready for Alice over WinRM."
	winrmScriptName   = "alice-winrm-setup.ps1"
	winrmHarnessName  = "alice-winrm-harness.ps1"
)

// winrmHarness is a test-only wrapper around the generated script, never part of the product: with -PasswordFromStdin
// its Read-Host (a function, which PowerShell resolves before the cmdlet) answers each of the script's password
// prompts with one line of stdin as a SecureString, so the script runs unattended under -NonInteractive. Without the
// switch a prompt fails, as it would for an operator who cannot answer.
const winrmHarness = `param([switch]$PasswordFromStdin)
if ($PasswordFromStdin) {
    function Read-Host {
        param([string]$Prompt, [switch]$AsSecureString)
        $line = [Console]::In.ReadLine()
        $s = New-Object System.Security.SecureString
        if ($null -ne $line) { foreach ($c in $line.ToCharArray()) { $s.AppendChar($c) } }
        $s.MakeReadOnly()
        return $s
    }
}
& (Join-Path $PSScriptRoot '` + winrmScriptName + `')
`

// winrmModule loads the WSMan: drive only where it is missing (PowerShell 7): Import-Module of the module failed in a
// Windows PowerShell child of the test on the runners (W7 run 2), where 5.1 has the drive from the start.
const winrmModule = "if (-not (Get-PSDrive -Name WSMan -ErrorAction SilentlyContinue)) { Import-Module Microsoft.WSMan.Management }\n"

// winrmPS runs a check or fixture script (tests only). Values reach it through $env:, a secret only through stdin.
// It ends with exit 0: powershell.exe -Command otherwise exits 1 when the last statement left $? false (an error
// caught or silenced on the way, W7 runner run 1); a terminating error still ends it with 1 before that line.
func winrmPS(env map[string]string, stdin, script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"$ErrorActionPreference = 'Stop'; "+winrmModule+script+"\nexit 0")
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

func winrmPSMust(t *testing.T, env map[string]string, stdin, script string) string {
	t.Helper()
	out, err := winrmPS(env, stdin, script)
	require.NoError(t, err, "powershell: %s\nstdout: %s", script, out)
	return out
}

// winrmPassword is a new password within Alice's rule: 32 characters with upper and lower case, a digit and a symbol.
func winrmPassword(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 14)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	return "Aa1!" + hex.EncodeToString(raw)
}

// winrmSetup is a directory that holds .\alice-helper.exe (the helper the job built, its checksums embedded as the
// image build would), where the WinRM script runs.
type winrmSetup struct {
	dir   string
	amd64 string
}

// newWinRMSetup skips unless ALICE_WIN_SETUP=1. It restores the token policy as found and removes the firewall rule
// Alice-WinRM-In when the test ends (both registered before any run of the script).
func newWinRMSetup(t *testing.T) *winrmSetup {
	t.Helper()
	if os.Getenv("ALICE_WIN_SETUP") != "1" {
		t.Skip("set ALICE_WIN_SETUP=1 to prepare this Windows machine for Alice over WinRM (it changes the machine)")
	}
	require.Equal(t, "amd64", runtime.GOARCH, "the runners are AMD64")
	amd64, arm64 := setupHelpers(t)
	withChecksums(t, setupFileSHA256(t, amd64), setupFileSHA256(t, arm64))
	dir := t.TempDir()
	setupCopy(t, amd64, filepath.Join(dir, "alice-helper.exe"))
	keepTokenPolicy(t)
	t.Cleanup(func() {
		if out, err := winrmPS(nil, "", `Remove-NetFirewallRule -Name '`+winrmFirewallRule+`' -ErrorAction SilentlyContinue`); err != nil {
			t.Errorf("removing the firewall rule %s: %v: %s", winrmFirewallRule, err, out)
		}
	})
	return &winrmSetup{dir: dir, amd64: amd64}
}

// run runs the script for user through the harness, as an administrator would, in the directory that holds
// .\alice-helper.exe. answers nil runs it without -PasswordFromStdin. Every secret is checked to be absent from the
// output and replaced before the output is logged or returned.
func (w *winrmSetup) run(t *testing.T, user string, answers []string, secrets ...string) (string, error) {
	t.Helper()
	script, err := SetupScriptWinRM(user, "", false)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(w.dir, winrmScriptName), []byte(script), 0o600))
	harness := filepath.Join(w.dir, winrmHarnessName)
	require.NoError(t, os.WriteFile(harness, []byte(winrmHarness), 0o600))
	args := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness}
	if answers != nil {
		args = append(args, "-PasswordFromStdin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	cmd.Env = powershellEnviron()
	cmd.Dir = w.dir
	cmd.WaitDelay = 5 * time.Second
	if answers != nil {
		cmd.Stdin = strings.NewReader(strings.Join(answers, "\r\n") + "\r\n")
	}
	out, err := cmd.CombinedOutput()
	text := string(out)
	for _, s := range secrets {
		leaked := strings.Contains(text, s)
		text = strings.ReplaceAll(text, s, "<password>")
		assert.False(t, leaked, "the script's output holds a password it was given")
	}
	t.Logf("the WinRM setup script for %s (err %v):\n%s", user, err, text)
	return text, err
}

// prepared runs the script for alice with a new password and returns the password.
func (w *winrmSetup) prepared(t *testing.T) string {
	t.Helper()
	pw := winrmPassword(t)
	out, err := w.run(t, setupAccount, []string{pw, pw}, pw)
	require.NoError(t, err, "the WinRM setup script succeeds")
	require.Contains(t, out, winrmReadyLine)
	return pw
}

// readTokenPolicy is LocalAccountTokenFilterPolicy (absent: true when the value does not exist).
func readTokenPolicy(t *testing.T) (v uint32, absent bool) {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, winrmPolicyKey, registry.QUERY_VALUE)
	require.NoError(t, err)
	defer func() { _ = k.Close() }()
	got, _, err := k.GetIntegerValue(winrmPolicyValue)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, true
	}
	require.NoError(t, err)
	return uint32(got), false //nolint:gosec // G115: a DWORD read back
}

func tokenPolicyText(v uint32, absent bool) string {
	if absent {
		return "absent"
	}
	return strconv.FormatUint(uint64(v), 10)
}

// keepTokenPolicy restores LocalAccountTokenFilterPolicy as found when the test ends (deleted when it was absent).
func keepTokenPolicy(t *testing.T) {
	t.Helper()
	v, absent := readTokenPolicy(t)
	t.Cleanup(func() {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, winrmPolicyKey, registry.SET_VALUE)
		if err == nil {
			if absent {
				if err = k.DeleteValue(winrmPolicyValue); errors.Is(err, registry.ErrNotExist) {
					err = nil
				}
			} else {
				err = k.SetDWordValue(winrmPolicyValue, v)
			}
			_ = k.Close()
		}
		if err != nil {
			t.Errorf("restoring %s to %s: %v", winrmPolicyValue, tokenPolicyText(v, absent), err)
		}
	})
}

// winrmState is what the script must never change: the WinRM and LSA settings the WinRS fixture records (its
// testdata/settings.ps1, read here, without the token policy, which the script may set) and every listener.
func winrmState(t *testing.T) []string {
	t.Helper()
	script, err := os.ReadFile(filepath.Join("winrs", "testdata", "settings.ps1"))
	require.NoError(t, err)
	var out []string
	// Its own Import-Module line is replaced by winrmModule's guard (winrmPS adds it).
	text := strings.Replace(string(script), "Import-Module Microsoft.WSMan.Management\n", "", 1)
	for _, l := range strings.Split(winrmPSMust(t, nil, "", text), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, winrmPolicyValue+"=") {
			out = append(out, l)
		}
	}
	require.NotEmpty(t, out)
	for _, l := range strings.Split(winrmPSMust(t, nil, "", `foreach ($l in @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate)) {
    "listener $($l.Address) $($l.Transport) $($l.Port) $($l.Hostname) $($l.Enabled) $($l.CertificateThumbprint)"
}`), "\n") {
		out = append(out, strings.TrimSpace(l))
	}
	slices.Sort(out)
	return out
}

// ---- TLS -------------------------------------------------------------------------------------------------------

// winrmPinned accepts only a leaf with spki, as tlspin's pin mode does.
func winrmPinned(spki []byte) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, //nolint:gosec // G402: VerifyConnection pins the SPKI
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 && bytes.Equal(cs.PeerCertificates[0].RawSubjectPublicKeyInfo, spki) {
				return nil
			}
			return errors.New("not the pinned SubjectPublicKeyInfo")
		}}
}

// presented is the leaf addr presents to a handshake with sni ("" for none); nothing is sent after it.
func presented(addr, sni string) (*x509.Certificate, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr,
		&tls.Config{MinVersion: tls.VersionTLS12, ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec // G402: reads the identity only
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

// waitPresented waits up to a minute until addr presents want (any leaf when want is nil) and returns the leaf.
func waitPresented(t *testing.T, addr string, want *x509.Certificate) *x509.Certificate {
	t.Helper()
	var got *x509.Certificate
	var err error
	for end := time.Now().Add(time.Minute); ; time.Sleep(time.Second) {
		got, err = presented(addr, "")
		if err == nil && (want == nil || bytes.Equal(got.Raw, want.Raw)) {
			return got
		}
		if time.Now().After(end) {
			break
		}
	}
	gotName := ""
	if got != nil {
		gotName = got.Subject.CommonName
	}
	require.FailNow(t, "the listener does not present the expected certificate", "%s: presents %q, err %v", addr, gotName, err)
	return nil
}

// thumbOf is Windows' name of a certificate: the upper-case hex SHA-1 of its DER.
func thumbOf(c *x509.Certificate) string {
	return fmt.Sprintf("%X", sha1.Sum(c.Raw)) //nolint:gosec // the thumbprint, Windows' name of the certificate
}

// removeCertWhenDone removes a certificate of a LocalMachine store when the test ends, with its key when it has one;
// one never added is not an error.
func removeCertWhenDone(t *testing.T, store, thumb string) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := winrmPS(map[string]string{"STORE": store, "THUMB": thumb}, "", `$p = "Cert:\LocalMachine\$env:STORE\$env:THUMB"
if (Test-Path -LiteralPath $p) {
    if ((Get-Item -LiteralPath $p).HasPrivateKey) { Remove-Item -LiteralPath $p -DeleteKey } else { Remove-Item -LiteralPath $p }
}`); err != nil {
			t.Errorf("removing the certificate %s from %s: %v: %s", thumb, store, err, out)
		}
	})
}

// importWithKey puts the certificate and its key into LocalMachine\My through a PFX (its password on stdin) and
// removes both when the test ends. It returns the thumbprint.
func importWithKey(t *testing.T, c *x509.Certificate, key crypto.Signer) string {
	t.Helper()
	pw := winrmPassword(t)
	pfx, err := pkcs12.LegacyDES.Encode(key, c, nil, pw) // the widest Import-PfxCertificate support; the file is temporary
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "cert.pfx")
	require.NoError(t, os.WriteFile(path, pfx, 0o600))
	thumb := thumbOf(c)
	removeCertWhenDone(t, "My", thumb)
	got := winrmPSMust(t, map[string]string{"PFX": path}, pw, `$pw = ConvertTo-SecureString -String ([Console]::In.ReadLine()) -AsPlainText -Force
(Import-PfxCertificate -FilePath $env:PFX -CertStoreLocation Cert:\LocalMachine\My -Password $pw).Thumbprint`)
	require.Equal(t, thumb, got)
	return thumb
}

// f32Listener makes the HTTPS listener 127.0.0.1:45521 with a new ECDSA P-256 certificate and removes both when the
// test ends. It returns the certificate.
func f32Listener(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	require.NoError(t, err)
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: winrmF32Host}, DNSNames: []string{winrmF32Host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	thumb := importWithKey(t, c, key)
	t.Cleanup(func() {
		if out, err := winrmPS(nil, "", `$l = @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate | Where-Object { $_.Port -eq '`+winrmF32Port+`' })
if ($l.Count -gt 0) { Remove-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet `+winrmListenerSels+` }`); err != nil {
			t.Errorf("removing the F32 listener: %v: %s", err, out)
		}
		// The http.sys record WinRM made for it, if the removal left it.
		netsh := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
		if out, err := exec.Command(netsh, "http", "show", "sslcert", "ipport="+winrmF32Addr).CombinedOutput(); err == nil && bytes.Contains(out, []byte(winrmF32Port)) {
			out, err = exec.Command(netsh, "http", "delete", "sslcert", "ipport="+winrmF32Addr).CombinedOutput()
			t.Logf("the http.sys record %s was left after the listener's removal; deleted: %v: %s", winrmF32Addr, err, bytes.TrimSpace(out))
		}
	})
	winrmPSMust(t, map[string]string{"THUMB": thumb}, "", `New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet `+winrmListenerSels+
		` -ValueSet @{ Hostname = '`+winrmF32Host+`'; CertificateThumbprint = $env:THUMB; Port = '`+winrmF32Port+`' } | Out-Null`)
	return c
}

// ---- WinRS ---------------------------------------------------------------------------------------------------------

// winrsRun runs program with line in SSH_ORIGINAL_COMMAND through WinRS at addr, as user with pw, pinned to spki.
func winrsRun(addr string, spki []byte, user, pw, program, line string, stdin []byte) (winrs.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := &winrs.Client{TLS: winrmPinned(spki), User: user, Password: pw}
	return c.Run(ctx, winrs.Call{Addr: addr, Program: program, Args: []string{"ssh"},
		Env: map[string]string{"SSH_ORIGINAL_COMMAND": line}, Stdin: stdin, Timeout: time.Minute, MaxOutput: 1 << 20})
}

// winrsVersion is the installed helper's version answer over WinRS to the image's listener, as alice with pw.
func winrsVersion(t *testing.T, spki []byte, pw string) winproto.VersionResponse {
	t.Helper()
	r, err := winrsRun(winrmImageAddr, spki, setupAccount, pw, winproto.HelperPath, winproto.SubVersion, nil)
	require.NoError(t, err, "version over WinRS")
	require.Equal(t, 0, r.ExitCode, "version over WinRS: %s", r.Stdout)
	var v winproto.VersionResponse
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(r.Stdout), &v), "%s", r.Stdout)
	return v
}

// ---- the account -----------------------------------------------------------------------------------------------

// winrmAccountState is what the script sets on alice: its flags, its Administrators membership, and the deny rights.
func winrmAccountState(t *testing.T) (flags int, admin bool, rights map[string]string) {
	t.Helper()
	out := winrmPSMust(t, map[string]string{"ACCOUNT": setupAccount}, "", `[int](([ADSI]"WinNT://$env:COMPUTERNAME/$env:ACCOUNT,user").UserFlags.Value)`)
	flags, err := strconv.Atoi(out)
	require.NoError(t, err, out)

	asid, err := xwindows.StringToSid(setupAdministrators)
	require.NoError(t, err)
	group, _, _, err := asid.LookupAccount("")
	require.NoError(t, err)
	code, members := runNet(t, "", "localgroup", group)
	require.Equal(t, 0, code, "net localgroup %s: %s", group, members)
	for _, l := range strings.Split(members, "\n") {
		l = strings.TrimSpace(l)
		_, name, _ := strings.Cut(l, `\`)
		admin = admin || strings.EqualFold(l, setupAccount) || strings.EqualFold(name, setupAccount)
	}

	rights = map[string]string{}
	for _, l := range strings.Split(winrmPSMust(t, nil, "", `$inf = Join-Path $env:TEMP ('alice-w7-rights-' + [guid]::NewGuid().ToString('N') + '.inf')
try {
    & "$env:WINDIR\System32\secedit.exe" /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "secedit /export exited $LASTEXITCODE" }
    Get-Content -LiteralPath $inf -Encoding Unicode | Where-Object { $_ -match '^\s*SeDeny\w+LogonRight\s*=' }
} finally {
    Remove-Item -LiteralPath $inf -Force -ErrorAction SilentlyContinue
}`), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			rights[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return flags, admin, rights
}

// passwordLastSet is net user's "Password last set" line of alice.
func passwordLastSet(t *testing.T) string {
	t.Helper()
	code, out := runNet(t, "", "user", setupAccount)
	require.Equal(t, 0, code, "net user %s: %s", setupAccount, out)
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Password last set") {
			return strings.TrimSpace(l)
		}
	}
	require.FailNow(t, "net user names no Password last set", "%s", out)
	return ""
}

// firewallRule is the rule Alice-WinRM-In: display name, direction, action, enabled, protocol, port and addresses.
func firewallRule(t *testing.T) []string {
	t.Helper()
	return strings.Split(winrmPSMust(t, nil, "", `$r = Get-NetFirewallRule -Name '`+winrmFirewallRule+`'
$p = $r | Get-NetFirewallPortFilter
$a = $r | Get-NetFirewallAddressFilter
"$($r.DisplayName)|$($r.Direction)|$($r.Action)|$($r.Enabled)|$($p.Protocol)|$($p.LocalPort)|$(@($a.RemoteAddress) -join ',')"`), "|")
}

// listenerLine is the script's line for a listener: address, port, printed SPKI fingerprint and SHA-1 thumbprint.
var listenerLine = regexp.MustCompile(`(?m)^Listener (\S+) port (\d+): SPKI (SHA256:[A-Za-z0-9+/]+) \(SHA-1 thumbprint ([0-9A-F]+)\)\r?$`)

// printedListeners maps each port the script printed to its fingerprint and thumbprint.
func printedListeners(out string) map[string][2]string {
	m := map[string][2]string{}
	for _, g := range listenerLine.FindAllStringSubmatch(out, -1) {
		m[g[2]] = [2]string{g[3], g[4]}
	}
	return m
}

// ---- the tests -------------------------------------------------------------------------------------------------

// F32 and Ruling 18 on the runner: the script prepares alice with the password it asks for; WinRS signs in with it;
// the image's listener and its WinRM settings are as found; the printed SPKI fingerprints are what Alice's client sees.
func TestRealWinRMSetupScript(t *testing.T) {
	w := newWinRMSetup(t)

	// A domain account the server does not know: refused before any change, no account, no prompt (none is answered).
	out, err := w.run(t, `ALICEW7NODOM\alice-w7`, nil)
	require.Error(t, err, "an unknown domain account is refused")
	assert.Contains(t, out, "is not known to this server")
	assert.NotContains(t, out, "Creating the local account")

	f32 := f32Listener(t)
	image := waitPresented(t, winrmImageAddr, nil)
	waitPresented(t, winrmF32Addr, f32)
	before := winrmState(t)
	policy, absent := readTokenPolicy(t)
	found := tokenPolicyText(policy, absent)

	// Alice's rule and the confirmation: both refused before the account changes, the passwords never printed.
	short := "Aa1!" + hex.EncodeToString(make([]byte, 2)) // 8 characters
	out, err = w.run(t, setupAccount, []string{short}, short)
	require.Error(t, err, "a password outside Alice's rule is refused")
	assert.Contains(t, out, "12 to 128 printable ASCII characters")
	pw, other := winrmPassword(t), winrmPassword(t)
	out, err = w.run(t, setupAccount, []string{pw, other}, pw, other)
	require.Error(t, err, "two different entries are refused")
	assert.Contains(t, out, "The two passwords differ")

	out, err = w.run(t, setupAccount, []string{pw, pw}, pw)
	require.NoError(t, err, "the WinRM setup script succeeds")
	require.Contains(t, out, winrmReadyLine)
	fact := func(format string, args ...any) { t.Logf("FACT F32: "+format, args...) }
	fact("the script %s the local account %s", map[bool]string{true: "created", false: "set the password of"}[strings.Contains(out, "Creating the local account")], setupAccount)

	// The helper, the account (password never expires, an administrator, denied local and Remote Desktop sign-in, never
	// denied network sign-in).
	assert.Equal(t, setupFileSHA256(t, w.amd64), setupFileSHA256(t, winproto.HelperPath), "the helper is the built one")
	sid, _, _, err := xwindows.LookupSID("", setupAccount)
	require.NoError(t, err)
	flags, admin, rights := winrmAccountState(t)
	assert.NotZero(t, flags&0x10000, "PasswordNeverExpires (UserFlags %#x)", flags)
	assert.True(t, admin, "alice is a member of Administrators")
	// secedit names an account it can resolve by name, else by *SID (runner run 4).
	holds := func(right string) bool {
		for _, e := range strings.Split(rights[right], ",") {
			e = strings.TrimSpace(e)
			_, name, _ := strings.Cut(e, `\`)
			if e == "*"+sid.String() || strings.EqualFold(e, setupAccount) || strings.EqualFold(name, setupAccount) {
				return true
			}
		}
		return false
	}
	for _, r := range []string{"SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight"} {
		assert.True(t, holds(r), "%s holds alice: %q", r, rights[r])
	}
	assert.False(t, holds("SeDenyNetworkLogonRight"), "never denied network sign-in: %q", rights["SeDenyNetworkLogonRight"])

	// The token policy (F24): 1 for a local account, printed as found.
	now, nowAbsent := readTokenPolicy(t)
	assert.Contains(t, out, "LocalAccountTokenFilterPolicy found: "+found+";")
	if absent || policy == 0 {
		assert.Equal(t, "1", tokenPolicyText(now, nowAbsent), "set to 1 when 0 or absent")
	} else {
		assert.Equal(t, found, tokenPolicyText(now, nowAbsent), "kept as found")
	}
	fact("LocalAccountTokenFilterPolicy found %s, after the script %s", found, tokenPolicyText(now, nowAbsent))

	// The firewall rule, and everything the script never changes.
	rule := firewallRule(t)
	require.Len(t, rule, 7, "%v", rule)
	assert.Equal(t, []string{"Alice WinRM (TCP 5986)", "Inbound", "Allow", "True", "TCP", "5986", "Any"}, rule)
	assert.Equal(t, before, winrmState(t), "the listeners, Basic, Negotiate, AllowUnencrypted and the other settings are as found")

	// F32: the printed fingerprints are what Alice's client sees, for the image's listener and the ECDSA one.
	printed := printedListeners(out)
	for _, c := range []struct {
		port string
		addr string
		leaf *x509.Certificate
	}{{"5986", winrmImageAddr, image}, {winrmF32Port, winrmF32Addr, f32}} {
		seen := waitPresented(t, c.addr, nil)
		want := providers.TLSIdentity(seen.RawSubjectPublicKeyInfo).Fingerprint
		got, ok := printed[c.port]
		require.True(t, ok, "the script prints the listener on %s: %s", c.port, out)
		fact("listener port %s (%s): printed %s, thumbprint %s; Alice's client sees %s, thumbprint %s",
			c.port, seen.PublicKeyAlgorithm, got[0], got[1], want, thumbOf(seen))
		assert.Equal(t, want, got[0], "the printed SPKI fingerprint of port %s", c.port)
		assert.Equal(t, thumbOf(seen), got[1], "the printed thumbprint of port %s", c.port)
		assert.True(t, bytes.Equal(c.leaf.Raw, seen.Raw), "port %s presents the expected certificate", c.port)
	}
	assert.Equal(t, x509.ECDSA, f32.PublicKeyAlgorithm)

	// WinRS signs in with the password and runs the installed helper (after F32's checks, which need no WinRS call).
	v := winrsVersion(t, image.RawSubjectPublicKeyInfo, pw)
	assert.Equal(t, winproto.Version, v.Helper)

	// A second run with an empty answer changes nothing.
	state := func() []string {
		flags, admin, rights := winrmAccountState(t)
		v, a := readTokenPolicy(t)
		return append(winrmState(t), setupFileSHA256(t, winproto.HelperPath), passwordLastSet(t), strings.Join(firewallRule(t), "|"),
			tokenPolicyText(v, a), strconv.Itoa(flags), strconv.FormatBool(admin), fmt.Sprint(rights))
	}
	again := state()
	out, err = w.run(t, setupAccount, []string{""})
	require.NoError(t, err, "the second run succeeds")
	require.Contains(t, out, winrmReadyLine)
	assert.Contains(t, out, "The password of alice is kept.")
	assert.Equal(t, again, state(), "running the script again with an empty answer changes nothing")
	assert.Equal(t, v, winrsVersion(t, image.RawSubjectPublicKeyInfo, pw), "the password is unchanged")
}

// winrmSite is the IIS fixture of TestRealWinRMProvider: the site alice-w7-provider with the https binding *:45522 and
// its http.sys record 0.0.0.0:45522, which names old (a self-signed certificate in My with its key).
func winrmSite(t *testing.T) pki.Leaf {
	t.Helper()
	old := pki.SelfSigned("alice-w7-old.test", pki.ECDSA256, time.Now())
	thumb := importWithKey(t, old.Cert, old.Key)
	dir := filepath.Join(os.Getenv("SystemDrive")+`\`, "inetpub", winrmSiteName)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.MkdirAll(dir, 0o750))
	key := "ipport=0.0.0.0:" + strconv.Itoa(winrmSitePort)
	netsh := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	t.Cleanup(func() {
		if out, err := exec.Command(netsh, "http", "delete", "sslcert", key).CombinedOutput(); err != nil {
			t.Errorf("cleanup of the record %s: %v %s", key, err, out)
		}
	})
	out, err := exec.Command(netsh, "http", "add", "sslcert", key, "certhash="+thumb, "appid="+winproto.AppIDIIS, "certstorename=MY").CombinedOutput()
	require.NoError(t, err, "netsh: %s", out)
	t.Cleanup(func() {
		if out, err := exec.Command(appcmdPath(), "delete", "site", winrmSiteName).CombinedOutput(); err != nil {
			t.Errorf("cleanup of the site %s: %v %s", winrmSiteName, err, out)
		}
	})
	out, err = exec.Command(appcmdPath(), "add", "site", "/name:"+winrmSiteName, "/physicalPath:"+dir,
		"/bindings:https/*:"+strconv.Itoa(winrmSitePort)+":").CombinedOutput()
	require.NoError(t, err, "appcmd add site: %s", out)
	_ = exec.Command(appcmdPath(), "start", "site", "/site.name:"+winrmSiteName).Run() // "already started" is not an error here
	waitPresented(t, "127.0.0.1:"+strconv.Itoa(winrmSitePort), old.Cert)
	return old
}

func appcmdPath() string {
	return filepath.Join(os.Getenv("SystemRoot"), "system32", "inetsrv", "appcmd.exe")
}

// R71 over real WinRS: the provider with a WinRM target 127.0.0.1:5986 pins the listener after the first
// host_key_unconfirmed, then tests the connection, discovers, deploys to an alice-w7- binding, rolls back after a
// failed verification, deploys again with a passing one, and plans the cleanup.
func TestRealWinRMProvider(t *testing.T) {
	w := newWinRMSetup(t)
	pw := w.prepared(t)
	old := winrmSite(t)
	siteAddr := "127.0.0.1:" + strconv.Itoa(winrmSitePort)
	image := waitPresented(t, winrmImageAddr, nil)

	pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: &memHostKeys{}},
		linuxssh.MaxConnections, linuxssh.MaxConnectionsPerTarget, linuxssh.IdleTimeout)
	t.Cleanup(pool.Close)
	prov := New(Options{Pool: pool, Attempts: 5, RetryWait: 2 * time.Second})
	ref := providers.TargetRef{ID: testTarget, Name: "runner", Kind: providers.KindWindows,
		Config: providers.TargetConfig{"host": "127.0.0.1", "port": 5986, "username": setupAccount, "transport": TransportWinRM}}
	cred := &winrmCred{fakeCred: newFakeCred(t), pw: pw}
	hk := &memHostKeys{}
	env := providers.Env{Clock: clock.Real{}, HostKeys: hk}
	ctx := context.Background()

	// First contact: unconfirmed, with the presented identity; then pinned as an Administrator would confirm it.
	_, err := prov.Open(ctx, ref, cred, env)
	pe := providerErr(t, err)
	require.Equal(t, tlspin.CodeUnconfirmed, pe.Code, "%v", err)
	require.Len(t, hk.seen, 1)
	presentedID := providers.TLSIdentity(image.RawSubjectPublicKeyInfo)
	assert.Equal(t, presentedID, hk.seen[0])
	assert.Equal(t, presentedID.Fingerprint, pe.Params["fingerprint"])
	pinned := hk.seen[0]
	hk.pinned = &pinned
	s, err := prov.Open(ctx, ref, cred, env)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	rep, err := s.TestConnection(ctx)
	require.NoError(t, err)
	assert.Equal(t, pinned, rep.HostKey)

	res, err := s.Discover(ctx, providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	var loc, listener *providers.CertLocation
	for i := range res.Certificates {
		switch res.Certificates[i].Location.CertPath {
		case "http.sys/ipport/0.0.0.0:" + strconv.Itoa(winrmSitePort):
			loc = &res.Certificates[i].Location
		case "http.sys/ipport/0.0.0.0:5986":
			listener = &res.Certificates[i].Location
		}
	}
	require.NotNil(t, loc, "the fixture's binding is discovered: %+v", res.Certificates)
	require.True(t, loc.Supported, "%+v", *loc)
	require.NotNil(t, listener, "the WinRM listener's record is discovered")
	assert.False(t, listener.Supported, "Ruling 11: the WinRM listener's binding is never deployable")
	assert.Equal(t, UnsupportedForeignApp, listener.Unsupported)
	oldSHA1, _ := loc.Details["cert_sha1"].(string)
	require.NotEmpty(t, oldSHA1)

	ca := pki.NewCA("alice-w7-provider", pki.ECDSA256, time.Now())
	removeCertWhenDone(t, "CA", thumbOf(ca.Intermediate))
	issue := func(name string) pki.Leaf {
		l := ca.Issue(pki.Opts{CommonName: name, SANs: []string{name}}, time.Now())
		removeCertWhenDone(t, "My", thumbOf(l.Cert))
		return l
	}
	deployReq := func(op uuid.UUID, l pki.Leaf) providers.DeployRequest {
		return providers.DeployRequest{OperationID: op, Location: *loc, ExpectCertSHA256: derSHA256(old.Cert.Raw),
			CertificatePEM: l.FullchainPEM, PrivateKeyPEM: providers.NewSecret(append([]byte(nil), l.KeyPEM...)),
			Fingerprint: derSHA256(l.Cert.Raw), SANs: l.Cert.DNSNames, KeyType: "ecdsa", OldFingerprint: derSHA256(old.Cert.Raw),
			OldSANs: old.Cert.DNSNames, ChainLength: 2}
	}

	// A deployment whose verification fails (it expects a leaf never deployed), then its rollback: old again.
	b, never := issue("alice-w7-b.test"), issue("alice-w7-never.test")
	op1 := uuid.New()
	out, err := s.DeployCertificate(ctx, deployReq(op1, b), &stepLog{})
	require.NoError(t, err, "%+v", out)
	require.Equal(t, providers.DeployCommitted, out.Result, "%+v", out)
	waitPresented(t, siteAddr, b.Cert)
	vr, err := s.VerifyDeployment(ctx, providers.VerifyRequest{Location: *loc, Fingerprint: derSHA256(never.Cert.Raw),
		PreviousFingerprint: derSHA256(old.Cert.Raw), SANs: never.Cert.DNSNames, KeyType: "ecdsa"})
	require.NoError(t, err)
	assert.False(t, vr.OK, "%+v", vr)
	assert.Equal(t, derSHA256(b.Cert.Raw), vr.Served)
	rb, err := s.RollbackDeployment(ctx, providers.RollbackRequest{OperationID: op1, Location: *loc, OldFingerprint: derSHA256(old.Cert.Raw),
		OldSANs: old.Cert.DNSNames, KeyType: "ecdsa",
		Backup: providers.BackupRef{OperationID: op1, Store: "My", PreviousSHA1: oldSHA1, PreviousSHA256: derSHA256(old.Cert.Raw)}}, &stepLog{})
	require.NoError(t, err, "%+v", rb)
	assert.Equal(t, providers.DeployRolledBack, rb.Result, "%+v", rb)
	waitPresented(t, siteAddr, old.Cert)

	// A deployment that verifies.
	c := issue("alice-w7-c.test")
	op2 := uuid.New()
	out, err = s.DeployCertificate(ctx, deployReq(op2, c), &stepLog{})
	require.NoError(t, err, "%+v", out)
	require.Equal(t, providers.DeployCommitted, out.Result, "%+v", out)
	vr, err = s.VerifyDeployment(ctx, providers.VerifyRequest{Location: *loc, Fingerprint: derSHA256(c.Cert.Raw),
		PreviousFingerprint: derSHA256(old.Cert.Raw), SANs: c.Cert.DNSNames, KeyType: "ecdsa"})
	require.NoError(t, err)
	assert.True(t, vr.OK, "%+v", vr)

	// The cleanup plan: c is bound, so kept; b, rolled back, is in My.
	cleaner, ok := s.(providers.CertificateCleaner)
	require.True(t, ok)
	plan, err := cleaner.PlanCleanup(ctx, []providers.CleanupRef{{SHA1: sha1Hex(b.Cert.Raw), SHA256: derSHA256(b.Cert.Raw)},
		{SHA1: sha1Hex(c.Cert.Raw), SHA256: derSHA256(c.Cert.Raw)}})
	require.NoError(t, err)
	t.Logf("the cleanup plan: %+v", plan)
	states := map[string]string{}
	for _, wv := range plan.Watched {
		states[wv.SHA256] = wv.State
	}
	assert.Equal(t, providers.WatchKept, states[derSHA256(c.Cert.Raw)], "the bound certificate is kept")
	assert.NotEqual(t, providers.WatchAbsent, states[derSHA256(b.Cert.Raw)], "the rolled-back certificate is in My")
	assert.NotEmpty(t, states[derSHA256(b.Cert.Raw)])
}

// Ruling 18's coexistence: after the SSH script and the WinRM script, version answers over SSH (key) and over WinRS
// (password) from the same helper.
func TestRealBothTransportsShareTheHelper(t *testing.T) {
	w := newWinRMSetup(t)

	// The SSH half, with a fresh key, as TestRealSetupScript prepares it.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "alice-w7-both")
	require.NoError(t, err)
	keyDir := t.TempDir()
	keyFile := filepath.Join(keyDir, "id_ed25519")
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600))
	icacls := filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe")
	out, err := exec.Command(icacls, keyFile, "/inheritance:r", "/grant:r", os.Getenv("USERNAME")+":F").CombinedOutput()
	require.NoError(t, err, "icacls: %s", out)
	line := AuthorizedKeysLine(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))+" alice-w7-both", "")
	script, err := SetupScript(line, false)
	require.NoError(t, err)
	scriptFile := filepath.Join(w.dir, "alice-setup.ps1")
	require.NoError(t, os.WriteFile(scriptFile, []byte(script), 0o600))
	runSetupScript(t, w.dir, scriptFile)
	waitForSSHD(t)
	hostPub, err := os.ReadFile(setupHostEd25519Pub)
	require.NoError(t, err)
	f := strings.Fields(string(hostPub))
	require.GreaterOrEqual(t, len(f), 2)
	knownHosts := filepath.Join(keyDir, "known_hosts")
	require.NoError(t, os.WriteFile(knownHosts, []byte("localhost "+f[0]+" "+f[1]+"\n"), 0o600))

	// The WinRM half.
	pw := w.prepared(t)
	image := waitPresented(t, winrmImageAddr, nil)

	code, stdout, stderr := setupSSH(t, keyFile, knownHosts, winproto.SubVersion)
	require.Equal(t, 0, code, "ssh version: %s %s", stdout, stderr)
	var overSSH winproto.VersionResponse
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stdout), &overSSH), "%s", stdout)
	overWinRS := winrsVersion(t, image.RawSubjectPublicKeyInfo, pw)
	assert.Equal(t, overSSH, overWinRS, "one helper answers both transports")
	assert.Equal(t, setupFileSHA256(t, w.amd64), setupFileSHA256(t, winproto.HelperPath))
}

// fidelityAnswer is what TestFidelityWinRM compares: the exit code, the helper's JSON without its message (or, for
// the machine's facts, its field names and the fields the emulator is configured with), and the winrs error kind.
type fidelityAnswer struct {
	Exit int
	JSON any
	Err  string
}

func fidelityOf(r winrs.Result, err error, fieldsOnly bool, keep ...string) fidelityAnswer {
	a := fidelityAnswer{Exit: r.ExitCode}
	var fe *winrs.FaultError
	switch {
	case err == nil:
	case errors.Is(err, winrs.ErrAuthRefused):
		a.Err = "auth_refused"
	case errors.As(err, &fe):
		a.Err = fmt.Sprintf("fault %d at %s", fe.Code, fe.Action)
	default:
		a.Err = "other: " + err.Error()
	}
	if err != nil {
		return a
	}
	var m map[string]any
	if json.Unmarshal(bytes.TrimSpace(r.Stdout), &m) != nil {
		a.JSON = "not JSON: " + string(r.Stdout)
		return a
	}
	delete(m, "message")
	if !fieldsOnly {
		a.JSON = m
		return a
	}
	fields := map[string]any{}
	for k, v := range m {
		fields[k] = nil
		if slices.Contains(keep, k) {
			fields[k] = v
		}
	}
	a.JSON = fields
	return a
}

// R71 fidelity: the emulator's WinRM listener, configured like the runner (the WinRM record 0.0.0.0:5986 with a
// self-signed RSA certificate, the account alice with the same password, an elevated token), answers the scenarios
// as real WinRS does. The machine's facts (win-facts, iis-dump) are compared by their field names and the fields
// the emulator is configured with; the runner's own values are not modelled.
func TestFidelityWinRM(t *testing.T) {
	w := newWinRMSetup(t)
	pw := w.prepared(t)
	image := waitPresented(t, winrmImageAddr, nil)

	m := wintest.NewModel()
	m.SetElevated(true)
	l := pki.SelfSigned(foldASCII(os.Getenv("COMPUTERNAME")), pki.RSA2048, time.Now())
	sha1 := m.AddCertificate("My", l.CertPEM, l.KeyPEM, wintest.CertOptions{})
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 5986, AppID: winrmAppID, CertSHA1: sha1, Store: "My"})
	ws := wintest.NewWinRMServer(t, m)
	m.SetWinRMAccount(setupAccount, pw)

	wrong := winrmPassword(t)
	absent := `C:\Program Files\Alice\alice-w7-absent.exe`
	refused := winproto.SubIISDeploy + " " + winproto.ArgOp + " " + uuid.NewString()
	for _, sc := range []struct {
		name       string
		pw         string
		program    string
		line       string
		stdin      []byte
		fieldsOnly bool
		keep       []string
	}{
		{"version", pw, winproto.HelperPath, winproto.SubVersion, nil, false, nil},
		{"win-facts", pw, winproto.HelperPath, winproto.SubWinFacts, nil, true, []string{"ok", "elevated"}},
		{"iis-dump", pw, winproto.HelperPath, winproto.SubIISDump, nil, true, []string{"ok"}},
		{"a refused iis-deploy", pw, winproto.HelperPath, refused, []byte("{"), false, nil},
		{"a wrong password", wrong, winproto.HelperPath, winproto.SubVersion, nil, false, nil},
		{"a fault at Command", pw, absent, winproto.SubVersion, nil, false, nil},
	} {
		t.Run(sc.name, func(t *testing.T) {
			r, err := winrsRun(winrmImageAddr, image.RawSubjectPublicKeyInfo, setupAccount, sc.pw, sc.program, sc.line, sc.stdin)
			real := fidelityOf(r, err, sc.fieldsOnly, sc.keep...)
			r, err = winrsRun(ws.Addr, ws.SPKI, setupAccount, sc.pw, sc.program, sc.line, sc.stdin)
			emulated := fidelityOf(r, err, sc.fieldsOnly, sc.keep...)
			t.Logf("real: %+v", real)
			assert.Equal(t, real, emulated)
			assert.NotContains(t, real.Err, "other:", "a known answer")
		})
	}
}
