//go:build windows

package windows

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers/windows/winproto"
)

// The setup script on real Windows (R60 Task 11, design §6.1): TestRealSetupScript runs the script
// SetupScript renders, as an administrator would, on a Windows runner, then signs in with the key over
// OpenSSH. It changes the machine for good (OpenSSH Server, the local account alice, sshd_config, the
// helper under Program Files, the firewall rule), so it runs only when ALICE_WIN_SETUP=1: the Windows
// workflow sets it on its runners and fails a run whose log lacks its PASS line.
//
// The helper is the one the job built (ALICE_WIN_HELPER_DIR holds alice-winhelper-windows-amd64.exe and
// -arm64.exe, as make winhelper names them) or, without that variable, built here; the test sets the
// package's checksum variables to those files, as the image build's linker flags would.

const (
	setupSSHDir          = `C:\ProgramData\ssh`
	setupSSHDConfig      = setupSSHDir + `\sshd_config`
	setupAuthorizedKeys  = setupSSHDir + `\administrators_authorized_keys`
	setupAdministrators  = "S-1-5-32-544"
	setupLocalSystem     = "S-1-5-18"
	setupHostEd25519Pub  = setupSSHDir + `\ssh_host_ed25519_key.pub`
	setupReadyLine       = "This server is ready for Alice."
	setupAccount         = "alice"
	setupInvalidArgument = winproto.CodeInvalidArgument
)

// setupHelpers returns the amd64 and arm64 helper files.
func setupHelpers(t *testing.T) (amd64, arm64 string) {
	t.Helper()
	if dir := os.Getenv("ALICE_WIN_HELPER_DIR"); dir != "" {
		amd64 = filepath.Join(dir, "alice-winhelper-windows-amd64.exe")
		arm64 = filepath.Join(dir, "alice-winhelper-windows-arm64.exe")
		for _, f := range []string{amd64, arm64} {
			_, err := os.Stat(f)
			require.NoError(t, err, "ALICE_WIN_HELPER_DIR names the built helpers")
		}
		return amd64, arm64
	}
	dir := t.TempDir()
	build := func(arch string) string {
		out := filepath.Join(dir, "alice-winhelper-windows-"+arch+".exe")
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w", "-o", out, "alice/cmd/alice-winhelper")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=windows", "GOARCH="+arch)
		b, err := cmd.CombinedOutput()
		require.NoError(t, err, "go build %s: %s", arch, b)
		return out
	}
	return build("amd64"), build("arm64")
}

func setupFileSHA256(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: a fixed path or one the test made
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

func setupCopy(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from) //nolint:gosec // G304: a file the test built or was given
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(to, b, 0o600))
}

// powershellEnviron is this process's environment without PSModulePath. A go test started from
// PowerShell 7 (the workflow's pwsh steps) inherits pwsh's module path, and Windows PowerShell 5.1 then
// loads 7's modules: no Cert: drive, no Microsoft.PowerShell.Security (Windows run 1). Without the
// variable Windows PowerShell builds its default machine path.
func powershellEnviron() []string {
	out := []string{}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !strings.EqualFold(k, "PSModulePath") {
			out = append(out, kv)
		}
	}
	return out
}

// setupPowershell runs a check script (tests only); values reach it through $env:.
func setupPowershell(t *testing.T, env map[string]string, script string) string {
	t.Helper()
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"$ErrorActionPreference = 'Stop'; "+script)
	cmd.Env = powershellEnviron()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "powershell: %s: %s", script, stderr.String())
	return strings.TrimSpace(string(out))
}

// runSetupScript runs the script file as the guide tells an administrator to, in the directory that
// holds .\alice-helper.exe.
func runSetupScript(t *testing.T, dir, script string) {
	t.Helper()
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	cmd.Env = powershellEnviron()
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	t.Logf("setup script:\n%s", out)
	require.NoError(t, err, "the setup script succeeds")
	assert.Contains(t, string(out), setupReadyLine)
}

// setupState is what a second run of the script must leave unchanged.
func setupState(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		setupSSHDConfig:     setupFileSHA256(t, setupSSHDConfig),
		setupAuthorizedKeys: setupFileSHA256(t, setupAuthorizedKeys),
		winproto.HelperPath: setupFileSHA256(t, winproto.HelperPath),
		"acl:authorized_keys": setupPowershell(t, map[string]string{"ALICE_W1_FILE": setupAuthorizedKeys},
			`(Get-Acl -LiteralPath $env:ALICE_W1_FILE).Sddl`),
	}
}

// setupSSH runs the OpenSSH client of Windows against this machine's sshd as the account, with the host
// key pinned (never accepted blindly) and one connection per call (W0 F3: a second session on one
// connection gets the first session's command).
func setupSSH(t *testing.T, key, knownHosts, line string) (int, []byte, []byte) {
	t.Helper()
	client := filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "ssh.exe")
	cmd := exec.Command(client, "-n", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile="+knownHosts, "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
		"-o", "ConnectTimeout=20", setupAccount+"@localhost", line)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else {
		require.NoError(t, err)
	}
	return code, stdout.Bytes(), stderr.Bytes()
}

func TestRealSetupScript(t *testing.T) {
	if os.Getenv("ALICE_WIN_SETUP") != "1" {
		t.Skip("set ALICE_WIN_SETUP=1 to prepare this Windows machine for Alice (it changes the machine)")
	}
	require.Equal(t, "amd64", runtime.GOARCH, "the runners are AMD64")
	amd64, arm64 := setupHelpers(t)
	withChecksums(t, setupFileSHA256(t, amd64), setupFileSHA256(t, arm64))

	// A fresh key, as Alice's platform key would be.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "alice-w1-setup")
	require.NoError(t, err)
	keyDir := t.TempDir()
	keyFile := filepath.Join(keyDir, "id_ed25519")
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600))
	// OpenSSH refuses a private key other accounts may read: the runner's account only.
	icacls := filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe")
	out, err := exec.Command(icacls, keyFile, "/inheritance:r", "/grant:r", os.Getenv("USERNAME")+":F").CombinedOutput()
	require.NoError(t, err, "icacls: %s", out)

	line := AuthorizedKeysLine(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))+" alice-w1-setup", "")
	require.NotEmpty(t, line)
	script, err := SetupScript(line, false)
	require.NoError(t, err)
	require.Contains(t, script, setupFileSHA256(t, amd64), "the script checks the helper the job built")

	work := t.TempDir()
	setupCopy(t, amd64, filepath.Join(work, "alice-helper.exe"))
	scriptFile := filepath.Join(work, "alice-setup.ps1")
	require.NoError(t, os.WriteFile(scriptFile, []byte(script), 0o600))

	runSetupScript(t, work, scriptFile)

	// The helper is the built one.
	assert.Equal(t, setupFileSHA256(t, amd64), setupFileSHA256(t, winproto.HelperPath))

	// sshd_config holds the Match block for alice, and sshd applies it to the account.
	cfg, err := os.ReadFile(setupSSHDConfig)
	require.NoError(t, err)
	cfgText := strings.ReplaceAll(string(cfg), "\r\n", "\n")
	assert.Contains(t, cfgText, "# BEGIN Alice\n"+strings.ReplaceAll(MatchBlock, "__USER__", setupAccount)+"# END Alice\n")
	sshd := setupPowershell(t, nil, `$p = "$((Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'").PathName)".Trim()
if ($p.StartsWith('"')) { $p.Substring(1, $p.IndexOf('"', 1) - 1) } else { ($p -split ' ')[0] }`)
	effective, err := exec.Command(sshd, "-T", "-C", "user="+setupAccount+",host=localhost,addr=127.0.0.1").CombinedOutput()
	require.NoError(t, err, "sshd -T: %s", effective)
	settings := map[string]string{}
	for _, l := range strings.Split(strings.ReplaceAll(string(effective), "\r\n", "\n"), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), " "); ok {
			settings[k] = v // sshd -T prints keywords in lower case
		}
	}
	assert.True(t, strings.EqualFold(`"`+winproto.HelperPath+`" ssh`, settings["forcecommand"]),
		"sshd -T -C user=alice: forcecommand %q", settings["forcecommand"])
	assert.Equal(t, "publickey", settings["authenticationmethods"])
	assert.Equal(t, "no", settings["permittty"])
	assert.Equal(t, "no", settings["allowtcpforwarding"])
	assert.Equal(t, "no", settings["x11forwarding"])

	// administrators_authorized_keys: Alice's line, readable by Administrators and SYSTEM only.
	keys, err := os.ReadFile(setupAuthorizedKeys)
	require.NoError(t, err)
	assert.Contains(t, strings.Split(strings.ReplaceAll(string(keys), "\r\n", "\n"), "\n"), line)
	var acl struct {
		Protected bool   `json:"protected"`
		SIDs      string `json:"sids"`
	}
	require.NoError(t, json.Unmarshal([]byte(setupPowershell(t, map[string]string{"ALICE_W1_FILE": setupAuthorizedKeys},
		`$a = Get-Acl -LiteralPath $env:ALICE_W1_FILE
$s = @($a.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
@{ protected = $a.AreAccessRulesProtected; sids = ($s -join ',') } | ConvertTo-Json -Compress`)), &acl))
	assert.True(t, acl.Protected, "no inherited access")
	assert.ElementsMatch(t, []string{setupAdministrators, setupLocalSystem}, strings.Split(acl.SIDs, ","))

	// The host key, pinned from ssh-keyscan and checked against sshd's own public key file.
	hostPub, err := os.ReadFile(setupHostEd25519Pub)
	require.NoError(t, err)
	hostFields := strings.Fields(string(hostPub))
	require.GreaterOrEqual(t, len(hostFields), 2)
	keyscan := filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "ssh-keyscan.exe")
	scanned, err := exec.Command(keyscan, "-t", "ed25519", "-p", "22", "localhost").Output()
	require.NoError(t, err, "ssh-keyscan")
	var pinned []string
	for _, l := range strings.Split(strings.ReplaceAll(string(scanned), "\r\n", "\n"), "\n") {
		if f := strings.Fields(l); len(f) >= 3 && f[0] == "localhost" && f[1] == hostFields[0] && f[2] == hostFields[1] {
			pinned = append(pinned, "localhost "+f[1]+" "+f[2])
		}
	}
	require.NotEmpty(t, pinned, "ssh-keyscan reports sshd's own ed25519 host key: %s", scanned)
	knownHosts := filepath.Join(keyDir, "known_hosts")
	require.NoError(t, os.WriteFile(knownHosts, []byte(strings.Join(pinned, "\n")+"\n"), 0o600))

	// The forced command answers version; a shell line is refused by the helper (exit 2), not run.
	code, stdout, stderr := setupSSH(t, keyFile, knownHosts, winproto.SubVersion)
	require.Equal(t, 0, code, "ssh version: %s %s", stdout, stderr)
	var version winproto.VersionResponse
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stdout), &version), string(stdout))
	assert.Equal(t, winproto.Protocol, version.Protocol)
	assert.Equal(t, winproto.Version, version.Helper)

	code, stdout, stderr = setupSSH(t, keyFile, knownHosts, "version & whoami")
	assert.Equal(t, winproto.ExitRefused, code, "ssh 'version & whoami': %s %s", stdout, stderr)
	var refusal winproto.ErrorResponse
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stdout), &refusal), string(stdout))
	assert.Equal(t, setupInvalidArgument, refusal.Code)
	assert.Equal(t, 1, bytes.Count(bytes.TrimSpace(stdout), []byte("\n"))+1, "one JSON line, nothing from whoami: %s", stdout)

	// A second run changes nothing.
	before := setupState(t)
	runSetupScript(t, work, scriptFile)
	assert.Equal(t, before, setupState(t), "running the script again changes nothing")
	code, stdout, stderr = setupSSH(t, keyFile, knownHosts, winproto.SubVersion)
	assert.Equal(t, 0, code, "ssh version after the second run: %s %s", stdout, stderr)
}
