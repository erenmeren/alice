//go:build windows

package windows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	xwindows "golang.org/x/sys/windows"

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
	require.NoError(t, err, "powershell: %s\nstdout: %s\nstderr: %s", script, out, stderr.String())
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
	return setupSSHWith(t, key, knownHosts, nil, line)
}

// setupSSHCommand is the client's command line: the options every call shares, then extra, then the
// account and, unless it is "", the remote line.
func setupSSHCommand(ctx context.Context, account, key, knownHosts string, extra []string, line string) *exec.Cmd {
	client := filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "ssh.exe")
	args := []string{"-n", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=" + knownHosts, "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
		"-o", "ConnectTimeout=20"}
	args = append(append(args, extra...), account+"@localhost")
	if line != "" {
		args = append(args, line)
	}
	return exec.CommandContext(ctx, client, args...) //nolint:gosec // G204: the system's ssh.exe with the test's arguments
}

// setupSSHWith runs one client (one connection) with extra options and returns its exit code, stdout
// and stderr; it fails the test when the client runs longer than 30 s.
func setupSSHWith(t *testing.T, key, knownHosts string, extra []string, line string) (int, []byte, []byte) {
	t.Helper()
	return setupSSHAs(t, setupAccount, key, knownHosts, extra, line)
}

// setupSSHAs is setupSSHWith as another account.
func setupSSHAs(t *testing.T, account, key, knownHosts string, extra []string, line string) (int, []byte, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := setupSSHCommand(ctx, account, key, knownHosts, extra, line)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	require.NoError(t, ctx.Err(), "ssh %v %q did not end: %s %s", extra, line, stdout.Bytes(), stderr.Bytes())
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else {
		require.NoError(t, err)
	}
	return code, stdout.Bytes(), stderr.Bytes()
}

// freeLoopbackPort is a TCP port nothing listens on at the moment.
func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, ln.Close())
	return port
}

// localForwardServesNothing opens a local forward to sshd itself through the account and checks that
// a connection through it never reaches sshd (AllowTcpForwarding no and the key's restrict refuse the
// channel): no "SSH-" banner arrives. A client that exits because the forward is refused also passes.
func localForwardServesNothing(t *testing.T, key, knownHosts string) {
	t.Helper()
	port := freeLoopbackPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := setupSSHCommand(ctx, setupAccount, key, knownHosts, []string{"-N", "-o", "ExitOnForwardFailure=yes",
		"-L", "127.0.0.1:" + port + ":127.0.0.1:22"}, "")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	defer func() {
		cancel()
		<-exited
	}()
	var conn net.Conn
	for deadline := time.Now().Add(15 * time.Second); conn == nil && time.Now().Before(deadline); {
		select {
		case <-exited:
			t.Logf("the client ended before forwarding: %s", stderr.Bytes())
			return
		default:
		}
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second)
		if err == nil {
			conn = c
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	require.NotNil(t, conn, "the client's local forward listens")
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	got, _ := io.ReadAll(conn)
	assert.NotContains(t, string(got), "SSH-", "the forward reached sshd: TCP forwarding is allowed")
}

// otherAdministrator is the second local administrator TestRealSetupScript signs in as with Alice's key.
const otherAdministrator = "alice-w1-other"

// runNet runs net.exe and returns its exit code and combined output, with secret (if not "") replaced in the
// output, so neither a log line nor a failure message ever holds it.
func runNet(t *testing.T, secret string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "net.exe"), args...) //nolint:gosec // G204: the system's net.exe with the test's arguments
	cmd.Stdin = strings.NewReader("Y\r\n")
	out, err := cmd.CombinedOutput()
	text := string(out)
	if secret != "" {
		text = strings.ReplaceAll(text, secret, "<password>")
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, text
	case errors.As(err, &exit):
		return exit.ExitCode(), text
	}
	require.NoError(t, err, "net.exe could not run: %s", text)
	return -1, text
}

// redactedArgs is args for a failure message, with secret replaced.
func redactedArgs(secret string, args []string) string {
	return strings.ReplaceAll(strings.Join(args, " "), secret, "<password>")
}

// deleteOtherAdministrator removes the account; "no such user" (exit 2 with NET HELPMSG 2221) is success.
func deleteOtherAdministrator(t *testing.T) {
	t.Helper()
	code, out := runNet(t, "", "user", otherAdministrator, "/delete")
	if code != 0 && (code != 2 || !strings.Contains(out, "2221")) {
		t.Errorf("net user %s /delete: exit %d: %s", otherAdministrator, code, out)
	}
}

// newOtherAdministrator creates the local account otherAdministrator with a random 32-character password nobody
// sees, adds it to the local Administrators group (its name resolved from S-1-5-32-544, whatever the language of
// Windows) and deletes it when the test ends. It uses net.exe, not the LocalAccounts cmdlets: those exit 1 without
// an error when the test starts Windows PowerShell (runner run 6), which is also why the setup script uses ADSI.
// The profile a sign-in creates is left behind (a runner is thrown away).
func newOtherAdministrator(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 14)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	pw := "Aa1!" + hex.EncodeToString(raw) // 32 characters: upper, lower, digit, symbol

	sid, err := xwindows.StringToSid(setupAdministrators)
	require.NoError(t, err)
	group, _, _, err := sid.LookupAccount("")
	require.NoError(t, err, "the name of %s", setupAdministrators)

	deleteOtherAdministrator(t)
	t.Cleanup(func() { deleteOtherAdministrator(t) })
	// /Y answers the "longer than 14 characters" question of net.exe.
	for _, args := range [][]string{
		{"user", otherAdministrator, pw, "/add", "/Y", "/comment:Alice W1 test (removed by the test)"},
		{"localgroup", group, otherAdministrator, "/add"},
	} {
		code, out := runNet(t, pw, args...)
		require.Equal(t, 0, code, "net %s: %s", redactedArgs(pw, args), out)
	}
	return otherAdministrator
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

	// sshd_config holds the Match block for alice and sshd accepts the file; what the block does is
	// checked below over real connections (Win32-OpenSSH's "sshd -T -C user=alice" cannot resolve the
	// local account: "ga_init, unable to resolve user", Windows run 2).
	cfg, err := os.ReadFile(setupSSHDConfig)
	require.NoError(t, err)
	cfgText := strings.ReplaceAll(string(cfg), "\r\n", "\n")
	assert.Contains(t, cfgText, "# BEGIN Alice\n"+strings.ReplaceAll(MatchBlock, "__USER__", setupAccount)+"# END Alice\n")
	sshd := setupPowershell(t, nil, `$p = "$((Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'").PathName)".Trim()
if ($p.StartsWith('"')) { $p.Substring(1, $p.IndexOf('"', 1) - 1) } else { ($p -split ' ')[0] }`)
	checked, err := exec.Command(sshd, "-t").CombinedOutput()
	require.NoError(t, err, "sshd -t: %s", checked)

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

	// PermitTTY no: a forced terminal never gets a shell. sshd refuses the PTY; Win32-OpenSSH's client
	// then ends the session with 255 (Windows run 3), or a client that carries on gets only the
	// helper's answer. Either way stdout holds nothing but, at most, the helper's one JSON line.
	code, stdout, stderr = setupSSHWith(t, keyFile, knownHosts, []string{"-tt"}, winproto.SubVersion)
	ttyOut := bytes.TrimSpace(stdout)
	helperJSON := func() bool {
		var v winproto.VersionResponse
		return bytes.Count(ttyOut, []byte("\n")) == 0 && json.Unmarshal(ttyOut, &v) == nil && v.Protocol == winproto.Protocol
	}
	switch code {
	case 255:
		assert.Contains(t, string(stderr), "PTY allocation request failed", "ssh -tt: the PTY is refused")
		assert.True(t, len(ttyOut) == 0 || helperJSON(), "ssh -tt: no shell output: %q", stdout)
	case 0:
		assert.True(t, helperJSON(), "ssh -tt: exactly the helper's JSON: %q", stdout)
	default:
		t.Errorf("ssh -tt version: exit %d: %s %s", code, stdout, stderr)
	}

	// AllowTcpForwarding no (and the key's restrict): a remote forward is refused, so the client
	// gives up at once, and a local forward never reaches anything.
	code, stdout, stderr = setupSSHWith(t, keyFile, knownHosts, []string{"-N", "-o", "ExitOnForwardFailure=yes",
		"-R", "127.0.0.1:" + freeLoopbackPort(t) + ":127.0.0.1:22"}, "")
	assert.NotEqual(t, 0, code, "a remote forward is refused: %s %s", stdout, stderr)
	localForwardServesNothing(t, keyFile, knownHosts)

	// AuthenticationMethods publickey: a password sign-in is not offered.
	code, stdout, stderr = setupSSHWith(t, keyFile, knownHosts, []string{"-o", "PreferredAuthentications=password",
		"-o", "PubkeyAuthentication=no"}, winproto.SubVersion)
	assert.NotEqual(t, 0, code, "a password sign-in fails: %s %s", stdout, stderr)
	assert.Empty(t, bytes.TrimSpace(stdout), "nothing ran")
	assert.Contains(t, string(stderr), "Permission denied")

	// Final review C1: sshd reads administrators_authorized_keys for every member of Administrators, and the
	// Match User block covers only alice. The key line's own command= confines Alice's key to the helper on
	// every other administrator account too: a shell line reaches the helper as SSH_ORIGINAL_COMMAND and is
	// refused, version still answers.
	other := newOtherAdministrator(t)
	code, stdout, stderr = setupSSHAs(t, other, keyFile, knownHosts, nil, "whoami")
	assert.Equal(t, winproto.ExitRefused, code, "ssh %s@localhost whoami: %s %s", other, stdout, stderr)
	assert.NotContains(t, string(stdout), other, "whoami never ran (it prints the account in lower case)")
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stdout), &refusal), "the helper's refusal: %s", stdout)
	assert.Equal(t, winproto.CodeUnknownSubcommand, refusal.Code)
	code, stdout, stderr = setupSSHAs(t, other, keyFile, knownHosts, nil, winproto.SubVersion)
	require.Equal(t, 0, code, "ssh %s@localhost version: %s %s", other, stdout, stderr)
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stdout), &version), string(stdout))
	assert.Equal(t, winproto.Protocol, version.Protocol)

	// A second run changes nothing.
	before := setupState(t)
	runSetupScript(t, work, scriptFile)
	assert.Equal(t, before, setupState(t), "running the script again changes nothing")
	code, stdout, stderr = setupSSH(t, keyFile, knownHosts, winproto.SubVersion)
	assert.Equal(t, 0, code, "ssh version after the second run: %s %s", stdout, stderr)
}
