//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

// requireReal skips a test that reads or changes the machine unless ALICE_WIN_REAL=1: the Windows
// workflow (Task 11) sets it on its runners and fails on a skip; a developer's Windows box does not run
// them by accident.
func requireReal(t *testing.T) {
	t.Helper()
	if os.Getenv("ALICE_WIN_REAL") != "1" {
		t.Skip("set ALICE_WIN_REAL=1 to run against this Windows machine")
	}
}

// runPowershell runs a fixture or cross-check script with extra environment variables (tests only: the
// helper never runs PowerShell). Values reach the script through $env:, never through its text.
func runPowershell(env map[string]string, script string) ([]byte, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"$ErrorActionPreference = 'Stop'; "+script)
	cmd.Env = powershellEnviron()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, errors.New(err.Error() + ": " + stderr.String())
	}
	return out, nil
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

func powershellEnv(t *testing.T, env map[string]string, script string) []byte {
	t.Helper()
	out, err := runPowershell(env, script)
	require.NoError(t, err, "powershell: %s", script)
	return out
}

func powershell(t *testing.T, script string) []byte {
	t.Helper()
	return powershellEnv(t, nil, script)
}

func TestRealHostIsElevated(t *testing.T) {
	requireReal(t)
	el, err := newHost().Elevated()
	require.NoError(t, err)
	assert.True(t, el, "the runner's administrator token is elevated")
}

func TestRealOSFactsMatchTheRegistryReadIndependently(t *testing.T) {
	requireReal(t)
	f, err := newHost().OSFacts(context.Background())
	require.NoError(t, err)
	var cim struct{ Version, BuildNumber, Caption string }
	require.NoError(t, json.Unmarshal(powershell(t,
		"Get-CimInstance Win32_OperatingSystem | Select-Object Version,BuildNumber,Caption | ConvertTo-Json -Compress"), &cim))
	// Win32_OperatingSystem.Version is major.minor.build; the helper adds the update build revision.
	assert.True(t, strings.HasPrefix(f.Build, cim.Version+"."), "build %q, CIM version %q", f.Build, cim.Version)
	parts := strings.Split(f.Build, ".")
	require.Len(t, parts, 4, f.Build)
	assert.Equal(t, cim.BuildNumber, parts[2])
	// The caption is "Microsoft " and the registry's ProductName.
	assert.Equal(t, strings.TrimSpace(cim.Caption), "Microsoft "+f.Product)
	assert.Equal(t, "Server", f.InstallationType)
	if _, err := os.Stat(filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "sshd.exe")); err == nil {
		assert.NotEmpty(t, f.OpenSSHVersion, "sshd.exe is installed")
	}
}

func TestRealIISFacts(t *testing.T) {
	requireReal(t)
	f, err := newHost().IISFacts(context.Background())
	require.NoError(t, err, "the workflow installs IIS (Web-Server) before the tests")
	assert.True(t, f.Installed)
	assert.Equal(t, "10.0", f.Version)
	assert.False(t, f.SharedConfig, "the runner has no shared configuration")
	// AutoCertRebind as Task Scheduler reports it ("absent" when the task does not exist).
	state := strings.TrimSpace(string(powershell(t,
		`$task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\CertificateServicesClient\' -TaskName AutoCertRebind -ErrorAction SilentlyContinue; `+
			`if ($task) { [string]$task.State } else { 'absent' }`)))
	assert.Equal(t, state != "absent" && state != "Disabled", f.AutoCertRebind, "task state %q", state)
}

// denyFactFiles makes every fact file unreadable, as for a non-elevated token (inetsrv\config and
// System32\Tasks admit only Administrators and SYSTEM).
func denyFactFiles(t *testing.T) {
	t.Helper()
	old := openFact
	openFact = func(path string) (io.ReadCloser, error) {
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_ACCESS_DENIED}
	}
	t.Cleanup(func() { openFact = old })
}

func TestUnreadableFactFilesAreUnknown(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "redirection.config")
	require.NoError(t, os.WriteFile(cfg, []byte(`<configuration><configurationRedirection enabled="true" /></configuration>`), 0o600))
	task := filepath.Join(dir, "AutoCertRebind")
	require.NoError(t, os.WriteFile(task, []byte(`<Task><Settings><Enabled>true</Enabled></Settings></Task>`), 0o600))
	got, err := sharedConfig(cfg)
	require.NoError(t, err)
	require.True(t, got, "positive control: the file reads as shared when it can be opened")

	denyFactFiles(t)
	got, err = sharedConfig(cfg)
	require.NoError(t, err, "access denied is not a failed reading")
	assert.False(t, got)
	got, err = taskEnabled(task)
	require.NoError(t, err)
	assert.False(t, got)
}

// Ruling 3: win-facts answers without an elevated token, whose reads of the IIS fact files are denied.
func TestRealWinFactsWithUnreadableFactFiles(t *testing.T) {
	requireReal(t)
	denyFactFiles(t)
	f, err := newHost().IISFacts(context.Background())
	require.NoError(t, err)
	assert.True(t, f.Installed)
	assert.False(t, f.SharedConfig)
	assert.False(t, f.AutoCertRebind)

	var out bytes.Buffer
	code := winhelper.Run(context.Background(), newHost(), []string{winproto.SubWinFacts}, nil, &out)
	require.Equal(t, winproto.ExitOK, code, out.String())
	var answer winproto.WinFactsResponse
	require.NoError(t, json.Unmarshal(out.Bytes(), &answer))
	assert.True(t, answer.OK)
	assert.True(t, answer.IIS.Installed)
}

func TestRealStoresListTheMachineStores(t *testing.T) {
	requireReal(t)
	stores, err := newHost().Stores(context.Background())
	require.NoError(t, err)
	for _, s := range []string{"My", "CA", "Root"} {
		assert.Contains(t, stores, s)
	}
}

// buildHelper builds this command into a temporary directory.
func buildHelper(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "alice-helper.exe")
	cmd := exec.Command("go", "build", "-o", exe, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return exe
}

// runHelper runs the built helper and returns its exit code and its one JSON line.
func runHelper(t *testing.T, exe, original string, args ...string) (int, map[string]any) {
	t.Helper()
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+original)
	out, err := cmd.Output()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else {
		require.NoError(t, err)
	}
	var answer map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(out), &answer), string(out))
	return code, answer
}

func TestMainRefusesAShellLine(t *testing.T) {
	requireReal(t)
	exe := buildHelper(t)

	code, answer := runHelper(t, exe, "version & whoami", winproto.SubSSH)
	assert.Equal(t, winproto.ExitRefused, code)
	assert.Equal(t, winproto.CodeInvalidArgument, answer["code"])

	code, answer = runHelper(t, exe, "version", winproto.SubSSH)
	assert.Equal(t, winproto.ExitOK, code)
	assert.EqualValues(t, winproto.Protocol, answer["protocol"])
	assert.Equal(t, winproto.Version, answer["helper"])

	// A local run by an administrator names the subcommand on the command line.
	code, answer = runHelper(t, exe, "", winproto.SubVersion)
	assert.Equal(t, winproto.ExitOK, code)
	assert.EqualValues(t, winproto.Protocol, answer["protocol"])
}

// The fact files' parsing needs no real machine.
func TestFactFilesParse(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, data, 0o600))
		return p
	}
	utf16LE := func(s string) []byte {
		b := []byte{0xff, 0xfe}
		for _, c := range utf16.Encode([]rune(s)) {
			b = append(b, byte(c), byte(c>>8))
		}
		return b
	}
	task := func(enabled string) string {
		return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Settings>` + enabled +
			`<Hidden>true</Hidden></Settings><Actions Context="LocalSystem"/></Task>`
	}

	for _, c := range []struct {
		name string
		data []byte
		want bool
	}{
		{"disabled", utf16LE(task("<Enabled>false</Enabled>")), false},
		{"enabled", utf16LE(task("<Enabled>true</Enabled>")), true},
		{"default", utf16LE(task("")), true},
		{"utf8", []byte("\xef\xbb\xbf" + strings.Replace(task("<Enabled>true</Enabled>"), "UTF-16", "UTF-8", 1)), true},
	} {
		got, err := taskEnabled(write("task-"+c.name, c.data))
		require.NoError(t, err, c.name)
		assert.Equal(t, c.want, got, c.name)
	}
	got, err := taskEnabled(filepath.Join(dir, "absent"))
	require.NoError(t, err)
	assert.False(t, got, "no task, no rebind")

	redirect := func(attrs string) []byte {
		return []byte("\xef\xbb\xbf<configuration><configSections><section name=\"configurationRedirection\" /></configSections>" +
			"<configurationRedirection " + attrs + " /></configuration>")
	}
	for _, c := range []struct {
		attrs string
		want  bool
	}{{`enabled="true" path="\\files\iis"`, true}, {`enabled="false"`, false}, {"", false}} {
		got, err := sharedConfig(write("redirection.config", redirect(c.attrs)))
		require.NoError(t, err, c.attrs)
		assert.Equal(t, c.want, got, c.attrs)
	}
	got, err = sharedConfig(filepath.Join(dir, "absent.config"))
	require.NoError(t, err)
	assert.False(t, got)

	_, err = sharedConfig(write("broken.config", []byte("<configuration><configurationRedirection")))
	assert.Error(t, err, "a configuration that does not parse is an error, not a guess")
	_, err = taskEnabled(write("huge", bytes.Repeat([]byte(" "), maxFactFile+1)))
	assert.Error(t, err, "a file over the bound is refused")
}
