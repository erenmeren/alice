//go:build windows

package winrs_test

// Diagnostics of runner run 3 (R71 Task 4): every program run over WinRS exited 1 with no stdout, and some Creates
// were refused with 0x80070005. These hand-driven calls log what each variant answers ("FACT F25-diag:"); nothing
// here is asserted.

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/winrs"
)

// diagDir is a directory without spaces whose ACL grants Administrators and alice-w7 read and execute.
const diagDir = `C:\alice-w7-diag`

func first(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return fmt.Sprintf("%q", b)
}

// diagCall is one hand-driven call: Create (env), Command (program and args, quoted or not on the wire, through
// cmd.exe or not), one Send with stdin, Receive until done, Delete. It logs every stage's answer.
func (f *fx) diagCall(t *testing.T, name, program string, args []string, env map[string]string, stdin []byte, skipCmd, quoted, logBody bool) {
	t.Helper()
	r := newRaw(t, imageAddr, f.spki, account, f.pw)
	body, err := winrs.CreateShellRequest(r.header(), env, 2*time.Minute)
	require.NoError(t, err)
	a := r.post(body, true)
	if a.err != nil || a.status != http.StatusOK {
		fact(t, "F25-diag", "%s: Create: status %d, %s, err %v", name, a.status, a.fault(), a.err)
		return
	}
	shell, err := winrs.ParseShellCreated(a.body)
	require.NoError(t, err)
	defer r.delete(t, shell)

	cmd, err := winrs.CommandRequest(r.header(), shell, program, args)
	require.NoError(t, err)
	if !quoted { // the program without the quotes CommandRequest puts around it
		i, j := bytes.Index(cmd, []byte("<rsp:Command>")), bytes.Index(cmd, []byte("</rsp:Command>"))
		require.True(t, i >= 0 && j > i)
		inner := bytes.ReplaceAll(cmd[i:j], []byte("&#34;"), nil)
		cmd = append(append(append([]byte{}, cmd[:i]...), inner...), cmd[j:]...)
	}
	if !skipCmd {
		on := []byte(`<w:Option Name="WINRS_SKIP_CMD_SHELL">TRUE</w:Option>`)
		require.Contains(t, string(cmd), string(on))
		cmd = bytes.Replace(cmd, on, []byte(`<w:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</w:Option>`), 1)
	}
	if logBody {
		fact(t, "F25-diag", "the raw Command request body: %s", cmd)
	}
	a = r.post(cmd, false)
	if a.err != nil || a.status != http.StatusOK {
		fact(t, "F25-diag", "%s: Command: status %d, %s, err %v", name, a.status, a.fault(), a.err)
		return
	}
	cmdID, err := winrs.ParseCommandStarted(a.body)
	require.NoError(t, err)
	send, err := winrs.SendRequest(r.header(), shell, cmdID, stdin, true)
	require.NoError(t, err)
	if a = r.post(send, false); a.err != nil || a.status != http.StatusOK {
		fact(t, "F25-diag", "%s: Send: status %d, %s, err %v", name, a.status, a.fault(), a.err)
	}
	stdout, stderr, code, err := r.receive(shell, cmdID)
	fact(t, "F25-diag", "%s: exit %d, stdout %s, stderr %s, err %v", name, code, first(stdout, 400), first(stderr, 400), err)
}

// diagnoseCommands runs the matrix of runner run 3's diagnosis (logged only).
func diagnoseCommands(t *testing.T, f *fx) {
	t.Helper()
	removeDiagDir := func() error {
		var err error
		for i := 0; i < 20; i++ {
			if err = os.RemoveAll(diagDir); err == nil {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return err
	}
	require.NoError(t, removeDiagDir(), "a %s left by an earlier run", diagDir)
	t.Cleanup(func() {
		if err := removeDiagDir(); err != nil {
			t.Errorf("removing %s: %v", diagDir, err)
		}
	})
	require.NoError(t, os.Mkdir(diagDir, 0o700))
	out, err := exec.Command("icacls", diagDir, "/grant", "*"+adminsSID+":(OI)(CI)RX", account+":(OI)(CI)RX").CombinedOutput()
	require.NoError(t, err, "icacls: %s", out)
	hash := filepath.Join(diagDir, "stdinhash.exe")
	b, err := os.ReadFile(f.stdinhash)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(hash, b, 0o600))
	acl, _ := exec.Command("icacls", f.dir).CombinedOutput()
	fact(t, "F25-diag", "the ACL of the test program directory %s: %s", f.dir, strings.Join(strings.Fields(string(acl)), " "))

	whoami := filepath.Join(os.Getenv("SystemRoot"), "System32", "whoami.exe")
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	line := map[string]string{"SSH_ORIGINAL_COMMAND": winproto.SubVersion}
	for _, c := range []struct {
		name         string
		program      string
		args         []string
		env          map[string]string
		stdin        []byte
		skip, quoted bool
	}{
		{"whoami, quoted, no cmd.exe (the codec's form)", whoami, nil, nil, nil, true, true},
		{"whoami, unquoted, no cmd.exe", whoami, nil, nil, nil, true, false},
		{"whoami, quoted, through cmd.exe", whoami, nil, nil, nil, false, true},
		{"whoami, unquoted, through cmd.exe", whoami, nil, nil, nil, false, false},
		{"stdinhash 3 in " + diagDir + ", quoted, no cmd.exe", hash, []string{"3"}, nil, []byte("x"), true, true},
		{"stdinhash 3 in " + diagDir + ", unquoted, no cmd.exe", hash, []string{"3"}, nil, []byte("x"), true, false},
		{"stdinhash 3 in " + diagDir + ", unquoted, through cmd.exe", hash, []string{"3"}, nil, []byte("x"), false, false},
		{"stdinhash 3 in the test directory, quoted, no cmd.exe", f.stdinhash, []string{"3"}, nil, []byte("x"), true, true},
		{"cmd /c echo %SSH_ORIGINAL_COMMAND%, through cmd.exe", cmdExe, []string{"/c", "echo", "%SSH_ORIGINAL_COMMAND%"}, line, nil, false, false},
		{"the helper ssh with version, quoted, no cmd.exe", f.helper, []string{"ssh"}, line, nil, true, true},
		{"the helper ssh with version, unquoted, no cmd.exe", f.helper, []string{"ssh"}, line, nil, true, false},
	} {
		f.diagCall(t, c.name, c.program, c.args, c.env, c.stdin, c.skip, c.quoted, c.program == whoami && c.skip && c.quoted)
	}
}

// retryRefusedCreate logs, for a call refused with a WS-Management fault (0x80070005 at Create in runner run 3), the
// shells listed for alice-w7 and the WinRM Operational events since t0, then runs the call once more after 2 s and
// logs that too. It returns the retry's result (or the first one when there was no fault).
func (f *fx) retryRefusedCreate(t *testing.T, c *winrs.Client, call winrs.Call, res winrs.Result, err error, t0 time.Time) (winrs.Result, error) {
	t.Helper()
	var fe *winrs.FaultError
	if !errors.As(err, &fe) {
		return res, err
	}
	shells, serr := f.shells()
	fact(t, "F25-diag", "a call refused with WS-Management fault %d: alice-w7's shells %v (err %v)", fe.Code, shells, serr)
	fact(t, "F25-diag", "WinRM Operational events since the test started: %s", winrmMessages(t, t0))
	time.Sleep(2 * time.Second)
	res, err = run(c, call)
	fact(t, "F25-diag", "the same call again after 2 s: %s", outcome(res, err))
	return res, err
}

// winrmMessages is the WinRM Operational events since t0: id and the first 300 characters of the message.
func winrmMessages(t *testing.T, t0 time.Time) string {
	t.Helper()
	out, err := psRun(map[string]string{"SINCE": t0.UTC().Format(time.RFC3339Nano)}, "", sinceScript+
		`@(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WinRM/Operational'; StartTime = $since } -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated | ForEach-Object { $m = "$($_.Message)" -replace '\s+', ' '; if ($m.Length -gt 300) { $m = $m.Substring(0, 300) }; "[$($_.Id)] $m" }) -join ' | '`)
	if err != nil {
		return fmt.Sprintf("(not read: %v)", err)
	}
	return out
}
