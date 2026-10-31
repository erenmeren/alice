//go:build windows

package winrs_test

// Diagnostics of runner runs 3 and 4 (R71 Task 4): every program run over WinRS exited 1 with no stdout, and some
// Creates were refused with 0x80070005. These hand-driven calls log what each variant answers ("FACT F24-diag:" for
// the matrix, "FACT W7-diag:" for a refused Create); nothing here is asserted.

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

// edit is a change of a request body: the option name's value, or the option dropped (to ""), or the program's
// quotes removed (unquote).
type edit struct{ option, from, to string }

var unquote = edit{option: "unquote"}

func (e edit) apply(t *testing.T, body []byte) []byte {
	t.Helper()
	if e == unquote { // the program without the quotes CommandRequest puts around it
		i, j := bytes.Index(body, []byte("<rsp:Command>")), bytes.Index(body, []byte("</rsp:Command>"))
		if i < 0 || j < i {
			t.Logf("W7-diag: the body has no rsp:Command")
			return body
		}
		inner := bytes.ReplaceAll(bytes.ReplaceAll(body[i:j], []byte("&#34;"), nil), []byte(`"`), nil)
		return append(append(append([]byte{}, body[:i]...), inner...), body[j:]...)
	}
	old := []byte(`<w:Option Name="` + e.option + `">` + e.from + `</w:Option>`)
	if !bytes.Contains(body, old) {
		t.Logf("W7-diag: the body has no %s, so this variant is the codec's form", old)
		return body
	}
	repl := []byte{}
	if e.to != "" {
		repl = []byte(`<w:Option Name="` + e.option + `">` + e.to + `</w:Option>`)
	}
	return bytes.Replace(body, old, repl, 1)
}

// The option changes of the matrix.
var (
	profile     = edit{"WINRS_NOPROFILE", "TRUE", "FALSE"}
	noCodepage  = edit{"WINRS_CODEPAGE", "65001", ""}
	codepage437 = edit{"WINRS_CODEPAGE", "65001", "437"}
	noConsole   = edit{"WINRS_CONSOLEMODE_STDIN", "FALSE", ""}
	consoleOn   = edit{"WINRS_CONSOLEMODE_STDIN", "FALSE", "TRUE"}
	throughCmd  = edit{"WINRS_SKIP_CMD_SHELL", "TRUE", "FALSE"}
)

// pywinrm's defaults: NOPROFILE FALSE and CODEPAGE 437 at Create; CONSOLEMODE_STDIN TRUE, SKIP_CMD_SHELL FALSE and
// the program unquoted at Command.
var pywinrmCreate, pywinrmCommand = []edit{profile, codepage437}, []edit{consoleOn, throughCmd, unquote}

// diagCall is one hand-driven call: Create (env), Command, one Send with stdin, Receive until done, Delete, with
// the given changes of the Create and Command bodies the codec builds. It logs every stage's answer.
func (f *fx) diagCall(t *testing.T, name, program string, args []string, env map[string]string, stdin []byte,
	create, command []edit, logBody bool) {
	t.Helper()
	r := newRaw(t, imageAddr, f.spki, account, f.pw)
	body, err := winrs.CreateShellRequest(r.header(), env, 2*time.Minute)
	require.NoError(t, err)
	for _, e := range create {
		body = e.apply(t, body)
	}
	a := r.post(body, true)
	if a.err != nil || a.status != http.StatusOK {
		fact(t, "F24-diag", "%s: Create: status %d, %s, err %v", name, a.status, a.fault(), a.err)
		return
	}
	shell, err := winrs.ParseShellCreated(a.body)
	require.NoError(t, err)
	defer r.delete(t, shell)

	cmd, err := winrs.CommandRequest(r.header(), shell, program, args)
	require.NoError(t, err)
	for _, e := range command {
		cmd = e.apply(t, cmd)
	}
	if logBody {
		fact(t, "F24-diag", "the raw Create request body: %s", body)
		fact(t, "F24-diag", "the raw Command request body: %s", cmd)
	}
	a = r.post(cmd, false)
	if a.err != nil || a.status != http.StatusOK {
		fact(t, "F24-diag", "%s: Command: status %d, %s, err %v", name, a.status, a.fault(), a.err)
		return
	}
	cmdID, err := winrs.ParseCommandStarted(a.body)
	require.NoError(t, err)
	send, err := winrs.SendRequest(r.header(), shell, cmdID, stdin, true)
	require.NoError(t, err)
	if a = r.post(send, false); a.err != nil || a.status != http.StatusOK {
		fact(t, "F24-diag", "%s: Send: status %d, %s, err %v", name, a.status, a.fault(), a.err)
	}
	stdout, stderr, code, err := r.receive(shell, cmdID)
	n := 400
	if strings.Contains(name, "/groups") {
		n = 4000 // the token
	}
	fact(t, "F24-diag", "%s: exit %d, stdout %s, stderr %s, err %v", name, code, first(stdout, n), first(stderr, 400), err)
}

// diagnoseCommands runs the matrix of runner runs 3 and 4 (logged only): at the start of the first real test,
// before any setting changes.
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

	whoami := filepath.Join(os.Getenv("SystemRoot"), "System32", "whoami.exe")
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	line := map[string]string{"SSH_ORIGINAL_COMMAND": winproto.SubVersion}
	x := []byte("x")
	for i, c := range []struct {
		name            string
		program         string
		args            []string
		env             map[string]string
		stdin           []byte
		create, command []edit
	}{
		{"whoami, the codec's form", whoami, nil, nil, nil, nil, nil},
		{"whoami /groups /priv, the codec's form", whoami, []string{"/groups", "/priv"}, nil, nil, nil, nil},
		{"whoami /groups /priv, pywinrm's form", whoami, []string{"/groups", "/priv"}, nil, nil, pywinrmCreate, pywinrmCommand},
		{"whoami, unquoted", whoami, nil, nil, nil, nil, []edit{unquote}},
		{"whoami, through cmd.exe, unquoted", whoami, nil, nil, nil, nil, []edit{throughCmd, unquote}},
		{"whoami, WINRS_NOPROFILE FALSE", whoami, nil, nil, nil, []edit{profile}, nil},
		{"whoami, no WINRS_CODEPAGE", whoami, nil, nil, nil, []edit{noCodepage}, nil},
		{"whoami, no WINRS_CONSOLEMODE_STDIN", whoami, nil, nil, nil, nil, []edit{noConsole}},
		{"whoami, WINRS_CONSOLEMODE_STDIN TRUE", whoami, nil, nil, nil, nil, []edit{consoleOn}},
		{"whoami, pywinrm's form", whoami, nil, nil, nil, pywinrmCreate, pywinrmCommand},
		{"stdinhash 3 in " + diagDir + ", the codec's form", hash, []string{"3"}, nil, x, nil, nil},
		{"stdinhash 3 in " + diagDir + ", unquoted", hash, []string{"3"}, nil, x, nil, []edit{unquote}},
		{"stdinhash 3 in " + diagDir + ", WINRS_NOPROFILE FALSE", hash, []string{"3"}, nil, x, []edit{profile}, nil},
		{"stdinhash 3 in " + diagDir + ", no WINRS_CODEPAGE", hash, []string{"3"}, nil, x, []edit{noCodepage}, nil},
		{"stdinhash 3 in " + diagDir + ", WINRS_CONSOLEMODE_STDIN TRUE", hash, []string{"3"}, nil, x, nil, []edit{consoleOn}},
		{"stdinhash 3 in " + diagDir + ", pywinrm's form", hash, []string{"3"}, nil, x, pywinrmCreate, pywinrmCommand},
		{"stdinhash 3 in the test directory, the codec's form", f.stdinhash, []string{"3"}, nil, x, nil, nil},
		{"cmd /c echo %SSH_ORIGINAL_COMMAND%, pywinrm's form", cmdExe, []string{"/c", "echo", "%SSH_ORIGINAL_COMMAND%"}, line, nil, pywinrmCreate, pywinrmCommand},
		{"the helper ssh with version, the codec's form", f.helper, []string{"ssh"}, line, nil, nil, nil},
		{"the helper ssh with version, pywinrm's form", f.helper, []string{"ssh"}, line, nil, pywinrmCreate, pywinrmCommand},
	} {
		f.diagCall(t, c.name, c.program, c.args, c.env, c.stdin, c.create, c.command, i == 0)
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
	fact(t, "W7-diag", "a call refused with WS-Management fault %d: alice-w7's shells %v (err %v)", fe.Code, shells, serr)
	fact(t, "W7-diag", "WinRM Operational events since the test started: %s", winrmMessages(t, t0))
	time.Sleep(2 * time.Second)
	res, err = run(c, call)
	fact(t, "W7-diag", "the same call again after 2 s: %s", outcome(res, err))
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
