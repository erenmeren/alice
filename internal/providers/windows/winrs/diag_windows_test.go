//go:build windows

package winrs_test

// Hand-driven calls for what winrs.Client does not show: stderr, and a Command body changed by hand. Runner runs 3-6
// used them to find why programs exited 1 (the codec's escaped quotes, fixed in a594ffec); a short subset stays on
// record ("FACT F24-diag:"), and F25 and F29 use rawRun. Nothing here is asserted.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/winrs"
)

func first(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return fmt.Sprintf("%q", b)
}

// rawRun is one hand-driven call: Create (env), Command (its body passed through edit when not nil), one Send with
// stdin, Receive until done, Delete. A failed stage is returned as an error naming it.
func (f *fx) rawRun(t *testing.T, program string, args []string, env map[string]string, stdin []byte,
	edit func([]byte) []byte) (stdout, stderr []byte, code int, err error) {
	t.Helper()
	r := newRaw(t, imageAddr, f.spki, account, f.pw)
	body, err := winrs.CreateShellRequest(r.header(), env, 2*time.Minute)
	require.NoError(t, err)
	a := r.post(body, true)
	if a.err != nil || a.status != http.StatusOK {
		return nil, nil, 0, fmt.Errorf("Create: status %d, %s, err %w", a.status, a.fault(), a.err)
	}
	shell, err := winrs.ParseShellCreated(a.body)
	require.NoError(t, err)
	defer r.delete(t, shell)
	cmd, err := winrs.CommandRequest(r.header(), shell, program, args)
	require.NoError(t, err)
	if edit != nil {
		cmd = edit(cmd)
	}
	a = r.post(cmd, false)
	if a.err != nil || a.status != http.StatusOK {
		return nil, nil, 0, fmt.Errorf("Command: status %d, %s, err %w", a.status, a.fault(), a.err)
	}
	cmdID, err := winrs.ParseCommandStarted(a.body)
	require.NoError(t, err)
	send, err := winrs.SendRequest(r.header(), shell, cmdID, stdin, true)
	require.NoError(t, err)
	if a = r.post(send, false); a.err != nil || a.status != http.StatusOK {
		return nil, nil, 0, fmt.Errorf("Send: status %d, %s, err %w", a.status, a.fault(), a.err)
	}
	return r.receive(shell, cmdID)
}

// diagnoseCommands logs three calls in the codec's form with their stderr (logged only).
func diagnoseCommands(t *testing.T, f *fx) {
	t.Helper()
	whoami := filepath.Join(os.Getenv("SystemRoot"), "System32", "whoami.exe")
	for _, c := range []struct {
		name    string
		program string
		args    []string
		env     map[string]string
		stdin   []byte
	}{
		{"whoami", whoami, nil, nil, nil},
		{"stdinhash 3 with stdin x", f.stdinhash, []string{"3"}, nil, []byte("x")},
		{"the helper ssh with version", f.helper, []string{"ssh"}, map[string]string{"SSH_ORIGINAL_COMMAND": winproto.SubVersion}, nil},
	} {
		stdout, stderr, code, err := f.rawRun(t, c.program, c.args, c.env, c.stdin, nil)
		fact(t, "F24-diag", "%s: exit %d, stdout %s, stderr %s, err %v", c.name, code, first(stdout, 400), first(stderr, 400), err)
	}
}
