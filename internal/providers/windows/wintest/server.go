package wintest

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

// Handler answers helper command lines with the helper's own code (winhelper.ExecuteForced) on the
// model; a call killed at a crash point (KillAt) answers nothing, with KilledExit.
// A missing helper or a missing ForceCommand answers like cmd.exe: exit 1, the text on stderr only.
func (m *Model) Handler() linuxsshtest.Handler {
	return func(cmd string, stdin []byte) linuxsshtest.Response {
		sub, _, _ := strings.Cut(cmd, " ")
		m.mu.Lock()
		missing := m.helperMissing || m.noForced
		protocol := m.protocol
		delay := m.delays[sub]
		m.mu.Unlock()
		if missing {
			return linuxsshtest.Response{Stderr: []byte("'" + sub + "' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"), Exit: 1}
		}
		var out bytes.Buffer
		if cmd == winproto.SubVersion && protocol != winproto.Protocol {
			b, _ := json.Marshal(winproto.VersionResponse{OK: true, Helper: winproto.Version, Protocol: protocol})
			return linuxsshtest.Response{Stdout: append(b, '\n'), Delay: delay}
		}
		o := winhelper.ExecuteForced(context.Background(), m.Host(), cmd, bytes.NewReader(stdin), &out)
		if o.Killed {
			// A helper killed at a crash point printed nothing (KillAt).
			return linuxsshtest.Response{Exit: KilledExit, Delay: delay}
		}
		return linuxsshtest.Response{Stdout: out.Bytes(), Exit: o.Exit, Delay: delay}
	}
}

// NewServer starts an SSH server whose handler is the model's, in the mode of Windows OpenSSH (every
// session after the first on a connection sees the first command, design §8), and TLS listeners on
// random loopback ports for the bindings the model has now (see Serve, Endpoint). Both stop with the test.
func NewServer(t testing.TB, m *Model) *linuxsshtest.Server {
	t.Helper()
	s := linuxsshtest.NewServer(t, m.Handler())
	s.StickyFirstCommand()
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Serve(ctx, "127.0.0.1:0"); err != nil {
		cancel()
		t.Fatalf("wintest: serve: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		m.serving.Wait()
	})
	return s
}
