//go:build linux

// Command alice-helper is the root-owned static helper Alice runs on managed Linux servers through
// sudo (spec §6.6, §12.2, §12.3, §13.1, R13, R21). It is the enforcement point of Alice's remote
// command surface: every argument is hostile, authorized_keys paths are computed by the helper
// itself from /etc/passwd and sshd -T, and every answer is exactly one JSON line on stdout.
package main

import (
	"context"
	"io"
	"log/syslog"
	"os"
	"os/exec"
	"syscall"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
)

func main() {
	syscall.Umask(0o077)
	os.Exit(run(os.Args[1:], productionSys()))
}

// productionSys is the real environment: the whole filesystem, the real user IDs and sshd.
func productionSys() *sys {
	return &sys{
		euid:     os.Geteuid,
		sudoUser: func() string { return os.Getenv("SUDO_USER") },
		now:      time.Now, //nolint:forbidigo // the helper is a separate binary; its clock is injected through sys.now
		runSSHD:  runSSHD,
		stdin:    os.Stdin,
		stdout:   os.Stdout,
		syslog:   writeSyslog,
	}
}

// sshdPath is the OpenSSH server binary on every supported distribution (spec §12.1).
const sshdPath = "/usr/sbin/sshd"

// runSSHD runs sshd with a clean environment; stdout is capped at sshdOutputLimit, stderr dropped.
func runSSHD(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, sshdPath, args...) //nolint:gosec // G204: fixed binary; arguments are fixed flags and validated user names
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	out := &capWriter{max: sshdOutputLimit}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if out.over {
		return nil, errTooLarge
	}
	return out.buf, nil
}

// capWriter keeps at most max bytes and notes that more arrived.
type capWriter struct {
	max  int
	buf  []byte
	over bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if len(w.buf)+len(p) > w.max {
		w.over = true
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

// writeSyslog records the call in the authpriv log (spec §12.3): the calling user, the subcommand
// and the normalized path, never contents. Failures are ignored (the answer to Alice still counts).
func writeSyslog(subcommand, path string) {
	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, "alice-helper")
	if err != nil {
		return
	}
	defer func() { _ = w.Close() }()
	user := os.Getenv("SUDO_USER")
	if !helperproto.ValidUser(user) {
		user = "unknown"
	}
	_ = w.Info("user=" + user + " subcommand=" + subcommand + " path=" + path)
}
