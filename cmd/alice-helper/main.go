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
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

func main() {
	syscall.Umask(0o077)
	keepRunning()
	os.Exit(run(os.Args[1:], productionSys()))
}

// keepRunning makes SIGHUP and SIGPIPE harmless: a dropped SSH connection must never stop a
// transaction half-way (R38 item 1); a write to a closed stdout then fails with EPIPE instead.
// The signals are caught, not ignored, so nginx and systemctl start with the default dispositions
// (an ignored signal would be inherited across exec).
func keepRunning() {
	signal.Notify(make(chan os.Signal, 1), syscall.SIGHUP, syscall.SIGPIPE)
}

// productionSys is the real environment: the whole filesystem, the real user IDs and sshd.
func productionSys() *sys {
	s := &sys{
		euid:     os.Geteuid,
		sudoUser: func() string { return os.Getenv("SUDO_USER") },
		now:      time.Now, //nolint:forbidigo // the helper is a separate binary; its clock is injected through sys.now
		runSSHD:  runSSHD,
		stdin:    os.Stdin,
		stdout:   os.Stdout,
		chown:    func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) },
		// systemctl is not a web-server program: it is not pre-checked (Ruling 15, KI-40).
		runSystemctl: func(ctx context.Context, args ...string) error {
			_, _, err := runProgram(ctx, systemctlPath, 64<<10, args...)
			return err
		},
		statfs: func(fd int) (int64, error) {
			var st unix.Statfs_t
			if err := unix.Fstatfs(fd, &st); err != nil {
				return 0, err
			}
			return int64(st.Bavail) * st.Bsize, nil //nolint:gosec // G115: block counts fit an int64
		},
		fsMagic: func(fd int) (int64, error) {
			var st unix.Statfs_t
			if err := unix.Fstatfs(fd, &st); err != nil {
				return 0, err
			}
			return st.Type, nil
		},
		dial: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	s.syslog = func(subcommand, path string) { writeSyslog(s.sudoUserName(), subcommand, path) }
	// The web-server programs run only after the root-control pre-check (Ruling 15). They are set
	// here, not in the literal, because they are methods of s.
	s.runNginx = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		return s.runGuarded(ctx, nginxPath, nil, helperproto.MaxServerConfig, args...)
	}
	s.runApache = s.runApacheCtl
	s.runHAProxy = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		return s.runGuarded(ctx, haproxyPath, nil, helperproto.MaxServerConfig, args...)
	}
	return s
}

// haproxyPath is HAProxy's program (Ruling 2); haproxy-dump runs it through runHAProxy.
const haproxyPath = "/usr/sbin/haproxy"

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
func writeSyslog(user, subcommand, path string) {
	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, "alice-helper")
	if err != nil {
		return
	}
	defer func() { _ = w.Close() }()
	if user == "" {
		user = "unknown"
	}
	_ = w.Info("user=" + user + " subcommand=" + subcommand + " path=" + path)
}
