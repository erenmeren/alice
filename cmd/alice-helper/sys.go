//go:build linux

package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
)

// sys is everything the helper touches outside its own memory. Paths inside the helper are
// "guest" paths (as on the server); host turns them into real paths under root, so tests can run
// every subcommand against a temporary directory as an unprivileged user.
type sys struct {
	root string // filesystem prefix: "" in production, a temporary directory in tests
	// rootUID is the owner every directory of an absolute AuthorizedKeysFile pattern outside the
	// home must have (rootControlled): 0 in production; tests that do not run as root use their uid.
	rootUID int
	// rootGID is root's group (0 in production; tests use their own gid), compared with key files'
	// groups the same way rootUID is with their owners.
	rootGID  int
	euid     func() int
	sudoUser func() string
	now      func() time.Time
	runSSHD  func(ctx context.Context, args ...string) ([]byte, error)
	// runNginx runs /usr/sbin/nginx with fixed arguments (-V, -T, -t) through runProgram; stdout is
	// capped at helperproto.MaxNginxConfig, stderr at 64 KiB. A missing binary is an
	// fs.ErrNotExist error.
	runNginx func(ctx context.Context, args ...string) (stdout, stderr []byte, err error)
	// runSystemctl runs /usr/bin/systemctl with fixed arguments (Task 6).
	runSystemctl func(ctx context.Context, args ...string) error
	// statfs returns the bytes available to root in the file system of a descriptor.
	statfs func(fd int) (int64, error)
	// fsMagic returns the file system type (statfs f_type) of a descriptor.
	fsMagic func(fd int) (int64, error)
	// dial opens the TCP connection of tls-probe.
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	stdin  io.Reader
	stdout io.Writer
	syslog func(subcommand, path string)
	// chown sets the owner of a file or directory the helper created, through its descriptor
	// (tests record instead: they do not run as root).
	chown func(f *os.File, uid, gid int) error
	// beforeRename runs just before a staged file replaces the real one (nil in production; tests
	// inject failures and races).
	beforeRename func() error
	// afterMkdirSSH runs between creating a missing .ssh and opening it (nil in production; tests
	// inject races).
	afterMkdirSSH func()
	// walkHook runs in resolveRoot between the check of a directory and its open (nil in
	// production; tests inject swaps).
	walkHook func(name string)
	// afterDeployStep runs at each step and at each finer point of nginx-deploy and nginx-restore
	// (nil in production); a test returns errKilled to simulate the helper dying right there (no
	// rollback, no cleanup, the journal stays). killed is set when it did.
	afterDeployStep func(point string) error
	killed          bool
}

// host returns the real path of an absolute guest path.
func (s *sys) host(guest string) string { return filepath.Join(s.root, guest) }

// guest returns the guest path of a real path, or false when it lies outside root.
func (s *sys) guest(host string) (string, bool) {
	if s.root == "" {
		return host, true
	}
	if host == s.root {
		return "/", true
	}
	rel, ok := strings.CutPrefix(host, s.root)
	if !ok || !strings.HasPrefix(rel, "/") {
		return "", false
	}
	return rel, true
}

// sudoUserName is the account that called the helper through sudo, when it is a valid user name.
func (s *sys) sudoUserName() string {
	if u := s.sudoUser(); helperproto.ValidUser(u) {
		return u
	}
	return ""
}
