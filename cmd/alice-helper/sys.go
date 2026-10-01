//go:build linux

package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
)

// sys is everything the helper touches outside its own memory. Paths inside the helper are
// "guest" paths (as on the server); host turns them into real paths under root, so tests can run
// every subcommand against a temporary directory as an unprivileged user.
type sys struct {
	root     string // filesystem prefix: "" in production, a temporary directory in tests
	euid     func() int
	sudoUser func() string
	now      func() time.Time
	runSSHD  func(ctx context.Context, args ...string) ([]byte, error)
	stdin    io.Reader
	stdout   io.Writer
	syslog   func(subcommand, path string)
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
