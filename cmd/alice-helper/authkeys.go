//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/sshdconf"
)

// candidate is one authorized_keys file the helper may read or write (spec §13.3 step 2).
type candidate struct {
	acct account
	path string // the expanded path, as listed to Alice and as Alice names it
	real string // the path after resolving symlinks (missing trailing elements kept)
	dir  string // the resolved directory real must stay in: the home, or the directory of an absolute pattern
}

// scanItem is one expanded AuthorizedKeysFile entry: a candidate, or (ok false) a path that is a
// valid helper path but is refused (it leaves its directory).
type scanItem struct {
	path string
	c    candidate
	ok   bool
}

type userScan struct {
	acct       account
	items      []scanItem
	command    string // the user's effective AuthorizedKeysCommand
	unreadable bool   // "sshd -T -C user=…" failed for this user
}

type scanResult struct {
	users    []userScan
	warnings []string
	command  string
	owners   map[int]string
}

func (r *scanResult) warn(code string) {
	if !slices.Contains(r.warnings, code) {
		r.warnings = append(r.warnings, code)
	}
}

// find returns the candidate whose listed path is exactly path.
func (r scanResult) find(path string) (candidate, bool) {
	for _, u := range r.users {
		for _, it := range u.items {
			if it.ok && it.path == path {
				return it.c, true
			}
		}
	}
	return candidate{}, false
}

// scan computes every candidate file from /etc/passwd and sshd -T. It is the only source of
// paths for authkeys-read and authkeys-write: a path from the caller is only ever compared to it.
// The files themselves are opened later through openCandidate, which re-checks containment.
func (s *sys) scan(ctx context.Context) (scanResult, error) {
	accts, err := s.accounts()
	if err != nil {
		return scanResult{}, failed(helperproto.CodeIOError, "cannot read /etc/passwd")
	}
	r := scanResult{warnings: []string{}, owners: owners(accts)}
	global, _, gerr := s.sshdConfig(ctx)
	if gerr != nil {
		global = sshdconf.Config{AuthorizedKeysFile: sshdconf.DefaultAuthorizedKeysFile, AuthorizedKeysCommand: "none"}
		r.warn(helperproto.WarnSSHDUnreadable)
	}
	r.command = global.AuthorizedKeysCommand
	if s.directoryUsers() {
		r.warn(helperproto.WarnDirectoryUsers)
	}
	selected, truncated := s.toScan(accts)
	if truncated {
		r.warn(helperproto.WarnTooManyUsers)
	}
	for _, a := range selected {
		cfg := global
		us := userScan{acct: a}
		if gerr == nil {
			uc, _, err := s.sshdConfig(ctx, "-C", "user="+a.name+",host=localhost,addr=127.0.0.1")
			if err != nil {
				us.unreadable = true
				r.warn(helperproto.WarnSSHDUnreadable)
			} else {
				cfg = uc
			}
		}
		us.command = cfg.AuthorizedKeysCommand
		for _, pattern := range cfg.AuthorizedKeysFile {
			p, c, valid, ok := s.candidateFor(a, pattern)
			switch {
			case !valid:
				r.warn(helperproto.WarnUnsupportedPath)
				continue
			case slices.ContainsFunc(us.items, func(x scanItem) bool { return x.path == p }):
				continue
			}
			us.items = append(us.items, scanItem{path: p, c: c, ok: ok})
		}
		r.users = append(r.users, us)
	}
	return r, nil
}

// candidateFor expands one AuthorizedKeysFile pattern for a. valid reports that the expansion is a
// valid helper path (p); ok that it is also a candidate: after resolving symlinks it must stay inside the user's home, or inside the directory
// of an absolute pattern (/etc/ssh/keys/%u stays in /etc/ssh/keys).
func (s *sys) candidateFor(a account, pattern string) (p string, c candidate, valid, ok bool) {
	p, err := sshdconf.Expand(pattern, a.name, a.home, a.uid)
	if err != nil || !helperproto.ValidPath(p) {
		return "", candidate{}, false, false
	}
	allowed := a.home
	if strings.HasPrefix(pattern, "/") {
		allowed = filepath.Dir(p)
	}
	dir, found := s.resolveNearest(allowed)
	if !found {
		return p, candidate{}, true, false
	}
	real, found := s.resolveNearest(p)
	if !found || !within(real, dir) {
		return p, candidate{}, true, false
	}
	return p, candidate{acct: a, path: p, real: real, dir: dir}, true, true
}

func cmdAuthKeysList(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "authkeys-list takes no arguments")
	}
	s.syslog(helperproto.SubAuthKeysList, "")
	r, err := s.scan(ctx)
	if err != nil {
		return nil, err
	}
	resp := helperproto.AuthKeysListResponse{OK: true, Users: []helperproto.UserFiles{}, AuthorizedKeysCommand: r.command, Warnings: r.warnings}
	for _, u := range r.users {
		uf := helperproto.UserFiles{User: u.acct.name, UID: u.acct.uid, Home: u.acct.home, Files: []helperproto.FileInfo{},
			SSHDUnreadable: u.unreadable, AuthorizedKeysCommand: u.command}
		for _, it := range u.items {
			if !it.ok {
				uf.Files = append(uf.Files, helperproto.FileInfo{Path: it.path, Exists: true, Unsupported: true})
				continue
			}
			uf.Files = append(uf.Files, s.fileInfo(it.c, r.owners))
		}
		resp.Users = append(resp.Users, uf)
	}
	return resp, nil
}

// fileInfo describes a candidate without returning its content. Everything comes from one opened
// descriptor (fstat), never from a second look at the path.
func (s *sys) fileInfo(c candidate, names map[int]string) helperproto.FileInfo {
	fi := helperproto.FileInfo{Path: c.path}
	f, err := s.openCandidate(c)
	if errors.Is(err, fs.ErrNotExist) {
		fi.StrictModesOK = s.strictModes(c, nil)
		return fi
	}
	if err != nil {
		fi.Exists, fi.Unsupported = true, true
		return fi
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		fi.Exists, fi.Unsupported = true, true
		return fi
	}
	fi.Exists, fi.Size, fi.Mode = true, st.Size(), fmt.Sprintf("%04o", st.Mode().Perm())
	uid, _ := owner(st)
	fi.Owner = names[uid]
	if fi.Owner == "" {
		fi.Owner = strconv.Itoa(uid)
	}
	if fileOK(st, c.acct) != nil {
		fi.Unsupported = true
		return fi
	}
	if st.Size() > helperproto.MaxAuthorizedKeysSize {
		fi.TooLarge = true
	} else if data, err := io.ReadAll(io.LimitReader(f, helperproto.MaxAuthorizedKeysSize+1)); err == nil && len(data) <= helperproto.MaxAuthorizedKeysSize {
		fi.SHA256 = hexSHA(data)
	}
	fi.StrictModesOK = s.strictModes(c, st)
	return fi
}

// strictModes mirrors sshd's StrictModes: the file and every existing directory from it up to
// the allowed directory are owned by the user or root and not writable by group or others.
func (s *sys) strictModes(c candidate, file fs.FileInfo) bool {
	ok := func(st fs.FileInfo) bool {
		uid, _ := owner(st)
		return st.Mode().Perm()&0o022 == 0 && (uid == c.acct.uid || uid == 0)
	}
	if file != nil && !ok(file) {
		return false
	}
	for d := filepath.Dir(c.real); within(d, c.dir); d = filepath.Dir(d) {
		if st, err := os.Stat(s.host(d)); err == nil && !ok(st) {
			return false
		}
		if d == c.dir || d == "/" {
			break
		}
	}
	return true
}

func cmdAuthKeysRead(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 1 {
		return nil, refused(helperproto.CodeUsage, "usage: authkeys-read <path>")
	}
	path := args[0]
	if !helperproto.ValidPath(path) {
		return nil, refused(helperproto.CodeInvalidArgument, "the path is not allowed")
	}
	s.syslog(helperproto.SubAuthKeysRead, path)
	r, err := s.scan(ctx)
	if err != nil {
		return nil, err
	}
	c, ok := r.find(path)
	if !ok {
		return nil, refused(helperproto.CodePathNotAllowed, "the path is not an authorized_keys file of a listed user")
	}
	data, err := s.readCandidate(c)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, precondition(helperproto.CodeNotFound, "the file does not exist")
	case errors.Is(err, errTooLarge):
		return nil, refused(helperproto.CodeTooLarge, "the file is too large")
	case errors.Is(err, errEscaped):
		return nil, refused(helperproto.CodePathNotAllowed, "the path leaves its allowed directory")
	case errors.Is(err, errUnsafe):
		return nil, refused(helperproto.CodeUnsafeFile, "the file is hard-linked or owned by another user")
	case errors.Is(err, errNotRegular), errors.Is(err, syscall.ELOOP):
		return nil, refused(helperproto.CodeNotRegularFile, "the path is not a regular file")
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "the file cannot be read")
	}
	return helperproto.AuthKeysReadResponse{OK: true, Path: path, SHA256: hexSHA(data), ContentB64: base64.StdEncoding.EncodeToString(data)}, nil
}
