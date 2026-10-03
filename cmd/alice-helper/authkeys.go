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
	"syscall"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/sshdconf"
)

// candidate is one authorized_keys file the helper may read or write (spec §13.3 step 2).
type candidate struct {
	acct account
	path string // the expanded path, as listed to Alice and as Alice names it
	real string // the path after resolving symlinks (missing trailing elements kept)
	dir  string // the resolved directory real must stay in: the home, or the directory of an absolute pattern
	// inHome is true when path lies in the user's home (whatever the pattern looked like): dir is
	// then the resolved home, a missing .ssh may be created and StrictModes stops at the home.
	inHome bool
	// through is true when the scan reached the file through a symlink below dir (real differs
	// from path rebased on dir). Opening then follows symlinks beneath dir, and for a user other
	// than root the directory that really holds the file must be the user's (throughOK).
	through bool
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
		us := userScan{acct: a, unreadable: gerr != nil}
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
// valid helper path (p); ok that it is also a candidate (A-1 of the final review):
//   - a path that lies in the user's home, from a relative pattern or an absolute one such as
//     /home/%u/.ssh/authorized_keys, must stay inside the resolved home after resolving symlinks;
//   - any other path (an absolute pattern such as /etc/ssh/keys/%u) must sit in a directory that is
//     not reached through a symlink and whose existing components are all root's and not writable
//     by group or others (rootControlled), and must stay inside that directory.
//
// The home rule is decided lexically first: a user who replaces ~/.ssh by a symlink to /root/.ssh
// never turns an absolute pattern into "a directory of its own" whose containment passes trivially.
func (s *sys) candidateFor(a account, pattern string) (p string, c candidate, valid, ok bool) {
	p, err := sshdconf.Expand(pattern, a.name, a.home, a.uid)
	if err != nil || !helperproto.ValidPath(p) {
		return "", candidate{}, false, false
	}
	home := filepath.Clean(a.home)
	inHome := within(p, home)
	allowed := home
	if !inHome {
		allowed = filepath.Dir(p)
	}
	dir, found := s.resolveNearest(allowed)
	if !found || (!inHome && (dir != allowed || !s.rootControlled(allowed))) {
		return p, candidate{}, true, false
	}
	real, found := s.resolveNearest(p)
	if !found || !within(real, dir) {
		return p, candidate{}, true, false
	}
	rel, err := filepath.Rel(allowed, p)
	if err != nil {
		return p, candidate{}, true, false
	}
	through := real != filepath.Join(dir, rel)
	return p, candidate{acct: a, path: p, real: real, dir: dir, inHome: inHome, through: through}, true, true
}

// rootControlled reports whether every existing component of the guest directory dir, from dir
// up to "/", is a directory owned by root that group and others cannot write: nobody but root can
// then swap a component between the scan and the open. Missing trailing components are allowed
// (the write then fails with NOT_FOUND: only <home>/.ssh is ever created).
func (s *sys) rootControlled(dir string) bool {
	for d := dir; ; d = filepath.Dir(d) {
		st, err := os.Lstat(s.host(d))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil || !st.IsDir():
			return false
		default:
			uid, _ := owner(st)
			if uid != s.rootUID || st.Mode().Perm()&0o022 != 0 {
				return false
			}
		}
		if d == "/" {
			return true
		}
	}
}

// throughOK refuses a file of a user other than root that the scan reached through a symlink
// when the directory that really holds it (parent, from fstat of the opened directory) is not the
// user's: a link the user planted must not make root read or rewrite a file in a directory root
// or another user controls (A-1). It applies to reads, listings and writes alike.
func throughOK(c candidate, parent unix.Stat_t) error {
	if !c.through || c.acct.uid == 0 || int(parent.Uid) == c.acct.uid {
		return nil
	}
	return errUnsafe
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
	f, parent, err := s.openCandidate(c)
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
	if fileOK(st, parent, c.acct) != nil {
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
	return helperproto.AuthKeysReadResponse{OK: true, Path: path, SHA256: hexSHA(data), ContentB64: base64.StdEncoding.EncodeToString(data), Owner: c.acct.name}, nil
}
