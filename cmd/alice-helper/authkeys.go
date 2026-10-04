//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	names    []string // every valid account name (accountNames)
	namesFit bool     // names holds every account name
	unlisted []helperproto.UnlistedAccount
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
	r.names, r.namesFit = accountNames(accts)
	global, _, gerr := s.sshdConfig(ctx)
	if gerr != nil {
		global = sshdconf.Config{AuthorizedKeysFile: sshdconf.DefaultAuthorizedKeysFile, AuthorizedKeysCommand: "none"}
		r.warn(helperproto.WarnSSHDUnreadable)
	}
	r.command = global.AuthorizedKeysCommand
	if s.directoryUsers() {
		r.warn(helperproto.WarnDirectoryUsers)
	}
	selected, unlisted, truncated := s.toScan(accts)
	r.unlisted = unlisted
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
	switch {
	case !found:
		return p, candidate{}, true, false
	case inHome && !s.homeTrusted(a, home, dir):
		return p, candidate{}, true, false
	case !inHome && (dir != allowed || !s.rootControlled(allowed)):
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

// homeTrusted decides whether the home of a (home as in /etc/passwd, resolved its resolved form)
// may hold candidates. The directories above the home must be root-controlled (rootControlled,
// which accepts root's own symlinks into root-controlled directories, such as /home -> var/home),
// or another user could swap the home between the scan and the open; standard /home/<u>, /root
// and /var/lib/<x> layouts are. When the home itself is a symlink, the directory it resolves to must
// belong to the account (root excepted) and sit in a root-controlled directory: a user who can
// write the directory of someone's home could otherwise point it at /root, and re-basing on the
// resolved home would hide the symlink from throughOK (re-review item 1).
//
// The owner of a home that is not a symlink is not checked, as sshd does not: whatever it holds,
// files are only taken from inside it (containment), must be the user's or root's in a
// root-controlled directory (fileOK), must have one link (no hard link to another file), and a
// symlink inside it only leads into a directory of the user (throughOK).
func (s *sys) homeTrusted(a account, home, resolved string) bool {
	if home == "/" {
		return true
	}
	parent := filepath.Dir(home)
	if !s.rootControlled(parent) {
		return false
	}
	if rp, ok := s.resolveNearest(parent); ok && filepath.Join(rp, filepath.Base(home)) == resolved {
		return true // only root-controlled ancestors are symlinks; the home itself is not
	}
	if resolved != "/" && !s.rootControlled(filepath.Dir(resolved)) {
		return false
	}
	st, err := os.Lstat(s.host(resolved))
	if err != nil || !st.IsDir() {
		return false
	}
	uid, _ := owner(st)
	return a.uid == 0 || uid == a.uid
}

// maxRootLinks bounds the symlinks rootControlled follows (a loop is refused, not followed).
const maxRootLinks = 40

// rootControlled reports whether nobody but root can change the guest directory dir or any
// directory above it, so nothing can be swapped between the scan and the open. It walks from "/"
// down: every existing component must be a directory owned by root that group and others cannot
// write, or a symlink owned by root (its directory was checked before it), in which case the walk
// starts again on the path it leads to, whose components must pass the same test (at most
// maxRootLinks links). A link target with a ".." component is refused: cleaning it as text would
// check another path than the kernel opens (it follows an earlier link first), and no legitimate
// layout (/home -> var/home, /home -> /data/home) needs one. Missing trailing components are
// allowed (the write then fails with NOT_FOUND: only <home>/.ssh is ever created), but the path
// checked must be the one resolveNearest (and so the open) uses, or the answer is false.
func (s *sys) rootControlled(dir string) bool {
	ok := func(st fs.FileInfo) bool {
		uid, _ := owner(st)
		return uid == s.rootUID
	}
	path := filepath.Clean(dir)
	links := 0
restart:
	st, err := os.Lstat(s.host("/"))
	if err != nil || !ok(st) || st.Mode().Perm()&0o022 != 0 {
		return false
	}
	cur := "/"
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, c := range parts {
		if c == "" {
			continue
		}
		next := filepath.Join(cur, c)
		st, err := os.Lstat(s.host(next))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return s.sameResolved(dir, filepath.Join(append([]string{cur}, parts[i:]...)...))
		case err != nil || !ok(st):
			return false
		case st.Mode()&fs.ModeSymlink != 0:
			links++
			target, err := os.Readlink(s.host(next))
			if err != nil || links > maxRootLinks || slices.Contains(strings.Split(target, "/"), "..") {
				return false
			}
			if filepath.IsAbs(target) {
				g, inRoot := s.guest(filepath.Clean(target))
				if !inRoot {
					return false
				}
				target = g
			} else {
				target = filepath.Join(cur, target)
			}
			path = filepath.Join(append([]string{target}, parts[i+1:]...)...)
			goto restart
		case !st.IsDir() || st.Mode().Perm()&0o022 != 0:
			return false
		}
		cur = next
	}
	return s.sameResolved(dir, cur)
}

// sameResolved reports whether the guest path dir resolves (as resolveNearest and the open see
// it) to checked, the path rootControlled walked.
func (s *sys) sameResolved(dir, checked string) bool {
	r, ok := s.resolveNearest(dir)
	return ok && r == checked
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
	resp := helperproto.AuthKeysListResponse{OK: true, Users: []helperproto.UserFiles{}, AuthorizedKeysCommand: r.command, Warnings: r.warnings,
		Accounts: r.names, AccountsComplete: r.namesFit && !slices.Contains(r.warnings, helperproto.WarnTooManyUsers) &&
			!slices.Contains(r.warnings, helperproto.WarnDirectoryUsers) && len(r.unlisted) == 0,
		Unlisted: append([]helperproto.UnlistedAccount{}, r.unlisted...)}
	if resp.Accounts == nil {
		resp.Accounts = []string{}
	}
	inline := helperproto.MaxListInline // AUD-22: raw bytes of file content the answer still carries
	for _, u := range r.users {
		uf := helperproto.UserFiles{User: u.acct.name, UID: u.acct.uid, Home: u.acct.home, Files: []helperproto.FileInfo{},
			SSHDUnreadable: u.unreadable, AuthorizedKeysCommand: u.command}
		for _, it := range u.items {
			if !it.ok {
				uf.Files = append(uf.Files, helperproto.FileInfo{Path: it.path, Exists: true, Unsupported: true})
				continue
			}
			uf.Files = append(uf.Files, s.fileInfo(it.c, r.owners, &inline))
		}
		resp.Users = append(resp.Users, uf)
	}
	return fitList(resp), nil
}

// fitList keeps the whole answer, its newline included, within helperproto.MaxListOutput (S8), so
// a large but legal configuration never makes Alice's read fail: first files give up their inline
// content, the last listed first (Alice reads them with authkeys-read; their hash stays); then
// users are left out from the end (the highest uids), and finally the account names; the answer
// then says Truncated and the account list is not complete. Every round gives something up, so it
// ends.
func fitList(resp helperproto.AuthKeysListResponse) helperproto.AuthKeysListResponse {
	for {
		b, err := json.Marshal(resp)
		if err != nil {
			return resp // writeJSON answers IO_ERROR for an answer it cannot encode
		}
		excess := len(b) + 1 - helperproto.MaxListOutput
		if excess <= 0 {
			return resp
		}
		if dropInline(&resp, excess) {
			continue
		}
		resp.Truncated, resp.AccountsComplete = true, false
		if n := len(resp.Users); n > 0 {
			freed := 0
			for n > 0 && freed < excess {
				u, _ := json.Marshal(resp.Users[n-1])
				freed += len(u) + 1
				n--
			}
			resp.Users = resp.Users[:n]
			continue
		}
		if len(resp.Accounts) == 0 {
			return resp
		}
		resp.Accounts = []string{}
	}
}

// dropInline removes the inline content of the last listed files until at least excess bytes of
// the encoded answer are freed (or none is left); it reports whether it removed any.
func dropInline(resp *helperproto.AuthKeysListResponse, excess int) bool {
	freed, dropped := 0, false
	for i := len(resp.Users) - 1; i >= 0 && freed < excess; i-- {
		files := resp.Users[i].Files
		for j := len(files) - 1; j >= 0 && freed < excess; j-- {
			if !files[j].Inline {
				continue
			}
			// `,"content_b64":"…"` goes; `"inline":true` becomes `"inline":false` (one byte more).
			freed += len(files[j].ContentB64) + len(`,"content_b64":""`) - 1
			files[j].Inline, files[j].ContentB64 = false, ""
			dropped = true
		}
	}
	return dropped
}

// fileInfo describes a candidate. Everything comes from one opened descriptor (fstat), never from
// a second look at the path. With inline (protocol 6, AUD-22) the content the helper read for the
// hash is returned too while it fits the remaining budget *inline: the same descriptor, checks and
// bytes authkeys-read would use (readCandidate), so it changes no trust decision.
func (s *sys) fileInfo(c candidate, names map[int]string, inline *int) helperproto.FileInfo {
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
		if inline != nil && len(data) <= *inline {
			fi.Inline, fi.ContentB64 = true, base64.StdEncoding.EncodeToString(data)
			*inline -= len(data)
		}
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
