//go:build linux

package main

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"alice/internal/providers/linuxssh/helperproto"
)

// account is one /etc/passwd entry.
type account struct {
	name        string
	uid, gid    int
	home, shell string
}

const (
	passwdLimit   = 4 << 20
	nsswitchLimit = 64 << 10
	maxUsers      = 200 // spec §13.2
	nobodyUID     = 65534
)

// accounts reads /etc/passwd directly: the static helper has no NSS (R37 item 4). It reads the
// entries glibc's files module reads, because sshd looks accounts up through it (AUD-03: an entry
// sshd accepts is never skipped without a word): leading blanks are ignored, blank and "#" lines
// are skipped, missing trailing fields are empty (an empty shell is /bin/sh), the shell is the
// rest of the line, and uid and gid are read like glibc's strtou32. A line glibc refuses (fewer
// than four fields, a uid or gid that is not a number) is no account for sshd either and is
// skipped.
func (s *sys) accounts() ([]account, error) {
	data, err := s.readRegular("/etc/passwd", passwdLimit)
	if err != nil {
		return nil, err
	}
	var out []account
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimLeft(line, " \t\v\f\r")
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.SplitN(line, ":", 7)
		if len(f) < 4 {
			continue
		}
		uid, ok1 := parseID(f[2])
		gid, ok2 := parseID(f[3])
		if !ok1 || !ok2 {
			continue
		}
		for len(f) < 7 {
			f = append(f, "")
		}
		out = append(out, account{name: f[0], uid: uid, gid: gid, home: f[5], shell: f[6]})
	}
	return out, nil
}

// parseID reads a uid or gid field as glibc's files module does (strtou32: strtoul in base 10,
// leading blanks and one sign allowed, the whole field a number, a value above 2^32-1, also a
// negative one, read as 2^32-1).
func parseID(field string) (int, bool) {
	s := strings.TrimLeft(field, " \t\n\v\f\r")
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg, s = s[0] == '-', s[1:]
	}
	if s == "" {
		return 0, false
	}
	const maxID = 1<<32 - 1
	v := uint64(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		if v <= maxID {
			v = v*10 + uint64(c-'0')
		}
	}
	switch {
	case v > maxID, neg && v != 0:
		return maxID, true
	}
	return int(v), true //nolint:gosec // G115: v <= 2^32-1 fits an int on every helper platform (64-bit)
}

// toScan selects the accounts whose keys are inventoried (spec §13.1): root, every other uid-0
// account and every normal account (uid >= 1000, not nobody) with an existing home and a login
// shell, and the account that runs the helper through sudo (alice-svc, a system account) so Alice's
// own key appears in the inventory. Only the first entry of a name counts, as for getpwnam and so
// for sshd; names are compared exactly ("John" and "john" are two accounts).
//
// unlisted names every entry that cannot be listed (AUD-03): a name outside ValidAccount (any
// entry: its keys could exist and the account list cannot name it), or an account the rule would
// select whose home is not a path the helper accepts (CleanHome). Nothing is skipped silently. It
// holds at most helperproto.MaxUnlistedAccounts entries. Homes are reported cleaned.
func (s *sys) toScan(accts []account) (out []account, unlisted []helperproto.UnlistedAccount, truncated bool) {
	sudo := s.sudoUserName()
	seen := map[string]bool{}
	report := func(uid int, reason string) {
		if len(unlisted) < helperproto.MaxUnlistedAccounts {
			unlisted = append(unlisted, helperproto.UnlistedAccount{UID: uid, Reason: reason})
		}
	}
	for _, a := range accts {
		if seen[a.name] {
			continue
		}
		seen[a.name] = true
		if !helperproto.ValidAccount(a.name) {
			report(a.uid, helperproto.UnlistedName)
			continue
		}
		isRoot, isSudo := a.name == "root" && a.uid == 0, sudo != "" && a.name == sudo
		normal := a.uid == 0 || (a.uid >= 1000 && a.uid != nobodyUID)
		if !isRoot && !isSudo && (!normal || !loginShell(a.shell)) {
			continue
		}
		home, ok := helperproto.CleanHome(a.home)
		if !ok {
			report(a.uid, helperproto.UnlistedHome)
			continue
		}
		a.home = home
		if !isRoot && !isSudo && !s.isDir(a.home) {
			continue
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].uid != out[j].uid {
			return out[i].uid < out[j].uid
		}
		return out[i].name < out[j].name
	})
	if len(out) > maxUsers {
		return out[:maxUsers], unlisted, true
	}
	return out, unlisted, false
}

// loginShell reports whether an account can sign in with its shell field. An empty field is /bin/sh
// for sshd and login (passwd(5)).
func loginShell(shell string) bool {
	return !strings.HasSuffix(shell, "/nologin") && !strings.HasSuffix(shell, "/false")
}

// accountNames returns every ValidAccount name, sorted and deduplicated, at most
// helperproto.MaxAccountNames (never nil); fits is false when there were more.
func accountNames(accts []account) (names []string, fits bool) {
	seen := map[string]bool{}
	names = []string{}
	for _, a := range accts {
		if helperproto.ValidAccount(a.name) && !seen[a.name] {
			seen[a.name] = true
			names = append(names, a.name)
		}
	}
	sort.Strings(names)
	if len(names) > helperproto.MaxAccountNames {
		return names[:helperproto.MaxAccountNames], false
	}
	return names, true
}

func (s *sys) isDir(guest string) bool {
	st, err := os.Stat(s.host(guest))
	return err == nil && st.IsDir()
}

// directoryUsers reports whether accounts may come from a directory service the helper cannot list.
func (s *sys) directoryUsers() bool {
	data, err := s.readRegular("/etc/nsswitch.conf", nsswitchLimit)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "passwd:")
		if !ok {
			continue
		}
		for _, src := range strings.Fields(rest) {
			if src == "ldap" || src == "sss" {
				return true
			}
		}
	}
	return false
}

// groupNames maps gids to the names in /etc/group (the first entry wins, as for getgrgid); empty
// when the file cannot be read. A gid whose first name is not a ValidAccount maps to "": it is
// reported as a number (S6: a name leaves the server only when it passes the account rule).
func (s *sys) groupNames() map[int]string {
	m := map[int]string{}
	data, err := s.readRegular("/etc/group", passwdLimit)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) != 4 {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if _, seen := m[gid]; err != nil || gid < 0 || seen {
			continue
		}
		m[gid] = ""
		if helperproto.ValidAccount(f[0]) {
			m[gid] = f[0]
		}
	}
	return m
}

// owners maps uids to account names (the first entry wins, as for getpwuid). A uid whose first
// name is not a ValidAccount maps to "": the owner is then reported as its uid (S6).
func owners(accts []account) map[int]string {
	m := map[int]string{}
	for _, a := range accts {
		if _, ok := m[a.uid]; ok {
			continue
		}
		m[a.uid] = ""
		if helperproto.ValidAccount(a.name) {
			m[a.uid] = a.name
		}
	}
	return m
}
