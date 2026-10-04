//go:build linux

package main

import (
	"errors"
	"io"
	"io/fs"
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
	// oddID: glibc reads the uid or gid only as a signed, "+"-prefixed or clamped value (M1).
	oddID bool
}

const (
	passwdLimit   = 4 << 20
	nsswitchLimit = 64 << 10
	maxUsers      = 200 // spec §13.2
	nobodyUID     = 65534
)

// accounts reads /etc/passwd directly: the static helper has no NSS (R37 item 4).
func (s *sys) accounts() ([]account, error) {
	accts, _, err := s.passwd()
	return accts, err
}

// passwd reads the entries glibc's files module reads, because sshd looks accounts up through it
// (AUD-03, C1: an entry sshd accepts is never skipped without a word, and an entry glibc refuses
// never hides a later one): each line ends at its first NUL (glibc reads it as a C string; nul
// reports that the file has one), leading blanks are ignored, blank and "#" lines are skipped, a
// name starting with "+" or "-" is skipped (NIS compat syntax: glibc's files lookups never answer
// it), missing trailing fields are empty (an empty shell is /bin/sh), the shell is the rest of the
// line, and uid and gid are read like glibc's strtou32. A line glibc refuses (fewer than four
// fields, a uid or gid that is not a number) is no account and is skipped. Only glibc systems are
// supported (musl reads ids differently).
func (s *sys) passwd() (accts []account, nul bool, err error) {
	data, err := s.readRegular("/etc/passwd", passwdLimit)
	if err != nil {
		return nil, false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, 0); i >= 0 {
			line, nul = line[:i], true
		}
		line = strings.TrimLeft(line, " \t\v\f\r")
		if line == "" || line[0] == '#' || line[0] == '+' || line[0] == '-' {
			continue
		}
		f := strings.SplitN(line, ":", 7)
		if len(f) < 4 {
			continue
		}
		uid, plainUID, ok1 := parseID(f[2])
		gid, plainGID, ok2 := parseID(f[3])
		if !ok1 || !ok2 {
			continue
		}
		for len(f) < 7 {
			f = append(f, "")
		}
		accts = append(accts, account{name: f[0], uid: uid, gid: gid, home: f[5], shell: f[6], oddID: !plainUID || !plainGID})
	}
	return accts, nul, nil
}

// parseID reads a uid or gid field as glibc's files module does (strtou32: strtoul in base 10,
// leading blanks and one sign allowed, the whole field a number, a value above 2^32-1, also a
// negative one, read as 2^32-1). plain is false when the value is not what was written as a plain
// decimal number below 2^32-1 ((uid_t)-1): a sign, a "+", 32-bit overflow or 4294967295 (M1).
func parseID(field string) (id int, plain, ok bool) {
	s := strings.TrimLeft(field, " \t\n\v\f\r")
	signed := false
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		signed, neg, s = true, s[0] == '-', s[1:]
	}
	if s == "" {
		return 0, false, false
	}
	const maxID = 1<<32 - 1
	v := uint64(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false, false
		}
		if v <= maxID {
			v = v*10 + uint64(c-'0')
		}
	}
	if v > maxID || neg && v != 0 {
		return maxID, false, true
	}
	return int(v), !signed && v < maxID, true //nolint:gosec // G115: v <= 2^32-1 fits an int on every helper platform (64-bit)
}

// toScan selects the accounts whose keys are inventoried (spec §13.1): root, every other uid-0
// account and every normal account (uid >= 1000, not nobody) with an existing home and a login
// shell, and the account that runs the helper through sudo (alice-svc, a system account) so Alice's
// own key appears in the inventory. Only the first entry of a name counts, as for getpwnam and so
// for sshd; names are compared exactly ("John" and "john" are two accounts).
//
// unlisted names every entry that cannot be listed (AUD-03): a name outside ValidAccount or a uid
// or gid glibc reads only as a clamped or signed value (any entry: its keys could exist and the
// account list cannot name it reliably), or an account the rule would select whose home is not a
// path the helper accepts (CleanHome). Nothing is skipped silently. It holds at most
// helperproto.MaxUnlistedAccounts entries. Homes are reported cleaned.
//
// The rule, for the documentation: accounts with uid 1..999 (other than the sudo user), the uid
// 65534 (nobody), accounts whose shell ends in "/nologin" or "/false", and accounts whose cleaned
// home is not an existing directory are not inventoried and not reported, even where sshd could
// accept a key for them (for example through AuthorizedKeysFile /etc/ssh/keys/%u).
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
		if a.oddID {
			report(a.uid, helperproto.UnlistedID)
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

// localSources are the nsswitch passwd sources whose accounts the helper sees or that hold no
// login accounts with keys: files (/etc/passwd), systemd (dynamic service users; its userdb
// records are checked separately, userdbRecords) and mymachines (container users). Stock Debian,
// Ubuntu and RHEL configurations name only these besides sss.
var localSources = map[string]bool{"files": true, "systemd": true, "mymachines": true}

// maxUserdbEntries bounds the entries read from one userdb directory.
const maxUserdbEntries = 4096

// userdbDirs are systemd's userdb drop-in directories (and homed's identity directory) with the
// suffix of an account record there.
var userdbDirs = []struct{ dir, suffix string }{
	{"/etc/userdb", ".user"}, {"/run/userdb", ".user"}, {"/run/host/userdb", ".user"},
	{"/usr/local/lib/userdb", ".user"}, {"/usr/lib/userdb", ".user"}, {"/var/lib/systemd/home", ".identity"},
}

// directoryUsers reports whether accounts may come from a source the helper cannot list (I2, fix
// round 2). Whenever the helper cannot be sure that the passwd sources are only the local files it
// reads, the answer is true:
//   - nsswitch.conf is read through the root-controlled walk (a root's link, such as authselect's
//     /etc/nsswitch.conf, is followed; a link or directory others can change is refused) and must
//     be a regular file of root's that others cannot write, within nsswitchLimit; any failure,
//     also a missing or dangling file (what glibc then defaults to differs between versions), is
//     true;
//   - any passwd source other than localSources is true, also a token glibc would not take as a
//     source (a bare ":") and an action item in brackets that never ends; the database name is the
//     text up to the first blank or colon, as glibc reads it (blanks are space, tab, CR, VT and FF),
//     and every passwd line counts;
//   - with systemd as a source, any userdb account record (userdbRecords) is true.
func (s *sys) directoryUsers() bool {
	data, err := s.readNSSwitch()
	if err != nil {
		return true
	}
	nonLocal, systemd := passwdSources(string(data))
	if nonLocal {
		return true
	}
	return systemd && s.userdbRecords()
}

// readNSSwitch reads /etc/nsswitch.conf through the root-controlled walk.
func (s *sys) readNSSwitch() ([]byte, error) {
	rf, err := s.walkRoot("/etc/nsswitch.conf")
	if err != nil {
		return nil, err
	}
	defer rf.close()
	f, st, err := rf.openLinked(true) // only read: a second name of a root-owned file changes nothing
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if int(st.Uid) != s.rootUID || st.Mode&0o022 != 0 {
		return nil, errNotRootControlled
	}
	data, err := io.ReadAll(io.LimitReader(f, nsswitchLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > nsswitchLimit {
		return nil, errTooLarge
	}
	return data, nil
}

// nssBlanks are the characters glibc's nsswitch parser skips as blanks (isspace without newline).
const nssBlanks = " \t\r\v\f"

// passwdSources reads the sources of every passwd line: nonLocal when one is not in localSources,
// systemd when systemd is one. Blanks are nssBlanks wherever glibc skips them (N4b); a CR after an
// allowed source (a CRLF file) is a blank too.
func passwdSources(data string) (nonLocal, systemd bool) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimLeft(line, nssBlanks)
		if line == "" || line[0] == '#' {
			continue
		}
		end := strings.IndexAny(line, nssBlanks+":")
		if end < 0 || line[:end] != "passwd" {
			continue
		}
		rest := line[end:]
		if rest[0] == ':' {
			rest = rest[1:]
		}
		inAction := false
		for _, src := range strings.FieldsFunc(rest, func(r rune) bool { return strings.ContainsRune(nssBlanks, r) }) {
			switch {
			case inAction || strings.HasPrefix(src, "["):
				inAction = !strings.HasSuffix(src, "]")
			case src == "systemd":
				systemd = true
			case !localSources[src]:
				nonLocal = true
			}
		}
		if inAction {
			nonLocal = true // an action item that never ends: glibc's reading of the line is unclear
		}
	}
	return nonLocal, systemd
}

// userdbRecords reports whether systemd's userdb can serve an account the helper cannot see: an
// account record in a drop-in directory, or a systemd-homed identity. A missing directory has
// none; a directory others can change, a path that is not a directory, more than
// maxUserdbEntries entries or any other error counts as a record.
func (s *sys) userdbRecords() bool {
	for _, d := range userdbDirs {
		st, err := os.Stat(s.host(d.dir))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil || !st.IsDir() || !s.rootControlled(d.dir):
			return true
		}
		dir, err := os.Open(s.host(d.dir))
		if err != nil {
			return true
		}
		names, err := dir.Readdirnames(maxUserdbEntries + 1)
		_ = dir.Close()
		if err != nil && !errors.Is(err, io.EOF) || len(names) > maxUserdbEntries {
			return true
		}
		for _, n := range names {
			if strings.HasSuffix(n, d.suffix) {
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
		if _, ok := m[a.uid]; ok || strings.HasPrefix(a.name, "+") || strings.HasPrefix(a.name, "-") {
			continue // the first entry wins; getpwuid never answers a NIS-compat entry (M2)
		}
		m[a.uid] = ""
		if helperproto.ValidAccount(a.name) {
			m[a.uid] = a.name
		}
	}
	return m
}
