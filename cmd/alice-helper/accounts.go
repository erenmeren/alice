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

// accounts reads /etc/passwd directly: the static helper has no NSS (R37 item 4). Malformed lines
// are skipped.
func (s *sys) accounts() ([]account, error) {
	data, err := s.readRegular("/etc/passwd", passwdLimit)
	if err != nil {
		return nil, err
	}
	var out []account
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) != 7 {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || uid < 0 || gid < 0 {
			continue
		}
		out = append(out, account{name: f[0], uid: uid, gid: gid, home: f[5], shell: f[6]})
	}
	return out, nil
}

// toScan selects the accounts whose keys are inventoried (spec §13.1): root, every normal account
// (uid >= 1000, not nobody) with an existing home and a login shell, and the account that runs the
// helper through sudo (alice-svc, a system account) so Alice's own key appears in the inventory.
func (s *sys) toScan(accts []account) []account {
	sudo := s.sudoUserName()
	seen := map[string]bool{}
	var out []account
	for _, a := range accts {
		if seen[a.name] || !helperproto.ValidUser(a.name) || !helperproto.ValidPath(a.home) {
			continue
		}
		ok := (a.name == "root" && a.uid == 0) || (sudo != "" && a.name == sudo) ||
			(a.uid >= 1000 && a.uid != nobodyUID && loginShell(a.shell) && s.isDir(a.home))
		if !ok {
			continue
		}
		seen[a.name] = true
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].uid != out[j].uid {
			return out[i].uid < out[j].uid
		}
		return out[i].name < out[j].name
	})
	if len(out) > maxUsers {
		out = out[:maxUsers]
	}
	return out
}

func loginShell(shell string) bool {
	return shell != "" && !strings.HasSuffix(shell, "/nologin") && !strings.HasSuffix(shell, "/false")
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

// owners maps uids to account names (the first entry wins).
func owners(accts []account) map[int]string {
	m := map[int]string{}
	for _, a := range accts {
		if _, ok := m[a.uid]; !ok {
			m[a.uid] = a.name
		}
	}
	return m
}
