//go:build linux

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

func listedUsers(m map[string]any) []string {
	var users []string
	for _, u := range m["users"].([]any) {
		users = append(users, u.(map[string]any)["user"].(string))
	}
	return users
}

// withKeys gives a guest home a .ssh/authorized_keys with one line naming who.
func (f *fixture) withKeys(home, who string) string {
	f.t.Helper()
	f.mkdir(home, 0o755)
	f.mkdir(home+"/.ssh", 0o700)
	content := "ssh-ed25519 AAAA " + who + "\n"
	f.write(home+"/.ssh/authorized_keys", content, 0o600)
	return content
}

// AUD-03 (from the audit's PoC 1 and 1b): names that Linux and sshd accept but the old pattern
// refused (a dot, a capital letter, a Samba "$") and a home written with a trailing slash are
// listed with their files, and the list is complete.
func TestAccountsOutsideTheOldGrammarAreListed(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/etc/passwd", strings.Replace(f.read("/etc/passwd"), "Bad Name:x:1004:1004::/home/deploy:/bin/bash\n", "", 1), 0o644)
	var passwd strings.Builder
	passwd.WriteString(f.read("/etc/passwd"))
	for _, n := range []string{"john.doe", "Deploy2", "trail", "svc$", "a..b"} {
		f.withKeys("/home/"+strings.TrimSuffix(n, "$"), n+"@laptop")
	}
	fmt.Fprintf(&passwd, "john.doe:x:%d:%d::/home/john.doe:/bin/bash\n", f.uid, f.uid)
	fmt.Fprintf(&passwd, "Deploy2:x:%d:%d::/home/Deploy2:/bin/bash\n", f.uid, f.uid)
	fmt.Fprintf(&passwd, "trail:x:%d:%d::/home/trail/:/bin/bash\n", f.uid, f.uid)
	fmt.Fprintf(&passwd, "svc$:x:%d:%d::/home/svc:/bin/bash\n", f.uid, f.uid)
	fmt.Fprintf(&passwd, "a..b:x:%d:%d::/home/a..b:/bin/bash\n", f.uid, f.uid)
	fmt.Fprintf(&passwd, "WS01$:x:%d:%d::/nonexistent:/usr/sbin/nologin\n", f.uid+1, f.uid+1)
	f.write("/etc/passwd", passwd.String(), 0o644)

	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code, "%v", m)
	users := listedUsers(m)
	assert.Subset(t, users, []string{"john.doe", "Deploy2", "trail", "svc$", "a..b"})
	assert.Equal(t, "/home/trail", listUser(t, m, "trail")["home"], "the home is cleaned")
	assert.Equal(t, "/home/trail/.ssh/authorized_keys", filesOf(listUser(t, m, "trail"))[0]["path"])
	for _, n := range []string{"john.doe", "Deploy2", "trail", "svc$", "a..b"} {
		fi := filesOf(listUser(t, m, n))[0]
		assert.Equal(t, true, fi["exists"], n)
		assert.Equal(t, true, fi["inline"], n)
	}
	assert.Equal(t, []any{}, m["unlisted"])
	assert.Equal(t, []any{}, m["warnings"])
	assert.Equal(t, true, m["accounts_complete"])
	assert.Subset(t, m["accounts"], []any{"Deploy2", "WS01$", "john.doe", "trail", "svc$", "a..b"})

	code, r := f.run("authkeys-read", "/home/john.doe/.ssh/authorized_keys")
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, "john.doe", r["owner"])
	code, r = f.run("authkeys-read", "/home/trail/.ssh/authorized_keys")
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, "trail", r["owner"])
	code, r = f.run("authkeys-read", "/home/svc/.ssh/authorized_keys")
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, "svc$", r["owner"])
}

// AUD-03: an entry the helper cannot list is reported with its uid and reason, and the account
// list is incomplete. Nothing is silent, and the name of such an entry never leaves the server.
func TestUnlistedAccountsAreReportedNeverSilent(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/etc/passwd", f.read("/etc/passwd")+
		"bad,name:x:1009:1009::/home/deploy:/bin/bash\n"+
		"dotdot:x:1010:1010::/home/x/../dotdot:/bin/bash\n"+
		"relhome:x:1011:1011::home/relhome:/bin/bash\n"+
		"emptyhome:x:1012:1012:::/bin/bash\n"+
		"spacehome:x:1013:1013::/home/a b:/bin/bash\n"+
		".dot:x:1014:1014::/home/deploy:/usr/sbin/nologin\n"+ // a system account: its name is still reported
		"\x1b[31mred:x:1015:1015::/home/deploy:/bin/bash\n"+
		"kullanıcı:x:1016:1016::/home/deploy:/bin/bash\n"+
		strings.Repeat("n", 33)+":x:1017:1017::/home/deploy:/bin/bash\n"+
		"12345:x:1018:1018::/home/deploy:/bin/bash\n"+
		"svc:x:500:500::home/svc:/usr/sbin/nologin\n", 0o644) // never scanned: a bad home does not matter
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code, "%v", m)
	assert.ElementsMatch(t, []any{
		map[string]any{"uid": 1004.0, "reason": "name"}, // "Bad Name" of the base fixture
		map[string]any{"uid": 1009.0, "reason": "name"},
		map[string]any{"uid": 1010.0, "reason": "home"},
		map[string]any{"uid": 1011.0, "reason": "home"},
		map[string]any{"uid": 1012.0, "reason": "home"},
		map[string]any{"uid": 1013.0, "reason": "home"},
		map[string]any{"uid": 1014.0, "reason": "name"},
		map[string]any{"uid": 1015.0, "reason": "name"},
		map[string]any{"uid": 1016.0, "reason": "name"},
		map[string]any{"uid": 1017.0, "reason": "name"},
		map[string]any{"uid": 1018.0, "reason": "name"},
	}, m["unlisted"])
	assert.Equal(t, false, m["accounts_complete"])
	assert.Equal(t, []any{}, m["warnings"], "unlisted entries are their own field, not a global warning")
	for _, n := range []string{"dotdot", "relhome", "emptyhome", "spacehome"} {
		assert.NotContains(t, listedUsers(m), n)
		assert.Contains(t, m["accounts"], n, "a valid name is still an account name")
	}
	out := f.out.String()
	for _, secret := range []string{"bad,name", "Bad Name", ".dot", "\x1b", "\\u001b", "kullan", strings.Repeat("n", 33), "12345"} {
		assert.NotContains(t, out, secret, "an unlisted name never leaves the server")
	}
}

func TestUnlistedAccountsAreBounded(t *testing.T) {
	f := newFixture(t)
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < helperproto.MaxUnlistedAccounts+20; i++ {
		fmt.Fprintf(&b, "bad name %d:x:%d:%d::/home/deploy:/bin/bash\n", i, 30000+i, 30000+i)
	}
	f.write("/etc/passwd", b.String(), 0o644)
	_, m := f.run("authkeys-list")
	assert.Len(t, m["unlisted"], helperproto.MaxUnlistedAccounts)
	assert.Equal(t, false, m["accounts_complete"])
}

// A hostile /etc/passwd: 100,000 entries of names outside the rule and one name of 1 MiB. The
// answer stays small and bounded, the valid accounts are still listed.
func TestHostilePasswdIsBounded(t *testing.T) {
	f := newFixture(t)
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&b, "x %d:x:%d:1::\n", i, 40000+i)
	}
	fmt.Fprintf(&b, "%s:x:50:50::/home/deploy:/bin/bash\n", strings.Repeat("z", 1<<20))
	require.Less(t, b.Len(), passwdLimit, "within the size the helper reads")
	f.write("/etc/passwd", b.String(), 0o644)
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code)
	assert.Len(t, m["unlisted"], helperproto.MaxUnlistedAccounts)
	assert.Contains(t, listedUsers(m), "deploy")
	assert.Less(t, f.out.Len(), 64<<10, "the answer does not grow with the hostile entries")
	assert.NotContains(t, f.out.String(), "zzzz")
}

// The static helper reads /etc/passwd itself, so it must see the entries glibc's files module
// sees (sshd looks accounts up through it): comment and blank lines and leading blanks are ignored,
// missing trailing fields are empty (an empty shell is /bin/sh), and the shell is the rest of the
// line. A line glibc cannot read (no uid) is no account for sshd either.
func TestPasswdIsReadAsGlibcReadsIt(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.withKeys("/home/short", "short")
	f.withKeys("/home/long", "long")
	f.withKeys("/home/indented", "indented")
	f.withKeys("/home/plus", "plus")
	f.write("/etc/passwd", f.read("/etc/passwd")+
		"# a comment:x:1020:1020::/home/deploy:/bin/bash\n"+
		"   # an indented comment with a bad name\n"+
		"\n   \n"+
		fmt.Sprintf("short:x:%d:%d::/home/short\n", f.uid, f.uid)+ // six fields: no shell, so /bin/sh
		fmt.Sprintf("long:x:%d:%d::/home/long:/bin/bash:extra\n", f.uid, f.uid)+ // the shell is the rest
		fmt.Sprintf("  \tindented:x:%d:%d::/home/indented:/bin/bash\n", f.uid, f.uid)+
		fmt.Sprintf("plus:x: %d: %d::/home/plus:/bin/bash\n", f.uid, f.uid)+ // strtoul skips leading blanks
		"nouid:x::1021::/home/deploy:/bin/bash\n"+ // glibc refuses the line: no account
		"badgid:x:1022:x::/home/deploy:/bin/bash\n"+
		"three:x:1023\n", 0o644)
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code, "%v", m)
	assert.Subset(t, listedUsers(m), []string{"short", "long", "indented", "plus"})
	assert.Equal(t, []any{map[string]any{"uid": 1004.0, "reason": "name"}}, m["unlisted"], "only the base fixture's Bad Name")
	for _, n := range []string{"nouid", "badgid", "three"} {
		assert.NotContains(t, m["accounts"], n)
	}
	assert.Equal(t, float64(f.uid), listUser(t, m, "plus")["uid"])
}

func TestParseID(t *testing.T) {
	for _, tc := range []struct {
		in        string
		id        int
		plain, ok bool
	}{
		{"0", 0, true, true}, {"1001", 1001, true, true}, {" 1001", 1001, true, true}, {"0001", 1, true, true},
		{"4294967294", 4294967294, true, true},
		{"\t+7", 7, false, true}, {"4294967295", 4294967295, false, true}, {"4294967296", 4294967295, false, true},
		{"99999999999999999999999", 4294967295, false, true}, {"-1", 4294967295, false, true}, {"-0", 0, false, true},
		{"", 0, false, false}, {" ", 0, false, false}, {"+", 0, false, false}, {"-", 0, false, false}, {"1001 ", 0, false, false},
		{"10a", 0, false, false}, {"0x10", 0, false, false}, {"١٢", 0, false, false},
	} {
		id, plain, ok := parseID(tc.in)
		assert.Equal(t, tc.ok, ok, "%q", tc.in)
		if tc.ok {
			assert.Equal(t, tc.id, id, "%q", tc.in)
			assert.Equal(t, tc.plain, plain, "%q", tc.in)
		}
	}
}

// getpwnam answers with the first entry of a name, so that is the account sshd logs in: a later
// entry of the same name is never listed (it would list the wrong home), even when the first one
// is not scanned. Names are compared exactly: John and john are two accounts.
func TestDuplicateNamesAreTheFirstEntry(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.withKeys("/home/dup", "dup")
	f.withKeys("/home/John", "John")
	f.withKeys("/home/john", "john")
	f.write("/etc/passwd", f.read("/etc/passwd")+
		"dup:x:1030:1030::/home/dup:/usr/sbin/nologin\n"+
		fmt.Sprintf("dup:x:%d:%d::/home/dup:/bin/bash\n", f.uid, f.uid)+
		fmt.Sprintf("deploy:x:%d:%d::/home/dup:/bin/bash\n", f.uid, f.uid)+
		fmt.Sprintf("John:x:%d:%d::/home/John:/bin/bash\n", f.uid, f.uid)+
		fmt.Sprintf("john:x:%d:%d::/home/john:/bin/bash\n", f.uid, f.uid)+
		"bad name:x:1031:1031::/h:/bin/bash\nbad name:x:1031:1031::/h:/bin/bash\n", 0o644)
	_, m := f.run("authkeys-list")
	users := listedUsers(m)
	assert.NotContains(t, users, "dup", "the first dup has no login shell")
	assert.Equal(t, "/home/deploy", listUser(t, m, "deploy")["home"], "the first deploy entry")
	assert.Equal(t, 1, strings.Count(strings.Join(users, ","), "deploy"))
	assert.Equal(t, "/home/John", listUser(t, m, "John")["home"])
	assert.Equal(t, "/home/john", listUser(t, m, "john")["home"])
	assert.Contains(t, m["unlisted"], map[string]any{"uid": 1031.0, "reason": "name"})
	assert.Len(t, m["unlisted"], 2, "Bad Name, and bad name once")
	code, r := f.run("authkeys-read", "/home/John/.ssh/authorized_keys")
	require.Equal(t, 0, code)
	assert.Equal(t, "John", r["owner"])
}

// S6: a file owner's name leaves the server only when it is an account name; the first entry of a
// uid decides it (as getpwuid and ls -l do), and an invalid one is answered with the uid.
func TestOwnerNamesFollowTheAccountRule(t *testing.T) {
	m := owners([]account{{name: "bad,name", uid: 7}, {name: "valid", uid: 7}, {name: "root", uid: 0}, {name: "John.Doe", uid: 8},
		{name: "x\x00", uid: 9}})
	assert.Equal(t, map[int]string{7: "", 0: "root", 8: "John.Doe", 9: ""}, m)
	assert.Equal(t, "7", ownerName(m, 7))
	assert.Equal(t, "John.Doe", ownerName(m, 8))

	f := newFixture(t)
	f.write("/etc/group", "root:x:0:\nbad group:x:7:\nlater:x:7:\nSamba.Users:x:8:\n", 0o644)
	assert.Equal(t, map[int]string{0: "root", 7: "", 8: "Samba.Users"}, f.s.groupNames())

	skipOddUID(t)
	f.write("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy@laptop\n", 0o600)
	f.write("/etc/passwd", strings.Replace(f.read("/etc/passwd"), "deploy:x:", "evil name:x:1:1::/:/bin/false\ndeploy:x:", 1), 0o644)
	f.write("/etc/passwd", strings.Replace(f.read("/etc/passwd"), "root:x:0:0:root:/root:/bin/bash\n",
		fmt.Sprintf("root:x:0:0:root:/root:/bin/bash\nowner,name:x:%d:%d::/:/bin/false\n", f.uid, f.uid), 1), 0o644)
	_, out := f.run("authkeys-list")
	if os.Getuid() != 0 {
		assert.Equal(t, fmt.Sprint(f.uid), filesOf(listUser(t, out, "deploy"))[0]["owner"], "the uid's first name is not an account name")
	}
	assert.NotContains(t, f.out.String(), "owner,name")
}

// AUD-22 (from the audit's PoC 2): authkeys-list returns the files it read, so a discovery needs
// one scan; the sshd runs of a listing grow with the accounts, not with accounts times files.
func TestAuthKeysListInlinesWhatItRead(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	const n = 60
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("u%d", i)
		f.withKeys("/home/"+name, name)
		fmt.Fprintf(&b, "%s:x:%d:%d::/home/%s:/bin/bash\n", name, f.uid, f.uid, name)
	}
	f.write("/etc/passwd", b.String(), 0o644)
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code)
	inline := 0
	for _, u := range m["users"].([]any) {
		for _, fi := range filesOf(u.(map[string]any)) {
			if fi["exists"] != true || fi["unsupported"] == true {
				assert.NotContains(t, fi, "content_b64", fi["path"])
				continue
			}
			require.Equal(t, true, fi["inline"], fi["path"])
			raw, err := base64.StdEncoding.DecodeString(fi["content_b64"].(string))
			require.NoError(t, err)
			assert.Equal(t, hexSHA(raw), fi["sha256"], "the inline content is what was hashed")
			inline++
		}
	}
	assert.GreaterOrEqual(t, inline, n)
	assert.LessOrEqual(t, f.sshdCalls.Load(), int64(len(m["users"].([]any))+1), "one sshd -T per account plus the global one")

	// The inline content is what authkeys-read answers for the same file.
	fi := filesOf(listUser(t, m, "u7"))[0]
	before := f.sshdCalls.Load()
	code, r := f.run("authkeys-read", "/home/u7/.ssh/authorized_keys")
	require.Equal(t, 0, code)
	assert.Equal(t, fi["content_b64"], r["content_b64"])
	assert.Equal(t, fi["sha256"], r["sha256"])
	assert.Greater(t, f.sshdCalls.Load()-before, int64(n), "authkeys-read still scans every account (its owner guards the change)")
}

func TestInlineContentStopsAtItsBudget(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	big := strings.Repeat("ssh-ed25519 AAAA "+strings.Repeat("x", 60)+"\n", 12000) // ~ 914 KiB per file
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < 6; i++ { // ~ 5.4 MiB in total: more than MaxListInline
		name := fmt.Sprintf("big%d", i)
		f.mkdir("/home/"+name, 0o755)
		f.mkdir("/home/"+name+"/.ssh", 0o700)
		f.write("/home/"+name+"/.ssh/authorized_keys", big, 0o600)
		fmt.Fprintf(&b, "%s:x:%d:%d::/home/%s:/bin/bash\n", name, f.uid, f.uid, name)
	}
	f.write("/etc/passwd", b.String(), 0o644)
	_, m := f.run("authkeys-list")
	total, without := 0, 0
	for _, u := range m["users"].([]any) {
		for _, fi := range filesOf(u.(map[string]any)) {
			if fi["exists"] != true {
				continue
			}
			if fi["inline"] == true {
				raw, _ := base64.StdEncoding.DecodeString(fi["content_b64"].(string))
				total += len(raw)
			} else {
				without++
				assert.NotEmpty(t, fi["sha256"], "a file over the budget still has its hash")
				assert.NotContains(t, fi, "content_b64")
			}
		}
	}
	assert.LessOrEqual(t, total, helperproto.MaxListInline)
	assert.Positive(t, without)
	assert.Equal(t, false, m["truncated"])
	assert.LessOrEqual(t, f.out.Len(), helperproto.MaxListOutput)
}

// longPatterns is an sshd -T text whose AuthorizedKeysFile has n absolute patterns of about 4 KiB
// each (valid helper paths in a directory that does not exist): metadata that is large but legal.
func longPatterns(n int) string {
	var b strings.Builder
	b.WriteString("authorizedkeysfile .ssh/authorized_keys")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, " /etc/ssh/k%03d/%s/%%u", i, strings.Repeat("p", 4000))
	}
	b.WriteString("\n")
	return strings.Replace(globalSSHD, "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n", b.String(), 1)
}

// S8: when the metadata alone would pass MaxListOutput, the helper lists fewer users (in uid
// order, root first) and says so: the answer is truncated and the account list incomplete, never
// a failed discovery.
func TestListAnswerIsTruncatedToItsBound(t *testing.T) {
	f := newFixture(t)
	f.global = longPatterns(10)
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < 195; i++ {
		fmt.Fprintf(&b, "u%d:x:%d:%d::/home/deploy:/bin/bash\n", i, 3000+i, 3000+i)
	}
	f.write("/etc/passwd", b.String(), 0o644)
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code)
	assert.LessOrEqual(t, f.out.Len(), helperproto.MaxListOutput)
	assert.Greater(t, f.out.Len(), helperproto.MaxListOutput-200<<10, "only as many users as needed are left out")
	assert.Equal(t, true, m["truncated"])
	assert.Equal(t, false, m["accounts_complete"])
	users := listedUsers(m)
	assert.Less(t, len(users), 198)
	assert.Equal(t, "root", users[0])
	assert.Len(t, m["accounts"], 202, "the account names are all there")
}

// S8: inline content is given up before any user: the files without it keep their hash and are
// read with authkeys-read.
func TestListAnswerDropsInlineContentBeforeUsers(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/etc/passwd", strings.Replace(f.read("/etc/passwd"), "Bad Name:x:1004:1004::/home/deploy:/bin/bash\n", "", 1), 0o644)
	f.global = longPatterns(80)
	big := strings.Repeat("ssh-ed25519 AAAA "+strings.Repeat("x", 60)+"\n", 12000)
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("big%d", i)
		f.mkdir("/home/"+name, 0o755)
		f.mkdir("/home/"+name+"/.ssh", 0o700)
		f.write("/home/"+name+"/.ssh/authorized_keys", big, 0o600)
		fmt.Fprintf(&b, "%s:x:%d:%d::/home/%s:/bin/bash\n", name, f.uid, f.uid, name)
	}
	f.write("/etc/passwd", b.String(), 0o644)
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code)
	assert.LessOrEqual(t, f.out.Len(), helperproto.MaxListOutput)
	assert.Equal(t, false, m["truncated"])
	inline, without := 0, 0
	for i := 0; i < 5; i++ {
		fi := filesOf(listUser(t, m, fmt.Sprintf("big%d", i)))[0]
		assert.Equal(t, hexSHA([]byte(big)), fi["sha256"])
		if fi["inline"] == true {
			inline++
		} else {
			without++
		}
	}
	assert.Positive(t, inline)
	assert.Positive(t, without, "some content was given up for the bound")
	assert.Equal(t, true, m["accounts_complete"], "nothing is missing")
}

// A file shared by several accounts (an absolute AuthorizedKeysFile) is listed, with its content,
// for each of them; reads and writes still resolve it to the first account in uid order (root),
// so the inline listing cannot make the root guards see another owner.
func TestSharedFileStillResolvesToItsFirstAccount(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("a file all accounts may use is root's: needs uid 0 (the root helper suite)")
	}
	f, _ := newWriteFixture(t)
	f.mkdir("/etc/ssh/keys", 0o755)
	f.write("/etc/ssh/keys/shared", "ssh-ed25519 AAAA shared@x\n", 0o644)
	f.global = strings.Replace(globalSSHD, "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2", "authorizedkeysfile /etc/ssh/keys/shared", 1)
	_, m := f.run("authkeys-list")
	for _, u := range []string{"root", "alice-svc", "deploy"} {
		fi := filesOf(listUser(t, m, u))[0]
		assert.Equal(t, "/etc/ssh/keys/shared", fi["path"], u)
		assert.Equal(t, true, fi["inline"], u)
	}
	code, r := f.run("authkeys-read", "/etc/ssh/keys/shared")
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, "root", r["owner"])
	f.s.stdin = strings.NewReader("")
	code, w := f.run("authkeys-write", "/etc/ssh/keys/shared", "--expect-sha256", hexOf("ssh-ed25519 AAAA shared@x\n"),
		"--content-sha256", hexOf(""), "--op", "0190f5a0-0000-7000-8000-000000000031")
	require.Equal(t, 0, code, "%v", w)
	assert.Equal(t, "root", w["owner"])
}

// A file that changes between the listing and the write: the hash of the listing (and of its inline
// content) no longer matches, and the helper refuses the write without touching the file.
func TestWriteAfterAChangeSinceTheListingIsRefused(t *testing.T) {
	f, _ := newWriteFixture(t)
	f.write("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy@laptop\n", 0o600)
	_, m := f.run("authkeys-list")
	listed := filesOf(listUser(t, m, "deploy"))[0]
	require.Equal(t, true, listed["inline"])
	f.write("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy@laptop\nssh-ed25519 BBBB other@admin\n", 0o600)
	f.s.stdin = strings.NewReader("")
	code, w := f.run("authkeys-write", "/home/deploy/.ssh/authorized_keys", "--expect-sha256", listed["sha256"].(string),
		"--content-sha256", hexOf(""), "--op", "0190f5a0-0000-7000-8000-000000000032")
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeHashMismatch, w["code"])
	assert.Contains(t, f.read("/home/deploy/.ssh/authorized_keys"), "other@admin")
}

// Phase 3's protections hold for inline content: a hard-linked file, a file owned by another user
// and a symlink out of the home are listed unsupported, without content.
func TestInlineContentOnlyForFilesTheHelperWouldRead(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/etc/shadow", "root:SECRET-HASH:19000::::::\n", 0o600)
	require.NoError(t, os.Link(f.host("/etc/shadow"), f.host("/home/deploy/.ssh/authorized_keys")))
	require.NoError(t, os.Symlink("../../../etc/shadow", f.host("/home/deploy/.ssh/authorized_keys2")))
	_, m := f.run("authkeys-list")
	for _, fi := range filesOf(listUser(t, m, "deploy")) {
		assert.Equal(t, true, fi["unsupported"], fi["path"])
		assert.Equal(t, false, fi["inline"], fi["path"])
		assert.NotContains(t, fi, "content_b64")
	}
	assert.NotContains(t, f.out.String(), "SECRET-HASH")
	assert.NotContains(t, f.out.String(), base64.StdEncoding.EncodeToString([]byte("root:SECRET")))
}

// Homes shared with another account: an account whose home is another user's directory gets that
// user's file listed as a candidate, but never its content unless sshd would accept the file for
// it too (fileOK: its own, or root's in a root-controlled directory). A home of "/" is listed.
func TestHomesSharedWithAnotherAccount(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy@laptop\n", 0o600)
	if os.Getuid() == 0 { // make the file deploy's, as on a real server
		require.NoError(t, os.Chown(f.host("/home/deploy/.ssh"), f.uid, f.uid))
		require.NoError(t, os.Chown(f.host("/home/deploy/.ssh/authorized_keys"), f.uid, f.uid))
	}
	f.write("/etc/passwd", f.read("/etc/passwd")+"intruder:x:4242:4242::/home/deploy/:/bin/bash\nslash:x:4243:4243::/:/bin/bash\n", 0o644)
	_, m := f.run("authkeys-list")
	mine := filesOf(listUser(t, m, "deploy"))[0]
	assert.Equal(t, true, mine["inline"])
	theirs := filesOf(listUser(t, m, "intruder"))[0]
	assert.Equal(t, "/home/deploy/.ssh/authorized_keys", theirs["path"])
	assert.Equal(t, "/home/deploy", listUser(t, m, "intruder")["home"])
	assert.Equal(t, true, theirs["unsupported"], "another user's file is not intruder's")
	assert.NotContains(t, theirs, "content_b64")
	assert.Equal(t, "/.ssh/authorized_keys", filesOf(listUser(t, m, "slash"))[0]["path"])
	code, r := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
	require.Equal(t, 0, code)
	assert.Equal(t, "deploy", r["owner"], "the first account in uid order")
}

// A local user who swaps their file for a link to /etc/shadow (or a hard link) after the scan
// chose it and before the listing reads it gets it listed unsupported: the content is taken only
// from a descriptor that passed the same checks as authkeys-read.
func TestASwapAfterTheScanNeverInlinesAnotherFile(t *testing.T) {
	skipOddUID(t)
	for _, swap := range []string{"symlink", "hardlink"} {
		t.Run(swap, func(t *testing.T) {
			f := newFixture(t)
			f.write("/etc/shadow", "root:SECRET-HASH:19000::::::\n", 0o600)
			f.write("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy@laptop\n", 0o600)
			f.mkdir("/home/zz", 0o755)
			f.write("/etc/passwd", f.read("/etc/passwd")+fmt.Sprintf("zz:x:%d:%d::/home/zz:/bin/bash\n", f.uid+10, f.uid+10), 0o644)
			ak := f.host("/home/deploy/.ssh/authorized_keys")
			f.onSSHD = func(args []string) {
				if len(args) == 3 && strings.HasPrefix(args[2], "user=zz,") { // the last account: deploy's file is chosen
					require.NoError(t, os.Remove(ak))
					if swap == "symlink" {
						require.NoError(t, os.Symlink("../../../etc/shadow", ak))
					} else {
						require.NoError(t, os.Link(f.host("/etc/shadow"), ak))
					}
				}
			}
			_, m := f.run("authkeys-list")
			fi := filesOf(listUser(t, m, "deploy"))[0]
			assert.Equal(t, true, fi["unsupported"])
			assert.NotContains(t, fi, "content_b64")
			assert.NotContains(t, f.out.String(), "SECRET-HASH")
			assert.NotContains(t, f.out.String(), base64.StdEncoding.EncodeToString([]byte("root:SECRET")))
		})
	}
}

// C1: a NUL byte in /etc/passwd. glibc reads each line only up to its first NUL (a C string); the
// helper does the same, so a line glibc refuses never hides a later entry of the same name, a
// shell after a NUL never makes an account look unscanned, and a line cut short is still the
// account glibc sees. A file with a NUL is never called complete.
func TestPasswdNULBytesAreReadAsGlibcReadsThem(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/etc/passwd", strings.Replace(f.read("/etc/passwd"), "Bad Name:x:1004:1004::/home/deploy:/bin/bash\n", "", 1), 0o644)
	f.withKeys("/home/bob", "bob")
	f.withKeys("/home/carol", "carol")
	f.write("/etc/passwd", f.read("/etc/passwd")+
		"bob:x\x00:1500:1500::/nonexistent:/usr/sbin/nologin\n"+ // glibc: two fields, refused
		fmt.Sprintf("bob:x:%d:%d::/home/bob:/bin/bash\n", f.uid, f.uid)+ // so this is bob
		fmt.Sprintf("carol:x:%d:%d::/home/carol:/bin/bash\x00/nologin\n", f.uid, f.uid)+ // glibc: shell /bin/bash
		"eve:x:1503:1503\x00junk\n", 0o644) // glibc: an account with an empty home and shell
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "/home/bob", listUser(t, m, "bob")["home"])
	assert.Equal(t, true, filesOf(listUser(t, m, "bob"))[0]["inline"])
	assert.Equal(t, "/home/carol", listUser(t, m, "carol")["home"])
	assert.Equal(t, []any{map[string]any{"uid": 1503.0, "reason": "home"}}, m["unlisted"])
	assert.Equal(t, []any{helperproto.WarnAccountsNUL}, m["warnings"])
	assert.Equal(t, false, m["accounts_complete"])
	assert.Subset(t, m["accounts"], []any{"bob", "carol", "eve"})

	// Without the NUL bytes the same accounts make a complete list.
	f.write("/etc/passwd", strings.ReplaceAll(strings.Replace(f.read("/etc/passwd"), "bob:x\x00:1500:1500::/nonexistent:/usr/sbin/nologin\n", "", 1),
		"\x00/nologin", ""), 0o644)
	f.write("/etc/passwd", strings.Replace(f.read("/etc/passwd"), "eve:x:1503:1503\x00junk\n", "", 1), 0o644)
	_, m = f.run("authkeys-list")
	assert.Equal(t, []any{}, m["warnings"])
	assert.Equal(t, true, m["accounts_complete"])
}

// C1: no line glibc refuses shadows a later entry of the same name, whatever the reason of the
// refusal (too few fields, a uid or gid that is not a number, a NIS-compat name).
func TestRefusedLinesNeverShadowALaterEntry(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.withKeys("/home/bob", "bob")
	for _, refused := range []string{
		"bob:x:1500\n", "bob:x::1500::/nonexistent:/usr/sbin/nologin\n", "bob:x:1500:x::/nonexistent:/usr/sbin/nologin\n",
		"bob:x:15 00:1500::/nonexistent:/usr/sbin/nologin\n", "bob\n", "   \t\n", "# bob:x:1500:1500::/nonexistent:/usr/sbin/nologin\n",
	} {
		f.write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"+refused+fmt.Sprintf("bob:x:%d:%d::/home/bob:/bin/bash\n", f.uid, f.uid), 0o644)
		_, m := f.run("authkeys-list")
		assert.Equal(t, "/home/bob", listUser(t, m, "bob")["home"], "%q", refused)
		assert.Equal(t, []any{}, m["unlisted"], "%q", refused)
	}
}

// M1: a uid or gid glibc reads only as a clamped or signed value is reported, never scanned with
// a number nobody wrote. The entry is still the first of its name.
func TestOddIDsAreReported(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.withKeys("/home/big", "big")
	f.write("/etc/passwd", f.read("/etc/passwd")+
		"big:x:4294967296:1000::/home/big:/bin/bash\n"+
		fmt.Sprintf("big:x:%d:%d::/home/big:/bin/bash\n", f.uid, f.uid)+
		"neg:x:-1:1000::/home/big:/bin/bash\n"+
		"plus:x:+1600:1000::/home/big:/bin/bash\n"+
		"max:x:4294967295:1000::/home/big:/bin/bash\n"+
		"gid:x:1601:-5::/home/big:/usr/sbin/nologin\n", 0o644)
	_, m := f.run("authkeys-list")
	assert.NotContains(t, listedUsers(m), "big")
	assert.ElementsMatch(t, []any{
		map[string]any{"uid": 1004.0, "reason": "name"},
		map[string]any{"uid": 4294967295.0, "reason": "id"},
		map[string]any{"uid": 4294967295.0, "reason": "id"},
		map[string]any{"uid": 1600.0, "reason": "id"},
		map[string]any{"uid": 4294967295.0, "reason": "id"},
		map[string]any{"uid": 1601.0, "reason": "id"},
	}, m["unlisted"])
	assert.Equal(t, false, m["accounts_complete"])
}

// M2: glibc's files module never answers an entry whose name starts with "+" or "-" (NIS compat
// syntax; getpwnam and getpwuid skip them), so they are no accounts and are skipped, not reported.
// nsswitch "compat" is a source the helper cannot read (I2).
func TestNISCompatLinesAreNoAccounts(t *testing.T) {
	f := newFixture(t)
	f.write("/etc/passwd", f.read("/etc/passwd")+"+\n+:x:0:0:::\n+@admins:x:::::\n-baduser:x:0:0:::\n+deploy::::::\n", 0o644)
	_, m := f.run("authkeys-list")
	assert.Equal(t, []any{map[string]any{"uid": 1004.0, "reason": "name"}}, m["unlisted"], "only the base fixture's Bad Name")
	assert.Equal(t, "/home/deploy", listUser(t, m, "deploy")["home"])
	assert.NotContains(t, m["accounts"], "+")
	assert.Equal(t, "root", owners([]account{{name: "+", uid: 0}, {name: "root", uid: 0}})[0], "a compat line is never an owner")
}

// I2: any passwd source but files, systemd and mymachines can hold accounts the helper cannot see.
func TestDirectoryUsersAreAnySourceButFiles(t *testing.T) {
	f := newFixture(t)
	for line, want := range map[string]bool{
		"passwd: files":                                    false,
		"passwd:files systemd":                             false,
		"passwd: files mymachines systemd":                 false,
		"passwd:         files systemd\ngroup: files ldap": false,
		"passwd: files [NOTFOUND=return] systemd":          false,
		"# passwd: files ldap\npasswd: files":              false,
		"passwd: files extrausers":                         true,
		"passwd: files altfiles":                           true,
		"passwd: compat":                                   true,
		"passwd: files winbind":                            true,
		"passwd: nis files":                                true,
		"passwd: db files":                                 true,
		"passwd: sss files systemd":                        true,
		"passwd: files ldap":                               true,
	} {
		f.write("/etc/nsswitch.conf", line+"\n", 0o644)
		assert.Equal(t, want, f.s.directoryUsers(), "%q", line)
	}
	f.write("/etc/nsswitch.conf", "passwd: files extrausers\n", 0o644)
	_, m := f.run("authkeys-list")
	assert.Equal(t, []any{helperproto.WarnDirectoryUsers}, m["warnings"])
	assert.Equal(t, false, m["accounts_complete"])
}

// I1: authkeys-read names the uid of the account it resolved the file to.
func TestAuthKeysReadNamesTheOwnersUID(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy@laptop\n", 0o600)
	code, r := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, float64(f.uid), r["uid"])
}

// Fix round 2: whenever the helper cannot be sure the account sources are only the local files it
// reads, the list is incomplete with directory_users_not_listed — never the reverse.

// N4: glibc takes the database name up to the first blank or colon; any other token is a source.
func TestPasswdLineSpellings(t *testing.T) {
	f := newFixture(t)
	for line, want := range map[string]bool{
		"passwd sss":                     true,
		"passwd : sss":                   true,
		"passwd : files":                 true, // a bare ":" is not a source the helper knows
		"passwd\tsss":                    true,
		"passwd:files:":                  true,
		"passwd: files [NOTFOUND=return": true, // an action that never ends
		"passwd: files [ NOTFOUND=return ] systemd": false,
		"passwd:files":       false,
		"passwd_compat: nis": false, // another database
		"passwdx: sss":       false,
	} {
		f.write("/etc/nsswitch.conf", line+"\n", 0o644)
		assert.Equal(t, want, f.s.directoryUsers(), "%q", line)
	}
}

// N2: a symlinked nsswitch.conf (authselect) is followed when the link and its target are root's
// under root-controlled directories; a link the walk refuses is never "local only".
func TestSymlinkedNSSwitchIsFollowedOrRefused(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/authselect", 0o755)
	f.write("/etc/authselect/nsswitch.conf", "passwd: files sss\n", 0o644)
	require.NoError(t, os.Remove(f.host("/etc/nsswitch.conf")))
	require.NoError(t, os.Symlink("/etc/authselect/nsswitch.conf", f.host("/etc/nsswitch.conf")))
	assert.True(t, f.s.directoryUsers(), "the target names sss")
	f.write("/etc/authselect/nsswitch.conf", "passwd: files systemd\n", 0o644)
	assert.False(t, f.s.directoryUsers(), "a followed link to a local configuration is local")

	// The target's directory can be changed by others: refused, so incomplete.
	require.NoError(t, os.Chmod(f.host("/etc/authselect"), 0o777))
	assert.True(t, f.s.directoryUsers())
	require.NoError(t, os.Chmod(f.host("/etc/authselect"), 0o755))
	// The target itself is writable by others.
	require.NoError(t, os.Chmod(f.host("/etc/authselect/nsswitch.conf"), 0o666))
	assert.True(t, f.s.directoryUsers())
	require.NoError(t, os.Chmod(f.host("/etc/authselect/nsswitch.conf"), 0o644))
	// A link into a directory others control.
	f.mkdir("/tmp", 0o777)
	f.write("/tmp/nss", "passwd: files\n", 0o644)
	require.NoError(t, os.Remove(f.host("/etc/nsswitch.conf")))
	require.NoError(t, os.Symlink("/tmp/nss", f.host("/etc/nsswitch.conf")))
	assert.True(t, f.s.directoryUsers())
	// A dangling link reads as a missing file: glibc's default, files.
	require.NoError(t, os.Remove(f.host("/etc/nsswitch.conf")))
	require.NoError(t, os.Symlink("/etc/nowhere", f.host("/etc/nsswitch.conf")))
	assert.False(t, f.s.directoryUsers())

	_, m := f.run("authkeys-list")
	assert.Equal(t, []any{}, m["warnings"])
	require.NoError(t, os.Remove(f.host("/etc/nsswitch.conf")))
	require.NoError(t, os.Symlink("/tmp/nss", f.host("/etc/nsswitch.conf")))
	_, m = f.run("authkeys-list")
	assert.Equal(t, []any{helperproto.WarnDirectoryUsers}, m["warnings"])
	assert.Equal(t, false, m["accounts_complete"])
}

// N3: only a missing nsswitch.conf is glibc's default (files); an unreadable or oversized one is
// never "local only".
func TestUnreadableNSSwitchIsNotLocal(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, os.Remove(f.host("/etc/nsswitch.conf")))
	assert.False(t, f.s.directoryUsers(), "missing: files")
	f.write("/etc/nsswitch.conf", strings.Repeat("# padding\n", 7000)+"passwd: sss\n", 0o644)
	assert.True(t, f.s.directoryUsers(), "oversized")
	require.NoError(t, os.Remove(f.host("/etc/nsswitch.conf")))
	f.mkdir("/etc/nsswitch.conf", 0o755)
	assert.True(t, f.s.directoryUsers(), "not a regular file")
	require.NoError(t, os.Remove(f.host("/etc/nsswitch.conf")))
	require.NoError(t, unix.Mkfifo(f.host("/etc/nsswitch.conf"), 0o644))
	assert.True(t, f.s.directoryUsers(), "a FIFO is never opened and never local")
	require.NoError(t, os.Remove(f.host("/etc/nsswitch.conf")))
	f.write("/etc/nsswitch.conf", "passwd: files\n", 0o644)
	require.NoError(t, os.Link(f.host("/etc/nsswitch.conf"), f.host("/etc/nsswitch.hard")))
	assert.False(t, f.s.directoryUsers(), "a second name of a root-owned file changes nothing")
}

// N1: systemd's userdb serves accounts the helper cannot see (drop-in *.user records, homed's
// *.identity). With systemd as a passwd source, any such record makes the list incomplete.
func TestUserdbRecordsMakeTheListIncomplete(t *testing.T) {
	f := newFixture(t)
	f.write("/etc/nsswitch.conf", "passwd: files systemd\n", 0o644)
	assert.False(t, f.s.directoryUsers(), "no userdb directory: local")
	for _, dir := range []string{"/run/userdb", "/run/host/userdb", "/usr/local/lib/userdb", "/usr/lib/userdb", "/var/lib/systemd/home"} {
		f.mkdir(dir, 0o755)
	}
	f.write("/run/userdb/io.systemd.Multiplexer", "", 0o644) // a socket's name: not a record
	f.write("/run/userdb/hidden.group", "{}", 0o644)
	assert.False(t, f.s.directoryUsers(), "directories without user records")
	for _, rec := range []string{"/etc/userdb/x.user", "/run/userdb/hidden.user", "/run/host/userdb/h.user",
		"/usr/local/lib/userdb/l.user", "/usr/lib/userdb/u.user", "/var/lib/systemd/home/alice.identity"} {
		f.mkdir(filepath.Dir(rec), 0o755)
		f.write(rec, "{}", 0o644)
		assert.True(t, f.s.directoryUsers(), rec)
		require.NoError(t, os.Remove(f.host(rec)))
	}
	f.write("/etc/nsswitch.conf", "passwd: files\n", 0o644)
	f.write("/etc/userdb/x.user", "{}", 0o644)
	assert.False(t, f.s.directoryUsers(), "without systemd as a source glibc never asks userdb")

	f.write("/etc/nsswitch.conf", "passwd: files systemd\n", 0o644)
	_, m := f.run("authkeys-list")
	assert.Equal(t, []any{helperproto.WarnDirectoryUsers}, m["warnings"])
	assert.Equal(t, false, m["accounts_complete"])
	require.NoError(t, os.Remove(f.host("/etc/userdb/x.user")))

	// A userdb directory others can change, one that is not a directory, or one too large to list
	// is never "no records".
	require.NoError(t, os.Chmod(f.host("/etc/userdb"), 0o777))
	assert.True(t, f.s.directoryUsers(), "writable by others")
	require.NoError(t, os.Chmod(f.host("/etc/userdb"), 0o755))
	require.NoError(t, os.Remove(f.host("/usr/lib/userdb")))
	f.write("/usr/lib/userdb", "", 0o644)
	assert.True(t, f.s.directoryUsers(), "not a directory")
	require.NoError(t, os.Remove(f.host("/usr/lib/userdb")))
	for i := 0; i <= maxUserdbEntries; i++ {
		f.write(fmt.Sprintf("/run/userdb/s%d.group", i), "", 0o644)
	}
	assert.True(t, f.s.directoryUsers(), "more entries than the helper lists")
}
