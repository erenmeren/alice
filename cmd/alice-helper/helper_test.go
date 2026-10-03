//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

var testNow = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// globalSSHD is canned "sshd -T" output.
const globalSSHD = `pubkeyauthentication yes
passwordauthentication no
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
authorizedkeyscommand none
hostkey /etc/ssh/ssh_host_ed25519_key
hostkey /etc/ssh/ssh_host_rsa_key
`

const deployCtx = "user=deploy,host=localhost,addr=127.0.0.1"

// testUID is the uid the fixture gives "deploy": the test's own uid when it is a normal user,
// else 1000 (files created by a root test run are then root-owned, which StrictModes accepts too).
func testUID() int {
	if u := os.Getuid(); u >= 1000 {
		return u
	}
	return 1000
}

// skipOddUID skips ownership assertions when the tests run as a system user (1..999): the files
// they create are then owned by neither "deploy" nor root.
func skipOddUID(t *testing.T) {
	if u := os.Getuid(); u != 0 && u < 1000 {
		t.Skip("ownership checks need a test uid of 0 or >= 1000")
	}
}

type fixture struct {
	t         *testing.T
	root      string
	s         *sys
	out       bytes.Buffer
	mu        sync.Mutex
	logged    []string
	sshdCalls atomic.Int64
	global    string
	perUser   map[string]string
	sshdFails bool
	cFails    bool // only "sshd -T -C user=…" fails
	onSSHD    func(args []string)
	uid       int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	f := &fixture{t: t, root: root, global: globalSSHD, perUser: map[string]string{}, uid: testUID()}
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{"/etc", 0o755}, {"/etc/ssh", 0o755}, {"/root", 0o700}, {"/home", 0o755}, {"/home/deploy", 0o755},
		{"/home/deploy/.ssh", 0o700}, {"/home/nologin", 0o755}, {"/var", 0o755}, {"/var/lib", 0o755},
		{"/var/lib/alice-svc", 0o755}, {"/var/lib/alice-svc/.ssh", 0o700},
	} {
		f.mkdir(d.path, d.mode)
	}
	f.write("/etc/passwd", fmt.Sprintf(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice-svc:x:998:998:Alice:/var/lib/alice-svc:/bin/bash
deploy:x:%d:%d:Deploy:/home/deploy:/bin/bash
nologin:x:1002:1002::/home/nologin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
ghost:x:1003:1003::/home/ghost:/bin/bash
Bad Name:x:1004:1004::/home/deploy:/bin/bash
broken line
`, f.uid, f.uid), 0o644)
	f.write("/etc/nsswitch.conf", "passwd: files systemd\ngroup: files\n", 0o644)
	f.s = &sys{
		root:     root,
		rootUID:  os.Getuid(),
		euid:     func() int { return 0 },
		sudoUser: func() string { return "alice-svc" },
		now:      func() time.Time { return testNow },
		runSSHD:  f.runSSHD,
		stdin:    strings.NewReader(""),
		stdout:   &f.out,
		syslog: func(sub, path string) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.logged = append(f.logged, sub+" "+path)
		},
	}
	return f
}

func (f *fixture) runSSHD(_ context.Context, args ...string) ([]byte, error) {
	f.sshdCalls.Add(1)
	if f.onSSHD != nil {
		f.onSSHD(args)
	}
	if f.sshdFails || (f.cFails && len(args) == 3) {
		return nil, errors.New("exit status 255")
	}
	if len(args) == 3 && args[0] == "-T" && args[1] == "-C" {
		if c, ok := f.perUser[args[2]]; ok {
			return []byte(c), nil
		}
		return []byte(f.global), nil
	}
	if len(args) == 1 && args[0] == "-T" {
		return []byte(f.global), nil
	}
	return nil, fmt.Errorf("unexpected sshd arguments %q", args)
}

func (f *fixture) host(guest string) string { return filepath.Join(f.root, guest) }

func (f *fixture) mkdir(guest string, mode os.FileMode) {
	f.t.Helper()
	require.NoError(f.t, os.MkdirAll(f.host(guest), 0o700))
	require.NoError(f.t, os.Chmod(f.host(guest), mode))
}

func (f *fixture) write(guest, content string, mode os.FileMode) {
	f.t.Helper()
	require.NoError(f.t, os.WriteFile(f.host(guest), []byte(content), 0o600))
	require.NoError(f.t, os.Chmod(f.host(guest), mode))
}

func (f *fixture) read(guest string) string {
	f.t.Helper()
	b, err := os.ReadFile(f.host(guest))
	require.NoError(f.t, err)
	return string(b)
}

func (f *fixture) loggedLines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.logged...)
}

// run runs the helper and checks the output contract: exactly one line of valid JSON.
func (f *fixture) run(args ...string) (int, map[string]any) {
	f.t.Helper()
	f.out.Reset()
	code := run(args, f.s)
	line := f.out.String()
	require.True(f.t, strings.HasSuffix(line, "\n"), "output ends with a newline: %q", line)
	require.Equal(f.t, 1, strings.Count(line, "\n"), "exactly one line: %q", line)
	var m map[string]any
	require.NoError(f.t, json.Unmarshal([]byte(line), &m), line)
	return code, m
}

func hexOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// listUser returns the "users" entry of an authkeys-list answer for name.
func listUser(t *testing.T, m map[string]any, name string) map[string]any {
	t.Helper()
	for _, u := range m["users"].([]any) {
		if u.(map[string]any)["user"] == name {
			return u.(map[string]any)
		}
	}
	t.Fatalf("user %s not listed", name)
	return nil
}

func filesOf(u map[string]any) []map[string]any {
	var out []map[string]any
	for _, f := range u["files"].([]any) {
		out = append(out, f.(map[string]any))
	}
	return out
}

func TestVersionNeedsNoRoot(t *testing.T) {
	f := newFixture(t)
	f.s.euid = func() int { return 1001 }
	code, m := f.run("version")
	assert.Equal(t, 0, code)
	assert.Equal(t, map[string]any{"ok": true, "helper": helperproto.Version, "protocol": float64(helperproto.Protocol)}, m)
	assert.Zero(t, f.sshdCalls.Load())
}

func TestPrivilegedSubcommandsNeedRoot(t *testing.T) {
	f := newFixture(t)
	f.s.euid = func() int { return 1001 }
	for _, args := range [][]string{
		{"sshd-dump"}, {"hostkeys"}, {"authkeys-list"}, {"authkeys-read", "/home/deploy/.ssh/authorized_keys"},
	} {
		code, m := f.run(args...)
		assert.Equal(t, helperproto.ExitRefused, code, "%v", args)
		assert.Equal(t, helperproto.CodeNotRoot, m["code"], "%v", args)
		assert.Equal(t, false, m["ok"], "%v", args)
	}
	assert.Zero(t, f.sshdCalls.Load(), "nothing runs before the root check")
	assert.Empty(t, f.loggedLines())
}

func TestUnknownSubcommandAndUsage(t *testing.T) {
	f := newFixture(t)
	code, m := f.run()
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeUsage, m["code"])
	for _, sub := range []string{"nginx-dump", "install-cert", "sh", "--help", "VERSION"} {
		code, m = f.run(sub)
		assert.Equal(t, helperproto.ExitRefused, code, sub)
		assert.Equal(t, helperproto.CodeUnknownSubcommand, m["code"], sub)
	}
	for _, args := range [][]string{{"sshd-dump", "x"}, {"hostkeys", "x"}, {"authkeys-list", "--user", "root"}, {"authkeys-read"},
		{"authkeys-read", "/a", "/b"}} {
		code, m = f.run(args...)
		assert.Equal(t, helperproto.ExitRefused, code, "%v", args)
		assert.Equal(t, helperproto.CodeUsage, m["code"], "%v", args)
	}
	assert.Zero(t, f.sshdCalls.Load())
}

func TestSSHDDump(t *testing.T) {
	f := newFixture(t)
	code, m := f.run("sshd-dump")
	assert.Equal(t, 0, code)
	assert.Equal(t, map[string]any{"ok": true, "config": globalSSHD, "fallback": false}, m)
	assert.Equal(t, []string{"sshd-dump "}, f.loggedLines())

	f.sshdFails = true
	code, m = f.run("sshd-dump")
	assert.Equal(t, 0, code)
	assert.Equal(t, map[string]any{"ok": true, "config": "", "fallback": true}, m)
}

func TestHostKeys(t *testing.T) {
	f := newFixture(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	f.write("/etc/ssh/ssh_host_ed25519_key.pub", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))+" root@web-01\n", 0o644)
	// A .pub that is a symlink is never followed.
	require.NoError(t, os.Symlink("ssh_host_ed25519_key.pub", f.host("/etc/ssh/ssh_host_rsa_key.pub")))

	code, m := f.run("hostkeys")
	assert.Equal(t, 0, code)
	assert.Equal(t, []any{map[string]any{"type": "ssh-ed25519", "bits": float64(256), "fingerprint": ssh.FingerprintSHA256(k),
		"path": "/etc/ssh/ssh_host_ed25519_key.pub"}}, m["keys"])

	f.sshdFails = true // defaults are tried when sshd -T fails
	code, m = f.run("hostkeys")
	assert.Equal(t, 0, code)
	assert.Len(t, m["keys"], 1)

	f.global = "hostkey /nowhere/key\n"
	f.sshdFails = false
	_, m = f.run("hostkeys")
	assert.Equal(t, []any{}, m["keys"], "missing keys are skipped and the list is never null")
}

func TestAuthKeysListUsersAndFiles(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy@laptop\n", 0o600)
	f.mkdir("/etc/ssh/keys", 0o755)
	f.write("/etc/ssh/keys/deploy", "central\n", 0o644)
	f.perUser[deployCtx] = "authorizedkeysfile .ssh/authorized_keys /etc/ssh/keys/%u\n"

	code, m := f.run("authkeys-list")
	assert.Equal(t, 0, code)
	var names []string
	for _, u := range m["users"].([]any) {
		names = append(names, u.(map[string]any)["user"].(string))
	}
	assert.Equal(t, []string{"root", "alice-svc", "deploy"}, names, "root, the sudo user and real users; never daemon, nologin, nobody or ghost")
	assert.Equal(t, "none", m["authorized_keys_command"])
	assert.Equal(t, []any{}, m["warnings"])

	owner := "deploy"
	if os.Getuid() == 0 {
		owner = "root"
	}
	deploy := filesOf(listUser(t, m, "deploy"))
	require.Len(t, deploy, 2)
	assert.Equal(t, map[string]any{"path": "/home/deploy/.ssh/authorized_keys", "exists": true, "size": float64(31),
		"sha256": hexOf("ssh-ed25519 AAAA deploy@laptop\n"), "mode": "0600", "owner": owner, "strict_modes_ok": true,
		"too_large": false, "unsupported": false}, deploy[0])
	assert.Equal(t, "/etc/ssh/keys/deploy", deploy[1]["path"])
	assert.Equal(t, true, deploy[1]["exists"])
	assert.Equal(t, "0644", deploy[1]["mode"])

	root := filesOf(listUser(t, m, "root"))
	require.Len(t, root, 2)
	assert.Equal(t, "/root/.ssh/authorized_keys", root[0]["path"])
	assert.Equal(t, false, root[0]["exists"])
	assert.Equal(t, "", root[0]["sha256"])
	svc := filesOf(listUser(t, m, "alice-svc"))
	assert.Equal(t, "/var/lib/alice-svc/.ssh/authorized_keys", svc[0]["path"])
	assert.Equal(t, []string{"authkeys-list "}, f.loggedLines())
}

func TestAuthKeysListWarnings(t *testing.T) {
	f := newFixture(t)
	f.write("/etc/nsswitch.conf", "passwd:  files sss\n", 0o644)
	f.global = strings.Replace(globalSSHD, "authorizedkeyscommand none", "authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys %u", 1)
	_, m := f.run("authkeys-list")
	assert.Equal(t, []any{helperproto.WarnDirectoryUsers}, m["warnings"])
	assert.Equal(t, "/usr/bin/sss_ssh_authorizedkeys %u", m["authorized_keys_command"])

	f.write("/etc/nsswitch.conf", "passwd: files ldap\n", 0o644)
	f.sshdFails = true
	_, m = f.run("authkeys-list")
	assert.ElementsMatch(t, []any{helperproto.WarnDirectoryUsers, helperproto.WarnSSHDUnreadable}, m["warnings"])
	assert.Equal(t, "none", m["authorized_keys_command"], "without sshd -T the default applies")
	paths := []any{}
	for _, fi := range filesOf(listUser(t, m, "deploy")) {
		paths = append(paths, fi["path"])
	}
	assert.Equal(t, []any{"/home/deploy/.ssh/authorized_keys", "/home/deploy/.ssh/authorized_keys2"}, paths)
}

func TestAuthKeysListStrictModes(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/home/deploy/.ssh/authorized_keys", "x\n", 0o600)
	strict := func() bool {
		_, m := f.run("authkeys-list")
		return filesOf(listUser(t, m, "deploy"))[0]["strict_modes_ok"].(bool)
	}
	assert.True(t, strict())
	require.NoError(t, os.Chmod(f.host("/home/deploy/.ssh/authorized_keys"), 0o666))
	assert.False(t, strict(), "a world-writable file is ignored by sshd")
	require.NoError(t, os.Chmod(f.host("/home/deploy/.ssh/authorized_keys"), 0o600))
	require.NoError(t, os.Chmod(f.host("/home/deploy"), 0o775))
	assert.False(t, strict(), "a group-writable home is ignored by sshd")
	require.NoError(t, os.Chmod(f.host("/home/deploy"), 0o755))
	assert.True(t, strict())
}

// A-13: a symlink that leaves the home directory is never a candidate, never listed, never read.
func TestEscapingSymlinkIsNotACandidate(t *testing.T) {
	f := newFixture(t)
	f.write("/etc/shadow", "root:SECRET-HASH:19000::::::\n", 0o600)
	require.NoError(t, os.Symlink("../../../etc/shadow", f.host("/home/deploy/.ssh/authorized_keys2")))

	_, m := f.run("authkeys-list")
	assert.Equal(t, []any{}, m["warnings"], "a valid path that is refused is flagged on the file, not globally")
	files := filesOf(listUser(t, m, "deploy"))
	require.Len(t, files, 2)
	assert.Equal(t, map[string]any{"path": "/home/deploy/.ssh/authorized_keys2", "exists": true, "size": float64(0), "sha256": "",
		"mode": "", "owner": "", "strict_modes_ok": false, "too_large": false, "unsupported": true}, files[1])

	for _, p := range []string{"/home/deploy/.ssh/authorized_keys2", "/etc/shadow", "/root/.ssh/../../etc/shadow"} {
		code, m := f.run("authkeys-read", p)
		assert.Equal(t, helperproto.ExitRefused, code, p)
		assert.Contains(t, []any{helperproto.CodePathNotAllowed, helperproto.CodeInvalidArgument}, m["code"], p)
		assert.NotContains(t, f.out.String(), "SECRET-HASH")
	}
}

func TestSymlinkInsideHomeIsFollowed(t *testing.T) {
	f := newFixture(t)
	f.write("/home/deploy/.ssh/authorized_keys", "real\n", 0o600)
	f.asUser("/home/deploy/.ssh", "/home/deploy/.ssh/authorized_keys") // as root: a symlink is followed into the user's directory only (A-1)
	require.NoError(t, os.Symlink("authorized_keys", f.host("/home/deploy/.ssh/authorized_keys2")))
	code, m := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys2")
	assert.Equal(t, 0, code)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("real\n")), m["content_b64"])
}

func TestAuthKeysRead(t *testing.T) {
	f := newFixture(t)
	content := "ssh-ed25519 AAAA deploy@laptop\n# comment\n"
	f.write("/home/deploy/.ssh/authorized_keys", content, 0o600)
	code, m := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
	assert.Equal(t, 0, code)
	assert.Equal(t, map[string]any{"ok": true, "path": "/home/deploy/.ssh/authorized_keys", "sha256": hexOf(content),
		"content_b64": base64.StdEncoding.EncodeToString([]byte(content)), "owner": "deploy"}, m)
	assert.Equal(t, []string{"authkeys-read /home/deploy/.ssh/authorized_keys"}, f.loggedLines())

	code, m = f.run("authkeys-read", "/root/.ssh/authorized_keys")
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeNotFound, m["code"])

	f.write("/home/deploy/.ssh/authorized_keys", strings.Repeat("#", helperproto.MaxAuthorizedKeysSize+1), 0o600)
	code, m = f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeTooLarge, m["code"])

	f.mkdir("/home/deploy/.ssh/authorized_keys2", 0o700)
	code, m = f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys2")
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeNotRegularFile, m["code"])
}

func TestAuthKeysListReportsLargeFiles(t *testing.T) {
	f := newFixture(t)
	f.write("/home/deploy/.ssh/authorized_keys", strings.Repeat("#", helperproto.MaxAuthorizedKeysSize+1), 0o600)
	_, m := f.run("authkeys-list")
	fi := filesOf(listUser(t, m, "deploy"))[0]
	assert.Equal(t, true, fi["too_large"])
	assert.Equal(t, "", fi["sha256"])
	assert.Equal(t, float64(helperproto.MaxAuthorizedKeysSize+1), fi["size"])
}

// A-12: an argument outside the vocabulary is refused before anything is read, run or logged.
func TestArgumentsOutsideTheVocabularyAreRefused(t *testing.T) {
	f := newFixture(t)
	for _, bad := range []string{
		"/home/deploy/.ssh/authorized_keys; cat /etc/shadow",
		"/home/deploy/.ssh/authorized_keys`id`",
		"/home/deploy/.ssh/$(id)",
		"/home/deploy/.ssh/authorized_keys\n/etc/shadow",
		"/home/kullanıcı/.ssh/authorized_keys",
		"/home/deploy/.ssh/../../../etc/shadow",
		"/home/deploy/.ssh//authorized_keys",
		"home/deploy/.ssh/authorized_keys",
		"-rf",
		"",
		strconv.Quote("/home/deploy/.ssh/authorized_keys"),
	} {
		code, m := f.run("authkeys-read", bad)
		assert.Equal(t, helperproto.ExitRefused, code, "%q", bad)
		assert.Equal(t, helperproto.CodeInvalidArgument, m["code"], "%q", bad)
	}
	assert.Zero(t, f.sshdCalls.Load(), "nothing ran")
	assert.Empty(t, f.loggedLines(), "nothing was logged with a hostile path")
}

// addZed adds a user that sorts after "deploy", so its sshd call runs between the scan's
// resolution of deploy's files and the read.
func (f *fixture) addZed() {
	f.t.Helper()
	f.mkdir("/home/zed", 0o755)
	f.write("/etc/passwd", f.read("/etc/passwd")+"zed:x:2000:2000::/home/zed:/bin/bash\n", 0o644)
}

// C-1: after the scan resolved ~/.ssh/authorized_keys, ~/.ssh becomes a symlink to a directory that
// holds a secret. Both openat2 and the component-wise fallback must refuse.
func TestAttackSwapRace(t *testing.T) {
	for _, tc := range []struct {
		name    string
		openat2 bool
		target  func(f *fixture) string
	}{
		{"openat2 absolute", true, func(f *fixture) string { return f.host("/etc/evil") }},
		{"openat2 relative", true, func(*fixture) string { return "../../etc/evil" }},
		{"fallback absolute", false, func(f *fixture) string { return f.host("/etc/evil") }},
		{"fallback relative", false, func(*fixture) string { return "../../etc/evil" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useOpenat2 = tc.openat2
			t.Cleanup(func() { useOpenat2 = true })
			f := newFixture(t)
			f.addZed()
			f.write("/home/deploy/.ssh/authorized_keys", "mine\n", 0o600)
			f.mkdir("/etc/evil", 0o755)
			f.write("/etc/evil/authorized_keys", "SECRET-HASH\n", 0o600)
			swapped := false
			f.onSSHD = func(args []string) {
				if len(args) == 3 && strings.HasPrefix(args[2], "user=zed") && !swapped {
					swapped = true
					require.NoError(t, os.Rename(f.host("/home/deploy/.ssh"), f.host("/home/deploy/.ssh.orig")))
					require.NoError(t, os.Symlink(tc.target(f), f.host("/home/deploy/.ssh")))
				}
			}
			code, m := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
			require.True(t, swapped, "the swap happened between scan and read")
			assert.Equal(t, helperproto.ExitRefused, code)
			assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
			assert.NotContains(t, f.out.String(), "SECRET")
			assert.NotContains(t, f.out.String(), hexOf("SECRET-HASH\n"))

			// The same swap during authkeys-list: the file is flagged and never hashed.
			require.NoError(t, os.Remove(f.host("/home/deploy/.ssh")))
			require.NoError(t, os.Rename(f.host("/home/deploy/.ssh.orig"), f.host("/home/deploy/.ssh")))
			swapped = false
			_, m = f.run("authkeys-list")
			require.True(t, swapped)
			fi := filesOf(listUser(t, m, "deploy"))[0]
			assert.Equal(t, true, fi["unsupported"])
			assert.Equal(t, "", fi["sha256"])
			assert.NotContains(t, f.out.String(), hexOf("SECRET-HASH\n"))
		})
	}
}

// N-3: a symlink to a sibling directory inside the home appears after the scan. Both openat2 and
// the walk refuse it: the scan saw no symlink, so none may be followed at the open (A-1 of the final
// review: the sibling could be a root-owned directory of the home).
func TestIntermediateSymlinkAfterScan(t *testing.T) {
	for _, openat2OK := range []bool{true, false} {
		t.Run(fmt.Sprintf("openat2=%v", openat2OK), func(t *testing.T) {
			useOpenat2 = openat2OK
			t.Cleanup(func() { useOpenat2 = true })
			f := newFixture(t)
			f.addZed()
			f.write("/home/deploy/.ssh/authorized_keys", "real\n", 0o600)
			swapped := false
			f.onSSHD = func(args []string) {
				if len(args) == 3 && strings.HasPrefix(args[2], "user=zed") && !swapped {
					swapped = true
					require.NoError(t, os.Rename(f.host("/home/deploy/.ssh"), f.host("/home/deploy/.ssh.orig")))
					require.NoError(t, os.Symlink(".ssh.orig", f.host("/home/deploy/.ssh")))
				}
			}
			code, m := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
			require.True(t, swapped)
			assert.Equal(t, helperproto.ExitRefused, code)
			assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
		})
	}
}

// N-2: openat2 errors that mean "not supported here" fall back to the walk; refusals do not.
func TestOpenat2ErrorsAndFallback(t *testing.T) {
	orig := openat2
	t.Cleanup(func() { openat2 = orig })
	for _, tc := range []struct {
		err      error
		wantCode int
	}{
		{unix.ENOSYS, 0}, {unix.EPERM, 0}, {unix.EINVAL, 0},
		{unix.EXDEV, helperproto.ExitRefused}, {unix.ELOOP, helperproto.ExitRefused}, {unix.EAGAIN, helperproto.ExitFailed},
	} {
		openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, tc.err }
		f := newFixture(t)
		f.write("/home/deploy/.ssh/authorized_keys", "real\n", 0o600)
		code, _ := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
		assert.Equal(t, tc.wantCode, code, "%v", tc.err)
	}
}

// N-1: root-owned files are accepted only where root controls the directory.
func TestOwnerRules(t *testing.T) {
	user := account{name: "deploy", uid: 1000}
	const writable, locked = 0o40775, 0o40755
	assert.NoError(t, ownerOK(1000, 1000, writable, user), "the user's own file")
	assert.NoError(t, ownerOK(0, 0, locked, user), "root-owned file in a root-owned 0755 directory")
	assert.ErrorIs(t, ownerOK(0, 1000, locked, user), errUnsafe, "stale root inode in the user's directory")
	assert.ErrorIs(t, ownerOK(0, 0, writable, user), errUnsafe, "root-owned file in a group-writable directory")
	assert.ErrorIs(t, ownerOK(2000, 0, locked, user), errUnsafe, "another user's file")
	assert.NoError(t, ownerOK(0, 1000, writable, account{name: "root", uid: 0}), "root's own files")
}

// N-1 end to end (needs root to create a root-owned file in a user-owned directory).
func TestStaleRootInodeInUserDirIsRefused(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to chown; TestOwnerRules covers the rule")
	}
	f := newFixture(t)
	f.write("/home/deploy/.ssh/authorized_keys", "stale shadow\n", 0o600)
	require.NoError(t, os.Chown(f.host("/home/deploy/.ssh"), f.uid, f.uid))
	code, m := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeUnsafeFile, m["code"])
	// Root-owned file in a root-owned directory is fine.
	require.NoError(t, os.Chown(f.host("/home/deploy/.ssh"), 0, 0))
	code, _ = f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
	assert.Equal(t, 0, code)
}

// I-1: a hard link to a file outside the home is refused (spec §13.3).
func TestAttackHardLink(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/etc/shadow", "root:SECRET-HASH:19000::::::\n", 0o600)
	require.NoError(t, os.Link(f.host("/etc/shadow"), f.host("/home/deploy/.ssh/authorized_keys")))
	code, m := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeUnsafeFile, m["code"])
	assert.NotContains(t, f.out.String(), "SECRET")
	_, m = f.run("authkeys-list")
	fi := filesOf(listUser(t, m, "deploy"))[0]
	assert.Equal(t, true, fi["unsupported"])
	assert.Equal(t, "", fi["sha256"])
}

func TestAttackForeignOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("a root-owned file is accepted; the test needs a non-root owner")
	}
	f := newFixture(t)
	f.write("/etc/passwd", strings.Replace(f.read("/etc/passwd"), fmt.Sprintf("deploy:x:%d:%d", f.uid, f.uid), "deploy:x:7777:7777", 1), 0o644)
	f.write("/home/deploy/.ssh/authorized_keys", "x\n", 0o600)
	code, m := f.run("authkeys-read", "/home/deploy/.ssh/authorized_keys")
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeUnsafeFile, m["code"])
}

// I-2: a failing per-user "sshd -T -C" is flagged, not silently replaced by the global answer.
func TestPerUserSSHDFailureIsFlagged(t *testing.T) {
	f := newFixture(t)
	f.cFails = true
	_, m := f.run("authkeys-list")
	assert.Equal(t, []any{helperproto.WarnSSHDUnreadable}, m["warnings"])
	assert.Equal(t, true, listUser(t, m, "deploy")["sshd_unreadable"])

	f.cFails, f.sshdFails = false, true // the global call fails: every user is unreadable (N-4)
	_, m = f.run("authkeys-list")
	for _, u := range m["users"].([]any) {
		assert.Equal(t, true, u.(map[string]any)["sshd_unreadable"], u.(map[string]any)["user"])
	}
	f.sshdFails, f.cFails = false, true

	f.cFails = false
	f.perUser[deployCtx] = "authorizedkeysfile .ssh/authorized_keys\nauthorizedkeyscommand /usr/bin/x %u\n"
	_, m = f.run("authkeys-list")
	d := listUser(t, m, "deploy")
	assert.Equal(t, false, d["sshd_unreadable"])
	assert.Equal(t, "/usr/bin/x %u", d["authorized_keys_command"])
	assert.Equal(t, "none", listUser(t, m, "root")["authorized_keys_command"])
	assert.Equal(t, "none", m["authorized_keys_command"])
}

func TestTooManyUsers(t *testing.T) {
	f := newFixture(t)
	var b strings.Builder
	for i := 0; i < 205; i++ {
		fmt.Fprintf(&b, "u%d:x:%d:%d::/home/deploy:/bin/bash\n", i, 3000+i, 3000+i)
	}
	f.write("/etc/passwd", f.read("/etc/passwd")+b.String(), 0o644)
	_, m := f.run("authkeys-list")
	assert.Equal(t, []any{helperproto.WarnTooManyUsers}, m["warnings"])
	assert.Len(t, m["users"], 200)
}

// D13: an expansion that is a valid path but is refused is listed as unsupported; one that is not
// a valid path only raises the global warning.
func TestUnsupportedPatterns(t *testing.T) {
	f := newFixture(t)
	f.global = "authorizedkeysfile .ssh/authorized_keys /outside/%u .ssh/with%20space\n"
	_, m := f.run("authkeys-list")
	var paths []any
	for _, fi := range filesOf(listUser(t, m, "deploy")) {
		paths = append(paths, fi["path"])
	}
	assert.Equal(t, []any{"/home/deploy/.ssh/authorized_keys", "/outside/deploy"}, paths)
	assert.Equal(t, []any{helperproto.WarnUnsupportedPath}, m["warnings"])
}
