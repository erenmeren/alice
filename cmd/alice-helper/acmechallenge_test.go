//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

// The HTTP-01 webroot commands (protocol 7, ACME Task 7). The helper writes and removes one token
// file in helperproto.ACMEChallengeDir, a directory the administrator created and published in
// Nginx; it never creates a directory, never follows a link and touches no other path.

const acmeDir = helperproto.ACMEChallengeDir

var (
	acmeToken = strings.Repeat("T", 43)
	acmeThumb = strings.Repeat("h", 42) + "_"
	acmeBody  = acmeToken + "." + acmeThumb
)

// acmeFixture is the helper fixture with the challenge directory prepared as the guide says.
func acmeFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.mkdir(acmeDir, 0o755)
	for _, d := range []string{"/var/www", helperproto.ACMEWebroot, helperproto.ACMEWebroot + "/.well-known"} {
		require.NoError(t, os.Chmod(f.host(d), 0o755))
	}
	return f
}

func (f *fixture) put(token, body string) (int, map[string]any) {
	f.t.Helper()
	f.s.stdin = strings.NewReader(body)
	return f.run(helperproto.SubACMEChallengePut, "--token", token)
}

func (f *fixture) rm(token string) (int, map[string]any) {
	f.t.Helper()
	return f.run(helperproto.SubACMEChallengeRm, "--token", token)
}

// tree lists every path below the fixture root with its type, mode and content (for regular files):
// the proof that a command touched nothing it should not.
func (f *fixture) tree() map[string]string {
	f.t.Helper()
	out := map[string]string{}
	require.NoError(f.t, filepath.WalkDir(f.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		v := info.Mode().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own temporary tree
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			v += " -> " + target
		}
		out[strings.TrimPrefix(p, f.root)] = v
		return nil
	}))
	return out
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, d := range des {
		names = append(names, d.Name())
	}
	sort.Strings(names)
	return names
}

func TestACMEChallengePutWritesOneFile(t *testing.T) {
	f := acmeFixture(t)
	before := f.tree()
	code, m := f.put(acmeToken, acmeBody)
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, map[string]any{"ok": true, "path": acmeDir + "/" + acmeToken, "replaced": false}, m)
	after := f.tree()
	file := acmeDir + "/" + acmeToken
	assert.Equal(t, "-rw-r--r-- "+acmeBody, after[file], "the key authorization, mode 0644, nothing appended")
	delete(after, file)
	assert.Equal(t, before, after, "no other path changed, no temporary file left")
	assert.Equal(t, []string{helperproto.SubACMEChallengePut + " " + file}, f.loggedLines())
}

func TestACMEChallengePutModeIgnoresTheUmask(t *testing.T) {
	old := syscall.Umask(0o077) // main sets it
	defer syscall.Umask(old)
	f := acmeFixture(t)
	code, m := f.put(acmeToken, acmeBody)
	require.Equal(t, helperproto.ExitOK, code, m)
	st, err := os.Lstat(f.host(acmeDir + "/" + acmeToken))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), st.Mode(), "Nginx's workers must read it")
}

func TestACMEChallengePutReplacesAtomically(t *testing.T) {
	f := acmeFixture(t)
	code, m := f.put(acmeToken, acmeBody)
	require.Equal(t, helperproto.ExitOK, code, m)
	file := f.host(acmeDir + "/" + acmeToken)
	var first unix.Stat_t
	require.NoError(t, unix.Lstat(file, &first))
	other := acmeToken + "." + strings.Repeat("Z", 43)
	code, m = f.put(acmeToken, other)
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, true, m["replaced"])
	b, err := os.ReadFile(file) //nolint:gosec // G304: the test's tree
	require.NoError(t, err)
	assert.Equal(t, other, string(b))
	var second unix.Stat_t
	require.NoError(t, unix.Lstat(file, &second))
	assert.NotEqual(t, first.Ino, second.Ino, "a new file was renamed into place, the old one was not rewritten")
	assert.Equal(t, []string{acmeToken}, entries(t, f.host(acmeDir)))
}

// A token that starts with "-" is base64url like any other; the helper reads it as --token's value.
func TestACMEChallengeLeadingDashToken(t *testing.T) {
	f := acmeFixture(t)
	tok := "-" + strings.Repeat("a", 42)
	code, m := f.put(tok, tok+"."+acmeThumb)
	require.Equal(t, helperproto.ExitOK, code, m)
	code, m = f.rm(tok)
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, true, m["removed"])
}

func TestACMEChallengeRm(t *testing.T) {
	f := acmeFixture(t)
	before := f.tree()
	code, m := f.put(acmeToken, acmeBody)
	require.Equal(t, helperproto.ExitOK, code, m)
	code, m = f.rm(acmeToken)
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, map[string]any{"ok": true, "path": acmeDir + "/" + acmeToken, "removed": true}, m)
	assert.Equal(t, before, f.tree(), "back to the prepared tree")
	code, m = f.rm(acmeToken)
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, false, m["removed"], "a missing file is success")
	assert.Contains(t, f.loggedLines(), helperproto.SubACMEChallengeRm+" "+acmeDir+"/"+acmeToken)
}

func TestACMEChallengeRmWithoutDirectory(t *testing.T) {
	f := newFixture(t) // no /var/www at all
	before := f.tree()
	code, m := f.rm(acmeToken)
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, false, m["removed"], "nothing can be there to remove")
	assert.Equal(t, before, f.tree(), "no directory is created")
}

func TestACMEChallengePutNeedsThePreparedDirectory(t *testing.T) {
	for name, prep := range map[string]func(f *fixture){
		"no /var/www":       func(*fixture) {},
		"no webroot":        func(f *fixture) { f.mkdir("/var/www", 0o755) },
		"no .well-known":    func(f *fixture) { f.mkdir(helperproto.ACMEWebroot, 0o755) },
		"no acme-challenge": func(f *fixture) { f.mkdir(helperproto.ACMEWebroot+"/.well-known", 0o755) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			prep(f)
			before := f.tree()
			code, m := f.put(acmeToken, acmeBody)
			assert.Equal(t, helperproto.ExitPrecondition, code)
			assert.Equal(t, helperproto.CodeNotFound, m["code"])
			assert.Equal(t, before, f.tree(), "the helper never creates a directory")
		})
	}
}

// Every refusal leaves the tree exactly as it was (a link's target included).
func TestACMEChallengeRefusals(t *testing.T) {
	type tc struct {
		prep func(f *fixture)
		args []string // nil: --token acmeToken
		body string   // put's stdin ("" means acmeBody)
		put  [2]any   // exit, code of put ("": not run)
		rm   [2]any   // exit, code of rm ("": not run)
	}
	outside := "/srv/elsewhere" // a real directory a link could point at
	mkOutside := func(f *fixture) {
		f.mkdir(outside+"/.well-known/acme-challenge", 0o755)
		f.write(outside+"/.well-known/acme-challenge/"+acmeToken, "precious", 0o644)
	}
	// An absolute target is made real (inside the fixture), so a write through the link would show
	// in the tree.
	link := func(f *fixture, guest, target string) {
		if strings.HasPrefix(target, "/") {
			target = f.host(target)
		}
		require.NoError(f.t, os.Symlink(target, f.host(guest)))
	}
	refusedArg := [2]any{helperproto.ExitRefused, helperproto.CodeInvalidArgument}
	usage := [2]any{helperproto.ExitRefused, helperproto.CodeUsage}
	pathNotAllowed := [2]any{helperproto.ExitRefused, helperproto.CodePathNotAllowed}
	insecure := [2]any{helperproto.ExitRefused, helperproto.CodeInsecurePermissions}
	notRegular := [2]any{helperproto.ExitRefused, helperproto.CodeNotRegularFile}
	cases := map[string]tc{
		"token 21 characters":     {args: []string{"--token", strings.Repeat("a", 21)}, put: refusedArg, rm: refusedArg},
		"token 129 characters":    {args: []string{"--token", strings.Repeat("a", 129)}, put: refusedArg, rm: refusedArg},
		"traversal ..":            {args: []string{"--token", "../../../../etc/" + strings.Repeat("a", 22)}, put: refusedArg, rm: refusedArg},
		"bare ..":                 {args: []string{"--token", ".."}, put: refusedArg, rm: refusedArg},
		"slash":                   {args: []string{"--token", strings.Repeat("a", 11) + "/" + strings.Repeat("a", 11)}, put: refusedArg, rm: refusedArg},
		"absolute":                {args: []string{"--token", "/etc/" + strings.Repeat("a", 22)}, put: refusedArg, rm: refusedArg},
		"dot":                     {args: []string{"--token", strings.Repeat("a", 22) + ".tmp"}, put: refusedArg, rm: refusedArg},
		"NUL":                     {args: []string{"--token", strings.Repeat("a", 22) + "\x00x"}, put: refusedArg, rm: refusedArg},
		"unicode":                 {args: []string{"--token", strings.Repeat("a", 21) + "ç"}, put: refusedArg, rm: refusedArg},
		"unicode slash lookalike": {args: []string{"--token", strings.Repeat("a", 11) + "∕" + strings.Repeat("a", 11)}, put: refusedArg, rm: refusedArg},
		"space":                   {args: []string{"--token", strings.Repeat("a", 22) + " x"}, put: refusedArg, rm: refusedArg},
		"no arguments":            {args: []string{}, put: usage, rm: usage},
		"no --token":              {args: []string{acmeToken}, put: usage, rm: usage},
		"--token=":                {args: []string{"--token=" + acmeToken}, put: usage, rm: usage},
		"extra argument":          {args: []string{"--token", acmeToken, "--path", "/etc"}, put: usage, rm: usage},
		"oversize body":           {body: acmeBody + strings.Repeat("A", helperproto.MaxACMEBody+1-len(acmeBody)), put: [2]any{helperproto.ExitRefused, helperproto.CodeTooLarge}},
		"body of another token":   {body: strings.Repeat("U", 43) + "." + acmeThumb, put: [2]any{helperproto.ExitRefused, helperproto.CodeBadContent}},
		"body with newline":       {body: acmeBody + "\n", put: [2]any{helperproto.ExitRefused, helperproto.CodeBadContent}},
		"body bad charset":        {body: acmeToken + "." + strings.Repeat("h", 42) + "/", put: [2]any{helperproto.ExitRefused, helperproto.CodeBadContent}},
		"body cut short":          {body: acmeBody[:len(acmeBody)-1], put: [2]any{helperproto.ExitRefused, helperproto.CodeBadContent}},
		"NUL body":                {body: "\x00", put: [2]any{helperproto.ExitRefused, helperproto.CodeBadContent}},
		"symlinked /var/www": {prep: func(f *fixture) {
			mkOutside(f)
			f.mkdir("/var", 0o755)
			f.mkdir("/srv/www/alice-acme/.well-known/acme-challenge", 0o755)
			link(f, "/var/www", "/srv/www")
		}, put: pathNotAllowed, rm: pathNotAllowed},
		"symlinked webroot": {prep: func(f *fixture) {
			mkOutside(f)
			f.mkdir("/var/www", 0o755)
			link(f, helperproto.ACMEWebroot, outside)
		}, put: pathNotAllowed, rm: pathNotAllowed},
		"symlinked .well-known": {prep: func(f *fixture) {
			mkOutside(f)
			f.mkdir(helperproto.ACMEWebroot, 0o755)
			link(f, helperproto.ACMEWebroot+"/.well-known", outside+"/.well-known")
		}, put: pathNotAllowed, rm: pathNotAllowed},
		"symlinked challenge directory": {prep: func(f *fixture) {
			mkOutside(f)
			f.mkdir(helperproto.ACMEWebroot+"/.well-known", 0o755)
			link(f, acmeDir, outside+"/.well-known/acme-challenge")
		}, put: pathNotAllowed, rm: pathNotAllowed},
		"relative symlink challenge directory": {prep: func(f *fixture) {
			f.mkdir(helperproto.ACMEWebroot+"/.well-known/real", 0o755)
			link(f, acmeDir, "real")
		}, put: pathNotAllowed, rm: pathNotAllowed},
		"challenge directory is a file": {prep: func(f *fixture) {
			f.mkdir(helperproto.ACMEWebroot+"/.well-known", 0o755)
			f.write(acmeDir, "x", 0o644)
		}, put: pathNotAllowed, rm: pathNotAllowed},
		"world-writable challenge directory": {prep: func(f *fixture) {
			f.mkdir(acmeDir, 0o755)
			require.NoError(f.t, os.Chmod(f.host(acmeDir), 0o777))
		}, put: insecure, rm: insecure},
		"sticky world-writable challenge directory": {prep: func(f *fixture) {
			f.mkdir(acmeDir, 0o755)
			require.NoError(f.t, os.Chmod(f.host(acmeDir), 0o777|os.ModeSticky))
		}, put: insecure, rm: insecure},
		"group-writable .well-known": {prep: func(f *fixture) {
			f.mkdir(acmeDir, 0o755)
			require.NoError(f.t, os.Chmod(f.host(helperproto.ACMEWebroot+"/.well-known"), 0o775))
		}, put: insecure, rm: insecure},
		"world-writable /var/www": {prep: func(f *fixture) {
			f.mkdir(acmeDir, 0o755)
			require.NoError(f.t, os.Chmod(f.host("/var/www"), 0o777))
		}, put: insecure, rm: insecure},
		"symlink at the token name": {prep: func(f *fixture) {
			f.mkdir(acmeDir, 0o755)
			f.write("/etc/shadow", "root:secret", 0o600)
			link(f, acmeDir+"/"+acmeToken, "/etc/shadow")
		}, put: notRegular, rm: notRegular},
		"dangling symlink at the token name": {prep: func(f *fixture) {
			f.mkdir(acmeDir, 0o755)
			link(f, acmeDir+"/"+acmeToken, "/etc/created-by-follow")
		}, put: notRegular, rm: notRegular},
		"directory at the token name": {prep: func(f *fixture) {
			f.mkdir(acmeDir+"/"+acmeToken, 0o755)
		}, put: notRegular, rm: notRegular},
		"fifo at the token name": {prep: func(f *fixture) {
			f.mkdir(acmeDir, 0o755)
			require.NoError(f.t, unix.Mkfifo(f.host(acmeDir+"/"+acmeToken), 0o644))
		}, put: notRegular, rm: notRegular},
	}
	for name, c := range cases {
		for _, sub := range []string{helperproto.SubACMEChallengePut, helperproto.SubACMEChallengeRm} {
			want := c.put
			if sub == helperproto.SubACMEChallengeRm {
				want = c.rm
			}
			if want[0] == nil {
				continue
			}
			t.Run(name+"/"+sub, func(t *testing.T) {
				f := newFixture(t)
				if c.prep != nil {
					c.prep(f)
				} else {
					f.mkdir(acmeDir, 0o755)
				}
				args := c.args
				if args == nil {
					args = []string{"--token", acmeToken}
				}
				body := c.body
				if body == "" {
					body = acmeBody
				}
				before := f.tree()
				f.s.stdin = strings.NewReader(body)
				code, m := f.run(append([]string{sub}, args...)...)
				assert.Equal(t, want[0], code, m)
				assert.Equal(t, want[1], m["code"], m)
				assert.Equal(t, false, m["ok"])
				assert.Equal(t, before, f.tree(), "nothing changed")
			})
		}
	}
}

func TestACMEChallengeOnASpecialFileSystem(t *testing.T) {
	f := acmeFixture(t)
	f.s.fsMagic = func(int) (int64, error) { return unix.FUSE_SUPER_MAGIC, nil }
	before := f.tree()
	code, m := f.put(acmeToken, acmeBody)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	code, m = f.rm(acmeToken)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	assert.Equal(t, before, f.tree())
}

// A directory swapped for a link between its check and its open is refused (the walk opens every
// element with O_NOFOLLOW and compares the opened inode with the checked one).
func TestACMEChallengeDirectorySwappedDuringTheWalk(t *testing.T) {
	for _, elem := range helperproto.ACMEChallengeDirElems()[1:] {
		t.Run(elem, func(t *testing.T) {
			f := acmeFixture(t)
			f.mkdir("/srv/decoy/"+elem, 0o755)
			f.s.walkHook = func(name string) {
				if name != elem {
					return
				}
				var guest string
				for _, e := range helperproto.ACMEChallengeDirElems() {
					guest += "/" + e
					if e == elem {
						break
					}
				}
				require.NoError(t, os.Rename(f.host(guest), f.host("/srv/moved")))
				require.NoError(t, os.Symlink(f.host("/srv/decoy/"+elem), f.host(guest)))
			}
			code, m := f.put(acmeToken, acmeBody)
			assert.Equal(t, helperproto.ExitRefused, code, m)
			assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
			assert.Empty(t, entries(t, f.host("/srv/decoy/"+elem)), "nothing written through the link")
		})
	}
}

// A directory replaced by another real directory between its check and its open is refused too.
func TestACMEChallengeDirectoryReplacedDuringTheWalk(t *testing.T) {
	f := acmeFixture(t)
	f.s.walkHook = func(name string) {
		if name != "acme-challenge" {
			return
		}
		require.NoError(t, os.Rename(f.host(acmeDir), f.host("/srv-moved")))
		f.mkdir(acmeDir, 0o755)
	}
	code, m := f.put(acmeToken, acmeBody)
	assert.Equal(t, helperproto.ExitRefused, code, m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
}

func TestACMEChallengePutFailedRenameLeavesNoTemporaryFile(t *testing.T) {
	f := acmeFixture(t)
	code, m := f.put(acmeToken, acmeBody)
	require.Equal(t, helperproto.ExitOK, code, m)
	f.s.beforeRename = func() error { return errors.New("disk gone") }
	code, m = f.put(acmeToken, acmeToken+"."+strings.Repeat("Z", 43))
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
	assert.Equal(t, []string{acmeToken}, entries(t, f.host(acmeDir)), "the temporary file is removed")
	b, err := os.ReadFile(f.host(acmeDir + "/" + acmeToken))
	require.NoError(t, err)
	assert.Equal(t, acmeBody, string(b), "the published file is unchanged")
}

func TestACMEChallengeTemporaryNamesAreFreshAndNeverTokens(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		n, err := acmeTempName()
		require.NoError(t, err)
		assert.False(t, seen[n])
		seen[n] = true
		assert.True(t, strings.HasPrefix(n, ".alice-acme-"), n)
		assert.False(t, helperproto.ValidACMEToken(n), "a temporary name can never be a token: %s", n)
		assert.Len(t, n, len(".alice-acme-")+32)
	}
}

// A temporary name that already exists (a planted file or link) is never opened: O_EXCL makes the
// helper pick another name.
func TestACMEChallengeTemporaryNameCollision(t *testing.T) {
	f := acmeFixture(t)
	planted := ".alice-acme-" + strings.Repeat("0", 32)
	require.NoError(t, os.Symlink("/etc/shadow", f.host(acmeDir+"/"+planted)))
	names := []string{planted, ".alice-acme-" + strings.Repeat("1", 32)}
	old := acmeTempName
	acmeTempName = func() (string, error) {
		n := names[0]
		names = names[1:]
		return n, nil
	}
	defer func() { acmeTempName = old }()
	code, m := f.put(acmeToken, acmeBody)
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, []string{planted, acmeToken}, entries(t, f.host(acmeDir)))
	target, err := os.Readlink(f.host(acmeDir + "/" + planted))
	require.NoError(t, err)
	assert.Equal(t, "/etc/shadow", target, "the planted link is untouched")
}

func TestACMEChallengeNeedsRoot(t *testing.T) {
	f := acmeFixture(t)
	f.s.euid = func() int { return 1000 }
	code, m := f.put(acmeToken, acmeBody)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeNotRoot, m["code"])
	code, m = f.rm(acmeToken)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeNotRoot, m["code"])
}

func TestACMEChallengeStdinReadError(t *testing.T) {
	f := acmeFixture(t)
	f.s.stdin = failingReader{}
	code, m := f.run(helperproto.SubACMEChallengePut, "--token", acmeToken)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
	assert.Empty(t, entries(t, f.host(acmeDir)))
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection dropped") }

// As root (the real case, in a throwaway container): the file is root's with mode 0644 under the
// helper's umask 077; a challenge directory or a directory above it owned by another user is
// refused, even with mode 0755 (its owner could swap entries).
func TestACMEChallengeAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (chown)")
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	f := acmeFixture(t)
	f.s.rootUID, f.s.rootGID = 0, 0
	code, m := f.put(acmeToken, acmeBody)
	require.Equal(t, helperproto.ExitOK, code, m)
	var st unix.Stat_t
	require.NoError(t, unix.Lstat(f.host(acmeDir+"/"+acmeToken), &st))
	assert.Equal(t, uint32(0), st.Uid)
	assert.Equal(t, uint32(0o644), st.Mode&0o7777)
	for _, d := range []string{"/var/www", helperproto.ACMEWebroot, helperproto.ACMEWebroot + "/.well-known", acmeDir} {
		t.Run(d, func(t *testing.T) {
			require.NoError(t, os.Chown(f.host(d), 1000, 1000))
			defer func() { require.NoError(t, os.Chown(f.host(d), 0, 0)) }()
			before := f.tree()
			code, m := f.put(acmeToken, acmeToken+"."+strings.Repeat("Z", 43))
			assert.Equal(t, helperproto.ExitRefused, code, m)
			assert.Equal(t, helperproto.CodeInsecurePermissions, m["code"])
			code, m = f.rm(acmeToken)
			assert.Equal(t, helperproto.ExitRefused, code, m)
			assert.Equal(t, helperproto.CodeInsecurePermissions, m["code"])
			assert.Equal(t, before, f.tree())
		})
	}
	code, m = f.rm(acmeToken)
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, true, m["removed"])
}

// I/O failures answer IO_ERROR (exit 4) and leave the directory as it was.
func TestACMEChallengeIOFailures(t *testing.T) {
	t.Run("temporary name", func(t *testing.T) {
		f := acmeFixture(t)
		old := acmeTempName
		acmeTempName = func() (string, error) { return "", errors.New("no entropy") }
		defer func() { acmeTempName = old }()
		code, m := f.put(acmeToken, acmeBody)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		assert.Empty(t, entries(t, f.host(acmeDir)))
	})
	t.Run("every temporary name taken", func(t *testing.T) {
		f := acmeFixture(t)
		planted := ".alice-acme-" + strings.Repeat("0", 32)
		f.write(acmeDir+"/"+planted, "x", 0o644)
		old := acmeTempName
		acmeTempName = func() (string, error) { return planted, nil }
		defer func() { acmeTempName = old }()
		code, m := f.put(acmeToken, acmeBody)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		assert.Equal(t, []string{planted}, entries(t, f.host(acmeDir)), "the planted file is never opened or removed")
	})
	t.Run("read-only directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes a read-only directory")
		}
		f := acmeFixture(t)
		code, m := f.put(acmeToken, acmeBody)
		require.Equal(t, helperproto.ExitOK, code, m)
		require.NoError(t, os.Chmod(f.host(acmeDir), 0o555))
		defer func() { _ = os.Chmod(f.host(acmeDir), 0o755) }()
		code, m = f.put(acmeToken, acmeToken+"."+strings.Repeat("Z", 43))
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		code, m = f.rm(acmeToken)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		assert.Equal(t, []string{acmeToken}, entries(t, f.host(acmeDir)))
	})
	t.Run("unsearchable directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root searches any directory")
		}
		f := acmeFixture(t)
		require.NoError(t, os.Chmod(f.host(helperproto.ACMEWebroot+"/.well-known"), 0o600))
		defer func() { _ = os.Chmod(f.host(helperproto.ACMEWebroot+"/.well-known"), 0o755) }()
		code, m := f.put(acmeToken, acmeBody)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		code, m = f.rm(acmeToken)
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
	})
	t.Run("token entry unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root searches any directory")
		}
		f := acmeFixture(t)
		// readable but not searchable: the directory opens, a name in it cannot be looked up
		require.NoError(t, os.Chmod(f.host(acmeDir), 0o444))
		defer func() { _ = os.Chmod(f.host(acmeDir), 0o755) }()
		code, m := f.rm(acmeToken)
		assert.Equal(t, helperproto.ExitFailed, code, m)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
	})
}

// A caller that never closes stdin cannot keep the helper: the read ends with the helper's budget.
func TestACMEChallengePutStdinBoundedByTheBudget(t *testing.T) {
	f := acmeFixture(t)
	r, w := io.Pipe()
	defer func() { _ = w.Close() }()
	f.s.stdin = r
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := cmdACMEChallengePut(ctx, f.s, []string{"--token", acmeToken})
	var he *helperError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, helperproto.CodeIOError, he.code)
	assert.Equal(t, helperproto.ExitFailed, he.exit)
	assert.Empty(t, entries(t, f.host(acmeDir)))
}

// Fidelity: the emulator of the fake SSH server (linuxsshtest) answers the HTTP-01 commands as the helper
// does: the same exit status, error code, path and replaced/removed flags for the same scenario.
func TestEmulatorFidelityACMEChallenge(t *testing.T) {
	type step struct {
		sub, token, body string
	}
	long := strings.Repeat("a", 129)
	scenarios := map[string][]step{
		"put, replace, rm, rm again": {
			{helperproto.SubACMEChallengePut, acmeToken, acmeBody},
			{helperproto.SubACMEChallengePut, acmeToken, acmeToken + "." + strings.Repeat("Z", 43)},
			{helperproto.SubACMEChallengeRm, acmeToken, ""},
			{helperproto.SubACMEChallengeRm, acmeToken, ""},
		},
		"refusals": {
			{helperproto.SubACMEChallengePut, long, long + "." + acmeThumb},
			{helperproto.SubACMEChallengeRm, strings.Repeat("a", 22) + "/x", ""},
			{helperproto.SubACMEChallengePut, acmeToken, acmeBody + strings.Repeat("A", helperproto.MaxACMEBody)},
			{helperproto.SubACMEChallengePut, acmeToken, acmeBody + "\n"},
			{helperproto.SubACMEChallengePut, acmeToken, ""},
		},
	}
	for name, steps := range scenarios {
		for _, prepared := range []bool{true, false} {
			t.Run(name+"/prepared="+strconv.FormatBool(prepared), func(t *testing.T) {
				f := newFixture(t)
				emu := linuxsshtest.NewEmulator()
				emu.SetACMEChallengeDir(prepared)
				if prepared {
					f.mkdir(acmeDir, 0o755)
				}
				h := emu.Handler()
				for i, st := range steps {
					f.s.stdin = strings.NewReader(st.body)
					code, real := f.run(st.sub, "--token", st.token)
					line := "sudo -n " + helperproto.HelperPath + " " + st.sub + " --token '" + st.token + "'"
					r := h(line, []byte(st.body))
					var emuAns map[string]any
					require.NoError(t, json.Unmarshal(r.Stdout, &emuAns), "%d: %s", i, r.Stderr)
					assert.Equal(t, code, r.Exit, "step %d exit", i)
					delete(real, "message")
					delete(emuAns, "message")
					assert.Equal(t, real, emuAns, "step %d answer", i)
				}
			})
		}
	}
}
