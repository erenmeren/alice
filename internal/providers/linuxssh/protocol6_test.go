package linuxssh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

// rewriteList answers authkeys-list with the emulator's answer changed by edit; every other
// command goes to the emulator.
func rewriteList(t *testing.T, e *provEnv, edit func(*helperproto.AuthKeysListResponse)) {
	t.Helper()
	emu := e.emu.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		r := emu(cmd, stdin)
		if !strings.Contains(cmd, " "+helperproto.SubAuthKeysList) {
			return r
		}
		var list helperproto.AuthKeysListResponse
		require.NoError(t, json.Unmarshal(r.Stdout, &list))
		edit(&list)
		raw, err := json.Marshal(list)
		require.NoError(t, err)
		return linuxsshtest.Response{Stdout: append(raw, '\n')}
	})
}

func countReads(e *provEnv) int {
	n := 0
	for _, c := range e.srv.Commands() {
		if strings.Contains(c, " "+helperproto.SubAuthKeysRead+" ") {
			n++
		}
	}
	return n
}

// AUD-03: accounts with a dot, a capital or a final $ and a home written with a trailing slash are
// listed with their keys; entries the helper could not list become warnings with the uid, and the
// account list is not complete (inventory then never marks a vanished user's keys missing on this
// server).
func TestDiscoverReportsUnlistedAccounts(t *testing.T) {
	e := newProvEnv(t)
	kj, fpj := keyLine(t, "ed25519", "", "john@laptop")
	kd, fpd := keyLine(t, "ed25519", "", "deploy2@laptop")
	ks, fps := keyLine(t, "ed25519", "", "svc@laptop")
	e.emu.AddUser("john.doe", 1005, "/home/john.doe")
	e.emu.SetFile("/home/john.doe/.ssh/authorized_keys", []byte(kj+"\n"))
	e.emu.AddUser("Deploy2", 1006, "/home/Deploy2/")
	e.emu.SetFile("/home/Deploy2/.ssh/authorized_keys", []byte(kd+"\n"))
	e.emu.AddUser("svc$", 1007, "/home/svc")
	e.emu.SetFile("/home/svc/.ssh/authorized_keys", []byte(ks+"\n"))
	e.emu.AddUser("bad name", 1009, "/home/bad")
	e.emu.AddUser("dotdot", 1010, "/home/x/../dotdot")
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.False(t, res.AccountsComplete)
	assert.False(t, res.Partial, "every listed file was read")
	assert.Subset(t, res.Accounts, []string{"john.doe", "Deploy2", "svc$", "dotdot"})
	got := map[string]string{}
	for _, k := range res.SSHKeys {
		got[k.Fingerprint] = k.OSUser + " " + k.FilePath
	}
	assert.Equal(t, "john.doe /home/john.doe/.ssh/authorized_keys", got[fpj])
	assert.Equal(t, "Deploy2 /home/Deploy2/.ssh/authorized_keys", got[fpd], "the home is cleaned")
	assert.Equal(t, "svc$ /home/svc/.ssh/authorized_keys", got[fps])
	assert.Contains(t, res.Warnings, providers.Warning{Code: helperproto.WarnAccountNameUnsupported, Params: map[string]string{"uid": "1009"}})
	assert.Contains(t, res.Warnings, providers.Warning{Code: helperproto.WarnAccountHomeUnsupported, Params: map[string]string{"uid": "1010"}})
	raw, err := json.Marshal(res)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "bad name", "an invalid name never reaches the result")
	assert.Zero(t, countReads(e), "AUD-22: every listed file came inline")
}

// A hostile helper cannot make Alice keep a wrong reason, a negative uid or an unbounded list.
func TestDiscoverBoundsUnlistedAccounts(t *testing.T) {
	e := newProvEnv(t)
	list := helperproto.AuthKeysListResponse{OK: true, Users: []helperproto.UserFiles{}, AuthorizedKeysCommand: "none",
		Warnings: []string{}, Accounts: []string{"root"}, AccountsComplete: true}
	list.Unlisted = append(list.Unlisted, helperproto.UnlistedAccount{UID: -1, Reason: helperproto.UnlistedName},
		helperproto.UnlistedAccount{UID: 7, Reason: "x"})
	for i := 0; i < 1000; i++ {
		list.Unlisted = append(list.Unlisted, helperproto.UnlistedAccount{UID: 2000 + i, Reason: helperproto.UnlistedName})
	}
	raw, err := json.Marshal(list)
	require.NoError(t, err)
	emu := e.emu.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if strings.Contains(cmd, " authkeys-list") {
			return linuxsshtest.Response{Stdout: raw}
		}
		return emu(cmd, stdin)
	})
	s := e.open(t)
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.False(t, res.AccountsComplete)
	n := 0
	for _, w := range res.Warnings {
		if w.Code == helperproto.WarnAccountNameUnsupported || w.Code == helperproto.WarnAccountHomeUnsupported {
			n++
			uid, err := strconv.Atoi(w.Params["uid"])
			require.NoError(t, err)
			assert.GreaterOrEqual(t, uid, 2000, "the negative uid and the unknown reason are dropped")
		}
	}
	assert.Equal(t, helperproto.MaxUnlistedAccounts-2, n, "the list is cut at its bound before the bad entries are dropped")

	// An answer with no unlisted field at all (null) is read as an empty list.
	list.Unlisted = nil
	raw, err = json.Marshal(list)
	require.NoError(t, err)
	res, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.True(t, res.AccountsComplete)
}

// AUD-22: inline content is used; no authkeys-read is sent for it.
func TestDiscoverUsesInlineContent(t *testing.T) {
	e := newProvEnv(t)
	line, fp := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile(deployFile, []byte(line+"\n"))
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Zero(t, countReads(e), "every listed file came inline")
	found := false
	for _, k := range res.SSHKeys {
		found = found || k.Fingerprint == fp
	}
	assert.True(t, found)
	assert.Contains(t, res.ReadFiles, deployFile)
	assert.False(t, res.Partial)
}

// AUD-22: inline content must be exactly what the helper hashed, and no larger than a file the
// helper reads; anything else is a protocol error that fails the discovery (never a silent
// partial inventory).
func TestDiscoverRefusesInlineContentThatIsNotWhatWasHashed(t *testing.T) {
	big := bytes.Repeat([]byte("#"), helperproto.MaxAuthorizedKeysSize+1)
	bigSum := sha256.Sum256(big)
	for name, edit := range map[string]func(*helperproto.FileInfo){
		"another hash": func(f *helperproto.FileInfo) { f.SHA256 = strings.Repeat("0", 64) },
		"other content": func(f *helperproto.FileInfo) {
			f.ContentB64 = base64.StdEncoding.EncodeToString([]byte("ssh-ed25519 AAAA evil\n"))
		},
		"not base64": func(f *helperproto.FileInfo) { f.ContentB64 = "%%%" },
		"no content": func(f *helperproto.FileInfo) { f.ContentB64 = "" },
		"larger than read": func(f *helperproto.FileInfo) {
			f.ContentB64, f.SHA256 = base64.StdEncoding.EncodeToString(big), hex.EncodeToString(bigSum[:])
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newProvEnv(t)
			line, _ := keyLine(t, "ed25519", "", "deploy@laptop")
			e.emu.SetFile(deployFile, []byte(line+"\n"))
			rewriteList(t, e, func(l *helperproto.AuthKeysListResponse) {
				for i := range l.Users {
					for j := range l.Users[i].Files {
						if l.Users[i].Files[j].Inline {
							edit(&l.Users[i].Files[j])
						}
					}
				}
			})
			_, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
			pe := providerCode(t, err)
			assert.Equal(t, "ssh.protocol_error", pe.Code)
			assert.Equal(t, helperproto.SubAuthKeysList, pe.Params["subcommand"])
		})
	}
}

// S8: a truncated listing is a partial discovery with an incomplete account list, never a failure
// and never silently complete.
func TestDiscoverTruncatedListIsPartialAndIncomplete(t *testing.T) {
	e := newProvEnv(t)
	rewriteList(t, e, func(l *helperproto.AuthKeysListResponse) { l.Truncated = true })
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.True(t, res.Partial)
	assert.False(t, res.AccountsComplete)
	assert.True(t, hasWarning(res.Warnings, providers.WarnListTruncated, ""))
}

// S6 on Alice's side: a listed user whose name is not an account name (only a broken or hostile
// helper sends one) is shown by uid only; its files are not read and its name is nowhere in the
// result.
func TestDiscoverNeverCarriesAnInvalidListedUserName(t *testing.T) {
	e := newProvEnv(t)
	k, fp := keyLine(t, "ed25519", "", "evil@x")
	content := []byte(k + "\n")
	sum := sha256.Sum256(content)
	rewriteList(t, e, func(l *helperproto.AuthKeysListResponse) {
		for _, name := range []string{"bad name", "-x", "x\x1b[31m", strings.Repeat("a", 33)} {
			l.Users = append(l.Users, helperproto.UserFiles{User: name, UID: 1009, Home: "/home/bad", AuthorizedKeysCommand: "none",
				Files: []helperproto.FileInfo{{Path: "/home/bad/.ssh/authorized_keys", Exists: true, Size: int64(len(content)),
					SHA256: hex.EncodeToString(sum[:]), StrictModesOK: true, Inline: true, ContentB64: base64.StdEncoding.EncodeToString(content)}}})
		}
		l.Accounts = append(l.Accounts, "bad name")
	})
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.False(t, res.AccountsComplete)
	for _, key := range res.SSHKeys {
		assert.NotEqual(t, fp, key.Fingerprint)
	}
	assert.Contains(t, res.Warnings, providers.Warning{Code: helperproto.WarnAccountNameUnsupported, Params: map[string]string{"uid": "1009"}})
	assert.NotContains(t, res.ReadFiles, "/home/bad/.ssh/authorized_keys")
	raw, err := json.Marshal(res)
	require.NoError(t, err)
	for _, bad := range []string{"bad name", `"-x"`, "\\u001b", strings.Repeat("a", 33)} {
		assert.NotContains(t, string(raw), bad)
	}
}

// AUD-22: a change never takes the listing's inline content: it reads the file again with
// authkeys-read (whose owner the guards check) and writes against that hash. A listing that shows
// other content changes nothing about what is written.
func TestKeyChangesReadTheFileAgain(t *testing.T) {
	e := newProvEnv(t)
	k1, fp1 := keyLine(t, "ed25519", "", "one@x")
	k2, _ := keyLine(t, "ed25519", "", "two@x")
	e.emu.SetFile(deployFile, []byte(k1+"\n"+k2+"\n"))
	forged := []byte(k1 + "\n")
	sum := sha256.Sum256(forged)
	rewriteList(t, e, func(l *helperproto.AuthKeysListResponse) {
		for i := range l.Users {
			for j := range l.Users[i].Files {
				if l.Users[i].Files[j].Path == deployFile {
					l.Users[i].Files[j].ContentB64 = base64.StdEncoding.EncodeToString(forged)
					l.Users[i].Files[j].SHA256 = hex.EncodeToString(sum[:])
				}
			}
		}
	})
	s := e.open(t)
	_, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	res, err := s.RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp1), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Removed)
	assert.True(t, res.Verified)
	assert.Equal(t, k2+"\n", fileOf(t, e, deployFile), "the second key, which the listing did not show, is kept")
	assert.Equal(t, 2, countReads(e), "the read before the write and the verification")
}

// A file shared by several accounts (an absolute AuthorizedKeysFile) is listed with its content
// for each of them, but a change still resolves it to its first account (root): another account
// cannot remove root's last key through it, and root's last key needs the confirmation.
func TestSharedFileKeepsTheOwnerGuards(t *testing.T) {
	e := newProvEnv(t)
	const shared = "/etc/ssh/keys/shared"
	e.emu.SetSSHD(strings.Replace(linuxsshtest.DefaultSSHD, "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
		"authorizedkeysfile "+shared, 1))
	k, fp := keyLine(t, "ed25519", "", "root@bastion")
	e.emu.SetFile(shared, []byte(k+"\n"))
	s := e.open(t)
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	var users []string
	for _, key := range res.SSHKeys {
		users = append(users, key.OSUser)
	}
	assert.ElementsMatch(t, []string{"root", "alice-svc", "deploy"}, users)
	assert.Zero(t, countReads(e))

	_, err = s.RemoveAuthorizedKey(context.Background(), removeReq("deploy", shared, fp), nil)
	assert.Equal(t, "os_user", providerCode(t, err).Params["field"])
	_, err = s.RemoveAuthorizedKey(context.Background(), removeReq("root", shared, fp), nil)
	assert.Equal(t, "sshkey.last_root_key", providerCode(t, err).Code)
	assert.Empty(t, e.emu.Writes())
	assert.Equal(t, k+"\n", fileOf(t, e, shared))
}

// AUD-03: keys of accounts named outside SEC-062's pattern can be removed; a request naming
// something that is not an account name is refused before any helper command.
func TestKeyChangesTakeEveryAccountName(t *testing.T) {
	e := newProvEnv(t)
	s := e.open(t)
	for _, n := range []string{"john.doe", "Deploy2", "svc$"} {
		home := "/home/" + strings.TrimSuffix(n, "$")
		e.emu.AddUser(n, 1005, home)
		k1, fp1 := keyLine(t, "ed25519", "", "one@x")
		k2, _ := keyLine(t, "ed25519", "", "two@x")
		e.emu.SetFile(home+"/.ssh/authorized_keys", []byte(k1+"\n"+k2+"\n"))
		res, err := s.RemoveAuthorizedKey(context.Background(), removeReq(n, home+"/.ssh/authorized_keys", fp1), nil)
		require.NoError(t, err, n)
		assert.Equal(t, 1, res.Removed, n)
		assert.Equal(t, k2+"\n", fileOf(t, e, home+"/.ssh/authorized_keys"), n)
	}

	e = newProvEnv(t)
	s = e.open(t)
	_, fp := keyLine(t, "ed25519", "", "x")
	for _, user := range []string{"", "-x", ".", "..", "a b", "a/b", "a,b", "x\x00", "é", "1000", strings.Repeat("a", 33), "a$b"} {
		_, err := s.RemoveAuthorizedKey(context.Background(), removeReq(user, deployFile, fp), nil)
		pe := providerCode(t, err)
		assert.Equal(t, "os_user", pe.Params["field"], "%q", user)
	}
	assert.Equal(t, []string{"/usr/local/libexec/alice-helper version"}, e.srv.Commands())
}

// S8: the helper's bound on its listing is below what Alice reads, so a listing within it never
// fails with ssh.output_too_large.
func TestListBoundFitsAlicesReadLimit(t *testing.T) {
	assert.Less(t, helperproto.MaxListOutput, DefaultMaxOutput)
	assert.Equal(t, int64(DefaultMaxOutput), CmdAuthKeysList().maxOutput)
}

// A truncated listing that leaves out the requested user names the truncation, like too_many_users.
func TestAddForAUserLeftOutOfATruncatedListingNamesIt(t *testing.T) {
	e := newProvEnv(t)
	const shared = "/etc/ssh/shared_keys"
	e.emu.SetSSHD(strings.Replace(linuxsshtest.DefaultSSHD, "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
		"authorizedkeysfile "+shared, 1))
	rewriteList(t, e, func(l *helperproto.AuthKeysListResponse) {
		var kept []helperproto.UserFiles
		for _, u := range l.Users {
			if u.User != "deploy" {
				kept = append(kept, u)
			}
		}
		l.Users, l.Truncated = kept, true
	})
	add, _ := keyLine(t, "ed25519", "", "n@x")
	_, err := e.open(t).AddAuthorizedKey(context.Background(),
		providers.AuthKeyChange{OperationID: keyOp, OSUser: "deploy", FilePath: shared, Line: add}, nil)
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.helper_refused", pe.Code)
	assert.Equal(t, providers.WarnListTruncated, pe.Params["reason"])
	assert.Empty(t, e.emu.Writes())
}

// The emulator inlines what fits the helper's budget and nothing it cannot read (FailRead), so a
// discovery reads exactly those files with authkeys-read.
func TestDiscoverReadsOnlyWhatIsNotInline(t *testing.T) {
	e := newProvEnv(t)
	var reads atomic.Int64
	emu := e.emu.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if strings.Contains(cmd, " authkeys-read ") {
			reads.Add(1)
		}
		return emu(cmd, stdin)
	})
	big := []byte(strings.Repeat("# "+strings.Repeat("x", 76)+"\n", 12000)) // ~ 937 KB, no keys
	for i := 0; i < 6; i++ {
		home := "/home/big" + strconv.Itoa(i)
		e.emu.AddUser("big"+strconv.Itoa(i), 2000+i, home)
		e.emu.SetFile(home+"/.ssh/authorized_keys", big)
	}
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, int64(2), reads.Load(), "four files fit the 4 MiB budget, two are read")
	assert.False(t, res.Partial)
}
