package linuxssh

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

var keyOp = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000bb")

type stepLog struct {
	mu    sync.Mutex
	steps []string
}

func (l *stepLog) Step(name string, status providers.StepStatus, _ map[string]string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.steps = append(l.steps, name+":"+string(status))
}

func (l *stepLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.steps...)
}

func removeReq(user, path, fp string, protected ...string) providers.AuthKeyChange {
	return providers.AuthKeyChange{OperationID: keyOp, OSUser: user, FilePath: path, Fingerprint: fp, ProtectedFingerprints: protected}
}

func platformLine(e *provEnv, options, comment string) (string, string) {
	pub := e.cred.signer.PublicKey()
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment
	if options != "" {
		line = options + " " + line
	}
	return line, ssh.FingerprintSHA256(pub)
}

func fileOf(t *testing.T, e *provEnv, path string) string {
	t.Helper()
	b, ok := e.emu.File(path)
	require.True(t, ok)
	return string(b)
}

func TestProviderAdvertisesAuthorizedKeys(t *testing.T) {
	assert.True(t, newProvEnv(t).prov.Capabilities().Has(providers.CapAuthorizedKeys))
}

// F-36: Alice's own key is refused by fingerprint (another comment or other options do not
// matter), before any remote command, in any file.
func TestRemoveRefusesAlicesOwnKey(t *testing.T) {
	e := newProvEnv(t)
	own, ownFP := platformLine(e, `from="10.9.9.9",no-pty`, "renamed-by-someone")
	other, _ := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile(aliceFile, []byte(own+"\n"+other+"\n"))
	e.emu.SetFile(deployFile, []byte(own+"\n"))
	s := e.open(t)

	for _, path := range []string{aliceFile, deployFile} {
		user := "alice-svc"
		if path == deployFile {
			user = "deploy"
		}
		_, err := s.RemoveAuthorizedKey(context.Background(), removeReq(user, path, ownFP, ownFP), nil)
		pe := providerCode(t, err)
		assert.Equal(t, "sshkey.own_key_protected", pe.Code, path)
		assert.Equal(t, "protected_fingerprint", pe.Params["reason"])
	}
	assert.Equal(t, []string{"/usr/local/libexec/alice-helper version"}, e.srv.Commands(), "nothing beyond Open ran")
	assert.Empty(t, e.emu.Writes())
	assert.Equal(t, own+"\n"+other+"\n", fileOf(t, e, aliceFile))
}

// Removing the last key of the account Alice signs in with would lock Alice out of the server.
func TestRemoveRefusesTheLastKeyOfTheConnectionAccount(t *testing.T) {
	e := newProvEnv(t)
	only, onlyFP := keyLine(t, "ed25519", "", "someone@laptop")
	e.emu.SetFile(aliceFile, []byte(only+"\n"))
	_, err := e.open(t).RemoveAuthorizedKey(context.Background(), removeReq("alice-svc", aliceFile, onlyFP), nil)
	pe := providerCode(t, err)
	assert.Equal(t, "sshkey.own_key_protected", pe.Code)
	assert.Equal(t, "last_key_of_connection_account", pe.Params["reason"])
	assert.Empty(t, e.emu.Writes())
}

func TestRemoveLastRootKeyNeedsConfirmation(t *testing.T) {
	e := newProvEnv(t)
	k, fp := keyLine(t, "ed25519", `from="10.0.0.0/8"`, "root@bastion")
	e.emu.SetFile(rootFile, []byte(k+"\n"))
	s := e.open(t)
	_, err := s.RemoveAuthorizedKey(context.Background(), removeReq("root", rootFile, fp), nil)
	assert.Equal(t, "sshkey.last_root_key", providerCode(t, err).Code)
	assert.Empty(t, e.emu.Writes())

	req := removeReq("root", rootFile, fp)
	req.AllowLastRootKey = true
	res, err := s.RemoveAuthorizedKey(context.Background(), req, nil)
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.True(t, res.Verified)
	assert.Equal(t, 1, res.Removed)
	assert.Empty(t, fileOf(t, e, rootFile))
}

// F-35: no key change on a host whose keys come from AuthorizedKeysCommand.
func TestRemoveRefusedWhenKeysAreManagedElsewhere(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetSSHD(strings.Replace(linuxsshtest.DefaultSSHD, "authorizedkeyscommand none",
		"authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys", 1))
	k, fp := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile(deployFile, []byte(k+"\n"))
	_, err := e.open(t).RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), nil)
	assert.Equal(t, "ssh.keys_managed_elsewhere", providerCode(t, err).Code)
	for _, c := range e.srv.Commands() {
		assert.NotContains(t, c, "authkeys-", "the file is neither read nor written")
	}
}

func TestRemoveRefusesCertAuthorityLines(t *testing.T) {
	e := newProvEnv(t)
	ca, caFP := keyLine(t, "ed25519", "cert-authority", "ca@corp")
	k, _ := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile(deployFile, []byte(ca+"\n"+k+"\n"))
	_, err := e.open(t).RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, caFP), nil)
	pe := providerCode(t, err)
	assert.Equal(t, "sshkey.not_removable", pe.Code)
	assert.Equal(t, "cert_authority", pe.Params["reason"])
	assert.Empty(t, e.emu.Writes())
}

// Review Focus 1: CRLF endings, comments, unreadable lines and other keys stay byte-for-byte.
func TestRemoveKeepsCRLFAndForeignLines(t *testing.T) {
	e := newProvEnv(t)
	a, _ := keyLine(t, "ed25519", "", "a@x")
	target, fp := keyLine(t, "ed25519", `command="echo a,b",from="10.0.0.0/8"`, "target@x")
	b, _ := keyLine(t, "ed25519", "", "b@x")
	before := a + "\r\n# a comment\r\n" + target + "\r\ngarbage that is not a key\r\n" + target + "\r\n" + b + "\r\n"
	e.emu.SetFile(deployFile, []byte(before))
	res, err := e.open(t).RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), nil)
	require.NoError(t, err)
	assert.Equal(t, 2, res.Removed, "every line with the fingerprint goes")
	assert.Equal(t, a+"\r\n# a comment\r\ngarbage that is not a key\r\n"+b+"\r\n", fileOf(t, e, deployFile))
	assert.True(t, res.Verified)
	assert.NotEqual(t, res.OldSHA256, res.NewSHA256)
}

func TestRemoveIsIdempotentAndLogsSteps(t *testing.T) {
	e := newProvEnv(t)
	k, fp := keyLine(t, "ed25519", "", "deploy@laptop")
	keep, _ := keyLine(t, "ed25519", "", "deploy@desktop")
	e.emu.SetFile(deployFile, []byte(k+"\n"+keep+"\n"))
	s := e.open(t)
	log := &stepLog{}
	res, err := s.RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), log)
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.Equal(t, []string{"precheck:started", "precheck:ok", "read:started", "read:ok", "write:started", "write:ok",
		"verify:started", "verify:ok"}, log.all())

	again, err := s.RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), nil)
	require.NoError(t, err)
	assert.False(t, again.Changed)
	assert.Equal(t, again.OldSHA256, again.NewSHA256)
	assert.Len(t, e.emu.Writes(), 1, "the second removal wrote nothing")
	assert.Equal(t, keep+"\n", fileOf(t, e, deployFile))
}

func TestRemoveFromAMissingFileChangesNothing(t *testing.T) {
	e := newProvEnv(t)
	_, fp := keyLine(t, "ed25519", "", "x")
	res, err := e.open(t).RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), nil)
	require.NoError(t, err)
	assert.False(t, res.Changed)
	assert.Empty(t, e.emu.Writes())
}

// A request outside the helper vocabulary never reaches a command line.
func TestKeyOperationsRefuseHostileRequests(t *testing.T) {
	e := newProvEnv(t)
	s := e.open(t)
	_, fp := keyLine(t, "ed25519", "", "x")
	for _, req := range []providers.AuthKeyChange{
		removeReq("deploy", "/home/deploy/.ssh/authorized_keys; id", fp),
		removeReq("deploy\nroot", deployFile, fp),
		removeReq("deploy", deployFile, ""),
		{OSUser: "deploy", FilePath: deployFile, Fingerprint: fp}, // no operation id
	} {
		_, err := s.RemoveAuthorizedKey(context.Background(), req, nil)
		pe := providerCode(t, err)
		assert.Equal(t, "ssh.helper_refused", pe.Code)
		assert.Equal(t, "INVALID_ARGUMENT", pe.Params["helper_code"])
	}
	assert.Equal(t, []string{"/usr/local/libexec/alice-helper version"}, e.srv.Commands())
}

// F-37: a file without a trailing newline gets the new key on its own line; the old bytes stay.
func TestAddAppendsOnItsOwnLine(t *testing.T) {
	e := newProvEnv(t)
	old, _ := keyLine(t, "ed25519", "", "old@x")
	e.emu.SetFile(deployFile, []byte("# keys\n"+old)) // no trailing newline
	add, _ := keyLine(t, "ed25519", "", "new@x")
	res, err := e.open(t).AddAuthorizedKey(context.Background(),
		providers.AuthKeyChange{OperationID: keyOp, OSUser: "deploy", FilePath: deployFile, Line: add}, nil)
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.True(t, res.Verified)
	assert.Equal(t, "# keys\n"+old+"\n"+add+"\n", fileOf(t, e, deployFile))
}

func TestAddCreatesAMissingFile(t *testing.T) {
	e := newProvEnv(t)
	add, _ := keyLine(t, "ed25519", "", "new@x")
	res, err := e.open(t).AddAuthorizedKey(context.Background(),
		providers.AuthKeyChange{OperationID: keyOp, OSUser: "deploy", FilePath: deployFile, Line: add}, nil)
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.Equal(t, "absent", res.OldSHA256)
	assert.Equal(t, add+"\n", fileOf(t, e, deployFile))
	found := false
	for _, c := range e.srv.Commands() {
		found = found || strings.Contains(c, "authkeys-write '"+deployFile+"' --expect-sha256 'absent'")
	}
	assert.True(t, found, "the write expects the file to be absent")
}

func TestAddExistingKeyChangesNothing(t *testing.T) {
	e := newProvEnv(t)
	k, _ := keyLine(t, "ed25519", "", "x@y")
	e.emu.SetFile(deployFile, []byte(k+"\n"))
	res, err := e.open(t).AddAuthorizedKey(context.Background(),
		providers.AuthKeyChange{OperationID: keyOp, OSUser: "deploy", FilePath: deployFile, Line: k + "-other-comment"}, nil)
	require.NoError(t, err)
	assert.False(t, res.Changed)
	assert.Empty(t, e.emu.Writes())
}

func TestAddRefusesALineThatIsNotOneKey(t *testing.T) {
	e := newProvEnv(t)
	k, _ := keyLine(t, "ed25519", "", "x@y")
	s := e.open(t)
	for _, bad := range []string{"not a key", k + "\n" + k, k + "\x1b[31m"} {
		_, err := s.AddAuthorizedKey(context.Background(),
			providers.AuthKeyChange{OperationID: keyOp, OSUser: "deploy", FilePath: deployFile, Line: bad}, nil)
		assert.Equal(t, "ssh.helper_refused", providerCode(t, err).Code, "%q", bad)
	}
	assert.Empty(t, e.emu.Writes())
}

// F-38: the file changes between read and write once; the write is refused (hash mismatch), the
// file is read again and the change is kept.
func TestConcurrentChangeIsRetriedAndKept(t *testing.T) {
	e := newProvEnv(t)
	k, fp := keyLine(t, "ed25519", "", "deploy@laptop")
	keep, _ := keyLine(t, "ed25519", "", "deploy@desktop")
	e.emu.SetFile(deployFile, []byte(k+"\n"+keep+"\n"))
	calls := 0
	e.emu.BeforeWrite(func(path string) {
		calls++
		if calls == 1 {
			cur, _ := e.emu.File(path)
			e.emu.SetFile(path, append(cur, []byte("# added by someone else\n")...))
		}
	})
	log := &stepLog{}
	res, err := e.open(t).RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), log)
	require.NoError(t, err)
	assert.True(t, res.Verified)
	assert.Equal(t, 2, calls)
	assert.Equal(t, keep+"\n# added by someone else\n", fileOf(t, e, deployFile))
	assert.Contains(t, log.all(), "write:failed")
}

func TestConcurrentChangeEveryTimeFailsAfterThreeAttempts(t *testing.T) {
	e := newProvEnv(t)
	k, fp := keyLine(t, "ed25519", "", "deploy@laptop")
	keep, _ := keyLine(t, "ed25519", "", "deploy@desktop")
	e.emu.SetFile(deployFile, []byte(k+"\n"+keep+"\n"))
	calls := 0
	e.emu.BeforeWrite(func(path string) {
		calls++
		cur, _ := e.emu.File(path)
		e.emu.SetFile(path, append(cur, []byte("# busy\n")...))
	})
	_, err := e.open(t).RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), nil)
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.file_changed", pe.Code)
	assert.True(t, pe.Retryable)
	assert.Equal(t, "3", pe.Params["attempts"])
	assert.Equal(t, 3, calls)
	assert.Empty(t, e.emu.Writes())
	assert.Contains(t, fileOf(t, e, deployFile), k, "the key is still there: nothing was written")
}

func TestBeforeWriteHookSeesEveryWrite(t *testing.T) {
	e := newProvEnv(t)
	k, fp := keyLine(t, "ed25519", "", "deploy@laptop")
	keep, _ := keyLine(t, "ed25519", "", "deploy@desktop")
	e.emu.SetFile(deployFile, []byte(k+"\n"+keep+"\n"))
	var seen []string
	beforeAuthKeysWrite = func(path string) { seen = append(seen, path) }
	t.Cleanup(func() { beforeAuthKeysWrite = nil })
	_, err := e.open(t).RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), nil)
	require.NoError(t, err)
	assert.Equal(t, []string{deployFile}, seen)
}

// A closed session's connection may already serve another session: no key operation runs on it.
func TestKeyOperationsRefuseAClosedSession(t *testing.T) {
	e := newProvEnv(t)
	k, fp := keyLine(t, "ed25519", "", "x@y")
	s := e.open(t)
	require.NoError(t, s.Close())
	_, err := s.RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), nil)
	assert.Equal(t, "ssh.unreachable", providerCode(t, err).Code)
	_, err = s.AddAuthorizedKey(context.Background(),
		providers.AuthKeyChange{OperationID: keyOp, OSUser: "deploy", FilePath: deployFile, Line: k}, nil)
	assert.Equal(t, "ssh.unreachable", providerCode(t, err).Code)
	assert.Equal(t, []string{"/usr/local/libexec/alice-helper version"}, e.srv.Commands())
}

// Helper refusals of a write map like discovery's: nothing was written, so the result is empty.
func TestWriteRefusalsAreMapped(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(*provEnv)
		code  string
		hc    string
	}{
		"unsafe":       {func(e *provEnv) { e.emu.SetUnsupported(deployFile) }, "ssh.helper_refused", "UNSAFE_FILE"},
		"insecure":     {func(e *provEnv) { e.emu.SetInsecure(deployFile) }, "ssh.helper_refused", "INSECURE_PERMISSIONS"},
		"user command": {func(e *provEnv) { e.emu.SetUserSSHD("deploy", "authorizedkeyscommand /bin/x\n") }, "ssh.keys_managed_elsewhere", "AUTHORIZED_KEYS_COMMAND"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newProvEnv(t)
			k, fp := keyLine(t, "ed25519", "", "a@x")
			keep, _ := keyLine(t, "ed25519", "", "b@x")
			e.emu.SetFile(deployFile, []byte(k+"\n"+keep+"\n"))
			tc.setup(e)
			res, err := e.open(t).RemoveAuthorizedKey(context.Background(), removeReq("deploy", deployFile, fp), nil)
			pe := providerCode(t, err)
			assert.Equal(t, tc.code, pe.Code)
			assert.Equal(t, tc.hc, pe.Params["helper_code"])
			assert.Equal(t, providers.AuthKeyResult{}, res)
			assert.Empty(t, e.emu.Writes())
		})
	}
}
