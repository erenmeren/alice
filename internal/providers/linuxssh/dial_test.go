package linuxssh

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

func okHandler(cmd string, _ []byte) linuxsshtest.Response {
	if cmd == CmdVersion().Line() {
		return versionJSON(1)
	}
	return linuxsshtest.Response{Exit: 127}
}

// F-30: an unknown server's key is shown, never trusted: the connection stops at the key
// exchange, no authentication is attempted and no command runs.
func TestFirstContactStopsBeforeAuthentication(t *testing.T) {
	srv, cfg, cred := testServer(t, okHandler)
	hk := &memHostKeys{}
	_, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	pe := providerCode(t, err)
	assert.Equal(t, "target.host_key_unconfirmed", pe.Code)
	assert.False(t, pe.Retryable)
	assert.Equal(t, ssh.FingerprintSHA256(srv.HostKey()), pe.Params["fingerprint"])
	assert.Zero(t, srv.AuthAttempts(), "no authentication attempt before the key is confirmed")
	assert.Empty(t, srv.Commands())
	obs := hk.observations()
	require.Len(t, obs, 1)
	assert.False(t, obs[0].changed)
	assert.Equal(t, srv.HostKey().Marshal(), obs[0].key.PublicKey)
	assert.Equal(t, "ssh-ed25519", obs[0].key.Type)
	assert.Zero(t, cred.fetches(), "the client key is never decrypted for an unconfirmed server")

	// After an administrator pins the key, the same server is reachable.
	hk.pin(srv.HostKey())
	c, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	assert.Equal(t, ssh.FingerprintSHA256(srv.HostKey()), c.HostKey().Fingerprint)
	res, err := c.Run(context.Background(), CmdVersion())
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)
	assert.Equal(t, []string{"/usr/local/libexec/alice-helper version"}, srv.Commands())
}

// F-31: a different key stops the connection before authentication and is reported as changed.
func TestChangedHostKeyStopsBeforeAuthentication(t *testing.T) {
	srv, cfg, cred := testServer(t, okHandler)
	hk := &memHostKeys{}
	old := srv.HostKey()
	hk.pin(old)
	newKey := linuxsshtest.NewHostKey(t)
	srv.SetHostKey(newKey)

	_, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	pe := providerCode(t, err)
	assert.Equal(t, "target.host_key_changed", pe.Code)
	assert.Equal(t, ssh.FingerprintSHA256(old), pe.Params["old_fingerprint"])
	assert.Equal(t, ssh.FingerprintSHA256(newKey.PublicKey()), pe.Params["new_fingerprint"])
	assert.Zero(t, srv.AuthAttempts())
	assert.Zero(t, cred.fetches(), "the client key is never decrypted for a changed server")
	assert.Empty(t, srv.Commands())
	obs := hk.observations()
	require.Len(t, obs, 1)
	assert.True(t, obs[0].changed)
	assert.Equal(t, newKey.PublicKey().Marshal(), obs[0].key.PublicKey)
}

// A server that no longer offers the pinned key type (ed25519 pinned, only ECDSA offered) has
// changed its identity too; the pinned algorithm list makes the handshake fail, a key-only probe
// reports the new key.
func TestMissingPinnedAlgorithmCountsAsChanged(t *testing.T) {
	srv, cfg, cred := testServer(t, okHandler)
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	ecdsaKey := linuxsshtest.NewECDSAHostKey(t)
	srv.SetHostKeyAlgorithms(ecdsaKey)

	_, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	pe := providerCode(t, err)
	assert.Equal(t, "target.host_key_changed", pe.Code)
	assert.Equal(t, ssh.FingerprintSHA256(ecdsaKey.PublicKey()), pe.Params["new_fingerprint"])
	assert.Zero(t, srv.AuthAttempts())
	obs := hk.observations()
	require.Len(t, obs, 1)
	assert.True(t, obs[0].changed)
	assert.Equal(t, "ecdsa-sha2-nistp256", obs[0].key.Type)
}

// The pinned key restricts the host-key algorithms: a server that offers both the pinned ECDSA
// key and an Ed25519 key is accepted with the pinned one.
func TestPinnedAlgorithmIsTheOnlyOneOffered(t *testing.T) {
	srv, cfg, cred := testServer(t, okHandler)
	ecdsaKey := linuxsshtest.NewECDSAHostKey(t)
	srv.SetHostKeyAlgorithms(linuxsshtest.NewHostKey(t), ecdsaKey)
	hk := &memHostKeys{}
	hk.pin(ecdsaKey.PublicKey())
	c, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	assert.Equal(t, "ecdsa-sha2-nistp256", c.HostKey().Type)
	assert.Empty(t, hk.observations())
}

func TestAuthenticationFailure(t *testing.T) {
	srv, cfg, cred := testServer(t, okHandler)
	srv.Authorize(newFakeCred(t).signer.PublicKey()) // the server trusts another key
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	_, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.auth_failed", pe.Code)
	assert.False(t, pe.Retryable)
	assert.Positive(t, srv.AuthAttempts())
	assert.Equal(t, cred.releases(), cred.fetches(), "every decrypted key is released")
	assert.Empty(t, srv.Commands())
}

func TestUnreachableServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	_, err = newDialer(&memHostKeys{}).Dial(context.Background(), testTarget,
		Config{Host: "127.0.0.1", Port: port, Username: "alice-svc"}, newFakeCred(t))
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.unreachable", pe.Code)
	assert.True(t, pe.Retryable)
}

func TestHostKeyStoreFailureIsNotAConnection(t *testing.T) {
	srv, cfg, cred := testServer(t, okHandler)
	_, err := newDialer(&memHostKeys{fail: errors.New("database down")}).Dial(context.Background(), testTarget, cfg, cred)
	assert.Equal(t, "internal.unexpected", providerCode(t, err).Code)
	assert.Zero(t, srv.AuthAttempts())
}

func pinnedConn(t *testing.T, h linuxsshtest.Handler) (*linuxsshtest.Server, *Conn) {
	t.Helper()
	srv, cfg, cred := testServer(t, h)
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	c, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return srv, c
}

func TestRunPassesStdinAndReturnsExitCode(t *testing.T) {
	var mu sync.Mutex
	var gotStdin []byte
	_, c := pinnedConn(t, func(_ string, stdin []byte) linuxsshtest.Response {
		mu.Lock()
		gotStdin = stdin
		mu.Unlock()
		return linuxsshtest.Response{Stdout: []byte(`{"ok":false}`), Exit: 3}
	})
	cmd, err := CmdAuthKeysWrite("/root/.ssh/authorized_keys", helperproto.AbsentSHA256, testOp, []byte("line\n"))
	require.NoError(t, err)
	res, err := c.Run(context.Background(), cmd)
	require.NoError(t, err)
	assert.Equal(t, 3, res.ExitCode)
	assert.Equal(t, `{"ok":false}`, string(res.Stdout))
	mu.Lock()
	assert.Equal(t, "line\n", string(gotStdin))
	mu.Unlock()
	assert.True(t, c.Healthy())
}

func TestRunWithoutExitStatusIsAProtocolError(t *testing.T) {
	_, c := pinnedConn(t, func(string, []byte) linuxsshtest.Response { return linuxsshtest.Response{Exit: -1} })
	_, err := c.Run(context.Background(), CmdVersion())
	assert.Equal(t, "ssh.protocol_error", providerCode(t, err).Code)
}

// Review Focus 3: a host that sends more than a command may return is cut off.
func TestRunCapsOutput(t *testing.T) {
	_, c := pinnedConn(t, func(string, []byte) linuxsshtest.Response {
		return linuxsshtest.Response{Stdout: bytes.Repeat([]byte("A"), 512<<10)}
	})
	_, err := c.Run(context.Background(), CmdVersion()) // version may answer at most 64 KiB
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.output_too_large", pe.Code)
	assert.Equal(t, "version", pe.Params["subcommand"])
	assert.False(t, c.Healthy(), "the connection is not reused after a flood")
}

// F-39, Review Focus 3: a slow host (10 s per command) fails the step on its own budget and the
// connection is closed; it is never reused.
func TestRunTimesOutAndClosesSession(t *testing.T) {
	_, c := pinnedConn(t, func(string, []byte) linuxsshtest.Response {
		return linuxsshtest.Response{Delay: 10 * time.Second, Stdout: []byte(`{"ok":true}`)}
	})
	cmd := CmdSSHDDump()
	cmd.timeout = 300 * time.Millisecond
	start := time.Now()
	_, err := c.Run(context.Background(), cmd)
	elapsed := time.Since(start)
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.True(t, pe.Retryable)
	assert.Equal(t, "sshd-dump", pe.Params["subcommand"])
	assert.Less(t, elapsed, 3*time.Second, "the 10 s answer was not awaited")
	assert.False(t, c.Healthy())
	_, err = c.Run(context.Background(), CmdVersion())
	assert.Equal(t, "ssh.unreachable", providerCode(t, err).Code, "a closed connection runs nothing")
}

func TestRunHonoursContextCancellation(t *testing.T) {
	_, c := pinnedConn(t, func(string, []byte) linuxsshtest.Response {
		return linuxsshtest.Response{Delay: 10 * time.Second}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := c.Run(ctx, CmdVersion())
	assert.Equal(t, "ssh.timeout", providerCode(t, err).Code)
	assert.False(t, c.Healthy())
}

// runWithin runs c.Run in a goroutine and fails the test when it has not returned within d (a Run
// that hangs fails here instead of at the package's test timeout).
func runWithin(t *testing.T, d time.Duration, c *Conn, ctx context.Context, cmd HelperCommand) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := c.Run(ctx, cmd)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("Run did not return within %s", d)
		return nil
	}
}

// Opening the command's session is bounded like the command: a server that never answers the
// channel open fails the call on the context, and the connection is not reused.
func TestRunBoundsTheSessionOpenByTheContext(t *testing.T) {
	srv, c := pinnedConn(t, okHandler)
	srv.HoldChannelOpens()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := runWithin(t, 5*time.Second, c, ctx, CmdVersion())
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, c.Healthy())
}

// The command's time budget covers opening its session too.
func TestRunBoundsTheSessionOpenByTheCommandTimeout(t *testing.T) {
	srv, c := pinnedConn(t, okHandler)
	srv.HoldChannelOpens()
	cmd := CmdVersion()
	cmd.timeout = 300 * time.Millisecond
	err := runWithin(t, 5*time.Second, c, context.Background(), cmd)
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.Equal(t, "version", pe.Params["subcommand"])
	assert.False(t, c.Healthy())
}

// A connection the server dropped during a command is not healthy afterwards, however the command
// ended (a dropped connection can end the session without an exit status, which alone does not
// break the connection): the next command runs nothing. Opening a session on a dead connection
// can wait forever in x/crypto/ssh (a channel registered after the connection's channels were
// dropped is never answered), so the next command must not try.
func TestRunAfterTheServerDroppedTheConnection(t *testing.T) {
	srv, c := pinnedConn(t, func(string, []byte) linuxsshtest.Response { return linuxsshtest.Response{Hangup: true} })
	_, err := c.Run(context.Background(), CmdVersion())
	require.Error(t, err)
	require.Eventually(t, func() bool { return !c.Healthy() }, 5*time.Second, 5*time.Millisecond,
		"the dropped connection is noticed without another command")
	before := len(srv.Commands())
	err = runWithin(t, 5*time.Second, c, context.Background(), CmdVersion())
	assert.Equal(t, "ssh.unreachable", providerCode(t, err).Code)
	assert.Len(t, srv.Commands(), before, "nothing was sent")
}

// A context cancelled before the call runs nothing (no random pick against a fast answer) and
// leaves the connection usable.
func TestRunWithACancelledContextRunsNothing(t *testing.T) {
	srv, c := pinnedConn(t, okHandler)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 20; i++ {
		_, err := c.Run(ctx, CmdVersion())
		pe := providerCode(t, err)
		assert.Equal(t, "ssh.timeout", pe.Code)
		assert.ErrorIs(t, err, context.Canceled)
	}
	assert.Empty(t, srv.Commands())
	assert.True(t, c.Healthy())
}

func TestOSReleaseIsParsedAndCleaned(t *testing.T) {
	srv, c := pinnedConn(t, func(cmd string, _ []byte) linuxsshtest.Response {
		if cmd != OSReleaseCommand {
			return linuxsshtest.Response{Exit: 127}
		}
		return linuxsshtest.Response{Stdout: []byte("NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu \x1b[31m22.04 LTS\"\nHOME_URL=\"https://www.ubuntu.com/\"\n")}
	})
	r, err := c.OSRelease(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ubuntu", r.ID)
	assert.Equal(t, "22.04", r.VersionID)
	assert.Equal(t, "Ubuntu [31m22.04 LTS", r.PrettyName, "control characters (terminal escapes) are dropped")
	assert.Equal(t, []string{"cat /etc/os-release"}, srv.Commands())
}

func TestDecodeHelper(t *testing.T) {
	type out = helperproto.VersionResponse
	ok, err := DecodeHelper[out](Result{Stdout: []byte(`{"ok":true,"helper":"1.0.0","protocol":1}`)}, "version")
	require.NoError(t, err)
	assert.Equal(t, 1, ok.Protocol)

	for _, tc := range []struct {
		name   string
		r      Result
		code   string
		helper string
		retry  bool
	}{
		{"ok false", Result{Stdout: []byte(`{"ok":false}`)}, "ssh.protocol_error", "", false},
		{"no ok field", Result{Stdout: []byte(`{"helper":"1"}`)}, "ssh.protocol_error", "", false},
		{"not json", Result{Stdout: []byte("hello")}, "ssh.protocol_error", "", false},
		{"two values", Result{Stdout: []byte(`{"ok":true}{"ok":true}`)}, "ssh.protocol_error", "", false},
		{"refused", Result{ExitCode: 2, Stdout: []byte(`{"ok":false,"code":"PATH_NOT_ALLOWED","message":"no"}`)}, "ssh.helper_refused", "PATH_NOT_ALLOWED", false},
		{"failed", Result{ExitCode: 4, Stdout: []byte(`{"ok":false,"code":"IO_ERROR","message":"no"}`)}, "ssh.helper_refused", "IO_ERROR", true},
		{"hash mismatch", Result{ExitCode: 3, Stdout: []byte(`{"ok":false,"code":"HASH_MISMATCH","message":"x"}`)}, "ssh.file_changed", "HASH_MISMATCH", true},
		{"not found", Result{ExitCode: 3, Stdout: []byte(`{"ok":false,"code":"NOT_FOUND","message":"x"}`)}, "ssh.helper_refused", "NOT_FOUND", false},
		{"keys managed elsewhere", Result{ExitCode: 2, Stdout: []byte(`{"ok":false,"code":"AUTHORIZED_KEYS_COMMAND","message":"x"}`)}, "ssh.keys_managed_elsewhere", "AUTHORIZED_KEYS_COMMAND", false},
		{"sshd failed", Result{ExitCode: 3, Stdout: []byte(`{"ok":false,"code":"SSHD_FAILED","message":"x"}`)}, "ssh.helper_refused", "SSHD_FAILED", false},
		{"unsafe file", Result{ExitCode: 2, Stdout: []byte(`{"ok":false,"code":"UNSAFE_FILE","message":"x"}`)}, "ssh.helper_refused", "UNSAFE_FILE", false},
		{"hash mismatch on the wrong exit", Result{ExitCode: 2, Stdout: []byte(`{"ok":false,"code":"HASH_MISMATCH","message":"x"}`)}, "ssh.helper_refused", "HASH_MISMATCH", false},
		{"hostile code", Result{ExitCode: 2, Stdout: []byte(`{"ok":false,"code":"X; rm -rf /","message":"x"}`)}, "ssh.protocol_error", "", false},
		{"error with ok true", Result{ExitCode: 2, Stdout: []byte(`{"ok":true,"code":"USAGE"}`)}, "ssh.protocol_error", "", false},
		{"sudo refused", Result{ExitCode: 1, Stdout: nil}, "ssh.helper_missing", "", false},
		{"not installed", Result{ExitCode: 127}, "ssh.helper_missing", "", false},
	} {
		_, err := DecodeHelper[out](tc.r, "authkeys-read")
		pe := providerCode(t, err)
		assert.Equal(t, tc.code, pe.Code, tc.name)
		assert.Equal(t, tc.retry, pe.Retryable, tc.name)
		assert.Equal(t, tc.helper, pe.Params["helper_code"], tc.name)
		assert.Equal(t, "authkeys-read", pe.Params["subcommand"], tc.name)
	}
}

func TestParseConfig(t *testing.T) {
	c, errs := ParseConfig(providers.TargetConfig{"host": "web-01.example.com", "port": float64(2222), "username": "deploy"})
	require.Empty(t, errs)
	assert.Equal(t, Config{Host: "web-01.example.com", Port: 2222, Username: "deploy"}, c)

	c, errs = ParseConfig(providers.TargetConfig{"host": "2001:db8::5"})
	require.Empty(t, errs)
	assert.Equal(t, Config{Host: "2001:db8::5", Port: 22, Username: "alice-svc"}, c)

	_, errs = ParseConfig(providers.TargetConfig{"port": 0, "username": "Root!"})
	fields := map[string]string{}
	for _, e := range errs {
		fields[e.Field] = e.Code
	}
	assert.Equal(t, map[string]string{"host": validate.Required, "port": validate.OutOfRange, "username": validate.Pattern}, fields)

	_, errs = ParseConfig(providers.TargetConfig{"host": "web 01; id", "port": "22"})
	fields = map[string]string{}
	for _, e := range errs {
		fields[e.Field] = e.Code
	}
	assert.Equal(t, map[string]string{"host": validate.Pattern, "port": validate.OutOfRange}, fields)
}

// A host-key store that hangs must not hang Dial past its handshake budget (the callback does no I/O).
func TestHungHostKeyStoreDoesNotHangDial(t *testing.T) {
	_, cfg, cred := testServer(t, okHandler)
	release := make(chan struct{})
	defer close(release)
	d := newDialer(&memHostKeys{blockObserved: release})
	d.HandshakeTimeout = 300 * time.Millisecond
	start := time.Now()
	_, err := d.Dial(context.Background(), testTarget, cfg, cred)
	assert.Less(t, time.Since(start), 600*time.Millisecond+time.Second/2)
	assert.Equal(t, "internal.unexpected", providerCode(t, err).Code)
}

func TestHelperKilledBySignalIsNotHelperMissing(t *testing.T) {
	_, c := pinnedConn(t, func(string, []byte) linuxsshtest.Response {
		return linuxsshtest.Response{Signal: "KILL"}
	})
	_, err := c.Run(context.Background(), CmdVersion())
	assert.Equal(t, "ssh.protocol_error", providerCode(t, err).Code)
}

func TestCleanValueDropsControlAndFormatCharacters(t *testing.T) {
	assert.Equal(t, "Ubuntu 22.04", cleanValue("\"Ubu\u0085ntu\u202e 22\u200b.04\u0007\"", 200))
}

func TestServerWithoutPublicKeyAuthIsAuthFailed(t *testing.T) {
	srv, cfg, cred := testServer(t, okHandler)
	srv.DisablePublicKeyAuth()
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	_, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.auth_failed", pe.Code)
	assert.False(t, pe.Retryable)
	assert.Equal(t, "publickey_not_offered", pe.Params["reason"])
}

func TestLazyAuthFetchesAndReleasesOnce(t *testing.T) {
	cred := newFakeCred(t)
	a := &lazyAuth{cred: cred, ctx: context.Background()}
	s1, err := a.signers()
	require.NoError(t, err)
	s2, err := a.signers()
	require.NoError(t, err)
	assert.Equal(t, s1[0].PublicKey().Marshal(), s2[0].PublicKey().Marshal())
	attempted, err := a.done()
	require.NoError(t, err)
	assert.True(t, attempted)
	assert.Equal(t, 1, cred.fetches())
	assert.Equal(t, 1, cred.releases())
}

// Every helper error code maps to a reason of the provider catalog (global constraints).
func TestEveryHelperCodeHasAReason(t *testing.T) {
	catalog := map[string]bool{"ssh.helper_refused": true, "ssh.file_changed": true, "ssh.keys_managed_elsewhere": true, "ssh.output_too_large": true}
	codes := []string{helperproto.CodeUsage, helperproto.CodeUnknownSubcommand, helperproto.CodeNotRoot,
		helperproto.CodeInvalidArgument, helperproto.CodePathNotAllowed, helperproto.CodeNotRegularFile,
		helperproto.CodeInsecurePermissions, helperproto.CodeTooLarge, helperproto.CodeHashMismatch,
		helperproto.CodeNotFound, helperproto.CodeSSHDFailed, helperproto.CodeIOError, helperproto.CodeUnsafeFile,
		helperproto.CodeAuthorizedKeysCommand, helperproto.CodeContentMismatch, helperproto.CodeHomeNotWritable,
		helperproto.CodeNginxNotFound, helperproto.CodeConfigInvalid, helperproto.CodeConfigChanged, helperproto.CodeNoSpace,
		helperproto.CodeBadContent, helperproto.CodeBusy, helperproto.CodeUnknownOp, helperproto.CodeProbeFailed,
		helperproto.CodeOutputTooLarge, helperproto.CodeSuperseded}
	for _, code := range codes {
		for _, exit := range []int{helperproto.ExitRefused, helperproto.ExitPrecondition, helperproto.ExitFailed} {
			reason, _ := helperReason(helperproto.SubNginxDeploy, exit, code)
			assert.True(t, catalog[reason], "%s (exit %d) -> %s", code, exit, reason)
		}
	}
}

// The codes of the Nginx subcommands: BUSY and IO_ERROR are retryable refusals, OUTPUT_TOO_LARGE
// is the existing output-too-large reason, a hash mismatch of a deploy or restore is final, and the
// rest are plain refusals. Nothing but a well-formed answer is a refusal ("nothing changed").
func TestNginxHelperCodesMapToProviderErrors(t *testing.T) {
	type out struct{}
	for _, tc := range []struct {
		sub    string
		exit   int
		code   string
		reason string
		retry  bool
	}{
		{"nginx-deploy", 4, "BUSY", "ssh.helper_refused", true},
		{"nginx-restore", 4, "BUSY", "ssh.helper_refused", true},
		{"cleanup", 4, "BUSY", "ssh.helper_refused", true},
		{"nginx-deploy", 4, "IO_ERROR", "ssh.helper_refused", true},
		{"nginx-dump", 4, "IO_ERROR", "ssh.helper_refused", true},
		{"nginx-test", 4, "IO_ERROR", "ssh.helper_refused", true},
		{"nginx-dump", 4, "OUTPUT_TOO_LARGE", "ssh.output_too_large", false},
		{"nginx-deploy", 3, "HASH_MISMATCH", "ssh.file_changed", false},
		{"nginx-restore", 3, "HASH_MISMATCH", "ssh.file_changed", false},
		{"authkeys-write", 3, "HASH_MISMATCH", "ssh.file_changed", true},
		{"nginx-deploy", 3, "SUPERSEDED", "ssh.helper_refused", false},
		{"nginx-restore", 3, "SUPERSEDED", "ssh.helper_refused", false},
		{"nginx-restore", 3, "UNKNOWN_OP", "ssh.helper_refused", false},
		{"nginx-deploy", 3, "NO_SPACE", "ssh.helper_refused", false},
		{"nginx-deploy", 2, "TOO_LARGE", "ssh.helper_refused", false},
		{"nginx-deploy", 2, "INVALID_ARGUMENT", "ssh.helper_refused", false},
		{"nginx-deploy", 2, "BAD_CONTENT", "ssh.helper_refused", false},
		{"nginx-deploy", 3, "CONTENT_MISMATCH", "ssh.helper_refused", false},
		{"nginx-deploy", 3, "CONFIG_CHANGED", "ssh.helper_refused", false},
		{"nginx-dump", 3, "NGINX_NOT_FOUND", "ssh.helper_refused", false},
		{"nginx-test", 3, "NGINX_NOT_FOUND", "ssh.helper_refused", false},
		{"nginx-dump", 3, "CONFIG_INVALID", "ssh.helper_refused", false},
		{"tls-probe", 4, "PROBE_FAILED", "ssh.helper_refused", false},
	} {
		body := `{"ok":false,"code":"` + tc.code + `","message":"x"}`
		_, err := DecodeHelper[out](Result{ExitCode: tc.exit, Stdout: []byte(body)}, tc.sub)
		pe := providerCode(t, err)
		assert.Equal(t, tc.reason, pe.Code, "%s %s", tc.sub, tc.code)
		assert.Equal(t, tc.retry, pe.Retryable, "%s %s", tc.sub, tc.code)
		assert.Equal(t, tc.code, pe.Params["helper_code"])
	}
	// No answer, a malformed answer, a signal or an unknown exit is never a refusal.
	for name, r := range map[string]Result{
		"exit 4 without JSON": {ExitCode: 4},
		"exit 3 truncated":    {ExitCode: 3, Stdout: []byte(`{"ok":false,"code":"SUPERS`)},
		"exit 0 without ok":   {Stdout: []byte(`{"phase":"committed"}`)},
		"exit 0 empty":        {},
	} {
		_, err := DecodeHelper[out](r, "nginx-deploy")
		assert.Equal(t, "ssh.protocol_error", providerCode(t, err).Code, name)
	}
}

// A2-I1: a server that stalls x/crypto's read loop (a malformed exit-status, then more requests
// than it buffers, the channel held open) cannot hold Run past its budget: closing the socket does
// not wake that loop, so Run gives up after a short grace and abandons the goroutine.
func TestRunReturnsWhenTheServerStallsTheReadLoop(t *testing.T) {
	_, c := pinnedConn(t, func(string, []byte) linuxsshtest.Response { return linuxsshtest.Response{StallReadLoop: true} })
	// Fix round 1, minor 8: a command with stdin (as nginx-deploy's key), wiped by the caller once Run
	// returned while the session goroutine is abandoned; run under -race.
	input := bytes.Repeat([]byte("k"), 256<<10)
	cmd, err := CmdNginxDeploy(testTarget, "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", strings.Repeat("a", 64), input)
	require.NoError(t, err)
	cmd.timeout = 300 * time.Millisecond
	err = runWithin(t, 5*time.Second+abandonGrace, c, context.Background(), cmd)
	cmd.WipeInput()
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.False(t, c.Healthy())

	_, c = pinnedConn(t, func(string, []byte) linuxsshtest.Response { return linuxsshtest.Response{StallReadLoop: true} })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err = runWithin(t, 5*time.Second+abandonGrace, c, ctx, CmdVersion())
	assert.Equal(t, "ssh.timeout", providerCode(t, err).Code)
	assert.False(t, c.Healthy())
}

// blockingCred is a credential source that ignores its context (a hung vault): it answers only once
// release is closed.
type blockingCred struct {
	inner    *fakeCred
	release  chan struct{}
	mu       sync.Mutex
	released int
}

func (b *blockingCred) SSHSigner(ctx context.Context) (ssh.Signer, func(), error) {
	<-b.release
	s, rel, err := b.inner.SSHSigner(ctx)
	return s, func() {
		rel()
		b.mu.Lock()
		b.released++
		b.mu.Unlock()
	}, err
}

// A2 m4: the client key is fetched on the handshake path; a credential source that ignores its
// context cannot hold Dial past the handshake budget, and a key it hands out late is released.
func TestHungCredentialSourceDoesNotHangDial(t *testing.T) {
	srv, cfg, cred := testServer(t, okHandler)
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	bc := &blockingCred{inner: cred, release: make(chan struct{})}
	d := newDialer(hk)
	d.HandshakeTimeout = 300 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		_, err := d.Dial(context.Background(), testTarget, cfg, bc)
		done <- err
	}()
	select {
	case err := <-done:
		pe := providerCode(t, err)
		assert.Equal(t, "internal.unexpected", pe.Code)
		assert.True(t, pe.Retryable, "fix round 1 minor 6: a key that came too late may come in time later")
	case <-time.After(5 * time.Second):
		close(bc.release)
		t.Fatal("Dial hung on the credential source")
	}
	close(bc.release)
	require.Eventually(t, func() bool {
		bc.mu.Lock()
		defer bc.mu.Unlock()
		return bc.released == 1
	}, 5*time.Second, 10*time.Millisecond, "the late key is released")
}

// dropServer (adapted from the audit's PoC, AUD-10) accepts TCP connections and runs the SSH
// handshake with hostKey; when the client starts public-key authentication it closes the
// connection (an sshd restart, LoginGraceTime, a firewall state loss). With beforeBanner it closes
// the connection before any SSH data (sshd over MaxStartups, a load balancer without a backend).
func dropServer(t *testing.T, hostKey ssh.Signer, beforeBanner bool) Config {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			if beforeBanner {
				_ = nc.Close()
				continue
			}
			go func() {
				conf := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
					_ = nc.Close()
					return nil, errors.New("dropped")
				}}
				conf.AddHostKey(hostKey)
				_, _, _, _ = ssh.NewServerConn(nc, conf)
				_ = nc.Close()
			}()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return Config{Host: "127.0.0.1", Port: addr.Port, Username: "alice-svc"}
}

// AUD-10: a connection lost during authentication (the host key matched its pin) is the retryable
// ssh.unreachable, not ssh.auth_failed (which marks the target, mails every Administrator and is
// never retried); only the server's "no more methods" answer is an authentication failure.
func TestConnectionLostDuringAuthenticationIsUnreachable(t *testing.T) {
	hostKey := linuxsshtest.NewHostKey(t)
	cfg := dropServer(t, hostKey, false)
	hk := &memHostKeys{}
	hk.pin(hostKey.PublicKey())
	_, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, newFakeCred(t))
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.unreachable", pe.Code)
	assert.True(t, pe.Retryable)
}

// AUD-10: a server that closes the connection before the SSH banner is the retryable
// ssh.unreachable, with or without a pinned key.
func TestConnectionClosedBeforeTheBannerIsUnreachable(t *testing.T) {
	hostKey := linuxsshtest.NewHostKey(t)
	cfg := dropServer(t, hostKey, true)
	for name, hk := range map[string]*memHostKeys{"pinned": func() *memHostKeys {
		hk := &memHostKeys{}
		hk.pin(hostKey.PublicKey())
		return hk
	}(), "unpinned": {}} {
		_, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, newFakeCred(t))
		pe := providerCode(t, err)
		assert.Equal(t, "ssh.unreachable", pe.Code, name)
		assert.True(t, pe.Retryable, name)
	}
}

// Fix round 1, minor 4: AUD-10 tells an authentication refusal from a lost connection by
// x/crypto's message text. This pins the wording against the real library: a rejected key, a server
// without public-key authentication and a disconnect for too many attempts are each recognised; if
// x/crypto changes its wording this fails loudly.
func TestAuthRefusalWordingOfXCrypto(t *testing.T) {
	refusal := func(t *testing.T, srv *linuxsshtest.Server, cfg Config, cred *fakeCred) error {
		t.Helper()
		conf := &ssh.ClientConfig{User: cfg.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(cred.signer)},
			HostKeyCallback: ssh.FixedHostKey(srv.HostKey())}
		r := (&Dialer{Clock: clock.Real{}}).handshake(context.Background(), cfg.addr(), conf)
		if r.client != nil {
			_ = r.client.Close()
		}
		require.Error(t, r.err)
		return r.err
	}
	t.Run("key rejected", func(t *testing.T) {
		srv, cfg, _ := testServer(t, okHandler)
		err := refusal(t, srv, cfg, newFakeCred(t))
		assert.True(t, authRefused(err), "%v", err)
		assert.Contains(t, err.Error(), "ssh: unable to authenticate")
	})
	t.Run("no public-key authentication", func(t *testing.T) {
		srv, cfg, cred := testServer(t, okHandler)
		srv.DisablePublicKeyAuth()
		err := refusal(t, srv, cfg, cred)
		assert.True(t, authRefused(err), "%v", err)
	})
	t.Run("too many authentication failures", func(t *testing.T) {
		srv, cfg, _ := testServer(t, okHandler)
		srv.SetMaxAuthTries(1)
		err := refusal(t, srv, cfg, newFakeCred(t))
		assert.Contains(t, err.Error(), "too many authentication failures")
		assert.True(t, authRefused(err), "%v", err)
	})
	t.Run("a lost connection is not a refusal", func(t *testing.T) {
		assert.False(t, authRefused(errors.New("ssh: handshake failed: EOF")))
	})
}

// Dial classifies the disconnect for too many attempts as the authentication failure it is.
func TestTooManyAuthenticationFailuresIsAuthFailed(t *testing.T) {
	srv, cfg, _ := testServer(t, okHandler)
	srv.SetMaxAuthTries(1)
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	_, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, newFakeCred(t))
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.auth_failed", pe.Code)
	assert.False(t, pe.Retryable)
}
