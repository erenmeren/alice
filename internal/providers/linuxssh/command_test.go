package linuxssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
)

var testOp = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000aa")

func TestQuoteArgIsTheOnlyQuoting(t *testing.T) {
	q, err := quoteArg("/home/deploy/.ssh/authorized_keys")
	require.NoError(t, err)
	assert.Equal(t, "'/home/deploy/.ssh/authorized_keys'", q)
	for _, bad := range []string{"a'b", "a b", "", "-x", "--", "a\nb", "$(id)", "?", "[a]", "{a,b}", "!x", "a\\b", "%", "a\tb",
		"a;b", "a|b", "a&b", "a<b", "a>b", "a`b", "a\"b", "a*b", "a~b", "a#b", "a=b", "a,b", "ç"} {
		_, err := quoteArg(bad)
		assert.ErrorIs(t, err, ErrInvalidArgument, "%q", bad)
	}
}

func TestQuoteArgLengthLimit(t *testing.T) {
	_, err := quoteArg(strings.Repeat("a", 4096))
	assert.NoError(t, err)
	_, err = quoteArg(strings.Repeat("a", 4097))
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestCommandLinesAreExact(t *testing.T) {
	read, err := CmdAuthKeysRead("/home/deploy/.ssh/authorized_keys")
	require.NoError(t, err)
	write, err := CmdAuthKeysWrite("/root/.ssh/authorized_keys", helperproto.AbsentSHA256, testOp, []byte("x\n"))
	require.NoError(t, err)
	sha := strings.Repeat("ab", 32)
	// A-2 (protocol 3): the SHA-256 of the new content travels on the command line.
	const xSHA = "73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac"
	const emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	writeSHA, err := CmdAuthKeysWrite("/root/.ssh/authorized_keys", sha, testOp, nil)
	require.NoError(t, err)
	cleanup, err := CmdCleanup(testOp)
	require.NoError(t, err)

	for _, tc := range []struct {
		cmd  HelperCommand
		line string
		sub  string
	}{
		{CmdVersion(), "/usr/local/libexec/alice-helper version", "version"},
		{CmdSSHDDump(), "sudo -n /usr/local/libexec/alice-helper sshd-dump", "sshd-dump"},
		{CmdHostKeys(), "sudo -n /usr/local/libexec/alice-helper hostkeys", "hostkeys"},
		{CmdAuthKeysList(), "sudo -n /usr/local/libexec/alice-helper authkeys-list", "authkeys-list"},
		{read, "sudo -n /usr/local/libexec/alice-helper authkeys-read '/home/deploy/.ssh/authorized_keys'", "authkeys-read"},
		{write, "sudo -n /usr/local/libexec/alice-helper authkeys-write '/root/.ssh/authorized_keys' --expect-sha256 'absent' --content-sha256 '" + xSHA + "' --op '0190f5a0-0000-7000-8000-0000000000aa'", "authkeys-write"},
		{writeSHA, "sudo -n /usr/local/libexec/alice-helper authkeys-write '/root/.ssh/authorized_keys' --expect-sha256 '" + sha + "' --content-sha256 '" + emptySHA + "' --op '0190f5a0-0000-7000-8000-0000000000aa'", "authkeys-write"},
		{cleanup, "sudo -n /usr/local/libexec/alice-helper cleanup --op '0190f5a0-0000-7000-8000-0000000000aa'", "cleanup"},
	} {
		assert.Equal(t, tc.line, tc.cmd.Line())
		assert.Equal(t, tc.sub, tc.cmd.Subcommand())
	}
}

func TestCommandBudgets(t *testing.T) {
	read, err := CmdAuthKeysRead("/root/.ssh/authorized_keys")
	require.NoError(t, err)
	assert.Equal(t, DefaultCommandTimeout, CmdVersion().timeout)
	assert.Equal(t, LongCommandTimeout, CmdSSHDDump().timeout)
	assert.Equal(t, LongCommandTimeout, CmdAuthKeysList().timeout)
	// A-5: authkeys-read and authkeys-write run the same scan as authkeys-list (sshd -T per user),
	// so they get its budget; the helper gives up on its own (helperproto.HelperBudget) 10 s before
	// Alice normally does (a timed-out write is still an uncertain outcome for Alice).
	write, err := CmdAuthKeysWrite("/root/.ssh/authorized_keys", helperproto.AbsentSHA256, testOp, []byte("x\n"))
	require.NoError(t, err)
	assert.Equal(t, LongCommandTimeout, read.timeout)
	assert.Equal(t, LongCommandTimeout, write.timeout)
	assert.LessOrEqual(t, helperproto.HelperBudget+10*time.Second, LongCommandTimeout, "margin for the connection")
	assert.LessOrEqual(t, helperproto.HelperBudget+10*time.Second, DefaultCommandTimeout+30*time.Second)
	assert.Equal(t, int64(DefaultMaxOutput), CmdAuthKeysList().maxOutput)
	// authkeys-read answers base64 of up to 1 MiB plus JSON: 2 MiB is enough and bounded.
	assert.Equal(t, int64(2<<20), read.maxOutput)
	assert.False(t, CmdVersion().sudo, "version runs without sudo (sudoers does not list it)")
	assert.True(t, read.sudo)
}

func TestWriteCopiesItsContent(t *testing.T) {
	content := []byte("ssh-ed25519 AAAA x\n")
	c, err := CmdAuthKeysWrite("/root/.ssh/authorized_keys", helperproto.AbsentSHA256, testOp, content)
	require.NoError(t, err)
	content[0] = 'X'
	assert.Equal(t, "ssh-ed25519 AAAA x\n", string(c.input()))
}

// A-12: every string that would cross into a command line is validated; hostile values never
// produce a command.
func TestHostileArgumentsNeverBecomeCommands(t *testing.T) {
	hostile := []string{
		"",
		"relative/.ssh/authorized_keys",
		"/root/.ssh/authorized_keys; rm -rf /",
		"/root/`id`",
		"/root/$(id)",
		"/root/.ssh/authorized_keys\nid",
		"/root/.ssh/authorized_keys\r",
		"/root/a\x00b",
		"/home/çağla/.ssh/authorized_keys",
		"/home/a b/.ssh/authorized_keys",
		"/home/x/../../etc/shadow",
		"/root/./.ssh/authorized_keys",
		"/root/.ssh/'x'",
		"/root/.ssh/authorized_keys|cat",
		"/root/*",
		"/root/~x",
		"-rf",
		"/" + strings.Repeat("a/", 2048) + "x",
	}
	for _, p := range hostile {
		c, err := CmdAuthKeysRead(p)
		assert.ErrorIs(t, err, ErrInvalidArgument, "read %q", p)
		assert.Empty(t, c.Line(), "no command for %q", p)
		_, err = CmdAuthKeysWrite(p, helperproto.AbsentSHA256, testOp, nil)
		assert.ErrorIs(t, err, ErrInvalidArgument, "write %q", p)
	}
	for _, h := range []string{"absent; id", "ABAB", strings.Repeat("g", 64), "$(id)", strings.Repeat("A", 64)} {
		_, err := CmdAuthKeysWrite("/root/.ssh/authorized_keys", h, testOp, nil)
		assert.ErrorIs(t, err, ErrInvalidArgument, "sha %q", h)
	}
	_, err := CmdAuthKeysWrite("/root/.ssh/authorized_keys", helperproto.AbsentSHA256, uuid.Nil, nil)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	_, err = CmdCleanup(uuid.Nil)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	_, err = CmdAuthKeysWrite("/root/.ssh/authorized_keys", helperproto.AbsentSHA256, testOp,
		make([]byte, helperproto.MaxAuthorizedKeysSize+1))
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestNginxCommandLinesAreExact(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	input := []byte(`{"cert_pem":"c","key_pem":"k"}`)
	h := sha256.Sum256(input)
	deploy, err := CmdNginxDeploy(testOp, "/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", sha, input)
	require.NoError(t, err)
	restore, err := CmdNginxRestore(testOp)
	require.NoError(t, err)
	status, err := CmdNginxStatus(testOp)
	require.NoError(t, err)
	probe, err := CmdTLSProbe("127.0.0.1", 443, "www.example.test", helperproto.ProbeRSA)
	require.NoError(t, err)
	probeNoSNI, err := CmdTLSProbe("::1", 8443, "", helperproto.ProbeAny)
	require.NoError(t, err)
	cleanup, err := CmdCleanup(testOp)
	require.NoError(t, err)
	op := "'0190f5a0-0000-7000-8000-0000000000aa'"
	const pre = "sudo -n /usr/local/libexec/alice-helper "
	for _, tc := range []struct {
		cmd  HelperCommand
		line string
		sub  string
		sudo bool
	}{
		{CmdNginxDump(), pre + "nginx-dump", "nginx-dump", true},
		{CmdNginxTest(), pre + "nginx-test", "nginx-test", true},
		{deploy, pre + "nginx-deploy --op " + op + " --cert '/etc/nginx/ssl/www.crt' --key '/etc/nginx/ssl/www.key' --expect-cert-sha256 '" + sha + "' --content-sha256 '" + hex.EncodeToString(h[:]) + "'", "nginx-deploy", true},
		{restore, pre + "nginx-restore --op " + op, "nginx-restore", true},
		{status, pre + "nginx-status --op " + op, "nginx-status", true},
		{cleanup, pre + "cleanup --op " + op, "cleanup", true},
		{probe, "/usr/local/libexec/alice-helper tls-probe --addr '127.0.0.1' --port '443' --sni 'www.example.test' --key-type 'rsa'", "tls-probe", false},
		{probeNoSNI, "/usr/local/libexec/alice-helper tls-probe --addr '::1' --port '8443' --sni '_' --key-type 'any'", "tls-probe", false},
	} {
		assert.Equal(t, tc.line, tc.cmd.Line())
		assert.Equal(t, tc.sub, tc.cmd.Subcommand())
		assert.Equal(t, tc.sudo, tc.cmd.sudo)
	}
	assert.Equal(t, input, deploy.input())
	assert.Equal(t, int64(helperproto.ServerDumpOutput), CmdNginxDump().maxOutput)
	assert.Equal(t, LongCommandTimeout, CmdNginxDump().timeout)
	assert.Equal(t, LongCommandTimeout, CmdNginxTest().timeout)
	assert.Equal(t, DeployCommandTimeout, deploy.timeout)
	assert.Equal(t, DeployCommandTimeout, restore.timeout)
	// pre-rename budget + nginx -t + reload + rollback nginx -t + rollback reload (30 s each) + startup margin
	assert.GreaterOrEqual(t, DeployCommandTimeout, helperproto.HelperBudget+4*30*time.Second+30*time.Second,
		"the helper's worst case (about 176 s) fits with room for sudo and SSH startup")
	assert.Equal(t, DefaultCommandTimeout, status.timeout)
	assert.Equal(t, DefaultCommandTimeout, probe.timeout)
	assert.Greater(t, cleanup.timeout, 30*time.Second, "cleanup may wait 30 s for the Nginx lock")
}

func TestNginxCommandsRefuseHostileValues(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	deploy := func(cert, key, expect string, op uuid.UUID, in []byte) error {
		_, e := CmdNginxDeploy(op, cert, key, expect, in)
		return e
	}
	probe := func(addr string, port int, sni, kt string) error { _, e := CmdTLSProbe(addr, port, sni, kt); return e }
	in := []byte("{}")
	for name, err := range map[string]error{
		"deploy relative cert":   deploy("etc/x.crt", "/k.key", sha, testOp, in),
		"deploy dotdot":          deploy("/etc/../shadow", "/k.key", sha, testOp, in),
		"deploy same path":       deploy("/a.pem", "/a.pem", sha, testOp, in),
		"deploy root path":       deploy("/", "/a.key", sha, testOp, in),
		"deploy absent hash":     deploy("/a.crt", "/a.key", helperproto.AbsentSHA256, testOp, in),
		"deploy short hash":      deploy("/a.crt", "/a.key", "abcd", testOp, in),
		"deploy shell":           deploy("/a.crt;rm -rf /", "/a.key", sha, testOp, in),
		"deploy quote":           deploy("/a'.crt", "/a.key", sha, testOp, in),
		"deploy nil op":          deploy("/a.crt", "/a.key", sha, uuid.Nil, in),
		"deploy empty input":     deploy("/a.crt", "/a.key", sha, testOp, nil),
		"deploy too large":       deploy("/a.crt", "/a.key", sha, testOp, make([]byte, helperproto.MaxDeployInput+1)),
		"probe hostname":         probe("localhost", 443, "a.b", "any"),
		"probe zone":             probe("fe80::1%eth0", 443, "a.b", "any"),
		"probe non canonical ip": probe("::ffff:1.2.3.4 ", 443, "a.b", "any"),
		"probe port 0":           probe("127.0.0.1", 0, "a.b", "any"),
		"probe port high":        probe("127.0.0.1", 65536, "a.b", "any"),
		"probe sni space":        probe("127.0.0.1", 443, "a b", "any"),
		"probe sni injection":    probe("127.0.0.1", 443, "$(id)", "any"),
		"probe sni ip":           probe("127.0.0.1", 443, "10.0.0.1", "any"),
		"probe key type":         probe("127.0.0.1", 443, "a.b", "dsa"),
	} {
		assert.ErrorIs(t, err, ErrInvalidArgument, name)
	}
	_, err := CmdNginxRestore(uuid.Nil)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	_, err = CmdNginxStatus(uuid.Nil)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestWipeInputClearsTheKey(t *testing.T) {
	c, err := CmdNginxDeploy(testOp, "/a.crt", "/a.key", strings.Repeat("ab", 32), []byte("secret key bytes"))
	require.NoError(t, err)
	c.WipeInput()
	assert.Equal(t, make([]byte, len("secret key bytes")), c.input())
}

// The private key travels in stdin only: the command line, its formatting and its error carry none of it.
func TestDeployKeyIsNeverOutsideStdin(t *testing.T) {
	const needle = "KEYMATERIAL-0123456789abcdef"
	raw, err := json.Marshal(helperproto.NginxDeployInput{CertPEM: "cert-pem", KeyPEM: needle})
	require.NoError(t, err)
	c, err := CmdNginxDeploy(testOp, "/a.crt", "/a.key", strings.Repeat("ab", 32), raw)
	require.NoError(t, err)
	assert.Contains(t, string(c.input()), needle, "the key is in the payload")
	assert.NotContains(t, c.Line(), needle)
	assert.NotContains(t, fmt.Sprintf("%v|%+v|%#v|%s", c.tokens, c.Subcommand(), c.Line(), c.Subcommand()), needle)
	// A rejected deployment (too large) names the limit, never the content.
	big := append(raw, make([]byte, helperproto.MaxDeployInput)...)
	_, err = CmdNginxDeploy(testOp, "/a.crt", "/a.key", strings.Repeat("ab", 32), big)
	require.ErrorIs(t, err, ErrInvalidArgument)
	assert.NotContains(t, err.Error(), needle)
	_, err = CmdNginxDeploy(testOp, "/a.crt\n"+needle, "/a.key", strings.Repeat("ab", 32), raw)
	require.ErrorIs(t, err, ErrInvalidArgument)
	assert.NotContains(t, err.Error(), needle)
	// The command itself prints its line only: every verb, value and pointer, fmt and slog.
	marker := "MARKERKEYBYTES"
	secret, err := json.Marshal(helperproto.NginxDeployInput{CertPEM: "c", KeyPEM: "-----BEGIN " + "PRIVATE KEY-----" + marker})
	require.NoError(t, err)
	sc, err := CmdNginxDeploy(testOp, "/a.crt", "/a.key", strings.Repeat("ab", 32), secret)
	require.NoError(t, err)
	var buf bytes.Buffer
	th, jh := slog.NewTextHandler(&buf, nil), slog.NewJSONHandler(&buf, nil)
	slog.New(th).Info("run", "cmd", sc, "ptr", &sc)
	slog.New(jh).Info("run", slog.Any("cmd", sc), slog.Any("ptr", &sc))
	rendered := []string{buf.String()}
	for _, v := range []any{sc, &sc} {
		rendered = append(rendered, fmt.Sprintf("%v %+v %#v %s %d %x %X %q %10.3s", v, v, v, v, v, v, v, v, v))
	}
	text := strings.Join(rendered, "\n")
	decimal := strings.Trim(fmt.Sprintf("%d", []byte(marker)), "[]")
	for _, needle := range []string{marker, "PRIVATE KEY", hex.EncodeToString([]byte(marker)), decimal, base64.StdEncoding.EncodeToString([]byte(marker))} {
		assert.NotContains(t, text, needle)
	}
	assert.Contains(t, fmt.Sprintf("%s", sc), "nginx-deploy --op")
	assert.Contains(t, buf.String(), "nginx-deploy")
	// The input type redacts itself when formatted.
	in := helperproto.NginxDeployInput{CertPEM: "c", KeyPEM: needle}
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v %s", in, in, in, in), needle)
}

// A command held in an unexported field of another struct is formatted by fmt without its Format
// method (fmt cannot call methods on unexported fields): its stdin is behind a pointer, which fmt
// prints as an address below the top level, so the wrapper never prints the key either.
func TestAWrappedCommandNeverPrintsItsStdin(t *testing.T) {
	marker := "WRAPPEDKEYMARKER"
	secret, err := json.Marshal(helperproto.NginxDeployInput{CertPEM: "c", KeyPEM: "-----BEGIN " + "PRIVATE KEY-----" + marker})
	require.NoError(t, err)
	c, err := CmdNginxDeploy(testOp, "/a.crt", "/a.key", strings.Repeat("ab", 32), secret)
	require.NoError(t, err)
	type wrapper struct {
		name string
		cmd  HelperCommand
		list []HelperCommand
		ptr  *HelperCommand
	}
	w := wrapper{name: "w", cmd: c, list: []HelperCommand{c}, ptr: &c}
	text := fmt.Sprintf("%v %+v %#v %s %q %x %X", w, w, w, w, w, w, w) + fmt.Sprintf("%v %+v %#v", &w, &w, &w)
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("w", slog.Any("w", w))
	slog.New(slog.NewTextHandler(&buf, nil)).Info("w", "w", w)
	text += buf.String()
	decimal := strings.Trim(fmt.Sprintf("%d", []byte(marker)), "[]")
	for _, needle := range []string{marker, "PRIVATE KEY", hex.EncodeToString([]byte(marker)), decimal, base64.StdEncoding.EncodeToString([]byte(marker))} {
		assert.NotContains(t, text, needle)
	}
	// A copy shares the input: wiping either wipes the bytes the other would send.
	cp := c
	cp.WipeInput()
	assert.Equal(t, make([]byte, len(secret)), c.input())
}
