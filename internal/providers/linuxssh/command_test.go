package linuxssh

import (
	"strings"
	"testing"

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
	assert.Equal(t, DefaultCommandTimeout, read.timeout)
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
	assert.Equal(t, "ssh-ed25519 AAAA x\n", string(c.stdin))
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
