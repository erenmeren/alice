package linuxssh

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

var (
	h01Token = strings.Repeat("k", 43)
	h01Auth  = []byte(h01Token + "." + strings.Repeat("t", 43))
)

func TestACMEChallengeCommandLinesAreExact(t *testing.T) {
	put, err := CmdACMEChallengePut(h01Token, h01Auth)
	require.NoError(t, err)
	rm, err := CmdACMEChallengeRm(h01Token)
	require.NoError(t, err)
	const pre = "sudo -n /usr/local/libexec/alice-helper "
	assert.Equal(t, pre+"acme-challenge-put --token '"+h01Token+"'", put.Line())
	assert.Equal(t, pre+"acme-challenge-rm --token '"+h01Token+"'", rm.Line())
	assert.Equal(t, helperproto.SubACMEChallengePut, put.Subcommand())
	assert.Equal(t, helperproto.SubACMEChallengeRm, rm.Subcommand())
	assert.True(t, put.sudo)
	assert.True(t, rm.sudo)
	assert.Equal(t, h01Auth, put.input(), "the key authorization travels on stdin only")
	assert.NotContains(t, put.Line(), string(h01Auth))
	assert.Nil(t, rm.input())
	assert.Equal(t, DefaultCommandTimeout, put.timeout)
	assert.Equal(t, DefaultCommandTimeout, rm.timeout)
	assert.Equal(t, int64(smallOutput), put.maxOutput)
	// A base64url token may start with "-": it is quoted as one word and the helper reads it as
	// --token's value (quoteArg refuses a leading "-" for the option-parsing subcommands).
	dash := "-" + strings.Repeat("a", 42)
	c, err := CmdACMEChallengeRm(dash)
	require.NoError(t, err)
	assert.Equal(t, pre+"acme-challenge-rm --token '"+dash+"'", c.Line())
}

func TestACMEChallengeCommandsCopyTheirInput(t *testing.T) {
	in := append([]byte(nil), h01Auth...)
	c, err := CmdACMEChallengePut(h01Token, in)
	require.NoError(t, err)
	in[0] = 'X'
	assert.Equal(t, h01Auth, c.input())
}

func TestACMEChallengeCommandsRefuseHostileValues(t *testing.T) {
	thumb := strings.Repeat("t", 43)
	for _, tok := range []string{
		"", strings.Repeat("a", 21), strings.Repeat("a", 129), "../../etc/passwd" + strings.Repeat("a", 10),
		strings.Repeat("a", 22) + "/x", strings.Repeat("a", 22) + "'", strings.Repeat("a", 22) + "' ; id #",
		strings.Repeat("a", 22) + "\x00", strings.Repeat("a", 22) + "\n", strings.Repeat("a", 21) + "ç", "$(id)" + strings.Repeat("a", 22),
		strings.Repeat("a", 22) + ".", strings.Repeat("a", 22) + " x",
	} {
		c, err := CmdACMEChallengePut(tok, []byte(tok+"."+thumb))
		assert.ErrorIs(t, err, ErrInvalidArgument, "put %q", tok)
		assert.Empty(t, c.Line())
		c, err = CmdACMEChallengeRm(tok)
		assert.ErrorIs(t, err, ErrInvalidArgument, "rm %q", tok)
		assert.Empty(t, c.Line())
		_, err = quoteToken(tok)
		assert.ErrorIs(t, err, ErrInvalidArgument, "quote %q", tok)
	}
	for name, body := range map[string][]byte{
		"empty":         nil,
		"other token":   []byte(strings.Repeat("z", 43) + "." + thumb),
		"newline":       append(append([]byte(nil), h01Auth...), '\n'),
		"short":         h01Auth[:len(h01Auth)-1],
		"oversize":      append(append([]byte(nil), h01Auth...), make([]byte, helperproto.MaxACMEBody)...),
		"shell in body": []byte(h01Token + "." + strings.Repeat("t", 38) + "$(id)"),
	} {
		_, err := CmdACMEChallengePut(h01Token, body)
		assert.ErrorIs(t, err, ErrInvalidArgument, name)
	}
}

// h01Env is a provider over the emulator; the session's connection carries the helper's protocol.
func h01Conn(t *testing.T, e *provEnv) *Conn {
	t.Helper()
	return connOf(t, e.open(t))
}

func TestPublishAndRemoveHTTP01Token(t *testing.T) {
	e := newProvEnv(t)
	c := h01Conn(t, e)
	res, err := c.PublishHTTP01Token(context.Background(), h01Token, h01Auth)
	require.NoError(t, err)
	assert.Equal(t, helperproto.ACMEChallengePath(h01Token), res.Path)
	assert.False(t, res.Replaced)
	got, ok := e.emu.ACMEToken(h01Token)
	require.True(t, ok)
	assert.Equal(t, h01Auth, got)
	res, err = c.PublishHTTP01Token(context.Background(), h01Token, h01Auth)
	require.NoError(t, err)
	assert.True(t, res.Replaced)
	removed, err := c.RemoveHTTP01Token(context.Background(), h01Token)
	require.NoError(t, err)
	assert.True(t, removed)
	_, ok = e.emu.ACMEToken(h01Token)
	assert.False(t, ok)
	removed, err = c.RemoveHTTP01Token(context.Background(), h01Token)
	require.NoError(t, err)
	assert.False(t, removed, "a missing file is success")
	var lines []string
	for _, l := range e.srv.Commands() {
		if strings.Contains(l, "acme-challenge") {
			lines = append(lines, l)
		}
	}
	assert.Equal(t, []string{
		"sudo -n /usr/local/libexec/alice-helper acme-challenge-put --token '" + h01Token + "'",
		"sudo -n /usr/local/libexec/alice-helper acme-challenge-put --token '" + h01Token + "'",
		"sudo -n /usr/local/libexec/alice-helper acme-challenge-rm --token '" + h01Token + "'",
		"sudo -n /usr/local/libexec/alice-helper acme-challenge-rm --token '" + h01Token + "'",
	}, lines)
}

func TestHTTP01TokenRefusalsCarryTheHelperCode(t *testing.T) {
	e := newProvEnv(t)
	c := h01Conn(t, e)
	e.emu.SetACMEChallengeDir(false)
	_, err := c.PublishHTTP01Token(context.Background(), h01Token, h01Auth)
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.helper_refused", pe.Code)
	assert.Equal(t, helperproto.CodeNotFound, pe.Params["helper_code"])
	assert.Equal(t, helperproto.SubACMEChallengePut, pe.Params["subcommand"])
	removed, err := c.RemoveHTTP01Token(context.Background(), h01Token)
	require.NoError(t, err, "no directory: nothing to remove")
	assert.False(t, removed)
	e.emu.SetACMEChallengeDir(true)
	e.emu.FailACME(helperproto.ExitRefused, helperproto.CodePathNotAllowed)
	_, err = c.PublishHTTP01Token(context.Background(), h01Token, h01Auth)
	assert.Equal(t, helperproto.CodePathNotAllowed, providerCode(t, err).Params["helper_code"])
	_, err = c.RemoveHTTP01Token(context.Background(), h01Token)
	assert.Equal(t, helperproto.CodePathNotAllowed, providerCode(t, err).Params["helper_code"])
	// An invalid value never reaches the server.
	before := len(e.srv.Commands())
	_, err = c.PublishHTTP01Token(context.Background(), "../x", h01Auth)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	_, err = c.RemoveHTTP01Token(context.Background(), "../x")
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Len(t, e.srv.Commands(), before)
}

// A1: a protocol 6 helper still opens a session for every existing operation; only HTTP-01 is
// refused, with its own reason, and nothing is sent to the helper.
func TestProtocol6HelperIsRefusedOnlyForHTTP01(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetProtocol(6)
	s := e.open(t)
	_, err := s.TestConnection(context.Background())
	require.NoError(t, err, "existing operations keep working on a protocol 6 helper")
	_, err = s.(*session).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	c := connOf(t, s)
	before := len(e.srv.Commands())
	_, err = c.PublishHTTP01Token(context.Background(), h01Token, h01Auth)
	pe := providerCode(t, err)
	assert.Equal(t, ReasonHTTP01HelperOutdated, pe.Code)
	assert.ErrorIs(t, err, ErrHTTP01HelperOutdated)
	assert.Equal(t, map[string]string{"helper_protocol": "6", "required_protocol": "7"}, pe.Params)
	assert.False(t, pe.Retryable)
	_, err = c.RemoveHTTP01Token(context.Background(), h01Token)
	assert.ErrorIs(t, err, ErrHTTP01HelperOutdated)
	assert.Len(t, e.srv.Commands(), before, "the helper's version is already known: nothing is sent")
	// The helper is reinstalled: the next session reads the new version.
	e.emu.SetProtocol(helperproto.Protocol)
	require.NoError(t, s.Close())
	c2 := h01Conn(t, e)
	_, err = c2.PublishHTTP01Token(context.Background(), h01Token, h01Auth)
	require.NoError(t, err)
}

// A connection that never went through Open asks the helper for its version first.
func TestHTTP01OnAConnectionWithoutAVersion(t *testing.T) {
	for _, p := range []int{6, 7} {
		emu := linuxsshtest.NewEmulator()
		emu.SetProtocol(p)
		srv, cfg, cred := testServer(t, emu.Handler())
		hk := &memHostKeys{}
		hk.pin(srv.HostKey())
		c, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		_, err = c.PublishHTTP01Token(context.Background(), h01Token, h01Auth)
		if p == 6 {
			assert.ErrorIs(t, err, ErrHTTP01HelperOutdated)
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, "/usr/local/libexec/alice-helper version", srv.Commands()[0])
	}
}

func TestHTTP01VersionFailurePropagates(t *testing.T) {
	emu := linuxsshtest.NewEmulator()
	emu.SetHelperMissing(true)
	srv, cfg, cred := testServer(t, emu.Handler())
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	c, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	_, err = c.RemoveHTTP01Token(context.Background(), h01Token)
	assert.Equal(t, "ssh.helper_missing", providerCode(t, err).Code)
}

// The emulator mirrors sudo: without the nginx profile (or with the sudoers file of an older
// setup) sudo refuses the line before the helper sees it.
func TestHTTP01WithoutTheNginxProfile(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetNginxProfile(false)
	c := h01Conn(t, e)
	_, err := c.PublishHTTP01Token(context.Background(), h01Token, h01Auth)
	assert.Equal(t, "ssh.helper_missing", providerCode(t, err).Code)
}
