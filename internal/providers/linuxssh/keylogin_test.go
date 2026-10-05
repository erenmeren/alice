package linuxssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

type signerSource struct {
	s        ssh.Signer
	released *bool
}

func (k signerSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return k.s, func() {
		if k.released != nil {
			*k.released = true
		}
	}, nil
}

func newUserKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " alice:test:2026-10-05"
}

// Review Focus 1: accepted only when the server took exactly this key for this user.
func TestVerifyKeyLoginOutcomes(t *testing.T) {
	e := newProvEnv(t)
	s, line := newUserKey(t)
	other, _ := newUserKey(t)
	e.emu.AddUser("deploy", 1001, "/home/deploy")
	e.emu.SetFile("/home/deploy/.ssh/authorized_keys", []byte(line+"\n"))
	e.srv.SetLoginCheck(e.emu.AcceptsLogin)
	sess := e.open(t)
	defer sess.Close()

	// every login is a connection of its own that the server sees closed again, and runs nothing
	cmds, conns, open := len(e.srv.Commands()), e.srv.Connections(), e.srv.OpenConnections()
	login := func(user string, key providers.CredentialSource) providers.KeyLoginResult {
		t.Helper()
		r, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: user, Key: key})
		require.NoError(t, err)
		conns++
		assert.Equal(t, conns, e.srv.Connections(), "one TCP connection per test login")
		assert.Eventually(t, func() bool { return e.srv.OpenConnections() == open }, 5*time.Second, 10*time.Millisecond,
			"the test login's connection is closed again")
		assert.Len(t, e.srv.Commands(), cmds, "a test login runs nothing")
		return r
	}

	released := false
	assert.Equal(t, providers.KeyLoginAccepted, login("deploy", signerSource{s, &released}).Outcome)
	assert.True(t, released, "the key is released after the handshake")
	assert.Equal(t, providers.KeyLoginRefused, login("deploy", signerSource{other, nil}).Outcome)
	assert.Equal(t, providers.KeyLoginRefused, login("nobody", signerSource{s, nil}).Outcome, "the key is not the user's")

	// a cert-authority line (any spelling of the option) never lets a key in
	ca, caLine := newUserKey(t)
	e.emu.SetFile("/home/deploy/.ssh/authorized_keys2", []byte("CERT-AUTHORITY "+caLine+"\n"))
	assert.Equal(t, providers.KeyLoginRefused, login("deploy", signerSource{ca, nil}).Outcome, "a cert-authority line is not a key")
	assert.False(t, e.emu.AcceptsLogin("deploy", ca.PublicKey()))
	e.emu.SetFile("/home/deploy/.ssh/authorized_keys2", []byte(caLine+"\n"))
	assert.Equal(t, providers.KeyLoginAccepted, login("deploy", signerSource{ca, nil}).Outcome, "the same key as a plain line is")
}

// The budget bounds one test login: a server that says nothing ends it with ssh.timeout, whether
// the budget or the caller's own deadline expires first, and the connection is closed again.
func TestVerifyKeyLoginBudgetExpires(t *testing.T) {
	e := newProvEnv(t)
	s, _ := newUserKey(t)
	sess := e.open(t)
	defer sess.Close()
	e.srv.StallHandshake()
	open := e.srv.OpenConnections()

	old := keyLoginTimeout
	t.Cleanup(func() { keyLoginTimeout = old })
	for _, tc := range []struct {
		name   string
		budget time.Duration
		parent time.Duration
	}{
		{"the budget", 100 * time.Millisecond, 0},
		{"the callers deadline", time.Hour, 100 * time.Millisecond},
	} {
		name := tc.name
		keyLoginTimeout = tc.budget
		c, cancel := context.WithCancel(context.Background())
		if tc.parent > 0 {
			cancel()
			c, cancel = context.WithTimeout(context.Background(), tc.parent)
		}
		start := time.Now()
		r, err := sess.VerifyKeyLogin(c, providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
		cancel()
		var pe *providers.Error
		require.ErrorAs(t, err, &pe, name)
		assert.Equal(t, "ssh.timeout", pe.Code, name)
		assert.ErrorIs(t, err, context.DeadlineExceeded, name)
		assert.Empty(t, r.Outcome, "a timeout is no outcome: %s", name)
		assert.Less(t, time.Since(start), 5*time.Second, name)
		assert.Eventually(t, func() bool { return e.srv.OpenConnections() == open }, 5*time.Second, 10*time.Millisecond, name)
	}
}

// Review Focus 1: a server that lets anyone in without a key proves nothing.
func TestVerifyKeyLoginWithoutKeyIsUnprovable(t *testing.T) {
	e := newProvEnv(t)
	s, _ := newUserKey(t)
	sess := e.open(t)
	defer sess.Close()
	e.srv.AcceptNoAuth()
	r, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginUnprovable, r.Outcome)
}

func TestVerifyKeyLoginNoPublicKeyMethodIsUnprovable(t *testing.T) {
	e := newProvEnv(t)
	s, _ := newUserKey(t)
	sess := e.open(t)
	defer sess.Close()
	e.srv.DisablePublicKeyAuth()
	r, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginUnprovable, r.Outcome)
}

func TestVerifyKeyLoginRefusesBadRequestsAndHonoursContext(t *testing.T) {
	e := newProvEnv(t)
	s, _ := newUserKey(t)
	sess := e.open(t)
	defer sess.Close()
	for _, req := range []providers.KeyLoginRequest{{}, {OSUser: "deploy"}, {OSUser: "bad user", Key: signerSource{s, nil}}} {
		_, err := sess.VerifyKeyLogin(context.Background(), req)
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, "ssh.helper_refused", pe.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sess.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	assert.ErrorIs(t, err, context.Canceled)
	require.NoError(t, sess.Close())
	_, err = sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	assert.Error(t, err, "a closed session refuses")
}

// A host key change seen by the test login is an error, never an outcome.
func TestVerifyKeyLoginHostKeyChanged(t *testing.T) {
	e := newProvEnv(t)
	s, _ := newUserKey(t)
	sess := e.open(t)
	defer sess.Close()
	e.srv.SetHostKey(linuxsshtest.NewHostKey(t)) // another key than the pinned one
	_, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "target.host_key_changed", pe.Code)
}

func TestKeyLoginBudget(t *testing.T) { assert.Equal(t, 10*time.Second, KeyLoginBudget) }

// T4-m3: a key source that fails is reported as such, not as a fault of the platform key; the code
// stays internal.unexpected and the source's own text never reaches the error.
func TestVerifyKeyLoginKeySourceFailure(t *testing.T) {
	e := newProvEnv(t)
	sess := e.open(t)
	defer sess.Close()
	_, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: canaryCred{canary: "CANARY-key-text"}})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "internal.unexpected", pe.Code)
	assert.NotContains(t, err.Error(), "CANARY-key-text")
	var ce credentialError
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Error(), "client key", "the internal text names no platform key")
	assert.NotContains(t, ce.Error(), "platform")
}
