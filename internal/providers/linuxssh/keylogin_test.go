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

	released := false
	r, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, &released}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginAccepted, r.Outcome)
	assert.True(t, released, "the key is released after the handshake")

	r, err = sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{other, nil}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginRefused, r.Outcome)

	r, err = sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "nobody", Key: signerSource{s, nil}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginRefused, r.Outcome, "the key is not the user's")

	for _, cmd := range e.srv.Commands() {
		assert.NotContains(t, cmd, "deploy", "a test login runs nothing")
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
