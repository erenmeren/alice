//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers/linuxssh/helperproto"
)

func TestRunSSHDReportsAFailingServer(t *testing.T) {
	if _, err := exec.LookPath(sshdPath); err != nil {
		t.Skip("no sshd on this machine")
	}
	// An unknown option makes sshd print its usage and exit non-zero: no output is trusted then.
	out, err := runSSHD(context.Background(), "-Z")
	require.Error(t, err)
	assert.Nil(t, out)
}

type opaqueKey struct{ ssh.PublicKey }

type cryptoKey struct {
	ssh.PublicKey
	k any
}

func (c cryptoKey) CryptoPublicKey() any { return c.k }

func TestKeyBitsByKeyType(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edSSH, err := ssh.NewPublicKey(edPub)
	require.NoError(t, err)
	assert.Equal(t, 256, keyBits(edSSH))

	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ecSSH, err := ssh.NewPublicKey(&ec.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, 384, keyBits(ecSSH))

	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaSSH, err := ssh.NewPublicKey(&rk.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, 2048, keyBits(rsaSSH))

	assert.Zero(t, keyBits(opaqueKey{edSSH}), "a key without a crypto form has no size")
	assert.Zero(t, keyBits(cryptoKey{edSSH, struct{}{}}), "an unknown key type has no size")
}

func TestGuestPathMapping(t *testing.T) {
	plain := &sys{}
	g, ok := plain.guest("/etc/ssh")
	assert.True(t, ok)
	assert.Equal(t, "/etc/ssh", g)

	s := &sys{root: "/srv/root"}
	g, ok = s.guest("/srv/root")
	assert.True(t, ok)
	assert.Equal(t, "/", g)
	g, ok = s.guest("/srv/root/etc/ssh")
	assert.True(t, ok)
	assert.Equal(t, "/etc/ssh", g)
	_, ok = s.guest("/srv/rootkit/etc")
	assert.False(t, ok, "a sibling that merely shares the prefix is outside the root")
	_, ok = s.guest("/elsewhere")
	assert.False(t, ok)
}

func TestSudoUserNameIgnoresInvalidNames(t *testing.T) {
	s := &sys{sudoUser: func() string { return "alice_ops" }}
	assert.Equal(t, "alice_ops", s.sudoUserName())
	s.sudoUser = func() string { return "bad name; rm -rf" }
	assert.Empty(t, s.sudoUserName())
	s.sudoUser = func() string { return "" }
	assert.Empty(t, s.sudoUserName())
}

func TestCurrentContentLimits(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	require.NoError(t, os.WriteFile(big, make([]byte, helperproto.MaxAuthorizedKeysSize+1), 0o600))
	f, err := os.Open(big) //nolint:gosec // G304: a path inside the test's temporary directory
	require.NoError(t, err)
	_, err = current{f: f}.content()
	assert.ErrorIs(t, err, errTooLarge)
	require.NoError(t, f.Close())

	_, err = current{f: f}.content()
	assert.Error(t, err, "a closed descriptor cannot be read")
}

func TestWriteNewAtNeverReplacesOrFollows(t *testing.T) {
	dir := t.TempDir()
	d, err := os.Open(dir) //nolint:gosec // G304: a path inside the test's temporary directory
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })

	require.NoError(t, writeNewAt(d, "fresh", []byte("one")))
	require.Error(t, writeNewAt(d, "fresh", []byte("two")), "an existing file is never overwritten")
	got, err := os.ReadFile(filepath.Join(dir, "fresh")) //nolint:gosec // G304: a path inside the test's temporary directory
	require.NoError(t, err)
	assert.Equal(t, "one", string(got))

	require.NoError(t, os.Symlink(filepath.Join(dir, "fresh"), filepath.Join(dir, "link")))
	require.Error(t, writeNewAt(d, "link", []byte("three")), "a symlink is never followed")
}
