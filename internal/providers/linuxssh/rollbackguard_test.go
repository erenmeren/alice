package linuxssh

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

// R48: the guarded restore has nginx-restore's argument vector (the sudoers line admits it) with the guard on stdin
// only, and refuses an input the helper would not read.
func TestCmdNginxRestoreGuarded(t *testing.T) {
	input := []byte(`{"forbidden_spki_sha256":[],"forbidden_leaf_sha256":[]}`)
	c, err := CmdNginxRestoreGuarded(testOp, input)
	require.NoError(t, err)
	plain, err := CmdNginxRestore(testOp)
	require.NoError(t, err)
	assert.Equal(t, plain.Line(), c.Line(), "the same command line: the guard never appears on it")
	assert.Equal(t, helperproto.SubNginxRestore, c.Subcommand())
	assert.True(t, c.sudo)
	assert.Equal(t, DeployCommandTimeout, c.timeout)
	assert.Equal(t, input, c.input())
	assert.Nil(t, plain.input())

	for name, tc := range map[string]struct {
		op uuid.UUID
		in []byte
	}{
		"empty input":     {testOp, nil},
		"input too large": {testOp, make([]byte, helperproto.MaxRestoreInput+1)},
		"nil operation":   {uuid.Nil, input},
	} {
		_, err := CmdNginxRestoreGuarded(tc.op, tc.in)
		assert.ErrorIs(t, err, ErrInvalidArgument, name)
	}
}

// The refusal of a helper too old for the guard names both protocols and keeps its cause for errors.Is.
func TestRollbackGuardOutdated(t *testing.T) {
	e := RollbackGuardOutdated(9)
	assert.Equal(t, ReasonRollbackGuardOutdated, e.Code)
	assert.Equal(t, map[string]string{"helper_protocol": "9", "required_protocol": "10"}, e.Params)
	assert.ErrorIs(t, e, ErrRollbackGuardOutdated)
	assert.False(t, e.Retryable, "retrying cannot help before the helper is reinstalled")
}

// GuardsRollback is true from protocol 10 on and reports the protocol; a version that cannot be read is an error.
func TestGuardsRollback(t *testing.T) {
	for _, tc := range []struct {
		protocol int
		guards   bool
	}{{9, false}, {helperproto.RollbackGuardMinProtocol, true}, {helperproto.Protocol, true}} {
		emu := linuxsshtest.NewEmulator()
		emu.SetProtocol(tc.protocol)
		srv, cfg, cred := testServer(t, emu.Handler())
		hk := &memHostKeys{}
		hk.pin(srv.HostKey())
		c, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
		require.NoError(t, err)
		guards, p, err := c.GuardsRollback(context.Background())
		require.NoError(t, err)
		assert.Equal(t, tc.guards, guards, "protocol %d", tc.protocol)
		assert.Equal(t, tc.protocol, p)
		require.NoError(t, c.Close())
	}

	emu := linuxsshtest.NewEmulator()
	srv, cfg, cred := testServer(t, emu.Handler())
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	c, err := newDialer(hk).Dial(context.Background(), testTarget, cfg, cred)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	guards, p, err := c.GuardsRollback(context.Background())
	require.Error(t, err)
	assert.False(t, guards)
	assert.Zero(t, p)
}
