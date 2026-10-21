package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listenBoth binds both addresses or neither: when the health address is taken, the public listener it bound first
// is closed again, so a failed start leaves no port held.
func TestListenBothBindsBothOrNeither(t *testing.T) {
	ctx := context.Background()
	var lc net.ListenConfig
	taken, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer taken.Close()

	_, _, err = listenBoth(ctx, taken.Addr().String(), "127.0.0.1:0")
	require.Error(t, err)
	assert.ErrorContains(t, err, "listen on "+taken.Addr().String())

	free, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	publicAddr := free.Addr().String()
	require.NoError(t, free.Close())
	_, _, err = listenBoth(ctx, publicAddr, taken.Addr().String())
	require.Error(t, err)
	assert.ErrorContains(t, err, "listen on "+taken.Addr().String())
	again, err := lc.Listen(ctx, "tcp", publicAddr)
	require.NoError(t, err, "the public listener was closed when the health address failed")
	require.NoError(t, again.Close())

	pub, health, err := listenBoth(ctx, "127.0.0.1:0", "127.0.0.1:0")
	require.NoError(t, err)
	assert.NotEqual(t, pub.Addr().String(), health.Addr().String())
	require.NoError(t, pub.Close())
	require.NoError(t, health.Close())
}

func TestIgnoreClosed(t *testing.T) {
	require.NoError(t, ignoreClosed(nil))
	require.NoError(t, ignoreClosed(http.ErrServerClosed), "a server that was shut down is no failure")
	boom := errors.New("accept: too many open files")
	assert.ErrorIs(t, ignoreClosed(boom), boom)
}
