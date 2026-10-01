package linuxssh

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/providers/linuxssh/linuxsshtest"
)

var otherTarget = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000a2")

type poolEnv struct {
	srv  *linuxsshtest.Server
	cfg  Config
	cred *fakeCred
	hk   *memHostKeys
	pool *Pool
}

func newPoolEnv(t *testing.T, clk clock.Clock, max, perTarget int) *poolEnv {
	t.Helper()
	srv, cfg, cred := testServer(t, okHandler)
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	p := NewPool(&Dialer{Clock: clk, HostKeys: hk}, max, perTarget, IdleTimeout)
	t.Cleanup(p.Close)
	return &poolEnv{srv: srv, cfg: cfg, cred: cred, hk: hk, pool: p}
}

func shortCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestPoolReusesIdleConnectionUntilItExpires(t *testing.T) {
	fake := clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	e := newPoolEnv(t, fake, 2, 1)
	ctx := context.Background()

	c1, rel1, err := e.pool.Acquire(ctx, testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel1(true)
	afterFirst := e.srv.AuthAttempts()
	require.Positive(t, afterFirst)

	c2, rel2, err := e.pool.Acquire(ctx, testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	assert.Same(t, c1, c2, "an idle connection is reused")
	assert.Equal(t, afterFirst, e.srv.AuthAttempts(), "no new connection")
	rel2(true)

	fake.Advance(IdleTimeout)
	c3, rel3, err := e.pool.Acquire(ctx, testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	defer rel3(true)
	assert.NotSame(t, c1, c3, "an expired idle connection is closed, not reused")
	assert.False(t, c1.Healthy())
	assert.Greater(t, e.srv.AuthAttempts(), afterFirst)
}

func TestPoolLimitsConnectionsPerTarget(t *testing.T) {
	e := newPoolEnv(t, clock.Real{}, 2, 1)
	_, rel1, err := e.pool.Acquire(context.Background(), testTarget, e.cfg, e.cred)
	require.NoError(t, err)

	_, _, err = e.pool.Acquire(shortCtx(t, 200*time.Millisecond), testTarget, e.cfg, e.cred)
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.True(t, pe.Retryable)

	rel1(true)
	_, rel2, err := e.pool.Acquire(shortCtx(t, 2*time.Second), testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel2(true)
}

func TestPoolLimitsConnectionsInTotal(t *testing.T) {
	e := newPoolEnv(t, clock.Real{}, 1, 1)
	_, rel1, err := e.pool.Acquire(context.Background(), testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	_, _, err = e.pool.Acquire(shortCtx(t, 200*time.Millisecond), otherTarget, e.cfg, e.cred)
	assert.Equal(t, "ssh.timeout", providerCode(t, err).Code)
	rel1(true)
	_, rel2, err := e.pool.Acquire(shortCtx(t, 2*time.Second), otherTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel2(true)
}

// Review Focus 3: a failed dial and a connection broken by a timeout both give their slot back,
// and a broken connection is never handed out again.
func TestPoolReleasesSlotAfterFailure(t *testing.T) {
	e := newPoolEnv(t, clock.Real{}, 1, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadPort := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	dead := Config{Host: "127.0.0.1", Port: deadPort, Username: "alice-svc"}

	_, _, err = e.pool.Acquire(context.Background(), testTarget, dead, e.cred)
	assert.Equal(t, "ssh.unreachable", providerCode(t, err).Code)

	c, rel, err := e.pool.Acquire(shortCtx(t, 2*time.Second), testTarget, e.cfg, e.cred)
	require.NoError(t, err, "the failed dial freed its slot")

	e.srv.SetHandler(func(string, []byte) linuxsshtest.Response {
		return linuxsshtest.Response{Delay: 10 * time.Second}
	})
	cmd := CmdSSHDDump()
	cmd.timeout = 300 * time.Millisecond
	_, err = c.Run(context.Background(), cmd)
	assert.Equal(t, "ssh.timeout", providerCode(t, err).Code)
	before := e.srv.AuthAttempts()
	rel(true) // the caller claims healthy; the pool checks the connection itself

	c2, rel2, err := e.pool.Acquire(shortCtx(t, 2*time.Second), testTarget, e.cfg, e.cred)
	require.NoError(t, err, "the broken connection freed its slot")
	defer rel2(true)
	assert.NotSame(t, c, c2)
	assert.Greater(t, e.srv.AuthAttempts(), before, "a new connection was opened")
}

// An idle connection belongs to the key that was pinned when it was opened: after a re-pin it is
// closed and the next connection is checked against the new pin.
func TestPoolDropsIdleConnectionAfterRepin(t *testing.T) {
	e := newPoolEnv(t, clock.Real{}, 2, 1)
	c1, rel1, err := e.pool.Acquire(context.Background(), testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel1(true)
	e.hk.pin(linuxsshtest.NewHostKey(t).PublicKey())

	_, _, err = e.pool.Acquire(context.Background(), testTarget, e.cfg, e.cred)
	assert.Equal(t, "target.host_key_changed", providerCode(t, err).Code)
	assert.False(t, c1.Healthy())
}

func TestPoolCloseClosesIdleConnectionsAndRefusesAcquire(t *testing.T) {
	e := newPoolEnv(t, clock.Real{}, 2, 1)
	c1, rel1, err := e.pool.Acquire(context.Background(), testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel1(true)
	e.pool.Close()
	assert.False(t, c1.Healthy())
	_, _, err = e.pool.Acquire(context.Background(), testTarget, e.cfg, e.cred)
	assert.Equal(t, "ssh.unreachable", providerCode(t, err).Code)
}

func TestPoolReleaseIsIdempotent(t *testing.T) {
	e := newPoolEnv(t, clock.Real{}, 1, 1)
	_, rel, err := e.pool.Acquire(context.Background(), testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel(false)
	rel(false) // a second release must not free a slot twice (it would block forever on an empty channel)
	_, rel2, err := e.pool.Acquire(shortCtx(t, 2*time.Second), testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel2(true)
}
