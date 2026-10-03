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

// A server that dropped the connection while it sat idle (a restart, a reinstall) is dialed again:
// the stale connection is never handed out, so the next command neither fails as unreachable nor
// misses a changed host key.
func TestPoolDoesNotHandOutAConnectionTheServerClosed(t *testing.T) {
	e := newPoolEnv(t, clock.Real{}, 2, 1)
	key := linuxsshtest.NewHostKey(t)
	e.srv.SetHostKey(key)
	e.hk.pin(key.PublicKey())
	ctx := context.Background()
	c1, rel1, err := e.pool.Acquire(ctx, testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel1(true)
	attempts := e.srv.AuthAttempts()

	e.srv.SetHostKey(key) // same key, but every open connection is dropped
	c2, rel2, err := e.pool.Acquire(ctx, testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	defer rel2(true)
	assert.NotSame(t, c1, c2)
	assert.False(t, c1.Healthy())
	assert.Greater(t, e.srv.AuthAttempts(), attempts, "a new connection was opened")
	_, err = c2.Run(ctx, CmdVersion())
	require.NoError(t, err)

	e.srv.SetHostKey(linuxsshtest.NewHostKey(t)) // reinstalled: the next acquire sees the new key
	rel2(true)
	_, _, err = e.pool.Acquire(ctx, testTarget, e.cfg, e.cred)
	assert.Equal(t, "target.host_key_changed", providerCode(t, err).Code)
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

// Idle connections expire on their own: nothing has to acquire or release for the sweep to run.
func TestPoolSweepsIdleConnectionsInTheBackground(t *testing.T) {
	fake := clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	e := newPoolEnv(t, fake, 2, 1)
	c1, rel1, err := e.pool.Acquire(context.Background(), testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel1(true)
	require.True(t, c1.Healthy())
	fake.Advance(IdleTimeout)
	assert.Eventually(t, func() bool { return !c1.Healthy() }, 2*time.Second, 10*time.Millisecond)
}

// An Acquire that was waiting for a slot when the pool closed does not dial afterwards.
func TestPoolAcquireWaitingDuringCloseDoesNotDial(t *testing.T) {
	e := newPoolEnv(t, clock.Real{}, 1, 1)
	_, rel1, err := e.pool.Acquire(context.Background(), testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	before := e.srv.AuthAttempts()
	errc := make(chan error, 1)
	go func() {
		_, _, err := e.pool.Acquire(context.Background(), otherTarget, e.cfg, e.cred)
		errc <- err
	}()
	time.Sleep(100 * time.Millisecond) // let it block on the global slot
	e.pool.Close()
	rel1(true)
	select {
	case err := <-errc:
		pe := providerCode(t, err)
		assert.Equal(t, "ssh.unreachable", pe.Code)
		assert.ErrorIs(t, err, errPoolClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting Acquire never returned")
	}
	assert.Equal(t, before, e.srv.AuthAttempts(), "no connection was opened after Close")
}

// A-4 (R37 item 21): AcquireFresh never reuses an idle connection; the new connection goes back to
// the pool. When the fresh dial finds a changed host key, the idle connections of the target
// (opened with the old key, still alive) are closed too.
func TestPoolAcquireFreshDialsAndDropsIdleConnectionsOnAChangedKey(t *testing.T) {
	e := newPoolEnv(t, clock.Real{}, 4, 2)
	ctx := context.Background()
	c1, rel1, err := e.pool.Acquire(ctx, testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	rel1(true)
	dials := e.srv.Connections()

	c2, rel2, err := e.pool.AcquireFresh(ctx, testTarget, e.cfg, e.cred)
	require.NoError(t, err)
	assert.NotSame(t, c1, c2, "an idle connection exists, but a fresh one is dialed")
	assert.Equal(t, dials+1, e.srv.Connections())
	assert.True(t, c1.Healthy(), "the idle connection stays")
	rel2(true)
	e.pool.mu.Lock()
	assert.Len(t, e.pool.idle[testTarget], 2, "the fresh connection is kept for reuse")
	e.pool.mu.Unlock()

	// The server now presents another key; the idle connections were opened before and are alive.
	e.srv.SetHostKeyAlgorithms(linuxsshtest.NewHostKey(t))
	_, _, err = e.pool.AcquireFresh(ctx, testTarget, e.cfg, e.cred)
	assert.Equal(t, "target.host_key_changed", providerCode(t, err).Code)
	assert.False(t, c1.Healthy(), "idle connections of the old key are closed")
	assert.False(t, c2.Healthy())
	e.pool.mu.Lock()
	assert.Empty(t, e.pool.idle[testTarget])
	assert.Zero(t, e.pool.idleN)
	e.pool.mu.Unlock()
	_, _, err = e.pool.Acquire(ctx, testTarget, e.cfg, e.cred)
	assert.Equal(t, "target.host_key_changed", providerCode(t, err).Code, "nothing old is handed out afterwards")
}

// A-12: an idle time below two nanoseconds must not make the sweep ticker panic.
func TestNewPoolWithATinyIdleTimeDoesNotPanic(t *testing.T) {
	for _, idle := range []time.Duration{time.Nanosecond, 2 * time.Nanosecond} {
		assert.NotPanics(t, func() {
			p := NewPool(&Dialer{Clock: clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)), HostKeys: &memHostKeys{}}, 1, 1, idle)
			p.Close()
		}, "%v", idle)
	}
}
