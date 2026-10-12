//go:build integration

package db_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
)

// blackHole forwards TCP to target until freeze: from then on it drops every byte in both directions without closing
// anything, as a half-dead connection does (a cut network path, a frozen peer).
type blackHole struct {
	ln     net.Listener
	frozen atomic.Bool
	mu     sync.Mutex
	conns  []net.Conn
}

func newBlackHole(t *testing.T, target string) *blackHole {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	b := &blackHole{ln: ln}
	t.Cleanup(b.close)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			b.mu.Lock()
			b.conns = append(b.conns, c, up)
			b.mu.Unlock()
			go b.pipe(up, c)
			go b.pipe(c, up)
		}
	}()
	return b
}

func (b *blackHole) pipe(dst io.Writer, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 && !b.frozen.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (b *blackHole) close() {
	_ = b.ln.Close()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		_ = c.Close()
	}
}

// Review L-15: when fn fails and the connection no longer answers, InTx's rollback gives up after a bounded time
// instead of holding the caller until the TCP timeout.
func TestInTxRollbackOnADeadConnectionIsBounded(t *testing.T) {
	defer db.SetRollbackTimeout(300 * time.Millisecond)()
	u, err := url.Parse(freshDatabaseURL(t))
	require.NoError(t, err)
	hole := newBlackHole(t, u.Host)
	u.Host = hole.ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, u.String())
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	boom := errors.New("boom")
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- db.InTx(context.Background(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), "SELECT 1"); err != nil {
				return err
			}
			hole.frozen.Store(true)
			return boom
		})
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, boom)
		require.Less(t, time.Since(start), 5*time.Second)
	case <-time.After(10 * time.Second):
		hole.close() // let the stuck rollback end, so the goroutine does not outlive the test
		t.Fatal("the rollback on a dead connection did not give up")
	}
}
