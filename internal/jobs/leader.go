package jobs

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// leaderLockKey is the session advisory lock held by the process that schedules periodic work
// (spec §8.3, P2-06). An arbitrary constant next to the audit (…300), passphrase (…301) and
// target-limit (…302) keys.
const leaderLockKey int64 = 7160927315633811303

// Leader holds the scheduling advisory lock on one dedicated connection. The lock lives as long
// as that database session: when the session dies the lock is free for another process.
type Leader struct {
	pool   *pgxpool.Pool
	log    *slog.Logger
	mu     sync.Mutex
	conn   *pgxpool.Conn // non-nil while this process leads
	closed bool
}

// NewLeader returns a Leader that has not tried to lead yet. While it leads it permanently
// holds one connection of pool (until Close or a lost session): size the pool's MaxConns with
// that connection in mind.
func NewLeader(pool *pgxpool.Pool, log *slog.Logger) *Leader {
	return &Leader{pool: pool, log: log}
}

// destroy closes a pooled connection so that it is removed from the pool, not reused: any
// session lock it may hold dies with it.
func destroy(ctx context.Context, c *pgxpool.Conn) {
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = c.Conn().Close(closeCtx)
	c.Release() // a closed connection is destroyed, not returned to the pool
}

// IsLeader reports whether this process holds the lock, taking it when it is free. A held
// connection that no longer answers is dropped (its lock died with it) and the lock is tried
// again.
func (l *Leader) IsLeader(ctx context.Context) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	if l.conn != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := l.conn.Ping(pingCtx)
		cancel()
		if err == nil {
			return true
		}
		l.log.Warn("lost the scheduling lock's database session; trying to take the lock again")
		destroy(ctx, l.conn)
		l.conn = nil
	}
	c, err := l.pool.Acquire(ctx)
	if err != nil {
		return false
	}
	var ok bool
	if err := c.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, leaderLockKey).Scan(&ok); err != nil {
		destroy(ctx, c) // the lock may have been taken before the error: never pool that session
		return false
	}
	if !ok {
		c.Release()
		return false
	}
	l.conn = c
	l.log.Info("this process schedules periodic work")
	return true
}

// Close gives up leadership for good: the lock is released and the connection returned.
func (l *Leader) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var released bool
	if err := l.conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, leaderLockKey).Scan(&released); err != nil || !released {
		destroy(ctx, l.conn) // the lock dies with the session
	} else {
		l.conn.Release()
	}
	l.conn = nil
}
