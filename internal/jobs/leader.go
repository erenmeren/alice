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

// leaderAcquireTimeout bounds how long a leadership check waits for a pooled connection and for the lock query. The
// caller's context is the scheduler's Run context, which lives as long as the process: without a bound a saturated
// pool would hold the check (review L-16).
var leaderAcquireTimeout = 5 * time.Second

// Leader holds the scheduling advisory lock on one dedicated connection. The lock lives as long
// as that database session: when the session dies the lock is free for another process.
type Leader struct {
	pool      *pgxpool.Pool
	log       *slog.Logger
	mu        sync.Mutex
	conn      *pgxpool.Conn // non-nil while this process leads
	acquiring bool          // a check is taking a connection, without holding mu
	closed    bool
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
// again. The wait for a connection and the lock query are bounded by leaderAcquireTimeout and
// run without the mutex, so Close and other checks never queue behind a saturated pool; a check
// made while another one is taking the lock reports false.
func (l *Leader) IsLeader(ctx context.Context) bool {
	l.mu.Lock()
	if l.closed || l.acquiring {
		l.mu.Unlock()
		return false
	}
	if l.conn != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := l.conn.Ping(pingCtx)
		cancel()
		if err == nil {
			l.mu.Unlock()
			return true
		}
		l.log.Warn("lost the scheduling lock's database session; trying to take the lock again")
		destroy(ctx, l.conn)
		l.conn = nil
	}
	l.acquiring = true
	l.mu.Unlock()

	c := l.take(ctx)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.acquiring = false
	if c == nil {
		return false
	}
	if l.closed { // Close ran while the lock was being taken: give it up at once
		unlock(c)
		return false
	}
	l.conn = c
	l.log.Info("this process schedules periodic work")
	return true
}

// take acquires a connection and tries the lock on it, within leaderAcquireTimeout. It returns
// the connection that holds the lock, or nil.
func (l *Leader) take(ctx context.Context) *pgxpool.Conn {
	ctx, cancel := context.WithTimeout(ctx, leaderAcquireTimeout)
	defer cancel()
	c, err := l.pool.Acquire(ctx)
	if err != nil {
		return nil
	}
	var ok bool
	if err := c.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, leaderLockKey).Scan(&ok); err != nil {
		destroy(ctx, c) // the lock may have been taken before the error: never pool that session
		return nil
	}
	if !ok {
		c.Release()
		return nil
	}
	return c
}

// unlock releases the lock held on c and returns c to the pool; when that fails c is destroyed,
// and the lock dies with its session.
func unlock(c *pgxpool.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var released bool
	if err := c.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, leaderLockKey).Scan(&released); err != nil || !released {
		destroy(ctx, c)
		return
	}
	c.Release()
}

// Close gives up leadership for good: the lock is released and the connection returned. A check
// that is taking the lock at that moment gives it up as soon as it has it.
func (l *Leader) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.conn == nil {
		return
	}
	unlock(l.conn)
	l.conn = nil
}
