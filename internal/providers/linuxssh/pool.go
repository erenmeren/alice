package linuxssh

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"alice/internal/platform/clock"
	"alice/internal/providers"
)

// Connection limits (spec §8.5, §12.5; R37 item 17).
const (
	MaxConnections          = 10
	MaxConnectionsPerTarget = 2
	IdleTimeout             = 60 * time.Second
)

var errPoolClosed = errors.New("linuxssh: connection pool closed")

type idleConn struct {
	conn  *Conn
	since time.Time
}

// Pool bounds SSH connections: at most maxConns in use, at most perTarget in use per target. An
// idle connection is reused for at most the idle time, only with the same Config and only while
// the target's pinned key is still the key it was opened with.
//
// Idle connections do not count against the in-use limit: they hold no slot, and at most maxConns
// of them are kept, so the pool holds at most 2×maxConns sockets. A background sweep (every half
// idle time, stopped by Close) closes idle connections that reached the idle time, including
// those whose target configuration changed and so will never be taken again.
type Pool struct {
	dialer    *Dialer
	idleFor   time.Duration
	perTarget int
	maxIdle   int
	global    chan struct{}
	done      chan struct{} // closed by Close: wakes waiting Acquire calls, stops the sweep
	closeOnce sync.Once

	mu      sync.Mutex
	closed  bool
	targets map[uuid.UUID]chan struct{}
	idle    map[uuid.UUID][]idleConn
	idleN   int
	// forgotten holds deleted targets (ForgetTarget): their released connections are closed.
	forgotten map[uuid.UUID]bool
}

// NewPool returns a pool; zero or negative limits take the defaults.
func NewPool(d *Dialer, maxConns, perTarget int, idle time.Duration) *Pool {
	if maxConns <= 0 {
		maxConns = MaxConnections
	}
	if perTarget <= 0 {
		perTarget = MaxConnectionsPerTarget
	}
	if perTarget > maxConns {
		perTarget = maxConns
	}
	if idle <= 0 {
		idle = IdleTimeout
	}
	p := &Pool{
		dialer: d, idleFor: idle, perTarget: perTarget, maxIdle: maxConns,
		global:  make(chan struct{}, maxConns),
		done:    make(chan struct{}),
		targets: map[uuid.UUID]chan struct{}{},
		idle:    map[uuid.UUID][]idleConn{},
	}
	go p.sweepLoop(d.clk().NewTicker(sweepEvery(idle)))
	return p
}

// minSweepEvery floors the sweep period: half of a tiny idle time would be zero (a ticker panics)
// or keep a CPU busy.
const minSweepEvery = time.Millisecond

// sweepEvery is half the idle time, at least minSweepEvery.
func sweepEvery(idle time.Duration) time.Duration {
	return max(idle/2, minSweepEvery)
}

// sweepLoop closes expired idle connections until the pool is closed.
func (p *Pool) sweepLoop(t clock.Ticker) {
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-t.C():
			now := p.dialer.clk().Now()
			p.mu.Lock()
			stale := p.sweepLocked(now)
			p.mu.Unlock()
			for _, c := range stale {
				_ = c.Close()
			}
		}
	}
}

func (p *Pool) waitSlot(ctx context.Context, ch chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return slotError(err) // a free slot never wins over a cancelled context
	}
	select {
	case ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return slotError(ctx.Err())
	case <-p.done:
		return closedError()
	}
}

func slotError(err error) error {
	return providers.NewError("ssh.timeout", true, err, map[string]string{"wait": "connection_slot"})
}

func closedError() error {
	return providers.NewError("ssh.unreachable", false, errPoolClosed, nil)
}

func (p *Pool) targetSlots(target uuid.UUID) (chan struct{}, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, closedError()
	}
	ch, ok := p.targets[target]
	if !ok {
		ch = make(chan struct{}, p.perTarget)
		p.targets[target] = ch
	}
	return ch, nil
}

// Acquire returns a connection to target and its release function. release(healthy) must be called
// exactly once (later calls do nothing); a connection that is not healthy is closed, never reused.
func (p *Pool) Acquire(ctx context.Context, target uuid.UUID, cfg Config, cred providers.CredentialSource) (*Conn, func(healthy bool), error) {
	return p.acquire(ctx, target, cfg, cred, false)
}

// AcquireFresh is Acquire without reuse: it always dials, so the host key the server presents now
// is checked against the pin (an explicit connection test, R37 item 21). Released, the new
// connection is kept for reuse like any other.
func (p *Pool) AcquireFresh(ctx context.Context, target uuid.UUID, cfg Config, cred providers.CredentialSource) (*Conn, func(healthy bool), error) {
	return p.acquire(ctx, target, cfg, cred, true)
}

func (p *Pool) acquire(ctx context.Context, target uuid.UUID, cfg Config, cred providers.CredentialSource, fresh bool) (*Conn, func(healthy bool), error) {
	tsem, err := p.targetSlots(target)
	if err != nil {
		return nil, nil, err
	}
	if err := p.waitSlot(ctx, tsem); err != nil {
		return nil, nil, err
	}
	if err := p.waitSlot(ctx, p.global); err != nil {
		<-tsem
		return nil, nil, err
	}
	slots := func() {
		<-p.global
		<-tsem
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed { // closed while this call waited for its slots: never dial after Close
		slots()
		return nil, nil, closedError()
	}
	if !fresh {
		if c := p.takeIdle(ctx, target, cfg); c != nil {
			return c, p.releaser(target, c, slots), nil
		}
	}
	c, err := p.dialer.Dial(ctx, target, cfg, cred)
	if err != nil {
		slots()
		if hostKeyChanged(err) {
			p.dropIdle(target) // opened with a key the server no longer presents: never reuse them
		}
		return nil, nil, err
	}
	return c, p.releaser(target, c, slots), nil
}

// ForgetTarget closes the idle connections of a deleted target and drops its slot channel. A
// connection of it still in use is closed when released (forgotten targets keep nothing idle).
func (p *Pool) ForgetTarget(target uuid.UUID) {
	p.mu.Lock()
	delete(p.targets, target)
	if p.forgotten == nil {
		p.forgotten = map[uuid.UUID]bool{}
	}
	p.forgotten[target] = true
	p.mu.Unlock()
	p.dropIdle(target)
}

func hostKeyChanged(err error) bool {
	var pe *providers.Error
	return errors.As(err, &pe) && pe.Code == "target.host_key_changed"
}

// dropIdle closes the idle connections of target.
func (p *Pool) dropIdle(target uuid.UUID) {
	p.mu.Lock()
	list := p.idle[target]
	delete(p.idle, target)
	p.idleN -= len(list)
	p.mu.Unlock()
	for _, ic := range list {
		_ = ic.conn.Close()
	}
}

// takeIdle hands out an idle connection of target opened with cfg whose key is still pinned.
func (p *Pool) takeIdle(ctx context.Context, target uuid.UUID, cfg Config) *Conn {
	now := p.dialer.clk().Now()
	var found *Conn
	var stale []*Conn
	p.mu.Lock()
	list := p.idle[target]
	keep := list[:0]
	for _, ic := range list {
		expired := now.Sub(ic.since) >= p.idleFor
		switch {
		case found == nil && !expired && ic.conn.cfg == cfg && ic.conn.Healthy():
			found = ic.conn
		case expired || !ic.conn.Healthy():
			stale = append(stale, ic.conn)
		default:
			keep = append(keep, ic)
		}
	}
	p.idleN -= len(list) - len(keep)
	if len(keep) == 0 {
		delete(p.idle, target)
	} else {
		p.idle[target] = keep
	}
	p.mu.Unlock()
	for _, c := range stale {
		_ = c.Close()
	}
	if found == nil {
		return nil
	}
	pinned, err := p.dialer.HostKeys.Pinned(ctx, target)
	if err != nil || subtle.ConstantTimeCompare(pinned.PublicKey, found.hostKey.PublicKey) != 1 {
		_ = found.Close()
		return nil
	}
	if !found.alive(ctx) { // the server dropped it while idle (a restart or a reinstall): dial again
		return nil
	}
	return found
}

// sweepLocked removes expired idle connections; the caller closes them after unlocking.
func (p *Pool) sweepLocked(now time.Time) []*Conn {
	var stale []*Conn
	for t, list := range p.idle {
		keep := list[:0]
		for _, ic := range list {
			if now.Sub(ic.since) >= p.idleFor {
				stale = append(stale, ic.conn)
				continue
			}
			keep = append(keep, ic)
		}
		p.idleN -= len(list) - len(keep)
		if len(keep) == 0 {
			delete(p.idle, t)
		} else {
			p.idle[t] = keep
		}
	}
	return stale
}

func (p *Pool) releaser(target uuid.UUID, c *Conn, slots func()) func(bool) {
	var once sync.Once
	return func(healthy bool) {
		once.Do(func() {
			defer slots()
			now := p.dialer.clk().Now()
			p.mu.Lock()
			stale := p.sweepLocked(now)
			keep := healthy && c.Healthy() && !p.closed && p.idleN < p.maxIdle && !p.forgotten[target]
			if keep {
				p.idle[target] = append(p.idle[target], idleConn{conn: c, since: now})
				p.idleN++
			}
			p.mu.Unlock()
			for _, s := range stale {
				_ = s.Close()
			}
			if !keep {
				_ = c.Close()
			}
		})
	}
}

// Close closes every idle connection; connections in use are closed when released, and later
// Acquire calls fail.
func (p *Pool) Close() {
	p.closeOnce.Do(func() { close(p.done) })
	p.mu.Lock()
	p.closed = true
	var all []*Conn
	for t, list := range p.idle {
		for _, ic := range list {
			all = append(all, ic.conn)
		}
		delete(p.idle, t)
	}
	p.idleN = 0
	p.mu.Unlock()
	for _, c := range all {
		_ = c.Close()
	}
}
