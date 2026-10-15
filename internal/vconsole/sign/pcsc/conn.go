package pcsc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Connection states that make Transmit refuse to reach the card.
var (
	ErrClosed = errors.New("pcsc: the card connection is closed")
	// ErrAbandoned: a command was cancelled while the card still held it (typically waiting for a
	// touch). The connection is not used again; it is released as soon as the card answers.
	ErrAbandoned = errors.New("pcsc: the card connection was abandoned after a cancel")
	// ErrBusy: a second command was sent while one is in flight; the card protocol is sequential.
	ErrBusy = errors.New("pcsc: another command is in flight on this card connection")
	// ErrCloseTimeout: Close could not release the connection because the card has not answered
	// the abandoned command yet; it is released when the card answers (a YubiKey gives up waiting
	// for a touch after about 15 seconds) or when the process exits.
	ErrCloseTimeout = errors.New("pcsc: the card has not answered yet; the connection is released when it does")
)

// defaultCloseWait bounds how long Close waits for an in-flight command. It is longer than the
// YubiKey's own touch timeout (about 15 seconds), so a normal cancel during a touch prompt still
// ends with the handle released before Close returns.
const defaultCloseWait = 20 * time.Second

// rawCard is the part of a PC/SC card handle a conn uses: the scard card and context in the
// yubikey build, a fake in tests. Disconnect releases the card handle and its context.
type rawCard interface {
	Transmit(apdu []byte) ([]byte, error)
	Disconnect() error
}

// conn turns a blocking PC/SC handle into an openpgp.Card that honours ctx.
//
// PC/SC offers no safe way to abort a pending SCardTransmit: SCardCancel only ends a blocking
// SCardGetStatusChange, and pcsc-lite serialises every call on one context with a mutex, so a
// Disconnect issued during a Transmit just waits for it. Transmit therefore runs the card call in
// a goroutine; on cancel it returns ctx.Err() at once, marks the connection abandoned (no further
// command reaches the card) and leaves the release to that goroutine, which disconnects as soon as
// the card answers. The goroutine always ends with the card's answer: nothing outlives it.
type conn struct {
	raw       rawCard
	cancel    func()                           // PC/SC context cancel; may be nil
	mapErr    func(op string, err error) error // turns PC/SC failures into readable errors
	closeWait time.Duration

	mu        sync.Mutex
	busy      bool // a card call is in flight
	abandoned bool
	closed    bool
	releasing bool          // Disconnect has been started (exactly once)
	gone      chan struct{} // closed when Disconnect has returned
	closeErr  error         // the result of Disconnect; read after gone is closed

	// abandonHook, when set (tests only), runs in Transmit's cancel path after the last look at
	// the card's answer and before the connection is marked abandoned.
	abandonHook func()
}

func newConn(raw rawCard, cancel func(), mapErr func(op string, err error) error) *conn {
	return &conn{raw: raw, cancel: cancel, mapErr: mapErr, closeWait: defaultCloseWait, gone: make(chan struct{})}
}

type result struct {
	rsp []byte
	err error
}

// Transmit sends one command APDU. The card gets a private copy of apdu, zeroed once the card
// answers, so the caller may wipe its buffer (a PIN) as soon as Transmit returns, even after a
// cancel while the card still holds the command.
func (c *conn) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	if len(apdu) == 0 {
		return nil, errors.New("pcsc: empty command")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("pcsc: transmit: %w", err)
	}
	c.mu.Lock()
	switch {
	case c.closed:
		c.mu.Unlock()
		return nil, ErrClosed
	case c.abandoned:
		c.mu.Unlock()
		return nil, ErrAbandoned
	case c.busy:
		c.mu.Unlock()
		return nil, ErrBusy
	}
	c.busy = true
	c.mu.Unlock()

	buf := make([]byte, len(apdu))
	copy(buf, apdu)
	done := make(chan result, 1) // buffered: the goroutine never blocks on an abandoned caller
	go func() {
		rsp, err := c.raw.Transmit(buf)
		clear(buf)
		// Free the connection before handing over the answer, so that the caller's next command
		// never sees ErrBusy.
		c.finish()
		done <- result{rsp, err}
	}()

	select {
	case r := <-done:
		return c.answer(r)
	case <-ctx.Done():
	}
	// The card may have answered at the same moment: prefer its answer.
	select {
	case r := <-done:
		return c.answer(r)
	default:
	}
	if c.abandonHook != nil {
		c.abandonHook()
	}
	c.mu.Lock()
	// Cancel ends any blocking PC/SC call that can be cancelled; a pending transmit is not one of
	// them (see conn), so the abandoned state is what actually protects the card. It is skipped
	// once the release has started: the context may already be gone.
	if c.cancel != nil && !c.releasing {
		c.cancel()
	}
	c.abandoned = true
	// The card may have answered after the last look above: the goroutine has then finished
	// without releasing (it saw no abandon), so release here instead of holding the handle
	// until Close.
	rel := !c.busy && !c.releasing
	if rel {
		c.releasing = true
	}
	c.mu.Unlock()
	if rel {
		c.release()
	}
	return nil, fmt.Errorf("%w: %w", ErrAbandoned, ctx.Err())
}

func (c *conn) answer(r result) ([]byte, error) {
	if r.err != nil {
		return nil, c.mapErr("transmit", r.err)
	}
	return r.rsp, nil
}

// finish runs in the transmit goroutine after the card answered: it frees the connection and,
// when Close was called or the command was abandoned meanwhile, releases the handle.
func (c *conn) finish() {
	c.mu.Lock()
	c.busy = false
	rel := (c.closed || c.abandoned) && !c.releasing
	if rel {
		c.releasing = true
	}
	c.mu.Unlock()
	if rel {
		c.release()
	}
}

func (c *conn) release() {
	c.closeErr = c.raw.Disconnect()
	if c.closeErr != nil {
		c.closeErr = c.mapErr("disconnect", c.closeErr)
	}
	close(c.gone)
}

// Close releases the connection. It is idempotent and safe to call while a Transmit is in
// flight: it then waits up to closeWait for the card's answer (the handle cannot be released
// before) and returns ErrCloseTimeout if the card has not answered by then.
func (c *conn) Close() error {
	c.mu.Lock()
	c.closed = true
	rel := !c.busy && !c.releasing
	if rel {
		c.releasing = true
	}
	c.mu.Unlock()
	if rel {
		c.release()
	}
	t := time.NewTimer(c.closeWait)
	defer t.Stop()
	select {
	case <-c.gone:
		return c.closeErr
	case <-t.C:
		return ErrCloseTimeout
	}
}
