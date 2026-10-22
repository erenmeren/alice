package winhelper

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"alice/internal/providers/windows/winproto"
)

// WriteHost is a Host that can change the machine (the real helper and wintest). Every method that
// changes something is named as such; the platform-neutral transaction (validation, lock, journal, the
// guard, the step order, the self-restore) is winhelper's.
type WriteHost interface {
	Host
	// Lock takes the helper lock (helper.lock), waiting at most winproto.LockWait (ErrBusy after);
	// release is idempotent.
	Lock(ctx context.Context) (release func(), err error)
	// LockHeld reports whether another process holds the lock now (a status's Active).
	LockHeld() bool
	// ReadState reads a state file under the data directory: "journal/<op>.json",
	// "bindings/<hash>.json", "imports.json". found is false when there is none.
	ReadState(name string) (data []byte, found bool, err error)
	// WriteState replaces a state file durably: a temporary file, flushed, renamed over (write through).
	WriteState(name string, data []byte) error
	// DataDirSafe returns ErrJournal when the data directory is a reparse point, not owned by
	// Administrators or SYSTEM, or not writable.
	DataDirSafe() error
	// Binding reads the http.sys record the locator names, base and Extended; found is false when
	// http.sys holds none.
	Binding(ctx context.Context, l winproto.Locator) (winproto.SSLBinding, bool, error)
	// UpdateBinding sends one update of the whole record (http.sys replaces it, W0 F2): ErrKeyUnusable
	// (1312), ErrBindingNotFound.
	UpdateBinding(ctx context.Context, b winproto.SSLBinding) error
	// AddIntermediate adds a public certificate to LocalMachine\CA, never replacing one there; added is
	// false when it was there already.
	AddIntermediate(ctx context.Context, der []byte) (added bool, err error)
	// ImportPFX imports a PFX (BuildPFX) into a machine store with a non-exportable machine key and
	// returns the certificate's SHA-1. The caller clears pfx and password afterwards.
	ImportPFX(ctx context.Context, store string, pfx, password []byte, friendlyName string) (sha1 string, err error)
	// Event writes an Application event of source "Alice Helper", best effort.
	Event(id uint32, text string)
	// Point is a crash point between journal phases: a non-nil answer kills the operation there (tests
	// and the emulator); nil on the real host.
	Point(name string) error
}

// The WriteHost errors the helper decides on. A host returns them (wrapped or not); any other error is
// an I/O failure.
var (
	ErrBusy            = errors.New("winhelper: another process holds the helper lock")
	ErrJournal         = errors.New("winhelper: the data directory cannot be trusted or written")
	ErrKeyUnusable     = errors.New("winhelper: the certificate has no usable key")
	ErrBindingNotFound = errors.New("winhelper: http.sys holds no such record")
	ErrStore           = errors.New("winhelper: a certificate store could not be opened")
)

// writeGrace is how long a write handler that entered its gate may still run after the budget ended
// (W2 Ruling 7; tests lower it).
var writeGrace = winproto.WriteGrace

// gate guards a write command's first durable write (W2 Ruling 7). The handler calls enter right
// before it; Run calls close when the budget ends. Both under one mutex, so exactly one of these
// holds: the handler entered before close (the answer is OUTCOME_UNKNOWN), or it never enters (the
// answer is IO_ERROR: nothing changed).
type gate struct {
	mu      sync.Mutex
	entered bool
	closed  bool
	budget  context.Context
	wctx    context.Context
	cancel  context.CancelFunc
	stop    func() bool
}

// newGate makes the gate of one call: its write context does not end with the budget but writeGrace
// after it.
func newGate(budget context.Context) *gate {
	wctx, cancel := context.WithCancel(context.WithoutCancel(budget))
	g := &gate{budget: budget, wctx: wctx, cancel: cancel}
	grace := writeGrace
	g.stop = context.AfterFunc(budget, func() { time.AfterFunc(grace, cancel) })
	return g
}

// enter is called right before the first durable write. It fails (IO_ERROR, nothing changed) once
// the budget ended or Run closed the gate; otherwise it returns the context the handler finishes its
// step or self-restore under. A second enter returns the same.
func (g *gate) enter() (context.Context, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.budget.Err() != nil {
		return nil, failed(winproto.CodeIOError, "the call took too long")
	}
	g.entered = true
	return g.wctx, nil
}

// close is Run's at the end of the budget: no enter succeeds afterwards. It reports whether the
// handler had entered.
func (g *gate) close() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return g.entered
}

// finish ends the write context once the handler returned.
func (g *gate) finish() {
	g.stop()
	g.cancel()
}

// call is what a command's run handler gets.
type call struct {
	host  WriteHost
	args  []string
	input []byte // stdin, at most the command's input bound; nil when it takes none. Cleared after the handler.
	gate  *gate  // write commands only
}

// readInput reads at most limit bytes of stdin into one buffer of limit+1 bytes (the input holds a
// private key: a growing read would leave copies nobody clears). More is TOO_LARGE.
func readInput(r io.Reader, limit int) ([]byte, error) {
	buf := make([]byte, limit+1)
	if r == nil {
		return buf[:0], nil
	}
	n, err := io.ReadFull(r, buf)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil
	}
	if err != nil {
		clear(buf)
		return nil, failed(winproto.CodeIOError, "standard input could not be read")
	}
	if n > limit {
		clear(buf)
		return nil, refused(winproto.CodeTooLarge, "the input is too large")
	}
	return buf[:n], nil
}

// point is a crash point of a write subcommand: the handler returns its error at once, without any
// cleanup, as a killed process would stop there.
func point(h WriteHost, name string) error {
	if h.Point(name) != nil {
		return failed(winproto.CodeIOError, "the helper was stopped")
	}
	return nil
}

// Outcome is what one call answered. Abandoned is set when Run answered at the end of the budget
// while the handler was still running; with Code OUTCOME_UNKNOWN that handler had made its first
// durable write. The caller must then end the process at once (the real helper's main returns and
// exits; nothing may run after the answer), so the journal decides at the next iis-status.
type Outcome struct {
	Exit      int
	Code      string // the ErrorResponse code; "" for an answer
	Abandoned bool
}

// ExecuteForced is RunForced with the call's Outcome.
func ExecuteForced(ctx context.Context, h Host, originalCommand string, stdin io.Reader, stdout io.Writer) Outcome {
	args, ok := winproto.SplitCommandLine(originalCommand)
	if !ok {
		return answer(stdout, nil, refused(winproto.CodeInvalidArgument, "the command line is not allowed"))
	}
	return Execute(ctx, h, args, stdin, stdout)
}

// Execute is Run with the call's Outcome: it executes one call (args[0] is the subcommand) under the
// call budget, prints exactly one JSON line. A command with an input bound reads stdin first (at most
// that many bytes; more is TOO_LARGE, before any host call); no other command reads it. A write
// command runs under its gate (W2 Ruling 7).
func Execute(ctx context.Context, h Host, args []string, stdin io.Reader, stdout io.Writer) Outcome {
	if len(args) == 0 {
		return answer(stdout, nil, refused(winproto.CodeUsage, "usage: alice-helper <subcommand> [arguments]"))
	}
	c, ok := commands[args[0]]
	if !ok {
		return answer(stdout, nil, refused(winproto.CodeUnknownSubcommand, "unknown subcommand"))
	}
	ctx, cancel := context.WithTimeout(ctx, commandBudget)
	defer cancel()
	var g *gate
	if c.write {
		g = newGate(ctx)
	}
	type result struct {
		out any
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := c.execute(ctx, h, args[1:], stdin, g)
		done <- result{out, err}
	}()
	// The budget ends the call even when a host call ignores its context.
	select {
	case r := <-done:
		return answer(stdout, r.out, r.err)
	case <-ctx.Done():
		select {
		case r := <-done: // finished as the budget ended
			return answer(stdout, r.out, r.err)
		default:
		}
		err := failed(winproto.CodeIOError, "the call took too long")
		if g != nil && g.close() {
			// The handler changed something or may have: uncertain, never a refusal.
			err = failed(winproto.CodeOutcomeUnknown, "the call took too long after the first change")
		}
		o := answer(stdout, nil, err)
		o.Abandoned = true
		return o
	}
}

// execute runs one command after its input and elevation gates.
func (c command) execute(ctx context.Context, h Host, args []string, stdin io.Reader, g *gate) (any, error) {
	if g != nil {
		defer g.finish()
	}
	var input []byte
	if c.input > 0 {
		var err error
		if input, err = readInput(stdin, c.input); err != nil {
			return nil, err
		}
		defer clear(input[:cap(input)])
	}
	if c.elevated || c.write {
		el, err := h.Elevated()
		if err != nil {
			return nil, failed(winproto.CodeIOError, "the token could not be read")
		}
		if !el {
			return nil, refused(winproto.CodeNotElevated, "this subcommand needs an elevated token")
		}
	}
	if c.run == nil {
		return c.handle(ctx, h, args)
	}
	wh, ok := h.(WriteHost)
	if !ok {
		return nil, failed(winproto.CodeIOError, "this helper cannot change the machine")
	}
	return c.run(ctx, &call{host: wh, args: args, input: input, gate: g})
}
