package winhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"alice/internal/providers/windows/winproto"
)

// withCommand installs a command for one test (the real write commands come with Task 3's handlers).
func withCommand(t *testing.T, name string, c command) {
	t.Helper()
	old, had := commands[name]
	commands[name] = c
	t.Cleanup(func() {
		if had {
			commands[name] = old
		} else {
			delete(commands, name)
		}
	})
}

func lowerBudget(t *testing.T, budget, grace time.Duration) {
	t.Helper()
	oldB, oldG := commandBudget, writeGrace
	commandBudget, writeGrace = budget, grace
	t.Cleanup(func() { commandBudget, writeGrace = oldB, oldG })
}

func execute(t *testing.T, ctx context.Context, h Host, stdin io.Reader, args ...string) (Outcome, []byte) {
	t.Helper()
	var out bytes.Buffer
	o := Execute(ctx, h, args, stdin, &out)
	oneLine(t, out.Bytes())
	return o, out.Bytes()
}

// TestWriteGateNeverLiesAfterTheFirstWrite is Review Focus 1 (W2 Ruling 7).
func TestWriteGateNeverLiesAfterTheFirstWrite(t *testing.T) {
	lowerBudget(t, 50*time.Millisecond, 200*time.Millisecond)

	t.Run("blocked before enter: IO_ERROR, and enter fails afterwards", func(t *testing.T) {
		h := newWriteHost()
		answered := make(chan struct{})
		entered := make(chan error, 1)
		withCommand(t, "test-write", command{elevated: true, write: true, run: func(ctx context.Context, c *call) (any, error) {
			<-ctx.Done()
			<-answered
			_, err := c.gate.enter()
			entered <- err
			if err != nil {
				return nil, err
			}
			_ = c.host.WriteState("journal/x.json", []byte("{}"))
			return struct{}{}, nil
		}})
		start := time.Now()
		o, out := execute(t, context.Background(), h, nil, "test-write")
		close(answered)
		wantError(t, o.Exit, out, 4, winproto.CodeIOError)
		if o.Code != winproto.CodeIOError || !o.Abandoned || time.Since(start) > time.Second {
			t.Fatalf("%+v after %s", o, time.Since(start))
		}
		if err := <-entered; err == nil {
			t.Fatal("enter succeeded after the budget answered IO_ERROR")
		}
		if w := h.writes(); len(w) != 0 {
			t.Fatalf("writes %v", w)
		}
	})

	t.Run("entered and blocked: OUTCOME_UNKNOWN, the handler finishes in its grace", func(t *testing.T) {
		h := newWriteHost()
		h.setRecord(ipb(443, "My", h1))
		h.updateBlock = make(chan struct{})
		finished := make(chan error, 1)
		withCommand(t, "test-write", command{elevated: true, write: true, run: func(ctx context.Context, c *call) (any, error) {
			wctx, err := c.gate.enter()
			if err != nil {
				return nil, err
			}
			if err := c.host.WriteState("journal/x.json", []byte("{}")); err != nil {
				return nil, err
			}
			err = c.host.UpdateBinding(wctx, ipb(443, "My", h2))
			if ctx.Err() == nil || wctx.Err() != nil {
				err = errors.New("the write context must outlive the budget")
			}
			finished <- err
			<-wctx.Done() // ends WriteGrace after the budget
			return struct{}{}, nil
		}})
		o, out := execute(t, context.Background(), h, nil, "test-write")
		wantError(t, o.Exit, out, 4, winproto.CodeOutcomeUnknown)
		if o.Code != winproto.CodeOutcomeUnknown || !o.Abandoned {
			t.Fatalf("%+v", o)
		}
		close(h.updateBlock)
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		if w := h.writes(); len(w) != 2 || w[1] != "update http.sys/ipport/0.0.0.0:443" {
			t.Fatalf("writes %v", w)
		}
	})

	t.Run("a context that ended before enter: IO_ERROR, nothing written", func(t *testing.T) {
		h := newWriteHost()
		withCommand(t, "test-write", command{elevated: true, write: true, run: func(_ context.Context, c *call) (any, error) {
			if _, err := c.gate.enter(); err != nil {
				return nil, err
			}
			_ = c.host.WriteState("journal/x.json", []byte("{}"))
			return struct{}{}, nil
		}})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		for range 20 { // either side of Run's select
			o, out := execute(t, ctx, h, nil, "test-write")
			wantError(t, o.Exit, out, 4, winproto.CodeIOError)
		}
		if len(h.stateLog) != 0 || len(h.writes()) != 0 {
			t.Fatalf("state written: %v", h.writes())
		}
	})

	t.Run("an entered handler that answers in time is answered", func(t *testing.T) {
		h := newWriteHost()
		var wctx context.Context
		withCommand(t, "test-write", command{elevated: true, write: true, run: func(_ context.Context, c *call) (any, error) {
			var err error
			if wctx, err = c.gate.enter(); err != nil {
				return nil, err
			}
			if _, err := c.gate.enter(); err != nil { // a second enter is harmless
				return nil, err
			}
			return winproto.StatusResponse{OK: true, Phase: winproto.PhaseCommitted}, nil
		}})
		o, out := execute(t, context.Background(), h, nil, "test-write")
		if o.Exit != 0 || o.Code != "" || o.Abandoned || !strings.Contains(string(out), `"phase":"committed"`) {
			t.Fatalf("%+v %s", o, out)
		}
		if wctx.Err() == nil {
			t.Fatal("the write context outlived its handler")
		}
	})

	t.Run("a refusal after enter is the refusal", func(t *testing.T) {
		withCommand(t, "test-write", command{elevated: true, write: true, run: func(_ context.Context, c *call) (any, error) {
			if _, err := c.gate.enter(); err != nil {
				return nil, err
			}
			return nil, failed(winproto.CodeJournalFailed, "the journal could not be written")
		}})
		o, out := execute(t, context.Background(), newWriteHost(), nil, "test-write")
		wantError(t, o.Exit, out, 4, winproto.CodeJournalFailed)
		if o.Abandoned {
			t.Fatal("abandoned")
		}
	})
}

func TestGateCloseAndEnter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := newGate(ctx)
	defer g.finish()
	if g.close() {
		t.Fatal("entered before enter")
	}
	if _, err := g.enter(); err == nil {
		t.Fatal("enter after close")
	}
	g2 := newGate(ctx)
	defer g2.finish()
	if _, err := g2.enter(); err != nil {
		t.Fatal(err)
	}
	if !g2.close() {
		t.Fatal("close does not see the enter")
	}
}

// failReader fails the test when it is read.
type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) {
	r.t.Error("stdin was read")
	return 0, io.EOF
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestRunReadsBoundedStdin(t *testing.T) {
	var got []byte
	var calls int
	withCommand(t, winproto.SubIISDeploy, command{elevated: true, write: true, input: winproto.MaxDeployInput,
		run: func(_ context.Context, c *call) (any, error) {
			calls++
			got = c.input
			return struct{}{}, nil
		}})
	withCommand(t, winproto.SubIISStatus, command{elevated: true, run: func(_ context.Context, c *call) (any, error) {
		if c.input != nil || c.gate != nil {
			t.Error("iis-status has input or a gate")
		}
		return struct{}{}, nil
	}})

	h := newWriteHost()
	o, out := execute(t, context.Background(), h, bytes.NewReader(make([]byte, winproto.MaxDeployInput+1)), winproto.SubIISDeploy)
	wantError(t, o.Exit, out, 2, winproto.CodeTooLarge)
	if h.calls.Load() != 0 || calls != 0 {
		t.Fatalf("host calls %d, handler calls %d", h.calls.Load(), calls)
	}

	full := bytes.Repeat([]byte("k"), winproto.MaxDeployInput)
	o, out = execute(t, context.Background(), h, bytes.NewReader(full), winproto.SubIISDeploy)
	if o.Exit != 0 || calls != 1 || len(got) != winproto.MaxDeployInput {
		t.Fatalf("%+v %s len %d", o, out, len(got))
	}
	if !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("the input was not cleared after the handler")
	}

	// No stdin is an empty input.
	o, _ = execute(t, context.Background(), h, nil, winproto.SubIISDeploy)
	if o.Exit != 0 || len(got) != 0 {
		t.Fatalf("%+v %d", o, len(got))
	}
	o, out = execute(t, context.Background(), h, errReader{}, winproto.SubIISDeploy)
	wantError(t, o.Exit, out, 4, winproto.CodeIOError)

	// A command without input never reads stdin, nor do the read commands.
	if o, out = execute(t, context.Background(), h, failReader{t}, winproto.SubIISStatus); o.Exit != 0 {
		t.Fatalf("%+v %s", o, out)
	}
	for _, args := range [][]string{{"version"}, {"win-facts"}, {"iis-dump"}} {
		var b bytes.Buffer
		_ = Run(context.Background(), dumpHost(), args, failReader{t}, &b)
	}
}

func TestWriteCommandsNeedElevation(t *testing.T) {
	ran := false
	for _, sub := range []string{winproto.SubIISDeploy, winproto.SubIISRestore, winproto.SubIISStatus, winproto.SubIISFence} {
		// elevated is left false: a write command is elevated whatever its entry says.
		withCommand(t, sub, command{write: sub != winproto.SubIISStatus, elevated: sub == winproto.SubIISStatus,
			run: func(context.Context, *call) (any, error) { ran = true; return struct{}{}, nil }})
		h := newWriteHost()
		h.elevated = false
		o, out := execute(t, context.Background(), h, strings.NewReader("{}"), sub)
		wantError(t, o.Exit, out, 2, winproto.CodeNotElevated)
		if ran || len(h.writes()) != 0 {
			t.Fatalf("%s: ran %v writes %v", sub, ran, h.writes())
		}
		h.elevatedErr = errors.New("token")
		o, out = execute(t, context.Background(), h, nil, sub)
		wantError(t, o.Exit, out, 4, winproto.CodeIOError)
	}
	// Every registered command that writes is elevated and has a write handler.
	for name, c := range commands {
		if c.write && (c.run == nil || c.handle != nil) {
			t.Errorf("%s: a write command needs run and no handle", name)
		}
		if (c.run == nil) == (c.handle == nil) {
			t.Errorf("%s: exactly one of run and handle", name)
		}
		if c.input < 0 || c.input > winproto.MaxDeployInput {
			t.Errorf("%s: input bound %d", name, c.input)
		}
	}
}

func TestWriteCommandNeedsAWriteHost(t *testing.T) {
	withCommand(t, "test-write", command{elevated: true, write: true, run: func(context.Context, *call) (any, error) {
		t.Error("ran on a read-only host")
		return struct{}{}, nil
	}})
	o, out := execute(t, context.Background(), &fakeHost{elevated: true}, nil, "test-write")
	wantError(t, o.Exit, out, 4, winproto.CodeIOError)
}

func TestExecuteForced(t *testing.T) {
	var out bytes.Buffer
	o := ExecuteForced(context.Background(), &fakeHost{}, "version", nil, &out)
	if o.Exit != 0 || o.Code != "" || o.Abandoned {
		t.Fatalf("%+v", o)
	}
	out.Reset()
	o = ExecuteForced(context.Background(), &fakeHost{}, "version  x", nil, &out)
	if o.Exit != 2 || o.Code != winproto.CodeInvalidArgument {
		t.Fatalf("%+v", o)
	}
	var e winproto.ErrorResponse
	if err := json.Unmarshal(out.Bytes(), &e); err != nil || e.Code != winproto.CodeInvalidArgument {
		t.Fatal(err, e)
	}
}

func TestPointIsAKill(t *testing.T) {
	h := newWriteHost()
	if err := point(h, "deploy.prepared"); err != nil {
		t.Fatal(err)
	}
	h.pointErr = func(name string) error {
		if name == "deploy.bound" {
			return errors.New("kill")
		}
		return nil
	}
	err := point(h, "deploy.bound")
	var he *helperError
	if !errors.As(err, &he) || he.code != winproto.CodeIOError || strings.Contains(he.message, "kill") {
		t.Fatalf("%v", err)
	}
	if strings.Join(h.points, ",") != "deploy.prepared,deploy.bound" {
		t.Fatal(h.points)
	}
}
