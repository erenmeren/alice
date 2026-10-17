package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/api"
)

var _ apiLifecycle = (*api.Server)(nil)

// fakeLifecycle records the calls of the start and the shutdown in order.
type fakeLifecycle struct {
	mu    sync.Mutex
	calls []string
	ran   chan struct{}
}

func (f *fakeLifecycle) record(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}

func (f *fakeLifecycle) RunDenialSummaries(ctx context.Context) {
	close(f.ran)
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond) // a last sweep still writing
	f.record("summaries stopped")
}
func (f *fakeLifecycle) StopScans()                   { f.record("stop scans") }
func (f *fakeLifecycle) FlushDenials(context.Context) { f.record("flush denials") }

type fakeShutdowner struct {
	f    *fakeLifecycle
	name string
}

func (s fakeShutdowner) Shutdown(context.Context) error {
	s.f.record("shutdown " + s.name)
	return nil
}

// I3, M3, M7: the denial-summary writer is started; at shutdown the running audit scans stop
// first, then the servers drain, then the writer is joined, then the open windows are flushed.
func TestShutdownStopsScansThenDrainsThenFlushes(t *testing.T) {
	f := &fakeLifecycle{ran: make(chan struct{})}
	stop, done := startDenialSummaries(context.Background(), f)
	select {
	case <-f.ran:
	case <-time.After(5 * time.Second):
		t.Fatal("the denial-summary writer was not started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stopServing(ctx, f, []shutdowner{fakeShutdowner{f, "public"}, fakeShutdowner{f, "internal"}}, stop, done,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Equal(t, []string{"stop scans", "shutdown public", "shutdown internal", "summaries stopped", "flush denials"}, f.calls)
}

// The serve path uses the helpers above, and stops serving before the scheduler and the workers.
func TestServeWiresTheDenialWriterAndTheShutdownOrder(t *testing.T) {
	src, err := os.ReadFile("main.go")
	require.NoError(t, err)
	body := string(src)
	start := strings.Index(body, "startDenialSummaries(ctx, apiServer)")
	// The ports are bound earlier (listenBoth); serving the requests starts here.
	listen := strings.Index(body, "public.ServeTLS(publicLn")
	stop := strings.Index(body, "stopServing(shutdownCtx, apiServer, []shutdowner{public, internal}, stopDenialSummaries, denialSummariesDone, log)")
	sched := strings.Index(body, "\tstopSched()\n\twaitForScheduler")
	require.Positive(t, start, "the denial-summary writer is started")
	require.Positive(t, stop, "shutdown goes through stopServing")
	require.Positive(t, listen, "the public server serves its bound listener")
	assert.Less(t, start, listen, "the writer starts before the listeners")
	assert.Less(t, stop, sched, "serving stops before the scheduler")
	assert.NotContains(t, body, "public.Shutdown(", "the servers drain only inside stopServing, after StopScans")
}
