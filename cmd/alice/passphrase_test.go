package main

import (
	"bytes"
	"context"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/backup"
)

// openPTY opens a pseudo-terminal pair: the controlling side and the path of the terminal side.
func openPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	// SyscallConn, not Fd: Fd would switch the descriptor to blocking mode and read deadlines would stop working.
	rc, err := ptmx.SyscallConn()
	require.NoError(t, err)
	var n uint32
	var ioErr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		if ioErr = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); ioErr == nil { //nolint:gosec // G115
			n, ioErr = unix.IoctlGetUint32(int(fd), unix.TIOCGPTN) //nolint:gosec // G115
		}
	}))
	require.NoError(t, ioErr)
	return ptmx, "/dev/pts/" + strconv.FormatUint(uint64(n), 10)
}

// syncBuffer is a bytes.Buffer that the reading goroutine and the test may use at once.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitFor waits until the buffer contains want (the prompt is written only after echo is off and the signal handler
// is installed).
func waitFor(t *testing.T, b *syncBuffer, want string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(b.String(), want) }, 5*time.Second, 5*time.Millisecond,
		"no %q in %q", want, b.String())
}

// drain reads what the terminal side wrote to the controlling side until it stays quiet for 300 ms.
func drain(t *testing.T, ptmx *os.File) string {
	t.Helper()
	var got []byte
	buf := make([]byte, 4096)
	for {
		require.NoError(t, ptmx.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
		n, err := ptmx.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			return string(got)
		}
	}
}

// usePTY points ttyPath at a fresh pseudo-terminal and returns its controlling side and the terminal side.
func usePTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	ptmx, pts := openPTY(t)
	old := ttyPath
	ttyPath = pts
	t.Cleanup(func() { ttyPath = old })
	term, err := os.OpenFile(pts, os.O_RDWR|unix.O_NOCTTY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = term.Close() })
	return ptmx, term
}

func lflag(t *testing.T, term *os.File) uint32 {
	t.Helper()
	rc, err := term.SyscallConn()
	require.NoError(t, err)
	var tio *unix.Termios
	var ioErr error
	require.NoError(t, rc.Control(func(fd uintptr) { tio, ioErr = unix.IoctlGetTermios(int(fd), unix.TCGETS) })) //nolint:gosec // G115
	require.NoError(t, ioErr)
	return tio.Lflag
}

// I-2: the typed passphrase never comes back on the terminal. The input is written only after the prompt, i.e. after
// echo was switched off (the line discipline echoes at input time), and the controlling side is read afterwards: with
// echo on it would carry "kırmızı kedi\r\n".
func TestPassphraseIsNotEchoed(t *testing.T) {
	ptmx, term := usePTY(t)
	require.NotZero(t, lflag(t, term)&unix.ECHO, "a fresh pseudo-terminal echoes")
	before := lflag(t, term)
	var stderr syncBuffer
	src, ok := newPassphraseSource(false, nil, term, &stderr)
	require.True(t, ok)
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := src.read()
		done <- result{b, err}
	}()
	waitFor(t, &stderr, "Recovery passphrase: ")
	_, err := ptmx.WriteString("kırmızı kedi\n")
	require.NoError(t, err)
	r := <-done
	require.NoError(t, r.err)
	assert.Equal(t, "kırmızı kedi", string(r.b))
	echoed := drain(t, ptmx)
	assert.NotContains(t, echoed, "kırmızı", "the passphrase was echoed")
	assert.NotContains(t, echoed, "kedi", "the passphrase was echoed")
	assert.Equal(t, before, lflag(t, term), "echo is back on")
}

// I-1: a signal at the prompt restores the terminal, closes it and cancels the read, for each of the four signals.
func TestPassphrasePromptCancelledBySignal(t *testing.T) {
	sigs := []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}
	// The test's own handler keeps the test process alive should the prompt not catch the signal.
	guard := make(chan os.Signal, 8)
	signal.Notify(guard, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	t.Cleanup(func() { signal.Stop(guard) })
	for _, sig := range sigs {
		t.Run(sig.String(), func(t *testing.T) {
			ptmx, term := usePTY(t)
			before := lflag(t, term)
			var stderr syncBuffer
			src, ok := newPassphraseSource(false, nil, term, &stderr)
			require.True(t, ok)
			done := make(chan error, 1)
			go func() {
				b, err := src.read()
				clear(b)
				done <- err
			}()
			waitFor(t, &stderr, "Recovery passphrase: ")
			require.NoError(t, syscall.Kill(os.Getpid(), sig))
			select {
			case err := <-done:
				assert.ErrorIs(t, err, errPassphraseCancelled)
			case <-time.After(5 * time.Second):
				_, _ = ptmx.WriteString("\n") // unblock the reader
				<-done
				t.Fatal("the signal did not cancel the read")
			}
			assert.Equal(t, before, lflag(t, term), "the terminal's settings are restored")
			assert.NotZero(t, lflag(t, term)&unix.ECHO)
		})
	}
}

// I-1 through the commands: Ctrl-C at the prompt of backup verify --deep and of restore cancels the command.
func TestCommandsCancelAtThePassphrasePrompt(t *testing.T) {
	guard := make(chan os.Signal, 8)
	signal.Notify(guard, syscall.SIGINT)
	t.Cleanup(func() { signal.Stop(guard) })
	old := restoreFunc
	t.Cleanup(func() { restoreFunc = old })
	restoreFunc = func(_ context.Context, _ backup.Config, in backup.RestoreInput) (backup.RestoreResult, error) {
		_, err := in.AskPassphrase()
		return backup.RestoreResult{}, err
	}
	oldCheck := ownerCheckFunc
	t.Cleanup(func() { ownerCheckFunc = oldCheck })
	ownerCheckFunc = func(context.Context, string) error { return nil }
	vars := env(map[string]string{"ALICE_DATABASE_URL": "postgres://alice_app@db/alice", "ALICE_MIGRATE_DATABASE_URL": "postgres://alice_owner@db/alice"})
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"verify":  {[]string{"backup", "verify", "/nonexistent/x.alicebak", "--deep"}, "Verification cancelled.\n"},
		"restore": {[]string{"restore", "/nonexistent/x.alicebak", "--confirm", "RESTORE"}, msgCancelled + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			ptmx, term := usePTY(t)
			before := lflag(t, term)
			var out bytes.Buffer
			var errOut syncBuffer
			done := make(chan int, 1)
			go func() { done <- run(c.args, vars, term, &out, &errOut) }()
			waitFor(t, &errOut, "Recovery passphrase: ")
			require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGINT))
			select {
			case code := <-done:
				assert.Equal(t, 1, code)
				assert.Equal(t, "Recovery passphrase: \n"+c.want, errOut.String())
			case <-time.After(5 * time.Second):
				_, _ = ptmx.WriteString("\n")
				<-done
				t.Fatal("Ctrl-C did not cancel the command")
			}
			assert.Equal(t, before, lflag(t, term))
			assert.NotContains(t, drain(t, ptmx), "Recovery")
		})
	}
}

// On a terminal the passphrase is read from the terminal with echo off, the prompt on stderr, and the terminal's
// settings are restored afterwards.
func TestPassphraseFromTheTerminal(t *testing.T) {
	ptmx, pts := openPTY(t)
	old := ttyPath
	ttyPath = pts
	t.Cleanup(func() { ttyPath = old })
	term, err := os.OpenFile(pts, os.O_RDWR|unix.O_NOCTTY, 0)
	require.NoError(t, err)
	defer func() { _ = term.Close() }()
	assert.True(t, stdinIsTerminal(term))
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close(); _ = w.Close() }()
	assert.False(t, stdinIsTerminal(r), "a pipe is no terminal")
	before, err := unix.IoctlGetTermios(int(term.Fd()), unix.TCGETS) //nolint:gosec // G115
	require.NoError(t, err)

	var stderr bytes.Buffer
	src, ok := newPassphraseSource(false, nil, term, &stderr)
	require.True(t, ok)
	_, err = ptmx.WriteString("kırmızı kedi\n")
	require.NoError(t, err)
	got, err := src.read()
	require.NoError(t, err)
	assert.Equal(t, "kırmızı kedi", string(got))
	assert.Equal(t, "Recovery passphrase: \n", stderr.String())
	after, err := unix.IoctlGetTermios(int(term.Fd()), unix.TCGETS) //nolint:gosec // G115
	require.NoError(t, err)
	assert.Equal(t, before.Lflag, after.Lflag, "echo is back on")

	ttyPath = "/nonexistent/tty"
	_, err = readFromTTY(&stderr)
	assert.Error(t, err)
}
