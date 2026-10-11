package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxPassphraseBytes bounds one passphrase line on standard input (C6).
const maxPassphraseBytes = 1024

// msgPassphraseNeeded is C6's answer when no passphrase source is available (exit 2).
const msgPassphraseNeeded = "A passphrase is needed. Run this command in a terminal, or pass --passphrase-file to alicectl."

// ttyPath is the process's terminal; a variable only so a test can use a pseudo-terminal of its own.
var ttyPath = "/dev/tty"

// errPassphraseTooLong is a passphrase line over maxPassphraseBytes.
var errPassphraseTooLong = errors.New("the passphrase is longer than 1024 bytes")

// errPassphraseCancelled is a signal (Ctrl-C) at the passphrase prompt.
var errPassphraseCancelled = errors.New("the passphrase prompt was cancelled")

// stdinIsTerminal reports whether stdin is the process's terminal; a test's reader never is.
func stdinIsTerminal(stdin io.Reader) bool {
	f, ok := stdin.(*os.File)
	return ok && isTerminal(f)
}

// isTerminal is term.IsTerminal. The release binary links no terminal library (TestReleaseBinaryLinksNoTestOrVendorCode:
// golang.org/x/term is licensectl's), so the two terminal calls are made with golang.org/x/sys/unix, which it links
// anyway.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS) //nolint:gosec // G115: a file descriptor fits an int
	return err == nil
}

// passphraseSource reads the recovery passphrase by C6's rules: from /dev/tty without echo when stdin is a terminal,
// else only with --passphrase-stdin (one line of at most 1,024 bytes, exactly one trailing "\n" removed). The
// environment is never read. The caller clears the returned slice.
type passphraseSource struct {
	fromStdin bool
	in        *bufio.Reader
	stderr    io.Writer
	terminal  bool
}

// newPassphraseSource checks that a passphrase can be read at all (false: print msgPassphraseNeeded, exit 2).
func newPassphraseSource(fromStdin bool, in *bufio.Reader, stdin io.Reader, stderr io.Writer) (*passphraseSource, bool) {
	p := &passphraseSource{fromStdin: fromStdin, in: in, stderr: stderr, terminal: !fromStdin && stdinIsTerminal(stdin)}
	return p, p.fromStdin || p.terminal
}

// read returns the passphrase as typed, never normalised (secrets does that inside Unwrap).
func (p *passphraseSource) read() ([]byte, error) {
	if p.terminal {
		return readFromTTY(p.stderr)
	}
	return readLine(p.in, maxPassphraseBytes)
}

// passphraseSignals end the prompt: the terminal is restored before the process acts on them (I-1).
var passphraseSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// readFromTTY asks on stderr and reads one line from /dev/tty with echo switched off (term.ReadPassword's settings),
// restoring the terminal afterwards. A signal at the prompt (SIGINT, SIGTERM, SIGHUP, SIGQUIT) restores the settings,
// closes the terminal, which ends the blocked read, and returns errPassphraseCancelled.
func readFromTTY(stderr io.Writer) ([]byte, error) {
	tty, err := os.OpenFile(ttyPath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open the terminal: %w", err)
	}
	// The descriptor is reached through SyscallConn, never Fd: Fd switches it to blocking mode, and Close would then
	// no longer end a pending read.
	rc, err := tty.SyscallConn()
	if err != nil {
		_ = tty.Close()
		return nil, fmt.Errorf("open the terminal: %w", err)
	}
	old, err := getTermios(rc)
	if err != nil {
		_ = tty.Close()
		return nil, fmt.Errorf("read the terminal settings: %w", err)
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			_ = setTermios(rc, old)
			_ = tty.Close()
		})
	}
	defer restore()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, passphraseSignals...)
	defer signal.Stop(sigs)
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	quiet.Iflag |= unix.ICRNL
	if err := setTermios(rc, &quiet); err != nil {
		return nil, fmt.Errorf("switch the terminal echo off: %w", err)
	}
	var cancelled atomic.Bool
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sigs:
			cancelled.Store(true)
			restore()
		case <-done:
		}
	}()
	fmt.Fprint(stderr, "Recovery passphrase: ")
	defer fmt.Fprintln(stderr)
	line, err := readLine(bufio.NewReaderSize(tty, maxPassphraseBytes+16), maxPassphraseBytes)
	if cancelled.Load() {
		clear(line)
		return nil, errPassphraseCancelled
	}
	return line, err
}

func getTermios(rc syscall.RawConn) (*unix.Termios, error) {
	var t *unix.Termios
	var err error
	cerr := rc.Control(func(fd uintptr) { t, err = unix.IoctlGetTermios(int(fd), unix.TCGETS) }) //nolint:gosec // G115
	return t, errors.Join(cerr, err)
}

func setTermios(rc syscall.RawConn, t *unix.Termios) error {
	var err error
	cerr := rc.Control(func(fd uintptr) { err = unix.IoctlSetTermios(int(fd), unix.TCSETS, t) }) //nolint:gosec // G115
	return errors.Join(cerr, err)
}

// readLine reads one line of at most limit bytes and removes exactly one trailing "\n" (and nothing else). A longer
// line is an error; its bytes are cleared.
func readLine(in *bufio.Reader, limit int) ([]byte, error) {
	var buf []byte
	for {
		frag, err := in.ReadSlice('\n')
		buf = append(buf, frag...)
		clear(frag) // consumed: the copy in bufio's buffer is not needed any more
		if len(buf) > limit+1 || (len(buf) == limit+1 && !bytes.HasSuffix(buf, []byte("\n"))) {
			clear(buf)
			return nil, errPassphraseTooLong
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			clear(buf)
			return nil, err
		}
		break
	}
	line, _ := bytes.CutSuffix(buf, []byte("\n"))
	return line, nil
}
