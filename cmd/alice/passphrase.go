package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
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

// readFromTTY asks on stderr and reads one line from /dev/tty with echo switched off (term.ReadPassword's settings),
// restoring the terminal afterwards.
func readFromTTY(stderr io.Writer) ([]byte, error) {
	tty, err := os.OpenFile(ttyPath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open the terminal: %w", err)
	}
	defer func() { _ = tty.Close() }()
	fd := int(tty.Fd()) //nolint:gosec // G115: a file descriptor fits an int
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("read the terminal settings: %w", err)
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	quiet.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return nil, fmt.Errorf("switch the terminal echo off: %w", err)
	}
	defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }()
	fmt.Fprint(stderr, "Recovery passphrase: ")
	defer fmt.Fprintln(stderr)
	return readLine(bufio.NewReaderSize(tty, maxPassphraseBytes+16), maxPassphraseBytes)
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
