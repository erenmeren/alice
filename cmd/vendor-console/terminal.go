package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/term"
)

// terminalPassphrase reads a passphrase without echo. vendor-console refuses to read a passphrase
// from a pipe or file, so it never ends up in shell history, scripts or logs. Ctrl-C while
// typing restores the terminal (echo on) and exits with 130.
func terminalPassphrase(prompt string) ([]byte, error) {
	return readHidden(context.Background(), prompt, true)
}

// terminalSecret reads the YubiKey PIN without echo and gives up when ctx ends (the PIN prompt is
// inside the signer's 2 minute limit). Ctrl-C does not exit here: it returns an error wrapping
// context.Canceled, like the caller's interrupt context does, so the command's cleanup runs (the
// reserved output file is removed, the card closed) and it exits 1 with "signing cancelled".
//
// A terminal read cannot be interrupted, so on ctx's end or Ctrl-C the terminal is restored (echo
// on) and the read is left behind in its goroutine: the process exits soon after, and whatever
// that read still returns is zeroed and dropped. Zeroing covers our own buffers only:
// golang.org/x/term, the terminal driver, pcscd or WinSCard may keep copies of the PIN that this
// program cannot clear.
func terminalSecret(ctx context.Context, prompt string) ([]byte, error) {
	return readHidden(ctx, prompt, false)
}

// errInterrupted is Ctrl-C at the PIN prompt.
var errInterrupted = fmt.Errorf("interrupted: %w", context.Canceled)

type hiddenAnswer struct {
	p   []byte
	err error
}

// How a hidden read ended.
type hiddenEnd int

const (
	endRead hiddenEnd = iota
	endInterrupt
	endContext
)

// waitHidden waits for the read, Ctrl-C or the end of ctx. When the read does not win, its
// answer is zeroed whenever it arrives.
func waitHidden(ctx context.Context, read <-chan hiddenAnswer, interrupted <-chan os.Signal) (hiddenAnswer, hiddenEnd) {
	select {
	case a := <-read:
		return a, endRead
	case <-interrupted:
		go func() { a := <-read; clear(a.p) }()
		return hiddenAnswer{}, endInterrupt
	case <-ctx.Done():
		go func() { a := <-read; clear(a.p) }()
		return hiddenAnswer{}, endContext
	}
}

func readHidden(ctx context.Context, prompt string, exitOnInterrupt bool) ([]byte, error) {
	fd := int(os.Stdin.Fd()) //nolint:gosec // G115: a file descriptor always fits in int
	if !term.IsTerminal(fd) {
		return nil, errors.New("vendor-console must be run in a terminal so the passphrase or PIN is not echoed")
	}
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt)
	defer signal.Stop(interrupted)

	read := make(chan hiddenAnswer, 1)
	_, _ = fmt.Fprint(os.Stderr, prompt)
	go func() {
		p, err := term.ReadPassword(fd)
		read <- hiddenAnswer{p, err}
	}()
	a, how := waitHidden(ctx, read, interrupted)
	if how != endRead {
		_ = term.Restore(fd, state)
	}
	_, _ = fmt.Fprintln(os.Stderr)
	switch how {
	case endInterrupt:
		if exitOnInterrupt {
			os.Exit(130)
		}
		return nil, errInterrupted
	case endContext:
		return nil, ctx.Err()
	}
	return a.p, a.err
}
