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
// typing restores the terminal (echo on) before exiting.
func terminalPassphrase(prompt string) ([]byte, error) {
	return terminalSecret(context.Background(), prompt)
}

// terminalSecret is terminalPassphrase that gives up when ctx ends (the YubiKey PIN prompt is
// inside the signer's 2 minute limit). A terminal read cannot be interrupted, so on ctx's end the
// terminal is restored (echo on) and the read is left behind in its goroutine: the process exits
// soon after, and whatever that read still returns is zeroed and dropped.
func terminalSecret(ctx context.Context, prompt string) ([]byte, error) {
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

	type answer struct {
		p   []byte
		err error
	}
	read := make(chan answer, 1)
	_, _ = fmt.Fprint(os.Stderr, prompt)
	go func() {
		p, err := term.ReadPassword(fd)
		read <- answer{p, err}
	}()
	select {
	case a := <-read:
		_, _ = fmt.Fprintln(os.Stderr)
		return a.p, a.err
	case <-interrupted:
		_ = term.Restore(fd, state)
		_, _ = fmt.Fprintln(os.Stderr)
		os.Exit(130)
		return nil, nil // not reached
	case <-ctx.Done():
		_ = term.Restore(fd, state)
		_, _ = fmt.Fprintln(os.Stderr)
		go func() { a := <-read; clear(a.p) }()
		return nil, ctx.Err()
	}
}
