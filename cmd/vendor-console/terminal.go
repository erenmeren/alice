package main

import (
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
	fd := int(os.Stdin.Fd()) //nolint:gosec // G115: a file descriptor always fits in int
	if !term.IsTerminal(fd) {
		return nil, errors.New("vendor-console must be run in a terminal so the passphrase is not echoed")
	}
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt)
	done := make(chan struct{})
	defer func() {
		signal.Stop(interrupted)
		close(done)
	}()
	go func() {
		select {
		case <-interrupted:
			_ = term.Restore(fd, state)
			_, _ = fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-done:
		}
	}()
	_, _ = fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(os.Stderr)
	return p, err
}
