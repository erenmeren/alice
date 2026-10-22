// Package winhelper is the platform-neutral core of the Windows helper (design 2026-10-21 §7, R60,
// Ruling 4): the command table, the forced-command split, the elevation gate, the call budget and the
// answers. Everything that touches Windows (tokens, http.sys, the certificate stores, appcmd, the
// network) is behind Host, so the real helper and the emulator run this same code.
package winhelper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"

	"alice/internal/providers/windows/winproto"
)

// OSFacts are the operating system readings of a Host.
type OSFacts struct{ Build, Product, InstallationType, OpenSSHVersion string }

// Host is the machine the helper runs on.
type Host interface {
	// Elevated reports whether the helper's token is elevated.
	Elevated() (bool, error)
	OSFacts(ctx context.Context) (OSFacts, error)
	// IISFacts returns ErrIISNotInstalled when IIS is not installed.
	IISFacts(ctx context.Context) (winproto.IISFacts, error)
	Stores(ctx context.Context) ([]string, error)
	SSLBindings(ctx context.Context) ([]winproto.SSLBinding, error)
	// Certificate reads one certificate by store and SHA-1; found is false when the store has none.
	Certificate(ctx context.Context, store, sha1 string) (cert winproto.StoreCertificate, found bool, err error)
	ExpiredInStore(ctx context.Context, store string) (int, error)
	// AppcmdSites is the output of "appcmd list site /config /xml", at most winproto.MaxAppcmdOutput bytes.
	AppcmdSites(ctx context.Context) ([]byte, error)
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

// ErrIISNotInstalled is what Host.IISFacts returns on a machine without IIS.
var ErrIISNotInstalled = errors.New("winhelper: IIS is not installed")

// commandBudget bounds one call (tests lower it).
var commandBudget = winproto.HelperBudget

// helperError is a refusal or failure with its exit code. Messages are fixed texts: never a path from
// the caller, never OS error text.
type helperError struct {
	exit          int
	code, message string
}

func (e *helperError) Error() string { return e.code + ": " + e.message }

func refused(code, msg string) error {
	return &helperError{exit: winproto.ExitRefused, code: code, message: msg}
}

func failed(code, msg string) error {
	return &helperError{exit: winproto.ExitFailed, code: code, message: msg}
}

// command is one subcommand. Elevated ones need an elevated token (Ruling 3).
type command struct {
	elevated bool
	handle   func(ctx context.Context, h Host, args []string) (any, error)
}

var commands = map[string]command{
	winproto.SubVersion:  {handle: cmdVersion},
	winproto.SubWinFacts: {handle: cmdWinFacts},
	winproto.SubTLSProbe: {handle: cmdTLSProbe},
	winproto.SubIISDump:  {elevated: true, handle: cmdIISDump},
}

// RunForced is the "ssh" entry: it splits SSH_ORIGINAL_COMMAND with winproto.SplitCommandLine and runs it.
func RunForced(ctx context.Context, h Host, originalCommand string, stdin io.Reader, stdout io.Writer) int {
	args, ok := winproto.SplitCommandLine(originalCommand)
	if !ok {
		return reply(stdout, nil, refused(winproto.CodeInvalidArgument, "the command line is not allowed"))
	}
	return Run(ctx, h, args, stdin, stdout)
}

// Run executes one call (args[0] is the subcommand) under the call budget, prints exactly one JSON line
// and returns the exit code.
func Run(ctx context.Context, h Host, args []string, _ io.Reader, stdout io.Writer) int {
	if len(args) == 0 {
		return reply(stdout, nil, refused(winproto.CodeUsage, "usage: alice-helper <subcommand> [arguments]"))
	}
	c, ok := commands[args[0]]
	if !ok {
		return reply(stdout, nil, refused(winproto.CodeUnknownSubcommand, "unknown subcommand"))
	}
	ctx, cancel := context.WithTimeout(ctx, commandBudget)
	defer cancel()
	type result struct {
		out any
		err error
	}
	done := make(chan result, 1)
	go func() {
		if c.elevated {
			el, err := h.Elevated()
			if err != nil {
				done <- result{nil, failed(winproto.CodeIOError, "the token could not be read")}
				return
			}
			if !el {
				done <- result{nil, refused(winproto.CodeNotElevated, "this subcommand needs an elevated token")}
				return
			}
		}
		out, err := c.handle(ctx, h, args[1:])
		done <- result{out, err}
	}()
	// The budget ends the call even when a host reading ignores its context.
	select {
	case r := <-done:
		return reply(stdout, r.out, r.err)
	case <-ctx.Done():
		return reply(stdout, nil, failed(winproto.CodeIOError, "the call took too long"))
	}
}

// reply prints the answer or the error and returns the exit code.
func reply(w io.Writer, out any, err error) int {
	if err != nil {
		var he *helperError
		if !errors.As(err, &he) {
			he = &helperError{exit: winproto.ExitFailed, code: winproto.CodeIOError, message: "the operation failed"}
		}
		writeJSON(w, winproto.ErrorResponse{OK: false, Code: he.code, Message: he.message})
		return he.exit
	}
	writeJSON(w, out)
	return winproto.ExitOK
}

func writeJSON(w io.Writer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"ok":false,"code":"IO_ERROR","message":"the answer could not be encoded"}`)
	}
	_, _ = w.Write(append(b, '\n'))
}

func cmdVersion(_ context.Context, _ Host, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(winproto.CodeUsage, "version takes no arguments")
	}
	return winproto.VersionResponse{OK: true, Helper: winproto.Version, Protocol: winproto.Protocol}, nil
}

// cmdIISDump is a placeholder until the dump lands (Task 3).
func cmdIISDump(_ context.Context, _ Host, _ []string) (any, error) {
	return nil, failed(winproto.CodeIOError, "the dump is not available")
}
