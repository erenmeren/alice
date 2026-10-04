//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"alice/internal/providers/linuxssh/helperproto"
)

// helperError is a refusal or failure with its exit code (spec §12.3) and an internal code.
// Messages are fixed texts: never a path from the caller, never file contents, never OS errors.
type helperError struct {
	exit    int
	code    string
	message string
}

func (e *helperError) Error() string { return e.code + ": " + e.message }

func refused(code, msg string) error {
	return &helperError{exit: helperproto.ExitRefused, code: code, message: msg}
}

func precondition(code, msg string) error {
	return &helperError{exit: helperproto.ExitPrecondition, code: code, message: msg}
}

func failed(code, msg string) error {
	return &helperError{exit: helperproto.ExitFailed, code: code, message: msg}
}

// command is one subcommand. Privileged ones need euid 0 (sudo).
type command struct {
	privileged bool
	handle     func(ctx context.Context, s *sys, args []string) (any, error)
}

var commands = map[string]command{
	helperproto.SubVersion:       {handle: cmdVersion},
	helperproto.SubSSHDDump:      {privileged: true, handle: cmdSSHDDump},
	helperproto.SubHostKeys:      {privileged: true, handle: cmdHostKeys},
	helperproto.SubAuthKeysList:  {privileged: true, handle: cmdAuthKeysList},
	helperproto.SubAuthKeysRead:  {privileged: true, handle: cmdAuthKeysRead},
	helperproto.SubAuthKeysWrite: {privileged: true, handle: cmdAuthKeysWrite},
	helperproto.SubCleanup:       {privileged: true, handle: cmdCleanup},
	helperproto.SubNginxDump:     {privileged: true, handle: cmdNginxDump},
	helperproto.SubNginxTest:     {privileged: true, handle: cmdNginxTest},
	helperproto.SubNginxDeploy:   {privileged: true, handle: cmdNginxDeploy},
	helperproto.SubNginxRestore:  {privileged: true, handle: cmdNginxRestore},
	helperproto.SubNginxStatus:   {privileged: true, handle: cmdNginxStatus},
	helperproto.SubNginxFence:    {privileged: true, handle: cmdNginxFence},
	helperproto.SubTLSProbe:      {handle: cmdTLSProbe},
}

// commandBudget bounds one call. Alice gives authkeys-list, -read and -write 60 s (R37 item 17);
// the helper normally stops 10 s earlier and never replaces a file after its own deadline
// (replace); Alice still treats a write that timed out as uncertain (see helperproto.HelperBudget).
const commandBudget = helperproto.HelperBudget

// run executes one call and returns the exit code. It prints exactly one JSON line.
func run(args []string, s *sys) int {
	if len(args) == 0 {
		return reply(s, nil, refused(helperproto.CodeUsage, "usage: alice-helper <subcommand> [arguments]"))
	}
	c, ok := commands[args[0]]
	if !ok {
		return reply(s, nil, refused(helperproto.CodeUnknownSubcommand, "unknown subcommand"))
	}
	if c.privileged && s.euid() != 0 {
		return reply(s, nil, refused(helperproto.CodeNotRoot, "this subcommand must run as root through sudo"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandBudget)
	defer cancel()
	if c.privileged {
		s.sweepBackups()
		s.sweepLocks()
	}
	out, err := c.handle(ctx, s, args[1:])
	return reply(s, out, err)
}

// reply prints the answer or the error and returns the exit code.
func reply(s *sys, out any, err error) int {
	if err != nil {
		var he *helperError
		if !errors.As(err, &he) {
			he = &helperError{exit: helperproto.ExitFailed, code: helperproto.CodeIOError, message: "the operation failed"}
		}
		writeJSON(s.stdout, helperproto.ErrorResponse{OK: false, Code: he.code, Message: he.message})
		return he.exit
	}
	writeJSON(s.stdout, out)
	return helperproto.ExitOK
}

func writeJSON(w io.Writer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"ok":false,"code":"IO_ERROR","message":"the answer could not be encoded"}`)
	}
	_, _ = w.Write(append(b, '\n'))
}

func cmdVersion(_ context.Context, _ *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "version takes no arguments")
	}
	return helperproto.VersionResponse{OK: true, Helper: helperproto.Version, Protocol: helperproto.Protocol}, nil
}
