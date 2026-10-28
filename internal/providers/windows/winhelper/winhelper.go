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
	pendingOp     string // with RECOVERY_PENDING: the interrupted operation (ErrorResponse.PendingOp)
}

func (e *helperError) Error() string { return e.code + ": " + e.message }

func refused(code, msg string) error {
	return &helperError{exit: winproto.ExitRefused, code: code, message: msg}
}

func failed(code, msg string) error {
	return &helperError{exit: winproto.ExitFailed, code: code, message: msg}
}

// command is one subcommand. Elevated ones need an elevated token (Ruling 3). A W1 read command has
// handle; a command that needs a WriteHost has run instead. A write command (W2) is always elevated
// and runs under its gate (W2 Ruling 7). input is how many bytes of stdin the command reads (0: none,
// stdin is never read).
type command struct {
	elevated bool
	write    bool
	input    int
	handle   func(ctx context.Context, h Host, args []string) (any, error)
	run      func(ctx context.Context, c *call) (any, error)
}

var commands = map[string]command{
	winproto.SubVersion:  {handle: cmdVersion},
	winproto.SubWinFacts: {handle: cmdWinFacts},
	winproto.SubTLSProbe: {handle: cmdTLSProbe},
	winproto.SubIISDump:  {elevated: true, handle: cmdIISDump},

	// The write subcommands (W2): iis-deploy, iis-restore and iis-fence change the machine under their
	// gate; iis-status is an elevated read under no lock.
	winproto.SubIISDeploy:  {write: true, input: winproto.MaxDeployInput, run: cmdIISDeploy},
	winproto.SubIISRestore: {write: true, input: winproto.MaxRestoreInput, run: cmdIISRestore},
	winproto.SubIISStatus:  {elevated: true, run: cmdIISStatus},
	winproto.SubIISFence:   {write: true, run: cmdIISFence},

	// iis-cleanup (W3): --plan and --apply change the machine under the gate.
	winproto.SubIISCleanup: {write: true, input: winproto.MaxCleanupInput, run: cmdIISCleanup},

	// ccs-dump (W5): an elevated read of the CCS folder under no lock, the password on stdin;
	// ccs-deploy writes one CCS file under the gate.
	winproto.SubCCSDump:   {elevated: true, input: winproto.MaxCCSDumpInput, run: cmdCCSDump},
	winproto.SubCCSDeploy: {write: true, input: winproto.MaxCCSDeployInput, run: cmdCCSDeploy},

	// rdp-dump (W6): an elevated read of the RDP-Tcp listener under no lock, no input; rdp-deploy sets the
	// listener's certificate under the gate.
	winproto.SubRDPDump:   {elevated: true, run: cmdRDPDump},
	winproto.SubRDPDeploy: {write: true, input: winproto.MaxDeployInput, run: cmdRDPDeploy},
}

// RunForced is the "ssh" entry: it splits SSH_ORIGINAL_COMMAND with winproto.SplitCommandLine and runs it.
func RunForced(ctx context.Context, h Host, originalCommand string, stdin io.Reader, stdout io.Writer) int {
	return ExecuteForced(ctx, h, originalCommand, stdin, stdout).Exit
}

// Run executes one call (args[0] is the subcommand) under the call budget, prints exactly one JSON line
// and returns the exit code. Execute does the same and also tells whether the call was abandoned at
// the end of its budget.
func Run(ctx context.Context, h Host, args []string, stdin io.Reader, stdout io.Writer) int {
	return Execute(ctx, h, args, stdin, stdout).Exit
}

// reply prints the answer or the error and returns the exit code.
func reply(w io.Writer, out any, err error) int { return answer(w, out, err).Exit }

// answer prints the answer or the error and returns the call's Outcome.
func answer(w io.Writer, out any, err error) Outcome {
	if err != nil {
		var he *helperError
		if !errors.As(err, &he) {
			he = &helperError{exit: winproto.ExitFailed, code: winproto.CodeIOError, message: "the operation failed"}
		}
		writeJSON(w, winproto.ErrorResponse{OK: false, Code: he.code, Message: he.message, PendingOp: he.pendingOp})
		return Outcome{Exit: he.exit, Code: he.code}
	}
	writeJSON(w, out)
	return Outcome{Exit: winproto.ExitOK}
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
