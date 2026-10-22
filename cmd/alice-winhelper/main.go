//go:build windows

// Command alice-winhelper is alice-helper.exe, the helper Alice runs on managed Windows servers
// through OpenSSH's forced command (design 2026-10-21 §7, R60). The decisions live in
// internal/providers/windows/winhelper; this package only wires the real Windows host to them.
package main

import (
	"context"
	"os"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

func main() {
	o := run(os.Args[1:], newHost(winproto.DataDir))
	// When o.Abandoned is set the answer was given at the end of the budget while the handler still
	// runs (with OUTCOME_UNKNOWN it had made its first change): the process ends here at once, like a
	// crash, with no deferred cleanup and no lock release, so the journal decides at the next
	// iis-status (W2 Ruling 7). main therefore has nothing after the call and no defer.
	os.Exit(o.Exit)
}

// run is "ssh" (the forced-command entry: sshd passes the line in SSH_ORIGINAL_COMMAND) or one
// subcommand named on the command line.
func run(args []string, host winhelper.Host) winhelper.Outcome {
	ctx := context.Background()
	if len(args) == 1 && args[0] == "ssh" {
		return winhelper.ExecuteForced(ctx, host, os.Getenv("SSH_ORIGINAL_COMMAND"), os.Stdin, os.Stdout)
	}
	return winhelper.Execute(ctx, host, args, os.Stdin, os.Stdout)
}
