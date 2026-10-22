//go:build windows

// Command alice-winhelper is alice-helper.exe, the helper Alice runs on managed Windows servers
// through OpenSSH's forced command (design 2026-10-21 §7, R60). The decisions live in
// internal/providers/windows/winhelper; this package only wires the real Windows host to them.
package main

import (
	"context"
	"os"

	"alice/internal/providers/windows/winhelper"
)

func main() {
	os.Exit(run(os.Args[1:], newHost()))
}

// run is "ssh" (the forced-command entry: sshd passes the line in SSH_ORIGINAL_COMMAND) or one
// subcommand named on the command line.
func run(args []string, host winhelper.Host) int {
	ctx := context.Background()
	if len(args) == 1 && args[0] == "ssh" {
		return winhelper.RunForced(ctx, host, os.Getenv("SSH_ORIGINAL_COMMAND"), os.Stdin, os.Stdout)
	}
	return winhelper.Run(ctx, host, args, os.Stdin, os.Stdout)
}
