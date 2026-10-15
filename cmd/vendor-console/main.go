// Command vendor-console is the vendor's license record and issuing tool (design spec
// 2026-10-15-vendor-console-design.md). It never ships to customers; the alice binary must not
// link it or anything under internal/vconsole (checked by cmd/alice tests).
package main

import (
	"os"

	"alice/internal/platform/clock"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr, terminalPassphrase, clock.Real{}))
}
