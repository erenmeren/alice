// Package windows is the Windows server provider (design 2026-10-21-windows-iis-target-design.md §8).
package windows

import "regexp"

// The SHA-256 checksums of the alice-helper.exe binaries that belong to this Alice build: the lines
// of bin/alice-winhelper.sha256 that "make winhelper" writes, set at link time by "make build" and
// the image build (-X alice/internal/providers/windows.helperSHA256WindowsAMD64=...). Empty in a
// build without them (go build, go test).
var (
	helperSHA256WindowsAMD64 string
	helperSHA256WindowsARM64 string
)

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HelperChecksumsKnown reports whether this build embeds both alice-helper.exe checksums (make
// build and the image build do).
func HelperChecksumsKnown() bool {
	return sha256Hex.MatchString(helperSHA256WindowsAMD64) && sha256Hex.MatchString(helperSHA256WindowsARM64)
}
