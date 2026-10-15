//go:build windows

package secrets

import (
	"io/fs"
	"os"
)

// Master key file operations are not supported for the product on Windows;
// the vendor tools link this package but never use them. This file only makes
// the package compile there: the O_NOFOLLOW/O_NONBLOCK flags do not exist
// (0) and Windows ACLs are not inspected, so the owner check is skipped.
const (
	oNoFollow = 0
	oNonBlock = 0
)

// geteuid is the effective-UID lookup; tests replace it. It is -1 on Windows.
var geteuid = os.Geteuid

// checkKeyFileOwner is a no-op on Windows: ACLs are not inspected.
func checkKeyFileOwner(string, fs.FileInfo) error { return nil }
