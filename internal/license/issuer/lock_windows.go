//go:build windows

package issuer

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive lock on the first byte of f (LockFileEx, offset 0, length 1),
// waiting for it. f is the dedicated .lock file, which holds no data, so the lock is advisory:
// it excludes other callers of lockFile, not readers or writers of other files. Closing the file
// releases it.
func lockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
}
