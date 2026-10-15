//go:build unix

package issuer

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive flock on f, waiting for it and retrying when interrupted.
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX) //nolint:gosec // G115: a file descriptor always fits in int
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}
