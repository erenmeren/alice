//go:build unix

package license

import "syscall"

// Open flags for the time record: never follow a symlink, never wait on a FIFO.
const (
	oNoFollow = syscall.O_NOFOLLOW
	oNonBlock = syscall.O_NONBLOCK
)
