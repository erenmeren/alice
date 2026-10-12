//go:build linux

package clock

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootTime reads CLOCK_BOOTTIME: monotonic, not settable, and unlike CLOCK_MONOTONIC (Go's monotonic reading) it
// keeps counting while the system or virtual machine is suspended.
func bootTime() (time.Duration, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, false
	}
	return time.Duration(ts.Nano()), true
}
