//go:build !linux

package clock

import "time"

// bootTime has no source outside Linux: Real.Elapsed uses Go's monotonic clock.
func bootTime() (time.Duration, bool) { return 0, false }
