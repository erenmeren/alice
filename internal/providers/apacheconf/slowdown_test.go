package apacheconf

import (
	"testing"
	"time"
)

// slowdown scales the time limits of the hostile-size tests: the race detector (raceSlowdown) and
// the atomic coverage instrumentation that `make coverage` adds to it (about five times more) slow
// the lexer and the parser down by a constant factor, never by a worse complexity class.
func slowdown() time.Duration {
	if testing.CoverMode() != "" {
		return raceSlowdown * 5
	}
	return raceSlowdown
}
