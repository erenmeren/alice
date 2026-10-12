package clock

import "time"

// SetBootClock replaces the boot-time source of Real.Elapsed (counting suspended time) and restarts its uptime at
// the source's current reading. The returned function restores the production source.
func SetBootClock(now func() (time.Duration, bool)) (restore func()) {
	oldNow, oldStart, oldOK, oldProc := bootNow, bootStart, bootOK, processStart
	bootNow = now
	bootStart, bootOK = now()
	processStart = time.Now()
	lastElapsed.Store(0)
	return func() {
		bootNow, bootStart, bootOK, processStart = oldNow, oldStart, oldOK, oldProc
		lastElapsed.Store(0)
	}
}

// BootTime is the production boot-time source.
var BootTime = bootTime
