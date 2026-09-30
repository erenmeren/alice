package license

import "time"

// Clock rules (spec §16.5, R26, L-52).
const (
	// RollbackTolerance: a wall clock this far behind the HWM raises the "clock is behind"
	// warning. License math clamps to the HWM regardless (R36 item 9).
	RollbackTolerance = 65 * time.Minute
	// JumpThreshold: the wall clock advanced this much more than uptime since the last
	// observation = a suspicious forward jump.
	JumpThreshold = 48 * time.Hour
	// JumpSettle: uptime after which a held jump is accepted.
	JumpSettle = 24 * time.Hour
)

// ClockEvent is something the guard noticed during an observation.
type ClockEvent int

// Clock events, audited and shown to administrators by Service.
const (
	EventRollback ClockEvent = iota + 1
	EventJumpDetected
	EventJumpAccepted
	EventJumpCleared
)

// Jump describes a forward jump that is being held.
type Jump struct {
	Expected time.Time     // where the clock should be: the time before the jump plus uptime since
	Detected time.Time     // the wall time when the jump was seen
	By       time.Duration // how far the wall clock is ahead of Expected
}

// Reading is the result of one observation.
type Reading struct {
	Wall      time.Time // the system clock
	Trusted   time.Time // never earlier than any time Alice has accepted
	Effective time.Time // the time license states are computed from
	Behind    bool      // the wall clock is more than RollbackTolerance behind the HWM
	Jump      *Jump     // a held forward jump; nil when none
}

type heldJump struct {
	expected   time.Time     // Expected at baseUptime
	baseUptime time.Duration // uptime when the jump was seen (or when the process restarted)
	detected   time.Time
}

// Guard turns wall-clock and uptime observations into the trusted time. It is not safe
// for concurrent use; Service serializes access.
type Guard struct {
	hwm        time.Time
	seq        uint64
	lastWall   time.Time
	lastUptime time.Duration
	observed   bool
	jump       *heldJump
}

// SetHWM loads a persisted record (at start, before RestoreJump).
func (g *Guard) SetHWM(r HWMRecord) {
	g.hwm, g.seq = r.At.UTC().Truncate(time.Second), r.Seq
}

// HWM returns the current high-water mark and sequence.
func (g *Guard) HWM() HWMRecord { return HWMRecord{At: g.hwm, Seq: g.seq} }

// NextRecord returns the record to persist next; its sequence is one higher.
func (g *Guard) NextRecord() HWMRecord {
	g.seq++
	return g.HWM()
}

// Observe records the wall clock and the uptime and returns the reading.
//
//   - Trusted = max(wall, HWM + uptime since the previous observation): a clock set back
//     never moves time back (L-51, L-58) and does not stop it either.
//   - A wall clock more than 48 h ahead of the previous trusted time plus the uptime
//     elapsed since the previous observation is a suspicious jump (R26): license math uses
//     the time before the jump plus uptime, and the HWM follows that, until 24 h of uptime
//     have passed, the clock is corrected, or AcceptJump is called (a correction license,
//     L-61). While the clock is not behind, this is the wall clock advancing 48 h more
//     than uptime; a rolled-back clock being set right again is not a jump.
//   - The first observation after a start has nothing to compare with: downtime is not a jump.
func (g *Guard) Observe(wall time.Time, uptime time.Duration) (Reading, []ClockEvent) {
	wall = wall.UTC()
	var events []ClockEvent
	var dUp time.Duration // uptime since the previous observation
	if g.observed {
		dUp = max(uptime-g.lastUptime, 0)
		// Measured from the trusted time, so setting a rolled-back clock right is not a jump.
		expected := later(g.lastWall, g.hwm).Add(dUp)
		if g.jump == nil && wall.Sub(expected) > JumpThreshold {
			g.jump = &heldJump{expected: expected, baseUptime: uptime, detected: wall}
			events = append(events, EventJumpDetected)
		}
	}
	g.lastWall, g.lastUptime, g.observed = wall, uptime, true

	r := Reading{Wall: wall}
	if g.jump != nil {
		held := uptime - g.jump.baseUptime
		if held < 0 {
			held = 0
		}
		// Never behind the HWM plus uptime: after a restart the restored expected time may
		// lag the HWM, and license time must keep moving with uptime regardless.
		expected := later(g.jump.expected.Add(held), g.hwm.Add(dUp))
		switch {
		case wall.Sub(expected) <= JumpThreshold:
			g.jump = nil
			events = append(events, EventJumpCleared)
		case held >= JumpSettle:
			g.jump = nil
			events = append(events, EventJumpAccepted)
		default:
			g.hwm = expected
			r.Trusted, r.Effective = expected, expected
			r.Jump = &Jump{Expected: expected, Detected: g.jump.detected, By: wall.Sub(expected)}
			return r, events
		}
	}
	if g.hwm.Sub(wall) > RollbackTolerance {
		r.Behind = true
		events = append(events, EventRollback)
	}
	// While the wall clock is behind, the HWM advances with uptime, so time never stands
	// still for a customer who set the clock back (only downtime is not counted).
	// The HWM keeps full precision in memory (rounding at every observation would slow
	// time down); Encode stores whole seconds.
	trusted := later(wall, g.hwm.Add(dUp))
	g.hwm = trusted
	r.Trusted, r.Effective = trusted, trusted
	return r, events
}

// AcceptJump accepts a held jump at once. It reports whether one was held.
func (g *Guard) AcceptJump() bool {
	held := g.jump != nil
	g.jump = nil
	return held
}

// RestoreJump re-establishes a held jump after a restart. The 24 hours restart from
// uptime, which favours the customer (downtime is not counted). Call SetHWM first:
// expected is raised to the HWM, so the held time continues from where it stopped.
func (g *Guard) RestoreJump(expected, detected time.Time, uptime time.Duration) {
	g.jump = &heldJump{expected: later(expected.UTC(), g.hwm), baseUptime: uptime, detected: detected.UTC()}
}

// PendingJump returns the held jump's expected and detected times.
func (g *Guard) PendingJump() (expected, detected time.Time, ok bool) {
	if g.jump == nil {
		return time.Time{}, time.Time{}, false
	}
	return g.jump.expected, g.jump.detected, true
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
