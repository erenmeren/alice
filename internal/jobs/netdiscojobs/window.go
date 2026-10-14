package netdiscojobs

// When a scope's schedule wants a scan (design decision 1: every N hours, optionally only inside a daily window in an
// IANA time zone). The rule, including daylight saving time:
//
//   - Without a window the interval is real time: a scan is due when the last scheduled one was queued at least Hours
//     hours ago (or never). DST does not matter.
//   - A window [start, end) is a local time of day; it may cross midnight. The window of local day D opens at D's start
//     time and closes at its end time on its closing day (D, or D+1 when it crosses midnight), as an administrator
//     reads the clock, but never later than its usual length (end - start on the clock) after it opened. A time that
//     does not exist (the hour skipped when clocks spring forward) is the jump, the first instant after the gap; a
//     time that exists twice (the hour repeated when clocks fall back) is its first occurrence. So on a
//     spring-forward day a window across the jump is an hour shorter (01:00-03:00 closes at 03:00 EDT), on a
//     fall-back day a window across the repeated hour keeps its usual length and closes before its local end comes
//     round a second time, and a window lying wholly inside the skipped hour (its end is not after its opening) opens
//     at the jump for its usual length. Every local day has exactly one window: no day is skipped, and the repeated
//     hour does not open a second window.
//   - Inside a window the scans are slotted: the window's opening, then every Hours hours while the window lasts. A
//     scan is due when no scheduled scan was queued since the current slot began (a scope that was busy at the slot
//     catches up later in the same slot; never outside the window).
//   - An interval of 24 hours or more with a window counts windows, not hours: a scan is due in the window of local day
//     D when the last scheduled scan was queued before this window opened and at least ceil(Hours/24) local days before
//     D (the local day of the window it was queued in, or its own local day when it was queued outside any window).
//     A 23- or 25-hour day therefore neither skips nor doubles a daily scan.
//   - A last scan in the future (the clock was set back) counts as never.

import (
	"fmt"
	"slices"
	"time"

	"alice/internal/discovery"
)

const day = 24 * time.Hour

// Due reports whether a scope with schedule s wants a scan at now, given when its schedule last queued one (zero:
// never). An invalid schedule (zone, window) is discovery.ErrSchedule.
func Due(s discovery.Schedule, last, now time.Time) (bool, error) {
	if s.Hours <= 0 {
		return false, nil
	}
	if last.After(now) {
		last = time.Time{}
	}
	every := time.Duration(s.Hours) * time.Hour
	if s.WindowStart == "" && s.WindowEnd == "" {
		return last.IsZero() || now.Sub(last) >= every, nil
	}
	w, err := parseWindow(s)
	if err != nil {
		return false, err
	}
	open, d, ok := w.containing(now)
	if !ok {
		return false, nil
	}
	if last.IsZero() {
		return true, nil
	}
	if every >= day {
		if !last.Before(open) {
			return false, nil
		}
		lastDay := w.dayOf(last)
		need := (s.Hours + 23) / 24
		return daysBetween(lastDay, d) >= need, nil
	}
	slot := open.Add(now.Sub(open) / every * every)
	return last.Before(slot), nil
}

// civil is a calendar date.
type civil struct {
	y int
	m time.Month
	d int
}

func dateOf(t time.Time) civil {
	y, m, d := t.Date()
	return civil{y, m, d}
}

func (c civil) add(days int) civil {
	return dateOf(time.Date(c.y, c.m, c.d+days, 12, 0, 0, 0, time.UTC))
}

func daysBetween(a, b civil) int {
	return int(time.Date(b.y, b.m, b.d, 0, 0, 0, 0, time.UTC).Sub(time.Date(a.y, a.m, a.d, 0, 0, 0, 0, time.UTC)) / day)
}

// window is a parsed daily window: its start in minutes after local midnight, its usual length and its zone.
type window struct {
	start  int
	end    int
	length time.Duration
	loc    *time.Location
}

func parseWindow(s discovery.Schedule) (window, error) {
	zone := s.TimeZone
	if zone == "" {
		zone = "UTC"
	}
	loc, err := time.LoadLocation(zone)
	if err != nil || zone == "Local" {
		return window{}, fmt.Errorf("%w: time zone", discovery.ErrSchedule)
	}
	start, ok1 := discovery.ParseTimeOfDay(s.WindowStart)
	end, ok2 := discovery.ParseTimeOfDay(s.WindowEnd)
	if !ok1 || !ok2 || start == end {
		return window{}, fmt.Errorf("%w: window", discovery.ErrSchedule)
	}
	return window{start: start, end: end, length: time.Duration((end-start+24*60)%(24*60)) * time.Minute, loc: loc}, nil
}

// opening is when the window of local day c opens (see the rule above).
func (w window) opening(c civil) time.Time { return w.resolve(c, w.start) }

// closing is when the window of local day c that opened at open closes: at its local end time on its closing day
// (resolved like the opening), at most its usual length after it opened; a window the jump skipped entirely (its local
// end is not after its opening) lasts its usual length from the jump.
func (w window) closing(c civil, open time.Time) time.Time {
	usual := open.Add(w.length)
	day := c
	if w.end < w.start {
		day = c.add(1)
	}
	end := w.resolve(day, w.end)
	if !end.After(open) || end.After(usual) {
		return usual
	}
	return end
}

// resolve is the instant of local day c at minutes after midnight: a time that exists twice is its first occurrence, a
// time that does not exist (clocks jumped over it) is the jump.
func (w window) resolve(c civil, minutes int) time.Time {
	wall := time.Date(c.y, c.m, c.d, 0, 0, 0, 0, time.UTC).Add(time.Duration(minutes) * time.Minute)
	// The instant is wall minus the zone's offset at that instant; the offsets in force within a day around it are the
	// candidates (a zone changes its offset at most once in that span).
	var valid, after []time.Time
	seen := map[int]bool{}
	for h := -26; h <= 26; h += 2 {
		_, off := wall.Add(time.Duration(h) * time.Hour).In(w.loc).Zone()
		if seen[off] {
			continue
		}
		seen[off] = true
		t := wall.Add(-time.Duration(off) * time.Second)
		local := t.In(w.loc)
		switch lw := time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), local.Minute(), local.Second(), 0, time.UTC); {
		case lw.Equal(wall):
			valid = append(valid, t)
		case lw.After(wall):
			after = append(after, t)
		}
	}
	if len(valid) > 0 {
		return slices.MinFunc(valid, time.Time.Compare) // a repeated time: its first occurrence
	}
	// The time does not exist (clocks jumped over it): the candidate read with the offset before the jump lands past
	// the gap, and the window opens at the jump, where that instant's zone period begins.
	if len(after) == 0 {
		return wall // no zone does this; the wall time read as UTC rather than a panic
	}
	past := slices.MinFunc(after, time.Time.Compare)
	start, _ := past.In(w.loc).ZoneBounds()
	return start
}

// containing returns the opening and the local day of the window that now is in (the later one when two overlap).
func (w window) containing(now time.Time) (time.Time, civil, bool) {
	today := dateOf(now.In(w.loc))
	for _, c := range []civil{today, today.add(-1)} {
		open := w.opening(c)
		if !now.Before(open) && now.Before(w.closing(c, open)) {
			return open, c, true
		}
	}
	return time.Time{}, civil{}, false
}

// dayOf is the local day of the window t is in, or t's own local day outside any window.
func (w window) dayOf(t time.Time) civil {
	if _, c, ok := w.containing(t); ok {
		return c
	}
	return dateOf(t.In(w.loc))
}
