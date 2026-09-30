package license

import (
	"time"
)

// Phase is the license state (spec §7.6, R25, R1).
type Phase string

// Phases. The evaluation has no grace period: it ends directly in PhaseEvaluationExpired,
// which behaves as lock.
const (
	PhaseEvaluation        Phase = "evaluation"
	PhaseEvaluationExpired Phase = "evaluation_expired"
	PhaseActive            Phase = "active"
	PhaseGrace             Phase = "grace"
	PhaseLocked            Phase = "locked"
)

// Rules of spec §16.3 step 6, §19.3, R1, R25, R27.
const (
	EvaluationPeriod     = 30 * 24 * time.Hour
	EvaluationMaxTargets = 5
	GracePeriod          = 168 * time.Hour
	day                  = 24 * time.Hour
)

// Warning thresholds in days before the end, largest first.
var (
	ExpiryWarningDays     = []int{60, 30, 14, 7, 1}
	EvaluationWarningDays = []int{7, 3, 1}
)

// Installed is a stored license file that verified: its upload order and payload.
type Installed struct {
	Seq     int64
	KeyID   string
	Payload Payload
}

// Evaluation is the license state at one instant.
type Evaluation struct {
	Phase      Phase
	Current    *Payload  // the license in force; nil during the evaluation
	Pending    *Payload  // the newest uploaded license whose valid_from is still ahead (L-48)
	CurrentSeq int64     // upload sequence number of Current; 0 = none
	PendingSeq int64     // upload sequence number of Pending; 0 = none
	EndsAt     time.Time // end of the evaluation, or valid_until
	LocksAt    time.Time // start of lock: EndsAt for the evaluation, valid_until + 168 h otherwise
	DaysLeft   int       // whole days until EndsAt, rounded up; 0 once EndsAt is reached
	Threshold  int       // warning threshold reached (60/30/14/7/1, evaluation 7/3/1); 0 = none
	GraceDay   int       // 1..7 during grace: the n-th 24-hour period after valid_until (L-22)
	MaxTargets int       // 5 during the evaluation, otherwise max_targets of Current
}

// Evaluate computes the license state at now (the trusted, effective time) from the
// installation timestamp and the verified uploads. The rule is independent of upload order
// except for ties:
//  1. started = uploads with valid_from <= now.
//  2. superseded = license IDs named in Replaces by any started upload (direct, not transitive).
//  3. candidates = started uploads that are not superseded.
//  4. If any candidate is still valid (now < valid_until), the one with the latest valid_from
//     is in force (tie: higher Seq), even when it is shorter.
//  5. Otherwise the candidate with the latest valid_until is in force (tie: higher Seq); it is
//     in grace or locked. With no candidate the evaluation applies.
//  6. Pending = the highest-Seq upload with valid_from > now that is not superseded.
func Evaluate(now, installedAt time.Time, installed []Installed) Evaluation {
	now = now.UTC()
	superseded := map[string]bool{} // license IDs named in Replaces by a started upload
	for _, in := range installed {
		if !in.Payload.ValidFrom.After(now) && in.Payload.Replaces != "" {
			superseded[in.Payload.Replaces] = true
		}
	}
	var current, pending *Payload
	var currentSeq, pendingSeq int64
	var currentActive bool
	for i := range installed {
		in := installed[i]
		p := in.Payload
		if superseded[p.LicenseID] {
			continue
		}
		if p.ValidFrom.After(now) {
			if in.Seq > pendingSeq {
				pending, pendingSeq = &p, in.Seq
			}
			continue
		}
		active := now.Before(p.ValidUntil)
		var better bool
		switch {
		case current == nil:
			better = true
		case active != currentActive:
			better = active
		case active:
			better = laterThen(p.ValidFrom, current.ValidFrom, in.Seq, currentSeq)
		default:
			better = laterThen(p.ValidUntil, current.ValidUntil, in.Seq, currentSeq)
		}
		if better {
			current, currentSeq, currentActive = &p, in.Seq, active
		}
	}

	if current == nil {
		end := installedAt.UTC().Add(EvaluationPeriod)
		e := Evaluation{Pending: pending, PendingSeq: pendingSeq, EndsAt: end, LocksAt: end, MaxTargets: EvaluationMaxTargets}
		if now.Before(end) {
			e.Phase = PhaseEvaluation
			e.DaysLeft = daysLeft(end.Sub(now))
			e.Threshold = threshold(end.Sub(now), EvaluationWarningDays)
		} else {
			e.Phase = PhaseEvaluationExpired
		}
		return e
	}

	e := Evaluation{
		Current:    current,
		Pending:    pending,
		CurrentSeq: currentSeq,
		PendingSeq: pendingSeq,
		EndsAt:     current.ValidUntil,
		LocksAt:    current.ValidUntil.Add(GracePeriod),
		MaxTargets: current.MaxTargets,
	}
	switch {
	case now.Before(current.ValidUntil):
		e.Phase = PhaseActive
		e.DaysLeft = daysLeft(current.ValidUntil.Sub(now))
		e.Threshold = threshold(current.ValidUntil.Sub(now), ExpiryWarningDays)
	case now.Before(e.LocksAt):
		e.Phase = PhaseGrace
		e.GraceDay = int(now.Sub(current.ValidUntil)/day) + 1
	default:
		e.Phase = PhaseLocked
	}
	return e
}

// daysLeft rounds a positive duration up to whole days.
func daysLeft(remaining time.Duration) int {
	if remaining <= 0 {
		return 0
	}
	return int((remaining + day - 1) / day)
}

// threshold returns the smallest warning threshold (in days) that remaining has reached.
func threshold(remaining time.Duration, days []int) int {
	t := 0
	for _, d := range days {
		if remaining <= time.Duration(d)*day {
			t = d
		}
	}
	return t
}

// Locked reports lock behaviour: locked, or the evaluation has ended (R1).
func (e Evaluation) Locked() bool { return e.Phase == PhaseLocked || e.Phase == PhaseEvaluationExpired }

// Expired reports whether the license or evaluation has ended (grace included).
func (e Evaluation) Expired() bool { return e.Phase != PhaseEvaluation && e.Phase != PhaseActive }

// Key identifies the license in force for notice de-duplication: "evaluation" or its license ID.
// A renewal therefore restarts the warnings (L-17).
func (e Evaluation) Key() string {
	if e.Current == nil {
		return "evaluation"
	}
	return e.Current.LicenseID
}

// CanAdd reports whether one more target may be added (L-70, L-71; never while locked).
func (e Evaluation) CanAdd(targets int) bool { return !e.Locked() && targets < e.MaxTargets }

// OverLimit reports more targets than licensed, for example after a smaller renewal (R30).
func (e Evaluation) OverLimit(targets int) bool { return targets > e.MaxTargets }

// laterThen reports whether (t, seq) sorts after (ot, oseq): later time, then higher Seq.
func laterThen(t, ot time.Time, seq, oseq int64) bool {
	return t.After(ot) || (t.Equal(ot) && seq > oseq)
}
