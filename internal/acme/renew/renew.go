// Package renew decides when an ACME certificate is renewed automatically (plan 2026-10-13 design row 6, amendment
// A2: the rules of the Key Vault planner). It is pure: the caller passes every time and every value it read under the
// certificate's row lock; nothing is read or written here. inventory.PlanACMERenewals applies a Decision in the same
// transaction it read the Input in.
//
// The rules, in order:
//
//   - nothing while the licence gate refuses changes (a lock is neutral: no failure is counted and nothing is
//     written, not even a repair);
//   - nothing when automatic renewal is off, when it was stopped, or for a certificate that was never issued: the
//     FIRST order of a definition is always a person's act (the planner renews, it never issues unseen; a definition
//     created and never ordered stays pending until someone presses "Get the certificate");
//   - StopAfter (5) consecutive failures stop automatic renewal (Stop: state stopped, one audit row and one e-mail);
//     only a successful order (a person's "Renew now") makes it active again;
//   - nothing while an order runs;
//   - due at RenewAt = not_after - min(renew_before_days, lifetime/3): a 90-day certificate 30 days before its end, a
//     47-day one at two thirds of its life, a 6-day one two days before its end;
//   - ARI (RFC 9773): the CA's suggested window start is used when it is EARLIER than the local rule, never when it
//     is later. ARI can pull a renewal forward (a revocation or a mass-renewal event at the CA) but never push it past
//     the local rule, so a wrong or hostile window cannot make a certificate expire. An ARI failure is never a
//     failure of the certificate and never blocks a renewal: without a window the local rule alone decides;
//   - after failures, the next attempt waits Backoff(failures) (1 h, 2 h, 4 h, ... capped at 24 h) from the last
//     attempt, or until next_attempt_at (a CA's Retry-After) when that is later;
//   - MinSpacing (15 minutes) between two orders of one certificate, whatever ended the previous one (an interrupted
//     order counts no failure, so without the spacing a persistent interruption would order every minute);
//   - clock skew: a last attempt or a last order more than SkewTolerance in the future is ignored (the clock moved
//     back); a next_attempt_at further away than MaxBackoff is impossible unless the clock moved, and is repaired to
//     now + MaxBackoff (RepairNextAttempt) instead of waiting for it.
package renew

import "time"

// States of an ACME certificate (inventory.ACMEState*).
const (
	StatePending = "pending"
	StateIssuing = "issuing"
	StateActive  = "active"
	StateFailing = "failing"
	StateStopped = "stopped"
)

// Limits of automatic renewal.
const (
	// NotifyAfter consecutive failures send the "renewal failed" e-mail once; StopAfter stop automatic renewal.
	NotifyAfter = 3
	StopAfter   = 5
	// MinSpacing is the least time between two orders of one certificate started by the planner.
	MinSpacing = 15 * time.Minute
	// MaxBackoff caps the wait after failures, a CA's Retry-After and the ARI recheck.
	MaxBackoff = 24 * time.Hour
	// ARIRefresh is how often the renewal information of a certificate is asked for without a Retry-After;
	// MinARIRetry is the shortest Retry-After honoured.
	ARIRefresh  = 6 * time.Hour
	MinARIRetry = time.Hour
	// SkewTolerance is how far in the future a recorded time may be before it counts as clock skew.
	SkewTolerance = 5 * time.Minute
	// DefaultRenewBeforeDays is the window of a certificate whose window is not set.
	DefaultRenewBeforeDays = 30
)

// Window is the CA's suggested renewal window.
type Window struct{ Start, End time.Time }

// Input is what the planner read about one certificate, under its row lock.
type Input struct {
	Now time.Time
	// NotBefore and NotAfter of the current certificate; a zero NotAfter means none was issued yet.
	NotBefore, NotAfter time.Time
	RenewBeforeDays     int
	AutoRenew           bool
	State               string
	OrderRunning        bool
	Failures            int
	NextAttemptAt       *time.Time
	LastAttemptAt       *time.Time
	// LastOrderAt is when the newest issue order of the certificate started (any requester).
	LastOrderAt *time.Time
	// ARIWindow is the cached window of the current certificate; ARICheckedAt when it was last asked for and
	// ARINextCheckAt when it may be asked for again (the CA's Retry-After).
	ARIWindow                    *Window
	ARICheckedAt, ARINextCheckAt *time.Time
	// Locked: the licence gate refuses changes.
	Locked bool
}

// Action is what the planner does.
type Action int

// Actions.
const (
	None  Action = iota // nothing now
	Order               // start a renewal order
	Stop                // stop automatic renewal (StopAfter failures)
)

// Reasons of a Decision (logs and tests; never shown to a person).
const (
	ReasonLocked            = "locked"
	ReasonAutoRenewOff      = "auto_renew_off"
	ReasonStopped           = "stopped"
	ReasonNeverIssued       = "never_issued"
	ReasonStopAfterFailures = "stop_after_failures"
	ReasonOrderRunning      = "order_running"
	ReasonNotDue            = "not_due"
	ReasonBackoff           = "backoff"
	ReasonSpacing           = "spacing"
	ReasonDue               = "due"
	ReasonDueARI            = "due_ari"
)

// Decision is the outcome for one certificate.
type Decision struct {
	Action Action
	Reason string
	// RenewAt is when the certificate is due (the local rule, or an earlier ARI window start); zero without a
	// current certificate.
	RenewAt time.Time
	// RetryAt is the earliest attempt the failures and the spacing allow (zero: no wait).
	RetryAt time.Time
	// RefreshARI: the planner should ask the CA for the renewal window (the certificate is not due yet by the rule
	// and the cached answer is old).
	RefreshARI bool
	// RepairNextAttempt is a next_attempt_at to store instead of one beyond MaxBackoff (clock skew).
	RepairNextAttempt *time.Time
}

// Backoff is the wait after failures consecutive failed orders: 1 h, 2 h, 4 h, ... capped at MaxBackoff; no wait
// for failures < 1.
func Backoff(failures int) time.Duration {
	if failures < 1 {
		return 0
	}
	if failures > 6 { // 1 h << 5 = 32 h is over the cap already
		return MaxBackoff
	}
	return min(time.Hour<<(failures-1), MaxBackoff)
}

// RenewAt is the local rule: notAfter - min(renewBeforeDays, lifetime/3). renewBeforeDays < 1 is the default 30; a
// lifetime below zero (not_after before not_before) counts as zero.
func RenewAt(notBefore, notAfter time.Time, renewBeforeDays int) time.Time {
	if renewBeforeDays < 1 {
		renewBeforeDays = DefaultRenewBeforeDays
	}
	life := max(notAfter.Sub(notBefore), 0)
	return notAfter.Add(-min(time.Duration(renewBeforeDays)*24*time.Hour, life/3))
}

// NextARICheck is when renewal information may be asked for again after an answer (or a failure) at now with the
// CA's Retry-After (0: none): ARIRefresh without one, else the Retry-After bounded to MinARIRetry..MaxBackoff.
func NextARICheck(now time.Time, retryAfter time.Duration) time.Time {
	if retryAfter <= 0 {
		return now.Add(ARIRefresh)
	}
	return now.Add(min(max(retryAfter, MinARIRetry), MaxBackoff))
}

// Decide applies the rules of the package comment.
func Decide(in Input) Decision {
	var d Decision
	switch {
	case in.Locked:
		d.Reason = ReasonLocked
		return d
	case !in.AutoRenew:
		d.Reason = ReasonAutoRenewOff
		return d
	case in.State == StateStopped:
		d.Reason = ReasonStopped
		return d
	case in.NotAfter.IsZero():
		d.Reason = ReasonNeverIssued
		return d
	case in.Failures >= StopAfter:
		d.Action, d.Reason = Stop, ReasonStopAfterFailures
		return d
	case in.OrderRunning:
		d.Reason = ReasonOrderRunning
		return d
	}
	now := in.Now
	local := RenewAt(in.NotBefore, in.NotAfter, in.RenewBeforeDays)
	d.RenewAt, d.Reason = local, ReasonDue
	if in.ARIWindow != nil && in.ARIWindow.Start.Before(local) {
		d.RenewAt, d.Reason = in.ARIWindow.Start, ReasonDueARI
	}
	if now.Before(d.RenewAt) {
		d.Reason = ReasonNotDue
		d.RefreshARI = ariDue(in)
		return d
	}

	future := now.Add(SkewTolerance)
	if in.Failures > 0 && in.LastAttemptAt != nil && !in.LastAttemptAt.After(future) {
		d.RetryAt = in.LastAttemptAt.Add(Backoff(in.Failures))
	}
	if in.NextAttemptAt != nil {
		next := *in.NextAttemptAt
		if limit := now.Add(MaxBackoff); next.After(limit) {
			next = limit
			d.RepairNextAttempt = &limit
		}
		if next.After(d.RetryAt) {
			d.RetryAt = next
		}
	}
	reason := ReasonBackoff
	if in.LastOrderAt != nil && !in.LastOrderAt.After(future) {
		if s := in.LastOrderAt.Add(MinSpacing); s.After(d.RetryAt) {
			d.RetryAt, reason = s, ReasonSpacing
		}
	}
	if now.Before(d.RetryAt) {
		d.Reason = reason
		return d
	}
	d.Action = Order
	return d
}

// ariDue reports whether the cached renewal information is old enough to ask again.
func ariDue(in Input) bool {
	switch {
	case in.ARICheckedAt == nil:
		return true
	case in.ARINextCheckAt != nil:
		return !in.Now.Before(*in.ARINextCheckAt)
	}
	return !in.Now.Before(in.ARICheckedAt.Add(ARIRefresh))
}

// FailureState is a certificate right after a failed order was counted.
type FailureState struct {
	Failures  int
	AutoRenew bool
	// Issued: the certificate has a current certificate (a renewal failed, not a first issuance).
	Issued bool
	// Stopped: automatic renewal is stopped already; Notified: the "renewal failed" e-mail was sent since the last
	// success.
	Stopped, Notified bool
}

// FailureOutcome says what a counted failure triggers.
type FailureOutcome struct {
	// Notify: send the "renewal failed" e-mail (once per series, from NotifyAfter failures on).
	Notify bool
	// Stop: stop automatic renewal (StopAfter failures; one audit row and one e-mail).
	Stop bool
}

// AfterFailure decides the e-mail and the stop after a counted failure. Both apply only to renewals of an issued
// certificate with automatic renewal on: a person who orders a certificate for the first time sees the outcome on its
// page. The stop wins over the e-mail (its own e-mail says more).
func AfterFailure(f FailureState) FailureOutcome {
	if !f.AutoRenew || !f.Issued || f.Stopped {
		return FailureOutcome{}
	}
	if f.Failures >= StopAfter {
		return FailureOutcome{Stop: true}
	}
	return FailureOutcome{Notify: f.Failures >= NotifyAfter && !f.Notified}
}

// Neutral reports whether an order's failure code is not a failure of the certificate: the licence lock (the gate
// refused changes during the order) and an interrupted job. Such an order ends without counting a failure or
// backing off.
func Neutral(code string) bool {
	return code == "license.locked" || code == "job.lease_expired"
}
