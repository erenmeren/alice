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
//   - every failure has a class (owner decision 2026-10-20, docs/superpowers/rulings/acme-renewal-recovery.md):
//     transient (an outage that clears by itself: the CA, its lookups or the DNS hook unreachable or timing out, a rate
//     limit, a server error) or permanent (a setting, the account, a refused name, a wrong challenge answer: it needs a
//     person). StopAfter (5) PERMANENT failures of a series stop automatic renewal (Stop: state stopped, one audit row
//     and one e-mail); transient failures never stop it while the certificate is valid, and once it has expired
//     StopAfter failures of any class do (ShouldStop). A successful order, a person's "Check again and resume" (re-arm)
//     or switching automatic renewal on again starts a new series;
//   - a certificate stopped while its LAST failure was transient (a series that stopped before the classes existed,
//     or a person's order of a stopped certificate that failed in an outage) is ordered again by itself at the same
//     slow cadence (ReasonRecovery) until it has expired; a permanent stop waits for a person;
//   - nothing while an order runs;
//   - due at RenewAt = not_after - min(renew_before_days, lifetime/3): a 90-day certificate 30 days before its end, a
//     47-day one at two thirds of its life, a 6-day one two days before its end;
//   - ARI (RFC 9773): the CA's suggested window start is used when it is EARLIER than the local rule, never when it
//     is later. ARI can pull a renewal forward (a revocation or a mass-renewal event at the CA) but never push it past
//     the local rule, so a wrong or hostile window cannot make a certificate expire; a window that ends at or before
//     the current certificate's not_before is not about it and is ignored (no renewal loop). An ARI failure is never a
//     failure of the certificate and never blocks a renewal: without a window the local rule alone decides;
//   - after failures, the next attempt waits RetryWait from the last attempt: Backoff(failures) (1 h, 2 h, 4 h, ...
//     capped at 24 h), and after a transient failure never longer than RecoveryInterval of the time the certificate
//     had left (24 h, 12 h within 7 days of its end, 6 h within 3 days, 2 h within the last day); or until
//     next_attempt_at (a CA's Retry-After) when that is later;
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

// Classes of a failure (acme.ClassTransient, acme.ClassPermanent; "" before the first failure).
const (
	ClassTransient = "transient"
	ClassPermanent = "permanent"
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

// ExpiryNoticeDays are the days before the current certificate's end at which a certificate whose renewal fails (or
// stopped) gets the "expires soon, renewal failing" e-mail again, once per threshold and certificate.
func ExpiryNoticeDays() []int { return []int{14, 7, 3, 1} }

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
	// PermanentFailures counts the permanent failures of the series; LastFailureClass is the class of the last one.
	PermanentFailures int
	LastFailureClass  string
	NextAttemptAt     *time.Time
	LastAttemptAt     *time.Time
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
	ReasonRecovery          = "recovery"
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

// RecoveryInterval is the longest wait after a transient failure when left is the time the certificate had left: 24 h,
// 12 h within 7 days of its end, 6 h within 3 days, 2 h within the last day (and after it).
func RecoveryInterval(left time.Duration) time.Duration {
	const day = 24 * time.Hour
	switch {
	case left > 7*day:
		return MaxBackoff
	case left > 3*day:
		return 12 * time.Hour
	case left > day:
		return 6 * time.Hour
	}
	return 2 * time.Hour
}

// RetryWait is the wait after failures consecutive failed orders whose last one was of class, when the certificate had
// left before its end: Backoff(failures), never longer than RecoveryInterval(left) after a transient failure.
func RetryWait(failures int, class string, left time.Duration) time.Duration {
	w := Backoff(failures)
	if class == ClassTransient {
		w = min(w, RecoveryInterval(left))
	}
	return w
}

// ShouldStop reports whether a series of failures (permanent of them permanent) stops automatic renewal: StopAfter
// permanent failures, or, once the certificate has expired, StopAfter failures of any class.
func ShouldStop(failures, permanent int, expired bool) bool {
	return permanent >= StopAfter || (expired && failures >= StopAfter)
}

// ClassOfCode is the class of a failure known only by its code (a caller without the error, a row from before the
// classes): the codes of outages are transient, every other code permanent.
func ClassOfCode(code string) string {
	switch code {
	case "acme.ca_rate_limited", "acme.provider_unreachable", "acme.not_issued_in_time", "acme.order_abandoned", "acme.rollover_pending":
		return ClassTransient
	}
	return ClassPermanent
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
	now := in.Now
	expired := !in.NotAfter.IsZero() && !now.Before(in.NotAfter)
	recovering := false
	switch {
	case in.Locked:
		d.Reason = ReasonLocked
		return d
	case !in.AutoRenew:
		d.Reason = ReasonAutoRenewOff
		return d
	case in.State == StateStopped:
		if in.NotAfter.IsZero() || expired || in.LastFailureClass != ClassTransient {
			d.Reason = ReasonStopped
			return d
		}
		recovering = true
	case in.NotAfter.IsZero():
		d.Reason = ReasonNeverIssued
		return d
	case ShouldStop(in.Failures, in.PermanentFailures, expired):
		d.Action, d.Reason = Stop, ReasonStopAfterFailures
		return d
	}
	if in.OrderRunning {
		d.Reason = ReasonOrderRunning
		return d
	}
	local := RenewAt(in.NotBefore, in.NotAfter, in.RenewBeforeDays)
	d.RenewAt, d.Reason = local, ReasonDue
	// A window that ends at or before the current certificate's start cannot be about it (a buggy or hostile CA):
	// ignored, or every new certificate would be due at once.
	if in.ARIWindow != nil && in.ARIWindow.Start.Before(local) && in.ARIWindow.End.After(in.NotBefore) {
		d.RenewAt, d.Reason = in.ARIWindow.Start, ReasonDueARI
	}
	if now.Before(d.RenewAt) {
		d.Reason = ReasonNotDue
		d.RefreshARI = ariDue(in)
		return d
	}

	future := now.Add(SkewTolerance)
	if in.Failures > 0 && in.LastAttemptAt != nil && !in.LastAttemptAt.After(future) {
		d.RetryAt = in.LastAttemptAt.Add(RetryWait(in.Failures, in.LastFailureClass, in.NotAfter.Sub(*in.LastAttemptAt)))
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
	if recovering {
		d.Reason = ReasonRecovery
	}
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
	// Failures and PermanentFailures of the series, the counted one included.
	Failures, PermanentFailures int
	AutoRenew                   bool
	// Expired: the current certificate has ended.
	Expired bool
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
	// Stop: stop automatic renewal (ShouldStop; one audit row and one e-mail).
	Stop bool
}

// AfterFailure decides the e-mail and the stop after a counted failure. Both apply only to renewals of an issued
// certificate with automatic renewal on: a person who orders a certificate for the first time sees the outcome on its
// page. The stop wins over the e-mail (its own e-mail says more).
func AfterFailure(f FailureState) FailureOutcome {
	if !f.AutoRenew || !f.Issued || f.Stopped {
		return FailureOutcome{}
	}
	if ShouldStop(f.Failures, f.PermanentFailures, f.Expired) {
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
