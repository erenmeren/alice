package renew

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const day = 24 * time.Hour

var t0 = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

func at(d time.Duration) *time.Time { t := t0.Add(d); return &t }

// issued is an active certificate valid from nb to nb+life, auto renewal on, 30-day window.
func issued(nb time.Time, life time.Duration) Input {
	return Input{Now: t0, NotBefore: nb, NotAfter: nb.Add(life), RenewBeforeDays: 30, AutoRenew: true, State: StateActive}
}

func TestRenewAtClampsToALifetimeThird(t *testing.T) {
	for _, tc := range []struct {
		name   string
		life   time.Duration
		before int
		want   time.Duration // before not_after
	}{
		{"90-day certificate, 30-day window", 90 * day, 30, 30 * day},
		{"90-day certificate, 14-day window", 90 * day, 14, 14 * day},
		{"90-day certificate, 60-day window clamps to 30", 90 * day, 60, 30 * day},
		{"47-day certificate: a third", 47 * day, 30, 47 * day / 3},
		{"47-day certificate, 7-day window", 47 * day, 7, 7 * day},
		{"6-day certificate: two days", 6 * day, 30, 2 * day},
		{"6-day certificate, 1-day window", 6 * day, 1, day},
		{"window 0 is the default 30", 90 * day, 0, 30 * day},
		{"negative window is the default", 90 * day, -3, 30 * day},
		{"one-hour certificate", time.Hour, 1, 20 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nb := t0
			assert.Equal(t, nb.Add(tc.life).Add(-tc.want), RenewAt(nb, nb.Add(tc.life), tc.before))
		})
	}
	// A certificate whose not_after is before its not_before (garbage): due at not_after, never later.
	assert.Equal(t, t0, RenewAt(t0.Add(day), t0, 30))
}

func TestBackoff(t *testing.T) {
	for f, want := range map[int]time.Duration{-1: 0, 0: 0, 1: time.Hour, 2: 2 * time.Hour, 3: 4 * time.Hour, 4: 8 * time.Hour,
		5: 16 * time.Hour, 6: 24 * time.Hour, 7: 24 * time.Hour, 60: 24 * time.Hour, 1 << 30: 24 * time.Hour} {
		assert.Equal(t, want, Backoff(f), "failures %d", f)
	}
}

func TestDecide(t *testing.T) {
	nb90 := t0.Add(-61 * day) // a 90-day certificate due 1 day ago (renewAt = nb + 60 d)
	for _, tc := range []struct {
		name   string
		in     Input
		action Action
		reason string
		retry  *time.Time
	}{
		{"locked: nothing", func() Input { i := issued(nb90, 90*day); i.Locked = true; return i }(), None, ReasonLocked, nil},
		{"auto renewal off", func() Input { i := issued(nb90, 90*day); i.AutoRenew = false; return i }(), None, ReasonAutoRenewOff, nil},
		{"stopped", func() Input { i := issued(nb90, 90*day); i.State = StateStopped; i.Failures = 5; return i }(), None, ReasonStopped, nil},
		{"stopped, never issued, transient", Input{Now: t0, RenewBeforeDays: 30, AutoRenew: true, State: StateStopped, Failures: 5,
			LastFailureClass: ClassTransient}, None, ReasonStopped, nil},
		{"never issued: the first order is a person's", Input{Now: t0, RenewBeforeDays: 30, AutoRenew: true, State: StatePending}, None,
			ReasonNeverIssued, nil},
		{"never issued, failing", Input{Now: t0, RenewBeforeDays: 30, AutoRenew: true, State: StateFailing, Failures: 9}, None,
			ReasonNeverIssued, nil},
		{"five permanent failures stop", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.PermanentFailures, i.LastFailureClass, i.State = 5, 5, ClassPermanent, StateFailing
			return i
		}(), Stop, ReasonStopAfterFailures, nil},
		{"seven failures, five of them permanent, stop (the last one transient)", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.PermanentFailures, i.LastFailureClass, i.State = 7, 5, ClassTransient, StateFailing
			return i
		}(), Stop, ReasonStopAfterFailures, nil},
		{"five transient failures do not stop: the backoff paces", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.LastFailureClass, i.State, i.LastAttemptAt = 5, ClassTransient, StateFailing, at(-time.Hour)
			return i
		}(), None, ReasonBackoff, at(15 * time.Hour)},
		{"twenty transient failures, four permanent: no stop, the daily retry", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.PermanentFailures, i.LastFailureClass, i.State, i.LastAttemptAt = 20, 4, ClassTransient, StateFailing, at(-25*time.Hour)
			return i
		}(), Order, ReasonDue, nil},
		{"expired: five failures of any class stop", func() Input {
			i := issued(t0.Add(-100*day), 90*day)
			i.Failures, i.LastFailureClass, i.State = 5, ClassTransient, StateFailing
			return i
		}(), Stop, ReasonStopAfterFailures, nil},
		{"expired: four transient failures still order", func() Input {
			i := issued(t0.Add(-100*day), 90*day)
			i.Failures, i.LastFailureClass, i.State, i.LastAttemptAt = 4, ClassTransient, StateFailing, at(-9*time.Hour)
			return i
		}(), Order, ReasonDue, nil},
		{"stopped after a transient failure: recovery once the wait passed", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.PermanentFailures, i.LastFailureClass, i.State, i.LastAttemptAt = 6, 5, ClassTransient, StateStopped, at(-25*time.Hour)
			return i
		}(), Order, ReasonRecovery, nil},
		{"stopped after a transient failure: waits for the slow cadence", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.LastFailureClass, i.State, i.LastAttemptAt = 9, ClassTransient, StateStopped, at(-time.Hour)
			return i
		}(), None, ReasonBackoff, at(23 * time.Hour)},
		{"stopped after a transient failure, expired: stays stopped", func() Input {
			i := issued(t0.Add(-100*day), 90*day)
			i.Failures, i.LastFailureClass, i.State, i.LastAttemptAt = 9, ClassTransient, StateStopped, at(-48*time.Hour)
			return i
		}(), None, ReasonStopped, nil},
		{"stopped after a permanent failure: stays stopped", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.PermanentFailures, i.LastFailureClass, i.State, i.LastAttemptAt = 5, 5, ClassPermanent, StateStopped, at(-48*time.Hour)
			return i
		}(), None, ReasonStopped, nil},
		{"stopped in recovery while an order runs", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.LastFailureClass, i.State, i.OrderRunning = 9, ClassTransient, StateStopped, true
			return i
		}(), None, ReasonOrderRunning, nil},
		{"transient failures near the expiry: the retry comes sooner", func() Input {
			i := issued(t0.Add(-88*day), 90*day) // 2 days left
			i.Failures, i.LastFailureClass, i.State, i.LastAttemptAt = 8, ClassTransient, StateFailing, at(-7*time.Hour)
			return i
		}(), Order, ReasonDue, nil},
		{"permanent failures near the expiry: the ordinary backoff", func() Input {
			i := issued(t0.Add(-88*day), 90*day)
			i.Failures, i.PermanentFailures, i.LastFailureClass, i.State, i.LastAttemptAt = 4, 4, ClassPermanent, StateFailing, at(-7*time.Hour)
			return i
		}(), None, ReasonBackoff, at(time.Hour)},
		{"an order runs", func() Input { i := issued(nb90, 90*day); i.OrderRunning = true; return i }(), None, ReasonOrderRunning, nil},
		{"due by the local rule", issued(nb90, 90*day), Order, ReasonDue, nil},
		{"not due yet", issued(t0.Add(-59*day), 90*day), None, ReasonNotDue, nil},
		{"a revoked current certificate is due at once", func() Input { i := issued(t0.Add(-day), 90*day); i.Revoked = true; return i }(),
			Order, ReasonDueRevoked, nil},
		{"a revoked current certificate keeps the spacing", func() Input {
			i := issued(t0.Add(-day), 90*day)
			i.Revoked, i.LastOrderAt = true, at(-time.Minute)
			return i
		}(), None, ReasonSpacing, at(14 * time.Minute)},
		{"a revoked current certificate is not ordered with automatic renewal off", func() Input {
			i := issued(t0.Add(-day), 90*day)
			i.Revoked, i.AutoRenew = true, false
			return i
		}(), None, ReasonAutoRenewOff, nil},
		{"exactly at the renewal time", issued(t0.Add(-60*day), 90*day), Order, ReasonDue, nil},
		{"one second before", issued(t0.Add(-60*day).Add(time.Second), 90*day), None, ReasonNotDue, nil},
		{"6-day certificate on day 4", issued(t0.Add(-4*day), 6*day), Order, ReasonDue, nil},
		{"6-day certificate on day 3", issued(t0.Add(-3*day), 6*day), None, ReasonNotDue, nil},
		{"47-day certificate on day 32", issued(t0.Add(-32*day), 47*day), Order, ReasonDue, nil},
		{"47-day certificate on day 31", issued(t0.Add(-31*day), 47*day), None, ReasonNotDue, nil},
		{"expired certificate is due", issued(t0.Add(-100*day), 90*day), Order, ReasonDue, nil},
		{"ARI pulls the renewal earlier", func() Input {
			i := issued(t0.Add(-10*day), 90*day)
			i.ARIWindow = &Window{Start: t0.Add(-time.Hour), End: t0.Add(day)}
			return i
		}(), Order, ReasonDueARI, nil},
		{"ARI window later than the local rule is ignored", func() Input {
			i := issued(nb90, 90*day)
			i.ARIWindow = &Window{Start: t0.Add(10 * day), End: t0.Add(12 * day)}
			return i
		}(), Order, ReasonDue, nil},
		{"ARI window ending before the certificate began is ignored", func() Input {
			i := issued(t0.Add(-10*day), 90*day)
			i.ARIWindow = &Window{Start: t0.Add(-30 * day), End: t0.Add(-10 * day)}
			return i
		}(), None, ReasonNotDue, nil},
		{"ARI window ending exactly at not_before is ignored", func() Input {
			i := issued(t0.Add(-10*day), 90*day)
			i.ARIWindow = &Window{Start: t0.Add(-11 * day), End: t0.Add(-10 * day)}
			return i
		}(), None, ReasonNotDue, nil},
		{"ARI window of year 1 is ignored", func() Input {
			i := issued(t0.Add(-10*day), 90*day)
			i.ARIWindow = &Window{Start: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(1, 1, 2, 0, 0, 0, 0, time.UTC)}
			return i
		}(), None, ReasonNotDue, nil},
		{"ARI window that began before the certificate and ends after its start counts", func() Input {
			i := issued(t0.Add(-10*day), 90*day)
			i.ARIWindow = &Window{Start: t0.Add(-11 * day), End: t0.Add(-9 * day)}
			return i
		}(), Order, ReasonDueARI, nil},
		{"ARI window in the future: not due", func() Input {
			i := issued(t0.Add(-10*day), 90*day)
			i.ARIWindow = &Window{Start: t0.Add(time.Hour), End: t0.Add(day)}
			return i
		}(), None, ReasonNotDue, nil},
		{"one failure: an hour from the last attempt", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.LastAttemptAt, i.NextAttemptAt = 1, StateFailing, at(-30*time.Minute), at(30*time.Minute)
			return i
		}(), None, ReasonBackoff, at(30 * time.Minute)},
		{"one failure, an hour passed", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.LastAttemptAt, i.NextAttemptAt = 1, StateFailing, at(-61*time.Minute), at(-time.Minute)
			return i
		}(), Order, ReasonDue, nil},
		{"backoff from the last attempt without next_attempt_at", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.LastAttemptAt = 3, StateFailing, at(-3*time.Hour)
			return i
		}(), None, ReasonBackoff, at(time.Hour)},
		{"next_attempt_at later than the backoff wins (Retry-After)", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.LastAttemptAt, i.NextAttemptAt = 1, StateFailing, at(-2*time.Hour), at(5*time.Hour)
			return i
		}(), None, ReasonBackoff, at(5 * time.Hour)},
		{"backoff later than next_attempt_at wins", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.LastAttemptAt, i.NextAttemptAt = 4, StateFailing, at(-time.Hour), at(-30*time.Minute)
			return i
		}(), None, ReasonBackoff, at(7 * time.Hour)},
		{"capped at 24 hours", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.LastAttemptAt = 4, StateFailing, at(-25*time.Hour)
			return i
		}(), Order, ReasonDue, nil},
		{"a test run's Retry-After with no failures", func() Input {
			i := issued(nb90, 90*day)
			i.NextAttemptAt = at(2 * time.Hour)
			return i
		}(), None, ReasonBackoff, at(2 * time.Hour)},
		{"NULL next_attempt_at with a current certificate: from not_after", issued(nb90, 90*day), Order, ReasonDue, nil},
		{"spacing: an order started 10 minutes ago", func() Input {
			i := issued(nb90, 90*day)
			i.LastOrderAt = at(-10 * time.Minute)
			return i
		}(), None, ReasonSpacing, at(5 * time.Minute)},
		{"spacing: 15 minutes passed", func() Input {
			i := issued(nb90, 90*day)
			i.LastOrderAt = at(-15 * time.Minute)
			return i
		}(), Order, ReasonDue, nil},
		{"spacing later than the backoff", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.LastAttemptAt, i.LastOrderAt = 1, StateFailing, at(-2*time.Hour), at(-time.Minute)
			return i
		}(), None, ReasonSpacing, at(14 * time.Minute)},
		{"clock skew: not yet valid here, not due", issued(t0.Add(time.Hour), 90*day), None, ReasonNotDue, nil},
		{"clock skew: a last attempt in the future is ignored", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.LastAttemptAt = 2, StateFailing, at(48*time.Hour)
			return i
		}(), Order, ReasonDue, nil},
		{"clock skew: a last order in the future is ignored", func() Input {
			i := issued(nb90, 90*day)
			i.LastOrderAt = at(48 * time.Hour)
			return i
		}(), Order, ReasonDue, nil},
		{"clock skew: a few seconds ahead still counts", func() Input {
			i := issued(nb90, 90*day)
			i.LastOrderAt = at(30 * time.Second)
			return i
		}(), None, ReasonSpacing, at(15*time.Minute + 30*time.Second)},
		{"clock skew: next_attempt_at beyond the cap is repaired", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.NextAttemptAt = 1, StateFailing, at(400*day)
			return i
		}(), None, ReasonBackoff, at(24 * time.Hour)},
		{"failing and due again after the backoff", func() Input {
			i := issued(nb90, 90*day)
			i.Failures, i.State, i.LastAttemptAt, i.NextAttemptAt = 2, StateFailing, at(-3*time.Hour), at(-time.Hour)
			return i
		}(), Order, ReasonDue, nil},
		{"issuing state with no running order (a person's order just ended)", func() Input {
			i := issued(nb90, 90*day)
			i.State = StateIssuing
			return i
		}(), Order, ReasonDue, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(tc.in)
			assert.Equal(t, tc.action, d.Action, "action")
			assert.Equal(t, tc.reason, d.Reason, "reason")
			if tc.retry != nil {
				assert.Equal(t, *tc.retry, d.RetryAt, "retry at")
			}
		})
	}
}

func TestDecideRepairsANextAttemptBeyondTheCap(t *testing.T) {
	in := issued(t0.Add(-61*day), 90*day)
	in.Failures, in.State, in.NextAttemptAt = 1, StateFailing, at(400*day)
	d := Decide(in)
	if assert.NotNil(t, d.RepairNextAttempt) {
		assert.Equal(t, t0.Add(MaxBackoff), *d.RepairNextAttempt)
	}
	in.NextAttemptAt = at(MaxBackoff)
	assert.Nil(t, Decide(in).RepairNextAttempt, "exactly the cap is no skew")
	in.Locked = true
	in.NextAttemptAt = at(400 * day)
	assert.Nil(t, Decide(in).RepairNextAttempt, "nothing is written in lock")
}

func TestDecideRenewAtAndARIRefresh(t *testing.T) {
	in := issued(t0.Add(-10*day), 90*day)
	d := Decide(in)
	assert.Equal(t, in.NotBefore.Add(60*day), d.RenewAt)
	assert.True(t, d.RefreshARI, "never asked")

	in.ARICheckedAt = at(-time.Hour)
	assert.False(t, Decide(in).RefreshARI, "asked an hour ago")
	in.ARICheckedAt = at(-ARIRefresh)
	assert.True(t, Decide(in).RefreshARI, "six hours ago")
	in.ARINextCheckAt = at(time.Hour)
	assert.False(t, Decide(in).RefreshARI, "the CA's Retry-After is not over")
	in.ARINextCheckAt = at(-time.Second)
	in.ARICheckedAt = at(-2 * time.Hour)
	assert.True(t, Decide(in).RefreshARI, "the CA's Retry-After is over")

	in.ARIWindow = &Window{Start: t0.Add(5 * day), End: t0.Add(6 * day)}
	assert.Equal(t, t0.Add(5*day), Decide(in).RenewAt, "the window pulls the renewal earlier")

	due := issued(t0.Add(-61*day), 90*day)
	assert.False(t, Decide(due).RefreshARI, "a certificate that is due needs no window")
	for _, mut := range []func(*Input){
		func(i *Input) { i.Locked = true }, func(i *Input) { i.AutoRenew = false }, func(i *Input) { i.State = StateStopped },
		func(i *Input) { i.OrderRunning = true }, func(i *Input) { i.NotAfter = time.Time{} },
	} {
		i := issued(t0.Add(-10*day), 90*day)
		mut(&i)
		assert.False(t, Decide(i).RefreshARI)
	}
}

func TestNextARICheck(t *testing.T) {
	assert.Equal(t, t0.Add(ARIRefresh), NextARICheck(t0, 0))
	assert.Equal(t, t0.Add(MinARIRetry), NextARICheck(t0, time.Minute), "a Retry-After under an hour is an hour")
	assert.Equal(t, t0.Add(3*time.Hour), NextARICheck(t0, 3*time.Hour))
	assert.Equal(t, t0.Add(48*time.Hour), NextARICheck(t0, 48*time.Hour), "the CA's 48 h in full, past the local cap (R47)")
	assert.Equal(t, t0.Add(MaxCAWait), NextARICheck(t0, 30*day), "bounded at a week")
}

func TestAfterFailure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		in           FailureState
		notify, stop bool
	}{
		{"one failure", FailureState{Failures: 1, AutoRenew: true, Issued: true}, false, false},
		{"two", FailureState{Failures: 2, AutoRenew: true, Issued: true}, false, false},
		{"three: the e-mail", FailureState{Failures: 3, AutoRenew: true, Issued: true}, true, false},
		{"three, mailed already", FailureState{Failures: 3, AutoRenew: true, Issued: true, Notified: true}, false, false},
		{"four, not mailed (switched on later)", FailureState{Failures: 4, AutoRenew: true, Issued: true}, true, false},
		{"five permanent: the stop", FailureState{Failures: 5, PermanentFailures: 5, AutoRenew: true, Issued: true, Notified: true}, false, true},
		{"five permanent, never mailed: the stop only", FailureState{Failures: 5, PermanentFailures: 5, AutoRenew: true, Issued: true}, false, true},
		{"five transient: no stop", FailureState{Failures: 5, AutoRenew: true, Issued: true, Notified: true}, false, false},
		{"twelve, four permanent: no stop", FailureState{Failures: 12, PermanentFailures: 4, AutoRenew: true, Issued: true, Notified: true}, false, false},
		{"eight, five permanent: the stop", FailureState{Failures: 8, PermanentFailures: 5, AutoRenew: true, Issued: true, Notified: true}, false, true},
		{"expired, five transient: the stop", FailureState{Failures: 5, AutoRenew: true, Issued: true, Expired: true, Notified: true}, false, true},
		{"expired, four transient: no stop", FailureState{Failures: 4, AutoRenew: true, Issued: true, Expired: true, Notified: true}, false, false},
		{"six, stopped already", FailureState{Failures: 6, PermanentFailures: 6, AutoRenew: true, Issued: true, Stopped: true}, false, false},
		{"auto renewal off: nothing", FailureState{Failures: 5, PermanentFailures: 5, Issued: true}, false, false},
		{"never issued: a person's first order, nothing", FailureState{Failures: 5, PermanentFailures: 5, AutoRenew: true}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := AfterFailure(tc.in)
			assert.Equal(t, tc.notify, o.Notify, "notify")
			assert.Equal(t, tc.stop, o.Stop, "stop")
		})
	}
}

func TestNeutralCodes(t *testing.T) {
	assert.True(t, Neutral("license.locked"))
	assert.True(t, Neutral("job.lease_expired"))
	assert.False(t, Neutral("acme.ca_rate_limited"))
	assert.False(t, Neutral(""))
}

func TestRecoveryInterval(t *testing.T) {
	for left, want := range map[time.Duration]time.Duration{30 * day: 24 * time.Hour, 8 * day: 24 * time.Hour, 7 * day: 12 * time.Hour,
		4 * day: 12 * time.Hour, 3 * day: 6 * time.Hour, 2 * day: 6 * time.Hour, day: 2 * time.Hour, time.Hour: 2 * time.Hour, -day: 2 * time.Hour} {
		assert.Equal(t, want, RecoveryInterval(left), "left %s", left)
	}
}

func TestRetryWait(t *testing.T) {
	// Permanent (or unknown): the ordinary backoff, whatever is left.
	assert.Equal(t, 4*time.Hour, RetryWait(3, ClassPermanent, 12*time.Hour))
	assert.Equal(t, 24*time.Hour, RetryWait(9, "", 12*time.Hour))
	// Transient: the backoff, but never longer than the recovery interval of the time left.
	assert.Equal(t, 4*time.Hour, RetryWait(3, ClassTransient, 30*day))
	assert.Equal(t, 24*time.Hour, RetryWait(9, ClassTransient, 30*day))
	assert.Equal(t, 12*time.Hour, RetryWait(9, ClassTransient, 5*day))
	assert.Equal(t, 6*time.Hour, RetryWait(9, ClassTransient, 2*day))
	assert.Equal(t, 2*time.Hour, RetryWait(9, ClassTransient, 12*time.Hour))
	assert.Equal(t, time.Hour, RetryWait(1, ClassTransient, 12*time.Hour))
	assert.Equal(t, time.Duration(0), RetryWait(0, ClassTransient, 12*time.Hour))
}

func TestShouldStop(t *testing.T) {
	assert.False(t, ShouldStop(4, 4, false))
	assert.True(t, ShouldStop(5, 5, false))
	assert.False(t, ShouldStop(50, 4, false), "transient failures alone never stop before the expiry")
	assert.True(t, ShouldStop(5, 0, true), "after the expiry five of any class stop")
	assert.False(t, ShouldStop(4, 0, true))
}

func TestClassOfCode(t *testing.T) {
	for _, c := range []string{"acme.ca_rate_limited", "acme.provider_unreachable", "acme.not_issued_in_time", "acme.order_abandoned",
		"acme.rollover_pending"} {
		assert.Equal(t, ClassTransient, ClassOfCode(c), c)
	}
	for _, c := range []string{"acme.validation_failed_dns", "acme.hook_refused", "acme.account_rejected", "acme.identifier_refused",
		"acme.account_state", "acme.directory_invalid", "internal.unexpected", ""} {
		assert.Equal(t, ClassPermanent, ClassOfCode(c), c)
	}
}

func TestExpiryNoticeDays(t *testing.T) {
	assert.Equal(t, []int{14, 7, 3, 1}, ExpiryNoticeDays())
}

// The CA's earliest retry time (R47): a Retry-After of 48 h is waited for in full, past the local cap of 24 h; it is
// kept apart from the local backoff, so the repair of a skewed next_attempt_at never shortens it.
func TestDecideWaitsForTheCA(t *testing.T) {
	limited := func(now time.Duration) Input {
		in := issued(t0.Add(-61*day), 90*day)
		in.Now = t0.Add(now)
		in.Failures, in.LastFailureClass, in.State = 1, ClassTransient, StateFailing
		in.LastAttemptAt, in.NextAttemptAt, in.LastOrderAt = at(0), at(time.Hour), at(0)
		in.CANotBefore = at(48 * time.Hour)
		return in
	}
	d := Decide(limited(24 * time.Hour))
	assert.Equal(t, None, d.Action, "24 hours after the limit: the CA said 48")
	assert.Equal(t, ReasonCAWait, d.Reason)
	assert.Equal(t, t0.Add(48*time.Hour), d.RetryAt)
	assert.Nil(t, d.RepairNextAttempt)
	assert.Nil(t, d.RepairCANotBefore)
	assert.Equal(t, None, Decide(limited(48*time.Hour-time.Second)).Action)
	assert.Equal(t, Order, Decide(limited(48*time.Hour)).Action, "the CA's time has come")

	// A local next_attempt_at beyond its cap is repaired; the CA's time is not shortened by that repair.
	in := limited(0)
	in.NextAttemptAt = at(400 * day)
	in.CANotBefore = at(5 * day)
	d = Decide(in)
	if assert.NotNil(t, d.RepairNextAttempt) {
		assert.Equal(t, t0.Add(MaxBackoff), *d.RepairNextAttempt)
	}
	assert.Nil(t, d.RepairCANotBefore)
	assert.Equal(t, t0.Add(5*day), d.RetryAt, "the CA's five days, not the local cap")
	assert.Equal(t, ReasonCAWait, d.Reason)

	// The later of the two decides, and so does the spacing.
	in = limited(0)
	in.CANotBefore = at(30 * time.Minute)
	d = Decide(in)
	assert.Equal(t, ReasonBackoff, d.Reason, "the local backoff ends later")
	assert.Equal(t, t0.Add(time.Hour), d.RetryAt)
	in = limited(0)
	in.Failures, in.NextAttemptAt, in.LastAttemptAt, in.CANotBefore = 0, nil, nil, at(10*time.Minute)
	d = Decide(in)
	assert.Equal(t, ReasonSpacing, d.Reason)
	in.CANotBefore = at(-time.Minute)
	assert.Equal(t, Order, Decide(in.withNow(t0.Add(MinSpacing))).Action, "a CA time in the past is no wait")

	// A CA time further than MaxCAWait is impossible unless the clock moved back (it was stored at most MaxCAWait after
	// an earlier now): it is bounded to now + MaxCAWait, which is never earlier than what the CA asked for.
	in = limited(0)
	in.CANotBefore = at(400 * day)
	d = Decide(in)
	if assert.NotNil(t, d.RepairCANotBefore) {
		assert.Equal(t, t0.Add(MaxCAWait), *d.RepairCANotBefore)
	}
	assert.Equal(t, t0.Add(MaxCAWait), d.RetryAt)
	in.CANotBefore = at(MaxCAWait)
	assert.Nil(t, Decide(in).RepairCANotBefore, "exactly the bound is no skew")
	in.Locked = true
	in.CANotBefore = at(400 * day)
	assert.Nil(t, Decide(in).RepairCANotBefore, "nothing is written in lock")

	// The recovery of a stopped certificate waits for the CA too.
	in = limited(24 * time.Hour)
	in.State = StateStopped
	assert.Equal(t, ReasonCAWait, Decide(in).Reason)
	assert.Equal(t, Order, Decide(in.withNow(t0.Add(48*time.Hour))).Action)
}

func (in Input) withNow(now time.Time) Input { in.Now = now; return in }

func TestCAWaitCritical(t *testing.T) {
	nb := t0
	na := nb.Add(90 * day) // due at nb + 60 d, the middle of the window at nb + 75 d
	assert.False(t, CAWaitCritical(nb, na, 30, nb.Add(61*day)))
	assert.False(t, CAWaitCritical(nb, na, 30, nb.Add(75*day)), "exactly the middle")
	assert.True(t, CAWaitCritical(nb, na, 30, nb.Add(75*day+time.Second)))
	assert.True(t, CAWaitCritical(nb, na, 30, na.Add(day)), "past the end")
	short := nb.Add(6 * day) // due at nb + 4 d, the middle at nb + 5 d
	assert.True(t, CAWaitCritical(nb, short, 30, nb.Add(4*day+48*time.Hour)), "a 6-day certificate cannot wait 48 h at its renewal time")
	assert.False(t, CAWaitCritical(nb, short, 30, nb.Add(4*day+time.Hour)))
}
