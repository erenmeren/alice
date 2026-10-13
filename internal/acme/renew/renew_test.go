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
		{"never issued: the first order is a person's", Input{Now: t0, RenewBeforeDays: 30, AutoRenew: true, State: StatePending}, None,
			ReasonNeverIssued, nil},
		{"never issued, failing", Input{Now: t0, RenewBeforeDays: 30, AutoRenew: true, State: StateFailing, Failures: 9}, None,
			ReasonNeverIssued, nil},
		{"five failures stop", func() Input { i := issued(nb90, 90*day); i.Failures = 5; i.State = StateFailing; return i }(), Stop,
			ReasonStopAfterFailures, nil},
		{"seven failures stop", func() Input { i := issued(nb90, 90*day); i.Failures = 7; i.State = StateFailing; return i }(), Stop,
			ReasonStopAfterFailures, nil},
		{"an order runs", func() Input { i := issued(nb90, 90*day); i.OrderRunning = true; return i }(), None, ReasonOrderRunning, nil},
		{"due by the local rule", issued(nb90, 90*day), Order, ReasonDue, nil},
		{"not due yet", issued(t0.Add(-59*day), 90*day), None, ReasonNotDue, nil},
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
	assert.Equal(t, t0.Add(MaxBackoff), NextARICheck(t0, 30*day), "capped at a day")
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
		{"five: the stop", FailureState{Failures: 5, AutoRenew: true, Issued: true, Notified: true}, false, true},
		{"five, never mailed: the stop only", FailureState{Failures: 5, AutoRenew: true, Issued: true}, false, true},
		{"six, stopped already", FailureState{Failures: 6, AutoRenew: true, Issued: true, Stopped: true}, false, false},
		{"auto renewal off: nothing", FailureState{Failures: 5, Issued: true}, false, false},
		{"never issued: a person's first order, nothing", FailureState{Failures: 5, AutoRenew: true}, false, false},
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
