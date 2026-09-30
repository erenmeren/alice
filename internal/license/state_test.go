package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

const day = 24 * time.Hour

var (
	installedAt = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC) // T0
	expiry      = time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC) // E
)

// lic returns a verified upload valid from E-365d until E (baseline of §23.1: max_targets 10).
func lic(seq int64, id string, from, until time.Time, targets int) license.Installed {
	p := licensetest.Payload(testInstallation, from, until, targets)
	p.LicenseID = id
	return license.Installed{Seq: seq, KeyID: licensetest.KeyID, Payload: p}
}

func baseline() []license.Installed {
	return []license.Installed{lic(1, "LIC-A", expiry.Add(-365*day), expiry, 10)}
}

// §23.2 Evaluation mode.
func TestEvaluationMode(t *testing.T) {
	e := license.Evaluate(installedAt, installedAt, nil) // L-01
	assert.Equal(t, license.PhaseEvaluation, e.Phase)
	assert.Nil(t, e.Current)
	assert.Equal(t, 30, e.DaysLeft)
	assert.Equal(t, 5, e.MaxTargets)
	assert.True(t, e.EndsAt.Equal(installedAt.Add(30*day)))
	assert.True(t, e.LocksAt.Equal(e.EndsAt), "evaluation ends directly in lock (R1)")
	assert.Zero(t, e.Threshold)
	assert.Equal(t, "evaluation", e.Key())
	assert.False(t, e.Locked())
	assert.False(t, e.Expired())

	e = license.Evaluate(installedAt.Add(29*day+23*time.Hour+59*time.Minute), installedAt, nil) // L-02
	assert.Equal(t, license.PhaseEvaluation, e.Phase)
	assert.Equal(t, 1, e.DaysLeft)

	e = license.Evaluate(installedAt.Add(30*day), installedAt, nil) // L-03
	assert.Equal(t, license.PhaseEvaluationExpired, e.Phase)
	assert.True(t, e.Locked(), "evaluation expired behaves as lock")
	assert.True(t, e.Expired())
	assert.Zero(t, e.DaysLeft)
	assert.Zero(t, e.GraceDay, "no grace for the evaluation")
}

// L-07: administrators are warned 7, 3 and 1 days before the evaluation ends.
func TestEvaluationWarnings(t *testing.T) {
	for offset, want := range map[time.Duration]int{
		22*day + 23*time.Hour: 0,
		23 * day:              7,
		26 * day:              7,
		27 * day:              3,
		29 * day:              1,
		30*day - time.Second:  1,
	} {
		assert.Equal(t, want, license.Evaluate(installedAt.Add(offset), installedAt, nil).Threshold, offset.String())
	}
}

// L-05: a license ends the evaluation at once; L-06: the installation timestamp decides.
func TestLicenseEndsEvaluation(t *testing.T) {
	now := installedAt.Add(3 * day)
	e := license.Evaluate(now, installedAt, []license.Installed{lic(1, "LIC-A", now, now.Add(365*day), 10)})
	assert.Equal(t, license.PhaseActive, e.Phase)
	require.NotNil(t, e.Current)
	assert.Equal(t, "LIC-A", e.Key())
	assert.Equal(t, 10, e.MaxTargets)

	restored := license.Evaluate(installedAt.Add(40*day), installedAt, nil) // restore keeps installed_at (L-06)
	assert.Equal(t, license.PhaseEvaluationExpired, restored.Phase)
}

// §23.3 Warning thresholds (L-10, L-11, L-13).
func TestExpiryWarningThresholds(t *testing.T) {
	cases := []struct {
		at        time.Time
		threshold int
		daysLeft  int
	}{
		{expiry.Add(-61*day - 12*time.Hour), 0, 62}, // L-10
		{expiry.Add(-60 * day), 60, 60},             // L-11
		{expiry.Add(-31 * day), 60, 31},             // L-12: still the 60-day banner
		{expiry.Add(-30 * day), 30, 30},             // L-13
		{expiry.Add(-14 * day), 14, 14},
		{expiry.Add(-7 * day), 7, 7},
		{expiry.Add(-1 * day), 1, 1},
		{expiry.Add(-time.Second), 1, 1},
	}
	for _, tc := range cases {
		e := license.Evaluate(tc.at, installedAt, baseline())
		assert.Equal(t, license.PhaseActive, e.Phase, tc.at.String())
		assert.Equal(t, tc.threshold, e.Threshold, tc.at.String())
		assert.Equal(t, tc.daysLeft, e.DaysLeft, tc.at.String())
	}
}

// §23.4 Expiry, grace and lock (L-20..L-24), instant-based (R25).
func TestGraceAndLock(t *testing.T) {
	e := license.Evaluate(expiry, installedAt, baseline()) // L-20
	assert.Equal(t, license.PhaseGrace, e.Phase)
	assert.Equal(t, 1, e.GraceDay)
	assert.True(t, e.Expired())
	assert.False(t, e.Locked(), "grace: everything works")
	assert.True(t, e.LocksAt.Equal(expiry.Add(168*time.Hour)))

	assert.Equal(t, 1, license.Evaluate(expiry.Add(23*time.Hour+59*time.Minute+59*time.Second), installedAt, baseline()).GraceDay) // L-21
	for n := 1; n <= 7; n++ {                                                                                                      // L-22
		e := license.Evaluate(expiry.Add(time.Duration(n-1)*day), installedAt, baseline())
		assert.Equal(t, license.PhaseGrace, e.Phase, n)
		assert.Equal(t, n, e.GraceDay, n)
	}
	e = license.Evaluate(expiry.Add(167*time.Hour+59*time.Minute+59*time.Second), installedAt, baseline()) // L-23
	assert.Equal(t, license.PhaseGrace, e.Phase)
	assert.Equal(t, 7, e.GraceDay)

	e = license.Evaluate(expiry.Add(168*time.Hour), installedAt, baseline()) // L-24
	assert.Equal(t, license.PhaseLocked, e.Phase)
	assert.True(t, e.Locked())
	assert.Zero(t, e.GraceDay)
}

// L-17, L-30, L-31: a renewal takes effect immediately and restarts the warnings.
func TestRenewal(t *testing.T) {
	renewed := append(baseline(), lic(2, "LIC-B", expiry.Add(-20*day), expiry.Add(345*day), 10))
	e := license.Evaluate(expiry.Add(-14*day), installedAt, renewed)
	assert.Equal(t, "LIC-B", e.Key())
	assert.Zero(t, e.Threshold, "no 14-day warning of the old license (L-17)")

	inGrace := append(baseline(), lic(2, "LIC-B", expiry.Add(3*day), expiry.Add(368*day), 10))
	assert.Equal(t, license.PhaseActive, license.Evaluate(expiry.Add(3*day), installedAt, inGrace).Phase) // L-31
	inLock := append(baseline(), lic(2, "LIC-B", expiry.Add(20*day), expiry.Add(385*day), 10))
	assert.Equal(t, license.PhaseActive, license.Evaluate(expiry.Add(20*day), installedAt, inLock).Phase) // L-30
}

// L-32: an already expired renewal is accepted; its own dates decide.
func TestAlreadyExpiredRenewal(t *testing.T) {
	now := expiry.Add(30 * day) // locked under LIC-A
	recent := append(baseline(), lic(2, "LIC-B", now.Add(-200*day), now.Add(-100*time.Hour), 10))
	e := license.Evaluate(now, installedAt, recent)
	assert.Equal(t, license.PhaseGrace, e.Phase)
	assert.Equal(t, "LIC-B", e.Key())
	old := append(baseline(), lic(2, "LIC-B", now.Add(-400*day), now.Add(-168*time.Hour), 10))
	assert.Equal(t, license.PhaseLocked, license.Evaluate(now, installedAt, old).Phase)
}

// L-48: a license that starts later is pending; the previous license (or evaluation) continues.
func TestPendingLicense(t *testing.T) {
	now := expiry.Add(-10 * day)
	uploads := append(baseline(), lic(2, "LIC-B", now.Add(2*day), now.Add(367*day), 20))
	e := license.Evaluate(now, installedAt, uploads)
	assert.Equal(t, "LIC-A", e.Key())
	require.NotNil(t, e.Pending)
	assert.Equal(t, "LIC-B", e.Pending.LicenseID)
	assert.Equal(t, int64(2), e.PendingSeq)
	assert.Equal(t, int64(1), e.CurrentSeq)
	assert.Equal(t, 10, e.MaxTargets)

	e = license.Evaluate(now.Add(2*day), installedAt, uploads)
	assert.Equal(t, "LIC-B", e.Key())
	assert.Nil(t, e.Pending)
	assert.Equal(t, 20, e.MaxTargets)

	evalOnly := []license.Installed{lic(1, "LIC-B", installedAt.Add(5*day), installedAt.Add(370*day), 20)}
	e = license.Evaluate(installedAt.Add(time.Hour), installedAt, evalOnly)
	assert.Equal(t, license.PhaseEvaluation, e.Phase)
	require.NotNil(t, e.Pending)
}

// The newest upload that has started wins, even a correction license with earlier dates (L-61).
func TestNewestStartedUploadWins(t *testing.T) {
	correction := lic(2, "LIC-C", expiry.Add(-400*day), expiry.Add(30*day), 10)
	correction.Payload.Replaces = "LIC-A"
	e := license.Evaluate(expiry.Add(5*day), installedAt, append(baseline(), correction))
	assert.Equal(t, license.PhaseActive, e.Phase)
	assert.Equal(t, "LIC-C", e.Key())

	shorter := lic(2, "LIC-D", expiry.Add(-100*day), expiry.Add(-50*day), 10)
	e = license.Evaluate(expiry.Add(-60*day), installedAt, append(baseline(), shorter))
	assert.Equal(t, "LIC-D", e.Key(), "the vendor's latest file is authoritative, also when it is shorter")

	// Upload order, not slice order, decides.
	e = license.Evaluate(expiry.Add(5*day), installedAt, []license.Installed{correction, baseline()[0]})
	assert.Equal(t, "LIC-C", e.Key())
}

// §23.7 target limit (pure part): L-70, L-71, L-75, L-77, L-78, L-04.
func TestTargetLimit(t *testing.T) {
	active := license.Evaluate(expiry.Add(-100*day), installedAt, baseline())
	assert.True(t, active.CanAdd(9))   // L-70
	assert.False(t, active.CanAdd(10)) // L-71
	assert.False(t, active.OverLimit(10))
	assert.True(t, active.OverLimit(12), "L-75: 12 of 10 after a smaller renewal")
	assert.Equal(t, license.PhaseActive, active.Phase, "exceeding the limit never locks")

	eval := license.Evaluate(installedAt, installedAt, nil)
	assert.True(t, eval.CanAdd(4))
	assert.False(t, eval.CanAdd(5), "L-04: the evaluation allows 5 targets")

	small := license.Evaluate(installedAt.Add(time.Hour), installedAt, []license.Installed{lic(1, "LIC-S", installedAt, installedAt.Add(365*day), 3)})
	assert.True(t, small.OverLimit(5), "L-78")

	big := license.Evaluate(expiry.Add(-100*day), installedAt, append(baseline(), lic(2, "LIC-BIG", expiry.Add(-150*day), expiry.Add(200*day), 100)))
	assert.Equal(t, 100, big.MaxTargets, "L-77")

	locked := license.Evaluate(expiry.Add(200*day), installedAt, baseline())
	assert.False(t, locked.CanAdd(0), "nothing is added while locked")
}

func TestClasses(t *testing.T) {
	assert.False(t, license.ClassUnset.Valid())
	for _, c := range []license.Class{license.ClassAlways, license.ClassReadOnly, license.ClassChange} {
		assert.True(t, c.Valid(), c.String())
	}
	assert.False(t, license.Class(9).Valid())
	assert.Equal(t, "read_only", license.ClassReadOnly.String())
}

// A correction uploaded after an early renewal must not hide the pending renewal.
func TestCorrectionDoesNotHidePendingRenewal(t *testing.T) {
	renewal := lic(2, "LIC-B", expiry, expiry.Add(365*day), 10)
	correction := lic(3, "LIC-C", expiry.Add(-300*day), expiry, 10)
	correction.Payload.Replaces = "LIC-A"
	uploads := append(baseline(), renewal, correction)

	e := license.Evaluate(expiry.Add(-5*day), installedAt, uploads)
	assert.Equal(t, "LIC-C", e.Key())
	require.NotNil(t, e.Pending)
	assert.Equal(t, "LIC-B", e.Pending.LicenseID)
	assert.Equal(t, int64(2), e.PendingSeq)

	for _, at := range []time.Time{expiry.Add(time.Hour), expiry.Add(200 * time.Hour)} {
		e = license.Evaluate(at, installedAt, uploads)
		assert.Equal(t, license.PhaseActive, e.Phase, at.String())
		assert.Equal(t, "LIC-B", e.Key(), at.String())
		assert.Nil(t, e.Pending)
	}
}

// Every boundary flips exactly at its instant: t-1s, t, t+1s.
func TestBoundaries(t *testing.T) {
	evalEnd := installedAt.Add(30 * day)
	from := expiry.Add(20 * day)
	started := append(baseline(), lic(2, "LIC-B", from, from.Add(365*day), 20))
	type probe struct {
		name          string
		at            time.Time
		installed     []license.Installed
		before, after func(license.Evaluation) bool
	}
	thr := func(n int) func(license.Evaluation) bool {
		return func(e license.Evaluation) bool { return e.Threshold == n }
	}
	phase := func(p license.Phase) func(license.Evaluation) bool {
		return func(e license.Evaluation) bool { return e.Phase == p }
	}
	probes := []probe{
		{"evaluation end", evalEnd, nil, phase(license.PhaseEvaluation), phase(license.PhaseEvaluationExpired)},
		{"evaluation warning 7", installedAt.Add(23 * day), nil, thr(0), thr(7)},
		{"evaluation warning 3", installedAt.Add(27 * day), nil, thr(7), thr(3)},
		{"evaluation warning 1", installedAt.Add(29 * day), nil, thr(3), thr(1)},
		{"expiry 60", expiry.Add(-60 * day), baseline(), thr(0), thr(60)},
		{"expiry 30", expiry.Add(-30 * day), baseline(), thr(60), thr(30)},
		{"expiry 14", expiry.Add(-14 * day), baseline(), thr(30), thr(14)},
		{"expiry 7", expiry.Add(-7 * day), baseline(), thr(14), thr(7)},
		{"expiry 1", expiry.Add(-1 * day), baseline(), thr(7), thr(1)},
		{"expiry", expiry, baseline(), phase(license.PhaseActive), phase(license.PhaseGrace)},
		{"lock", expiry.Add(168 * time.Hour), baseline(), phase(license.PhaseGrace), phase(license.PhaseLocked)},
		{"valid_from", from, started, func(e license.Evaluation) bool { return e.Key() == "LIC-A" && e.Pending != nil },
			func(e license.Evaluation) bool { return e.Key() == "LIC-B" && e.Pending == nil }},
	}
	for _, p := range probes {
		assert.True(t, p.before(license.Evaluate(p.at.Add(-time.Second), installedAt, p.installed)), p.name+" t-1s")
		assert.True(t, p.after(license.Evaluate(p.at, installedAt, p.installed)), p.name+" t")
		assert.True(t, p.after(license.Evaluate(p.at.Add(time.Second), installedAt, p.installed)), p.name+" t+1s")
	}
}

// A future-dated correction leaves the license in force untouched until it starts.
func TestFutureCorrectionWaits(t *testing.T) {
	now := expiry.Add(-20 * day)
	c := lic(2, "LIC-C", now.Add(time.Hour), expiry.Add(30*day), 10)
	c.Payload.Replaces = "LIC-A"
	uploads := append(baseline(), c)

	e := license.Evaluate(now, installedAt, uploads)
	assert.Equal(t, license.PhaseActive, e.Phase)
	assert.Equal(t, "LIC-A", e.Key())
	require.NotNil(t, e.Pending)
	assert.Equal(t, "LIC-C", e.Pending.LicenseID)

	e = license.Evaluate(now.Add(time.Hour), installedAt, uploads)
	assert.Equal(t, "LIC-C", e.Key())
	assert.Nil(t, e.Pending)
}

// C replaces B replaces A: the chain resolves to C.
func TestCorrectionChain(t *testing.T) {
	b := lic(2, "LIC-B", expiry.Add(-300*day), expiry.Add(10*day), 10)
	b.Payload.Replaces = "LIC-A"
	c := lic(3, "LIC-C", expiry.Add(-200*day), expiry.Add(20*day), 10)
	c.Payload.Replaces = "LIC-B"
	e := license.Evaluate(expiry.Add(-5*day), installedAt, append(baseline(), b, c))
	assert.Equal(t, "LIC-C", e.Key())
	assert.Nil(t, e.Pending)
}

// Round-3 rule: a started correction supersedes its target directly; among the remaining
// valid licenses the latest valid_from wins. So C (Replaces A, valid_from E+3d) is also
// the latest active license at E+5d and takes over from B. This supersedes the round-2
// expectation that B stays current; the controller's definitive rule decides.
func TestStartedCorrectionOfOlderLicenseWinsByValidFrom(t *testing.T) {
	b := lic(2, "LIC-B", expiry, expiry.Add(365*day), 10)
	c := lic(3, "LIC-C", expiry.Add(3*day), expiry.Add(100*day), 10)
	c.Payload.Replaces = "LIC-A"
	e := license.Evaluate(expiry.Add(5*day), installedAt, append(baseline(), b, c))
	assert.Equal(t, license.PhaseActive, e.Phase)
	assert.Equal(t, "LIC-C", e.Key())
}

// N1: a correction of a not-yet-started renewal supersedes it once the correction has started.
func TestN1CorrectionOfFutureRenewal(t *testing.T) {
	b := lic(2, "LIC-B", expiry.Add(365*day), expiry.Add(730*day), 10)
	c := lic(3, "LIC-C", expiry, expiry.Add(400*day), 10)
	c.Payload.Replaces = "LIC-B"
	for _, at := range []time.Time{expiry.Add(day), expiry.Add(8 * day)} {
		e := license.Evaluate(at, installedAt, append(baseline(), b, c))
		assert.Equal(t, license.PhaseActive, e.Phase, at.String())
		assert.Equal(t, "LIC-C", e.Key(), at.String())
		assert.Nil(t, e.Pending, at.String())
	}
}

// N2: the replaced license was never uploaded; the correction stands on its own.
func TestN2CorrectionOfUnknownLicense(t *testing.T) {
	c := lic(1, "LIC-C", installedAt, installedAt.Add(365*day), 10)
	c.Payload.Replaces = "LIC-A"
	e := license.Evaluate(installedAt.Add(40*day), installedAt, []license.Installed{c})
	assert.Equal(t, license.PhaseActive, e.Phase)
	assert.Equal(t, "LIC-C", e.Key())
}

// N3: upload order A, C (replaces B), B (replaces A): C is current whatever the order.
func TestN3OrderIndependence(t *testing.T) {
	a := baseline()[0]
	c := lic(2, "LIC-C", expiry.Add(-100*day), expiry.Add(200*day), 10)
	c.Payload.Replaces = "LIC-B"
	b := lic(3, "LIC-B", expiry.Add(-200*day), expiry.Add(2*day), 10)
	b.Payload.Replaces = "LIC-A"
	e := license.Evaluate(expiry.Add(5*day), installedAt, []license.Installed{a, c, b})
	assert.Equal(t, license.PhaseActive, e.Phase)
	assert.Equal(t, "LIC-C", e.Key())
}

// A longer license that started earlier is preferred once the later-starting one has ended.
func TestLongerEarlierStartWinsAfterExpiry(t *testing.T) {
	long := lic(2, "LIC-L", expiry.Add(-400*day), expiry.Add(100*day), 10)
	e := license.Evaluate(expiry.Add(day), installedAt, append(baseline(), long))
	assert.Equal(t, license.PhaseActive, e.Phase)
	assert.Equal(t, "LIC-L", e.Key())
}

// With B (renewal from E) and C (replaces B, from E+20d) both unstarted, nothing is
// superseded yet (only started uploads supersede), so the highest-Seq upload, C, is pending.
// Once C starts, B is superseded and no longer pending or current.
func TestPendingCorrectionOfPendingRenewal(t *testing.T) {
	b := lic(2, "LIC-B", expiry, expiry.Add(365*day), 10)
	c := lic(3, "LIC-C", expiry.Add(20*day), expiry.Add(385*day), 10)
	c.Payload.Replaces = "LIC-B"
	uploads := append(baseline(), b, c)
	e := license.Evaluate(expiry.Add(-5*day), installedAt, uploads)
	assert.Equal(t, "LIC-A", e.Key())
	require.NotNil(t, e.Pending)
	assert.Equal(t, "LIC-C", e.Pending.LicenseID)

	e = license.Evaluate(expiry.Add(21*day), installedAt, uploads)
	assert.Equal(t, "LIC-C", e.Key())
	assert.Nil(t, e.Pending)
}

// Uploading an extra valid, unreplacing license never makes an active state worse.
func TestMonotonicity(t *testing.T) {
	b := lic(2, "LIC-B", expiry, expiry.Add(365*day), 10)
	c := lic(3, "LIC-C", expiry.Add(3*day), expiry.Add(100*day), 10)
	c.Payload.Replaces = "LIC-A"
	scenarios := [][]license.Installed{
		baseline(),
		append(baseline(), b),
		append(baseline(), b, c),
		append(baseline(), lic(2, "LIC-L", expiry.Add(-400*day), expiry.Add(100*day), 10)),
	}
	for si, base := range scenarios {
		for n := -70; n <= 400; n += 3 {
			at := expiry.Add(time.Duration(n) * day)
			before := license.Evaluate(at, installedAt, base)
			if before.Phase != license.PhaseActive {
				continue
			}
			extra := lic(99, "LIC-X", at.Add(-day), at.Add(50*day), 10)
			after := license.Evaluate(at, installedAt, append(append([]license.Installed(nil), base...), extra))
			assert.Equal(t, license.PhaseActive, after.Phase, "scenario %d day %d", si, n)
		}
	}
}
