package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/license"
)

func snapshotAt(now time.Time, installed []license.Installed) license.Snapshot {
	return license.Snapshot{
		InstallationID: testInstallation,
		InstalledAt:    installedAt,
		Eval:           license.Evaluate(now, installedAt, installed),
		Reading:        license.Reading{Wall: now, Trusted: now, Effective: now},
		Ready:          true,
	}
}

func kinds(bs []license.Banner) []string {
	out := []string{}
	for _, b := range bs {
		out = append(out, b.Kind+"/"+string(b.Severity))
	}
	return out
}

// §19.3: what everyone sees, and L-15: warnings go to Admins only.
func TestBannersForEveryone(t *testing.T) {
	eval := snapshotAt(installedAt, nil)
	assert.Equal(t, []string{"evaluation/info"}, kinds(eval.Banners(false)))
	b := eval.Banners(false)[0]
	assert.Equal(t, map[string]string{"days_left": "30", "max_targets": "5", "ends_at": "2026-10-31T09:00:00Z"}, b.Params)

	evalWarn := snapshotAt(installedAt.Add(27*day), nil)
	assert.Equal(t, []string{"evaluation/info"}, kinds(evalWarn.Banners(false)))
	assert.Equal(t, []string{"evaluation/caution"}, kinds(evalWarn.Banners(true)), "Admins: 3 days left is orange")
	assert.Equal(t, []string{"evaluation/warning"}, kinds(snapshotAt(installedAt.Add(23*day), nil).Banners(true)))

	assert.Equal(t, []string{"evaluation_ended/danger"}, kinds(snapshotAt(installedAt.Add(30*day), nil).Banners(false)))

	warn := snapshotAt(expiry.Add(-7*day), baseline())
	assert.Empty(t, warn.Banners(false), "L-15: no warning for Operators and Auditors")
	assert.Equal(t, []string{"expiry_warning/caution"}, kinds(warn.Banners(true)))
	assert.Equal(t, map[string]string{"days_left": "7", "valid_until": "2027-10-01T00:00:00Z"}, warn.Banners(true)[0].Params)
	assert.Equal(t, []string{"expiry_warning/warning"}, kinds(snapshotAt(expiry.Add(-30*day), baseline()).Banners(true)))
	assert.Empty(t, snapshotAt(expiry.Add(-61*day), baseline()).Banners(true), "L-10: no banner")

	grace := snapshotAt(expiry.Add(2*day+time.Hour), baseline())
	assert.Equal(t, []string{"grace/danger"}, kinds(grace.Banners(false)))
	assert.Equal(t, map[string]string{"valid_until": "2027-10-01T00:00:00Z", "locks_at": "2027-10-08T00:00:00Z", "grace_day": "3"},
		grace.Banners(false)[0].Params)

	assert.Equal(t, []string{"locked/danger"}, kinds(snapshotAt(expiry.Add(200*day), baseline()).Banners(false)))
}

func TestAdminOnlyBanners(t *testing.T) {
	s := snapshotAt(expiry.Add(-100*day), append(baseline(), lic(2, "LIC-B", expiry.Add(-90*day), expiry.Add(275*day), 10)))
	s.Tampered = true
	s.Reading.Behind = true
	s.Reading.Wall = expiry.Add(-120 * day)
	s.Reading.Jump = &license.Jump{By: 200*day + time.Hour}
	s.Targets = 12
	assert.Empty(t, s.Banners(false))
	assert.Equal(t, []string{"tampered/danger", "clock_behind/caution", "clock_jump/caution", "pending/info", "over_limit/warning"},
		kinds(s.Banners(true)))
	byKind := map[string]map[string]string{}
	for _, b := range s.Banners(true) {
		byKind[b.Kind] = b.Params
	}
	assert.Equal(t, "200", byKind["clock_jump"]["jump_days"])
	assert.Equal(t, map[string]string{"used": "12", "max": "10"}, byKind["over_limit"], "R30: persistent, no end date")
	assert.Equal(t, "2027-07-03T00:00:00Z", byKind["pending"]["valid_from"])

	full := snapshotAt(expiry.Add(-100*day), baseline())
	full.Targets = 10
	assert.Equal(t, []string{"limit_reached/info"}, kinds(full.Banners(true)), "§19.3 target limit reached")
}

// AUD-02: everyone sees that the license could not be checked, with the time of the last check,
// next to the banner of the last evaluated state.
func TestUnverifiedBannerForEveryone(t *testing.T) {
	s := snapshotAt(expiry.Add(-100*day), baseline())
	s.Reading.Wall = expiry.Add(-100*day + 90*time.Second)
	assert.Empty(t, s.Banners(false))
	s.Unverified = true
	for _, admin := range []bool{false, true} {
		bs := s.Banners(admin)
		assert.Equal(t, []string{"unverified/danger"}, kinds(bs), "admin=%v", admin)
		assert.Equal(t, map[string]string{"last_checked": "2027-06-23T00:01:30Z"}, bs[0].Params, "the system time of the last successful check")
	}
	grace := snapshotAt(expiry.Add(2*day), baseline())
	grace.Unverified = true
	assert.Equal(t, []string{"grace/danger", "unverified/danger"}, kinds(grace.Banners(false)))
}
