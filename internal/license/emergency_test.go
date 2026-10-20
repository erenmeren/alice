package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// An emergency extension (docs/superpowers/rulings/vendor-emergency-extension.md) is an ordinary
// license for the same installation, valid from the start of the UTC day it is signed for 1 to 30
// days. Alice has no notion of it; these tests pin that the ordinary rules of Evaluate pick it up
// after a lapse and hand over to the real renewal in every way the vendor console allows.

// startOfDay is where the vendor console starts an extension: 00:00 UTC of the signing day.
func startOfDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// lapsedWithExtension: LIC-A ended at E and the installation is locked (E+10d); the vendor signs a
// 14-day extension LIC-X that day and the customer uploads it.
func lapsedWithExtension() (now time.Time, ext license.Installed, uploads []license.Installed) {
	now = expiry.Add(10*day + 15*time.Hour)
	from := startOfDay(now)
	ext = lic(2, "LIC-X", from, from.Add(14*day), 10)
	return now, ext, append(baseline(), ext)
}

func TestEmergencyExtensionAfterLapseIsInForceUntilItsEnd(t *testing.T) {
	now, ext, uploads := lapsedWithExtension()
	require.Equal(t, license.PhaseLocked, license.Evaluate(now, installedAt, baseline()).Phase, "LIC-A alone is locked")

	e := license.Evaluate(now, installedAt, uploads)
	assert.Equal(t, license.PhaseActive, e.Phase, "the extension unlocks at once")
	assert.Equal(t, "LIC-X", e.Key())
	assert.True(t, e.EndsAt.Equal(ext.Payload.ValidUntil))
	assert.True(t, e.LocksAt.Equal(ext.Payload.ValidUntil.Add(license.GracePeriod)), "grace and lock follow the extension")
	assert.Equal(t, 10, e.MaxTargets, "the targets carried over")
	assert.Equal(t, 14, e.DaysLeft)
	assert.Equal(t, 14, e.Threshold, "the expiry warnings start at once (a 14-day term)")

	end := ext.Payload.ValidUntil
	e = license.Evaluate(end.Add(-time.Second), installedAt, uploads)
	assert.Equal(t, license.PhaseActive, e.Phase)
	assert.Equal(t, 1, e.Threshold)

	e = license.Evaluate(end, installedAt, uploads)
	assert.Equal(t, license.PhaseGrace, e.Phase, "after the extension: grace computed from its end")
	assert.Equal(t, "LIC-X", e.Key())
	assert.Equal(t, 1, e.GraceDay)

	e = license.Evaluate(end.Add(license.GracePeriod-time.Second), installedAt, uploads)
	assert.Equal(t, license.PhaseGrace, e.Phase)
	assert.Equal(t, 7, e.GraceDay)

	e = license.Evaluate(end.Add(license.GracePeriod), installedAt, uploads)
	assert.Equal(t, license.PhaseLocked, e.Phase, "then lock, as after any license")
	assert.Equal(t, "LIC-X", e.Key())

	// Upload order does not matter.
	e = license.Evaluate(now, installedAt, []license.Installed{ext, baseline()[0]})
	assert.Equal(t, "LIC-X", e.Key())
}

// The extension is also correct when it is uploaded during grace, before the lock.
func TestEmergencyExtensionDuringGrace(t *testing.T) {
	now := expiry.Add(3 * day)
	from := startOfDay(now)
	uploads := append(baseline(), lic(2, "LIC-X", from, from.Add(30*day), 10))
	e := license.Evaluate(now, installedAt, uploads)
	assert.Equal(t, license.PhaseActive, e.Phase)
	assert.Equal(t, "LIC-X", e.Key())
	assert.Zero(t, e.GraceDay)
}

// The real renewal, in the three shapes the vendor console lets a signer issue it.
func TestRenewalAfterEmergencyExtension(t *testing.T) {
	now, ext, uploads := lapsedWithExtension()
	later := now.Add(3 * day) // the renewal is uploaded three days into the extension

	t.Run("renewed from the extension: starts where it ends", func(t *testing.T) {
		r := lic(3, "LIC-R", ext.Payload.ValidUntil, ext.Payload.ValidUntil.AddDate(1, 0, 0), 20)
		all := append(append([]license.Installed(nil), uploads...), r)
		e := license.Evaluate(later, installedAt, all)
		assert.Equal(t, "LIC-X", e.Key(), "the extension stays in force")
		require.NotNil(t, e.Pending)
		assert.Equal(t, "LIC-R", e.Pending.LicenseID)
		assert.True(t, e.LocksAt.Equal(ext.Payload.ValidUntil.Add(license.GracePeriod)))

		e = license.Evaluate(ext.Payload.ValidUntil, installedAt, all)
		assert.Equal(t, license.PhaseActive, e.Phase, "no grace: the renewal takes over at the extension's end")
		assert.Equal(t, "LIC-R", e.Key())
		assert.Equal(t, 20, e.MaxTargets)
		assert.Nil(t, e.Pending)
	})

	t.Run("starts on the upload day", func(t *testing.T) {
		r := lic(3, "LIC-R", startOfDay(later), startOfDay(later).AddDate(1, 0, 0), 20)
		e := license.Evaluate(later, installedAt, append(append([]license.Installed(nil), uploads...), r))
		assert.Equal(t, license.PhaseActive, e.Phase)
		assert.Equal(t, "LIC-R", e.Key(), "a later start wins over the extension")
		assert.Equal(t, 20, e.MaxTargets)
		assert.Zero(t, e.Threshold, "no warnings of the extension's end any more")
	})

	t.Run("starts on the same day as the extension", func(t *testing.T) {
		r := lic(3, "LIC-R", ext.Payload.ValidFrom, ext.Payload.ValidFrom.AddDate(1, 0, 0), 20)
		e := license.Evaluate(later, installedAt, append(append([]license.Installed(nil), uploads...), r))
		assert.Equal(t, "LIC-R", e.Key(), "same start: the later upload wins")
	})

	t.Run("backdated to the lapse, replacing the extension", func(t *testing.T) {
		r := lic(3, "LIC-R", expiry, expiry.AddDate(1, 0, 0), 20)
		r.Payload.IssuedAt = expiry
		r.Payload.Replaces = "LIC-X"
		e := license.Evaluate(later, installedAt, append(append([]license.Installed(nil), uploads...), r))
		assert.Equal(t, license.PhaseActive, e.Phase)
		assert.Equal(t, "LIC-R", e.Key(), "the replaced extension no longer competes")
		assert.Equal(t, 20, e.MaxTargets)
	})

	// The shape the vendor console refuses (ErrStartsBeforeExtension): a renewal that starts before
	// the extension and does not replace it. Alice keeps the extension in force (the later start)
	// until it ends, with its targets and its end warnings, and only then the renewal; nothing
	// locks, but the customer sees a license about to end. This pins why the console refuses it.
	t.Run("backdated without replacing the extension", func(t *testing.T) {
		r := lic(3, "LIC-R", expiry, expiry.AddDate(1, 0, 0), 20)
		r.Payload.IssuedAt = expiry
		r.Payload.Replaces = "LIC-A"
		all := append(append([]license.Installed(nil), uploads...), r)
		e := license.Evaluate(later, installedAt, all)
		assert.Equal(t, "LIC-X", e.Key())
		assert.Equal(t, 10, e.MaxTargets)
		e = license.Evaluate(ext.Payload.ValidUntil, installedAt, all)
		assert.Equal(t, license.PhaseActive, e.Phase)
		assert.Equal(t, "LIC-R", e.Key())
	})
}
