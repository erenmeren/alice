//go:build integration

package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// The upload path end to end: a lapsed, locked installation takes an emergency extension, falls
// back into grace and lock after it, and takes the real renewal (also one signed before the
// extension and uploaded after it).
func TestEmergencyExtensionUploadAfterLapse(t *testing.T) {
	e := newEnv(t)
	start := e.clk.Now()
	end := start.AddDate(1, 0, 0)
	_, err := e.upload(e.payload("LIC-A", start, end, 10))
	require.NoError(t, err)
	// The renewal was signed before the lapse but reaches the customer only later.
	renewal := e.payload("LIC-R", end.Add(-5*day), end.AddDate(1, 0, 0), 20)
	renewal.IssuedAt = end.Add(-5 * day)

	e.tickAt(end.Add(10 * day))
	require.Equal(t, license.PhaseLocked, e.svc.Snapshot().Eval.Phase)
	require.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked)

	now := e.clk.Now()
	from := startOfDay(now)
	ext := e.payload("LIC-X", from, from.Add(14*day), 10)
	ext.IssuedAt = now.Truncate(time.Second)
	res, err := e.upload(ext)
	require.NoError(t, err)
	assert.False(t, res.Correction)
	assert.False(t, res.Pending)
	assert.Equal(t, license.PhaseActive, res.Phase)
	ev := e.svc.Snapshot().Eval
	assert.Equal(t, "LIC-X", ev.Key())
	assert.True(t, ev.LocksAt.Equal(ext.ValidUntil.Add(license.GracePeriod)))
	assert.NoError(t, e.svc.Allow(license.ClassChange), "unlocked at once")
	assert.Equal(t, string(license.PhaseActive), e.state())

	e.tickAt(ext.ValidUntil.Add(time.Hour))
	assert.Equal(t, license.PhaseGrace, e.svc.Snapshot().Eval.Phase, "grace computed from the extension's end")
	e.tickAt(ext.ValidUntil.Add(license.GracePeriod))
	assert.Equal(t, license.PhaseLocked, e.svc.Snapshot().Eval.Phase)

	// The renewal was issued before the extension; it is accepted because it lasts longer.
	res, err = e.upload(renewal)
	require.NoError(t, err)
	assert.Equal(t, license.PhaseActive, res.Phase)
	ev = e.svc.Snapshot().Eval
	assert.Equal(t, "LIC-R", ev.Key())
	assert.Equal(t, 20, ev.MaxTargets)
	assert.NoError(t, e.svc.Allow(license.ClassChange))
}
