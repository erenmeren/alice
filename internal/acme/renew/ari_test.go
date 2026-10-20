package renew

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The random time in the CA's window (RFC 9773 section 4.2; R50): inside the part of the window not later than the local
// rule, chosen once and kept while it stays inside, chosen again when the window moves or shrinks past it.
func TestChooseARIRenewAt(t *testing.T) {
	nb := t0.Add(-10 * day)
	local := nb.Add(60 * day) // a 90-day certificate: t0 + 50 d
	w := &Window{Start: t0.Add(40 * day), End: t0.Add(42 * day)}
	for _, rnd := range []func(int64) int64{first, last, func(n int64) int64 { return n / 2 }, nil} {
		got := ChooseARIRenewAt(nil, w, nb, local, rnd)
		if assert.NotNil(t, got) {
			assert.False(t, got.Before(w.Start), "inside the window")
			assert.True(t, got.Before(w.End), "inside the window")
		}
	}
	assert.Equal(t, w.Start, *ChooseARIRenewAt(nil, w, nb, local, first))
	assert.Equal(t, w.End.Add(-time.Second), *ChooseARIRenewAt(nil, w, nb, local, last))
	assert.Equal(t, w.Start, *ChooseARIRenewAt(nil, w, nb, local, func(int64) int64 { return -7 }), "a bad answer of the source is bounded")

	// Stable: a stored time inside the window is kept, whatever the randomness says.
	stored := w.Start.Add(30 * time.Hour)
	never := func(int64) int64 { t.Fatal("a stored time inside the window is not chosen again"); return 0 }
	for range 3 {
		assert.Equal(t, stored, *ChooseARIRenewAt(&stored, w, nb, local, never))
	}
	grown := &Window{Start: w.Start.Add(-day), End: w.End.Add(day)}
	assert.Equal(t, stored, *ChooseARIRenewAt(&stored, grown, nb, local, never), "a window that grows keeps the time")

	// The window moves (earlier: a revocation at the CA) or shrinks past the stored time: chosen again inside it.
	moved := &Window{Start: t0.Add(-2 * time.Hour), End: t0.Add(-time.Hour)}
	if got := ChooseARIRenewAt(&stored, moved, nb, local, last); assert.NotNil(t, got) {
		assert.Equal(t, moved.End.Add(-time.Second), *got)
	}
	shrunk := &Window{Start: w.Start, End: w.Start.Add(time.Hour)}
	if got := ChooseARIRenewAt(&stored, shrunk, nb, local, first); assert.NotNil(t, got) {
		assert.Equal(t, shrunk.Start, *got)
	}

	// Never later than the local rule: a window that runs past it is cut at it; one that starts at or after it is not
	// used (ARI never pushes a renewal later), nor is one that ends at or before the certificate began.
	across := &Window{Start: local.Add(-day), End: local.Add(5 * day)}
	assert.Equal(t, local.Add(-time.Second), *ChooseARIRenewAt(nil, across, nb, local, last))
	late := local.Add(day)
	assert.Equal(t, local.Add(-time.Second), *ChooseARIRenewAt(&late, across, nb, local, last), "a stored time past the local rule is chosen again")
	assert.Nil(t, ChooseARIRenewAt(nil, &Window{Start: local, End: local.Add(day)}, nb, local, first))
	assert.Nil(t, ChooseARIRenewAt(&stored, &Window{Start: nb.Add(-2 * day), End: nb}, nb, local, first))
	assert.Nil(t, ChooseARIRenewAt(&stored, nil, nb, local, first), "no window: the local rule alone")
}

// Decide chooses the time once and says when it must be stored; the stored time is used on the next call unchanged.
func TestDecideKeepsTheChosenARITime(t *testing.T) {
	in := issued(t0.Add(-10*day), 90*day)
	in.ARIWindow = &Window{Start: t0.Add(5 * day), End: t0.Add(9 * day)}
	d := Decide(in)
	if !assert.NotNil(t, d.ARIRenewAt) {
		return
	}
	assert.True(t, d.StoreARIRenewAt, "a new choice is stored")
	assert.Equal(t, *d.ARIRenewAt, d.RenewAt)
	assert.Equal(t, ReasonNotDue, d.Reason)
	assert.False(t, d.ARIRenewAt.Before(in.ARIWindow.Start))
	assert.True(t, d.ARIRenewAt.Before(in.ARIWindow.End))

	// A restart or the next run reads the stored time: the same time, nothing to store.
	in.ARIRenewAt = d.ARIRenewAt
	for range 5 {
		again := Decide(in)
		assert.Equal(t, *d.ARIRenewAt, again.RenewAt)
		assert.False(t, again.StoreARIRenewAt)
	}

	// The time comes: ordered on the CA's word.
	in.Now = *d.ARIRenewAt
	assert.Equal(t, Order, Decide(in).Action)
	assert.Equal(t, ReasonDueARI, Decide(in).Reason)
	in.Now = t0

	// The CA moves the window into the past (a mass revocation): chosen again, due now.
	in.ARIWindow = &Window{Start: t0.Add(-3 * time.Hour), End: t0.Add(-time.Hour)}
	moved := Decide(in)
	assert.Equal(t, Order, moved.Action)
	assert.Equal(t, ReasonDueARI, moved.Reason)
	assert.True(t, moved.StoreARIRenewAt)
	if assert.NotNil(t, moved.ARIRenewAt) {
		assert.True(t, moved.ARIRenewAt.Before(in.ARIWindow.End))
	}

	// No window any more (the CA stopped offering renewal information): the local rule exactly, the stored time cleared.
	in.ARIWindow = nil
	gone := Decide(in)
	assert.Nil(t, gone.ARIRenewAt)
	assert.True(t, gone.StoreARIRenewAt)
	assert.Equal(t, RenewAt(in.NotBefore, in.NotAfter, 30), gone.RenewAt)
	in.ARIRenewAt = nil
	assert.False(t, Decide(in).StoreARIRenewAt, "nothing stored, nothing to clear")

	// Nothing is chosen or written in lock.
	in.ARIWindow = &Window{Start: t0.Add(5 * day), End: t0.Add(9 * day)}
	in.Locked = true
	assert.False(t, Decide(in).StoreARIRenewAt)
	assert.Nil(t, Decide(in).ARIRenewAt)
}

// RenewalTime is the time shown: the stored time chosen in the CA's window while it applies, else the local rule.
func TestRenewalTime(t *testing.T) {
	nb, na := t0.Add(-10*day), t0.Add(80*day)
	local := RenewAt(nb, na, 30)
	w := &Window{Start: t0.Add(5 * day), End: t0.Add(9 * day)}
	chosen := t0.Add(6 * day)
	got, fromCA := RenewalTime(&chosen, w, nb, na, 30)
	assert.Equal(t, chosen, got)
	assert.True(t, fromCA)
	for _, tc := range []struct {
		name   string
		stored *time.Time
		w      *Window
	}{
		{"nothing chosen", nil, w},
		{"no window", &chosen, nil},
		{"the stored time is outside the window", at(20 * day), w},
		{"the window starts after the local rule", &chosen, &Window{Start: local, End: local.Add(day)}},
	} {
		got, fromCA := RenewalTime(tc.stored, tc.w, nb, na, 30)
		assert.Equal(t, local, got, tc.name)
		assert.False(t, fromCA, tc.name)
	}
}
