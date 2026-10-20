package jobs

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/license"
)

// The drift work (R52): observing only reads managed systems (paused in lock); the automatic repair is continuity work
// as an automatic deployment is (R44). A failed observation runs once and mails nobody: it is on the locations.
func TestDriftTypes(t *testing.T) {
	assert.Equal(t, inventory.JobDriftObserve, DriftObserve.Name)
	assert.Equal(t, license.ClassReadOnly, DriftSchedule.Class)
	assert.Equal(t, license.ClassReadOnly, DriftObserve.Class)
	assert.Equal(t, license.ClassContinuity, DriftRepair.Class)
	assert.Equal(t, 1, MaxAttemptsFor(DriftObserve))
	assert.False(t, AlertsWhenExhausted(DriftObserve))
	got, ok := lookup("drift.repair")
	assert.True(t, ok)
	assert.Equal(t, DriftRepair, got)
}
