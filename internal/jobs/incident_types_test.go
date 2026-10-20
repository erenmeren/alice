package jobs

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/license"
)

// The incident task is the inventory's name and runs in every license state (the inventory asks the gate before it
// deploys, orders or revokes).
func TestIncidentAdvanceType(t *testing.T) {
	assert.Equal(t, inventory.JobIncidentAdvance, IncidentAdvance.Name)
	assert.Equal(t, license.ClassAlways, IncidentAdvance.Class)
	got, ok := lookup("incident.advance")
	assert.True(t, ok)
	assert.Equal(t, IncidentAdvance, got)
}
