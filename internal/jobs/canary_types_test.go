package jobs

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/license"
)

// Canary deployment (R65, decision 17): the advance and the rounds run in every licence state; a round runs once and
// mails nobody (the advance queues the next one).
func TestCanaryTypes(t *testing.T) {
	assert.Equal(t, inventory.JobCanaryAdvance, CanaryAdvance.Name)
	assert.Equal(t, license.ClassAlways, CanaryAdvance.Class)
	assert.Equal(t, inventory.JobCanaryCheck, CanaryCheck.Name)
	assert.Equal(t, license.ClassAlways, CanaryCheck.Class)
	assert.Equal(t, 1, MaxAttemptsFor(CanaryCheck))
	assert.False(t, AlertsWhenExhausted(CanaryCheck))
	assert.False(t, heldInLock(CanaryCheck))
	got, ok := lookup("canary.check")
	assert.True(t, ok)
	assert.Equal(t, CanaryCheck, got)
}
