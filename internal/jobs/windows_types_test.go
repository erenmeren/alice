package jobs

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/license"
)

// The Windows certificate cleanup (R62 W3 Ruling 13): removing certificates changes a server (refused and held in lock);
// the schedule only queues (paused in lock, as discovery.schedule). A failed cleanup runs once and mails nobody: the next
// day's run retries it.
func TestWindowsCleanupTypes(t *testing.T) {
	assert.Equal(t, inventory.JobWindowsCleanup, WindowsCleanup.Name)
	assert.Equal(t, license.ClassChange, WindowsCleanup.Class)
	assert.Equal(t, "windows.cleanup_schedule", WindowsCleanupSchedule.Name)
	assert.Equal(t, license.ClassReadOnly, WindowsCleanupSchedule.Class)
	assert.Equal(t, 1, MaxAttemptsFor(WindowsCleanup))
	assert.False(t, AlertsWhenExhausted(WindowsCleanup))
	assert.True(t, heldInLock(WindowsCleanup))
}
