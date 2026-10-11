package backup_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/backup"
)

func TestAlarmAfter48Hours(t *testing.T) {
	setup := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	success := time.Date(2026, 10, 3, 2, 30, 0, 0, time.UTC)

	st := backup.State{SetupCompletedAt: setup, LastSuccessAt: success}
	assert.False(t, st.Alarm(success.Add(backup.AlarmAfter-time.Nanosecond)))
	assert.True(t, st.Alarm(success.Add(backup.AlarmAfter)), "exactly 48 hours")
	assert.True(t, st.Alarm(success.Add(100*time.Hour)))

	never := backup.State{SetupCompletedAt: setup}
	assert.False(t, never.Alarm(setup.Add(backup.AlarmAfter-time.Second)))
	assert.True(t, never.Alarm(setup.Add(backup.AlarmAfter)), "no success ever: counted from the setup completion")

	open := backup.State{}
	assert.False(t, open.Alarm(setup.Add(1000*time.Hour)), "never before setup is complete")
	assert.False(t, backup.State{LastSuccessAt: success}.Alarm(success.Add(100*time.Hour)), "never before setup is complete")
	assert.Equal(t, 48*time.Hour, backup.AlarmAfter)
}

func TestFailing(t *testing.T) {
	assert.False(t, backup.State{}.Failing())
	assert.True(t, backup.State{ConsecutiveFailures: 1}.Failing())
}
