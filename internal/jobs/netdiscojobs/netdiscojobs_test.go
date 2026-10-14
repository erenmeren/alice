package netdiscojobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/clock"
)

type allow struct{}

func (allow) Allow(license.Class) error { return nil }

// A build that forgot a dependency never starts: Register and the tasks panic.
func TestMissingDependenciesPanic(t *testing.T) {
	r := jobs.NewRunner(jobs.RunnerConfig{})
	assert.Panics(t, func() { Register(nil, Deps{}) })
	assert.Panics(t, func() { Register(r, Deps{License: allow{}, Clock: clock.Real{}}) }, "no pool")
	assert.Panics(t, func() { ScheduleTask(Deps{Clock: clock.Real{}}, time.Minute) })
	assert.Panics(t, func() { RetentionTask(Deps{}, time.Hour) })
	assert.False(t, r.Handles(jobs.NetdiscoScan))
}

func TestTasksHaveTheirTypes(t *testing.T) {
	d := Deps{Pool: nil, Clock: clock.Real{}}
	assert.Panics(t, func() { RetentionTask(d, time.Hour) })
	assert.Equal(t, license.ClassReadOnly, jobs.NetdiscoSchedule.Class, "the scheduler pauses the schedule in lock")
	assert.Equal(t, license.ClassAlways, jobs.NetdiscoRetention.Class, "retention runs in lock")
}

// The scanner's sentinel errors map onto the job: a scan that does not exist is not found, a scan another run holds is
// ALC-DSC-0004 (never retried), a database failure is unexpected (retryable, so the one attempt ends the job dead).
func TestScanErrorsBecomeJobFailures(t *testing.T) {
	h := newHandlers(Deps{})
	job := jobs.Job{Type: jobs.NetdiscoScan, Payload: map[string]string{PayloadScanID: uuid.NewString()}}
	for _, tc := range []struct {
		err    error
		class  jobs.FailureClass
		reason string
	}{
		{discovery.ErrScanNotFound, jobs.Permanent, "system.not_found"},
		{discovery.ErrScanBusy, jobs.Permanent, "discovery.scan_running"},
		{errors.New("connection refused"), jobs.Retryable, "internal.unexpected"},
	} {
		h.run = func(context.Context, discovery.Deps, uuid.UUID) error { return tc.err }
		res, err := h.scan(context.Background(), job, nil)
		assert.Nil(t, res)
		var f *jobs.Failure
		require.ErrorAs(t, err, &f)
		assert.Equal(t, tc.class, f.Class, tc.reason)
		assert.Equal(t, tc.reason, f.Reason)
	}
	h.run = func(context.Context, discovery.Deps, uuid.UUID) error { panic("never called") }
	_, err := h.scan(context.Background(), jobs.Job{Payload: map[string]string{}}, nil)
	var f *jobs.Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, "system.not_found", f.Reason)
}

// The handler hands the scanner the job's dependencies.
func TestScanDepsCarryTheJobsDependencies(t *testing.T) {
	d := Deps{License: allow{}, Clock: clock.Real{}, DatabaseURL: "postgres://db.internal/alice", Lease: time.Minute}
	got := newHandlers(d).scanDeps()
	assert.NotNil(t, got.Store)
	assert.Equal(t, d.License, got.License)
	assert.Equal(t, d.Clock, got.Clock)
	assert.Equal(t, d.DatabaseURL, got.DatabaseURL, "the scan policy refuses the database's hosts")
	assert.Equal(t, time.Minute, got.Lease)
}

// A tampered job's payload is not trusted: the end hook ends nothing for it (the orphan sweep ends its real scan).
func TestEndHookIgnoresATamperedJob(t *testing.T) {
	assert.NoError(t, newHandlers(Deps{}).ended(context.Background(), nil, jobs.JobEnd{Status: jobs.StatusDead, Reason: "job.tampered"}))
}

func TestMinutes(t *testing.T) {
	for in, want := range map[string]int{"00:00": 0, "23:59": 1439, "04:30": 270} {
		got, ok := minutes(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "4:30", "24:00", "12:60", "ab:cd", "12-30", "+1:30", "12:3x", "123:00"} {
		_, ok := minutes(in)
		assert.False(t, ok, in)
	}
}
