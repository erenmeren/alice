package jobs

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/license"
)

// Network discovery job types (A1, A5). The namespace is netdisco.*: discovery.schedule is the SSH-key target
// discovery task and stays as it is. A scan is read-only work (paused in lock) and runs once (a scan that failed is
// started again by a person or by the scope's schedule, never by the queue's backoff); at most two run at once in the
// whole installation (runner cap table). The schedule is a ReadOnly periodic task; retention is ClassAlways, so the
// cleanup also runs in lock.
func TestNetdiscoJobTypes(t *testing.T) {
	assert.Equal(t, "netdisco.scan", NetdiscoScan.Name, "the backup restore cancels jobs by this exact name")
	assert.Equal(t, "netdisco.schedule", NetdiscoSchedule.Name)
	assert.Equal(t, "netdisco.retention", NetdiscoRetention.Name)
	assert.Equal(t, license.ClassReadOnly, NetdiscoScan.Class)
	assert.Equal(t, license.ClassReadOnly, NetdiscoSchedule.Class, "a ClassChange periodic task would panic at start-up")
	assert.Equal(t, license.ClassAlways, NetdiscoRetention.Class, "cleanup runs in lock too")

	assert.Equal(t, 1, MaxAttemptsFor(NetdiscoScan))
	n, ok := MaxRunningFor(NetdiscoScan)
	assert.True(t, ok)
	assert.Equal(t, 2, n)
	assert.Equal(t, MaxConcurrentNetdiscoScans, n)
	types, limits := capTable()
	assert.Contains(t, types, NetdiscoScan.Name, "the claim query receives the scan's cap")
	for i, name := range types {
		if name == NetdiscoScan.Name {
			assert.Equal(t, 2, limits[i])
		}
	}
	for _, typ := range []Type{NetdiscoSchedule, NetdiscoRetention} {
		_, capped := MaxRunningFor(typ)
		assert.False(t, capped, typ.Name)
	}

	// The SSH-key target discovery task is untouched.
	assert.Equal(t, "discovery.schedule", DiscoverySchedule.Name)
	assert.Equal(t, license.ClassReadOnly, DiscoverySchedule.Class)
}

// One scan per scope at a time: the dedupe key of a scan job is "netdisco.scan:<scope id>" (A5).
func TestNetdiscoScanDedupeKey(t *testing.T) {
	scope := uuid.MustParse("0192a3b4-c5d6-7e8f-9012-3456789abcde")
	assert.Equal(t, "netdisco.scan:0192a3b4-c5d6-7e8f-9012-3456789abcde", NetdiscoScanDedupeKey(scope))
	assert.NotEqual(t, NetdiscoScanDedupeKey(scope), NetdiscoScanDedupeKey(uuid.New()))
}

// The types are registered (Task 8 of the network discovery plan), each with its literal name and class, so they can be
// queued and scheduled: the runner gets the scan's handler and the scheduler the two periodic tasks (internal/jobs/netdiscojobs,
// wired in cmd/alice). The web's job labels are read from these literal Register calls.
func TestNetdiscoTypesAreRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, typ := range Types() {
		names[typ.Name] = true
	}
	for _, typ := range []Type{NetdiscoScan, NetdiscoSchedule, NetdiscoRetention} {
		reg, ok := lookup(typ.Name)
		assert.True(t, ok, "%s is registered", typ.Name)
		assert.Equal(t, typ, reg, "%s is registered with its class", typ.Name)
		assert.True(t, names[typ.Name], "jobs.Types() lists %s", typ.Name)
	}
}
