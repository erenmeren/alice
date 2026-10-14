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

// The types are declared but not registered until their handlers exist (Task 8): a registered type without a handler
// makes checkWiring refuse to start the server, and an unregistered one cannot be queued or scheduled (ErrUnknownType),
// so nothing can enqueue a scan before the scanner exists. Task 8 registers them and turns this test around.
func TestNetdiscoTypesAreNotRegisteredBeforeTheirHandlers(t *testing.T) {
	for _, typ := range []Type{NetdiscoScan, NetdiscoSchedule, NetdiscoRetention} {
		_, ok := lookup(typ.Name)
		assert.False(t, ok, "%s is registered: register its handler (Task 8) and update this test", typ.Name)
	}
}
