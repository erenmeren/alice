//go:build integration

package targetjobs_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/providers/fake"
)

const day = 24 * time.Hour

// schedule runs the discovery scheduler once and returns how many jobs it queued.
func (e *env) schedule() int {
	e.t.Helper()
	n, err := e.inv.ScheduleDiscovery(e.ctx)
	require.NoError(e.t, err)
	return n
}

// R37 item 13: a scheduled discovery that fails without changing the target's status (an
// outdated helper keeps the target "ok") is not queued again every minute: the next one waits for
// the next discovery interval.
func TestFailingScheduledDiscoveryRunsOncePerInterval(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t))
	e.prov.Configure(func(c *fake.Config) { c.DiscoverErr = providers.NewError("ssh.helper_outdated", false, nil, nil) })
	discovers := e.prov.Count("Discover")

	e.clock.Advance(day)
	require.Equal(t, 1, e.schedule())
	e.drain()
	assert.Equal(t, discovers+1, e.prov.Count("Discover"))
	assert.Equal(t, inventory.StatusOK, e.status(tg.ID), "the failure leaves the status alone")

	for range 3 {
		e.clock.Advance(time.Minute)
		assert.Zero(t, e.schedule(), "a failed scheduled discovery is not repeated within its interval")
		e.drain()
	}
	assert.Equal(t, discovers+1, e.prov.Count("Discover"))

	e.clock.Advance(day)
	assert.Equal(t, 1, e.schedule(), "the next interval queues the next discovery")
}

// A discovery that succeeds after a transient failure moves the target back to "ok" (with its
// last success time), so the nightly schedule keeps running.
func TestSuccessfulDiscoveryRestoresAnUnreachableTarget(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t))
	e.prov.Configure(func(c *fake.Config) { c.DiscoverErr = providers.NewError("ssh.unreachable", true, nil, nil) })
	scan, err := e.inv.RequestDiscovery(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	e.drain()
	require.Equal(t, jobs.StatusQueued, e.job(scan).Status)
	require.Equal(t, inventory.StatusUnreachable, e.status(tg.ID))

	e.prov.Configure(func(c *fake.Config) { c.DiscoverErr = nil })
	e.clock.Advance(time.Minute)
	e.drain()
	require.Equal(t, jobs.StatusSucceeded, e.job(scan).Status)
	got, err := e.inv.GetTarget(e.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusOK, got.Status)
	assert.Empty(t, got.LastErrorCode)
	require.NotNil(t, got.LastSuccessAt)
	assert.Equal(t, e.clock.Now().UTC(), *got.LastSuccessAt)
	assert.Equal(t, 1, countRows(t, e, `SELECT count(*) FROM audit_log WHERE action = 'target.status_changed'
  AND details->>'from_status' = 'unreachable' AND details->>'to_status' = 'ok' AND details->>'reason' = 'discovery_ok'`))

	e.clock.Advance(day)
	assert.Equal(t, 1, e.schedule(), "the restored target is scheduled again")
}

// A removal that succeeds also proves the connection: an unreachable target is "ok" again.
func TestSuccessfulRemovalRestoresAnUnreachableTarget(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t), key("deploy", "/home/deploy/.ssh/authorized_keys", 1, "SHA256:dep"))
	e.prov.Configure(func(c *fake.Config) {
		c.RemoveResult = providers.AuthKeyResult{Changed: true, Removed: 1, Verified: true}
	})
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET status = 'unreachable', last_error_code = 'ssh.timeout' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	jobID, err := e.inv.RequestKeyRemoval(e.ctx, e.admin, locationOf(t, e, tg.ID, "SHA256:dep").ID, false)
	require.NoError(t, err)
	e.drain()
	require.Equal(t, jobs.StatusSucceeded, e.job(jobID).Status)
	got, err := e.inv.GetTarget(e.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusOK, got.Status)
	assert.Empty(t, got.LastErrorCode)
	assert.Equal(t, 1, countRows(t, e, `SELECT count(*) FROM audit_log WHERE action = 'target.status_changed'
  AND details->>'to_status' = 'ok' AND details->>'reason' = 'removal_ok'`))
}

// A success never leaves a status that needs a person: authentication failures and changed host
// keys are not cleared by a discovery or a removal.
func TestSuccessKeepsStatusesThatNeedAPerson(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t))
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET status = 'auth_failed', last_error_code = 'ssh.auth_failed' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	_, err = e.inv.Reconcile(e.ctx, tg.ID, providers.DiscoveryResult{})
	require.NoError(t, err)
	got, err := e.inv.GetTarget(e.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusAuthFailed, got.Status)
	assert.Equal(t, "ssh.auth_failed", got.LastErrorCode)
}

// The ruling on B-2: an unreachable server is tested again once per discovery interval (never
// every minute), and once it answers it is scanned at once and scheduled as usual. Statuses that
// need a person (auth_failed, host_key_changed) are never retried automatically.
func TestUnreachableTargetIsRetestedOncePerInterval(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t))
	e.prov.Configure(func(c *fake.Config) { c.TestErr = providers.NewError("ssh.unreachable", true, nil, nil) })
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET status = 'unreachable', last_error_code = 'ssh.unreachable' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	assert.Zero(t, e.schedule(), "not due before its interval")

	e.clock.Advance(day)
	require.Equal(t, 1, e.schedule())
	list, _, err := e.queue.List(e.ctx, jobs.ListFilter{TargetID: tg.ID, Status: jobs.StatusQueued})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, jobs.TargetTestConnection.Name, list[0].Type)
	assert.Equal(t, string(jobs.KindScheduled), list[0].Kind)
	tests := e.prov.Count("TestConnection")
	e.drain()
	assert.Equal(t, tests+1, e.prov.Count("TestConnection"))
	assert.Equal(t, inventory.StatusUnreachable, e.status(tg.ID))
	for range 3 {
		e.clock.Advance(time.Minute)
		assert.Zero(t, e.schedule(), "a failed re-test waits for the next interval")
	}

	e.prov.Configure(func(c *fake.Config) { c.TestErr = nil })
	discovers := e.prov.Count("Discover")
	e.clock.Advance(day)
	require.Equal(t, 1, e.schedule())
	e.drain()
	assert.Equal(t, inventory.StatusOK, e.status(tg.ID))
	assert.Equal(t, discovers+1, e.prov.Count("Discover"), "a server that answers again is scanned at once")

	for _, status := range []string{inventory.StatusAuthFailed, inventory.StatusHostKeyChanged} {
		_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET status = $2 WHERE id = $1", tg.ID, status)
		require.NoError(t, err)
		e.clock.Advance(3 * day)
		assert.Zero(t, e.schedule(), "%s is never retried automatically", status)
	}
}

// Task 17 carry: after a re-pin the target is connected again and the schedule resumes.
func TestScheduleDiscoveryResumesAfterRepin(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.confirmed(hostKey(t))
	e.prov.Configure(func(c *fake.Config) { c.PresentedKey = hostKey(t) })
	_, err := e.inv.RequestTest(e.ctx, e.admin, tg.ID)
	require.NoError(t, err)
	e.drain()
	require.Equal(t, inventory.StatusHostKeyChanged, e.status(tg.ID))
	e.clock.Advance(day)
	assert.Zero(t, e.schedule())

	recs, err := e.inv.ListHostKeys(e.ctx, tg.ID)
	require.NoError(t, err)
	var observed inventory.HostKeyRecord
	for _, r := range recs {
		if r.Status == "observed" {
			observed = r
		}
	}
	_, err = e.inv.RepinHostKey(e.ctx, e.admin, tg.ID, observed.ID, observed.Fingerprint, "Server reinstalled, ticket CHG-1042")
	require.NoError(t, err)
	e.drain()
	require.Equal(t, inventory.StatusOK, e.status(tg.ID))
	e.clock.Advance(day)
	assert.Equal(t, 1, e.schedule(), "the re-pinned target is scheduled again")
}
