package targetjobs

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
)

// stubInventory scripts the inventory side of the handlers; unset functions answer success.
type stubInventory struct {
	target       inventory.Target
	refErr       error
	refAfter     func(n int) (inventory.Target, error) // TargetRef calls after the first
	refCalls     int
	protected    []string
	protectedErr error
	okErr        error
	failErr      error
	failures     []string
	reconcileErr error
	discoveryErr error
	location     inventory.KeyLocation
	locationErr  error
	markErr      error
	removalErr   error
	removals     []string
	removalCtx   []error // ctx.Err() at each RecordRemovalFailure
}

func (s *stubInventory) TargetRef(_ context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error) {
	s.refCalls++
	t, err := s.target, s.refErr
	if s.refCalls > 1 && s.refAfter != nil {
		t, err = s.refAfter(s.refCalls)
	}
	return providers.TargetRef{ID: id, Name: t.Name, Kind: providers.KindLinuxSSH}, t, err
}
func (s *stubInventory) Credentials() providers.CredentialSource { return nil }
func (s *stubInventory) HostKeyStore() providers.HostKeyStore    { return nil }
func (s *stubInventory) PlatformKey(context.Context) (inventory.PlatformKey, error) {
	return inventory.PlatformKey{Fingerprint: "SHA256:own"}, nil
}
func (s *stubInventory) ProtectedFingerprints(context.Context) ([]string, error) {
	return s.protected, s.protectedErr
}
func (s *stubInventory) RecordConnectionOK(context.Context, uuid.UUID, providers.ConnectionReport) error {
	return s.okErr
}
func (s *stubInventory) RecordConnectionFailure(_ context.Context, _ uuid.UUID, reason string) error {
	s.failures = append(s.failures, reason)
	return s.failErr
}
func (s *stubInventory) Reconcile(context.Context, uuid.UUID, providers.DiscoveryResult) (inventory.ReconcileSummary, error) {
	return inventory.ReconcileSummary{Keys: 1}, s.reconcileErr
}
func (s *stubInventory) RequestDiscovery(context.Context, inventory.Actor, uuid.UUID) (uuid.UUID, error) {
	return uuid.New(), s.discoveryErr
}
func (s *stubInventory) KeyLocation(context.Context, uuid.UUID) (inventory.KeyLocation, error) {
	return s.location, s.locationErr
}
func (s *stubInventory) MarkKeyRemoved(context.Context, uuid.UUID, audit.Actor, providers.AuthKeyResult) error {
	return s.markErr
}
func (s *stubInventory) RecordRemovalFailure(ctx context.Context, _ uuid.UUID, _ audit.Actor, reason string) error {
	s.removals = append(s.removals, reason)
	s.removalCtx = append(s.removalCtx, ctx.Err())
	return s.removalErr
}

// closeErrProvider opens sessions whose Close fails.
type closeErrProvider struct{ *fake.Provider }

type closeErrSession struct{ providers.Session }

func (closeErrSession) Close() error { return errors.New("close failed") }

func (p closeErrProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return closeErrSession{s}, nil
}

type unit struct {
	inv  *stubInventory
	prov *fake.Provider
	h    *handlers
	logs *bytes.Buffer
}

func newUnit(t *testing.T, register bool, closeFails bool) *unit {
	t.Helper()
	u := &unit{inv: &stubInventory{target: inventory.Target{Name: "web-01", Status: inventory.StatusOK}}, logs: &bytes.Buffer{},
		prov: fake.New(providers.KindLinuxSSH)}
	reg := providers.NewRegistry()
	if register {
		if closeFails {
			reg.Register(closeErrProvider{u.prov})
		} else {
			reg.Register(u.prov)
		}
	}
	reg.Freeze()
	u.h = newHandlers(Deps{Inventory: u.inv, Registry: reg, Clock: clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)),
		Log: slog.New(slog.NewTextHandler(u.logs, nil))})
	return u
}

func reason(t *testing.T, err error) (string, jobs.FailureClass) {
	t.Helper()
	var f *jobs.Failure
	require.ErrorAs(t, err, &f)
	return f.Reason, f.Class
}

var testJob = jobs.Job{ID: uuid.New(), Type: jobs.TargetTestConnection, TargetID: uuid.New()}

func TestRegisterWithoutLoggerDiscards(t *testing.T) {
	h := newHandlers(Deps{})
	require.NotNil(t, h.d.Log)
	h.d.Log.Info("nothing is written")
}

func TestOpenFailures(t *testing.T) {
	u := newUnit(t, true, false)
	u.inv.refErr = inventory.ErrNotFound
	_, err := u.h.testConnection(context.Background(), testJob, nil)
	r, c := reason(t, err)
	assert.Equal(t, "system.not_found", r)
	assert.Equal(t, jobs.Permanent, c)

	u = newUnit(t, true, false)
	u.inv.refErr = errors.New("database down")
	_, err = u.h.discover(context.Background(), testJob, nil)
	r, c = reason(t, err)
	assert.Equal(t, "internal.unexpected", r)
	assert.Equal(t, jobs.Retryable, c)

	u = newUnit(t, true, false)
	u.inv.target.Status = inventory.StatusPendingHostKey
	_, err = u.h.discover(context.Background(), testJob, nil)
	r, _ = reason(t, err)
	assert.Equal(t, "target.host_key_unconfirmed", r)
	assert.Zero(t, u.prov.Count("Open"))

	u = newUnit(t, false, false)
	_, err = u.h.testConnection(context.Background(), testJob, nil)
	r, c = reason(t, err)
	assert.Equal(t, "internal.unexpected", r)
	assert.Equal(t, jobs.Permanent, c, "a missing provider does not appear by retrying")

	u = newUnit(t, true, false)
	u.prov.Configure(func(c *fake.Config) { c.OpenErr = providers.NewError("ssh.unreachable", true, nil, nil) })
	u.inv.failErr = errors.New("database down")
	_, err = u.h.testConnection(context.Background(), testJob, nil)
	r, c = reason(t, err)
	assert.Equal(t, "ssh.unreachable", r)
	assert.Equal(t, jobs.Retryable, c)
	assert.Equal(t, []string{"ssh.unreachable"}, u.inv.failures)
	assert.Contains(t, u.logs.String(), "could not record a connection failure")

	u = newUnit(t, true, false)
	u.prov.Configure(func(c *fake.Config) { c.OpenErr = errors.New("not a provider error") })
	_, err = u.h.testConnection(context.Background(), testJob, nil)
	r, _ = reason(t, err)
	assert.Equal(t, "internal.unexpected", r)
	assert.Empty(t, u.inv.failures, "only provider reasons are recorded on the target")
}

func TestConnectionTestBranches(t *testing.T) {
	u := newUnit(t, true, false)
	u.prov.Configure(func(c *fake.Config) { c.TestErr = providers.NewError("ssh.helper_outdated", false, nil, nil) })
	_, err := u.h.testConnection(context.Background(), testJob, nil)
	r, c := reason(t, err)
	assert.Equal(t, "ssh.helper_outdated", r)
	assert.Equal(t, jobs.Permanent, c)
	assert.Equal(t, []string{"ssh.helper_outdated"}, u.inv.failures)

	u = newUnit(t, true, false)
	u.inv.okErr = errors.New("database down")
	_, err = u.h.testConnection(context.Background(), testJob, nil)
	r, c = reason(t, err)
	assert.Equal(t, "internal.unexpected", r)
	assert.Equal(t, jobs.Retryable, c)

	// Never scanned, but still not connected after the report (no pinned key): no discovery.
	u = newUnit(t, true, false)
	u.inv.refAfter = func(int) (inventory.Target, error) {
		return inventory.Target{Status: inventory.StatusPendingHostKey}, nil
	}
	out, err := u.h.testConnection(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.NotContains(t, out, "discovery_job_id")

	// The re-read fails: the test still succeeded, no discovery is queued.
	u = newUnit(t, true, false)
	u.inv.refAfter = func(int) (inventory.Target, error) { return inventory.Target{}, errors.New("database down") }
	out, err = u.h.testConnection(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.NotContains(t, out, "discovery_job_id")

	// The discovery cannot be queued: logged, the test still succeeded.
	u = newUnit(t, true, false)
	u.inv.target.Status = inventory.StatusChecking
	u.inv.refAfter = func(int) (inventory.Target, error) { return inventory.Target{Status: inventory.StatusOK}, nil }
	u.inv.discoveryErr = inventory.ErrHostKeyChanged
	out, err = u.h.testConnection(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.NotContains(t, out, "discovery_job_id")
	assert.Contains(t, u.logs.String(), "could not queue the first discovery")

	// A connected, never scanned target gets its first discovery.
	u = newUnit(t, true, true)
	out, err = u.h.testConnection(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.Contains(t, out, "discovery_job_id")
	assert.Contains(t, u.logs.String(), "closing a provider session failed")
}

func TestDiscoverBranches(t *testing.T) {
	u := newUnit(t, true, false)
	u.inv.reconcileErr = inventory.ErrNotFound
	_, err := u.h.discover(context.Background(), testJob, nil)
	r, c := reason(t, err)
	assert.Equal(t, "system.not_found", r)
	assert.Equal(t, jobs.Permanent, c)

	u = newUnit(t, true, false)
	u.inv.reconcileErr = errors.New("database down")
	_, err = u.h.discover(context.Background(), testJob, nil)
	r, c = reason(t, err)
	assert.Equal(t, "internal.unexpected", r)
	assert.Equal(t, jobs.Retryable, c)

	u = newUnit(t, true, false)
	u.prov.Configure(func(c *fake.Config) { c.Discovery.Partial = true })
	out, err := u.h.discover(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"key_count": 1, "new_count": 0, "missing_count": 0, "partial": true}, out)
}

func removalJob(target uuid.UUID, loc inventory.KeyLocation) jobs.Job {
	return jobs.Job{ID: uuid.New(), Type: jobs.SSHKeyRemove, TargetID: target, Payload: map[string]string{
		"location_id": loc.ID.String(), "fingerprint": loc.Fingerprint, "os_user": loc.OSUser, "file_path": loc.FilePath,
		"confirm_last_root_key": "false"}}
}

func removalUnit(t *testing.T) (*unit, jobs.Job) {
	t.Helper()
	u := newUnit(t, true, false)
	target := uuid.New()
	u.inv.protected = []string{"SHA256:own"}
	u.inv.location = inventory.KeyLocation{ID: uuid.New(), TargetID: target, Fingerprint: "SHA256:dep", OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"}
	return u, removalJob(target, u.inv.location)
}

func TestRemoveKeyRefusesBeforeConnecting(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		edit   func(u *unit, j *jobs.Job)
		reason string
		class  jobs.FailureClass
	}{
		"bad location id":  {func(_ *unit, j *jobs.Job) { j.Payload["location_id"] = "nope" }, "sshkey.not_removable", jobs.Permanent},
		"unknown location": {func(u *unit, _ *jobs.Job) { u.inv.locationErr = inventory.ErrNotFound }, "sshkey.not_removable", jobs.Permanent},
		"database down":    {func(u *unit, _ *jobs.Job) { u.inv.locationErr = errors.New("down") }, "internal.unexpected", jobs.Retryable},
		"other user":       {func(_ *unit, j *jobs.Job) { j.Payload["os_user"] = "root" }, "sshkey.not_removable", jobs.Permanent},
		"other file":       {func(_ *unit, j *jobs.Job) { j.Payload["file_path"] = "/root/.ssh/authorized_keys" }, "sshkey.not_removable", jobs.Permanent},
		"other target":     {func(_ *unit, j *jobs.Job) { j.TargetID = uuid.New() }, "sshkey.not_removable", jobs.Permanent},
		"other key":        {func(_ *unit, j *jobs.Job) { j.Payload["fingerprint"] = "SHA256:x" }, "sshkey.not_removable", jobs.Permanent},
		"protected unread": {func(u *unit, _ *jobs.Job) { u.inv.protectedErr = errors.New("down") }, "internal.unexpected", jobs.Retryable},
		"no platform key":  {func(u *unit, _ *jobs.Job) { u.inv.protected = nil }, "internal.unexpected", jobs.Retryable},
		"connection key": {func(u *unit, _ *jobs.Job) { u.inv.location.IsAliceConnectionKey = true },
			"sshkey.own_key_protected", jobs.Permanent},
		"rotation overlap": {func(u *unit, _ *jobs.Job) { u.inv.protected = append(u.inv.protected, "SHA256:dep") },
			"sshkey.own_key_protected", jobs.Permanent},
		"changed host key": {func(u *unit, _ *jobs.Job) { u.inv.target.Status = inventory.StatusHostKeyChanged },
			"target.host_key_changed", jobs.Permanent},
	} {
		t.Run(name, func(t *testing.T) {
			u, j := removalUnit(t)
			tc.edit(u, &j)
			_, err := u.h.removeKey(ctx, j, nil)
			r, c := reason(t, err)
			assert.Equal(t, tc.reason, r)
			assert.Equal(t, tc.class, c)
			assert.Zero(t, u.prov.Count("Open"))
		})
	}
}

func TestRemoveKeyBookkeeping(t *testing.T) {
	ctx := context.Background()
	u, j := removalUnit(t)
	now := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	u.inv.location.RemovedAt = &now
	out, err := u.h.removeKey(ctx, j, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"already_removed": true}, out)
	assert.Zero(t, u.prov.Count("Open"))

	u, j = removalUnit(t)
	u.inv.markErr = errors.New("database down")
	u.prov.Configure(func(c *fake.Config) {
		c.RemoveResult = providers.AuthKeyResult{Changed: true, Removed: 1, Verified: true}
	})
	_, err = u.h.removeKey(ctx, j, nil)
	r, c := reason(t, err)
	assert.Equal(t, "internal.unexpected", r)
	assert.Equal(t, jobs.Retryable, c, "the change is idempotent: a retry finds the key absent")

	u, j = removalUnit(t)
	u.inv.removalErr = errors.New("database down")
	u.inv.location.IsAliceConnectionKey = true
	_, err = u.h.removeKey(ctx, j, nil)
	require.Error(t, err)
	assert.Contains(t, u.logs.String(), "could not audit a failed key removal")

	// An Open failure is audited on the key with the job's reason.
	u, j = removalUnit(t)
	u.prov.Configure(func(c *fake.Config) { c.OpenErr = providers.NewError("ssh.auth_failed", false, nil, nil) })
	_, err = u.h.removeKey(ctx, j, nil)
	r, _ = reason(t, err)
	assert.Equal(t, "ssh.auth_failed", r)
	assert.Equal(t, []string{"ssh.auth_failed"}, u.inv.removals)
	assert.Equal(t, []string{"ssh.auth_failed"}, u.inv.failures)

	// The change request carries every protected fingerprint and the root confirmation.
	u, j = removalUnit(t)
	u.inv.protected = []string{"SHA256:own", "SHA256:old"}
	j.Payload["confirm_last_root_key"] = "true"
	_, err = u.h.removeKey(ctx, j, nil)
	require.NoError(t, err)
	var change providers.AuthKeyChange
	for _, c := range u.prov.Calls() {
		if c.Method == "RemoveAuthorizedKey" {
			change = c.Change
		}
	}
	assert.Equal(t, providers.AuthKeyChange{OperationID: j.ID, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys",
		Fingerprint: "SHA256:dep", ProtectedFingerprints: []string{"SHA256:own", "SHA256:old"}, AllowLastRootKey: true}, change)
}

// A retryable failure before the write is retried; an unexpected error is too.
func TestRemoveKeyFailureClasses(t *testing.T) {
	ctx := context.Background()
	u, j := removalUnit(t)
	u.prov.Configure(func(c *fake.Config) { c.RemoveErr = errors.New("not a provider error") })
	_, err := u.h.removeKey(ctx, j, nil)
	r, c := reason(t, err)
	assert.Equal(t, "internal.unexpected", r)
	assert.Equal(t, jobs.Retryable, c)
	assert.Equal(t, []string{"internal.unexpected"}, u.inv.removals)
	assert.Empty(t, u.inv.failures)

	u, j = removalUnit(t)
	u.prov.Configure(func(c *fake.Config) {
		c.RemoveResult = providers.AuthKeyResult{Changed: true}
		c.RemoveErr = providers.NewError("ssh.protocol_error", false, nil, map[string]string{"subcommand": "authkeys-write"})
	})
	out, err := u.h.removeKey(ctx, j, nil)
	r, c = reason(t, err)
	assert.Equal(t, "ssh.protocol_error", r)
	assert.Equal(t, jobs.NeedsAttention, c)
	assert.Equal(t, map[string]any{"changed": true, "removed": 0, "verified": false}, out)
}

func TestWriteTrackerForwardsSteps(t *testing.T) {
	var got []string
	w := &writeTracker{next: stepFunc(func(name string, s providers.StepStatus) { got = append(got, name+":"+string(s)) })}
	w.Step("read", providers.StepStarted, nil)
	assert.False(t, w.wrote)
	w.Step("write", providers.StepFailed, nil)
	assert.False(t, w.wrote, "only a started write counts")
	w.Step("write", providers.StepStarted, nil)
	assert.True(t, w.wrote)
	assert.Equal(t, []string{"read:started", "write:failed", "write:started"}, got)
	(&writeTracker{}).Step("write", providers.StepStarted, nil) // no recorder: nothing to forward
}

type stepFunc func(name string, s providers.StepStatus)

func (f stepFunc) Step(name string, s providers.StepStatus, _ map[string]string) { f(name, s) }

// The failure audit is written even when the job's context ended (lost lease, shutdown).
func TestRemovalFailureIsAuditedAfterCancel(t *testing.T) {
	u, j := removalUnit(t)
	u.inv.location.IsAliceConnectionKey = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := u.h.removeKey(ctx, j, nil)
	require.Error(t, err)
	assert.Equal(t, []string{"sshkey.own_key_protected"}, u.inv.removals)
	assert.Equal(t, []error{nil}, u.inv.removalCtx)
}

func TestRemoveUnverifiedIsNotRecordedAsRemoved(t *testing.T) {
	u, j := removalUnit(t)
	u.inv.markErr = errors.New("must not be called")
	u.prov.Configure(func(c *fake.Config) { c.RemoveResult = providers.AuthKeyResult{Changed: true, Removed: 1} })
	out, err := u.h.removeKey(context.Background(), j, nil)
	r, c := reason(t, err)
	assert.Equal(t, "sshkey.verify_failed", r)
	assert.Equal(t, jobs.NeedsAttention, c)
	assert.Equal(t, map[string]any{"changed": true, "removed": 1, "verified": false}, out)
	assert.Equal(t, []string{"sshkey.verify_failed"}, u.inv.removals)
}
