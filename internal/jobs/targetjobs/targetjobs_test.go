package targetjobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	reconciled   []providers.DiscoveryResult
	claims       []inventory.Claim // the claim on each Reconcile's context
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
	kind := providers.KindLinuxSSH
	if k, ok := providers.KindForTargetType(t.Type); ok {
		kind = k
	}
	return providers.TargetRef{ID: id, Name: t.Name, Kind: kind}, t, err
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
func (s *stubInventory) Reconcile(ctx context.Context, _ uuid.UUID, res providers.DiscoveryResult) (inventory.ReconcileSummary, error) {
	s.reconciled = append(s.reconciled, res)
	c, _ := inventory.ClaimFrom(ctx)
	s.claims = append(s.claims, c)
	sum := inventory.ReconcileSummary{Keys: 1}
	if res.WebServer != nil {
		sum.Certificates, sum.Locations, sum.NewLocations = 2, 3, 1
	}
	return sum, s.reconcileErr
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

// envProvider records the Env of every Open.
type envProvider struct {
	*fake.Provider
	envs *[]providers.Env
}

func (p envProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	*p.envs = append(*p.envs, e)
	return p.Provider.Open(ctx, t, c, e)
}

// A-4 (R37 item 21): the explicit connection test asks for a fresh connection; scans and removals
// may reuse one.
func TestOnlyTheConnectionTestAsksForAFreshConnection(t *testing.T) {
	var envs []providers.Env
	prov := fake.New(providers.KindLinuxSSH)
	reg := providers.NewRegistry()
	reg.Register(envProvider{prov, &envs})
	reg.Freeze()
	inv := &stubInventory{target: inventory.Target{Name: "web-01", Status: inventory.StatusOK, LastDiscoveryAt: &time.Time{}}}
	h := newHandlers(Deps{Inventory: inv, Registry: reg, Clock: clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))})
	_, err := h.testConnection(context.Background(), testJob, nil)
	require.NoError(t, err)
	_, err = h.discover(context.Background(), testJob, nil)
	require.NoError(t, err)
	require.Len(t, envs, 2)
	assert.True(t, envs[0].FreshConnection, "test connection")
	assert.False(t, envs[1].FreshConnection, "discovery")
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

// B1 M1: the scan is stored under the discovery job's claim, and a run that lost its job stops as
// a stale run without anything written.
func TestDiscoverStoresTheScanUnderTheJobsClaim(t *testing.T) {
	u := newUnit(t, true, false)
	j := jobs.Job{ID: uuid.New(), Type: jobs.TargetDiscover, TargetID: uuid.New(), Attempt: 3}
	_, err := u.h.discover(context.Background(), j, nil)
	require.NoError(t, err)
	assert.Equal(t, []inventory.Claim{{JobID: j.ID, Attempt: 3}}, u.inv.claims)

	u = newUnit(t, true, false)
	u.inv.reconcileErr = fmt.Errorf("wrapped: %w", inventory.ErrClaimLost)
	_, err = u.h.discover(context.Background(), j, nil)
	r, c := reason(t, err)
	assert.Equal(t, "job.lease_expired", r)
	assert.Equal(t, jobs.Retryable, c)
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

// AUD-25 (a), ruling S4: a refused address is a connection reason: the target shows it.
func TestRemoveKeyRecordsARefusedAddressOnTheTarget(t *testing.T) {
	u, j := removalUnit(t)
	u.prov.Configure(func(c *fake.Config) { c.RemoveErr = providers.NewError("ssh.address_not_allowed", false, nil, nil) })
	_, err := u.h.removeKey(context.Background(), j, nil)
	r, c := reason(t, err)
	assert.Equal(t, "ssh.address_not_allowed", r)
	assert.Equal(t, jobs.Permanent, c)
	assert.Equal(t, []string{"ssh.address_not_allowed"}, u.inv.failures)
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

// requestProvider records the DiscoverRequest of every session's Discover.
type requestProvider struct {
	*fake.Provider
	reqs *[]providers.DiscoverRequest
}

type requestSession struct {
	providers.Session
	reqs *[]providers.DiscoverRequest
}

func (p requestProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return requestSession{s, p.reqs}, nil
}

func (s requestSession) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	*s.reqs = append(*s.reqs, req)
	return s.Session.Discover(ctx, req)
}

// A target whose capabilities include discover_certificates is scanned for both halves; a Linux
// target for its SSH keys only. The job result of a certificate scan carries its counts.
func TestDiscoverReadsCertificatesOfNginxTargets(t *testing.T) {
	var reqs []providers.DiscoverRequest
	linux, nginx := fake.New(providers.KindLinuxSSH), fake.New(providers.KindNginx, providers.CapTestConnection,
		providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys, providers.CapDiscoverCerts)
	nginx.Configure(func(c *fake.Config) {
		c.Discovery = providers.DiscoveryResult{WebServer: &providers.WebServerFacts{Found: true, ConfigValid: true}}
	})
	reg := providers.NewRegistry()
	reg.Register(requestProvider{linux, &reqs})
	reg.Register(requestProvider{nginx, &reqs})
	reg.Freeze()
	inv := &stubInventory{target: inventory.Target{Name: "web-01", Type: inventory.TypeNginx, Status: inventory.StatusOK,
		Capabilities: []string{"authorized_keys", "discover_certificates", "discover_ssh_keys", "test_connection"}}}
	h := newHandlers(Deps{Inventory: inv, Registry: reg, Clock: clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))})
	out, err := h.discover(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"key_count": 1, "new_count": 0, "missing_count": 0, "partial": false,
		"certificate_count": 2, "location_count": 3}, out)

	inv.target = inventory.Target{Name: "web-02", Type: inventory.TypeLinux, Status: inventory.StatusOK,
		Capabilities: []string{"authorized_keys", "discover_ssh_keys", "test_connection"}}
	out, err = h.discover(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"key_count": 1, "new_count": 0, "missing_count": 0, "partial": false}, out)
	assert.Equal(t, []providers.DiscoverRequest{{SSHKeys: true, Certificates: true}, {SSHKeys: true}}, reqs)
}

// notFoundSession answers nginx.not_found to a discovery that asks for certificates, as the nginx
// provider does on a server without Nginx (nginx-dump runs first).
type notFoundSession struct {
	providers.Session
	reqs *[]providers.DiscoverRequest
	code string
}

func (s notFoundSession) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	*s.reqs = append(*s.reqs, req)
	if req.Certificates {
		return providers.DiscoveryResult{}, providers.NewError(s.code, false, nil, nil)
	}
	return s.Session.Discover(ctx, req)
}

type notFoundProvider struct {
	*fake.Provider
	reqs *[]providers.DiscoverRequest
	code string
}

func (p notFoundProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return notFoundSession{s, p.reqs, p.code}, nil
}

// An Nginx server without Nginx keeps its SSH-key discovery: the job scans the SSH half alone and
// reconciles it with Nginx facts that say "not found" (inventory then leaves the certificate
// locations as they are). Any other failure of the certificate half fails the job as before.
func TestDiscoverWithoutNginxStillScansSSHKeys(t *testing.T) {
	run := func(code string, sshErr error) (*stubInventory, []providers.DiscoverRequest, map[string]any, error) {
		var reqs []providers.DiscoverRequest
		prov := fake.New(providers.KindNginx, providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
			providers.CapDiscoverCerts)
		prov.Configure(func(c *fake.Config) {
			c.Discovery = providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{{OSUser: "deploy", Fingerprint: "SHA256:K"}},
				SSHD: providers.SSHDSummary{Read: true}}
			c.DiscoverErr = sshErr
		})
		reg := providers.NewRegistry()
		reg.Register(notFoundProvider{prov, &reqs, code})
		reg.Freeze()
		inv := &stubInventory{target: inventory.Target{Name: "web-01", Type: inventory.TypeNginx, Status: inventory.StatusOK,
			Capabilities: []string{"discover_certificates", "discover_ssh_keys"}}}
		h := newHandlers(Deps{Inventory: inv, Registry: reg, Clock: clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))})
		out, err := h.discover(context.Background(), testJob, nil)
		return inv, reqs, out, err
	}
	inv, reqs, out, err := run("nginx.not_found", nil)
	require.NoError(t, err)
	assert.Equal(t, []providers.DiscoverRequest{{SSHKeys: true, Certificates: true}, {SSHKeys: true}}, reqs)
	require.Len(t, inv.reconciled, 1)
	res := inv.reconciled[0]
	assert.Equal(t, &providers.WebServerFacts{Software: "nginx"}, res.WebServer, "Nginx not found")
	assert.Len(t, res.SSHKeys, 1)
	assert.True(t, res.SSHD.Read)
	assert.Equal(t, []string{providers.WarnWebServerNotFound}, []string{res.Warnings[len(res.Warnings)-1].Code})
	assert.Empty(t, inv.failures, "not a connection failure")
	assert.Contains(t, out, "location_count")

	// The SSH half fails as well: the job fails with its reason.
	inv, _, _, err = run("nginx.not_found", providers.NewError("ssh.timeout", true, nil, nil))
	r, _ := reason(t, err)
	assert.Equal(t, "ssh.timeout", r)
	assert.Empty(t, inv.reconciled)

	// The nginx sudoers profile is not installed: the SSH half is still scanned; nothing is known of
	// Nginx (no facts, the stored ones stay) and the warning says why.
	inv, reqs, _, err = run("nginx.profile_missing", nil)
	require.NoError(t, err)
	assert.Equal(t, []providers.DiscoverRequest{{SSHKeys: true, Certificates: true}, {SSHKeys: true}}, reqs)
	require.Len(t, inv.reconciled, 1)
	assert.Nil(t, inv.reconciled[0].WebServer)
	assert.Len(t, inv.reconciled[0].SSHKeys, 1)
	assert.Equal(t, providers.WarnWebServerProfileMissing, inv.reconciled[0].Warnings[len(inv.reconciled[0].Warnings)-1].Code)
	assert.Empty(t, inv.failures)

	inv, reqs, _, err = run("nginx.config_changed", nil)
	r, _ = reason(t, err)
	assert.Equal(t, "nginx.config_changed", r)
	assert.Len(t, reqs, 1, "any other failure of the certificate half fails the job")
	assert.Empty(t, inv.reconciled)
}

// blockingProvider's sessions block in Discover until the context ends and record its deadline.
type blockingProvider struct {
	*fake.Provider
	deadlines *[]time.Time
}

type blockingSession struct {
	providers.Session
	deadlines *[]time.Time
}

func (p blockingProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return blockingSession{s, p.deadlines}, nil
}

func (s blockingSession) Discover(ctx context.Context, _ providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	d, _ := ctx.Deadline()
	*s.deadlines = append(*s.deadlines, d)
	<-ctx.Done()
	return providers.DiscoveryResult{}, ctx.Err()
}

// AUD-04(a): a discovery job's server side has its own time limit (discoveryTimeout); a server that
// keeps the scan busy past it ends the run as a retryable timeout recorded on the server (W2 review,
// minor 7), and nothing is stored.
func TestDiscoveryHasAJobTimeLimit(t *testing.T) {
	old := discoveryTimeout
	discoveryTimeout = 50 * time.Millisecond
	defer func() { discoveryTimeout = old }()
	u := newUnit(t, false, false)
	var deadlines []time.Time
	reg := providers.NewRegistry()
	reg.Register(blockingProvider{u.prov, &deadlines})
	reg.Freeze()
	u.h.d.Registry = reg
	started := time.Now()
	_, err := u.h.discover(context.Background(), jobs.Job{ID: uuid.New(), Type: jobs.TargetDiscover, TargetID: uuid.New(), Attempt: 1}, nil)
	assert.Less(t, time.Since(started), 5*time.Second)
	r, c := reason(t, err)
	assert.Equal(t, "ssh.timeout", r)
	assert.Equal(t, jobs.Retryable, c)
	require.Len(t, deadlines, 1)
	assert.False(t, deadlines[0].IsZero(), "the scan runs under a deadline")
	assert.Empty(t, u.inv.reconciled, "nothing is stored")
	assert.Equal(t, []string{"ssh.timeout"}, u.inv.failures, "the server shows the timeout")
	assert.Equal(t, 20*time.Minute, old, "sized above the provider's own bounds (10 min reading + commands)")
}

// The certificate fallback is the web servers' alone and each kind answers to its own reason
// prefix: another kind's code, and a target that is not a web server, fail the job as before.
func TestScanFallsBackForEveryWebServerKind(t *testing.T) {
	run := func(kind providers.Kind, typ, code string) (*stubInventory, []providers.DiscoverRequest, error) {
		var reqs []providers.DiscoverRequest
		prov := fake.New(kind, providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys, providers.CapDiscoverCerts)
		reg := providers.NewRegistry()
		reg.Register(notFoundProvider{prov, &reqs, code})
		reg.Freeze()
		inv := &stubInventory{target: inventory.Target{Name: "web-01", Type: typ, Status: inventory.StatusOK,
			Capabilities: []string{"discover_certificates", "discover_ssh_keys"}}}
		h := newHandlers(Deps{Inventory: inv, Registry: reg, Clock: clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))})
		_, err := h.discover(context.Background(), testJob, nil)
		return inv, reqs, err
	}
	inv, reqs, err := run(providers.KindNginx, inventory.TypeNginx, "nginx.not_found")
	require.NoError(t, err)
	assert.Len(t, reqs, 2)
	require.Len(t, inv.reconciled, 1)
	assert.Equal(t, &providers.WebServerFacts{Software: "nginx"}, inv.reconciled[0].WebServer)

	// A helper too old for the kind's discovery: SSH keys are scanned, no facts, a warning.
	inv, reqs, err = run(providers.KindNginx, inventory.TypeNginx, "nginx.helper_too_old")
	require.NoError(t, err)
	assert.Len(t, reqs, 2)
	require.Len(t, inv.reconciled, 1)
	assert.Nil(t, inv.reconciled[0].WebServer)
	assert.Equal(t, "web_server_helper_too_old", inv.reconciled[0].Warnings[len(inv.reconciled[0].Warnings)-1].Code)

	// Not a web server: no fallback, the provider's error is the job's.
	inv, reqs, err = run(providers.KindLinuxSSH, inventory.TypeLinux, "nginx.not_found")
	r, _ := reason(t, err)
	assert.Equal(t, "nginx.not_found", r)
	assert.Len(t, reqs, 1)
	assert.Empty(t, inv.reconciled)

	// Another kind's prefix is not this kind's.
	inv, reqs, err = run(providers.KindNginx, inventory.TypeNginx, "apache.not_found")
	r, _ = reason(t, err)
	assert.Equal(t, "apache.not_found", r)
	assert.Len(t, reqs, 1)
	assert.Empty(t, inv.reconciled)
}
