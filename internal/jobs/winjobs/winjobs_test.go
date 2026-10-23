package winjobs

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

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
)

// The handler's order and its failures with scripted fakes (R62 W3 Task 7); winjobs_integration_test.go runs one job over
// SSH against the emulated Windows server.

const (
	sha1A   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sha256A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sha1B   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sha256B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fakeInv scripts the inventory side of the job; every call is recorded in calls (shared with the session).
type fakeInv struct {
	calls    *[]string
	target   inventory.Target
	refErr   error
	failures []string
	failErr  error

	watch    []providers.CleanupRef
	watchErr error
	decision inventory.CleanupDecision
	judgeErr error
	judged   providers.CleanupPlan

	recordErr error
	recorded  struct {
		incident *uuid.UUID
		plan     providers.CleanupPlan
		d        inventory.CleanupDecision
		res      providers.CleanupApplyResult
	}

	scheduled   int
	scheduleErr error
}

func (f *fakeInv) TargetRef(_ context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error) {
	*f.calls = append(*f.calls, "TargetRef")
	return providers.TargetRef{ID: id, Name: f.target.Name, Kind: providers.KindWindows}, f.target, f.refErr
}
func (f *fakeInv) Credentials() providers.CredentialSource { return nil }
func (f *fakeInv) HostKeyStore() providers.HostKeyStore    { return nil }
func (f *fakeInv) RecordConnectionFailure(_ context.Context, _ uuid.UUID, reason string) error {
	f.failures = append(f.failures, reason)
	return f.failErr
}
func (f *fakeInv) CleanupWatch(context.Context, uuid.UUID) ([]providers.CleanupRef, error) {
	*f.calls = append(*f.calls, "CleanupWatch")
	return f.watch, f.watchErr
}
func (f *fakeInv) JudgeCleanup(_ context.Context, _ uuid.UUID, plan providers.CleanupPlan) (inventory.CleanupDecision, error) {
	*f.calls = append(*f.calls, "JudgeCleanup")
	f.judged = plan
	return f.decision, f.judgeErr
}
func (f *fakeInv) RecordCleanup(_ context.Context, _ uuid.UUID, incident *uuid.UUID, plan providers.CleanupPlan, d inventory.CleanupDecision,
	res providers.CleanupApplyResult) error {
	*f.calls = append(*f.calls, "RecordCleanup")
	f.recorded.incident, f.recorded.plan, f.recorded.d, f.recorded.res = incident, plan, d, res
	return f.recordErr
}
func (f *fakeInv) ScheduleWindowsCleanup(context.Context) (int, error) {
	return f.scheduled, f.scheduleErr
}

// cleanerSession is a session that is a providers.CertificateCleaner; plain drops the interface.
type cleanerSession struct {
	providers.UnsupportedSession
	calls    *[]string
	watched  []providers.CleanupRef
	plan     providers.CleanupPlan
	planErr  error
	items    []providers.CleanupItem
	res      providers.CleanupApplyResult
	applyErr error
	closeErr error
}

func (s *cleanerSession) PlanCleanup(_ context.Context, watch []providers.CleanupRef) (providers.CleanupPlan, error) {
	*s.calls = append(*s.calls, "PlanCleanup")
	s.watched = watch
	return s.plan, s.planErr
}
func (s *cleanerSession) ApplyCleanup(_ context.Context, items []providers.CleanupItem) (providers.CleanupApplyResult, error) {
	*s.calls = append(*s.calls, "ApplyCleanup")
	s.items = items
	return s.res, s.applyErr
}
func (s *cleanerSession) Close() error {
	*s.calls = append(*s.calls, "Close")
	return s.closeErr
}

// plainSession is a session without the cleanup methods.
type plainSession struct{ providers.UnsupportedSession }

// winProvider is a Windows provider whose Open answers sess (or openErr).
type winProvider struct {
	*fake.Provider
	sess    providers.Session
	openErr error
}

func (p winProvider) Open(context.Context, providers.TargetRef, providers.CredentialSource, providers.Env) (providers.Session, error) {
	if p.openErr != nil {
		return nil, p.openErr
	}
	return p.sess, nil
}

type world struct {
	calls []string
	inv   *fakeInv
	sess  *cleanerSession
	prov  *winProvider
	logs  *bytes.Buffer
	h     *handlers
}

var testJob = jobs.Job{ID: uuid.MustParse("0190f5a0-0000-7000-8000-0000000000aa"), Type: jobs.WindowsCleanup,
	TargetID: uuid.MustParse("0190f5a0-0000-7000-8000-0000000000bb"), Payload: map[string]string{}, Attempt: 1, MaxAttempts: 1}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{logs: &bytes.Buffer{}}
	w.inv = &fakeInv{calls: &w.calls, target: inventory.Target{Name: "iis-01", Type: inventory.TypeWindows, Status: inventory.StatusOK,
		Capabilities: []string{string(providers.CapTestConnection), string(providers.CapCleanupCertificates)}}}
	w.sess = &cleanerSession{calls: &w.calls}
	w.prov = &winProvider{Provider: fake.New(providers.KindWindows, providers.CapTestConnection, providers.CapCleanupCertificates), sess: w.sess}
	reg := providers.NewRegistry()
	reg.Register(w.prov)
	reg.Freeze()
	w.h = &handlers{d: Deps{Inventory: w.inv, Registry: reg, Clock: clock.NewFake(time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)),
		Log: slog.New(slog.NewTextHandler(w.logs, nil))}}
	return w
}

func failure(t *testing.T, err error) *jobs.Failure {
	t.Helper()
	var f *jobs.Failure
	require.ErrorAs(t, err, &f)
	return f
}

// The handler: the target's checks, the watch list, the plan, Alice's judgement, the apply of what she would remove, the
// record; the result counts the candidates and the removals and lists what stays and why, with the plan's own facts.
func TestCleanupRunsInOrder(t *testing.T) {
	w := newWorld(t)
	incident := uuid.MustParse("0190f5a0-0000-7000-8000-0000000000cc")
	w.inv.watch = []providers.CleanupRef{{SHA1: sha1B, SHA256: sha256B}}
	w.sess.plan = providers.CleanupPlan{
		Candidates: []providers.CleanupCertificate{{Store: "My", SHA1: sha1A, SHA256: sha256A, Eligible: providers.CleanupAged},
			{Store: "My", SHA1: sha1B, SHA256: sha256B}},
		Watched: []providers.CleanupWatched{{Store: "My", SHA1: sha1B, SHA256: sha256B, State: providers.WatchKept, Reason: "bound"}},
		Pruned:  3, Partial: true, Warnings: []string{"journal_unreadable"}}
	item := providers.CleanupItem{Store: "My", SHA1: sha1A, SHA256: sha256A, Reason: providers.CleanupAged}
	w.inv.decision = inventory.CleanupDecision{Remove: []providers.CleanupItem{item},
		Kept: []inventory.CleanupKept{{SHA256: sha256B, Reason: inventory.CleanupKeptRollbackWindow}}}
	w.sess.res = providers.CleanupApplyResult{Results: []providers.CleanupItemResult{{SHA256: sha256A, Result: providers.CleanupRemoved}}}
	j := testJob
	j.Payload = map[string]string{"incident_id": incident.String()}

	out, err := w.h.cleanup(context.Background(), j, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"TargetRef", "CleanupWatch", "PlanCleanup", "JudgeCleanup", "ApplyCleanup", "RecordCleanup", "Close"}, w.calls)
	assert.Equal(t, w.inv.watch, w.sess.watched, "the watch list goes to the plan")
	assert.Equal(t, w.sess.plan, w.inv.judged, "the plan is judged")
	assert.Equal(t, []providers.CleanupItem{item}, w.sess.items, "only what Alice would remove is applied")
	require.NotNil(t, w.inv.recorded.incident)
	assert.Equal(t, incident, *w.inv.recorded.incident)
	assert.Equal(t, w.sess.plan, w.inv.recorded.plan)
	assert.Equal(t, w.inv.decision, w.inv.recorded.d)
	assert.Equal(t, w.sess.res, w.inv.recorded.res)
	assert.Equal(t, map[string]any{"candidates": 2, "removed": 1, "absent": 0, "pruned": 3, "partial": true,
		"warnings": []string{"journal_unreadable"}, "kept": []map[string]string{{"sha256": sha256B, "reason": inventory.CleanupKeptRollbackWindow}}}, out)
}

// What the server keeps at apply time is in the result with its reason, next to Alice's; one it no longer has is absent.
func TestCleanupResultListsWhatTheServerKept(t *testing.T) {
	w := newWorld(t)
	items := []providers.CleanupItem{{Store: "My", SHA1: sha1A, SHA256: sha256A, Reason: providers.CleanupAged},
		{Store: "My", SHA1: sha1B, SHA256: sha256B, Reason: providers.CleanupIncident}}
	w.inv.decision = inventory.CleanupDecision{Remove: items}
	w.sess.res = providers.CleanupApplyResult{Results: []providers.CleanupItemResult{{SHA256: sha256A, Result: providers.CleanupKept, Reason: "bound"},
		{SHA256: sha256B, Result: providers.CleanupAbsent}}}
	out, err := w.h.cleanup(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.Nil(t, w.inv.recorded.incident, "a scheduled job names no incident")
	assert.Equal(t, 0, out["removed"])
	assert.Equal(t, 1, out["absent"])
	assert.Equal(t, []map[string]string{{"sha256": sha256A, "reason": "bound"}}, out["kept"])
	assert.Equal(t, []string{}, out["warnings"], "no warnings is an empty list")
}

// The switch off (or nothing Alice would remove): the plan still runs (bookkeeping, the Q7 report), nothing is applied,
// and the record is made with an empty apply result.
func TestCleanupSwitchOffAppliesNothing(t *testing.T) {
	w := newWorld(t)
	w.sess.plan = providers.CleanupPlan{Candidates: []providers.CleanupCertificate{{Store: "My", SHA1: sha1A, SHA256: sha256A, Eligible: providers.CleanupAged}}}
	w.inv.decision = inventory.CleanupDecision{Kept: []inventory.CleanupKept{{SHA256: sha256A, Reason: inventory.CleanupKeptSwitchOff}}}
	out, err := w.h.cleanup(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"TargetRef", "CleanupWatch", "PlanCleanup", "JudgeCleanup", "RecordCleanup", "Close"}, w.calls, "no apply")
	assert.Equal(t, providers.CleanupApplyResult{}, w.inv.recorded.res)
	assert.Equal(t, 0, out["removed"])
	assert.Equal(t, []map[string]string{{"sha256": sha256A, "reason": inventory.CleanupKeptSwitchOff}}, out["kept"])
}

// A provider whose session is no CertificateCleaner, or a server without the capability, is Alice's own error: nothing is
// planned.
func TestCleanupWithoutTheInterfaceIsUnexpected(t *testing.T) {
	w := newWorld(t)
	w.prov.sess = plainSession{}
	_, err := w.h.cleanup(context.Background(), testJob, nil)
	f := failure(t, err)
	assert.Equal(t, "internal.unexpected", f.Reason)
	assert.Equal(t, jobs.Permanent, f.Class)
	assert.Equal(t, []string{"TargetRef"}, w.calls)

	w = newWorld(t)
	w.inv.target.Capabilities = []string{string(providers.CapTestConnection)}
	_, err = w.h.cleanup(context.Background(), testJob, nil)
	assert.Equal(t, "internal.unexpected", failure(t, err).Reason)
	assert.Equal(t, []string{"TargetRef", "Close"}, w.calls, "no capability: no plan")
}

// A plan or an apply whose outcome is unknown fails the job with the provider's reason (one attempt; the next day's plan
// settles it); nothing is recorded.
func TestCleanupOutcomeUnknown(t *testing.T) {
	unknown := providers.NewError("windows.cleanup_outcome_unknown", true, errors.New("exit 4"), map[string]string{"subcommand": "iis-cleanup"})
	w := newWorld(t)
	w.sess.planErr = unknown
	_, err := w.h.cleanup(context.Background(), testJob, nil)
	f := failure(t, err)
	assert.Equal(t, "windows.cleanup_outcome_unknown", f.Reason)
	assert.Equal(t, jobs.Retryable, f.Class)
	assert.Equal(t, []string{"TargetRef", "CleanupWatch", "PlanCleanup", "Close"}, w.calls)

	w = newWorld(t)
	w.inv.decision = inventory.CleanupDecision{Remove: []providers.CleanupItem{{Store: "My", SHA1: sha1A, SHA256: sha256A, Reason: providers.CleanupAged}}}
	w.sess.applyErr = unknown
	_, err = w.h.cleanup(context.Background(), testJob, nil)
	assert.Equal(t, "windows.cleanup_outcome_unknown", failure(t, err).Reason)
	assert.Equal(t, []string{"TargetRef", "CleanupWatch", "PlanCleanup", "JudgeCleanup", "ApplyCleanup", "Close"}, w.calls)
}

// The target's checks of every job that connects (driftjobs' open): nothing runs on a server that is gone, disabled or
// whose host key is not confirmed; a connection failure is recorded on the server and ends the job in one attempt.
func TestCleanupOpenChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(w *world)
		reason string
		class  jobs.FailureClass
	}{
		{"not found", func(w *world) { w.inv.refErr = inventory.ErrNotFound }, "system.not_found", jobs.Permanent},
		{"read error", func(w *world) { w.inv.refErr = errors.New("db down") }, "internal.unexpected", jobs.Retryable},
		{"host key changed", func(w *world) { w.inv.target.Status = inventory.StatusHostKeyChanged }, "target.host_key_changed", jobs.Permanent},
		{"disabled", func(w *world) { w.inv.target.Status = inventory.StatusDisabled }, "target.disabled", jobs.Permanent},
		{"host key unconfirmed", func(w *world) { w.inv.target.Status = inventory.StatusPendingHostKey }, "target.host_key_unconfirmed", jobs.Permanent},
		{"no provider", func(w *world) {
			reg := providers.NewRegistry()
			reg.Register(fake.New(providers.KindLinuxSSH, providers.CapTestConnection))
			reg.Freeze()
			w.h.d.Registry = reg
		}, "internal.unexpected", jobs.Permanent},
		{"provider error", func(w *world) { w.prov.openErr = providers.NewError("ssh.unreachable", true, errors.New("dial"), nil) }, "ssh.unreachable",
			jobs.Permanent},
		{"provider error not recorded", func(w *world) {
			w.prov.openErr = providers.NewError("ssh.timeout", true, errors.New("dial"), nil)
			w.inv.failErr = errors.New("db down")
		}, "ssh.timeout", jobs.Permanent},
		{"other error", func(w *world) { w.prov.openErr = errors.New("boom") }, "internal.unexpected", jobs.Retryable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.setup(w)
			_, err := w.h.cleanup(context.Background(), testJob, nil)
			f := failure(t, err)
			assert.Equal(t, tc.reason, f.Reason)
			assert.Equal(t, tc.class, f.Class)
			assert.Equal(t, []string{"TargetRef"}, w.calls, "nothing is planned")
		})
	}
	w := newWorld(t)
	w.prov.openErr = providers.NewError("ssh.unreachable", true, errors.New("dial"), nil)
	_, _ = w.h.cleanup(context.Background(), testJob, nil)
	assert.Equal(t, []string{"ssh.unreachable"}, w.inv.failures, "the connection failure is recorded on the server")
}

// Alice's own steps failing are internal.unexpected; a malformed incident id is too (nothing is sent).
func TestCleanupInventoryFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(w *world)
		calls []string
	}{
		{"bad incident id", func(w *world) {}, []string{"TargetRef", "Close"}},
		{"watch", func(w *world) { w.inv.watchErr = errors.New("db") }, []string{"TargetRef", "CleanupWatch", "Close"}},
		{"judge", func(w *world) { w.inv.judgeErr = errors.New("db") }, []string{"TargetRef", "CleanupWatch", "PlanCleanup", "JudgeCleanup", "Close"}},
		{"record", func(w *world) { w.inv.recordErr = errors.New("db") },
			[]string{"TargetRef", "CleanupWatch", "PlanCleanup", "JudgeCleanup", "RecordCleanup", "Close"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.setup(w)
			j := testJob
			if tc.name == "bad incident id" {
				j.Payload = map[string]string{"incident_id": "not-a-uuid"}
			}
			_, err := w.h.cleanup(context.Background(), j, nil)
			assert.Equal(t, "internal.unexpected", failure(t, err).Reason)
			assert.Equal(t, tc.calls, w.calls)
		})
	}
}

// A session that fails to close is logged, not failed.
func TestCleanupCloseFailureIsLogged(t *testing.T) {
	w := newWorld(t)
	w.sess.closeErr = errors.New("close")
	_, err := w.h.cleanup(context.Background(), testJob, nil)
	require.NoError(t, err)
	assert.Contains(t, w.logs.String(), "closing a provider session failed")
}

// Register installs the handler and refuses missing dependencies; the schedule task queues through the inventory and logs
// what it queued.
func TestRegisterAndScheduleTask(t *testing.T) {
	w := newWorld(t)
	assert.Panics(t, func() { Register(nil, Deps{}) })
	assert.Panics(t, func() { Register(nil, Deps{Inventory: w.inv}) })
	r := jobs.NewRunner(jobs.RunnerConfig{Clock: clock.NewFake(time.Now())})
	Register(r, Deps{Inventory: w.inv, Registry: w.h.d.Registry, Clock: w.h.d.Clock})
	assert.True(t, r.Handles(jobs.WindowsCleanup))

	assert.Panics(t, func() { ScheduleTask(nil, time.Hour, nil) })
	task := ScheduleTask(w.inv, time.Hour, nil)
	assert.Equal(t, jobs.WindowsCleanupSchedule, task.Type)
	assert.Equal(t, time.Hour, task.Every)
	w.inv.scheduled = 2
	require.NoError(t, task.Run(context.Background()))
	logs := &bytes.Buffer{}
	w.inv.scheduled, w.inv.scheduleErr = 0, errors.New("db")
	task = ScheduleTask(w.inv, time.Hour, slog.New(slog.NewTextHandler(logs, nil)))
	require.Error(t, task.Run(context.Background()))
	assert.NotContains(t, logs.String(), "queued")
	w.inv.scheduled, w.inv.scheduleErr = 3, nil
	require.NoError(t, task.Run(context.Background()))
	assert.Contains(t, logs.String(), "servers=3")
}

// The job types: the cleanup changes a server (held in lock), runs once and mails nobody when it fails (the next day's
// run retries); the schedule only queues (paused in lock).
func TestWindowsCleanupTypes(t *testing.T) {
	assert.Equal(t, inventory.JobWindowsCleanup, jobs.WindowsCleanup.Name)
	assert.Equal(t, "windows.cleanup_schedule", jobs.WindowsCleanupSchedule.Name)
	assert.Equal(t, 1, jobs.MaxAttemptsFor(jobs.WindowsCleanup))
	assert.False(t, jobs.AlertsWhenExhausted(jobs.WindowsCleanup))
}
