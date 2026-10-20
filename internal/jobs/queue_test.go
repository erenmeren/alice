package jobs

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/providers"
	"alice/internal/secrets"
	"alice/internal/sshkeys"
	"alice/locales"
)

func TestPayloadMACLabelIsTheSecretsLabel(t *testing.T) {
	assert.Equal(t, secrets.LabelJob, payloadMACLabel, "the job MAC key is the J-1 sub-key")
}

func TestPayloadMACCoversEveryField(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	id, target, by := uuid.New(), uuid.New(), uuid.New()
	payload := canonicalPayload(map[string]string{"location_id": "a"})
	mac := func(key []byte, id uuid.UUID, typ, kind string, target uuid.UUID, payload []byte, by uuid.UUID, role string, maxAttempts int) []byte {
		return payloadMAC(key, id, typ, kind, target, payload, by, role, maxAttempts)
	}
	base := mac(key, id, "sshkey.remove", "user", target, payload, by, "operator", 3)
	require.Len(t, base, 32)
	assert.Equal(t, base, mac(key, id, "sshkey.remove", "user", target, payload, by, "operator", 3), "deterministic")
	for name, other := range map[string][]byte{
		"key":          mac(bytes.Repeat([]byte{4}, 32), id, "sshkey.remove", "user", target, payload, by, "operator", 3),
		"id":           mac(key, uuid.New(), "sshkey.remove", "user", target, payload, by, "operator", 3),
		"type":         mac(key, id, "target.discover", "user", target, payload, by, "operator", 3),
		"kind":         mac(key, id, "sshkey.remove", "system", target, payload, by, "operator", 3),
		"target":       mac(key, id, "sshkey.remove", "user", uuid.New(), payload, by, "operator", 3),
		"no target":    mac(key, id, "sshkey.remove", "user", uuid.Nil, payload, by, "operator", 3),
		"payload":      mac(key, id, "sshkey.remove", "user", target, canonicalPayload(map[string]string{"location_id": "b"}), by, "operator", 3),
		"created by":   mac(key, id, "sshkey.remove", "user", target, payload, uuid.Nil, "operator", 3),
		"role":         mac(key, id, "sshkey.remove", "user", target, payload, by, "admin", 3),
		"max attempts": mac(key, id, "sshkey.remove", "user", target, payload, by, "operator", 30),
		"field shift":  mac(key, id, "sshkey.remove", "useroperator", target, payload, by, "", 3),
	} {
		assert.NotEqual(t, base, other, name)
	}
}

func TestCanonicalPayloadIsOrderIndependentAndNeverNull(t *testing.T) {
	assert.Equal(t, `{}`, string(canonicalPayload(nil)))
	a := canonicalPayload(map[string]string{"b": "2", "a": "1"})
	assert.Equal(t, `{"a":"1","b":"2"}`, string(a))
}

func TestBackoff(t *testing.T) {
	for _, tc := range []struct {
		attempt int
		jitter  float64
		want    time.Duration
	}{
		{0, 0, 30 * time.Second},
		{1, 0, 30 * time.Second},
		{2, 0, time.Minute},
		{3, 0, 2 * time.Minute},
		{6, 0, 16 * time.Minute},
		{7, 0, 30 * time.Minute},
		{40, 0, 30 * time.Minute},
		{1, 0.2, 36 * time.Second},
		{1, -0.2, 24 * time.Second},
		{1, 5, 36 * time.Second}, // jitter is clamped to ±20 %
	} {
		assert.Equal(t, tc.want, Backoff(tc.attempt, tc.jitter), "attempt %d jitter %v", tc.attempt, tc.jitter)
	}
}

func TestFromProvider(t *testing.T) {
	var f *Failure
	err := FromProvider(providers.NewError("ssh.unreachable", true, errors.New("dial tcp: refused"), map[string]string{"host": "web-01"}))
	require.ErrorAs(t, err, &f)
	assert.Equal(t, Retryable, f.Class)
	assert.Equal(t, "ssh.unreachable", f.Reason)
	assert.Equal(t, map[string]string{"host": "web-01"}, f.Params)

	err = FromProvider(providers.NewError("ssh.auth_failed", false, nil, nil))
	require.ErrorAs(t, err, &f)
	assert.Equal(t, Permanent, f.Class)
	assert.Equal(t, "ssh.auth_failed", f.Reason)

	same := Fail("sshkey.own_key_protected", nil, nil)
	assert.Same(t, same, FromProvider(same), "a classified failure passes through")

	err = FromProvider(errors.New("boom"))
	require.ErrorAs(t, err, &f)
	assert.Equal(t, Retryable, f.Class)
	assert.Equal(t, "internal.unexpected", f.Reason)
	assert.NoError(t, FromProvider(nil))
}

func TestFailureMessageHidesTheCause(t *testing.T) {
	err := Retry("ssh.timeout", nil, errors.New("CANARY-secret-detail"))
	assert.Equal(t, "jobs: ssh.timeout", err.Error())
	assert.NotContains(t, err.Error(), "CANARY")
	assert.ErrorContains(t, errors.Unwrap(err), "CANARY", "the cause stays reachable for errors.Is/As")
}

func TestMaxAttemptsFor(t *testing.T) {
	assert.Equal(t, 1, MaxAttemptsFor(TargetTestConnection))
	assert.Equal(t, 5, MaxAttemptsFor(TargetDiscover))
	assert.Equal(t, 3, MaxAttemptsFor(SSHKeyRemove))
	assert.Equal(t, 3, MaxAttemptsFor(CertificateDeploy))
	assert.Equal(t, 1, MaxAttemptsFor(CertificateDeployRecover), "the deployment sweep paces recovery, not job retries")
	assert.False(t, AlertsWhenExhausted(CertificateDeployRecover), "the deployment's own needs-attention email is the alert")
	assert.True(t, AlertsWhenExhausted(CertificateDeploy))
	assert.True(t, AlertsWhenExhausted(TargetDiscover))
}

// Phase 4: a deployment changes a server (refused and held in lock, R38); finishing or undoing an
// interrupted one, and the sweep that finds it, are never blocked by the license (L-82, R38 #8).
func TestPhase4JobTypesDeclareTheirLicenseClass(t *testing.T) {
	assert.Equal(t, Type{Name: inventory.JobCertificateDeploy, Class: license.ClassChange}, CertificateDeploy)
	assert.Equal(t, Type{Name: inventory.JobDeployRecover, Class: license.ClassAlways}, CertificateDeployRecover)
	assert.Equal(t, Type{Name: "deployment.recovery_sweep", Class: license.ClassAlways}, DeploymentRecoverySweep)
	assert.Equal(t, "certificate.deploy", inventory.JobCertificateDeploy)
	assert.Equal(t, "certificate.deploy_recover", inventory.JobDeployRecover)
	assert.NotPanics(t, func() {
		NewScheduler(nil, &fakeGate{}, quiet, Task{Type: DeploymentRecoverySweep, Every: time.Minute, Run: func(context.Context) error { return nil }})
	}, "the sweep is periodic work")
}

// Phase 6 (spec §8.2, §8.6, §13.4-§13.6): deploying a generated key changes a server; a rotation's
// per-location work finishes what is in flight and undoes the run's own additions in every state; its
// forward steps ask the gate themselves.
func TestPhase6JobClasses(t *testing.T) {
	assert.Equal(t, license.ClassChange, SSHKeyAdd.Class)
	assert.Equal(t, license.ClassAlways, RotationLocation.Class, "finishing in-flight work and undoing are never blocked (L-85, L-86)")
	assert.Equal(t, license.ClassReadOnly, RotationPlan.Class, "no preview is sent in lock (L-88)")
	assert.Equal(t, license.ClassAlways, RotationSweep.Class, "the sweep flags pauses in lock (L-83)")
	assert.Equal(t, license.ClassReadOnly, SSHKeyDestroyRetired.Class, "no deletion in lock (L-29)")
	assert.Equal(t, 3, MaxAttemptsFor(SSHKeyAdd))
	assert.Equal(t, 3, MaxAttemptsFor(RotationLocation))
	assert.False(t, AlertsWhenExhausted(RotationLocation), "the rotation's own emails carry its failures")
	assert.True(t, AlertsWhenExhausted(SSHKeyAdd))
	for _, typ := range []Type{RotationPlan, RotationSweep, SSHKeyDestroyRetired} {
		assert.NotPanics(t, func() {
			NewScheduler(nil, &fakeGate{}, quiet, Task{Type: typ, Every: time.Minute, Run: func(context.Context) error { return nil }})
		}, "%s is periodic work", typ.Name)
	}
}

// F7: the job types are registered with literal names (the web label guard reads literal Register calls);
// they must be the names the sshkeys module queues and schedules.
func TestPhase6JobTypesAreTheModulesNames(t *testing.T) {
	assert.Equal(t, sshkeys.JobDeploy, SSHKeyAdd.Name)
	assert.Equal(t, sshkeys.JobRotationLocation, RotationLocation.Name)
	assert.Equal(t, sshkeys.TaskPlan, RotationPlan.Name)
	assert.Equal(t, sshkeys.TaskSweep, RotationSweep.Name)
	assert.Equal(t, sshkeys.TaskDestroyRetired, SSHKeyDestroyRetired.Name)
}

func TestRetryAfterKeepsItsWait(t *testing.T) {
	var f *Failure
	require.ErrorAs(t, RetryAfter("sshkey.add_uncertain", nil, nil, 80*time.Second), &f)
	assert.Equal(t, Retryable, f.Class)
	assert.Equal(t, "sshkey.add_uncertain", f.Reason)
	assert.Equal(t, 80*time.Second, f.After)
	require.ErrorAs(t, Retry("ssh.timeout", nil, nil), &f)
	assert.Zero(t, f.After, "a plain retry waits the backoff only")
}

func TestPhase3JobTypesDeclareTheirLicenseClass(t *testing.T) {
	assert.Equal(t, Type{Name: inventory.JobTestConnection, Class: license.ClassReadOnly}, TargetTestConnection)
	assert.Equal(t, Type{Name: inventory.JobDiscover, Class: license.ClassReadOnly}, TargetDiscover)
	assert.Equal(t, Type{Name: inventory.JobSSHKeyRemove, Class: license.ClassChange}, SSHKeyRemove)
}

func TestHandleRefusesUnregisteredAndDuplicateHandlers(t *testing.T) {
	r := NewRunner(RunnerConfig{})
	h := func(_ context.Context, _ Job, _ StepRecorder) (map[string]any, error) { return nil, nil }
	assert.Panics(t, func() { r.Handle(Type{Name: "never.registered", Class: license.ClassAlways}, h) })
	assert.Panics(t, func() { r.Handle(Type{Name: TargetDiscover.Name, Class: license.ClassAlways}, h) }, "class must match the registry")
	assert.False(t, r.Handles(TargetDiscover))
	r.Handle(TargetDiscover, h)
	assert.True(t, r.Handles(TargetDiscover), "the composition root checks every job type has a handler")
	assert.False(t, r.Handles(TargetTestConnection))
	assert.Panics(t, func() { r.Handle(TargetDiscover, h) })
}

func TestNewRunnerDefaults(t *testing.T) {
	r := NewRunner(RunnerConfig{})
	assert.Equal(t, 8, r.cfg.Workers)
	assert.Equal(t, 45*time.Second, r.cfg.Lease)
	assert.Equal(t, 15*time.Second, r.cfg.Heartbeat)
	assert.Equal(t, time.Second, r.cfg.Poll)
	assert.Equal(t, time.Minute, r.cfg.ReapEvery)
	assert.Equal(t, time.Minute, r.cfg.ShutdownGrace)
	assert.NotEmpty(t, r.cfg.WorkerID)
	for range 100 {
		j := r.cfg.Jitter()
		assert.True(t, j >= -0.2 && j <= 0.2, "jitter %v", j)
	}
}

func TestScheduledTaskTypesDeclareTheirLicenseClass(t *testing.T) {
	assert.Equal(t, Type{Name: "audit.verify", Class: license.ClassAlways}, AuditVerify)
	assert.Equal(t, Type{Name: "maintenance.cleanup", Class: license.ClassAlways}, MaintenanceCleanup)
	assert.Equal(t, Type{Name: "discovery.schedule", Class: license.ClassReadOnly}, DiscoverySchedule)
	// The periodic scheduler accepts all three (it refuses only ClassChange tasks).
	assert.NotPanics(t, func() {
		NewScheduler(nil, &fakeGate{}, quiet,
			Task{Type: AuditVerify, Every: time.Hour, Run: func(context.Context) error { return nil }},
			Task{Type: MaintenanceCleanup, Every: time.Hour, Run: func(context.Context) error { return nil }},
			Task{Type: DiscoverySchedule, Every: time.Minute, Run: func(context.Context) error { return nil }})
	})
}

// releaseAll finds this runner's claims by the "<WorkerID>/" prefix of their token: a slash in
// the worker id would let one runner release another's jobs ("a" and "a/b").
func TestNewRunnerRefusesASlashInTheWorkerID(t *testing.T) {
	assert.PanicsWithValue(t, `jobs: worker id "a/b" must not contain "/"`, func() { NewRunner(RunnerConfig{WorkerID: "a/b"}) })
	assert.NotPanics(t, func() { NewRunner(RunnerConfig{WorkerID: "host-1-abc"}) })
	assert.NotContains(t, NewRunner(RunnerConfig{}).cfg.WorkerID, "/", "the default id has no slash")
}

// The admin emails of the jobs package exist in English and Turkish and use only the params
// the package sends.
func TestJobsEmailTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	id := uuid.MustParse("0190f5a0-0000-7000-8000-0000000000aa")
	for _, c := range []struct {
		template string
		params   map[string]string
		subject  []string
		body     []string
	}{
		{TemplateJobDead, deadAlertParams(id, "sshkey.remove", "ssh.timeout", 3),
			[]string{"sshkey.remove"}, []string{id.String(), "ssh.timeout", "3"}},
		{TemplateJobTampered, tamperedAlertParams(id, "sshkey.remove"),
			[]string{"sshkey.remove"}, []string{id.String()}},
		{TemplateAuditBroken, auditBrokenParams(audit.Report{FirstBadSeq: 4711, Problem: audit.ProblemHashMismatch}),
			nil, []string{"4711", audit.ProblemHashMismatch}},
	} {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", c.template, lang, c.params)
			assert.NotContains(t, m.Subject, "{{", "%s %s", c.template, lang)
			assert.NotContains(t, m.Body, "{{", "%s %s", c.template, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s: the key itself means a missing text", c.template, lang)
			assert.NotContains(t, m.Body, "email.", "%s %s: the key itself means a missing text", c.template, lang)
			for _, want := range c.subject {
				assert.Contains(t, m.Subject, want, "%s %s", c.template, lang)
			}
			for _, want := range c.body {
				assert.Contains(t, m.Body, want, "%s %s", c.template, lang)
			}
		}
	}
	en := s.Render("ada@example.com", TemplateJobTampered, "en", tamperedAlertParams(id, "sshkey.remove"))
	assert.NotContains(t, en.Body, "attempts", "a tampered job is not an exhausted one")
}

// Phase 5 (R40 row 29, scan D1): the access check is read-only work with one attempt; an import changes a
// vault (three attempts, retried only before the send); the poll (one attempt), the poll scheduler and the
// auto-deploy planner are continuity work (owner decision 2026-10-20: they run in the continuity window of a
// lock; the scheduler refuses only a ClassChange task and the planner re-checks ClassContinuity itself).
func TestPhase5JobTypes(t *testing.T) {
	assert.Equal(t, license.ClassReadOnly, KVTestConnection.Class)
	assert.Equal(t, license.ClassContinuity, KVPoll.Class)
	assert.Equal(t, license.ClassChange, KVImport.Class)
	assert.Equal(t, license.ClassContinuity, KVSchedule.Class)
	assert.Equal(t, license.ClassContinuity, KVAutoDeploy.Class, "a ClassChange periodic task would panic at start-up")
	assert.Equal(t, "kv.schedule", KVSchedule.Name)
	assert.Equal(t, "kv.auto_deploy", KVAutoDeploy.Name)
	assert.Equal(t, 1, MaxAttemptsFor(KVTestConnection))
	assert.Equal(t, 1, MaxAttemptsFor(KVPoll))
	assert.Equal(t, 3, MaxAttemptsFor(KVImport))
	assert.False(t, AlertsWhenExhausted(KVPoll), "the vault's status and its own email carry a failed poll")
	assert.True(t, AlertsWhenExhausted(KVImport))
	assert.True(t, AlertsWhenExhausted(KVTestConnection))
	assert.NotPanics(t, func() {
		NewScheduler(nil, &fakeGate{}, quiet,
			Task{Type: KVSchedule, Every: time.Minute, Run: func(context.Context) error { return nil }},
			Task{Type: KVAutoDeploy, Every: time.Minute, Run: func(context.Context) error { return nil }})
	})
}

func TestRetryWaitIsCappedAndOnlyForRetries(t *testing.T) {
	assert.Equal(t, 80*time.Second, retryWait(RetryAfter("x.y", nil, nil, 80*time.Second)))
	assert.Equal(t, maxBackoff, retryWait(RetryAfter("x.y", nil, nil, 5*time.Hour)), "M5: capped at the longest backoff")
	assert.Zero(t, retryWait(RetryAfter("x.y", nil, nil, -time.Second)))
	assert.Zero(t, retryWait(Fail("x.y", nil, nil)))
	assert.Zero(t, retryWait(errors.New("plain")))
}

// A job without a payload is stored and authenticated as the empty object, so its MAC equals that of an empty
// payload, and keys are sorted whatever the map's order.
func TestNilPayloadIsTheEmptyObject(t *testing.T) {
	assert.Equal(t, "{}", string(canonicalPayload(nil)))
	assert.Equal(t, canonicalPayload(map[string]string{}), canonicalPayload(nil))
	assert.Equal(t, `{"a":"1","b":"2"}`, string(canonicalPayload(map[string]string{"b": "2", "a": "1"})))
}

// classify never returns nil, so a handler that reports failure without an error is still recorded as an
// unexpected, retryable failure (never a success).
func TestClassifyNeverReturnsNil(t *testing.T) {
	f := classify(nil)
	require.NotNil(t, f)
	assert.Equal(t, Retryable, f.Class)
	assert.Equal(t, "internal.unexpected", f.Reason)
	assert.Equal(t, NeedsAttention, classify(Attention("x.y", nil, nil)).Class)
}

// ACME issuance: an order a person starts changes the world (a certificate authority and, through the hook, a DNS
// zone), so it is refused and held in lock and runs once (a retry would start a second order and burn the authority's
// rate limit; the planner paces repeats); the renewal planner's order of an issued certificate (acme.renew) is
// continuity work, also run once; cleanup of authorizations and leftover challenge records runs in every state; the
// renewal planner and the auto-deploy planner are periodic continuity work like the Key Vault ones.
func TestACMEJobTypes(t *testing.T) {
	assert.Equal(t, license.ClassChange, ACMEIssue.Class)
	assert.Equal(t, license.ClassContinuity, ACMERenew.Class)
	assert.Equal(t, "acme.renew", ACMERenew.Name)
	assert.Equal(t, 1, MaxAttemptsFor(ACMERenew))
	assert.True(t, AlertsWhenExhausted(ACMERenew))
	assert.Equal(t, license.ClassAlways, ACMECleanup.Class)
	assert.Equal(t, license.ClassContinuity, ACMESchedule.Class, "a ClassChange periodic task would panic at start-up")
	assert.Equal(t, license.ClassContinuity, ACMEAutoDeploy.Class)
	assert.Equal(t, "acme.issue", ACMEIssue.Name)
	assert.Equal(t, "acme.cleanup", ACMECleanup.Name)
	assert.Equal(t, "acme.schedule", ACMESchedule.Name)
	assert.Equal(t, "acme.auto_deploy", ACMEAutoDeploy.Name)
	assert.Equal(t, 1, MaxAttemptsFor(ACMEIssue))
	assert.Equal(t, 5, MaxAttemptsFor(ACMECleanup), "a hook that is briefly down: five tries on the queue's backoff")
	assert.False(t, AlertsWhenExhausted(ACMECleanup), "the order records the failure and the sweep queues the cleanup again hourly")
	assert.True(t, AlertsWhenExhausted(ACMEIssue))
	assert.Equal(t, license.ClassAlways, ACMESweep.Class, "the sweep ends crashed orders and queues cleanups in lock too")
	assert.Equal(t, "acme.sweep", ACMESweep.Name)
	assert.NotPanics(t, func() {
		NewScheduler(nil, &fakeGate{}, quiet,
			Task{Type: ACMESchedule, Every: time.Minute, Run: func(context.Context) error { return nil }},
			Task{Type: ACMEAutoDeploy, Every: time.Minute, Run: func(context.Context) error { return nil }},
			Task{Type: ACMESweep, Every: time.Minute, Run: func(context.Context) error { return nil }})
	})
}

// The continuity window (owner decision 2026-10-20): the automatic deployment shares certificate.deploy's handler and
// dedupe namespace with the continuity class; after the window a refused continuity job is held when it changes a
// system and cancelled when it only reads, as its kind of work was before.
func TestContinuityJobTypes(t *testing.T) {
	assert.Equal(t, license.ClassContinuity, CertificateDeployAuto.Class)
	assert.Equal(t, "certificate.deploy_auto", CertificateDeployAuto.Name)
	assert.Equal(t, MaxAttemptsFor(CertificateDeploy), MaxAttemptsFor(CertificateDeployAuto))
	assert.True(t, heldInLock(CertificateDeploy))
	assert.True(t, heldInLock(CertificateDeployAuto))
	assert.True(t, heldInLock(ACMERenew))
	assert.False(t, heldInLock(KVPoll), "a poll only reads: cancelled, and the scheduler queues it again after a renewal")
	assert.False(t, heldInLock(TargetDiscover))
	assert.False(t, heldInLock(AuditVerify))
	assert.Equal(t, []string{"kv.poll"}, continuityReadOnlyTypes())
	for _, typ := range Types() {
		if typ.Class == license.ClassContinuity {
			assert.Contains(t, []string{"acme.renew", "acme.schedule", "acme.auto_deploy", "certificate.deploy_auto", "kv.poll",
				"kv.schedule", "kv.auto_deploy", "drift.repair"}, typ.Name, "continuity is the upkeep of what is already managed only")
		}
	}
}
