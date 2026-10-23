// Package winjobs holds the Windows certificate cleanup (R62 W3, docs/superpowers/rulings/windows-iis.md Rulings 4, 8,
// 9, 12, 13): the queue handler windows.cleanup, which plans and applies the cleanup of one Windows server through the
// provider's providers.CertificateCleaner, and the periodic task windows.cleanup_schedule, which queues the daily run of
// every Windows server. Two judges must agree before a certificate is removed: the helper (Alice imported it, nothing on
// the server uses it, how long it has been unused; judged again at apply time) and Alice (inventory.JudgeCleanup: no
// rollback can need it, no deployment is running with it, no location holds it, a compromised one at once, the switch).
package winjobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
)

// Inventory is the part of *inventory.Service the handler and the task use.
type Inventory interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	Credentials() providers.CredentialSource
	HostKeyStore() providers.HostKeyStore
	RecordConnectionFailure(ctx context.Context, id uuid.UUID, reason string) error
	CleanupWatch(ctx context.Context, target uuid.UUID) ([]providers.CleanupRef, error)
	JudgeCleanup(ctx context.Context, target uuid.UUID, plan providers.CleanupPlan) (inventory.CleanupDecision, error)
	RecordCleanup(ctx context.Context, target uuid.UUID, incident *uuid.UUID, plan providers.CleanupPlan, d inventory.CleanupDecision,
		res providers.CleanupApplyResult) error
	ScheduleWindowsCleanup(ctx context.Context) (int, error)
}

var _ Inventory = (*inventory.Service)(nil)

// Deps are the handler's and the task's dependencies.
type Deps struct {
	Inventory Inventory
	Registry  *providers.Registry
	Clock     clock.Clock
	Log       *slog.Logger
}

// Register registers the windows.cleanup handler on the runner. It panics on a missing dependency.
func Register(r *jobs.Runner, d Deps) {
	if d.Inventory == nil || d.Registry == nil || d.Clock == nil {
		panic("winjobs: Register needs the inventory, the provider registry and a clock")
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	h := &handlers{d: d}
	r.Handle(jobs.WindowsCleanup, h.cleanup)
}

type handlers struct{ d Deps }

// cleanupTimeout bounds one cleanup of a server: a plan and an apply, each one helper call of at most the helper's budget
// (winproto.HelperBudget) and its connection. A variable so a test can shorten it.
var cleanupTimeout = 10 * time.Minute

// open returns a session after the target checks of every job that connects (driftjobs' open: a changed or unconfirmed
// host key and a disabled server run nothing, F-31). A connection failure is recorded on the server and fails the job in
// its one attempt (the next day's run tries again, without a job.dead e-mail).
func (h *handlers) open(ctx context.Context, id uuid.UUID) (providers.Session, inventory.Target, error) {
	ref, t, err := h.d.Inventory.TargetRef(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, t, jobs.Fail("system.not_found", nil, err)
	case err != nil:
		return nil, t, jobs.Retry("internal.unexpected", nil, err)
	case t.Status == inventory.StatusHostKeyChanged:
		return nil, t, jobs.Fail("target.host_key_changed", nil, nil)
	case t.Status == inventory.StatusDisabled:
		return nil, t, jobs.Fail("target.disabled", nil, nil)
	case t.Status == inventory.StatusPendingHostKey:
		return nil, t, jobs.Fail("target.host_key_unconfirmed", nil, nil)
	case !slices.Contains(t.Capabilities, string(providers.CapCleanupCertificates)):
		// Before any connection: a server whose provider does not clean up is never dialled for it.
		return nil, t, jobs.Fail("internal.unexpected", nil, fmt.Errorf("winjobs: the server cannot clean up certificates"))
	}
	p, ok := h.d.Registry.Get(ref.Kind)
	if !ok {
		return nil, t, jobs.Fail("internal.unexpected", nil, fmt.Errorf("winjobs: no provider %q", ref.Kind))
	}
	sess, err := p.Open(ctx, ref, h.d.Inventory.Credentials(), providers.Env{Clock: h.d.Clock, HostKeys: h.d.Inventory.HostKeyStore(), Log: h.d.Log})
	if err != nil {
		var pe *providers.Error
		if errors.As(err, &pe) {
			if rerr := h.d.Inventory.RecordConnectionFailure(ctx, id, pe.Code); rerr != nil {
				h.d.Log.Error("could not record a connection failure", "target_id", id.String(), "error_type", fmt.Sprintf("%T", rerr))
			}
			return nil, t, jobs.Fail(pe.Code, pe.Params, err)
		}
		return nil, t, jobs.FromProvider(err)
	}
	return sess, t, nil
}

// cleanup is windows.cleanup: the server's checks, the watch list (inventory.CleanupWatch: the compromised certificates
// the server ever held), the plan (PlanCleanup: the helper's candidates and its verdict on each watched certificate,
// with its own bookkeeping), Alice's judgement (inventory.JudgeCleanup), the apply of what she would remove (only when
// that is not nothing), and the record (inventory.RecordCleanup: the audit rows, and an incident's notice). The result
// counts the candidates, the removals and what was already gone, lists every certificate that stays with its reason
// (Alice's, then the server's at apply time) and carries the plan's own facts (pruned files, a partial listing, its
// warnings). A provider error fails the job as the provider says (windows.cleanup_outcome_unknown is retryable: the job
// runs once, and the next day's plan settles it); Alice's own failures are internal.unexpected.
func (h *handlers) cleanup(jobCtx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(jobCtx, cleanupTimeout)
	defer cancel()
	sess, _, err := h.open(ctx, j.TargetID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := sess.Close(); err != nil {
			h.d.Log.Warn("closing a provider session failed", "error_type", fmt.Sprintf("%T", err))
		}
	}()
	cleaner, ok := sess.(providers.CertificateCleaner)
	if !ok {
		return nil, jobs.Fail("internal.unexpected", nil, fmt.Errorf("winjobs: the server's provider session cannot clean up certificates"))
	}
	var incident *uuid.UUID
	if raw, ok := j.Payload["incident_id"]; ok {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, jobs.Fail("internal.unexpected", nil, fmt.Errorf("winjobs: the incident id is not a uuid: %w", err))
		}
		incident = &id
	}
	watch, err := h.d.Inventory.CleanupWatch(ctx, j.TargetID)
	if err != nil {
		return nil, jobs.Fail("internal.unexpected", nil, err)
	}
	plan, err := cleaner.PlanCleanup(ctx, watch)
	if err != nil {
		return nil, jobs.FromProvider(err)
	}
	d, err := h.d.Inventory.JudgeCleanup(ctx, j.TargetID, plan)
	if err != nil {
		return nil, jobs.Fail("internal.unexpected", nil, err)
	}
	var res providers.CleanupApplyResult
	if len(d.Remove) > 0 {
		if res, err = cleaner.ApplyCleanup(ctx, d.Remove); err != nil {
			return nil, jobs.FromProvider(err)
		}
	}
	if err := h.d.Inventory.RecordCleanup(ctx, j.TargetID, incident, plan, d, res); err != nil {
		return nil, jobs.Fail("internal.unexpected", nil, err)
	}
	return result(plan, d, res), nil
}

// result is the job's result: what the plan found, what was removed or already absent, and what stays and why.
func result(plan providers.CleanupPlan, d inventory.CleanupDecision, res providers.CleanupApplyResult) map[string]any {
	removed, absent := 0, 0
	kept := make([]map[string]string, 0, len(d.Kept))
	for _, k := range d.Kept {
		kept = append(kept, map[string]string{"sha256": k.SHA256, "reason": k.Reason})
	}
	for _, r := range res.Results {
		switch r.Result {
		case providers.CleanupRemoved:
			removed++
		case providers.CleanupAbsent:
			absent++
		default:
			kept = append(kept, map[string]string{"sha256": r.SHA256, "reason": r.Reason})
		}
	}
	warnings := plan.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	return map[string]any{"candidates": len(plan.Candidates), "removed": removed, "absent": absent, "kept": kept,
		"pruned": plan.Pruned, "partial": plan.Partial, "warnings": warnings}
}

// ScheduleTask is the periodic windows.cleanup_schedule (ClassReadOnly: the scheduler pauses it in lock): it queues the
// daily windows.cleanup of every Windows server that is due (inventory.ScheduleWindowsCleanup). It runs on the leader
// only, every `every` (an hour in a release build; never on the wall clock in the e2e build: a journey or a test runs it
// with POST /test/scheduler/run {"task": "windows.cleanup_schedule"}).
func ScheduleTask(inv Inventory, every time.Duration, log *slog.Logger) jobs.Task {
	if inv == nil {
		panic("winjobs: ScheduleTask needs the inventory")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return jobs.Task{Type: jobs.WindowsCleanupSchedule, Every: every, Run: func(ctx context.Context) error {
		n, err := inv.ScheduleWindowsCleanup(ctx)
		if n > 0 {
			log.Info("queued the certificate cleanup of Windows servers", "servers", n)
		}
		return err
	}}
}
