// Package driftjobs holds the certificate drift work (R52, docs/superpowers/rulings/certificate-drift.md): the queue
// handler drift.observe, which observes the bound locations of one server, and the periodic tasks drift.schedule (it
// queues the observations that are due) and drift.repair (it repairs drifted locations in mode auto through the
// deployment engine). The observation uses the existing paths only: the certificate half of a discovery (Discover with
// certificates only, stored by Reconcile: the file observation) and the deployment engine's verification
// (VerifyDeployment with the desired certificate: the TLS observation). Nothing here writes to a server.
package driftjobs

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

// Inventory is the part of *inventory.Service the handler and the tasks use.
type Inventory interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	Credentials() providers.CredentialSource
	HostKeyStore() providers.HostKeyStore
	RecordConnectionFailure(ctx context.Context, id uuid.UUID, reason string) error
	Reconcile(ctx context.Context, id uuid.UUID, res providers.DiscoveryResult) (inventory.ReconcileSummary, error)
	DriftProbes(ctx context.Context, target uuid.UUID) ([]inventory.DriftProbe, error)
	RecordDriftObservations(ctx context.Context, target uuid.UUID, results []inventory.DriftResult) (int, error)
	ScheduleDriftObservations(ctx context.Context) (int, error)
	PlanDriftRepairs(ctx context.Context) (inventory.DriftRepairRun, error)
}

var _ Inventory = (*inventory.Service)(nil)

// Deps are the handler's and the tasks' dependencies.
type Deps struct {
	Inventory Inventory
	Registry  *providers.Registry
	Clock     clock.Clock
	Log       *slog.Logger
}

// Register registers the drift.observe handler on the runner. It panics on a missing dependency.
func Register(r *jobs.Runner, d Deps) {
	if d.Inventory == nil || d.Registry == nil || d.Clock == nil {
		panic("driftjobs: Register needs the inventory, the provider registry and a clock")
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	h := &handlers{d: d}
	r.Handle(jobs.DriftObserve, h.observe)
}

type handlers struct{ d Deps }

// observeTimeout bounds one observation of a server: the certificate half of a discovery (the provider's own bound is
// a 60 s dump and the connection) and at most 20 locations' verifications (each at most 10 endpoints, a few attempts).
// A variable so a test can shorten it.
var observeTimeout = 15 * time.Minute

// open returns a session after the target checks of every job that connects (a changed or unconfirmed host key and a
// disabled server run nothing, F-31) and the closed reason when it cannot.
func (h *handlers) open(ctx context.Context, id uuid.UUID) (providers.Session, inventory.Target, string, error) {
	ref, t, err := h.d.Inventory.TargetRef(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, t, "system.not_found", jobs.Fail("system.not_found", nil, err)
	case err != nil:
		return nil, t, "internal.unexpected", jobs.Retry("internal.unexpected", nil, err)
	case t.Status == inventory.StatusHostKeyChanged:
		return nil, t, "target.host_key_changed", jobs.Fail("target.host_key_changed", nil, nil)
	case t.Status == inventory.StatusDisabled:
		return nil, t, "target.disabled", jobs.Fail("target.disabled", nil, nil)
	case t.Status == inventory.StatusPendingHostKey:
		return nil, t, "target.host_key_unconfirmed", jobs.Fail("target.host_key_unconfirmed", nil, nil)
	}
	p, ok := h.d.Registry.Get(ref.Kind)
	if !ok {
		return nil, t, "internal.unexpected", jobs.Fail("internal.unexpected", nil, fmt.Errorf("driftjobs: no provider %q", ref.Kind))
	}
	sess, err := p.Open(ctx, ref, h.d.Inventory.Credentials(), providers.Env{Clock: h.d.Clock, HostKeys: h.d.Inventory.HostKeyStore(), Log: h.d.Log})
	if err != nil {
		var pe *providers.Error
		code := "internal.unexpected"
		if errors.As(err, &pe) {
			code = pe.Code
			if rerr := h.d.Inventory.RecordConnectionFailure(ctx, id, pe.Code); rerr != nil {
				h.d.Log.Error("could not record a connection failure", "target_id", id.String(), "error_type", fmt.Sprintf("%T", rerr))
			}
		}
		// One attempt (jobs.MaxAttemptsFor): a failed observation waits for the next interval, without a job.dead e-mail.
		f := jobs.FromProvider(err)
		var jf *jobs.Failure
		if errors.As(f, &jf) {
			return nil, t, code, jobs.Fail(jf.Reason, jf.Params, err)
		}
		return nil, t, code, f
	}
	return sess, t, "", nil
}

// observe is drift.observe: the server's certificate files are scanned (when its provider discovers certificates;
// stored by Reconcile only while this run holds the job), then every bound location the inventory names
// (inventory.DriftProbes) is probed with the verification of its desired certificate, and what was seen is stored
// (inventory.RecordDriftObservations: the drift episodes and their notices). A server that cannot be used records the
// reason on each of its locations (their health becomes unreachable) and ends the job failed.
func (h *handlers) observe(jobCtx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(jobCtx, observeTimeout)
	defer cancel()
	claimed := inventory.WithClaim(jobCtx, inventory.Claim{JobID: j.ID, Attempt: j.Attempt})
	sess, t, code, err := h.open(ctx, j.TargetID)
	if err != nil {
		if code != "system.not_found" {
			h.recordFailure(claimed, j.TargetID, code)
		}
		return nil, err
	}
	defer func() {
		if err := sess.Close(); err != nil {
			h.d.Log.Warn("closing a provider session failed", "error_type", fmt.Sprintf("%T", err))
		}
	}()
	out := map[string]any{"file_scan": false}
	if slices.Contains(t.Capabilities, string(providers.CapDiscoverCerts)) {
		res, err := sess.Discover(ctx, providers.DiscoverRequest{Certificates: true})
		if err == nil {
			_, err = h.d.Inventory.Reconcile(claimed, j.TargetID, res)
		}
		switch {
		case errors.Is(err, inventory.ErrClaimLost):
			return nil, jobs.Retry("job.lease_expired", nil, err)
		case err != nil:
			// The probes still run: the website is observed even when the files could not be read this time.
			h.d.Log.Warn("the file scan of an observation failed", "target_id", j.TargetID.String(), "error_type", fmt.Sprintf("%T", err))
		default:
			out["file_scan"] = true
		}
	}
	probes, err := h.d.Inventory.DriftProbes(ctx, j.TargetID)
	if err != nil {
		return nil, jobs.Fail("internal.unexpected", nil, err)
	}
	results := make([]inventory.DriftResult, 0, len(probes))
	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		vr, err := sess.VerifyDeployment(ctx, p.Request)
		results = append(results, inventory.DriftResultOf(p.LocationID, p.Request, vr, err, h.d.Clock.Now()))
	}
	drifted, err := h.d.Inventory.RecordDriftObservations(claimed, j.TargetID, results)
	if errors.Is(err, inventory.ErrClaimLost) {
		return nil, jobs.Retry("job.lease_expired", nil, err)
	}
	if err != nil {
		return nil, jobs.Fail("internal.unexpected", nil, err)
	}
	out["probed"], out["drifted"] = len(results), drifted
	return out, nil
}

// recordFailure stores code as the failed probe of every location the observation would have probed.
func (h *handlers) recordFailure(ctx context.Context, target uuid.UUID, code string) {
	probes, err := h.d.Inventory.DriftProbes(ctx, target)
	if err != nil {
		h.d.Log.Error("could not read the locations of a failed observation", "target_id", target.String(), "error_type", fmt.Sprintf("%T", err))
		return
	}
	now := h.d.Clock.Now()
	results := make([]inventory.DriftResult, 0, len(probes))
	for _, p := range probes {
		results = append(results, inventory.DriftResult{LocationID: p.LocationID, At: now.UTC(), Error: code})
	}
	if _, err := h.d.Inventory.RecordDriftObservations(ctx, target, results); err != nil {
		h.d.Log.Error("could not record a failed observation", "target_id", target.String(), "error_type", fmt.Sprintf("%T", err))
	}
}

// ScheduleTask is the periodic drift.schedule (ClassReadOnly: the scheduler pauses it in lock): it queues a
// drift.observe job for every server with a bound location whose observation is due (inventory.ScheduleDriftObservations).
// It runs on the leader only, every `every` (five minutes in a release build; never on the wall clock in the e2e build:
// the journeys run it with POST /test/scheduler/run {"task": "drift.schedule"}).
func ScheduleTask(inv Inventory, every time.Duration, log *slog.Logger) jobs.Task {
	if inv == nil {
		panic("driftjobs: ScheduleTask needs the inventory")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return jobs.Task{Type: jobs.DriftSchedule, Every: every, Run: func(ctx context.Context) error {
		n, err := inv.ScheduleDriftObservations(ctx)
		if n > 0 {
			log.Info("queued the observation of bound certificate locations", "servers", n)
		}
		return err
	}}
}

// RepairTask is the periodic drift.repair (ClassContinuity, as certificate.deploy_auto: it runs in the continuity window
// of a lock too, and the planner asks the gate itself): it repairs drifted locations in mode auto
// (inventory.PlanDriftRepairs), each repair a certificate.deploy_auto job run by the deployment engine. Every minute in
// a release build; never on the wall clock in the e2e build (POST /test/scheduler/run {"task": "drift.repair"}).
func RepairTask(inv Inventory, every time.Duration, log *slog.Logger) jobs.Task {
	if inv == nil {
		panic("driftjobs: RepairTask needs the inventory")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return jobs.Task{Type: jobs.DriftRepair, Every: every, Run: func(ctx context.Context) error {
		run, err := inv.PlanDriftRepairs(ctx)
		if run.Created > 0 || run.BackedOff > 0 {
			log.Info("planned repairs of drifted certificate locations", "created", run.Created, "backed_off", run.BackedOff)
		}
		return err
	}}
}
