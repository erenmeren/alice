package acmejobs

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"alice/internal/inventory"
	"alice/internal/jobs"
)

// AutoDeployPlanner is the part of *inventory.Service the acme.auto_deploy task uses.
type AutoDeployPlanner interface {
	PlanACMEAutoDeploy(ctx context.Context) (inventory.ACMEDeployRun, error)
}

var _ AutoDeployPlanner = (*inventory.Service)(nil)

// errDeployPlanFailed is the error of a tick in which the automatic deployment planner failed for some certificates
// (their errors are logged by type only); the next tick plans again.
var errDeployPlanFailed = errors.New("acmejobs: the ACME automatic deployment plan failed for some certificates")

// AutoDeployTask is the periodic acme.auto_deploy: it plans the deployments of newly issued ACME certificates to their
// bound locations (inventory.PlanACMEAutoDeploy). Each deployment is a certificate.deploy_auto job (ClassContinuity: it
// runs in the continuity window of a lock and is held after it) run by the existing deployment engine (deployjobs),
// exactly as a person's request and the Key Vault planner's are. The task is continuity work too (the scheduler refuses
// only ClassChange tasks), so the scheduler's gate pauses it in lock once the window has ended; the planner itself
// returns at once while the gate refuses continuity work. It runs on the leader only (the scheduler's advisory
// lock), every minute in a release build and never on the wall clock in the e2e build (the journeys run it with
// POST /test/scheduler/run {"task": "acme.auto_deploy"}).
func AutoDeployTask(p AutoDeployPlanner, every time.Duration, log *slog.Logger) jobs.Task {
	if p == nil {
		panic("acmejobs: AutoDeployTask needs a planner")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return jobs.Task{Type: jobs.ACMEAutoDeploy, Every: every, Run: func(ctx context.Context) error {
		run, err := p.PlanACMEAutoDeploy(ctx)
		if run.Created > 0 || run.Held > 0 || run.Stopped > 0 {
			log.Info("planned automatic deployments of ACME certificates", "created", run.Created, "held", run.Held, "stopped", run.Stopped)
		}
		switch {
		case err == nil:
			return nil
		case errors.Is(err, inventory.ErrClaimLost), ctx.Err() != nil:
			return err
		}
		log.Error("planning automatic deployments of ACME certificates failed for some certificates", "created", run.Created,
			"error_type", typesOf(err))
		return errDeployPlanFailed
	}}
}
