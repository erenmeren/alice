package kvjobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"alice/internal/inventory"
	"alice/internal/jobs"
)

// PollScheduler is the part of *inventory.Service the kv.schedule task uses.
type PollScheduler interface {
	ScheduleKVPolls(ctx context.Context) (int, error)
}

// AutoDeployPlanner is the part of *inventory.Service the kv.auto_deploy task uses.
type AutoDeployPlanner interface {
	PlanKVAutoDeploy(ctx context.Context) (int, error)
}

var (
	_ PollScheduler     = (*inventory.Service)(nil)
	_ AutoDeployPlanner = (*inventory.Service)(nil)
)

// ScheduleTask is the periodic kv.schedule: it queues a kv.poll for every vault that is due (R40 row
// 13). It is read-only work: the scheduler's gate pauses it in lock, so no poll is queued then.
func ScheduleTask(s PollScheduler, every time.Duration) jobs.Task {
	return jobs.Task{Type: jobs.KVSchedule, Every: every, Run: func(ctx context.Context) error {
		_, err := s.ScheduleKVPolls(ctx)
		return err
	}}
}

// errPlanFailed is the error of a planner run in which a binding failed. The errors of single bindings
// are logged by type only (a database error's text can carry values); the next tick plans again.
var errPlanFailed = errors.New("kvjobs: the automatic deployment plan failed for some bindings")

// AutoDeployTask is the periodic kv.auto_deploy: it plans the deployments of renewed vault versions
// (PlanKVAutoDeploy; each deployment is a certificate.deploy job, ClassChange, refused and held in
// lock). The task's class is ReadOnly because the scheduler refuses ClassChange tasks (scan D1); the
// planner itself returns at once while the gate refuses changes, and the periodic gate stops it in the
// same states. It runs on the scheduler's context, which carries no job claim.
func AutoDeployTask(p AutoDeployPlanner, every time.Duration, log *slog.Logger) jobs.Task {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return jobs.Task{Type: jobs.KVAutoDeploy, Every: every, Run: func(ctx context.Context) error {
		n, err := p.PlanKVAutoDeploy(ctx)
		if n > 0 {
			log.Info("planned automatic deployments", "created", n)
		}
		switch {
		case err == nil:
			return nil
		case errors.Is(err, inventory.ErrClaimLost), ctx.Err() != nil:
			return err
		}
		log.Error("planning automatic deployments failed for some bindings", "created", n, "error_type", typesOf(err))
		return errPlanFailed
	}}
}

// typesOf lists the Go types of the (joined) errors of a planner run, without their text.
func typesOf(err error) string {
	var types []string
	var walk func(error)
	walk = func(e error) {
		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, m := range j.Unwrap() {
				walk(m)
			}
			return
		}
		t := fmt.Sprintf("%T", e)
		for _, have := range types {
			if have == t {
				return
			}
		}
		types = append(types, t)
	}
	walk(err)
	if len(types) > 5 {
		types = types[:5]
	}
	return strings.Join(types, ",")
}
