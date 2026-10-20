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
	SweepImports(ctx context.Context) (int, error)
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
// 13) and sweeps the imports nothing else would end (a job that ended without the handler finishing its
// import: discarded, reaped before the mark, panicked on the last attempt; and the unconditional end of an
// uncertain import). Each does its work whatever the other returns; the errors are logged by type and
// returned together. It is continuity work (owner decision 2026-10-20): it runs in the continuity window of a lock, so
// renewed vault versions are still seen, and the scheduler's gate pauses it once the window has ended.
func ScheduleTask(s PollScheduler, every time.Duration, log *slog.Logger) jobs.Task {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return jobs.Task{Type: jobs.KVSchedule, Every: every, Run: func(ctx context.Context) error {
		_, pollErr := s.ScheduleKVPolls(ctx)
		ended, sweepErr := s.SweepImports(ctx)
		if ended > 0 {
			log.Info("ended imports nobody else would end", "count", ended)
		}
		if pollErr != nil {
			log.Error("scheduling the Key Vault polls failed", "error_type", typesOf(pollErr))
		}
		if sweepErr != nil {
			log.Error("sweeping the imports failed", "error_type", typesOf(sweepErr))
		}
		if pollErr != nil || sweepErr != nil {
			return errScheduleFailed
		}
		return nil
	}}
}

// errScheduleFailed is the error of a tick in which the poll scheduler or the import sweep failed (their
// own errors are logged by type: a database error's text can carry values).
var errScheduleFailed = errors.New("kvjobs: scheduling the polls or sweeping the imports failed")

// errPlanFailed is the error of a planner run in which a binding failed. The errors of single bindings
// are logged by type only (a database error's text can carry values); the next tick plans again.
var errPlanFailed = errors.New("kvjobs: the automatic deployment plan failed for some bindings")

// AutoDeployTask is the periodic kv.auto_deploy: it plans the deployments of renewed vault versions
// (PlanKVAutoDeploy; each deployment is a certificate.deploy_auto job, ClassContinuity: it runs in the continuity
// window of a lock and is held after it). The task is continuity work too (the scheduler refuses only ClassChange
// tasks, scan D1); the planner itself returns at once while the gate refuses continuity work, and the periodic gate
// stops it in the same states. It runs on the scheduler's context, which carries no job claim.
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
