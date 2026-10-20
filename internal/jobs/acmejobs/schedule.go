package acmejobs

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

// Planner is the part of *inventory.Service the acme.schedule task uses.
type Planner interface {
	PlanACMERenewals(ctx context.Context) (inventory.ACMERenewRun, error)
}

var _ Planner = (*inventory.Service)(nil)

// errPlanFailed is the error of a tick in which the renewal planner failed for some certificates (their errors are
// logged by type only: a database error's text can carry values); the next tick plans again.
var errPlanFailed = errors.New("acmejobs: the ACME renewal plan failed for some certificates")

// ScheduleTask is the periodic acme.schedule: the renewal planner (inventory.PlanACMERenewals; each order is an
// acme.renew job, ClassContinuity). The task is continuity work too (owner decision 2026-10-20; the scheduler refuses
// only ClassChange tasks): it runs in the continuity window of a lock, and the scheduler's gate pauses it once the
// window has ended and while the licence cannot be verified; the planner itself returns at once while the gate refuses
// continuity work (no CA contact, no row written). It runs on the leader only (the scheduler's advisory lock), every
// minute in a release build and never on the wall clock in the e2e build (the journeys run it with
// POST /test/scheduler/run after moving the demo clock).
func ScheduleTask(p Planner, every time.Duration, log *slog.Logger) jobs.Task {
	if p == nil {
		panic("acmejobs: ScheduleTask needs a planner")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return jobs.Task{Type: jobs.ACMESchedule, Every: every, Run: func(ctx context.Context) error {
		run, err := p.PlanACMERenewals(ctx)
		if run.Started > 0 || run.Stopped > 0 || run.Failed > 0 {
			log.Info("planned ACME renewals", "started", run.Started, "stopped", run.Stopped, "failed", run.Failed, "ari_checked", run.ARIChecked)
		}
		switch {
		case err == nil:
			return nil
		case ctx.Err() != nil:
			return err
		}
		log.Error("planning ACME renewals failed for some certificates", "started", run.Started, "error_type", typesOf(err))
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
