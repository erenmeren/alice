package main

import (
	"errors"
	"fmt"

	"alice/internal/jobs"
	"alice/internal/providers"
)

// shippedProviders are the provider kinds this build registers (registerProviders).
var shippedProviders = []providers.Kind{providers.KindLinuxSSH, providers.KindNginx}

// checkWiring refuses to start a server that is not completely wired: a provider this build ships
// is not registered, or a job type has neither a handler on the runner nor a periodic task (a
// queued job of such a type is never claimed and waits forever; a periodic type that is not
// scheduled never runs, so for the recovery sweep nothing recovers an interrupted deployment).
// serve calls it before anything runs; it names every gap at once.
func checkWiring(reg *providers.Registry, runner *jobs.Runner, sched *jobs.Scheduler) error {
	var errs []error
	for _, k := range shippedProviders {
		if _, ok := reg.Get(k); !ok {
			errs = append(errs, fmt.Errorf("provider %s is not registered", k))
		}
	}
	for _, t := range jobs.Types() {
		if !runner.Handles(t) && !sched.Schedules(t) {
			errs = append(errs, fmt.Errorf("job type %s has no handler and is not scheduled", t.Name))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("alice is not completely wired: %w", errors.Join(errs...))
}
