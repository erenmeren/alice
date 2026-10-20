package main

import (
	"errors"
	"fmt"

	"alice/internal/jobs"
	"alice/internal/providers"
)

// shippedProviders are the provider kinds this build registers (registerProviders).
var shippedProviders = []providers.Kind{providers.KindLinuxSSH, providers.KindNginx, providers.KindApache, providers.KindHAProxy, providers.KindAzureKV}

// periodicTypes are the job types that run as periodic tasks of the scheduler (buildScheduler);
// every other job type is a queue type and needs a handler on the runner. A new type is a queue
// type until it is listed here.
var periodicTypes = []jobs.Type{jobs.LicenseEvaluate, jobs.NotifySend, jobs.AuditVerify, jobs.MaintenanceCleanup,
	jobs.DiscoverySchedule, jobs.DeploymentRecoverySweep, jobs.KVSchedule, jobs.KVAutoDeploy,
	jobs.RotationPlan, jobs.RotationSweep, jobs.SSHKeyDestroyRetired, jobs.AlertsScan,
	jobs.BackupSchedule, jobs.TLSRenew, jobs.AuditForward, jobs.JobsHeartbeat,
	jobs.ACMESchedule, jobs.ACMEAutoDeploy, jobs.ACMESweep, jobs.NetdiscoSchedule, jobs.NetdiscoRetention, jobs.IncidentAdvance}

// checkWiring refuses to start a server that is not completely wired: a provider this build ships
// is not registered, a queue job type has no handler on the runner (a queued job of that type is
// never claimed and waits forever), or a periodic type is not scheduled (it never runs; for the
// recovery sweep nothing would recover an interrupted deployment). serve calls it before anything
// runs; it names every gap at once.
func checkWiring(reg *providers.Registry, runner *jobs.Runner, sched *jobs.Scheduler) error {
	var errs []error
	for _, k := range shippedProviders {
		if _, ok := reg.Get(k); !ok {
			errs = append(errs, fmt.Errorf("provider %s is not registered", k))
		}
	}
	for _, t := range jobs.Types() {
		if isPeriodic(t) {
			if !sched.Schedules(t) {
				errs = append(errs, fmt.Errorf("periodic job type %s is not scheduled", t.Name))
			}
			continue
		}
		if !runner.Handles(t) {
			errs = append(errs, fmt.Errorf("queue job type %s has no handler", t.Name))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("alice is not completely wired: %w", errors.Join(errs...))
}

func isPeriodic(t jobs.Type) bool {
	for _, p := range periodicTypes {
		if p == t {
			return true
		}
	}
	return false
}
