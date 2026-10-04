package main

import (
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
)

// wiringServices is a services value whose fields are non-nil placeholders: the wiring functions
// only hand them on, they call nothing at build time.
func wiringServices(t *testing.T) *services {
	t.Helper()
	pool := newTestPool()
	t.Cleanup(pool.Close)
	reg := providers.NewRegistry()
	registerProviders(reg, pool, slog.New(slog.DiscardHandler))
	return &services{license: &license.Service{}, inventory: &inventory.Service{}, queue: &jobs.Queue{},
		registry: reg, sshPool: pool, auditLog: audit.New(clock.Real{}), audit: &audit.Service{}}
}

// requireEveryFieldSet fails for a zero field of a dependency struct (a nil service, logger or
// clock), except the named optional ones (documented defaults).
func requireEveryFieldSet(t *testing.T, deps any, optional ...string) {
	t.Helper()
	v := reflect.ValueOf(deps)
	require.Equal(t, reflect.Struct, v.Kind())
	for i := range v.NumField() {
		name := v.Type().Field(i).Name
		if containsString(optional, name) {
			continue
		}
		assert.False(t, v.Field(i).IsZero(), "%s.%s is not set", v.Type(), name)
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Every dependency of the job handlers is set; FirstRecovery is the one optional field
// (0 = inventory.FirstRecoveryDelay, the documented default).
func TestJobDepsCarryEveryDependency(t *testing.T) {
	svc := wiringServices(t)
	log := slog.New(slog.DiscardHandler)
	requireEveryFieldSet(t, deployDeps(svc, clock.Real{}, log), "FirstRecovery")
	requireEveryFieldSet(t, targetDeps(svc, clock.Real{}, log))
	assert.Same(t, svc.registry, deployDeps(svc, clock.Real{}, log).Registry)
	assert.Same(t, svc.inventory, deployDeps(svc, clock.Real{}, log).Inventory)
}

// The product as serve builds it is completely wired: every provider this build ships is
// registered, every job type has a handler (a queued job of a type without one would never be
// claimed) or is a periodic task, and the deployment recovery sweep runs every minute.
func TestServeWiringIsComplete(t *testing.T) {
	svc := wiringServices(t)
	log := slog.New(slog.DiscardHandler)
	runner := buildRunner(nil, svc, clock.Real{}, log)
	sched := buildScheduler(svc, nil, clock.Real{}, log)
	require.NoError(t, checkWiring(svc.registry, runner, sched))

	for _, k := range []providers.Kind{providers.KindLinuxSSH, providers.KindNginx} {
		_, ok := svc.registry.Get(k)
		assert.True(t, ok, "provider %s", k)
	}
	for _, typ := range []jobs.Type{jobs.TargetTestConnection, jobs.TargetDiscover, jobs.SSHKeyRemove,
		jobs.CertificateDeploy, jobs.CertificateDeployRecover} {
		assert.True(t, runner.Handles(typ), "the runner handles %s", typ.Name)
	}
	for _, typ := range []jobs.Type{jobs.LicenseEvaluate, jobs.NotifySend, jobs.AuditVerify, jobs.MaintenanceCleanup,
		jobs.DiscoverySchedule, jobs.DeploymentRecoverySweep} {
		assert.True(t, sched.Schedules(typ), "%s is scheduled", typ.Name)
	}
	assert.Equal(t, time.Minute, sweepEvery, "the recovery sweep runs every minute")
	// Every job type is either a queue type with a handler or a periodic task: iterate the
	// registry so a type added later without either fails here.
	for _, typ := range jobs.Types() {
		assert.True(t, runner.Handles(typ) || sched.Schedules(typ), "job type %s has no handler and is not scheduled", typ.Name)
	}
}

// checkWiring names every gap, so serve refuses to start instead of running degraded.
func TestCheckWiringRefusesAnIncompleteProduct(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	svc := wiringServices(t)

	onlySSH := providers.NewRegistry()
	pool := newTestPool()
	t.Cleanup(pool.Close)
	onlySSH.Register(linuxssh.New(linuxssh.Options{Pool: pool}))
	onlySSH.Freeze()
	err := checkWiring(onlySSH, buildRunner(nil, svc, clock.Real{}, log), buildScheduler(svc, nil, clock.Real{}, log))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider nginx is not registered")

	bare := jobs.NewRunner(jobs.RunnerConfig{})
	noSweep := jobs.NewScheduler(clock.Real{}, svc.license, log,
		jobs.Task{Type: jobs.NotifySend, Every: time.Minute, Run: func(context.Context) error { return nil }})
	err = checkWiring(svc.registry, bare, noSweep)
	require.Error(t, err)
	for _, typ := range []string{"certificate.deploy", "certificate.deploy_recover", "deployment.recovery_sweep", "target.discover"} {
		assert.Contains(t, err.Error(), "job type "+typ+" has no handler and is not scheduled")
	}
	assert.NotContains(t, err.Error(), "job type notify.send ")
	assert.True(t, strings.HasPrefix(err.Error(), "alice is not completely wired"), err.Error())
}

// deployjobs.Register panics on a missing dependency: a build that forgot one never starts.
func TestBuildRunnerPanicsOnAMissingDeployDependency(t *testing.T) {
	svc := wiringServices(t)
	svc.inventory = nil
	assert.Panics(t, func() { buildRunner(nil, svc, clock.Real{}, slog.New(slog.DiscardHandler)) })
}
