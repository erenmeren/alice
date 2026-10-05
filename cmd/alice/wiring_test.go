package main

import (
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/kvjobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx"
	"alice/internal/secrets"
	"alice/internal/sshkeys"
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
		registry: reg, sshPool: pool, auditLog: audit.New(clock.Real{}), audit: &audit.Service{},
		sshkeys: sshkeys.New(sshkeys.Config{HelperBudget: helperproto.HelperBudget})}
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
	requireEveryFieldSet(t, kvDeps(svc, clock.Real{}, log))
	requireEveryFieldSet(t, sshkeyDeps(svc, clock.Real{}, log))
	assert.Same(t, svc.sshkeys, sshkeyDeps(svc, clock.Real{}, log).Keys)
	assert.Same(t, svc.inventory, sshkeyDeps(svc, clock.Real{}, log).Targets)
	assert.Same(t, svc.registry, sshkeyDeps(svc, clock.Real{}, log).Registry)
	assert.Same(t, svc.license, sshkeyDeps(svc, clock.Real{}, log).Gate,
		"a rotation's add and removal jobs ask the licence gate before any session (L-29)")
	assert.Same(t, svc.registry, deployDeps(svc, clock.Real{}, log).Registry)
	assert.Same(t, svc.inventory, deployDeps(svc, clock.Real{}, log).Inventory)
	assert.Same(t, svc.registry, kvDeps(svc, clock.Real{}, log).Registry)
	assert.Same(t, svc.inventory, kvDeps(svc, clock.Real{}, log).Inventory)
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

	for _, k := range []providers.Kind{providers.KindLinuxSSH, providers.KindNginx, providers.KindAzureKV} {
		_, ok := svc.registry.Get(k)
		assert.True(t, ok, "provider %s", k)
	}
	for _, typ := range []jobs.Type{jobs.TargetTestConnection, jobs.TargetDiscover, jobs.SSHKeyRemove,
		jobs.CertificateDeploy, jobs.CertificateDeployRecover, jobs.KVTestConnection, jobs.KVPoll, jobs.KVImport,
		jobs.SSHKeyAdd, jobs.RotationLocation} {
		assert.True(t, runner.Handles(typ), "the runner handles %s", typ.Name)
	}
	for _, typ := range []jobs.Type{jobs.LicenseEvaluate, jobs.NotifySend, jobs.AuditVerify, jobs.MaintenanceCleanup,
		jobs.DiscoverySchedule, jobs.DeploymentRecoverySweep, jobs.KVSchedule, jobs.KVAutoDeploy,
		jobs.RotationPlan, jobs.RotationSweep, jobs.SSHKeyDestroyRetired} {
		assert.True(t, sched.Schedules(typ), "%s is scheduled", typ.Name)
	}
	assert.Positive(t, rotationPlanEvery, "the rotation planner has an interval in every build")
	assert.Positive(t, rotationSweepEvery, "the rotation sweep has an interval in every build")
	assert.Positive(t, destroyRetiredEvery, "the retired-key task has an interval in every build")
	assert.Positive(t, sweepEvery, "the sweep has an interval in every build (release: services_test.go; e2e: testapi_e2e_test.go)")
	assert.Positive(t, kvScheduleEvery, "the poll scheduler has an interval in every build")
	assert.Positive(t, kvAutoDeployEvery, "the automatic deployment planner has an interval in every build")
	// Every job type is either a queue type with a handler or a listed periodic type that is
	// scheduled: iterate the registry so a type added later without either fails here.
	for _, typ := range jobs.Types() {
		if isPeriodic(typ) {
			assert.True(t, sched.Schedules(typ), "periodic job type %s is scheduled", typ.Name)
		} else {
			assert.True(t, runner.Handles(typ), "queue job type %s has a handler", typ.Name)
		}
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
	assert.Contains(t, err.Error(), "provider azurekv is not registered")

	bare := jobs.NewRunner(jobs.RunnerConfig{})
	noSweep := jobs.NewScheduler(clock.Real{}, svc.license, log,
		jobs.Task{Type: jobs.NotifySend, Every: time.Minute, Run: func(context.Context) error { return nil }})
	err = checkWiring(svc.registry, bare, noSweep)
	require.Error(t, err)
	for _, typ := range []string{"certificate.deploy", "certificate.deploy_recover", "target.discover"} {
		assert.Contains(t, err.Error(), "queue job type "+typ+" has no handler")
	}
	assert.Contains(t, err.Error(), "periodic job type deployment.recovery_sweep is not scheduled")
	for _, typ := range []string{"kv.test_connection", "kv.poll", "kv.import"} {
		assert.Contains(t, err.Error(), "queue job type "+typ+" has no handler")
	}
	for _, typ := range []string{"kv.schedule", "kv.auto_deploy"} {
		assert.Contains(t, err.Error(), "periodic job type "+typ+" is not scheduled")
	}
	assert.NotContains(t, err.Error(), "notify.send")

	// A queue type is not satisfied by a periodic task, nor a periodic type by a handler.
	run := func(context.Context) error { return nil }
	misplaced := jobs.NewScheduler(clock.Real{}, svc.license, log,
		jobs.Task{Type: jobs.TargetDiscover, Every: time.Minute, Run: run})
	err = checkWiring(svc.registry, bare, misplaced)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "queue job type target.discover has no handler")
	assert.True(t, strings.HasPrefix(err.Error(), "alice is not completely wired"), err.Error())
}

// deployjobs.Register and kvjobs.Register panic on a missing dependency: a build that forgot one never
// starts.
func TestBuildRunnerPanicsOnAMissingDeployDependency(t *testing.T) {
	svc := wiringServices(t)
	svc.inventory = nil
	assert.Panics(t, func() { buildRunner(nil, svc, clock.Real{}, slog.New(slog.DiscardHandler)) })
}

// A nil *inventory.Service must stay a nil interface in the Key Vault dependencies, so Register
// refuses it.
func TestKeyVaultDepsKeepANilInventoryANilInterface(t *testing.T) {
	svc := wiringServices(t)
	svc.inventory = nil
	deps := kvDeps(svc, clock.Real{}, slog.New(slog.DiscardHandler))
	assert.Nil(t, deps.Inventory)
	assert.Panics(t, func() { kvjobs.Register(jobs.NewRunner(jobs.RunnerConfig{}), deps) })
}

// A build whose registry lacks the Key Vault provider does not start: a vault job would otherwise end
// internal.unexpected at run time (and no vault could be added). Every shipped kind is named.
func TestCheckWiringRefusesARegistryWithoutAzureKV(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	svc := wiringServices(t)
	pool := newTestPool()
	t.Cleanup(pool.Close)
	ssh := linuxssh.New(linuxssh.Options{Pool: pool})
	noKV := providers.NewRegistry()
	noKV.Register(ssh)
	noKV.Register(nginx.New(nginx.Options{SSH: ssh}))
	noKV.Freeze()
	err := checkWiring(noKV, buildRunner(nil, svc, clock.Real{}, log), buildScheduler(svc, nil, clock.Real{}, log))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider azurekv is not registered")
	assert.NotContains(t, err.Error(), "provider nginx is not registered")
	assert.Contains(t, shippedProviders, providers.KindAzureKV)
}

// A runner without the SSH key handlers and a scheduler without the rotation tasks are refused, and
// every Phase 6 gap is named: a queued sshkey.add or rotation.location job would wait forever, and a
// run would never be planned, advanced, paused in lock or finished.
func TestCheckWiringNamesRotationGaps(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	svc := wiringServices(t)
	runner := jobs.NewRunner(jobs.RunnerConfig{})
	sched := jobs.NewScheduler(clock.Real{}, svc.license, log,
		jobs.Task{Type: jobs.NotifySend, Every: time.Minute, Run: func(context.Context) error { return nil }})
	err := checkWiring(svc.registry, runner, sched)
	require.Error(t, err)
	for _, typ := range []string{"sshkey.add", "rotation.location"} {
		assert.Contains(t, err.Error(), "queue job type "+typ+" has no handler")
	}
	for _, typ := range []string{"rotation.plan", "rotation.sweep", "sshkey.destroy_retired"} {
		assert.Contains(t, err.Error(), "periodic job type "+typ+" is not scheduled")
	}
	assert.Contains(t, periodicTypes, jobs.RotationPlan)
	assert.Contains(t, periodicTypes, jobs.RotationSweep)
	assert.Contains(t, periodicTypes, jobs.SSHKeyDestroyRetired)

	wired := buildRunner(nil, svc, clock.Real{}, log)
	assert.True(t, wired.Handles(jobs.SSHKeyAdd))
	assert.True(t, wired.Handles(jobs.RotationLocation))
	require.NoError(t, checkWiring(svc.registry, wired, buildScheduler(svc, nil, clock.Real{}, log)))
}

// The scheduler gates the rotation tasks by their own license class, and the wiring adds no gate of
// its own: the sweep is ClassAlways, so in lock it still runs and pauses the live runs (L-83..L-88)
// and still queues their undo jobs; the planner and the retired-key task are read-only work the gate
// pauses in lock like the discovery scheduler (PlanDue refuses to plan in lock by itself too).
func TestRotationTasksKeepTheirLicenseClasses(t *testing.T) {
	assert.Equal(t, license.ClassAlways, jobs.RotationSweep.Class)
	assert.Equal(t, license.ClassReadOnly, jobs.RotationPlan.Class)
	assert.Equal(t, license.ClassReadOnly, jobs.SSHKeyDestroyRetired.Class)
	assert.Equal(t, sshkeys.TaskPlan, jobs.RotationPlan.Name)
	assert.Equal(t, sshkeys.TaskSweep, jobs.RotationSweep.Name)
	assert.Equal(t, sshkeys.TaskDestroyRetired, jobs.SSHKeyDestroyRetired.Name)
}

// The SSH key service is built with the helper's budget (the S3 wait before an undo after an add without
// a definite answer is that budget plus 30 s; sshkeys.New panics without it) and with no randomness of
// the caller's: a nil Rand is crypto/rand, so a generated key never depends on a reader a test or a
// caller could supply.
func TestSSHKeysConfigIsTheProductionOne(t *testing.T) {
	svc := wiringServices(t)
	log := slog.New(slog.DiscardHandler)
	// The pool connects lazily: nothing is dialled here.
	pool, err := pgxpool.New(context.Background(), "postgres://alice@127.0.0.1:1/alice?connect_timeout=1")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	keyring := &secrets.Keyring{}
	clk := clock.NewOffset(clock.Real{})
	cfg := sshkeysConfig(pool, keyring, svc.auditLog, clk, svc.license, svc.inventory, svc.queue, log)
	assert.Same(t, pool, cfg.Pool, "the service works on serve's application pool")
	assert.Same(t, keyring, cfg.Keyring, "generated private keys are sealed with serve's keyring")
	assert.Same(t, clk, cfg.Clock, "the service reads serve's clock")
	assert.Same(t, log, cfg.Log)
	assert.Equal(t, notify.AdminNotifier{Clock: clk}, cfg.Notifier, "rotation previews and results are mailed to the Administrators")
	assert.Equal(t, helperproto.HelperBudget, cfg.HelperBudget)
	assert.Nil(t, cfg.Rand, "production key generation takes no caller-supplied reader")
	assert.Same(t, svc.license, cfg.License)
	assert.Same(t, svc.inventory, cfg.Inventory)
	assert.Same(t, svc.queue, cfg.Jobs)
	assert.Same(t, svc.auditLog, cfg.Audit)
	built := sshkeys.New(cfg)
	assert.Equal(t, helperproto.HelperBudget+30*time.Second, built.UndoWait())
	assert.Panics(t, func() { cfg.HelperBudget = 0; sshkeys.New(cfg) }, "the service refuses to start without the budget")
}

// A nil *sshkeys.Service or *inventory.Service must stay a nil interface, so sshkeyjobs.Register
// refuses it and serve never starts without the SSH key handlers' dependencies.
func TestSSHKeyDepsKeepNilServicesNilInterfaces(t *testing.T) {
	svc := wiringServices(t)
	svc.sshkeys = nil
	svc.inventory = nil
	deps := sshkeyDeps(svc, clock.Real{}, slog.New(slog.DiscardHandler))
	assert.Nil(t, deps.Keys)
	assert.Nil(t, deps.Targets)

	noKeys := wiringServices(t)
	noKeys.sshkeys = nil
	assert.Panics(t, func() { buildRunner(nil, noKeys, clock.Real{}, slog.New(slog.DiscardHandler)) },
		"sshkeyjobs.Register refuses a runner without the SSH key service")
}
