package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/audit/forward"
	"alice/internal/auth"
	"alice/internal/auth/oidc"
	"alice/internal/backup"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/deployjobs"
	"alice/internal/jobs/kvjobs"
	"alice/internal/jobs/sshkeyjobs"
	"alice/internal/jobs/targetjobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/tlscert"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/reports"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/sshkeys"
	"alice/internal/version"
)

// Argon2id memory is 64 MiB per password hash, so at most two run at once
// (the container memory limit is 512 MiB). Recovery-code hashes use 8 MiB.
const (
	passwordHashConcurrency = 2
	recoveryHashConcurrency = 4
)

// serverClock is the clock of the process: wall time for everything, plus uptime for the
// license clock guard (spec R26).
type serverClock interface {
	clock.Clock
	clock.Monotonic
}

// services are the module services shared by serve and the CLI commands.
type services struct {
	pool      *pgxpool.Pool // the application pool the services were built on
	keyring   *secrets.Keyring
	auditLog  *audit.Log
	audit     *audit.Service
	auth      *auth.Service
	setup     *setup.Service
	license   *license.Service
	queue     *jobs.Queue
	inventory *inventory.Service
	registry  *providers.Registry
	sshPool   *linuxssh.Pool
	sshkeys   *sshkeys.Service // generated keys, their deploy, download and rotation (Phase 6)

	// Phase 7 (contract C12).
	notifySettings *notify.Settings // mail settings, recipients and delivery state; the sender's mailer source
	alerts         *alerts.Service  // expiry notices (alerts.scan) and thresholds
	reports        *reports.Service // dashboard, saved views, exports
	oidc           *oidc.Service    // identity providers, group mappings, SSO sign-in

	// Phase 8 (contract C8, C10, C11).
	backup   *backup.Service    // backups, their schedule, state and alarm
	forward  *forward.Forwarder // audit forwarding to syslog
	tlsStore *tlscert.Store     // the HTTPS certificate; set by serve only (a command never touches tls.*)
}

// buildServices loads (or, on a brand-new database, creates) the master key and wires the
// services on the application pool. It starts nothing: serve calls license.Start and imports
// ALICE_SMTP_* (notify.Settings.ImportEnv). It reads no mail configuration, so the recovery
// commands work while it is broken. catalog renders the mail settings' test e-mail.
func buildServices(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, catalog *i18n.Catalog, clk serverClock,
	log *slog.Logger) (*services, error) {
	keyring, err := secrets.LoadOrCreateMasterKey(ctx, pool, cfg.KeysDir, clk.Now())
	if err != nil {
		return nil, err
	}
	auditLog := audit.New(clk)
	passwords := auth.NewHasher(auth.PasswordParams, passwordHashConcurrency)
	authSvc := auth.NewService(auth.Config{
		Pool:           pool,
		Keyring:        keyring,
		Audit:          auditLog,
		Clock:          clk,
		Hasher:         passwords,
		RecoveryHasher: auth.NewHasher(auth.RecoveryCodeParams, recoveryHashConcurrency),
		Notifier:       notify.AdminNotifier{Clock: clk}, // the lockout e-mail (Phase 7)
		Log:            log,
	})
	lic := license.New(license.Config{
		Pool:      pool,
		Keyring:   keyring,
		Audit:     auditLog,
		Clock:     clk,
		Uptime:    clk,
		Keys:      license.EmbeddedKeys(),
		StateDir:  cfg.StateDir,
		BuildTime: buildTime(log),
		Notifier:  notify.AdminNotifier{Clock: clk},
		Targets:   inventory.Counter{},
		Log:       log,
	})
	queue := jobs.NewQueue(jobs.QueueConfig{Pool: pool, Keyring: keyring, Audit: auditLog, Clock: clk, Gate: lic})
	// The registry is a pointer: inventory gets it empty, the dialer gets inventory's host-key
	// store, and registerProviders fills and freezes it before anything reads it.
	registry := providers.NewRegistry()
	inv := inventory.New(inventory.Config{
		Pool:     pool,
		Keyring:  keyring,
		Audit:    auditLog,
		Clock:    clk,
		License:  lic,
		Registry: registry,
		Jobs:     queue,
		Notifier: notify.AdminNotifier{Clock: clk},
		Log:      log,
	})
	sshPool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clk, HostKeys: inv.HostKeyStore()},
		linuxssh.MaxConnections, linuxssh.MaxConnectionsPerTarget, linuxssh.IdleTimeout)
	registerProviders(registry, sshPool, log)
	// The mail settings exist before the setup service, whose wizard counts configured mail as its mail step (C11).
	notifySettings := notify.NewSettings(notifySettingsConfig(pool, &services{keyring: keyring, auditLog: auditLog}, catalog, clk, log))
	setupSvc := setup.New(setup.Config{
		Pool:      pool,
		Auth:      authSvc,
		Keyring:   keyring,
		Audit:     auditLog,
		Clock:     clk,
		Hasher:    passwords,
		BackupKDF: secrets.BackupKDF,
		License:   lic,
		Mail:      notifySettings, // configured mail counts as the wizard's mail step (C11)
	})
	svc := &services{
		pool:      pool,
		keyring:   keyring,
		auditLog:  auditLog,
		audit:     audit.NewService(auditLog, pool),
		auth:      authSvc,
		setup:     setupSvc,
		license:   lic,
		queue:     queue,
		inventory: inv,
		registry:  registry,
		sshPool:   sshPool,
		sshkeys:   sshkeys.New(sshkeysConfig(pool, keyring, auditLog, clk, lic, inv, queue, log)),
	}
	svc.notifySettings = notifySettings
	svc.alerts = alerts.New(alerts.Config{Pool: pool, Audit: auditLog, Clock: clk, License: lic,
		Notifier: notify.AdminNotifier{Clock: clk}, Log: log})
	svc.reports = reports.New(reports.Config{Pool: pool, Clock: clk, Audit: auditLog, License: lic, Alerts: svc.alerts,
		Delivery: svc.notifySettings, Inventory: inv})
	svc.oidc = oidc.New(oidcConfig(svc, clk, log))
	svc.backup = backup.New(backupServiceConfig(cfg, svc, clk, log))
	svc.forward = forward.New(forwardConfig(cfg, svc, clk, log))
	return svc, nil
}

// backupServiceConfig is the backup service of serve and the backup command (C8): the app pool, the keyring that
// opens the sender key, ALICE_BACKUP_DIR and ALICE_TZ as the schedule's default zone; the binary's release version
// is written into the headers.
func backupServiceConfig(cfg config.Config, svc *services, clk clock.Clock, log *slog.Logger) backup.Config {
	c := backupConfig(cfg, clk, log)
	c.Pool, c.Audit, c.Keyring, c.Notifier = svc.pool, svc.auditLog, svc.keyring, notify.AdminNotifier{Clock: clk}
	return c
}

// forwardConfig is the audit forwarder's configuration (C10): every connection goes through netaddr.DialContext and
// its address rule (SEC-065); the syslog HOSTNAME is the first ALICE_TLS_HOSTS name, else the host name.
func forwardConfig(cfg config.Config, svc *services, clk clock.Clock, log *slog.Logger) forward.Config {
	return forward.Config{
		Pool:  svc.pool,
		Audit: svc.auditLog,
		Clock: clk,
		Log:   log,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netaddr.DialContext(ctx, &net.Dialer{Timeout: forwardConnectTimeout}, network, addr)
		},
		Hostname: forwardHostname(cfg),
		AppName:  "alice",
	}
}

// forwardConnectTimeout bounds one connection to the syslog receiver.
const forwardConnectTimeout = 10 * time.Second

func forwardHostname(cfg config.Config) string {
	if len(cfg.TLSHosts) > 0 {
		return cfg.TLSHosts[0]
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return ""
}

// notifySettingsConfig is the mail settings' configuration (TestReleaseMailSettingsHaveNoDialerOverrideOrFallback).
// Dial stays nil in every build, so each SMTP connection goes through netaddr.DialContext and its address rule
// (SEC-065); Fallback is the e2e build's mailbox and nil in a release build, where an e-mail without mail settings is
// recorded as skipped (L-18). The SMTP password is sealed with serve's keyring.
func notifySettingsConfig(pool *pgxpool.Pool, svc *services, catalog *i18n.Catalog, clk clock.Clock, log *slog.Logger) notify.SettingsConfig {
	return notify.SettingsConfig{
		Pool:     pool,
		Keyring:  svc.keyring,
		Audit:    svc.auditLog,
		Clock:    clk,
		Catalog:  catalog,
		Fallback: testMailer,
		Log:      log,
	}
}

// oidcConfig is the SSO service's configuration. Dial stays nil, so discovery, key set and token requests to an
// identity provider go through netaddr.DialContext (SEC-065); client secrets are sealed with serve's keyring.
func oidcConfig(svc *services, clk clock.Clock, log *slog.Logger) oidc.Config {
	return oidc.Config{
		Pool:    svc.pool,
		Keyring: svc.keyring,
		Audit:   svc.auditLog,
		Clock:   clk,
		Auth:    svc.auth,
		Log:     log,
	}
}

// sshkeysConfig is the SSH key module's configuration (TestSSHKeysConfigIsTheProductionOne).
// HelperBudget is the helper's own budget (helperproto.HelperBudget): an undo after an add without a
// definite answer waits that long plus 30 s after the send (S3); sshkeys may not import the helper
// protocol, so the composition root hands it over, and sshkeys.New panics without it. Rand stays nil:
// the module then draws Ed25519 seeds from crypto/rand (RSA and ECDSA always use the standard
// library's randomness), so no reader of a caller's ever reaches key generation.
func sshkeysConfig(pool *pgxpool.Pool, keyring *secrets.Keyring, auditLog *audit.Log, clk clock.Clock, lic *license.Service,
	inv *inventory.Service, queue *jobs.Queue, log *slog.Logger) sshkeys.Config {
	return sshkeys.Config{
		Pool:         pool,
		Keyring:      keyring,
		Audit:        auditLog,
		Clock:        clk,
		License:      lic,
		Inventory:    inv,
		Jobs:         queue,
		Notifier:     notify.AdminNotifier{Clock: clk},
		Log:          log,
		HelperBudget: helperproto.HelperBudget,
	}
}

// jobRetention is how long finished jobs are kept before maintenance.cleanup prunes them (§8.2).
const jobRetention = 90 * 24 * time.Hour

// buildRunner builds the job workers with every queue handler: the Phase 3 target jobs (spec
// §8.1–§8.8), the Phase 4 certificate deployment and its recovery (§12.6, §8.8) and the Phase 5 Key
// Vault jobs (access check, poll, import; §11) and the Phase 6 SSH key jobs (sshkey.add: deploy with a
// test login; rotation.location: one location of a rotation run). Every claim passes the license gate;
// a job that runs out of attempts or fails its integrity check emails the Administrators.
// deployjobs.Register, kvjobs.Register and sshkeyjobs.Register panic on a missing dependency, so a
// build that lacks one never starts.
func buildRunner(pool *pgxpool.Pool, svc *services, clk clock.Clock, log *slog.Logger) *jobs.Runner {
	runner := jobs.NewRunner(jobs.RunnerConfig{Pool: pool, Queue: svc.queue, Gate: svc.license, Audit: svc.auditLog,
		Clock: clk, Log: log, Notifier: notify.AdminNotifier{Clock: clk}, ShutdownGrace: jobsShutdownGrace})
	targetjobs.Register(runner, targetDeps(svc, clk, log))
	deployjobs.Register(runner, deployDeps(svc, clk, log))
	kvjobs.Register(runner, kvDeps(svc, clk, log))
	sshkeyjobs.Register(runner, sshkeyDeps(svc, clk, log))
	return runner
}

// sshkeyDeps are the dependencies of the SSH key jobs, with the licence service as their gate. The S3
// wait comes from the service (Keys.UndoWait, built on Config.HelperBudget), so the handlers take no
// budget of their own.
func sshkeyDeps(svc *services, clk clock.Clock, log *slog.Logger) sshkeyjobs.Deps {
	d := sshkeyjobs.Deps{Registry: svc.registry, Clock: clk, Log: log}
	if svc.sshkeys != nil { // a nil *sshkeys.Service must stay a nil interface, so Register refuses it
		d.Keys = svc.sshkeys
	}
	if svc.inventory != nil {
		d.Targets = svc.inventory
	}
	if svc.license != nil {
		// The licence gate the runner and the SSH key service use: a rotation's add or removal job asks it
		// before opening a session, so a lock that begins after the sweep still reaches no server (L-29).
		d.Gate = svc.license
	}
	return d
}

// targetDeps are the dependencies of the Phase 3 target jobs (TestJobDepsCarryEveryDependency).
func targetDeps(svc *services, clk clock.Clock, log *slog.Logger) targetjobs.Deps {
	d := targetjobs.Deps{Registry: svc.registry, Clock: clk, Log: log}
	if svc.inventory != nil { // a nil *inventory.Service must stay a nil interface
		d.Inventory = svc.inventory
	}
	return d
}

// deployDeps are the dependencies of the deployment jobs. FirstRecovery keeps its default
// (inventory.FirstRecoveryDelay, 30 s).
func deployDeps(svc *services, clk clock.Clock, log *slog.Logger) deployjobs.Deps {
	d := deployjobs.Deps{Registry: svc.registry, Clock: clk, Log: log}
	if svc.inventory != nil { // a nil *inventory.Service must stay a nil interface, so Register refuses it
		d.Inventory = svc.inventory
	}
	return d
}

// kvDeps are the dependencies of the Key Vault jobs. The registry may lack the Key Vault provider (it
// is registered in providers.go once the build ships it): a vault's jobs then end with a closed
// reason, they do not panic.
func kvDeps(svc *services, clk clock.Clock, log *slog.Logger) kvjobs.Deps {
	d := kvjobs.Deps{Registry: svc.registry, Clock: clk, Log: log}
	if svc.inventory != nil { // a nil *inventory.Service must stay a nil interface, so Register refuses it
		d.Inventory = svc.inventory
	}
	return d
}

// buildScheduler is the periodic work of serve (spec §8.2, R37 item 15); every run passes the
// license gate, and serve runs it under the scheduling lock (WithLeader), so one process runs
// each task at a time; license.evaluate runs hourly in every process regardless of the lock
// (AUD-02), each run bounded by the license module (2 minutes, 30 s for the license row). The audit verification ticks hourly and verifies when the last intact
// verification is 23 hours old (jobs.AuditVerifyTask). The deployment recovery sweep (ClassAlways:
// it runs in lock too) queues the recovery of interrupted deployments and ends the ones whose job
// ended; it runs on the scheduler's context, which carries no job claim, every sweepEvery (one
// minute; the e2e build never ticks it: tests run it with POST /test/scheduler/run). The Key Vault
// tasks queue the polls that are due (kv.schedule) and plan the deployments of renewed vault versions
// (kv.auto_deploy) every kvScheduleEvery and kvAutoDeployEvery (a minute; the e2e build never ticks
// them); both are ReadOnly work, so the gate pauses them in lock like the discovery scheduler. The SSH
// key rotation has three tasks (contract C1): rotation.plan (ReadOnly, every rotationPlanEvery) creates
// the previewed runs whose notice is due; rotation.sweep (ClassAlways, every rotationSweepEvery) advances
// every live run, pauses it in lock (L-83..L-88), sends the renewal notice and re-queues location jobs,
// so it must run in lock and gets no gate here beyond the scheduler's own; sshkey.destroy_retired
// (ReadOnly, every destroyRetiredEvery) destroys retired private keys after 30 days, retires unused old
// keys and reconciles deploys whose job ended without an outcome. The e2e build never ticks the three:
// tests run them with POST /test/scheduler/run. The expiry scan (alerts.scan, ClassAlways: the notices go
// out in lock too, with the license note) runs every alertsScanEvery (15 minutes; never in the e2e build),
// one scan at a time (scanAlerts); maintenance.cleanup also prunes expired SSO sign-in states. The e2e
// tests use the same tasks.
func buildScheduler(svc *services, sender *notify.Sender, clk clock.Clock, log *slog.Logger) *jobs.Scheduler {
	return jobs.NewScheduler(clk, svc.license, log,
		// A failed evaluation is retried after 1, 2, 4, 8, then every 10 minutes (AUD-02): the gate refuses changes
		// after 3 hours without a successful one.
		jobs.Task{Type: jobs.LicenseEvaluate, Every: time.Hour, Run: svc.license.Tick, Retry: time.Minute},
		jobs.Task{Type: jobs.NotifySend, Every: time.Minute, Run: func(ctx context.Context) error {
			_, err := sender.Drain(ctx)
			return err
		}},
		jobs.AuditVerifyTask(jobs.AuditVerifyConfig{Pool: svc.pool, Verifier: svc.audit, Notifier: notify.AdminNotifier{Clock: clk}, Clock: clk}),
		jobs.Task{Type: jobs.MaintenanceCleanup, Every: time.Hour, Run: func(ctx context.Context) error {
			_, sessionsErr := svc.auth.PruneExpired(ctx)
			_, jobsErr := svc.queue.Prune(ctx, jobRetention)
			_, statesErr := svc.oidc.PruneStates(ctx) // expired SSO sign-in states (oidc.StateLifetime)
			return errors.Join(sessionsErr, jobsErr, statesErr)
		}},
		jobs.Task{Type: jobs.DiscoverySchedule, Every: time.Minute, Run: func(ctx context.Context) error {
			_, err := svc.inventory.ScheduleDiscovery(ctx)
			return err
		}},
		jobs.Task{Type: jobs.DeploymentRecoverySweep, Every: sweepEvery, Run: func(ctx context.Context) error {
			_, err := svc.inventory.SweepDeployments(ctx)
			return err
		}},
		kvjobs.ScheduleTask(svc.inventory, kvScheduleEvery, log),
		kvjobs.AutoDeployTask(svc.inventory, kvAutoDeployEvery, log),
		jobs.Task{Type: jobs.RotationPlan, Every: rotationPlanEvery, Run: func(ctx context.Context) error {
			_, err := svc.sshkeys.PlanDue(ctx)
			return err
		}},
		jobs.Task{Type: jobs.RotationSweep, Every: rotationSweepEvery, Run: func(ctx context.Context) error {
			_, err := svc.sshkeys.Sweep(ctx)
			return err
		}},
		jobs.Task{Type: jobs.SSHKeyDestroyRetired, Every: destroyRetiredEvery, Run: func(ctx context.Context) error {
			_, err := svc.sshkeys.DestroyRetiredKeys(ctx)
			return err
		}},
		jobs.Task{Type: jobs.AlertsScan, Every: alertsScanEvery, Run: func(ctx context.Context) error {
			return scanAlerts(ctx, svc, log)
		}},
		// Phase 8 (C1): the daily backup with its catch-up and 48-hour alarm, the temporary certificate's renewal,
		// audit forwarding and the heartbeat alice selfcheck reads.
		jobs.Task{Type: jobs.BackupSchedule, Every: backupScheduleEvery, Run: func(ctx context.Context) error {
			return svc.backup.RunScheduled(ctx)
		}},
		jobs.Task{Type: jobs.TLSRenew, Every: tlsRenewEvery, Run: func(ctx context.Context) error {
			return renewCertificate(ctx, svc, log)
		}},
		jobs.Task{Type: jobs.AuditForward, Every: auditForwardEvery, Run: func(ctx context.Context) error {
			return svc.forward.Run(ctx)
		}},
		jobs.Task{Type: jobs.JobsHeartbeat, Every: heartbeatEvery, Run: func(ctx context.Context) error {
			return writeHeartbeat(ctx, svc.pool, clk)
		}},
	)
}

// The intervals of the Phase 8 tasks that are the same in every build (contract C1); backupScheduleEvery is per build.
const (
	tlsRenewEvery     = 6 * time.Hour
	auditForwardEvery = 15 * time.Second
	heartbeatEvery    = time.Minute
)

// schedulerActor is the actor of the scheduled tasks' audit rows (C14).
var schedulerActor = audit.SystemActor("scheduler")

// renewCertificate is the tls.renew task: Store.Renew replaces Alice's temporary certificate when it is due (never a
// certificate the customer installed), and a renewal is audited https.temporary_renewed.
func renewCertificate(ctx context.Context, svc *services, log *slog.Logger) error {
	if svc.tlsStore == nil {
		return nil // a command, not serve: no listener and no certificate to renew
	}
	renewed, err := svc.tlsStore.Renew()
	if err != nil || !renewed {
		return err
	}
	info := svc.tlsStore.Info()
	log.Info("the temporary HTTPS certificate was renewed", "event", "https.temporary_renewed", "not_after", info.NotAfter)
	return svc.audit.Write(ctx, audit.Event{Actor: schedulerActor, Action: "https.temporary_renewed", ObjectType: "certificate",
		ObjectID: "https", Result: audit.Success, Details: map[string]string{
			"fingerprint": info.FingerprintSHA256, "not_after": info.NotAfter.UTC().Format(time.RFC3339)}})
}

// buildSender builds the email sender of serve (notify.send). At every drain it asks the mail
// settings for the mailer of the current configuration (Sender.Source): nothing is read from the
// environment here any more (ALICE_SMTP_* are imported once at the start, notify.Settings.ImportEnv).
func buildSender(pool *pgxpool.Pool, svc *services, catalog *i18n.Catalog, clk clock.Clock, log *slog.Logger) *notify.Sender {
	sender := &notify.Sender{Pool: pool, Catalog: catalog, Clock: clk, Log: log}
	if svc.notifySettings != nil { // a nil *notify.Settings must stay a nil interface
		sender.Source = svc.notifySettings
	}
	return sender
}

// buildTime is the link-time build timestamp; the license time never falls below it (§16.5,
// L-53). A build without one (go build without the Makefile, or docker compose build without
// ALICE_BUILD_TIME) starts with a warning: after a lost time record the license clock then
// has no floor.
func buildTime(log *slog.Logger) time.Time {
	t, err := time.Parse(time.RFC3339, version.BuildTime)
	if err != nil {
		log.Warn("this build has no build time, so the license clock has no lower bound if its time record is lost; "+
			"build with make (or set ALICE_BUILD_TIME for docker compose build)", "build_time", version.BuildTime)
		return time.Time{}
	}
	return t.UTC()
}

// alertsScanLock names the database lock one expiry scan holds while it runs.
const alertsScanLock = "alerts.scan"

// scanAlerts is the alerts.scan task: one expiry scan at a time. In one process the scheduler already runs a task
// once at a time (a tick and RunNow share its semaphore); across processes only the scheduling leader ticks, but a
// scan of a process that lost the lead may still run when the new leader starts one. The scan therefore holds a
// session lock in the database and a second one skips: two overlapping scans could record a less urgent notice after
// a more urgent one for the same expiry (their ledgers are read at the start of each scan). When the scan recorded
// notices that reach nobody, it says so (warnIfNobodyIsEmailed). A scan that fails after it recorded some notices skips
// that check: the next successful scan's notices bring the warning (accepted; Task 13 review minor 5).
func scanAlerts(ctx context.Context, svc *services, log *slog.Logger) error {
	return runExclusive(ctx, svc.pool, alertsScanLock, log, func(ctx context.Context) error {
		res, err := svc.alerts.Scan(ctx)
		if err != nil {
			return err
		}
		notices := 0
		for _, n := range res.Queued {
			notices += n
		}
		for _, n := range res.Suppressed {
			notices += n
		}
		if notices > 0 {
			warnIfNobodyIsEmailed(ctx, svc, notices, log)
		}
		return nil
	})
}

// runExclusive runs fn while a connection of its own holds the session advisory lock name. When another session holds
// it, fn is skipped with an Info line (event "<name>_skipped") and nil is returned. The lock ends with the session, so
// a process that dies never leaves it behind. The lock connection is idle while fn runs: if that one session ends
// meanwhile (idle_session_timeout, a proxy's idle cut, a reset), the lock is gone and another process's run may have
// overlapped. That cannot be prevented here, so the release step detects it (the unlock fails or finds no lock) and
// logs a WARN (event "<name>_lock_lost").
func runExclusive(ctx context.Context, pool *pgxpool.Pool, name string, log *slog.Logger, fn func(context.Context) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("lock %s: %w", name, err)
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, name).Scan(&locked); err != nil {
		return fmt.Errorf("lock %s: %w", name, err)
	}
	if !locked {
		log.Info("scheduled task skipped: another process is running it", "job_type", name, "event", name+"_skipped")
		return nil
	}
	defer func() {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		var held bool
		err := conn.QueryRow(uctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, name).Scan(&held)
		if err != nil || !held {
			log.Warn("scheduled task lost its lock while it ran; a run of another process may have overlapped it",
				"job_type", name, "event", name+"_lock_lost")
		}
		if err != nil {
			// Closing the session ends the lock; the pool then drops the connection.
			_ = conn.Conn().Close(uctx)
		}
	}()
	return fn(ctx)
}

// warnIfNobodyIsEmailed logs a warning when the recipients setting reaches nobody: no extra address and no enabled
// Administrator with an e-mail address (or Administrators switched off). The notices are then recorded (and listed
// on the dashboard) but no e-mail is queued (Task 7 review: this must not happen silently). The Administrator
// predicate is the one of notify's recipient list.
func warnIfNobodyIsEmailed(ctx context.Context, svc *services, notices int, log *slog.Logger) {
	r, err := svc.notifySettings.Recipients(ctx)
	if err != nil {
		log.Warn("alerts: the e-mail recipients could not be read", "error_type", fmt.Sprintf("%T", err))
		return
	}
	if len(r.Addresses) > 0 {
		return
	}
	if r.Administrators {
		var admins int
		if err := svc.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL AND email <> ''`).
			Scan(&admins); err != nil {
			log.Warn("alerts: the e-mail recipients could not be read", "error_type", fmt.Sprintf("%T", err))
			return
		}
		if admins > 0 {
			return
		}
	}
	log.Warn("alerts: expiry notices were recorded but no e-mail was queued: no enabled Administrator has an e-mail "+
		"address and no other recipient is set (Settings, E-mail recipients)", "event", "alerts.no_recipients", "notices", notices)
}
