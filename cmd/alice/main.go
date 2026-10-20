// Command alice is the Alice server and operator CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	// The zone database is in the binary: the distroless image has none, and ALICE_TZ needs it.
	_ "time/tzdata"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/api"
	"alice/internal/audit"
	"alice/internal/backup"
	"alice/internal/i18n"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/db"
	"alice/internal/platform/logging"
	"alice/internal/platform/tlscert"
	"alice/internal/setup"
	"alice/internal/webui"
	"alice/locales"
	"alice/migrations"
)

// dbStartupBudget is how long serve waits for PostgreSQL before giving up.
const dbStartupBudget = 60 * time.Second

const usage = `Usage: alice <command>

Commands:
  serve                       Start the Alice server (default)
  migrate [--to-latest]       Apply database migrations and exit (--to-latest is the default)
  backup [--out PATH] [--reason TEXT]
                              Make a backup now (into ALICE_BACKUP_DIR)
  backup list                 List the backups with their checksum check
  backup verify FILE [--deep] [--passphrase-stdin]
                              Check a backup file (--deep: decrypt it with the recovery passphrase)
  restore FILE [--db-only] [--passphrase-stdin] [--confirm RESTORE] [--accept-broken-audit-log] [--no-safety-backup]
          [--free-bytes N] [--wait-for-sessions DURATION]
                              Replace all data with a backup (Alice must be stopped)
  selfcheck                   Check the database, keys, audit log, license, HTTPS listener and background jobs
  support-bundle              Print a support report without secrets (JSON)
  healthcheck                 Exit 0 if the local server reports healthy (used by Docker)
  setup-token --reset         Print a new one-time setup code (only before the first administrator exists)
  audit verify                Check the audit log hash chain (exit code 1 if it is broken)
  admin reset-mfa <username>  Remove a user's authenticator app; they set up a new one at next sign-in
  admin unlock <username>     End a user's sign-in delay or lockout and reset the failed sign-in count
  license status              Show the installation ID and the license state
  license keys                List the license verification keys built into this binary
  version                     Print version information
  help                        Show this help
`

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}

// run executes one command. stdin carries a passphrase (--passphrase-stdin) and the restore confirmation; it is
// read only by the commands that need them.
func run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "configuration error:", err)
		return 1
	}
	log := logging.New(stderr, cfg.LogLevel)

	switch cmd {
	case "serve":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := serve(ctx, cfg, log); err != nil {
			log.Error("alice stopped with an error", "error", err.Error())
			return 1
		}
		return 0
	case "migrate":
		if rest := args[min(1, len(args)):]; len(rest) > 1 || (len(rest) == 1 && rest[0] != "--to-latest") {
			fmt.Fprintln(stderr, "usage: alice migrate [--to-latest]")
			return 2
		}
		if err := migrate(cfg); err != nil {
			fmt.Fprintln(stderr, "migration failed:", err)
			return 1
		}
		fmt.Fprintln(stdout, "database is up to date")
		return 0
	case "healthcheck":
		return healthcheck(cfg)
	case "backup":
		return runBackup(args[1:], cfg, stdin, stdout, stderr)
	case "restore":
		return runRestore(args[1:], cfg, stdin, stdout, stderr)
	case "selfcheck":
		return runSelfcheck(args[1:], cfg, stdout, stderr)
	case "support-bundle":
		return runSupportBundle(args[1:], cfg, stdout, stderr)
	case "setup-token":
		return runSetupToken(args[1:], cfg, stdout, stderr)
	case "audit":
		return runAudit(args[1:], cfg, stdout, stderr)
	case "admin":
		return runAdmin(args[1:], cfg, stdout, stderr)
	case "license":
		return runLicense(args[1:], cfg, stdout, stderr)
	case "version":
		v := buildVersion()
		fmt.Fprintf(stdout, "alice %s (commit %s, built %s)\n", v.Version, v.Commit, v.BuildTime)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

// openDB opens a pool and waits up to budget for the database. Only an
// unreachable database is worth the "not ready" wording; a wrong password or
// a missing database is reported as it is (db.ErrAuthFailed, db.ErrDatabaseMissing).
func openDB(ctx context.Context, url string, budget time.Duration) (*pgxpool.Pool, error) {
	openCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	pool, err := db.Open(openCtx, url)
	if err != nil {
		return nil, dbStartupError(err, budget)
	}
	return pool, nil
}

// dbStartupError adds the waiting time to "not reachable" errors only; a
// rejected password or a missing database is reported as is (it is final).
// (Kept from Task 3; TestDBStartupErrorMentionsWaitOnlyForUnreachable covers it.)
func dbStartupError(err error, budget time.Duration) error {
	if errors.Is(err, db.ErrUnreachable) {
		return fmt.Errorf("database not ready after %s: %w", budget, err)
	}
	return err
}

// migrateWith applies migrations through a short-lived pool on the owner role and
// closes it, so the running server never keeps an owner connection (the app role
// cannot rewrite the audit log, SEC-071).
func migrateWith(ctx context.Context, url string, budget time.Duration) error {
	pool, err := openDB(ctx, url, budget)
	if err != nil {
		return err
	}
	defer pool.Close()
	return db.Migrate(ctx, pool, migrations.FS)
}

// migrate needs only the owner connection: the production migrate service gets no application
// credential (S-37). Without an owner URL it falls back to ALICE_DATABASE_URL, as before.
func migrate(cfg config.Config) error {
	if cfg.MigrateDatabaseURL == "" {
		if err := cfg.RequireDatabase(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.MigrateTimeout)
	defer cancel()
	return migrateWith(ctx, cfg.MigrationURL(), time.Minute)
}

// requireCurrentSchema refuses a schema older or newer than the migrations built into this binary.
func requireCurrentSchema(ctx context.Context, pool *pgxpool.Pool) error {
	want, err := db.LatestVersion(migrations.FS)
	if err != nil {
		return err
	}
	have, err := db.SchemaVersion(ctx, pool)
	if err != nil {
		return err
	}
	if have > want {
		return fmt.Errorf("database schema is at version %d, newer than this Alice (%d): run the Alice version that "+
			"migrated it, or restore a backup made by this version", have, want)
	}
	if have < want {
		return fmt.Errorf("database schema is at version %d but this Alice needs %d: run the migrate service first "+
			"(docker compose run --rm migrate)", have, want)
	}
	return nil
}

func serve(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if err := cfg.RequireDatabase(); err != nil {
		return err
	}
	log.Info("starting alice", "version", buildVersion().Version, "config", cfg)
	external := cfg.Migrate == config.MigrateExternal
	if !external {
		if !cfg.SeparateMigrationRole() {
			log.Warn("ALICE_MIGRATE_DATABASE_URL is not set, so migrations and the application share one database role; " +
				"the audit log is then protected by database triggers only. Set ALICE_MIGRATE_DATABASE_URL to the owner role.")
		}
		if err := migrateWith(ctx, cfg.MigrationURL(), dbStartupBudget); err != nil {
			return err
		}
	}
	pool, err := openDB(ctx, cfg.DatabaseURL, dbStartupBudget)
	if err != nil {
		return err
	}
	if external {
		// The migrate service ran before this container (P1-01); serve never opens an owner connection.
		if err := requireCurrentSchema(ctx, pool); err != nil {
			pool.Close()
			return err
		}
	}
	// The pool closes last, within dbCloseBudget (closeWithin below); this covers a start that
	// fails before the workers run, when nothing can hold a connection.
	poolClosed := false
	defer func() {
		if !poolClosed {
			pool.Close()
		}
	}()

	// A restore that stopped after its swap point is completed before the master key is loaded: the staged files
	// belong to the database that is live now, and they are applied only when its restore ID says so (S-1).
	if applied, err := backup.FinishInterruptedRestore(ctx, pool, cfg.KeysDir, cfg.StateDir); err != nil {
		return fmt.Errorf("finish the interrupted restore: %w", err)
	} else if applied {
		log.Warn("an interrupted restore was completed: the restored keys and time record are now in place",
			"event", "backup.restore_finished")
	}
	clk := newClock()
	catalog, err := i18n.Load(locales.FS)
	if err != nil {
		return err
	}
	svc, err := buildServices(ctx, pool, cfg, catalog, clk, log)
	if err != nil {
		return err
	}
	// Closed in order at shutdown below; this covers a start that fails before then (Close is
	// idempotent).
	defer svc.sshPool.Close()
	health, err := db.NewHealthChecker(pool, migrations.FS)
	if err != nil {
		return err
	}
	sender := buildSender(pool, svc, catalog, clk, log)
	hosts := append([]string{"localhost", "127.0.0.1"}, cfg.TLSHosts...)
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	// The store repairs an interrupted certificate replacement, creates or renews the temporary certificate and
	// serves the current pair without a restart (C11).
	svc.tlsStore, err = tlscert.NewStore(cfg.KeysDir, hosts, clk.Now)
	if err != nil {
		return err
	}
	if err := auditRecoveredCertificate(ctx, svc, log); err != nil {
		return err
	}
	// The installation ID, the time record and the first evaluation exist before any request.
	if err := svc.license.Start(ctx); err != nil {
		return err
	}
	// ALICE_SMTP_* become the mail settings once, when none ever existed (S-12), before the scheduler sends
	// anything. An unreadable password or CA file stops the start with the error, as the Phase 2 mailer did.
	if _, err := svc.notifySettings.ImportEnv(ctx, cfg.SMTP, os.ReadFile); err != nil {
		return err
	}
	// The platform SSH key exists before the wizard or a target needs it (R37 item 1). On a
	// fresh installation its platform_key.created entry starts the audit chain.
	if _, err := svc.inventory.EnsurePlatformKey(ctx); err != nil {
		return err
	}
	runner := buildRunner(pool, svc, clk, log)
	// While it leads, the leader holds one connection of the pool for good (db.Open sizes the
	// pool for it). Every periodic task, the deployment recovery sweep included, runs only in the
	// process that holds it, except the license evaluation, which runs in every process (AUD-02:
	// each process's license gate trusts only its own evaluations of the last 3 hours).
	leader := jobs.NewLeader(pool, log)
	sched := buildScheduler(svc, sender, clk, log).WithLeader(leader)
	// A provider or a job type that is not wired fails the start (never a degraded server whose
	// deployments wait forever).
	if err := checkWiring(svc.registry, runner, sched); err != nil {
		return err
	}
	// Every live target's stored capabilities follow the registered provider (spec §8.1).
	if _, err := svc.inventory.SyncCapabilities(ctx); err != nil {
		return err
	}
	// Jobs whose worker died with the previous process are queued again before any request
	// can list them (§8.8); Run repeats the pass before its workers start.
	if _, err := runner.Recover(ctx); err != nil {
		return err
	}

	var apiServer *api.Server
	td := testDeps{
		OwnerURL:  cfg.MigrationURL(),
		Setup:     svc.setup,
		License:   svc.license,
		Scheduler: sched,
		Sender:    sender,
		Inventory: svc.inventory,
		Runner:    runner,
		StateDir:  cfg.StateDir,
		BackupDir: cfg.BackupDir,
		TLS:       svc.tlsStore,
		KeysDir:   cfg.KeysDir,
		TLSHosts:  hosts,
		Log:       log,
		ResetLimits: func() {
			if apiServer != nil {
				apiServer.ResetLimits()
			}
		},
	}
	deps := newAPIDeps(cfg, svc, health, catalog, clk, log, testHandler(td))
	apiServer = api.New(deps)
	warnIfTestBuild(log, deps.TestHandler)

	errLog := slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	public := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           apiServer.Handler(),
		TLSConfig:         tlscert.ServerConfigFor(svc.tlsStore),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          errLog,
	}
	internal := &http.Server{
		Addr:              cfg.HealthAddr,
		Handler:           api.NewHealthHandler(deps),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          errLog,
	}

	// Both ports are bound before anything starts and before "alice is ready" is logged: a port in
	// use stops the start with its error, and a client that waits for the ready line (the
	// integration tests, an operator watching the log) can connect at once. Serve took the
	// listeners in goroutines before, so the ready line could come before the ports listened.
	publicLn, internalLn, err := listenBoth(ctx, public.Addr, internal.Addr)
	if err != nil {
		return err
	}

	// The scheduler and the workers start last: nothing below can fail before the shutdown path
	// runs. The workers get their own context so a signal stops the HTTP servers and the
	// scheduler first and the workers only afterwards (§8.8: stop claiming, let running jobs end).
	schedCtx, stopSched := context.WithCancel(ctx)
	defer stopSched()
	schedDone := make(chan struct{})
	go func() {
		// The first heartbeat comes with the scheduler, not a minute later, so alice selfcheck passes right after a
		// start or a restore (M-3).
		if err := writeHeartbeat(schedCtx, pool, clk); err != nil {
			log.Warn("could not record the scheduler heartbeat", "error_type", fmt.Sprintf("%T", err))
		}
		sched.Run(schedCtx)
		close(schedDone)
	}()
	runnerCtx, stopRunner := context.WithCancel(context.WithoutCancel(ctx))
	defer stopRunner()
	runnerDone := make(chan struct{})
	if startJobWorkers {
		go func() {
			runner.Run(runnerCtx)
			close(runnerDone)
		}()
		log.Info("job workers started")
	} else {
		close(runnerDone)
		log.Info("job workers are not started in the e2e build; POST /test/jobs/drain runs due jobs")
	}
	// Summaries of coalesced denial audit rows are written once their 10-minute window ends (AUD-06).
	stopDenialSummaries, denialSummariesDone := startDenialSummaries(ctx, apiServer)
	defer stopDenialSummaries()
	errCh := make(chan error, 2)
	go func() { errCh <- ignoreClosed(public.ServeTLS(publicLn, "", "")) }()
	go func() { errCh <- ignoreClosed(internal.Serve(internalLn)) }()
	log.Info("alice is ready", "https", cfg.ListenAddr, "health", cfg.HealthAddr)

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case runErr = <-errCh:
	}
	// One deadline from the signal covers the HTTP drain, the scheduler and the job workers; the
	// steps after it have small budgets of their own, so the whole shutdown ends before Docker's
	// stop_grace_period (TestShutdownFitsTheStopGracePeriod). The workers stop claiming at once
	// and their running jobs get the runner's grace while HTTP drains.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), serveShutdownBudget)
	defer cancelShutdown()
	stopRunner()
	stopServing(shutdownCtx, apiServer, []shutdowner{public, internal}, stopDenialSummaries, denialSummariesDone, log)
	stopSched()
	waitForScheduler(shutdownCtx, schedDone, log)
	// Wait order (§8.8): HTTP, scheduler, workers (Run releases the leases of jobs that did not
	// end), the scheduling lock, the SSH connections, the time record, the database pool.
	if waitForJobs(shutdownCtx, runnerDone, log) && startJobWorkers {
		log.Info("job workers stopped")
	}
	closeWithin("the scheduling lock", leader.Close, leaderCloseBudget, log)
	closeWithin("the SSH connections", svc.sshPool.Close, sshPoolCloseBudget, log)
	log.Info("ssh connections closed")
	// A fresh context: the time record is saved even when the shutdown budget is used up.
	saveCtx, cancelSave := context.WithTimeout(context.Background(), timeRecordSaveBudget)
	defer cancelSave()
	if err := svc.license.Shutdown(saveCtx); err != nil {
		log.Error("could not save the license time record at shutdown", "error_type", fmt.Sprintf("%T", err))
	}
	poolClosed = true
	closeWithin("the database pool", pool.Close, dbCloseBudget, log)
	return runErr
}

// apiLifecycle is the part of *api.Server that the start and the shutdown use.
type apiLifecycle interface {
	RunDenialSummaries(ctx context.Context)
	StopScans()
	FlushDenials(ctx context.Context)
}

// shutdowner is an HTTP server's graceful stop.
type shutdowner interface {
	Shutdown(ctx context.Context) error
}

// startDenialSummaries runs the API's denial-summary writer (AUD-06) until stop is called or ctx
// ends; done is closed once it has returned.
func startDenialSummaries(ctx context.Context, a apiLifecycle) (stop context.CancelFunc, done <-chan struct{}) {
	jctx, cancel := context.WithCancel(ctx)
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		a.RunDenialSummaries(jctx)
	}()
	return cancel, ch
}

// stopServing stops the HTTP side, all within ctx (serveShutdownBudget, so the budget arithmetic of
// TestShutdownFitsTheStopGracePeriod covers every wait here), in this order:
//  1. running audit verifications and exports end at once (StopScans), so the drain never waits
//     up to 10 minutes for one (I3);
//  2. the servers drain: no request can be refused any more;
//  3. the denial-summary writer stops and is waited for, so the flush does not race its last sweep;
//  4. the counts of every open denial window are written (ruling S3: best effort; counts not
//     written by the deadline are lost, as on a crash).
func stopServing(ctx context.Context, a apiLifecycle, servers []shutdowner, stopSummaries context.CancelFunc,
	summariesDone <-chan struct{}, log *slog.Logger) {
	a.StopScans()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
	stopSummaries()
	select {
	case <-summariesDone:
	case <-ctx.Done():
		log.Warn("the denial summary writer did not stop before the shutdown deadline")
	}
	a.FlushDenials(ctx)
}

// Shutdown budgets. docker-compose.yml gives Alice stop_grace_period 90s; their sum stays below
// it (TestShutdownFitsTheStopGracePeriod).
const (
	// serveShutdownBudget is the deadline from the signal for the HTTP drain, the scheduler and
	// the job workers. It covers jobsShutdownGrace.
	serveShutdownBudget = 70 * time.Second
	// jobsShutdownGrace is the runner's total grace for running jobs (§8.8: up to 60 s; after it
	// the runner releases their leases).
	jobsShutdownGrace = 60 * time.Second
	// leaderCloseBudget bounds the release of the scheduling lock.
	leaderCloseBudget = 3 * time.Second
	// sshPoolCloseBudget bounds closing the idle SSH connections.
	sshPoolCloseBudget = 2 * time.Second
	// timeRecordSaveBudget bounds the save of the license time record at shutdown.
	timeRecordSaveBudget = 5 * time.Second
	// dbCloseBudget bounds closing the database pool: pgxpool waits for every borrowed
	// connection, and a stuck job may never return its connection.
	dbCloseBudget = 3 * time.Second
)

// closeWithin runs closeFn and waits at most limit for it; a close that hangs is left behind
// with a warning, because the process exits right afterwards.
func closeWithin(what string, closeFn func(), limit time.Duration, log *slog.Logger) {
	done := make(chan struct{})
	go func() {
		closeFn()
		close(done)
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		log.Warn("closing did not finish within the shutdown time; exiting anyway", "resource", what)
	}
}

// newAPIDeps hands the services serve built to the API. A test guards every service field:
// without License every license-gated route fails closed.
func newAPIDeps(cfg config.Config, svc *services, health api.HealthChecker, catalog *i18n.Catalog, clk clock.Clock,
	log *slog.Logger, testHandler http.Handler) api.Deps {
	return api.Deps{
		Health:         health,
		Catalog:        catalog,
		Version:        buildVersion(),
		UI:             webui.UI(),
		Log:            log,
		Clock:          clk,
		Auth:           svc.auth,
		Setup:          svc.setup,
		Audit:          svc.audit,
		License:        svc.license,
		Inventory:      svc.inventory,
		ACME:           acmeAPI(svc),
		Discovery:      discoveryAPI(svc),
		Incidents:      incidentAPI(svc),
		Services:       servicesAPI(svc),
		Jobs:           svc.queue,
		Providers:      svc.registry,
		SSHKeys:        sshKeysAPI(svc),
		TrustedProxies: cfg.TrustedProxies,
		TestHandler:    testHandler,
		Mail:           mailAPI(svc),
		Alerts:         alertsAPI(svc),
		Reports:        reportsAPI(svc),
		SSO:            ssoAPI(svc),
		LDAP:           ldapAPI(svc),
		Backup:         backupAPI(svc),
		Forward:        forwardAPI(svc),
		TLSStore:       httpsAPI(svc, log),
	}
}

// backupAPI, forwardAPI and httpsAPI keep a missing service a nil interface, as sshKeysAPI does (Phase 8).
func backupAPI(svc *services) api.BackupService {
	if svc.backup == nil {
		return nil
	}
	return svc.backup
}

func forwardAPI(svc *services) api.ForwardService {
	if svc.forward == nil {
		return nil
	}
	return svc.forward
}

// httpsAPI is setup.CertificateInstaller over the store: the one adapter the API's integration stack runs too.
func httpsAPI(svc *services, log *slog.Logger) api.HTTPSService {
	if svc.tlsStore == nil {
		return nil
	}
	return setup.CertificateInstaller{Store: svc.tlsStore, Setup: svc.setup, Log: log}
}

// sshKeysAPI keeps a nil *sshkeys.Service a nil interface: the key detail then answers without the
// generated-key fields instead of calling a nil service.
func sshKeysAPI(svc *services) api.SSHKeysService {
	if svc.sshkeys == nil {
		return nil
	}
	return svc.sshkeys
}

// acmeAPI is the inventory's ACME part; a nil inventory stays a nil interface, as sshKeysAPI does.
func acmeAPI(svc *services) api.ACMEService {
	if svc.inventory == nil {
		return nil
	}
	return svc.inventory
}

// incidentAPI is the incident service (the inventory); a nil inventory stays a nil interface, as acmeAPI does.
func incidentAPI(svc *services) api.IncidentService {
	if svc.inventory == nil {
		return nil
	}
	return svc.inventory
}

// servicesAPI is the services module (R49); a nil store stays a nil interface, as discoveryAPI does.
func servicesAPI(svc *services) api.ServicesService {
	if svc.serviceStore == nil {
		return nil
	}
	return svc.serviceStore
}

// discoveryAPI is the network discovery service; a nil service stays a nil interface, as acmeAPI does.
func discoveryAPI(svc *services) api.DiscoveryService {
	if svc.discovery == nil {
		return nil
	}
	return svc.discovery
}

// mailAPI, alertsAPI and reportsAPI keep a nil service a nil interface (C-s4-06), as sshKeysAPI does.
func mailAPI(svc *services) api.MailService {
	if svc.notifySettings == nil {
		return nil
	}
	return svc.notifySettings
}

func alertsAPI(svc *services) api.AlertsService {
	if svc.alerts == nil {
		return nil
	}
	return svc.alerts
}

func ssoAPI(svc *services) api.SSOService {
	if svc.oidc == nil {
		return nil
	}
	return svc.oidc
}

func ldapAPI(svc *services) api.LDAPService {
	if svc.ldap == nil {
		return nil
	}
	return svc.ldap
}

func reportsAPI(svc *services) api.ReportsService {
	if svc.reports == nil {
		return nil
	}
	return svc.reports
}

// waitForScheduler waits for running scheduled tasks to return, at most until ctx ends. It
// reports whether they returned in time.
func waitForScheduler(ctx context.Context, done <-chan struct{}, log *slog.Logger) bool {
	select {
	case <-done:
		return true
	case <-ctx.Done():
		log.Warn("scheduled tasks did not stop within the shutdown time; saving the license time record anyway")
		return false
	}
}

// waitForJobs waits for the job runner to return, at most until ctx ends. It reports whether it
// did; jobs it gave up on resume after the restart when their leases expire.
func waitForJobs(ctx context.Context, done <-chan struct{}, log *slog.Logger) bool {
	select {
	case <-done:
		return true
	case <-ctx.Done():
		log.Warn("background jobs did not stop within the shutdown time; their leases expire and they resume after the restart")
		return false
	}
}

func healthcheck(cfg config.Config) int {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.HealthAddr+"/healthz", nil)
	if err != nil {
		return 1
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: address comes from local configuration, not user input
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// auditRecoveredCertificate logs and audits what the certificate store repaired at its start (S-13): tlscert is a
// platform package and cannot write the audit log itself.
func auditRecoveredCertificate(ctx context.Context, svc *services, log *slog.Logger) error {
	reason := svc.tlsStore.Recovered()
	if reason == "" {
		return nil
	}
	info := svc.tlsStore.Info()
	log.Warn("an interrupted HTTPS certificate replacement was repaired", "event", "https.certificate_recovered", "reason", reason)
	return svc.audit.Write(ctx, audit.Event{Actor: audit.SystemActor("startup"), Action: "https.certificate_recovered",
		ObjectType: "certificate", ObjectID: "https", Result: audit.Success, Details: map[string]string{
			"fingerprint": info.FingerprintSHA256, "temporary": strconv.FormatBool(info.Temporary), "reason": reason}})
}

// listenBoth binds the public and the health address; when the second fails the first is closed.
func listenBoth(ctx context.Context, publicAddr, healthAddr string) (net.Listener, net.Listener, error) {
	var lc net.ListenConfig
	publicLn, err := lc.Listen(ctx, "tcp", publicAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on %s: %w", publicAddr, err)
	}
	healthLn, err := lc.Listen(ctx, "tcp", healthAddr)
	if err != nil {
		_ = publicLn.Close()
		return nil, nil, fmt.Errorf("listen on %s: %w", healthAddr, err)
	}
	return publicLn, healthLn, nil
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
