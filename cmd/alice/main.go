// Command alice is the Alice server and operator CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/api"
	"alice/internal/i18n"
	"alice/internal/platform/config"
	"alice/internal/platform/db"
	"alice/internal/platform/logging"
	"alice/internal/platform/tlscert"
	"alice/internal/version"
	"alice/internal/webui"
	"alice/locales"
	"alice/migrations"
)

// dbStartupBudget is how long serve waits for PostgreSQL before giving up.
const dbStartupBudget = 60 * time.Second

const usage = `Usage: alice <command>

Commands:
  serve                       Start the Alice server (default)
  migrate                     Apply database migrations and exit
  healthcheck                 Exit 0 if the local server reports healthy (used by Docker)
  setup-token --reset         Print a new one-time setup code (only before the first administrator exists)
  audit verify                Check the audit log hash chain (exit code 1 if it is broken)
  admin reset-mfa <username>  Remove a user's authenticator app; they set up a new one at next sign-in
  version                     Print version information
  help                        Show this help
`

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
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
		if err := migrate(cfg); err != nil {
			fmt.Fprintln(stderr, "migration failed:", err)
			return 1
		}
		fmt.Fprintln(stdout, "database is up to date")
		return 0
	case "healthcheck":
		return healthcheck(cfg)
	case "setup-token":
		return runSetupToken(args[1:], cfg, stdout, stderr)
	case "audit":
		return runAudit(args[1:], cfg, stdout, stderr)
	case "admin":
		return runAdmin(args[1:], cfg, stdout, stderr)
	case "version":
		v := version.Get()
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

func migrate(cfg config.Config) error {
	if err := cfg.RequireDatabase(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return migrateWith(ctx, cfg.MigrationURL(), time.Minute)
}

func serve(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if err := cfg.RequireDatabase(); err != nil {
		return err
	}
	log.Info("starting alice", "version", version.Get().Version, "config", cfg)
	if !cfg.SeparateMigrationRole() {
		log.Warn("ALICE_MIGRATE_DATABASE_URL is not set, so migrations and the application share one database role; " +
			"the audit log is then protected by database triggers only. Set ALICE_MIGRATE_DATABASE_URL to the owner role.")
	}
	if err := migrateWith(ctx, cfg.MigrationURL(), dbStartupBudget); err != nil {
		return err
	}
	pool, err := openDB(ctx, cfg.DatabaseURL, dbStartupBudget)
	if err != nil {
		return err
	}
	defer pool.Close()

	clk := newClock()
	svc, err := buildServices(ctx, pool, cfg.KeysDir, clk)
	if err != nil {
		return err
	}
	health, err := db.NewHealthChecker(pool, migrations.FS)
	if err != nil {
		return err
	}
	catalog, err := i18n.Load(locales.FS)
	if err != nil {
		return err
	}
	hosts := append([]string{"localhost", "127.0.0.1"}, cfg.TLSHosts...)
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	cert, err := tlscert.EnsureSelfSigned(cfg.KeysDir, hosts, clk.Now())
	if err != nil {
		return err
	}

	var apiServer *api.Server
	td := testDeps{
		OwnerURL: cfg.MigrationURL(),
		Setup:    svc.setup,
		Log:      log,
		ResetLimits: func() {
			if apiServer != nil {
				apiServer.ResetLimits()
			}
		},
	}
	deps := api.Deps{
		Health:         health,
		Catalog:        catalog,
		Version:        version.Get(),
		UI:             webui.UI(),
		Log:            log,
		Clock:          clk,
		Auth:           svc.auth,
		Setup:          svc.setup,
		Audit:          svc.audit,
		TrustedProxies: cfg.TrustedProxies,
		TestHandler:    testHandler(td),
	}
	apiServer = api.New(deps)

	errLog := slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	public := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           apiServer.Handler(),
		TLSConfig:         tlscert.ServerConfig(cert),
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

	errCh := make(chan error, 2)
	go func() { errCh <- ignoreClosed(public.ListenAndServeTLS("", "")) }()
	go func() { errCh <- ignoreClosed(internal.ListenAndServe()) }()
	log.Info("alice is ready", "https", cfg.ListenAddr, "health", cfg.HealthAddr)

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case runErr = <-errCh:
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()
	_ = public.Shutdown(shutdownCtx)
	_ = internal.Shutdown(shutdownCtx)
	return runErr
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

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
