package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/targetjobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/secrets"
	"alice/internal/setup"
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
}

// buildServices loads (or, on a brand-new database, creates) the master key and wires the
// services on the application pool. It starts nothing: serve calls license.Start. It does
// not touch the email configuration, so the recovery commands work while it is broken.
func buildServices(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, clk serverClock, log *slog.Logger) (*services, error) {
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
	registerProviders(registry, sshPool)
	setupSvc := setup.New(setup.Config{
		Pool:      pool,
		Auth:      authSvc,
		Keyring:   keyring,
		Audit:     auditLog,
		Clock:     clk,
		Hasher:    passwords,
		BackupKDF: secrets.BackupKDF,
		License:   lic,
	})
	return &services{
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
	}, nil
}

// jobRetention is how long finished jobs are kept before maintenance.cleanup prunes them (§8.2).
const jobRetention = 90 * 24 * time.Hour

// buildRunner builds the job workers with every Phase 3 handler (spec §8.1–§8.8). Every claim
// passes the license gate; a job that runs out of attempts or fails its integrity check emails
// the Administrators.
func buildRunner(pool *pgxpool.Pool, svc *services, clk clock.Clock, log *slog.Logger) *jobs.Runner {
	runner := jobs.NewRunner(jobs.RunnerConfig{Pool: pool, Queue: svc.queue, Gate: svc.license, Audit: svc.auditLog,
		Clock: clk, Log: log, Notifier: notify.AdminNotifier{Clock: clk}})
	targetjobs.Register(runner, targetjobs.Deps{Inventory: svc.inventory, Registry: svc.registry, Clock: clk, Log: log})
	return runner
}

// buildScheduler is the periodic work of serve (spec §8.2, R37 item 15); every run passes the
// license gate. The audit verification ticks hourly and verifies when the last intact
// verification is 23 hours old (jobs.AuditVerifyTask). The e2e tests use the same tasks.
func buildScheduler(svc *services, sender *notify.Sender, clk clock.Clock, log *slog.Logger) *jobs.Scheduler {
	return jobs.NewScheduler(clk, svc.license, log,
		jobs.Task{Type: jobs.LicenseEvaluate, Every: time.Hour, Run: svc.license.Tick},
		jobs.Task{Type: jobs.NotifySend, Every: time.Minute, Run: func(ctx context.Context) error {
			_, err := sender.Drain(ctx)
			return err
		}},
		jobs.AuditVerifyTask(jobs.AuditVerifyConfig{Pool: svc.pool, Verifier: svc.audit, Notifier: notify.AdminNotifier{Clock: clk}, Clock: clk}),
		jobs.Task{Type: jobs.MaintenanceCleanup, Every: time.Hour, Run: func(ctx context.Context) error {
			_, sessionsErr := svc.auth.PruneExpired(ctx)
			_, jobsErr := svc.queue.Prune(ctx, jobRetention)
			return errors.Join(sessionsErr, jobsErr)
		}},
		jobs.Task{Type: jobs.DiscoverySchedule, Every: time.Minute, Run: func(ctx context.Context) error {
			_, err := svc.inventory.ScheduleDiscovery(ctx)
			return err
		}},
	)
}

// buildSender builds the email sender of serve (notify.send). Only serve sends email, so
// only serve reads ALICE_SMTP_PASSWORD_FILE and ALICE_SMTP_CA_FILE.
func buildSender(pool *pgxpool.Pool, cfg config.Config, catalog *i18n.Catalog, clk clock.Clock, log *slog.Logger) (*notify.Sender, error) {
	mailer, err := newMailer(cfg, clk)
	if err != nil {
		return nil, err
	}
	return &notify.Sender{Pool: pool, Mailer: mailer, Catalog: catalog, Clock: clk, Log: log}, nil
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

// newMailer builds the SMTP mailer from ALICE_SMTP_*. Without a host it returns nil and the
// sender records emails as skipped (L-18). The e2e build uses its test mailbox instead.
func newMailer(cfg config.Config, clk clock.Clock) (notify.Mailer, error) {
	if testMailer != nil {
		return testMailer, nil
	}
	if !cfg.SMTP.Configured() {
		return nil, nil
	}
	c := notify.SMTPConfig{Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, From: cfg.SMTP.From, Username: cfg.SMTP.Username, TLSMode: cfg.SMTP.TLSMode}
	if cfg.SMTP.PasswordFile != "" {
		b, err := os.ReadFile(cfg.SMTP.PasswordFile) //nolint:gosec // G304: operator-supplied path from ALICE_SMTP_PASSWORD_FILE
		if err != nil {
			return nil, fmt.Errorf("read ALICE_SMTP_PASSWORD_FILE %s: %w", cfg.SMTP.PasswordFile, errors.Unwrap(err))
		}
		c.Password = secrets.NewPlaintext(bytes.TrimRight(b, "\r\n"))
	}
	if cfg.SMTP.CAFile != "" {
		pem, err := os.ReadFile(cfg.SMTP.CAFile) //nolint:gosec // G304: operator-supplied path from ALICE_SMTP_CA_FILE
		if err != nil {
			return nil, fmt.Errorf("read ALICE_SMTP_CA_FILE %s: %w", cfg.SMTP.CAFile, errors.Unwrap(err))
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ALICE_SMTP_CA_FILE %s holds no PEM certificate", cfg.SMTP.CAFile)
		}
		c.RootCAs = pool
	}
	m, err := notify.NewSMTPMailer(c, clk)
	if err != nil {
		return nil, err
	}
	return m, nil
}
