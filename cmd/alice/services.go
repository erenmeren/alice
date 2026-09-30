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
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
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
	keyring *secrets.Keyring
	audit   *audit.Service
	auth    *auth.Service
	setup   *setup.Service
	license *license.Service
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
		BuildTime: buildTime(),
		Notifier:  notify.AdminNotifier{Clock: clk},
		Log:       log,
	})
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
		keyring: keyring,
		audit:   audit.NewService(auditLog, pool),
		auth:    authSvc,
		setup:   setupSvc,
		license: lic,
	}, nil
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

// buildTime is the link-time build timestamp; the license time never falls below it (§16.5).
// Development builds have none.
func buildTime() time.Time {
	t, err := time.Parse(time.RFC3339, version.BuildTime)
	if err != nil {
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
