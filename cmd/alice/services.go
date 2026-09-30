package main

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/clock"
	"alice/internal/secrets"
	"alice/internal/setup"
)

// Argon2id memory is 64 MiB per password hash, so at most two run at once
// (the container memory limit is 512 MiB). Recovery-code hashes use 8 MiB.
const (
	passwordHashConcurrency = 2
	recoveryHashConcurrency = 4
)

// services are the module services shared by serve and the CLI commands.
type services struct {
	keyring *secrets.Keyring
	audit   *audit.Service
	auth    *auth.Service
	setup   *setup.Service
}

// buildServices loads (or, on a brand-new database, creates) the master key
// and wires the auth, setup and audit services on the application pool.
func buildServices(ctx context.Context, pool *pgxpool.Pool, keysDir string, clk clock.Clock) (*services, error) {
	keyring, err := secrets.LoadOrCreateMasterKey(ctx, pool, keysDir, clk.Now())
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
	setupSvc := setup.New(setup.Config{
		Pool:      pool,
		Auth:      authSvc,
		Keyring:   keyring,
		Audit:     auditLog,
		Clock:     clk,
		Hasher:    passwords,
		BackupKDF: secrets.BackupKDF,
	})
	return &services{
		keyring: keyring,
		audit:   audit.NewService(auditLog, pool),
		auth:    authSvc,
		setup:   setupSvc,
	}, nil
}
