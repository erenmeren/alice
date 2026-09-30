package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/config"
	"alice/internal/setup"
)

// cliBudget bounds how long an operator command waits for the database.
const cliBudget = 15 * time.Second

// cliActor names the host-root command line in the audit log.
const cliActor = "cli"

// runSetupToken prints a new setup code to stdout only: the code is never
// written to a file, so nothing is left behind once the administrator exists.
func runSetupToken(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "--reset" {
		fmt.Fprintln(stderr, "usage: alice setup-token --reset")
		return 2
	}
	return withServices(cfg, stderr, func(ctx context.Context, svc *services) int {
		code, err := svc.setup.ResetToken(ctx)
		if errors.Is(err, setup.ErrAlreadySetUp) {
			fmt.Fprintln(stderr, "An administrator already exists, so a setup code is no longer needed. Sign in instead.")
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, "could not create a setup code:", err)
			return 1
		}
		fmt.Fprintf(stdout, "One-time setup code: %s\n", code)
		fmt.Fprintln(stdout, "Enter it on the /setup page. Any earlier code no longer works; this one stops working when the first administrator is created.")
		return 0
	})
}

// runAudit does not load the master key (the chain does not need it), so it
// still works when the key file is missing or broken.
func runAudit(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "verify" {
		fmt.Fprintln(stderr, "usage: alice audit verify")
		return 2
	}
	return withPool(cfg, stderr, func(ctx context.Context, pool *pgxpool.Pool) int {
		svc := audit.NewService(audit.New(newClock()), pool)
		rep, err := svc.Verify(ctx, audit.SystemActor(cliActor))
		if err != nil {
			fmt.Fprintln(stderr, "could not verify the audit log:", err)
			return 1
		}
		if !rep.Intact {
			fmt.Fprintf(stdout, "Audit log integrity problem at entry %d (%s). %d entries checked.\n", rep.FirstBadSeq, rep.Problem, rep.Checked)
			return 1
		}
		fmt.Fprintf(stdout, "The audit log is intact: %d entries checked, head entry %d, head hash %s.\n", rep.Checked, rep.HeadSeq, hex.EncodeToString(rep.HeadHash))
		return 0
	})
}

func runAdmin(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[1] == "" || (args[0] != "reset-mfa" && args[0] != "unlock") {
		fmt.Fprintln(stderr, "usage: alice admin reset-mfa <username>\n       alice admin unlock <username>")
		return 2
	}
	if args[0] == "unlock" {
		return runAdminUnlock(args[1], cfg, stdout, stderr)
	}
	username := args[1]
	return withServices(cfg, stderr, func(ctx context.Context, svc *services) int {
		err := svc.auth.ResetMFAByUsername(ctx, username)
		if errors.Is(err, auth.ErrNotFound) {
			fmt.Fprintf(stderr, "There is no user named %q.\n", username)
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, "could not reset the authenticator app:", err)
			return 1
		}
		fmt.Fprintf(stdout, "The authenticator app of %q was removed. They set up a new one at their next sign-in.\n", username)
		return 0
	})
}

// runAdminUnlock ends a sign-in delay or lockout (host-root break-glass for a
// blocked administrator); it is audited as done by "cli".
func runAdminUnlock(username string, cfg config.Config, stdout, stderr io.Writer) int {
	return withServices(cfg, stderr, func(ctx context.Context, svc *services) int {
		err := svc.auth.UnlockByUsername(ctx, username)
		if errors.Is(err, auth.ErrNotFound) {
			fmt.Fprintf(stderr, "There is no user named %q.\n", username)
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, "could not unlock the account:", err)
			return 1
		}
		fmt.Fprintf(stdout, "The account %q was unlocked. The failed sign-in count is back to zero.\n", username)
		return 0
	})
}

// withPool opens the application pool for one operator command.
func withPool(cfg config.Config, stderr io.Writer, fn func(ctx context.Context, pool *pgxpool.Pool) int) int {
	if err := cfg.RequireDatabase(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := openDB(ctx, cfg.DatabaseURL, cliBudget)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer pool.Close()
	return fn(ctx, pool)
}

// withServices additionally loads the master key and wires the services.
func withServices(cfg config.Config, stderr io.Writer, fn func(ctx context.Context, svc *services) int) int {
	return withPool(cfg, stderr, func(ctx context.Context, pool *pgxpool.Pool) int {
		svc, err := buildServices(ctx, pool, cfg, newClock(), slog.New(slog.DiscardHandler))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return fn(ctx, svc)
	})
}
