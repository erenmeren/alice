package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"alice/internal/license"
	"alice/internal/platform/config"
)

func runLicense(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "keys" && args[0] != "status") {
		fmt.Fprintln(stderr, "usage: alice license status\n       alice license keys")
		return 2
	}
	if args[0] == "keys" {
		return printLicenseKeys(stdout)
	}
	return withServices(cfg, stderr, func(ctx context.Context, svc *services) int {
		snap, err := svc.license.Inspect(ctx)
		if errors.Is(err, license.ErrNoInstallation) {
			fmt.Fprintln(stderr, "Alice has not been started on this database yet, so there is no installation ID.")
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, "could not read the license state:", err)
			return 1
		}
		fmt.Fprintf(stdout, "Installation ID: %s\n", snap.InstallationID)
		fmt.Fprintf(stdout, "State: %s\n", snap.Eval.Phase)
		if cur := snap.Eval.Current; cur != nil {
			fmt.Fprintf(stdout, "License: %s for %s, up to %d targets, valid until %s\n",
				cur.LicenseID, cur.Customer, cur.MaxTargets, cur.ValidUntil.Format(time.RFC3339))
		} else {
			fmt.Fprintf(stdout, "Evaluation: ends %s (at most %d targets)\n", snap.Eval.EndsAt.Format(time.RFC3339), license.EvaluationMaxTargets)
		}
		if snap.Reading.Behind {
			fmt.Fprintln(stdout, "Warning: the system clock is behind the time Alice last saw; Alice uses the later time.")
		}
		return 0
	})
}

// printLicenseKeys lists the embedded verification keys so the owner can compare each
// fingerprint with the vendor's recorded one (spec §19.2).
func printLicenseKeys(stdout io.Writer) int {
	keys := license.EmbeddedKeys()
	if keys.Len() == 0 {
		fmt.Fprintln(stdout, "No license verification key is embedded in this build: no license file can be installed (evaluation only).")
	}
	for _, k := range keys.Keys() {
		fmt.Fprintf(stdout, "%s  %s  %s\n", k.ID, k.Status, license.Fingerprint(k.Key))
	}
	if license.TestKeyTrusted {
		fmt.Fprintln(stdout, "WARNING: test build: the test signing key is trusted. Never use this build for real data.")
	}
	return 0
}
