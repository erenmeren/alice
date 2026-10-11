package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/secrets"
	"alice/migrations"
)

// checkLine is one line of alice selfcheck (C9) and of the support bundle.
type checkLine struct {
	Label  string `json:"label"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

func (c checkLine) String() string {
	if c.OK {
		return "[ OK ] " + c.Label
	}
	return "[FAIL] " + c.Label + ": " + c.Reason
}

// Selfcheck budgets (C9). The heartbeat line alone is retried: a restored database carries an old heartbeat, and a
// process that just started writes its first within seconds (M-3). Variables only so the tests can shorten them.
var (
	selfcheckStep      = 5 * time.Second
	heartbeatWait      = 90 * time.Second
	heartbeatPoll      = 5 * time.Second
	heartbeatMaxAge    = 5 * time.Minute
	heartbeatMaxAhead  = time.Minute // a heartbeat further ahead of the clock proves nothing (M-2)
	errNotReachable    = errors.New("the database is not reachable")
	errNotInstalledTLS = errors.New("the listener presents another certificate than " + tlsCertFile)
)

const tlsCertFile = "tls.crt"

// The heartbeat (C1 jobs.heartbeat): written by the jobs.heartbeat task every minute and once when serve's scheduler
// starts.
const heartbeatKey = "jobs.heartbeat"

type heartbeat struct {
	At time.Time `json:"at"`
}

// writeHeartbeat records that the scheduler of this process runs.
func writeHeartbeat(ctx context.Context, q db.Querier, clk clock.Clock) error {
	now := clk.Now().UTC()
	return settings.Set(ctx, q, heartbeatKey, heartbeat{At: now.Truncate(time.Second)}, now)
}

func runSelfcheck(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: alice selfcheck")
		return 2
	}
	ctx, stop := commandContext()
	defer stop()
	code := 0
	for _, l := range selfcheck(ctx, cfg, func(l checkLine) { fmt.Fprintln(stdout, l) }) {
		if !l.OK {
			code = 1
		}
	}
	return code
}

// selfcheck runs C9's seven checks in order, reporting each line as soon as it is known. It writes nothing.
func selfcheck(ctx context.Context, cfg config.Config, report func(checkLine)) []checkLine {
	var lines []checkLine
	add := func(l checkLine) {
		lines = append(lines, l)
		if report != nil {
			report(l)
		}
	}
	pool, err := selfcheckPool(ctx, cfg)
	if pool != nil {
		defer pool.Close()
	}
	add(result("Database reachable", err))
	if err != nil {
		for _, label := range []string{"Database schema is current", "Master key opens the stored key check", "Audit log intact",
			"License readable"} {
			add(result(label, errNotReachable))
		}
		add(checkTLS(ctx, cfg))
		add(result("Background jobs running", errNotReachable))
		return lines
	}
	add(checkSchema(ctx, pool))
	keyErr := withStep(ctx, func(ctx context.Context) error { return secrets.CheckMasterKey(ctx, pool, cfg.KeysDir) })
	add(result("Master key opens the stored key check", keyErr))
	add(checkAudit(ctx, pool))
	add(checkLicense(ctx, pool, cfg, keyErr))
	add(checkTLS(ctx, cfg))
	add(checkHeartbeat(ctx, pool))
	return lines
}

func result(label string, err error) checkLine {
	if err != nil {
		return checkLine{Label: label, Reason: err.Error()}
	}
	return checkLine{Label: label, OK: true}
}

// withStep runs fn with C9's per-check budget.
func withStep(ctx context.Context, fn func(context.Context) error) error {
	sctx, cancel := context.WithTimeout(ctx, selfcheckStep)
	defer cancel()
	return fn(sctx)
}

// selfcheckPool opens the application pool and pings it within the step budget.
func selfcheckPool(ctx context.Context, cfg config.Config) (*pgxpool.Pool, error) {
	if err := cfg.RequireDatabase(); err != nil {
		return nil, err
	}
	var pool *pgxpool.Pool
	err := withStep(ctx, func(ctx context.Context) error {
		p, err := db.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		pool = p
		return p.Ping(ctx)
	})
	if err != nil && pool != nil {
		pool.Close()
		pool = nil
	}
	return pool, err
}

func checkSchema(ctx context.Context, pool *pgxpool.Pool) checkLine {
	want, err := db.LatestVersion(migrations.FS)
	if err != nil {
		return result("Database schema is current", err)
	}
	var have int64
	err = withStep(ctx, func(ctx context.Context) error {
		var err error
		have, err = db.SchemaVersion(ctx, pool)
		return err
	})
	if err != nil {
		return result("Database schema is current", err)
	}
	label := fmt.Sprintf("Database schema is current (version %d)", have)
	if have != want {
		return checkLine{Label: label, Reason: fmt.Sprintf("this Alice needs version %d", want)}
	}
	return checkLine{Label: label, OK: true}
}

func checkAudit(ctx context.Context, pool *pgxpool.Pool) checkLine {
	// The whole chain is read: no step budget, the command's context bounds it.
	rep, err := audit.Verify(ctx, pool)
	switch {
	case err != nil:
		return result("Audit log intact", err)
	case !rep.Intact:
		return checkLine{Label: "Audit log intact", Reason: fmt.Sprintf("damaged at entry %d (%s)", rep.FirstBadSeq, rep.Problem)}
	}
	head := hex.EncodeToString(rep.HeadHash)
	if len(head) > 16 {
		head = head[:16]
	}
	return checkLine{Label: fmt.Sprintf("Audit log intact (%d entries, head %s)", rep.Checked, head), OK: true}
}

// checkLicense evaluates the license read-only (license.Service.Inspect: the process has no running evaluation of its
// own). It needs the master key, so it is not readable when the key check failed.
func checkLicense(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, keyErr error) checkLine {
	const label = "License readable"
	if keyErr != nil {
		return checkLine{Label: label, Reason: "the master key could not be loaded"}
	}
	var snap license.Snapshot
	err := withStep(ctx, func(ctx context.Context) error {
		svc, err := inspectionLicense(ctx, pool, cfg)
		if err != nil {
			return err
		}
		snap, err = svc.Inspect(ctx)
		return err
	})
	if err != nil {
		return result(label, err)
	}
	return checkLine{Label: fmt.Sprintf("%s (%s)", label, snap.Eval.Phase), OK: true}
}

// inspectionLicense builds a license service that is only inspected: never started, so it writes nothing. The key
// check passed, so LoadOrCreateMasterKey only loads.
func inspectionLicense(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) (*license.Service, error) {
	clk := newClock()
	keyring, err := secrets.LoadOrCreateMasterKey(ctx, pool, cfg.KeysDir, clk.Now())
	if err != nil {
		return nil, err
	}
	log := slog.New(slog.DiscardHandler)
	return license.New(license.Config{Pool: pool, Keyring: keyring, Audit: audit.New(clk), Clock: clk, Uptime: clk,
		Keys: license.EmbeddedKeys(), StateDir: cfg.StateDir, BuildTime: buildTime(log), Notifier: notify.AdminNotifier{Clock: clk},
		Targets: inventory.Counter{}, Log: log}), nil
}

// checkTLS connects to the local listener and compares the presented leaf with keys/tls.crt.
func checkTLS(ctx context.Context, cfg config.Config) checkLine {
	const label = "HTTPS listener answers with the installed certificate"
	return result(label, withStep(ctx, func(ctx context.Context) error {
		_, port, err := net.SplitHostPort(cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("ALICE_LISTEN_ADDR %q has no port", cfg.ListenAddr)
		}
		want, err := installedLeaf(filepath.Join(cfg.KeysDir, tlsCertFile))
		if err != nil {
			return err
		}
		d := &tls.Dialer{Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The probe checks one thing: that the presented leaf is byte-equal to the installed certificate, which
			// VerifyConnection does (on every handshake, resumed or not). The certificate may be self-signed or name
			// another host.
			InsecureSkipVerify: true, //nolint:gosec // G402: the leaf is compared with keys/tls.crt in VerifyConnection
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, want) {
					return errNotInstalledTLS
				}
				return nil
			},
		}}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			if errors.Is(err, errNotInstalledTLS) {
				return errNotInstalledTLS
			}
			return fmt.Errorf("no TLS answer on 127.0.0.1:%s: %w", port, err)
		}
		return conn.Close()
	}))
}

// installedLeaf is the DER of the first certificate in path.
func installedLeaf(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the keys directory from configuration and a fixed name
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", tlsCertFile, err)
	}
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s holds no certificate", tlsCertFile)
		}
		if blk.Type == "CERTIFICATE" {
			return blk.Bytes, nil
		}
	}
}

// checkHeartbeat waits up to heartbeatWait, reading every heartbeatPoll, for a heartbeat younger than heartbeatMaxAge
// and not more than heartbeatMaxAhead in the future (a running scheduler overwrites one dated ahead within a minute).
func checkHeartbeat(ctx context.Context, pool *pgxpool.Pool) checkLine {
	const label = "Background jobs running"
	clk := clock.Real{}
	deadline := clk.Now().Add(heartbeatWait)
	for {
		var hb heartbeat
		var found bool
		err := withStep(ctx, func(ctx context.Context) error {
			var err error
			found, err = settings.Get(ctx, pool, heartbeatKey, &hb)
			return err
		})
		now := clk.Now()
		switch {
		case err != nil:
			return result(label, err)
		case found && now.Sub(hb.At) < heartbeatMaxAge && hb.At.Sub(now) <= heartbeatMaxAhead:
			return checkLine{Label: fmt.Sprintf("%s (last heartbeat %s UTC)", label, hb.At.UTC().Format("15:04")), OK: true}
		case !now.Add(heartbeatPoll).Before(deadline):
			if !found {
				return checkLine{Label: label, Reason: "no heartbeat was recorded"}
			}
			if hb.At.Sub(now) > heartbeatMaxAhead {
				return checkLine{Label: label, Reason: fmt.Sprintf("the last heartbeat is dated in the future (%s UTC); check the system clock",
					hb.At.UTC().Format("2006-01-02 15:04"))}
			}
			return checkLine{Label: label, Reason: fmt.Sprintf("the last heartbeat was at %s UTC", hb.At.UTC().Format("2006-01-02 15:04"))}
		}
		select {
		case <-ctx.Done():
			return result(label, ctx.Err())
		case <-time.After(heartbeatPoll):
		}
	}
}
