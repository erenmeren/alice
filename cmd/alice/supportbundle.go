package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit/forward"
	"alice/internal/backup"
	"alice/internal/jobs"
	"alice/internal/platform/config"
	"alice/internal/platform/db"
	"alice/internal/secrets"
	"alice/internal/version"
)

// supportBundle is C9's support report. It names no customer, no Installation ID, no host of a managed system and no
// secret: only versions, the redacted configuration, the selfcheck, counts and states.
type supportBundle struct {
	Version       version.Info     `json:"version"`
	Config        config.Config    `json:"config"` // config.Config.MarshalJSON: passwords redacted
	Selfcheck     []checkLine      `json:"selfcheck"`
	SchemaVersion int64            `json:"schema_version"`
	Tables        map[string]int64 `json:"tables"`
	License       bundleLicense    `json:"license"`
	Jobs          bundleJobs       `json:"jobs"`
	Backup        bundleBackup     `json:"backup"`
	Forwarding    bundleForwarding `json:"forwarding"`
	Errors        []string         `json:"errors,omitempty"` // the sections that could not be read
}

type bundleLicense struct {
	Phase    string `json:"phase"`
	DaysLeft int    `json:"days_left"`
}

type bundleJobs struct {
	Queued    int64 `json:"queued"`
	Running   int64 `json:"running"`
	Failed24h int64 `json:"failed_24h"`
	Dead24h   int64 `json:"dead_24h"`
}

type bundleBackup struct {
	LastSuccessAt *time.Time `json:"last_success_at"`
	Failing       bool       `json:"failing"`
}

type bundleForwarding struct {
	Enabled bool  `json:"enabled"`
	Backlog int64 `json:"backlog"`
}

func runSupportBundle(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: alice support-bundle")
		return 2
	}
	ctx, stop := commandContext()
	defer stop()
	b := supportBundle{Version: buildVersion(), Config: cfg, Tables: map[string]int64{}}
	b.Selfcheck = selfcheck(ctx, cfg, nil)
	if pool, err := selfcheckPool(ctx, cfg); err == nil {
		b.collect(ctx, pool, cfg)
		pool.Close()
	} else {
		b.Errors = append(b.Errors, "database: "+errNotReachable.Error())
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		fmt.Fprintln(stderr, "could not write the support bundle:", err)
		return 1
	}
	return 0
}

// collect reads the database sections; a section that fails is named in Errors and the others are still read.
func (b *supportBundle) collect(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) {
	note := func(section string, err error) {
		if err != nil {
			b.Errors = append(b.Errors, fmt.Sprintf("%s: %T", section, err))
		}
	}
	var err error
	b.SchemaVersion, err = db.SchemaVersion(ctx, pool)
	note("schema_version", err)
	note("tables", b.countTables(ctx, pool))
	clk := newClock()
	b.Jobs.Queued, b.Jobs.Running, b.Jobs.Failed24h, b.Jobs.Dead24h, err = jobCounts(ctx, pool, clk.Now().Add(-24*time.Hour))
	note("jobs", err)
	st, err := backup.New(backup.Config{Pool: pool, Clock: clk}).State(ctx)
	note("backup", err)
	if err == nil {
		if !st.LastSuccessAt.IsZero() {
			at := st.LastSuccessAt.UTC()
			b.Backup.LastSuccessAt = &at
		}
		b.Backup.Failing = st.Failing()
	}
	fs, fst, err := forward.New(forward.Config{Pool: pool, Clock: clk}).Settings(ctx)
	note("forwarding", err)
	b.Forwarding = bundleForwarding{Enabled: fs.Enabled, Backlog: fst.Backlog}
	if secretsErr := withStep(ctx, func(ctx context.Context) error { return secrets.CheckMasterKey(ctx, pool, cfg.KeysDir) }); secretsErr == nil {
		svc, err := inspectionLicense(ctx, pool, cfg)
		if err == nil {
			snap, ierr := svc.Inspect(ctx)
			err = ierr
			b.License = bundleLicense{Phase: string(snap.Eval.Phase), DaysLeft: snap.Eval.DaysLeft}
		}
		note("license", err)
	} else {
		note("license", secretsErr)
	}
}

// countTables counts the rows of every table the application role can read, exactly. The table names come from the
// catalog and are quoted by PostgreSQL's format('%I'): no SQL is built here.
func (b *supportBundle) countTables(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `SELECT table_name::text,
	(xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM public.%I', table_name), false, true, '')))[1]::text::bigint
FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			return err
		}
		b.Tables[name] = n
	}
	return rows.Err()
}

// jobCounts counts the queued and running jobs and the jobs that failed or died since since (C9).
func jobCounts(ctx context.Context, q db.Querier, since time.Time) (queued, running, failed, dead int64, err error) {
	err = q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = $1), count(*) FILTER (WHERE status = $2),
	count(*) FILTER (WHERE status = $3 AND finished_at >= $5), count(*) FILTER (WHERE status = $4 AND finished_at >= $5) FROM jobs`,
		string(jobs.StatusQueued), string(jobs.StatusRunning), string(jobs.StatusFailed), string(jobs.StatusDead), since).
		Scan(&queued, &running, &failed, &dead)
	return queued, running, failed, dead, err
}
