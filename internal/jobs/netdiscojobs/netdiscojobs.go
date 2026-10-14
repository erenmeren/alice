// Package netdiscojobs holds the jobs of network certificate discovery (plan 2026-10-13-network-discovery, design
// decisions 1 and 6, amendments A1, A4, A5): the netdisco.scan handler (one scan of one scope, discovery.Run), the
// periodic netdisco.schedule (queues the scans of scopes whose schedule is due) and netdisco.retention (removes old
// discovery rows), and StartTx, the one way a scan is queued (the API's start route and the schedule): the scan row and
// its job in one transaction.
//
// A scan job runs once (jobs.MaxAttemptsFor): a lost lease or a crash kills the job, so the scanner's own recovery of
// a scan left running (discovery.PGStore.BeginScan) never runs for it. The runner's end hook (jobs.Runner.OnEnd) ends
// the scan in the transaction that ends the job; the schedule tick and the retention run end any scan whose job is no
// longer queued or running (the hook's backstop). Payloads carry the scan id only: no scope contents, no secrets.
//
// Licence: netdisco.scan and netdisco.schedule are ClassReadOnly (the runner and the scheduler pause them in lock; the
// scanner asks the gate again before every batch); netdisco.retention is ClassAlways (it only deletes Alice's own
// discovery rows, so it runs in lock too). The lock's cancellation of a queued scan job cancels its scan with the
// license reason (end hook).
package netdiscojobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/discovery"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
)

// Enqueuer writes a job in the caller's transaction (*jobs.Queue).
type Enqueuer interface {
	Add(ctx context.Context, tx pgx.Tx, s jobs.Spec) (uuid.UUID, bool, error)
}

var _ Enqueuer = (*jobs.Queue)(nil)

// Deps are the dependencies of the discovery jobs. Pool, License and Clock are required by the scan handler; Pool, Queue
// and Clock by the schedule; Pool and Clock by the retention. DatabaseURL is Alice's database DSN, whose hosts the scan
// policy refuses. Lease is the runner's lease (0: discovery.DefaultLease, the runner's default). NewPolicy and Resolver
// are the scanner's (nil: the production scan policy and the system resolver); tests inject them.
type Deps struct {
	Pool        *pgxpool.Pool
	Queue       Enqueuer
	License     discovery.Licenser
	Clock       clock.Clock
	Log         *slog.Logger
	DatabaseURL string
	Lease       time.Duration
	NewPolicy   func(context.Context, netaddr.ScanPolicyInputs) (netaddr.ScanPolicy, error)
	Resolver    discovery.Resolver
}

func (d Deps) withLog() Deps {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	return d
}

// PayloadScanID is the one key of a scan job's payload.
const PayloadScanID = "scan_id"

// Job failure reasons that are not a scan's own code.
const (
	reasonNotFound = "system.not_found"
	reasonRunning  = "discovery.scan_running" // ALC-DSC-0004
)

// Register installs the netdisco.scan handler and its end hook on the runner; it panics on a missing dependency, so a
// build that forgot one never starts.
func Register(r *jobs.Runner, d Deps) {
	if r == nil || d.Pool == nil || d.License == nil || d.Clock == nil {
		panic("netdiscojobs: Register needs a runner, Deps.Pool, Deps.License and Deps.Clock")
	}
	newHandlers(d).install(r)
}

type handlers struct {
	d Deps
	// run is the scanner (discovery.Run); tests replace it.
	run func(ctx context.Context, d discovery.Deps, scanID uuid.UUID) error
}

func newHandlers(d Deps) *handlers {
	return &handlers{d: d.withLog(), run: discovery.Run}
}

func (h *handlers) install(r *jobs.Runner) {
	r.Handle(jobs.NetdiscoScan, h.scan)
	r.OnEnd(jobs.NetdiscoScan, h.ended)
}

func (h *handlers) scanDeps() discovery.Deps {
	return discovery.Deps{Store: discovery.NewStore(h.d.Pool), License: h.d.License, NewPolicy: h.d.NewPolicy,
		DatabaseURL: h.d.DatabaseURL, Resolver: h.d.Resolver, Clock: h.d.Clock, Lease: h.d.Lease}
}

// scan is the netdisco.scan handler. The scanner records every end of the scan in the scan's own row; the job mirrors
// it: a scan that finished, was cancelled (a person, its scope switched off, the license lock) or timed out (partial
// results kept) is a succeeded job whose result names the scan's state and code; a scan that failed is a failed job
// with the scan's code (permanent: the queue never repeats a scan; a person or the scope's schedule starts the next);
// a database failure is an unexpected failure (the one attempt is spent: the job is dead and the end hook ends the scan).
func (h *handlers) scan(ctx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	id, err := uuid.Parse(j.Payload[PayloadScanID])
	if err != nil {
		return nil, jobs.Fail(reasonNotFound, nil, err)
	}
	err = h.run(ctx, h.scanDeps(), id)
	switch {
	case errors.Is(err, discovery.ErrScanNotFound):
		return nil, jobs.Fail(reasonNotFound, nil, err)
	case errors.Is(err, discovery.ErrScanBusy):
		return nil, jobs.Fail(reasonRunning, map[string]string{"scan_id": id.String()}, err)
	case err != nil:
		return nil, jobs.FromProvider(err)
	}
	out, err := h.outcome(context.WithoutCancel(ctx), id)
	if err != nil {
		return nil, jobs.FromProvider(err)
	}
	if out.state == discovery.ScanFailed || out.state == discovery.ScanQueued || out.state == discovery.ScanRunning {
		code := out.code
		if code == "" {
			code = discovery.ReasonInterrupted
		}
		return nil, jobs.Fail(code, map[string]string{"scan_id": id.String()}, nil)
	}
	res := map[string]any{"scan_id": id.String(), "state": out.state, "endpoints_total": out.total,
		"endpoints_answered": out.answered, "endpoints_failed": out.failed, "endpoints_excluded": out.excluded}
	if out.code != "" {
		res["error_code"] = out.code
	}
	return res, nil
}

// scanOutcome is what a scan's row says after its run.
type scanOutcome struct {
	state, code                       string
	total, answered, failed, excluded int
}

func (h *handlers) outcome(ctx context.Context, id uuid.UUID) (scanOutcome, error) {
	var o scanOutcome
	err := h.d.Pool.QueryRow(ctx, `SELECT state, error_code, endpoints_total, endpoints_answered, endpoints_failed, endpoints_excluded
FROM discovery_scans WHERE id = $1`, id).Scan(&o.state, &o.code, &o.total, &o.answered, &o.failed, &o.excluded)
	if err != nil {
		return scanOutcome{}, fmt.Errorf("netdiscojobs: read the scan's outcome: %w", err)
	}
	return o, nil
}

// ended is the end hook of netdisco.scan: in the transaction that ends the job without success, the job's scan, if it
// is still queued or running, ends too. The license lock's cancellation cancels it with the license reason; anything
// else (a lost lease, a crash, the shutdown, a handler failure) fails it as interrupted (ALC-DSC-0012). A tampered
// job's payload is not trusted (the sweep ends its real scan), and a scan another live job holds is left to that job.
func (h *handlers) ended(ctx context.Context, tx pgx.Tx, end jobs.JobEnd) error {
	if end.Reason == "job.tampered" {
		return nil
	}
	state, code := discovery.ScanFailed, discovery.ReasonInterrupted
	if end.Status == jobs.StatusCancelled && strings.HasPrefix(end.Reason, "license.") {
		state, code = discovery.ScanCancelled, end.Reason
	}
	_, err := tx.Exec(ctx, `UPDATE discovery_scans s SET state = $2, error_code = $3, finished_at = greatest($4::timestamptz, s.started_at)
FROM jobs j
WHERE j.id = $1 AND j.type = 'netdisco.scan' AND s.id::text = j.payload->>'scan_id' AND s.state IN ('queued', 'running')
  AND NOT EXISTS (SELECT 1 FROM jobs o WHERE o.dedupe_key = j.dedupe_key AND o.id <> j.id
                  AND o.status IN ('queued', 'running', 'blocked_license') AND o.payload->>'scan_id' = j.payload->>'scan_id')`,
		end.ID, state, code, h.d.Clock.Now())
	if err != nil {
		return fmt.Errorf("netdiscojobs: end the scan of an ended job: %w", err)
	}
	return nil
}
