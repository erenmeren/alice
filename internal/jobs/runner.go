package jobs

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/providers"
)

// StepRecorder records the externally visible steps of a job (spec §6.3 item 2); the steps are
// stored in the job's result.
type StepRecorder interface {
	providers.StepLogger
}

// HandlerFunc runs one job. Its result map is stored as the job's result; it must hold ids and
// public facts only, never secrets. Errors are classified with FromProvider.
type HandlerFunc func(ctx context.Context, j Job, steps StepRecorder) (map[string]any, error)

// RunnerConfig holds the runner's dependencies and limits.
type RunnerConfig struct {
	Pool          *pgxpool.Pool
	Queue         *Queue
	Gate          Gate
	Audit         *audit.Log
	Clock         clock.Clock
	Log           *slog.Logger
	Workers       int            // default 8
	WorkerID      string         // default "<hostname>-<pid>-<random>"
	Lease         time.Duration  // default 45 s
	Heartbeat     time.Duration  // default 15 s
	Poll          time.Duration  // default 1 s
	ReapEvery     time.Duration  // default 60 s
	ShutdownGrace time.Duration  // default 60 s, in total: jobs are cancelled after half of it
	Jitter        func() float64 // in [-0.2, 0.2]; default crypto/rand
	Notifier      Notifier       // emails the Administrators about dead jobs; nil = no email
}

// Notifier queues an email to every Administrator inside tx; notify.AdminNotifier implements it.
type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}

// TemplateJobDead is the email sent when a job is out of attempts (spec §8.4 "exhausted jobs
// raise an alert"; until the Phase 7 alert engine the alert is this email). Its params are
// those of deadAlertParams.
const TemplateJobDead = "job.dead"

// alertsWhenDead reports whether a job of the type that dies emails the Administrators:
// AlertsWhenExhausted, on every path that ends a job dead (finish, release after a lost lease, the
// reaper after a crash). A recovery job's death is announced by its deployment's own escalation;
// the dead status and the job.dead audit row stay.
func alertsWhenDead(typ string) bool {
	t, ok := lookup(typ)
	return !ok || AlertsWhenExhausted(t)
}

// TemplateJobTampered is the email sent when a job's stored data fails its integrity check
// (threat J-1): the job was changed outside Alice and is never run. Its params are those of
// tamperedAlertParams.
const TemplateJobTampered = "job.tampered"

func deadAlertParams(id uuid.UUID, typ, reason string, attempts int) map[string]string {
	return map[string]string{"job_id": id.String(), "type": typ, "reason": reason, "attempts": strconv.Itoa(attempts)}
}

func tamperedAlertParams(id uuid.UUID, typ string) map[string]string {
	return map[string]string{"job_id": id.String(), "type": typ}
}

// alert queues an email to the Administrators in the transaction that stops the job: a job
// stops once (its status is final and every write is fenced), so each one is announced once.
func (r *Runner) alert(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	if r.cfg.Notifier == nil {
		return nil
	}
	if err := r.cfg.Notifier.NotifyAdmins(ctx, tx, template, params); err != nil {
		return fmt.Errorf("jobs: queue the %s email: %w", template, err)
	}
	return nil
}

// JobEnd is a job the runner ended without success: its new status (failed, dead or cancelled) and its reason
// (last_error_code).
type JobEnd struct {
	ID     uuid.UUID
	Status Status
	Reason string
}

// EndHook is run by the runner inside the transaction that ends a job of its type without success: a failure, a job out
// of attempts (on the handler's error, after a lost lease, at the shutdown, or found by the reaper after a crash), a
// job that is never run (tampered, unknown) and a job the license lock cancels. It lets the work a job stood for be
// closed together with the job, also when the handler never got to do it (the job's worker died). It runs in a
// savepoint: an error or a panic is logged by type and rolled back alone, and the job ends anyway (the hook's own
// backstop, for example a periodic sweep, must close what the hook could not).
type EndHook func(ctx context.Context, tx pgx.Tx, end JobEnd) error

// Runner claims and runs queued jobs (spec §8.1, §8.4, §8.5, §8.8).
type Runner struct {
	cfg      RunnerConfig
	mu       sync.Mutex
	handlers map[string]HandlerFunc
	endHooks map[string]EndHook
	stopping atomic.Bool // Run is shutting down: interrupted jobs are released, not failed

	sweepMu   sync.Mutex
	lastSweep time.Time // the last lock-mode sweep (sweepIfDue)
}

const (
	baseBackoff = 30 * time.Second
	maxBackoff  = 30 * time.Minute
)

// Backoff is the wait before the next attempt (spec §8.4): min(30 s · 2^(attempt-1), 30 min)
// times (1 + jitter), jitter clamped to ±20 %.
func Backoff(attempt int, jitter float64) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := maxBackoff
	if attempt <= 7 { // 30 s · 2^6 = 32 min is already above the cap
		d = min(baseBackoff<<(attempt-1), maxBackoff)
	}
	jitter = max(-0.2, min(0.2, jitter))
	return time.Duration(float64(d) * (1 + jitter))
}

func cryptoJitter() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	u := float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53) // [0, 1)
	return u*0.4 - 0.2
}

func defaultWorkerID() string {
	host, err := os.Hostname()
	if err != nil {
		host = "alice"
	}
	return host + "-" + strconv.Itoa(os.Getpid()) + "-" + rand.Text()[:8]
}

// NewRunner applies the defaults of RunnerConfig. It panics on a WorkerID that contains "/":
// claim tokens are "<WorkerID>/<uuid>" and the shutdown finds its own claims by that prefix.
func NewRunner(c RunnerConfig) *Runner {
	if c.Workers <= 0 {
		c.Workers = 8
	}
	if c.WorkerID == "" {
		c.WorkerID = defaultWorkerID()
	}
	if strings.Contains(c.WorkerID, "/") {
		panic(fmt.Sprintf("jobs: worker id %q must not contain %q", c.WorkerID, "/"))
	}
	for _, d := range []struct {
		v   *time.Duration
		def time.Duration
	}{{&c.Lease, 45 * time.Second}, {&c.Heartbeat, 15 * time.Second}, {&c.Poll, time.Second},
		{&c.ReapEvery, time.Minute}, {&c.ShutdownGrace, time.Minute}} {
		if *d.v <= 0 {
			*d.v = d.def
		}
	}
	if c.Jitter == nil {
		c.Jitter = cryptoJitter
	}
	if c.Log == nil {
		c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Runner{cfg: c, handlers: map[string]HandlerFunc{}, endHooks: map[string]EndHook{}}
}

// Handle installs the handler of a job type. It panics for a type that is not registered (with
// the same class) or that already has a handler.
func (r *Runner) Handle(t Type, h HandlerFunc) {
	reg, ok := lookup(t.Name)
	if !ok || reg != t || h == nil {
		panic(fmt.Sprintf("jobs: handler for unregistered job type %q", t.Name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.handlers[t.Name]; dup {
		panic(fmt.Sprintf("jobs: job type %q has two handlers", t.Name))
	}
	r.handlers[t.Name] = h
}

// OnEnd installs the end hook of a job type (EndHook). It panics for a type that is not registered (with the same
// class), a nil hook or a second hook.
func (r *Runner) OnEnd(t Type, h EndHook) {
	reg, ok := lookup(t.Name)
	if !ok || reg != t || h == nil {
		panic(fmt.Sprintf("jobs: end hook for unregistered job type %q", t.Name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.endHooks[t.Name]; dup {
		panic(fmt.Sprintf("jobs: job type %q has two end hooks", t.Name))
	}
	r.endHooks[t.Name] = h
}

// ended runs the end hook of typ, if any, in a savepoint of tx (EndHook).
func (r *Runner) ended(ctx context.Context, tx pgx.Tx, typ string, end JobEnd) {
	r.mu.Lock()
	h := r.endHooks[typ]
	r.mu.Unlock()
	if h == nil {
		return
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		r.cfg.Log.Error("job end hook failed", "job_id", end.ID.String(), "job_type", typ, "error_type", fmt.Sprintf("%T", err))
		return
	}
	err = func() (err error) {
		defer func() {
			if p := recover(); p != nil { // the value is not logged: it may hold data from the job
				err = errors.New("jobs: end hook panicked")
			}
		}()
		return h(ctx, sp, end)
	}()
	if err == nil {
		err = sp.Commit(ctx)
	}
	if err != nil {
		_ = sp.Rollback(ctx)
		r.cfg.Log.Error("job end hook failed", "job_id", end.ID.String(), "job_type", typ, "error_type", fmt.Sprintf("%T", err))
	}
}

// endedBy runs the end hook after a settle statement that ended c with status and reason, when it matched c's row.
func (r *Runner) endedBy(ctx context.Context, tx pgx.Tx, c *claimed, status Status, reason string, tag pgconn.CommandTag,
	err error) (pgconn.CommandTag, error) {
	if err == nil && tag.RowsAffected() == 1 {
		r.ended(ctx, tx, c.typ, JobEnd{ID: c.id, Status: status, Reason: reason})
	}
	return tag, err
}

func (r *Runner) handler(name string) HandlerFunc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.handlers[name]
}

// Handles reports whether the runner has a handler for t. It claims only such jobs, so a job of a
// type without a handler stays queued; serve refuses to start with one (cmd/alice checkWiring).
func (r *Runner) Handles(t Type) bool {
	reg, ok := lookup(t.Name)
	return ok && reg == t && r.handler(t.Name) != nil
}

// handled returns the job types this runner can run; it never claims others.
func (r *Runner) handled() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.handlers))
	for name := range r.handlers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (r *Runner) jobEvent(action string, result audit.Result, id uuid.UUID, details map[string]string) audit.Event {
	return audit.Event{Actor: jobsActor, Action: action, ObjectType: "job", ObjectID: id.String(), Result: result, Details: details}
}

// claimed is a job this worker holds the lease of.
type claimed struct {
	id          uuid.UUID
	token       string // this claim's lease owner: "<WorkerID>/<uuid>", in jobs.locked_by and target_locks.locked_by
	typ         string
	kind        string
	payload     []byte
	mac         []byte
	target      uuid.UUID
	attempts    int // after the claim: this run's attempt number
	maxAttempts int
	leaseUntil  time.Time // when the lease the claim took ends (the heartbeat extends it)
	createdBy   uuid.UUID
	role        string
}

// mine is the WHERE clause that makes a job update apply only to this claim of the job: its
// token and attempt number, while it runs. A run whose lease expired and whose job was claimed
// again (even by the same process) matches nothing. Its parameters are $1..$3 (fence); the
// statement's own parameters start at $4.
const mine = `WHERE id = $1 AND locked_by = $2 AND attempts = $3 AND status = 'running'`

// fence returns the parameters of mine followed by args.
func (c *claimed) fence(args ...any) []any {
	return append([]any{c.id, c.token, c.attempts}, args...)
}

var allClasses = []string{license.ClassAlways.String(), license.ClassReadOnly.String(), license.ClassChange.String()}

// maxCandidates bounds how many busy-target jobs one claim skips before it gives up.
const maxCandidates = 10

// claim takes the next due job in one transaction: the job row (SKIP LOCKED), the target lock
// and the attempt row commit together, so a target never runs two jobs. An expired target lock
// is taken over only when no job of that target is running any more, i.e. after the reaper
// re-queued it (§8.1). In lock it first moves queued external-change jobs to blocked_license and
// cancels queued read-only jobs (§8.6, in a transaction of its own), then claims only
// always-class work. While the license cannot be verified (license.ErrUnverified) or its lock is
// only due by the gate's own clock (license.ErrLockDue, AUD-02) it claims only always-class work
// and leaves the rest queued: no evaluation decided a lock, so nothing is held or cancelled, and
// the queued work starts by itself once an evaluation allows it (or is held then, if the
// evaluation confirms the lock).
func (r *Runner) claim(ctx context.Context) (*claimed, error) {
	types := r.handled()
	if len(types) == 0 {
		return nil, nil
	}
	now := r.cfg.Clock.Now().UTC()
	classes := allClasses
	if gate := r.cfg.Gate.Allow(license.ClassChange); errors.Is(gate, license.ErrLocked) {
		if license.ConfirmedLock(gate) {
			r.sweepIfDue(ctx, now)
		}
		classes = []string{license.ClassAlways.String()}
	}
	capTypes, capMax := capTable()
	var c *claimed
	err := db.InTx(ctx, r.cfg.Pool, func(tx pgx.Tx) error {
		skip := []uuid.UUID{} // never nil: ANY(NULL) would exclude every row
		for range maxCandidates {
			var (
				cand             claimed
				target, by       *uuid.UUID
				attempts, maxAtt int
			)
			err := tx.QueryRow(ctx, `SELECT id, type, kind, payload, payload_mac, target_id, attempts, max_attempts, created_by, created_by_role
FROM jobs j
WHERE status = 'queued' AND run_at <= $1 AND class = ANY($2) AND type = ANY($3) AND NOT (id = ANY($4::uuid[]))
  AND attempts < max_attempts
  AND NOT EXISTS (SELECT 1 FROM unnest($5::text[], $6::int[]) AS cap(type, max_running)
                  WHERE cap.type = j.type AND (SELECT count(*) FROM jobs o WHERE o.type = cap.type AND o.status = 'running') >= cap.max_running)
  AND (target_id IS NULL OR (
        NOT EXISTS (SELECT 1 FROM target_locks l WHERE l.target_id = j.target_id AND l.lease_until > $1)
    AND NOT EXISTS (SELECT 1 FROM jobs o WHERE o.target_id = j.target_id AND o.status = 'running')))
ORDER BY priority, run_at, id
FOR UPDATE SKIP LOCKED
LIMIT 1`, now, classes, types, skip, capTypes, capMax).Scan(&cand.id, &cand.typ, &cand.kind, &cand.payload, &cand.mac, &target,
				&attempts, &maxAtt, &by, &cand.role)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("jobs: select a job: %w", err)
			}
			if limit, capped := maxRunning[cand.typ]; capped {
				// Two claims can both have seen a free place: the count is taken again under a lock per
				// type, so the cap holds across workers and processes (the winner's running row is
				// committed before the next claim of the type gets the lock).
				full, err := capFull(ctx, tx, cand.typ, limit)
				if err != nil {
					return err
				}
				if full {
					skip = append(skip, cand.id)
					continue
				}
			}
			cand.token = r.cfg.WorkerID + "/" + uuid.Must(uuid.NewV7()).String()
			if target != nil {
				cand.target = *target
				var got uuid.UUID
				err := tx.QueryRow(ctx, `INSERT INTO target_locks (target_id, job_id, operation, locked_by, heartbeat_at, lease_until)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (target_id) DO UPDATE SET job_id = EXCLUDED.job_id, operation = EXCLUDED.operation,
    locked_by = EXCLUDED.locked_by, heartbeat_at = EXCLUDED.heartbeat_at, lease_until = EXCLUDED.lease_until
WHERE target_locks.lease_until <= $5
  AND NOT EXISTS (SELECT 1 FROM jobs o WHERE o.target_id = target_locks.target_id AND o.status = 'running')
RETURNING target_id`, cand.target, cand.id, cand.typ, cand.token, now, now.Add(r.cfg.Lease)).Scan(&got)
				if errors.Is(err, pgx.ErrNoRows) {
					skip = append(skip, cand.id) // another job holds the target (§12.5)
					continue
				}
				if err != nil {
					return fmt.Errorf("jobs: lock the target: %w", err)
				}
			}
			if by != nil {
				cand.createdBy = *by
			}
			if _, err := tx.Exec(ctx, `UPDATE jobs SET status = 'running', locked_by = $2, locked_until = $3, heartbeat_at = $4,
    attempts = attempts + 1, started_at = coalesce(started_at, $4)
WHERE id = $1`, cand.id, cand.token, now.Add(r.cfg.Lease), now); err != nil {
				return fmt.Errorf("jobs: mark running: %w", err)
			}
			cand.attempts, cand.maxAttempts, cand.leaseUntil = attempts+1, maxAtt, now.Add(r.cfg.Lease)
			if _, err := tx.Exec(ctx, `INSERT INTO job_attempts (id, job_id, attempt, worker_id, started_at) VALUES ($1, $2, $3, $4, $5)`,
				uuid.Must(uuid.NewV7()), cand.id, cand.attempts, cand.token, now); err != nil {
				return fmt.Errorf("jobs: record the attempt: %w", err)
			}
			c = &cand
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// capTable is maxRunning as the two arrays the claim query takes.
func capTable() ([]string, []int) {
	types, limits := []string{}, []int{}
	for t, n := range maxRunning {
		types, limits = append(types, t), append(limits, n)
	}
	return types, limits
}

// capFull takes the type's claim lock for the rest of the transaction and reports whether limit jobs of the
// type are running.
func capFull(ctx context.Context, tx pgx.Tx, typ string, limit int) (bool, error) {
	var running int
	if err := tx.QueryRow(ctx, `SELECT pg_advisory_xact_lock(hashtext('jobs.claim.cap.' || $1::text))`, typ).Scan(new(any)); err != nil {
		return false, fmt.Errorf("jobs: lock the claims of %s: %w", typ, err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE type = $1 AND status = 'running'", typ).Scan(&running); err != nil {
		return false, fmt.Errorf("jobs: count the running %s jobs: %w", typ, err)
	}
	return running >= limit, nil
}

// sweepIfDue runs the lock-mode sweep at most once per Poll interval for the whole runner (not
// once per worker). A failed sweep is logged; always-class work is still claimed.
func (r *Runner) sweepIfDue(ctx context.Context, now time.Time) {
	r.sweepMu.Lock()
	if !sweepDue(r.lastSweep, now, r.cfg.Poll) {
		r.sweepMu.Unlock()
		return
	}
	r.lastSweep = now
	r.sweepMu.Unlock()
	if err := r.sweepLocked(ctx, now); err != nil && ctx.Err() == nil {
		r.cfg.Log.Error("holding queued work in lock failed", "error_type", fmt.Sprintf("%T", err))
	}
}

// sweepDue says whether the lock sweep may run again: never swept, the last sweep is at least one poll interval ago, or
// it lies in the future (the clock was set back): a future sweep never counts as recent, or work would not be held
// until the clock caught up with it.
func sweepDue(last, now time.Time, poll time.Duration) bool {
	return last.IsZero() || now.Sub(last) >= poll || now.Before(last)
}

// sweepLocked holds queued external-change work for an Administrator's confirmation and
// cancels queued read-only work while the license is expired (spec §8.6, R29, L-81); each held
// job is audited job.blocked_license and each cancelled one job.cancelled_license. The audit
// rows are the transaction's last statements: the chain lock is held as briefly as possible.
func (r *Runner) sweepLocked(ctx context.Context, now time.Time) error {
	return db.InTx(ctx, r.cfg.Pool, func(tx pgx.Tx) error {
		cancelled, err := touched(ctx, tx, `UPDATE jobs SET status = 'cancelled', last_error_code = 'license.locked', finished_at = $1
WHERE status = 'queued' AND class = 'read_only' RETURNING id, type`, now)
		if err != nil {
			return fmt.Errorf("jobs: cancel read-only work in lock: %w", err)
		}
		blocked, err := touched(ctx, tx, `UPDATE jobs SET status = 'blocked_license' WHERE status = 'queued' AND class = 'change' RETURNING id, type`)
		if err != nil {
			return fmt.Errorf("jobs: hold changes in lock: %w", err)
		}
		for _, h := range cancelled {
			r.ended(ctx, tx, h.typ, JobEnd{ID: h.id, Status: StatusCancelled, Reason: "license.locked"})
		}
		for _, h := range cancelled {
			if _, err := r.cfg.Audit.Append(ctx, tx, r.jobEvent("job.cancelled_license", audit.Denied, h.id, map[string]string{"type": h.typ})); err != nil {
				return err
			}
		}
		for _, h := range blocked {
			if _, err := r.cfg.Audit.Append(ctx, tx, r.jobEvent("job.blocked_license", audit.Denied, h.id, map[string]string{"type": h.typ})); err != nil {
				return err
			}
		}
		return nil
	})
}

// heldJob is a job the lock-mode sweep cancelled or held.
type heldJob struct {
	id  uuid.UUID
	typ string
}

// touched runs an UPDATE that RETURNs id, type and collects the rows.
func touched(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]heldJob, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []heldJob
	for rows.Next() {
		var h heldJob
		if err := rows.Scan(&h.id, &h.typ); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

var errLeaseLost = errors.New("jobs: the lease was lost")

// settle ends this claim of c in one transaction: set changes the job row (its WHERE is mine,
// so it matches only while this claim still holds the job), then the attempt is closed, this
// claim's target lock released and the audit events written. It reports false when the lease
// was lost: another claim or the reaper owns the job now, and nothing is written.
func (r *Runner) settle(ctx context.Context, c *claimed, errorCode string,
	set func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error), events ...audit.Event) bool {
	err := db.InTx(ctx, r.cfg.Pool, func(tx pgx.Tx) error {
		now := r.cfg.Clock.Now().UTC()
		tag, err := set(tx, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errLeaseLost
		}
		if _, err := tx.Exec(ctx, `UPDATE job_attempts SET finished_at = $3, error_code = $4 WHERE job_id = $1 AND attempt = $2`,
			c.id, c.attempts, now, errorCode); err != nil {
			return fmt.Errorf("jobs: close the attempt: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM target_locks WHERE job_id = $1 AND locked_by = $2`, c.id, c.token); err != nil {
			return fmt.Errorf("jobs: release the target: %w", err)
		}
		for _, ev := range events {
			var err error
			switch ev.Action {
			case "job.dead":
				if ev.Details["shutdown"] == "true" || !alertsWhenDead(c.typ) {
					// Killed by this process's own shutdown (release), or a type whose death is
					// announced elsewhere: audited, not mailed.
					continue
				}
				err = r.alert(ctx, tx, TemplateJobDead, deadAlertParams(c.id, c.typ, ev.Details["reason"], c.attempts))
			case "job.tampered":
				err = r.alert(ctx, tx, TemplateJobTampered, tamperedAlertParams(c.id, c.typ))
			}
			if err != nil {
				return err
			}
		}
		for _, ev := range events {
			if _, err := r.cfg.Audit.Append(ctx, tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, errLeaseLost):
		r.cfg.Log.Warn("job lease lost before the job finished; another worker owns it now", "job_id", c.id.String(), "job_type", c.typ)
		return false
	case err != nil:
		r.cfg.Log.Error("could not record the end of a job", "job_id", c.id.String(), "job_type", c.typ, "error_type", fmt.Sprintf("%T", err))
		return false
	}
	return true
}

// terminate ends c without running it (unknown type, tampered payload, unclassified type).
func (r *Runner) terminate(ctx context.Context, c *claimed, reason, action string) {
	r.settle(ctx, c, reason, func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
		tag, err := tx.Exec(ctx, `UPDATE jobs SET status = 'dead', last_error_code = $4, finished_at = $5, locked_by = NULL,
    locked_until = NULL `+mine, c.fence(reason, now)...)
		return r.endedBy(ctx, tx, c, StatusDead, reason, tag, err)
	}, r.jobEvent(action, audit.Failure, c.id, map[string]string{"type": c.typ, "reason": reason, "attempt": strconv.Itoa(c.attempts)}))
}

// revert undoes a claim the gate refused after it was taken (the lock began in between). The
// refused claim is not an attempt: its attempt row is removed and the counter restored, so a
// confirmed job later starts with the same attempt number.
func (r *Runner) revert(ctx context.Context, c *claimed, t Type) {
	unclaim := func(tx pgx.Tx, tag pgconn.CommandTag, err error) (pgconn.CommandTag, error) {
		if err != nil || tag.RowsAffected() != 1 {
			return tag, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM job_attempts WHERE job_id = $1 AND attempt = $2`, c.id, c.attempts); err != nil {
			return tag, fmt.Errorf("jobs: drop the refused attempt: %w", err)
		}
		return tag, nil
	}
	if t.Class == license.ClassChange {
		r.settle(ctx, c, "license.locked", func(tx pgx.Tx, _ time.Time) (pgconn.CommandTag, error) {
			tag, err := tx.Exec(ctx, `UPDATE jobs SET status = 'blocked_license', attempts = attempts - 1, locked_by = NULL,
    locked_until = NULL `+mine, c.fence()...)
			return unclaim(tx, tag, err)
		}, r.jobEvent("job.blocked_license", audit.Denied, c.id, map[string]string{"type": c.typ}))
		return
	}
	r.settle(ctx, c, "license.locked", func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
		tag, err := tx.Exec(ctx, `UPDATE jobs SET status = 'cancelled', last_error_code = 'license.locked', finished_at = $4,
    attempts = attempts - 1, locked_by = NULL, locked_until = NULL `+mine, c.fence(now)...)
		tag, err = unclaim(tx, tag, err)
		return r.endedBy(ctx, tx, c, StatusCancelled, "license.locked", tag, err)
	}, r.jobEvent("job.cancelled_license", audit.Denied, c.id, map[string]string{"type": c.typ}))
}

// requeue undoes a claim the gate refused without a confirmed lock (license.ErrUnverified or
// license.ErrLockDue, AUD-02): the job is queued again as it was (the refused claim is not an
// attempt) and starts once an evaluation allows it. Nothing is audited: no decision was made.
func (r *Runner) requeue(ctx context.Context, c *claimed) {
	r.settle(ctx, c, "license.unverified", func(tx pgx.Tx, _ time.Time) (pgconn.CommandTag, error) {
		tag, err := tx.Exec(ctx, `UPDATE jobs SET status = 'queued', attempts = attempts - 1, locked_by = NULL,
    locked_until = NULL `+mine, c.fence()...)
		if err != nil || tag.RowsAffected() != 1 {
			return tag, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM job_attempts WHERE job_id = $1 AND attempt = $2`, c.id, c.attempts); err != nil {
			return tag, fmt.Errorf("jobs: drop the refused attempt: %w", err)
		}
		return tag, nil
	})
}

// stepLog collects a job's steps for its result.
type stepLog struct {
	mu    sync.Mutex
	steps []map[string]any
}

func (s *stepLog) Step(name string, status providers.StepStatus, params map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if params == nil {
		params = map[string]string{}
	}
	s.steps = append(s.steps, map[string]any{"name": name, "status": string(status), "params": params})
}

func (s *stepLog) list() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.steps...)
}

// call runs the handler; a panic becomes a retryable failure and its value is never logged
// (it may hold data from the job).
func (r *Runner) call(ctx context.Context, h HandlerFunc, j Job, steps StepRecorder) (res map[string]any, err error) {
	defer func() {
		if p := recover(); p != nil {
			r.cfg.Log.Error("job handler panicked", "job_id", j.ID.String(), "job_type", j.Type.Name)
			res, err = nil, Retry("internal.unexpected", nil, errors.New("jobs: handler panicked"))
		}
	}()
	return h(ctx, j, steps)
}

// beat extends this claim's job lease and target lock in one transaction. It returns
// errLeaseLost when either no longer belongs to this claim.
func (r *Runner) beat(ctx context.Context, c *claimed) error {
	return db.InTx(ctx, r.cfg.Pool, func(tx pgx.Tx) error {
		now := r.cfg.Clock.Now().UTC()
		tag, err := tx.Exec(ctx, `UPDATE jobs SET locked_until = $4, heartbeat_at = $5 `+mine, c.fence(now.Add(r.cfg.Lease), now)...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errLeaseLost
		}
		if c.target == uuid.Nil {
			return nil
		}
		tag, err = tx.Exec(ctx, `UPDATE target_locks SET heartbeat_at = $3, lease_until = $4 WHERE job_id = $1 AND locked_by = $2`,
			c.id, c.token, now, now.Add(r.cfg.Lease))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errLeaseLost
		}
		return nil
	})
}

// heartbeat extends the lease every Heartbeat until stop is called. When the job row or the
// target lock is no longer this claim's (the reaper took it), it sets lost and cancels the
// handler's context. It does the same when beats keep failing (the database cannot be reached)
// and the next beat would come after the lease ends: from then on another process may reap the
// job and run it again, so this run must stop its work on the server.
func (r *Runner) heartbeat(c *claimed, cancel context.CancelFunc, lost *atomic.Bool) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := r.cfg.Clock.NewTicker(r.cfg.Heartbeat)
		defer t.Stop()
		leaseUntil := c.leaseUntil
		for {
			select {
			case <-done:
				return
			case <-t.C():
				now := r.cfg.Clock.Now()
				ctx, cancelBeat := context.WithTimeout(context.Background(), 5*time.Second)
				err := r.beat(ctx, c)
				cancelBeat()
				switch {
				case err == nil:
					leaseUntil = now.Add(r.cfg.Lease) // the beat's own time is later: this end is on the safe side
					continue
				case errors.Is(err, errLeaseLost):
					r.cfg.Log.Warn("job lease lost; stopping the handler", "job_id", c.id.String(), "job_type", c.typ)
				case !r.cfg.Clock.Now().Add(r.cfg.Heartbeat).Before(leaseUntil):
					r.cfg.Log.Warn("job heartbeats keep failing and the lease is about to end; stopping the handler",
						"job_id", c.id.String(), "job_type", c.typ, "error_type", fmt.Sprintf("%T", err))
				default:
					r.cfg.Log.Warn("job heartbeat failed", "job_id", c.id.String(), "error_type", fmt.Sprintf("%T", err))
					continue
				}
				lost.Store(true)
				cancel()
				return
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
	}
}

// execute checks a claimed job (payload MAC, type, gate) and runs it.
func (r *Runner) execute(jobCtx context.Context, c *claimed) {
	ctx := context.WithoutCancel(jobCtx) // bookkeeping finishes even while shutting down
	t, ok := lookup(c.typ)
	if !ok {
		r.terminate(ctx, c, "job.unknown_type", "job.dead")
		return
	}
	var payload map[string]string
	if err := json.Unmarshal(c.payload, &payload); err != nil ||
		!hmac.Equal(c.mac, r.cfg.Queue.mac(c.id, c.typ, c.kind, c.target, canonicalPayload(payload), c.createdBy, c.role, c.maxAttempts)) {
		r.cfg.Log.Error("job payload does not match its MAC; the job is not run", "job_id", c.id.String(), "job_type", c.typ)
		r.terminate(ctx, c, "job.tampered", "job.tampered")
		return
	}
	if err := r.cfg.Gate.Allow(t.Class); err != nil {
		switch {
		case license.ConfirmedLock(err):
			r.revert(ctx, c, t)
		case errors.Is(err, license.ErrLocked): // unverified or lock due: no lock was decided
			r.requeue(ctx, c)
		default:
			r.terminate(ctx, c, "license.unclassified", "job.dead")
		}
		return
	}
	h := r.handler(c.typ)
	if h == nil { // claim only selects handled types; a handler is never removed
		r.terminate(ctx, c, "job.unknown_type", "job.dead")
		return
	}
	j := Job{ID: c.id, Type: t, Kind: Kind(c.kind), TargetID: c.target, Payload: payload, Attempt: c.attempts,
		MaxAttempts: c.maxAttempts, CreatedBy: c.createdBy, CreatedByRole: c.role}
	hctx, cancel := context.WithCancel(jobCtx)
	var lost atomic.Bool
	stop := r.heartbeat(c, cancel, &lost)
	steps := &stepLog{}
	res, err := r.call(hctx, h, j, steps)
	stop()
	cancel()
	if lost.Load() {
		r.release(ctx, c, false, retryWait(err)) // writes nothing when the job row is no longer this claim's
		return
	}
	r.finish(ctx, jobCtx, c, res, steps.list(), err)
}

func encodeResult(res map[string]any, steps []map[string]any, f *Failure) (string, error) {
	out := map[string]any{}
	for k, v := range res {
		out[k] = v
	}
	if len(steps) > 0 {
		out["steps"] = steps
	}
	if f != nil {
		if len(f.Params) > 0 {
			out["error_params"] = f.Params
		}
		if f.Class == NeedsAttention {
			out["needs_attention"] = true
		}
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// finish records the outcome of a run (spec §8.4).
func (r *Runner) finish(ctx, jobCtx context.Context, c *claimed, res map[string]any, steps []map[string]any, err error) {
	if err == nil {
		result, encErr := encodeResult(res, steps, nil)
		if encErr != nil {
			err = Retry("internal.unexpected", nil, encErr)
		} else {
			r.settle(ctx, c, "", func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
				return tx.Exec(ctx, `UPDATE jobs SET status = 'succeeded', result = $4::jsonb, last_error_code = '', finished_at = $5,
    locked_by = NULL, locked_until = NULL `+mine, c.fence(result, now)...)
			})
			return
		}
	}
	if r.stopping.Load() && jobCtx.Err() != nil {
		r.release(ctx, c, true, retryWait(err)) // interrupted by the shutdown: it runs again after the restart (§8.8)
		return
	}
	f := classify(err)
	if f.Reason == "internal.unexpected" {
		r.cfg.Log.Error("job failed unexpectedly", "job_id", c.id.String(), "job_type", c.typ, "error_type", fmt.Sprintf("%T", errors.Unwrap(f)))
	}
	result, encErr := encodeResult(res, steps, f)
	if encErr != nil {
		result = `{}`
	}
	t, _ := lookup(c.typ)
	switch {
	case f.Class == Retryable && c.attempts < c.maxAttempts:
		next := max(Backoff(c.attempts, r.cfg.Jitter()), retryWait(f))
		r.settle(ctx, c, f.Reason, func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
			return tx.Exec(ctx, `UPDATE jobs SET status = 'queued', run_at = $4, last_error_code = $5, result = $6::jsonb,
    locked_by = NULL, locked_until = NULL `+mine, c.fence(now.Add(next), f.Reason, result)...)
		})
	case f.Class == Retryable && AlertsWhenExhausted(t):
		r.settle(ctx, c, f.Reason, func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
			tag, err := tx.Exec(ctx, `UPDATE jobs SET status = 'dead', last_error_code = $4, result = $5::jsonb, finished_at = $6,
    locked_by = NULL, locked_until = NULL `+mine, c.fence(f.Reason, result, now)...)
			return r.endedBy(ctx, tx, c, StatusDead, f.Reason, tag, err)
		}, r.jobEvent("job.dead", audit.Failure, c.id, map[string]string{"type": c.typ, "reason": f.Reason, "attempt": strconv.Itoa(c.attempts)}))
	default:
		r.settle(ctx, c, f.Reason, func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
			tag, err := tx.Exec(ctx, `UPDATE jobs SET status = 'failed', last_error_code = $4, result = $5::jsonb, finished_at = $6,
    locked_by = NULL, locked_until = NULL `+mine, c.fence(f.Reason, result, now)...)
			return r.endedBy(ctx, tx, c, StatusFailed, f.Reason, tag, err)
		})
	}
}

// release hands an unfinished run back (graceful shutdown, lost target lock). The attempt
// counts, as with an expired lease (R37 item 20): a job without attempts left is dead. A job
// killed by this process's own shutdown is audited (detail shutdown=true) but not mailed: the
// Administrators restarted Alice themselves, and a connection test (one attempt) interrupted by
// every restart must not raise an alert. after is the handler's own least wait (RetryAfter, S3): the
// job runs again no sooner (a reaper that takes a job back cannot know it).
func (r *Runner) release(ctx context.Context, c *claimed, shutdown bool, after time.Duration) {
	if c.attempts >= c.maxAttempts {
		details := map[string]string{"type": c.typ, "reason": "job.lease_expired", "attempt": strconv.Itoa(c.attempts)}
		if shutdown {
			details["shutdown"] = "true"
		}
		r.settle(ctx, c, "job.lease_expired", func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
			tag, err := tx.Exec(ctx, `UPDATE jobs SET status = 'dead', last_error_code = 'job.lease_expired', finished_at = $4,
    locked_by = NULL, locked_until = NULL `+mine, c.fence(now)...)
			return r.endedBy(ctx, tx, c, StatusDead, "job.lease_expired", tag, err)
		}, r.jobEvent("job.dead", audit.Failure, c.id, details))
		return
	}
	r.settle(ctx, c, "job.lease_expired", func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
		return tx.Exec(ctx, `UPDATE jobs SET status = 'queued', run_at = $4, last_error_code = 'job.lease_expired',
    locked_by = NULL, locked_until = NULL `+mine, c.fence(now.Add(after))...)
	})
}

// retryWait is the least wait a handler's error asks for (RetryAfter), at most the longest backoff.
func retryWait(err error) time.Duration {
	var f *Failure
	if !errors.As(err, &f) || f.Class != Retryable {
		return 0
	}
	return min(max(f.After, 0), maxBackoff)
}

// RunOnce claims and runs one due job. It reports false when none was due.
func (r *Runner) RunOnce(ctx context.Context) (bool, error) { return r.runOnce(ctx, ctx) }

func (r *Runner) runOnce(claimCtx, jobCtx context.Context) (bool, error) {
	c, err := r.claim(claimCtx)
	if err != nil || c == nil {
		return false, err
	}
	r.execute(jobCtx, c)
	return true, nil
}

// requeued is a job that the reaper or the shutdown took back from its worker.
type requeued struct {
	id       uuid.UUID
	typ      string
	attempts int
	status   string
}

// takeBack re-queues (or, without attempts left, kills) the running jobs that the UPDATE in sql
// selects, closes their attempts, releases their target locks and audits them last.
// sql's parameters are $1 = now plus args; it must RETURN id, type, attempts, status. shutdown
// says that this process's own shutdown takes them back: a killed job is then audited with
// shutdown=true and not mailed (see release).
func (r *Runner) takeBack(ctx context.Context, tx pgx.Tx, now time.Time, shutdown bool, sql string, args ...any) ([]requeued, error) {
	rows, err := tx.Query(ctx, sql, append([]any{now}, args...)...)
	if err != nil {
		return nil, err
	}
	var all []requeued
	for rows.Next() {
		var x requeued
		if err := rows.Scan(&x.id, &x.typ, &x.attempts, &x.status); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(all))
	for _, x := range all {
		ids = append(ids, x.id)
	}
	if _, err := tx.Exec(ctx, `UPDATE job_attempts SET finished_at = $2, error_code = 'job.lease_expired'
WHERE job_id = ANY($1::uuid[]) AND finished_at IS NULL`, ids, now); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM target_locks WHERE job_id = ANY($1::uuid[])`, ids); err != nil {
		return nil, err
	}
	for _, x := range all {
		if x.status == string(StatusDead) {
			r.ended(ctx, tx, x.typ, JobEnd{ID: x.id, Status: StatusDead, Reason: "job.lease_expired"})
		}
	}
	for _, x := range all {
		if x.status == string(StatusDead) && !shutdown && alertsWhenDead(x.typ) {
			if err := r.alert(ctx, tx, TemplateJobDead, deadAlertParams(x.id, x.typ, "job.lease_expired", x.attempts)); err != nil {
				return nil, err
			}
		}
	}
	// The audit rows come last: the chain lock is held as briefly as possible.
	for _, x := range all {
		details := map[string]string{"type": x.typ, "attempt": strconv.Itoa(x.attempts), "reason": "job.lease_expired"}
		action, result := "job.recovered", audit.Success
		if x.status == string(StatusDead) {
			action, result = "job.dead", audit.Failure
			if shutdown {
				details["shutdown"] = "true"
			}
		}
		if _, err := r.cfg.Audit.Append(ctx, tx, r.jobEvent(action, result, x.id, details)); err != nil {
			return nil, err
		}
	}
	return all, nil
}

// takeBackSet is the SET list shared by Reap and releaseAll: re-queue, or dead without attempts left.
const takeBackSet = `UPDATE jobs SET
    status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
    finished_at = CASE WHEN attempts >= max_attempts THEN $1::timestamptz ELSE NULL END,
    locked_by = NULL, locked_until = NULL, run_at = $1, last_error_code = 'job.lease_expired'
`

// Reap re-queues jobs whose lease expired (their worker stopped: crash, kill, lost database
// connection; spec §8.8). The attempt that was cut off counts; a job without attempts left is
// dead. Expired target locks are released.
//
// Row locks are taken in the order every other writer uses (claim, beat, settle): jobs first,
// then target_locks, so a reaper and a worker cannot deadlock.
func (r *Runner) Reap(ctx context.Context) (int, error) {
	n := 0
	err := db.InTx(ctx, r.cfg.Pool, func(tx pgx.Tx) error {
		now := r.cfg.Clock.Now().UTC()
		// takeBack also deletes the target locks of the jobs it takes back.
		all, err := r.takeBack(ctx, tx, now, false, takeBackSet+`WHERE status = 'running' AND locked_until < $1
RETURNING id, type, attempts, status`)
		if err != nil {
			return fmt.Errorf("jobs: reap: %w", err)
		}
		n = len(all)
		// Then the remaining expired target locks whose job no longer runs.
		if _, err := tx.Exec(ctx, `DELETE FROM target_locks l WHERE lease_until < $1
  AND NOT EXISTS (SELECT 1 FROM jobs o WHERE o.id = l.job_id AND o.status = 'running' AND o.locked_until >= $1)`, now); err != nil {
			return fmt.Errorf("jobs: release expired target locks: %w", err)
		}
		return nil
	})
	return n, err
}

// Recover is the startup pass of spec §8.8: before the workers start, jobs whose lease expired
// are re-queued. Leases that have not expired may belong to a live process (F-69) and are left
// to the reaper. Run calls it before it starts its workers; calling it before Run as well is
// harmless (a second pass finds nothing).
func (r *Runner) Recover(ctx context.Context) (int, error) {
	n, err := r.Reap(ctx)
	if err == nil && n > 0 {
		r.cfg.Log.Info("recovered jobs whose worker stopped", "count", n)
	}
	return n, err
}

// Run first runs Recover (spec §8.8: before any worker starts), then Workers workers and the
// reaper until ctx ends. Then it stops claiming and gives running jobs ShutdownGrace in total:
// the first half to finish on their own; then they are cancelled and get the second half to
// return. Jobs that still have not returned are handed back (re-queued, or dead without
// attempts left), so they resume after a restart.
func (r *Runner) Run(ctx context.Context) {
	if _, err := r.Recover(ctx); err != nil && ctx.Err() == nil {
		// Not fatal: the reaper repeats the pass every ReapEvery.
		r.cfg.Log.Error("recovering jobs of stopped workers failed", "error_type", fmt.Sprintf("%T", err))
	}
	jobsCtx, cancelJobs := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelJobs()
	var workers sync.WaitGroup
	for range r.cfg.Workers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ctx.Err() == nil {
				ran, err := r.runOnce(ctx, jobsCtx)
				if err != nil && ctx.Err() == nil {
					r.cfg.Log.Error("claiming a job failed", "error_type", fmt.Sprintf("%T", err))
				}
				if !ran {
					select {
					case <-ctx.Done():
					case <-r.cfg.Clock.After(r.cfg.Poll):
					}
				}
			}
		}()
	}
	reaperDone := make(chan struct{})
	go func() {
		defer close(reaperDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.cfg.Clock.After(r.cfg.ReapEvery):
				if _, err := r.Reap(ctx); err != nil && ctx.Err() == nil {
					r.cfg.Log.Error("reaping expired job leases failed", "error_type", fmt.Sprintf("%T", err))
				}
			}
		}
	}()
	<-ctx.Done()
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	deadline := r.cfg.Clock.After(r.cfg.ShutdownGrace)
	select {
	case <-done:
	case <-r.cfg.Clock.After(r.cfg.ShutdownGrace / 2):
		r.stopping.Store(true)
		cancelJobs()
		select {
		case <-done:
		case <-deadline:
		}
	}
	<-reaperDone
	r.releaseAll(context.WithoutCancel(ctx))
}

// releaseAll hands every job a claim of this worker still holds back to the queue (or kills it
// when it has no attempts left).
func (r *Runner) releaseAll(ctx context.Context) {
	err := db.InTx(ctx, r.cfg.Pool, func(tx pgx.Tx) error {
		now := r.cfg.Clock.Now().UTC()
		_, err := r.takeBack(ctx, tx, now, true, takeBackSet+`WHERE status = 'running' AND left(locked_by, length($2) + 1) = $2 || '/'
RETURNING id, type, attempts, status`, r.cfg.WorkerID)
		return err
	})
	if err != nil {
		r.cfg.Log.Error("could not release the leases of unfinished jobs; they resume when the leases expire",
			"error_type", fmt.Sprintf("%T", err))
	}
}
