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
}

// Runner claims and runs queued jobs (spec §8.1, §8.4, §8.5, §8.8).
type Runner struct {
	cfg      RunnerConfig
	mu       sync.Mutex
	handlers map[string]HandlerFunc
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

// NewRunner applies the defaults of RunnerConfig.
func NewRunner(c RunnerConfig) *Runner {
	if c.Workers <= 0 {
		c.Workers = 8
	}
	if c.WorkerID == "" {
		c.WorkerID = defaultWorkerID()
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
	return &Runner{cfg: c, handlers: map[string]HandlerFunc{}}
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

func (r *Runner) handler(name string) HandlerFunc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.handlers[name]
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
// always-class work.
func (r *Runner) claim(ctx context.Context) (*claimed, error) {
	types := r.handled()
	if len(types) == 0 {
		return nil, nil
	}
	now := r.cfg.Clock.Now().UTC()
	classes := allClasses
	if errors.Is(r.cfg.Gate.Allow(license.ClassChange), license.ErrLocked) {
		r.sweepIfDue(ctx, now)
		classes = []string{license.ClassAlways.String()}
	}
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
  AND (target_id IS NULL OR (
        NOT EXISTS (SELECT 1 FROM target_locks l WHERE l.target_id = j.target_id AND l.lease_until > $1)
    AND NOT EXISTS (SELECT 1 FROM jobs o WHERE o.target_id = j.target_id AND o.status = 'running')))
ORDER BY priority, run_at, id
FOR UPDATE SKIP LOCKED
LIMIT 1`, now, classes, types, skip).Scan(&cand.id, &cand.typ, &cand.kind, &cand.payload, &cand.mac, &target,
				&attempts, &maxAtt, &by, &cand.role)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("jobs: select a job: %w", err)
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
			cand.attempts, cand.maxAttempts = attempts+1, maxAtt
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

// sweepIfDue runs the lock-mode sweep at most once per Poll interval for the whole runner (not
// once per worker). A failed sweep is logged; always-class work is still claimed.
func (r *Runner) sweepIfDue(ctx context.Context, now time.Time) {
	r.sweepMu.Lock()
	if !r.lastSweep.IsZero() && now.Sub(r.lastSweep) < r.cfg.Poll {
		r.sweepMu.Unlock()
		return
	}
	r.lastSweep = now
	r.sweepMu.Unlock()
	if err := r.sweepLocked(ctx, now); err != nil && ctx.Err() == nil {
		r.cfg.Log.Error("holding queued work in lock failed", "error_type", fmt.Sprintf("%T", err))
	}
}

// sweepLocked holds queued external-change work for an Administrator's confirmation and
// cancels queued read-only work while the license is expired (spec §8.6, R29, L-81). The audit
// rows are the transaction's last statements: the chain lock is held as briefly as possible.
func (r *Runner) sweepLocked(ctx context.Context, now time.Time) error {
	return db.InTx(ctx, r.cfg.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status = 'cancelled', last_error_code = 'license.locked', finished_at = $1
WHERE status = 'queued' AND class = 'read_only'`, now); err != nil {
			return fmt.Errorf("jobs: cancel read-only work in lock: %w", err)
		}
		rows, err := tx.Query(ctx, `UPDATE jobs SET status = 'blocked_license' WHERE status = 'queued' AND class = 'change' RETURNING id, type`)
		if err != nil {
			return fmt.Errorf("jobs: hold changes in lock: %w", err)
		}
		type held struct {
			id  uuid.UUID
			typ string
		}
		var blocked []held
		for rows.Next() {
			var h held
			if err := rows.Scan(&h.id, &h.typ); err != nil {
				rows.Close()
				return fmt.Errorf("jobs: hold changes in lock: %w", err)
			}
			blocked = append(blocked, h)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("jobs: hold changes in lock: %w", err)
		}
		for _, h := range blocked {
			if _, err := r.cfg.Audit.Append(ctx, tx, r.jobEvent("job.blocked_license", audit.Denied, h.id, map[string]string{"type": h.typ})); err != nil {
				return err
			}
		}
		return nil
	})
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
		return tx.Exec(ctx, `UPDATE jobs SET status = 'dead', last_error_code = $4, finished_at = $5, locked_by = NULL,
    locked_until = NULL `+mine, c.fence(reason, now)...)
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
		return unclaim(tx, tag, err)
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
// handler's context.
func (r *Runner) heartbeat(c *claimed, cancel context.CancelFunc, lost *atomic.Bool) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := r.cfg.Clock.NewTicker(r.cfg.Heartbeat)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C():
				ctx, cancelBeat := context.WithTimeout(context.Background(), 5*time.Second)
				err := r.beat(ctx, c)
				cancelBeat()
				if errors.Is(err, errLeaseLost) {
					r.cfg.Log.Warn("job lease lost; stopping the handler", "job_id", c.id.String(), "job_type", c.typ)
					lost.Store(true)
					cancel()
					return
				}
				if err != nil {
					r.cfg.Log.Warn("job heartbeat failed", "job_id", c.id.String(), "error_type", fmt.Sprintf("%T", err))
				}
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
		if !errors.Is(err, license.ErrLocked) {
			r.terminate(ctx, c, "license.unclassified", "job.dead")
			return
		}
		r.revert(ctx, c, t)
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
		r.release(ctx, c) // writes nothing when the job row is no longer this claim's
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
		r.release(ctx, c) // interrupted by the shutdown: it runs again after the restart (§8.8)
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
	switch {
	case f.Class == Retryable && c.attempts < c.maxAttempts:
		next := Backoff(c.attempts, r.cfg.Jitter())
		r.settle(ctx, c, f.Reason, func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
			return tx.Exec(ctx, `UPDATE jobs SET status = 'queued', run_at = $4, last_error_code = $5, result = $6::jsonb,
    locked_by = NULL, locked_until = NULL `+mine, c.fence(now.Add(next), f.Reason, result)...)
		})
	case f.Class == Retryable:
		r.settle(ctx, c, f.Reason, func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
			return tx.Exec(ctx, `UPDATE jobs SET status = 'dead', last_error_code = $4, result = $5::jsonb, finished_at = $6,
    locked_by = NULL, locked_until = NULL `+mine, c.fence(f.Reason, result, now)...)
		}, r.jobEvent("job.dead", audit.Failure, c.id, map[string]string{"type": c.typ, "reason": f.Reason, "attempt": strconv.Itoa(c.attempts)}))
	default:
		r.settle(ctx, c, f.Reason, func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
			return tx.Exec(ctx, `UPDATE jobs SET status = 'failed', last_error_code = $4, result = $5::jsonb, finished_at = $6,
    locked_by = NULL, locked_until = NULL `+mine, c.fence(f.Reason, result, now)...)
		})
	}
}

// release hands an unfinished run back (graceful shutdown, lost target lock). The attempt
// counts, as with an expired lease: a job without attempts left is dead.
func (r *Runner) release(ctx context.Context, c *claimed) {
	if c.attempts >= c.maxAttempts {
		r.settle(ctx, c, "job.lease_expired", func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
			return tx.Exec(ctx, `UPDATE jobs SET status = 'dead', last_error_code = 'job.lease_expired', finished_at = $4,
    locked_by = NULL, locked_until = NULL `+mine, c.fence(now)...)
		}, r.jobEvent("job.dead", audit.Failure, c.id, map[string]string{"type": c.typ, "reason": "job.lease_expired", "attempt": strconv.Itoa(c.attempts)}))
		return
	}
	r.settle(ctx, c, "job.lease_expired", func(tx pgx.Tx, now time.Time) (pgconn.CommandTag, error) {
		return tx.Exec(ctx, `UPDATE jobs SET status = 'queued', run_at = $4, last_error_code = 'job.lease_expired',
    locked_by = NULL, locked_until = NULL `+mine, c.fence(now)...)
	})
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
// sql's parameters are $1 = now plus args; it must RETURN id, type, attempts, status.
func (r *Runner) takeBack(ctx context.Context, tx pgx.Tx, now time.Time, sql string, args ...any) ([]requeued, error) {
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
	// The audit rows come last: the chain lock is held as briefly as possible.
	for _, x := range all {
		details := map[string]string{"type": x.typ, "attempt": strconv.Itoa(x.attempts), "reason": "job.lease_expired"}
		action, result := "job.recovered", audit.Success
		if x.status == string(StatusDead) {
			action, result = "job.dead", audit.Failure
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
func (r *Runner) Reap(ctx context.Context) (int, error) {
	n := 0
	err := db.InTx(ctx, r.cfg.Pool, func(tx pgx.Tx) error {
		now := r.cfg.Clock.Now().UTC()
		// Locks first (no audit row yet): expired target locks whose job no longer runs.
		if _, err := tx.Exec(ctx, `DELETE FROM target_locks l WHERE lease_until < $1
  AND NOT EXISTS (SELECT 1 FROM jobs o WHERE o.id = l.job_id AND o.status = 'running' AND o.locked_until >= $1)`, now); err != nil {
			return fmt.Errorf("jobs: release expired target locks: %w", err)
		}
		all, err := r.takeBack(ctx, tx, now, takeBackSet+`WHERE status = 'running' AND locked_until < $1
RETURNING id, type, attempts, status`)
		if err != nil {
			return fmt.Errorf("jobs: reap: %w", err)
		}
		n = len(all)
		return nil
	})
	return n, err
}

// Recover is the startup pass of spec §8.8: before the workers start, jobs whose lease expired
// are re-queued. Leases that have not expired may belong to a live process (F-69) and are left
// to the reaper.
func (r *Runner) Recover(ctx context.Context) (int, error) {
	n, err := r.Reap(ctx)
	if err == nil && n > 0 {
		r.cfg.Log.Info("recovered jobs whose worker stopped", "count", n)
	}
	return n, err
}

// Run runs Workers workers and the reaper until ctx ends. Then it stops claiming and gives
// running jobs ShutdownGrace in total: the first half to finish on their own; then they are
// cancelled and get the second half to return. Jobs that still have not returned are handed
// back (re-queued, or dead without attempts left), so they resume after a restart.
func (r *Runner) Run(ctx context.Context) {
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
		_, err := r.takeBack(ctx, tx, now, takeBackSet+`WHERE status = 'running' AND left(locked_by, length($2) + 1) = $2 || '/'
RETURNING id, type, attempts, status`, r.cfg.WorkerID)
		return err
	})
	if err != nil {
		r.cfg.Log.Error("could not release the leases of unfinished jobs; they resume when the leases expire",
			"error_type", fmt.Sprintf("%T", err))
	}
}
