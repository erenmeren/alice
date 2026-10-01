package jobs

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
)

// Errors of the queue.
var (
	ErrNotFound    = errors.New("jobs: not found")
	ErrNotWaiting  = errors.New("jobs: the job is not waiting for a confirmation")
	ErrUnknownType = errors.New("jobs: job type is not registered")
	ErrBadCursor   = errors.New("jobs: invalid cursor")
)

// Deriver derives a sub-key from the master key; *secrets.Keyring implements it. jobs may not
// import secrets (spec §5.4), so the queue takes this one-method view of the keyring.
type Deriver interface {
	Derive(label string) []byte
}

// payloadMACLabel is secrets.LabelJob (a test asserts it): the HKDF label of the job payload
// MAC (threat J-1: a row inserted or edited in the database is never executed).
const payloadMACLabel = "alice/job/v1"

// jobsActor is the audit actor of the queue's own decisions.
var jobsActor = audit.SystemActor("jobs")

// liveStatuses are the statuses under which a dedupe key is taken (jobs_dedupe_live).
const liveStatuses = `('queued', 'running', 'blocked_license')`

// QueueConfig holds the queue's dependencies.
type QueueConfig struct {
	Pool    *pgxpool.Pool
	Keyring Deriver // payload MAC under secrets.LabelJob
	Audit   *audit.Log
	Clock   clock.Clock
	Gate    Gate // Confirm refuses while the gate refuses external changes; nil refuses always
}

// Queue writes and reads jobs.
type Queue struct {
	pool    *pgxpool.Pool
	keyring Deriver
	audit   *audit.Log
	clock   clock.Clock
	gate    Gate
}

// NewQueue returns a Queue.
func NewQueue(c QueueConfig) *Queue {
	return &Queue{pool: c.Pool, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, gate: c.Gate}
}

var _ inventory.Enqueuer = (*Queue)(nil)

// Spec describes a job to enqueue.
type Spec struct {
	Type          Type
	TargetID      uuid.UUID // uuid.Nil = none
	Payload       map[string]string
	Kind          Kind
	Priority      int       // 0 = 1 for user jobs, 5 otherwise
	MaxAttempts   int       // 0 = the type's default (MaxAttemptsFor)
	RunAt         time.Time // zero = now
	DedupeKey     string
	CreatedBy     uuid.UUID
	CreatedByRole string
}

// Job is what a handler receives.
type Job struct {
	ID            uuid.UUID
	Type          Type
	Kind          Kind
	TargetID      uuid.UUID
	Payload       map[string]string
	Attempt       int // 1 for the first run
	MaxAttempts   int
	CreatedBy     uuid.UUID
	CreatedByRole string
}

// View is a stored job as the API shows it.
type View struct {
	ID            uuid.UUID
	Type          string
	Kind          string
	Status        Status
	TargetID      uuid.UUID
	Attempts      int
	MaxAttempts   int
	LastErrorCode string
	ErrorParams   map[string]string
	Result        map[string]any
	CreatedBy     uuid.UUID
	CreatedAt     time.Time
	RunAt         time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
}

// ListFilter selects jobs, newest first.
type ListFilter struct {
	Status   Status    // "" = all
	TargetID uuid.UUID // uuid.Nil = all
	Cursor   string
	Limit    int // 1..200, default 50
}

// canonicalPayload is the payload's JSON with sorted keys; a nil payload is {}.
func canonicalPayload(p map[string]string) []byte {
	if p == nil {
		p = map[string]string{}
	}
	b, err := json.Marshal(p)
	if err != nil {
		panic("jobs: encode payload: " + err.Error()) // a map of strings always encodes
	}
	return b
}

func uuidText(u uuid.UUID) string {
	if u == uuid.Nil {
		return ""
	}
	return u.String()
}

// payloadMAC is HMAC-SHA256 over everything that decides what a job does and on whose
// authority: id, type, kind, target, payload, creator, the creator's role and the attempt
// budget. Every field is length-prefixed, so no two field lists encode alike.
func payloadMAC(key []byte, id uuid.UUID, typ, kind string, target uuid.UUID, payload []byte, createdBy uuid.UUID,
	role string, maxAttempts int) []byte {
	m := hmac.New(sha256.New, key)
	for _, f := range [][]byte{[]byte("alice-job-v1"), []byte(id.String()), []byte(typ), []byte(kind), []byte(uuidText(target)),
		payload, []byte(uuidText(createdBy)), []byte(role), []byte(strconv.Itoa(maxAttempts))} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		m.Write(n[:])
		m.Write(f)
	}
	return m.Sum(nil)
}

// mac derives the key for one computation and clears it afterwards.
func (q *Queue) mac(id uuid.UUID, typ, kind string, target uuid.UUID, payload []byte, createdBy uuid.UUID, role string,
	maxAttempts int) []byte {
	key := q.keyring.Derive(payloadMACLabel)
	defer clear(key)
	return payloadMAC(key, id, typ, kind, target, payload, createdBy, role, maxAttempts)
}

func nullUUID(u uuid.UUID) *uuid.UUID {
	if u == uuid.Nil {
		return nil
	}
	return &u
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Add writes a job in tx. When a live job (queued, running or blocked) holds the same dedupe
// key, nothing is written and that job's id is returned with true.
func (q *Queue) Add(ctx context.Context, tx pgx.Tx, s Spec) (uuid.UUID, bool, error) {
	reg, ok := lookup(s.Type.Name)
	if !ok || reg != s.Type {
		return uuid.Nil, false, fmt.Errorf("%w: %q", ErrUnknownType, s.Type.Name)
	}
	if !s.Kind.valid() {
		return uuid.Nil, false, fmt.Errorf("jobs: invalid job kind %q", s.Kind)
	}
	priority := s.Priority
	if priority == 0 {
		priority = 5
		if s.Kind == KindUser {
			priority = 1
		}
	}
	maxAttempts := s.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = MaxAttemptsFor(s.Type)
	}
	now := q.clock.Now().UTC()
	runAt := s.RunAt.UTC()
	if s.RunAt.IsZero() {
		runAt = now
	}
	payload := canonicalPayload(s.Payload)
	// The job holding the dedupe key may finish between the INSERT and the SELECT; then the key
	// is free again and the INSERT is tried once more.
	for range 2 {
		id := uuid.Must(uuid.NewV7())
		var inserted uuid.UUID
		err := tx.QueryRow(ctx, `INSERT INTO jobs (id, type, class, kind, payload, payload_mac, target_id, dedupe_key, status,
    priority, run_at, max_attempts, created_by, created_by_role, created_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, 'queued', $9, $10, $11, $12, $13, $14)
ON CONFLICT (dedupe_key) WHERE status IN `+liveStatuses+` DO NOTHING
RETURNING id`,
			id, s.Type.Name, s.Type.Class.String(), string(s.Kind), string(payload),
			q.mac(id, s.Type.Name, string(s.Kind), s.TargetID, payload, s.CreatedBy, s.CreatedByRole, maxAttempts),
			nullUUID(s.TargetID), nullString(s.DedupeKey), priority, runAt, maxAttempts, nullUUID(s.CreatedBy), s.CreatedByRole, now,
		).Scan(&inserted)
		if err == nil {
			return inserted, false, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, false, fmt.Errorf("jobs: enqueue %s: %w", s.Type.Name, err)
		}
		var existing uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM jobs WHERE dedupe_key = $1 AND status IN `+liveStatuses, s.DedupeKey).Scan(&existing)
		if err == nil {
			return existing, true, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, false, fmt.Errorf("jobs: read the job holding the dedupe key: %w", err)
		}
	}
	return uuid.Nil, false, fmt.Errorf("jobs: enqueue %s: the dedupe key keeps changing hands", s.Type.Name)
}

// Enqueue is Add in its own transaction.
func (q *Queue) Enqueue(ctx context.Context, s Spec) (uuid.UUID, bool, error) {
	var id uuid.UUID
	var dup bool
	err := db.InTx(ctx, q.pool, func(tx pgx.Tx) error {
		var err error
		id, dup, err = q.Add(ctx, tx, s)
		return err
	})
	return id, dup, err
}

// EnqueueTx implements inventory.Enqueuer. A live job that holds the dedupe key answers the
// request only when its payload is the same; other options (a removal now confirmed for root's
// last key) answer inventory.ErrJobConflict instead of silently dropping them.
func (q *Queue) EnqueueTx(ctx context.Context, tx pgx.Tx, r inventory.JobRequest) (uuid.UUID, error) {
	t, ok := lookup(r.Type)
	if !ok {
		return uuid.Nil, fmt.Errorf("%w: %q", ErrUnknownType, r.Type)
	}
	id, dup, err := q.Add(ctx, tx, Spec{
		Type: t, TargetID: r.TargetID, Payload: r.Payload, Kind: Kind(r.Kind), DedupeKey: r.DedupeKey,
		CreatedBy: r.CreatedBy, CreatedByRole: r.CreatedByRole,
	})
	if err != nil || !dup {
		return id, err
	}
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT payload FROM jobs WHERE id = $1", id).Scan(&raw); err != nil {
		return uuid.Nil, fmt.Errorf("jobs: read the job holding the dedupe key: %w", err)
	}
	var existing map[string]string
	if err := json.Unmarshal(raw, &existing); err != nil {
		return uuid.Nil, fmt.Errorf("jobs: decode the payload of the job holding the dedupe key: %w", err)
	}
	if !maps.Equal(existing, r.Payload) {
		return uuid.Nil, inventory.ErrJobConflict
	}
	return id, nil
}

const viewColumns = `id, type, kind, status, target_id, attempts, max_attempts, last_error_code, result, created_by,
    created_at, run_at, started_at, finished_at`

func scanView(row pgx.Row) (View, error) {
	var (
		v          View
		status     string
		target, by *uuid.UUID
		result     []byte
	)
	if err := row.Scan(&v.ID, &v.Type, &v.Kind, &status, &target, &v.Attempts, &v.MaxAttempts, &v.LastErrorCode, &result,
		&by, &v.CreatedAt, &v.RunAt, &v.StartedAt, &v.FinishedAt); err != nil {
		return View{}, err
	}
	v.Status = Status(status)
	if target != nil {
		v.TargetID = *target
	}
	if by != nil {
		v.CreatedBy = *by
	}
	v.CreatedAt, v.RunAt = v.CreatedAt.UTC(), v.RunAt.UTC()
	for _, t := range []*time.Time{v.StartedAt, v.FinishedAt} {
		if t != nil {
			*t = t.UTC()
		}
	}
	v.Result = map[string]any{}
	if err := json.Unmarshal(result, &v.Result); err != nil {
		return View{}, fmt.Errorf("jobs: decode result: %w", err)
	}
	if params, ok := v.Result["error_params"].(map[string]any); ok {
		v.ErrorParams = map[string]string{}
		for k, val := range params {
			if s, ok := val.(string); ok {
				v.ErrorParams[k] = s
			}
		}
	}
	return v, nil
}

// Get returns one job.
func (q *Queue) Get(ctx context.Context, id uuid.UUID) (View, error) {
	v, err := scanView(q.pool.QueryRow(ctx, `SELECT `+viewColumns+` FROM jobs WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, fmt.Errorf("jobs: read job: %w", err)
	}
	return v, nil
}

func encodeCursor(at time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UnixMicro(), 10) + "|" + id.String()))
}

func decodeCursor(c string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, uuid.Nil, ErrBadCursor
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, ErrBadCursor
	}
	micros, err := strconv.ParseInt(at, 10, 64)
	if err != nil {
		return time.Time{}, uuid.Nil, ErrBadCursor
	}
	u, err := uuid.Parse(id)
	if err != nil {
		return time.Time{}, uuid.Nil, ErrBadCursor
	}
	return time.UnixMicro(micros).UTC(), u, nil
}

// List pages jobs newest first. The returned cursor is "" on the last page.
func (q *Queue) List(ctx context.Context, f ListFilter) ([]View, string, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 200)
	var (
		afterAt *time.Time
		afterID *uuid.UUID
	)
	if f.Cursor != "" {
		at, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		afterAt, afterID = &at, &id
	}
	rows, err := q.pool.Query(ctx, `SELECT `+viewColumns+` FROM jobs
WHERE ($1::text IS NULL OR status = $1)
  AND ($2::uuid IS NULL OR target_id = $2)
  AND ($3::timestamptz IS NULL OR (created_at, id) < ($3, $4::uuid))
ORDER BY created_at DESC, id DESC
LIMIT $5`, nullString(string(f.Status)), nullUUID(f.TargetID), afterAt, afterID, limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("jobs: list: %w", err)
	}
	defer rows.Close()
	var out []View
	for rows.Next() {
		v, err := scanView(rows)
		if err != nil {
			return nil, "", fmt.Errorf("jobs: list: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("jobs: list: %w", err)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeCursor(last.CreatedAt, last.ID)
	}
	return out, next, nil
}

// lockStatus reads a job's status and type under its row lock.
func lockStatus(ctx context.Context, tx pgx.Tx, id uuid.UUID) (Status, string, error) {
	var status, typ string
	err := tx.QueryRow(ctx, `SELECT status, type FROM jobs WHERE id = $1 FOR UPDATE`, id).Scan(&status, &typ)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("jobs: read job: %w", err)
	}
	return Status(status), typ, nil
}

// Confirm lets an Administrator start work that was held while the license was expired (R29,
// L-81): blocked_license -> queued. It is refused while the gate still refuses the work.
func (q *Queue) Confirm(ctx context.Context, actor audit.Actor, by uuid.UUID, id uuid.UUID) error {
	return db.InTx(ctx, q.pool, func(tx pgx.Tx) error {
		status, typ, err := lockStatus(ctx, tx, id)
		if err != nil {
			return err
		}
		if status != StatusBlocked {
			return ErrNotWaiting
		}
		t, ok := lookup(typ)
		if !ok {
			return fmt.Errorf("%w: %q", ErrUnknownType, typ)
		}
		if q.gate == nil {
			return license.ErrLocked
		}
		if err := q.gate.Allow(t.Class); err != nil {
			return err
		}
		now := q.clock.Now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status = 'queued', run_at = $2, confirmed_by = $3, confirmed_at = $2,
    last_error_code = '' WHERE id = $1`, id, now, nullUUID(by)); err != nil {
			return fmt.Errorf("jobs: confirm: %w", err)
		}
		_, err = q.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "job.confirmed", ObjectType: "job",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"type": typ}})
		return err
	})
}

// Discard cancels a job that waits for a confirmation or has not started yet.
func (q *Queue) Discard(ctx context.Context, actor audit.Actor, by uuid.UUID, id uuid.UUID) error {
	return db.InTx(ctx, q.pool, func(tx pgx.Tx) error {
		status, typ, err := lockStatus(ctx, tx, id)
		if err != nil {
			return err
		}
		if status != StatusBlocked && status != StatusQueued {
			return ErrNotWaiting
		}
		now := q.clock.Now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status = 'cancelled', finished_at = $2, confirmed_by = $3, confirmed_at = $2
WHERE id = $1`, id, now, nullUUID(by)); err != nil {
			return fmt.Errorf("jobs: discard: %w", err)
		}
		_, err = q.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "job.discarded", ObjectType: "job",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"type": typ, "from_status": string(status)}})
		return err
	})
}

// pruneBatch is how many jobs one Prune statement deletes: short statements, no long lock on
// a large table. A variable so a test can make it small.
var pruneBatch = 5000

// Prune deletes finished jobs (and, through the foreign key, their attempts) that ended more
// than olderThan ago (maintenance.cleanup, spec §8.2: 90 days), oldest first, in batches of
// pruneBatch until a batch comes back short. Unfinished jobs are kept. On an error it returns
// the number deleted so far.
func (q *Queue) Prune(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := q.clock.Now().UTC().Add(-olderThan)
	total := 0
	for {
		tag, err := q.pool.Exec(ctx, `DELETE FROM jobs WHERE id IN (
    SELECT id FROM jobs WHERE finished_at < $1 AND status IN ('succeeded', 'failed', 'cancelled', 'dead')
    ORDER BY finished_at LIMIT $2)`, cutoff, pruneBatch)
		if err != nil {
			return total, fmt.Errorf("jobs: prune: %w", err)
		}
		n := int(tag.RowsAffected())
		total += n
		if n < pruneBatch {
			return total, nil
		}
	}
}
