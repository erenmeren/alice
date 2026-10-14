package discovery

// This file is the scanner's view of the database (Store) and its PostgreSQL implementation's scan lifecycle: creating
// a scan, starting it (with the crash recovery of amendment A5), reading the discovery settings, the cancel flag, and
// ending it. Ingestion is ingest.go, retention retention.go, the read side link.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// Scan states (discovery_scans.state).
const (
	ScanQueued    = "queued"
	ScanRunning   = "running"
	ScanDone      = "done"
	ScanCancelled = "cancelled"
	ScanTimedOut  = "timed_out"
	ScanFailed    = "failed"
)

// Reasons a scan that did not finish normally records in discovery_scans.error_code: the API reasons of the ALC-DSC
// codes (internal/api/errors.go), and license.<denial> for a scan the license lock stopped. Never a Go error text.
const (
	ReasonEntryNotAllowed = "discovery.entry_not_allowed" // ALC-DSC-0002: no allowed scan network, or the rules cannot be read
	ReasonScopeTooLarge   = "discovery.scope_too_large"   // ALC-DSC-0001
	ReasonEntryInvalid    = "discovery.entry_invalid"     // ALC-DSC-0003
	ReasonCancelled       = "discovery.scan_cancelled"    // ALC-DSC-0005: a person cancelled it, or the scope was switched off
	ReasonTimedOut        = "discovery.scan_timed_out"    // ALC-DSC-0006: the whole-scan cap
	ReasonScopeNotFound   = "discovery.scope_not_found"   // ALC-DSC-0008: the scope was deleted
	ReasonScheduleInvalid = "discovery.schedule_invalid"  // ALC-DSC-0009
	ReasonInterrupted     = "discovery.scan_interrupted"  // ALC-DSC-0012: a restart, a shutdown or a database failure ended it
)

// Errors of the store.
var (
	// ErrScanRunning is ALC-DSC-0004: the scope has a scan queued or running (one at a time per scope).
	ErrScanRunning = errors.New("discovery: a scan of this scope is queued or running")
	// ErrScopeNotFound is ALC-DSC-0008: no live scope has that id.
	ErrScopeNotFound = errors.New("discovery: the scope does not exist")
	// ErrScanNotFound: no scan has that id.
	ErrScanNotFound = errors.New("discovery: the scan does not exist")
	// ErrScanBusy: the scan is running and was started less than one lease ago, so another run may still own it.
	ErrScanBusy = errors.New("discovery: the scan is running elsewhere")
	// ErrScanNotRunning: results were offered for a scan that is no longer running.
	ErrScanNotRunning = errors.New("discovery: the scan is not running")
)

// Settings keys (migration 00014; an absent row is the default).
const (
	SettingAllowedNetworks = "discovery.allowed_networks"
	SettingExclusions      = "discovery.exclusions"
	SettingRetentionDays   = "discovery.retention_days"
)

// ScanStart is what BeginScan found. Run is false when there is nothing to do: the scan has finished already, or it was
// left running by a run that ended more than one lease ago and is now failed (crash recovery). Otherwise the scan is
// running from StartedAt and Scope is its scope as stored (ScopeDeleted: soft-deleted since the scan was queued).
type ScanStart struct {
	Run             bool
	ScopeID         uuid.UUID
	Scope           Scope
	ScopeDeleted    bool
	CancelRequested bool
	StartedAt       time.Time
}

// RuleSettings are the stored discovery settings a scan is checked against, read together (one read: the scope rules
// of Expand and the scan policy cannot disagree). A missing row is an empty list.
type RuleSettings struct {
	AllowedNetworks  []string
	GlobalExclusions []string
}

// Finish ends a scan. Probed says the scan dialed: only then are the misses of its unanswered endpoints counted.
type Finish struct {
	ScanID, ScopeID uuid.UUID
	Now             time.Time
	State           string
	ErrorCode       string
	Probed          bool
}

// Store is what the scanner needs from the database; *PGStore is the production one.
type Store interface {
	// BeginScan starts a queued scan, or recovers one a dead run left running (see ScanStart).
	BeginScan(ctx context.Context, scanID uuid.UUID, now time.Time, lease time.Duration) (ScanStart, error)
	// ReadRules reads the allowed scan networks and the global exclusions.
	ReadRules(ctx context.Context) (RuleSettings, error)
	// CancelRequested reports whether someone asked the running scan to stop.
	CancelRequested(ctx context.Context, scanID uuid.UUID) (bool, error)
	// PrepareScan records the size of the expansion and marks the scope's endpoints that left it gone.
	PrepareScan(ctx context.Context, scanID, scopeID uuid.UUID, x *Expansion, now time.Time) error
	// Ingest records one batch of results.
	Ingest(ctx context.Context, b Batch) error
	// FinishScan ends the scan.
	FinishScan(ctx context.Context, f Finish) error
}

// pgPool is what PGStore needs of a pool (*pgxpool.Pool); tests wrap it to fail chosen calls.
type pgPool interface {
	db.Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// PGStore is the PostgreSQL Store (and the read side, retention and the scan creation the API uses).
type PGStore struct{ db pgPool }

// NewStore returns the store over pool (production: the alice_app pool).
func NewStore(pool pgPool) *PGStore { return &PGStore{db: pool} }

var _ Store = (*PGStore)(nil)

// inTx runs fn in a transaction, committed when fn returns nil.
func (s *PGStore) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("discovery: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("discovery: commit: %w", err)
	}
	return nil
}

// CreateScan queues a scan of a live scope (trigger manual or schedule; requestedBy nil for a schedule).
// ErrScanRunning when the scope has a scan queued or running (index discovery_scans_one_active), ErrScopeNotFound
// when the scope is deleted or unknown. It writes the scan row only: production queues a scan together with its job
// (netdiscojobs.StartTx calls CreateScanTx in the job's transaction).
func (s *PGStore) CreateScan(ctx context.Context, scopeID uuid.UUID, trigger string, requestedBy *uuid.UUID, now time.Time) (uuid.UUID, error) {
	return CreateScanTx(ctx, s.db, scopeID, trigger, requestedBy, now)
}

// CreateScanTx is CreateScan on q (a transaction: a refusal aborts it).
func CreateScanTx(ctx context.Context, q db.Querier, scopeID uuid.UUID, trigger string, requestedBy *uuid.UUID, now time.Time) (uuid.UUID, error) {
	id := uuid.New()
	tag, err := q.Exec(ctx, `INSERT INTO discovery_scans (id, scope_id, trigger, requested_by, queued_at)
SELECT $1, id, $3, $4, $5 FROM discovery_scopes WHERE id = $2 AND deleted_at IS NULL`, id, scopeID, trigger, requestedBy, now)
	switch {
	case db.IsUniqueViolationOn(err, "discovery_scans_one_active"):
		return uuid.Nil, ErrScanRunning
	case err != nil:
		return uuid.Nil, fmt.Errorf("discovery: queue a scan: %w", err)
	case tag.RowsAffected() == 0:
		return uuid.Nil, ErrScopeNotFound
	}
	return id, nil
}

// RequestCancel asks a queued or running scan to stop (the workers poll the flag). It reports whether such a scan was
// found.
func (s *PGStore) RequestCancel(ctx context.Context, scanID uuid.UUID) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE discovery_scans SET cancel_requested = true WHERE id = $1 AND state IN ('queued', 'running')`, scanID)
	if err != nil {
		return false, fmt.Errorf("discovery: cancel a scan: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// BeginScan implements Store. A queued scan becomes running at now. A running one whose start is more than one lease
// before now was left by a run that died (a restart, a lost lease): it is ended as failed with discovery.scan_interrupted
// and Run is false (idempotent: a second call finds it finished). A running one started within the lease is ErrScanBusy.
func (s *PGStore) BeginScan(ctx context.Context, scanID uuid.UUID, now time.Time, lease time.Duration) (ScanStart, error) {
	var st ScanStart
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var state string
		var started *time.Time
		err := tx.QueryRow(ctx, `SELECT state, scope_id, started_at, cancel_requested FROM discovery_scans WHERE id = $1 FOR UPDATE`,
			scanID).Scan(&state, &st.ScopeID, &started, &st.CancelRequested)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrScanNotFound
		case err != nil:
			return fmt.Errorf("discovery: read the scan: %w", err)
		case state == ScanRunning && started.After(now.Add(-lease)):
			return ErrScanBusy
		case state == ScanRunning:
			_, err := tx.Exec(ctx, `UPDATE discovery_scans SET state = 'failed', error_code = $2, finished_at = $3 WHERE id = $1`,
				scanID, ReasonInterrupted, now)
			return wrap("end an interrupted scan", err)
		case state != ScanQueued:
			return nil // finished: nothing to do
		}
		if _, err := tx.Exec(ctx, `UPDATE discovery_scans SET state = 'running', started_at = $2 WHERE id = $1`, scanID, now); err != nil {
			return wrap("start the scan", err)
		}
		st.Run, st.StartedAt = true, now
		var entries, exclusions []string
		var hours *int
		err = tx.QueryRow(ctx, `SELECT name::text, entries, ports, sni_names, exclusions, enabled, schedule_hours,
    coalesce(to_char(window_start, 'HH24:MI'), ''), coalesce(to_char(window_end, 'HH24:MI'), ''), window_tz, alert_on_expiry,
    rate_per_sec, concurrency, deleted_at IS NOT NULL
FROM discovery_scopes WHERE id = $1`, st.ScopeID).Scan(&st.Scope.Name, &entries, &st.Scope.Ports, &st.Scope.SNINames, &exclusions,
			&st.Scope.Enabled, &hours, &st.Scope.Schedule.WindowStart, &st.Scope.Schedule.WindowEnd, &st.Scope.Schedule.TimeZone,
			&st.Scope.AlertOnExpiry, &st.Scope.RatePerSec, &st.Scope.Concurrency, &st.ScopeDeleted)
		st.Scope.Entries, st.Scope.Exclusions = entries, exclusions
		if hours != nil {
			st.Scope.Schedule.Hours = *hours
		}
		return wrap("read the scope", err)
	})
	if err != nil {
		return ScanStart{}, err
	}
	return st, nil
}

// wrap returns nil for nil, else err with what was being done.
func wrap(what string, err error) error {
	if err != nil {
		return fmt.Errorf("discovery: %s: %w", what, err)
	}
	return nil
}

// ReadRules implements Store: one query reads both lists. A row that does not decode is an error (the scan then scans
// nothing).
func (s *PGStore) ReadRules(ctx context.Context) (RuleSettings, error) {
	var allowed, excluded []byte
	err := s.db.QueryRow(ctx, `SELECT (SELECT value FROM settings WHERE key = $1), (SELECT value FROM settings WHERE key = $2)`,
		SettingAllowedNetworks, SettingExclusions).Scan(&allowed, &excluded)
	if err != nil {
		return RuleSettings{}, wrap("read the discovery settings", err)
	}
	var r RuleSettings
	if err := errors.Join(decodeList(allowed, &r.AllowedNetworks), decodeList(excluded, &r.GlobalExclusions)); err != nil {
		return RuleSettings{}, err
	}
	return r, nil
}

func decodeList(raw []byte, dst *[]string) error {
	if raw == nil {
		return nil
	}
	return wrap("decode a discovery setting", json.Unmarshal(raw, dst))
}

// CancelRequested implements Store.
func (s *PGStore) CancelRequested(ctx context.Context, scanID uuid.UUID) (bool, error) {
	var c bool
	err := s.db.QueryRow(ctx, `SELECT cancel_requested FROM discovery_scans WHERE id = $1`, scanID).Scan(&c)
	return c, wrap("read the cancel flag", err)
}

// PrepareScan implements Store: endpoints_total, and every endpoint of the scope that is not in the expansion (the scope
// or the rules changed) is gone now. The endpoints of a host name that did not resolve this time are left as they are:
// a failed lookup says nothing about them.
func (s *PGStore) PrepareScan(ctx context.Context, scanID, scopeID uuid.UUID, x *Expansion, now time.Time) error {
	n := len(x.Dial) + len(x.Excluded)
	addrs, ports, snis := make([]netip.Addr, 0, n), make([]int32, 0, n), make([]string, 0, n)
	for _, list := range [][]Endpoint{x.Dial, x.Excluded} {
		for _, e := range list {
			addrs, ports, snis = append(addrs, e.Address), append(ports, int32(e.Port)), append(snis, e.SNI)
		}
	}
	unresolved := append([]string{}, x.Unresolved...)
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE discovery_scans SET endpoints_total = $2 WHERE id = $1`, scanID, x.Endpoints); err != nil {
			return wrap("record the scan size", err)
		}
		_, err := tx.Exec(ctx, `UPDATE discovery_endpoints e SET state = 'gone', gone_since = $2
WHERE e.scope_id = $1 AND e.state <> 'gone' AND NOT (e.host <> '' AND e.host = ANY ($6::text[]))
  AND NOT EXISTS (SELECT 1 FROM unnest($3::inet[], $4::int[], $5::text[]) AS k(a, p, s) WHERE k.a = e.address AND k.p = e.port AND k.s = e.sni)`,
			scopeID, now, addrs, ports, snis, unresolved)
		return wrap("mark the endpoints that left the scope", err)
	})
}

// FinishScan implements Store, in one transaction: when the scan probed, every endpoint it attempted that did not answer
// (refused, timeout, reset, no TLS) has one more miss and is gone after three, unless no attempted endpoint answered
// while the scope had answered before (Alice's own network may be down: nothing is counted); then the scan's state,
// and the scope's old scans are pruned (pruneScans).
func (s *PGStore) FinishScan(ctx context.Context, f Finish) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if f.Probed {
			if _, err := tx.Exec(ctx, `UPDATE discovery_endpoints SET missed_scans = missed_scans + 1,
    state = CASE WHEN missed_scans + 1 >= $3 THEN 'gone' ELSE state END,
    gone_since = CASE WHEN missed_scans + 1 >= $3 THEN $2::timestamptz END
WHERE last_scan_id = $1 AND state IN ('unreachable', 'no_tls') AND last_error_code IN ('refused', 'timeout', 'reset', 'no_tls')
  AND NOT EXISTS (SELECT 1 FROM discovery_scans s WHERE s.id = $1 AND s.endpoints_answered = 0
                  AND EXISTS (SELECT 1 FROM discovery_endpoints p WHERE p.scope_id = s.scope_id AND p.last_seen IS NOT NULL))`,
				f.ScanID, f.Now, MaxMissedScans); err != nil {
				return wrap("count the missed endpoints", err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE discovery_scans SET state = $2, error_code = $3, finished_at = $4 WHERE id = $1 AND state IN ('queued', 'running')`,
			f.ScanID, f.State, f.ErrorCode, f.Now); err != nil {
			return wrap("end the scan", err)
		}
		_, err := pruneScans(ctx, tx, f.ScopeID, f.Now)
		return err
	})
}

// MaxMissedScans is how many scans in a row an endpoint may miss before it is gone.
const MaxMissedScans = 3

// KeepScans finished scans are kept per scope, and every scan queued in the last KeepScansFor (the per-day cap on new
// certificates counts them).
const (
	KeepScans    = 30
	KeepScansFor = 24 * time.Hour
)

// pruneScans deletes the finished scans of a scope (uuid.Nil: of every scope) beyond the newest KeepScans that were
// queued more than KeepScansFor before now, and counts them. A scan in flight is never deleted (Z1020 refuses it anyway).
func pruneScans(ctx context.Context, q db.Querier, scopeID uuid.UUID, now time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM discovery_scans d USING (
    SELECT id, row_number() OVER (PARTITION BY scope_id ORDER BY queued_at DESC, id DESC) AS n
    FROM discovery_scans WHERE state NOT IN ('queued', 'running') AND ($1::uuid = '00000000-0000-0000-0000-000000000000' OR scope_id = $1)) r
WHERE d.id = r.id AND r.n > $2 AND d.queued_at < $3`, scopeID, KeepScans, now.Add(-KeepScansFor))
	return tag.RowsAffected(), wrap("prune old scans", err)
}
