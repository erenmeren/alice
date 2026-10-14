package discoverysvc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/discovery"
	"alice/internal/jobs/netdiscojobs"
	"alice/internal/platform/db"
)

// ScanView is one scan: its scope (and the scope's name, also when the scope was deleted since), how it was started,
// its state and counts, and the reason it ended without finishing (ErrorCode: a discovery.* or license.* reason).
type ScanView struct {
	ID                uuid.UUID
	ScopeID           uuid.UUID
	ScopeName         string
	Trigger           string
	State             string
	CancelRequested   bool
	EndpointsTotal    int
	EndpointsAnswered int
	EndpointsFailed   int
	EndpointsExcluded int
	CertificatesNew   int
	CertChurn         int
	RequestedBy       uuid.NullUUID
	QueuedAt          time.Time
	StartedAt         *time.Time
	FinishedAt        *time.Time
	ErrorCode         string
}

// ScanCursor is the position after a scan in the list's order (queued_at, id), newest first.
type ScanCursor struct {
	QueuedAt time.Time
	ID       uuid.UUID
}

// ScanFilter selects scans: of one scope (uuid.Nil: any), in one state ("" any), after a cursor, at most Limit.
type ScanFilter struct {
	ScopeID uuid.UUID
	State   string
	After   *ScanCursor
	Limit   int
}

const scanColumns = `x.id, x.scope_id, s.name::text, x.trigger, x.state, x.cancel_requested, x.endpoints_total, x.endpoints_answered,
    x.endpoints_failed, x.endpoints_excluded, x.certificates_new, x.cert_churn, x.requested_by, x.queued_at, x.started_at, x.finished_at,
    x.error_code
FROM discovery_scans x JOIN discovery_scopes s ON s.id = x.scope_id`

func scanScan(row pgx.Row) (ScanView, error) {
	var v ScanView
	err := row.Scan(&v.ID, &v.ScopeID, &v.ScopeName, &v.Trigger, &v.State, &v.CancelRequested, &v.EndpointsTotal, &v.EndpointsAnswered,
		&v.EndpointsFailed, &v.EndpointsExcluded, &v.CertificatesNew, &v.CertChurn, &v.RequestedBy, &v.QueuedAt, &v.StartedAt, &v.FinishedAt,
		&v.ErrorCode)
	v.QueuedAt, v.StartedAt, v.FinishedAt = v.QueuedAt.UTC(), utcPtr(v.StartedAt), utcPtr(v.FinishedAt)
	return v, err
}

func getScan(ctx context.Context, q db.Querier, id uuid.UUID) (ScanView, error) {
	v, err := scanScan(q.QueryRow(ctx, `SELECT `+scanColumns+` WHERE x.id = $1`, id))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ScanView{}, ErrNotFound
	case err != nil:
		return ScanView{}, fmt.Errorf("discoverysvc: read the scan: %w", err)
	}
	return v, nil
}

func scansByID(ctx context.Context, q db.Querier, ids []uuid.UUID) (map[uuid.UUID]ScanView, error) {
	out := map[uuid.UUID]ScanView{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT `+scanColumns+` WHERE x.id = ANY ($1::uuid[])`, ids)
	if err != nil {
		return nil, fmt.Errorf("discoverysvc: read the scans: %w", err)
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ScanView, error) { return scanScan(r) })
	if err != nil {
		return nil, fmt.Errorf("discoverysvc: read the scans: %w", err)
	}
	for _, v := range list {
		out[v.ID] = v
	}
	return out, nil
}

// GetScan reads one scan (ErrNotFound).
func (s *Service) GetScan(ctx context.Context, id uuid.UUID) (ScanView, error) {
	return getScan(ctx, s.pool, id)
}

// ListScans lists scans newest first; more reports whether a page follows.
func (s *Service) ListScans(ctx context.Context, f ScanFilter) (list []ScanView, more bool, err error) {
	n := pageSize(f.Limit)
	args := []any{n + 1}
	var where []string
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if f.ScopeID != uuid.Nil {
		where = append(where, "x.scope_id = "+arg(f.ScopeID))
	}
	if f.State != "" {
		where = append(where, "x.state = "+arg(f.State))
	}
	if f.After != nil {
		where = append(where, "(x.queued_at, x.id) < ("+arg(f.After.QueuedAt)+"::timestamptz, "+arg(f.After.ID)+"::uuid)")
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	rows, err := s.pool.Query(ctx, `SELECT `+scanColumns+cond+` ORDER BY x.queued_at DESC, x.id DESC LIMIT $1`, args...)
	if err != nil {
		return nil, false, fmt.Errorf("discoverysvc: list the scans: %w", err)
	}
	list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ScanView, error) { return scanScan(r) })
	if err != nil {
		return nil, false, fmt.Errorf("discoverysvc: list the scans: %w", err)
	}
	if more = len(list) > n; more {
		list = list[:n]
	}
	return list, more, nil
}

// StartScan queues a manual scan of a live, switched-on scope: the scan row, its netdisco.scan job (netdiscojobs.StartTx)
// and the discovery.scan.started row commit together. Refusals: discovery.ErrScopeNotFound (deleted or unknown),
// ErrScopeDisabled, discovery.ErrScanRunning (the scope has a scan queued or running), ErrTooManyScans
// (MaxActiveScans are active anywhere: refused, never queued, ruling of Task 8).
func (s *Service) StartScan(ctx context.Context, a Actor, scopeID uuid.UUID) (ScanView, error) {
	var v ScanView
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, startLock); err != nil {
			return fmt.Errorf("discoverysvc: serialise the start: %w", err)
		}
		var enabled, busy bool
		var active int
		err := tx.QueryRow(ctx, `SELECT s.enabled,
    EXISTS (SELECT 1 FROM discovery_scans WHERE scope_id = s.id AND state IN ('queued', 'running')),
    (SELECT count(*) FROM discovery_scans WHERE state IN ('queued', 'running'))
FROM discovery_scopes s WHERE s.id = $1 AND s.deleted_at IS NULL`, scopeID).Scan(&enabled, &busy, &active)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return discovery.ErrScopeNotFound
		case err != nil:
			return fmt.Errorf("discoverysvc: read the scope: %w", err)
		case !enabled:
			return ErrScopeDisabled
		case busy:
			return discovery.ErrScanRunning
		case active >= MaxActiveScans:
			return ErrTooManyScans
		}
		scanID, jobID, err := netdiscojobs.StartTx(ctx, tx, s.queue, netdiscojobs.StartRequest{ScopeID: scopeID, Trigger: netdiscojobs.TriggerManual,
			RequestedBy: a.UserID, Role: a.Role, Now: s.now()})
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, a, "discovery.scan.started", "discovery_scan", scanID.String(), map[string]string{
			"scan_id": scanID.String(), "scope_id": scopeID.String(), "job_id": jobID.String(), "trigger": netdiscojobs.TriggerManual}); err != nil {
			return err
		}
		v, err = getScan(ctx, tx, scanID)
		return err
	})
	return v, err
}

// CancelScan asks a queued or running scan to stop (the flag its workers poll; the scanner ends it as cancelled, results
// so far kept), with the discovery.scan.cancelled row in the same transaction. Idempotent: a scan already asked to stop,
// or already over, is answered as it is and nothing is written. ErrNotFound for an unknown scan.
func (s *Service) CancelScan(ctx context.Context, a Actor, id uuid.UUID) (ScanView, error) {
	var v ScanView
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var scope uuid.UUID
		var state string
		var requested bool
		err := tx.QueryRow(ctx, `SELECT scope_id, state, cancel_requested FROM discovery_scans WHERE id = $1 FOR UPDATE`, id).Scan(&scope, &state, &requested)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return fmt.Errorf("discoverysvc: read the scan: %w", err)
		}
		if !requested && (state == discovery.ScanQueued || state == discovery.ScanRunning) {
			if _, err := tx.Exec(ctx, `UPDATE discovery_scans SET cancel_requested = true WHERE id = $1`, id); err != nil {
				return fmt.Errorf("discoverysvc: cancel the scan: %w", err)
			}
			if err := s.appendAudit(ctx, tx, a, "discovery.scan.cancelled", "discovery_scan", id.String(), map[string]string{
				"scan_id": id.String(), "scope_id": scope.String(), "state": state}); err != nil {
				return err
			}
		}
		v, err = getScan(ctx, tx, id)
		return err
	})
	return v, err
}
