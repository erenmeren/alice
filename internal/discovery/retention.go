package discovery

// Retention (the netdisco.retention task, amendment A4): license class Always, so it runs in lock mode too; it only
// ever deletes or ends discovery_* rows.

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/settings"
)

// Retention settings and windows.
const (
	DefaultRetentionDays = 90
	MinRetentionDays     = 7
	MaxRetentionDays     = 730
	// OrphanRetention is how long a certificate no endpoint presents is kept after it was last seen.
	OrphanRetention = 7 * 24 * time.Hour
	// StaleScanAfter is how long after its start a running scan is certainly dead: no scan runs past its cap.
	StaleScanAfter = MaxScanDuration + 15*time.Minute
)

// RetentionStats counts what one retention run removed or ended.
type RetentionStats struct {
	Interrupted  int64 // running scans left by a dead run, ended as failed (discovery.scan_interrupted)
	Endpoints    int64 // gone endpoints older than the retention, and every endpoint of a deleted scope
	Certificates int64 // certificates no endpoint presents, not seen for OrphanRetention
	Scans        int64 // finished scans beyond the ones kept per scope
}

// Retain runs the retention at now, in one transaction: running scans past StaleScanAfter end as interrupted; gone
// endpoints whose gone_since is older than the retention (setting discovery.retention_days, absent: 90 days) and every
// endpoint of a deleted scope are deleted; then the certificates no endpoint refers to (as leaf or in its chain) and
// not seen for OrphanRetention; then the finished scans beyond the newest KeepScans per scope that are older than
// KeepScansFor.
func (s *PGStore) Retain(ctx context.Context, now time.Time) (RetentionStats, error) {
	var st RetentionStats
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		days := DefaultRetentionDays
		if _, err := settings.Get(ctx, tx, SettingRetentionDays, &days); err != nil {
			return wrap("read the retention", err)
		}
		days = min(max(days, MinRetentionDays), MaxRetentionDays)
		rows, err := tx.Query(ctx, `UPDATE discovery_scans SET state = 'failed', error_code = $2, finished_at = $1
WHERE state = 'running' AND started_at < $3 RETURNING id, scope_id`, now, ReasonInterrupted, now.Add(-StaleScanAfter))
		if err != nil {
			return wrap("end the stale scans", err)
		}
		ended, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Finish, error) {
			f := Finish{Now: now, State: ScanFailed, ErrorCode: ReasonInterrupted}
			return f, r.Scan(&f.ScanID, &f.ScopeID)
		})
		if err != nil {
			return wrap("end the stale scans", err)
		}
		for _, f := range ended {
			if err := s.finished(ctx, tx, f); err != nil {
				return err
			}
		}
		st.Interrupted = int64(len(ended))
		steps := []struct {
			n    *int64
			what string
			sql  string
			args []any
		}{
			{&st.Endpoints, "delete the old endpoints", `DELETE FROM discovery_endpoints e USING discovery_scopes s
WHERE s.id = e.scope_id AND (s.deleted_at IS NOT NULL OR (e.state = 'gone' AND e.gone_since < $1))`, []any{now.AddDate(0, 0, -days)}},
			{&st.Certificates, "delete the orphan certificates", `DELETE FROM discovery_certificates c WHERE c.last_seen < $1
AND NOT EXISTS (SELECT 1 FROM discovery_endpoints e WHERE e.fingerprint_sha256 = c.fingerprint_sha256)
AND NOT EXISTS (SELECT 1 FROM discovery_endpoints e WHERE e.chain_fingerprints @> ARRAY[c.fingerprint_sha256])`, []any{now.Add(-OrphanRetention)}},
		}
		for _, step := range steps {
			tag, err := tx.Exec(ctx, step.sql, step.args...)
			if err != nil {
				return wrap(step.what, err)
			}
			*step.n = tag.RowsAffected()
		}
		st.Scans, err = pruneScans(ctx, tx, uuid.Nil, now)
		return err
	})
	if err != nil {
		return RetentionStats{}, err
	}
	return st, nil
}
