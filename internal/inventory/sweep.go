package inventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// liveRecoveryJob is the condition, on a jobs row r, of a recovery job that is still live: queued,
// running, or held (a recovery is ClassAlways and is never held by the license, but a held one would
// still be live). The sweep (sweepWhere) and RequestRecovery (requestRecoveryLocked) use this one
// list, so neither queues a recovery while the other sees one live.
const liveRecoveryJob = `r.status IN ('queued', 'running', 'blocked_license')`

// sweepWhere selects the deployments the sweep handles ($1 now, $2 the recovery dedupe prefix):
// unfinished, their job not running, no live recovery job, and either on a deleted server, or
// possibly sent with recover_after passed, or never sent with a job that ended (or was pruned). A
// held (blocked_license) or still queued job of a deployment that never sent anything is left.
const sweepWhere = `FROM deployments d
JOIN targets t ON t.id = d.target_id
LEFT JOIN jobs j ON j.id = d.job_id
WHERE d.state <> 'done'
  AND (j.status IS NULL OR j.status <> 'running')
  AND NOT EXISTS (SELECT 1 FROM jobs r WHERE r.dedupe_key = $2 || d.id::text AND ` + liveRecoveryJob + `)
  AND (t.deleted_at IS NOT NULL
    OR (d.state IN ('deploying', 'recovering') AND (d.recover_after IS NULL OR d.recover_after <= $1))
    OR (d.state IN ('queued', 'precheck') AND (j.status IS NULL OR j.status NOT IN ('queued', 'blocked_license'))))`

// SweepDeployments makes sure no deployment is left unfinished unnoticed (R38 item 8; the
// periodic task deployment.recovery_sweep, ClassAlways: it runs in lock too). It picks at most
// sweepBatch deployments, oldest first (a short statement that skips rows another transaction
// holds), then handles each in a transaction of its own, after locking it and checking again that
// it still qualifies (another process's sweep may have handled it meanwhile):
//
//   - its server was deleted: it ends (deployment.target_deleted): failed when nothing was sent,
//     rollback_failed when a send may have happened (deployment.outcome_unknown email);
//   - nothing was sent (queued, precheck, or no operation id recorded) and its job ended without
//     ending it (dead, failed, cancelled, succeeded) or was pruned: it ends failed with the job's
//     error code when that fits the column (else deployment.interrupted);
//   - a send may have happened (deploying or recovering with an operation id) and recover_after
//     has passed: a recovery job is queued as RequestRecovery does; after MaxRecoveryAttempts it
//     ends rollback_failed (deployment.recovery_exhausted, deployment.outcome_unknown email).
//
// One deployment's error is logged with its id and does not stop the others (they still count);
// the run then returns an error naming how many failed, and the next run tries them again. Each
// transaction locks the deployment, then appends to jobs (its foreign key takes KEY SHARE on the
// target) before its audit rows, so it never holds the audit lock while waiting for a target.
func (s *Service) SweepDeployments(ctx context.Context) (int, error) {
	now := s.clock.Now().UTC()
	var ids []uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id `+sweepWhere+`
ORDER BY d.created_at, d.id LIMIT $3 FOR UPDATE OF d SKIP LOCKED`, now, recoverDedupePrefix, sweepBatch)
		if err != nil {
			return fmt.Errorf("inventory: find unfinished deployments: %w", err)
		}
		ids, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return fmt.Errorf("inventory: find unfinished deployments: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	n, failed := 0, 0
	for _, id := range ids {
		handled, err := s.sweepDeployment(ctx, id, now)
		if err != nil {
			failed++
			s.log.Error("could not sweep an unfinished deployment", "deployment_id", id.String(), "error_type", fmt.Sprintf("%T", err))
			continue
		}
		if handled {
			n++
		}
	}
	if failed > 0 {
		return n, fmt.Errorf("inventory: %d unfinished deployments could not be swept", failed)
	}
	return n, nil
}

// sweepDeployment handles one deployment in its own transaction; false when it no longer
// qualifies or another transaction holds it.
func (s *Service) sweepDeployment(ctx context.Context, id uuid.UUID, now time.Time) (bool, error) {
	handled := false
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var (
			deleted   bool
			jobStatus *string
			jobCode   string
		)
		d, err := scanLocked(tx.QueryRow(ctx, `SELECT `+lockedDeploymentColumns+`, t.deleted_at IS NOT NULL, j.status, coalesce(j.last_error_code, '')
`+sweepWhere+` AND d.id = $3
FOR NO KEY UPDATE OF d SKIP LOCKED`, now, recoverDedupePrefix, id), &deleted, &jobStatus, &jobCode)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		handled = true
		return s.sweepOne(ctx, tx, d, deleted, jobStatus, jobCode)
	})
	return handled, err
}

func (s *Service) sweepOne(ctx context.Context, tx pgx.Tx, d lockedDeployment, deleted bool, jobStatus *string, jobCode string) error {
	switch {
	case deleted:
		status := DeployStatusFailed
		if d.wasSent() {
			status = DeployStatusRollbackFailed
		}
		return s.finishLocked(ctx, tx, d, DeploymentFinish{Status: status, ErrorCode: "deployment.target_deleted"})
	case !d.wasSent():
		// Nothing was sent (a row in deploying or recovering without an operation id was not
		// written by Alice's engine and counts as never sent): failed, with the code of the job
		// that ended without ending it.
		code := interruptedCode
		if jobStatus != nil && *jobStatus != "queued" && *jobStatus != "blocked_license" {
			code = sanitizeCode(jobCode, interruptedCode)
		}
		return s.finishLocked(ctx, tx, d, DeploymentFinish{Status: DeployStatusFailed, ErrorCode: code})
	case d.attempts >= MaxRecoveryAttempts:
		return s.finishLocked(ctx, tx, d, DeploymentFinish{Status: DeployStatusRollbackFailed, ErrorCode: "deployment.recovery_exhausted"})
	}
	_, err := s.requestRecoveryLocked(ctx, tx, d)
	return err
}
