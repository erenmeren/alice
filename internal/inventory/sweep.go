package inventory

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// SweepDeployments makes sure no deployment is left unfinished unnoticed (R38 item 8; the
// periodic task deployment.recovery_sweep, ClassAlways: it runs in lock too). One transaction
// takes at most sweepBatch unfinished deployments, oldest first, whose job is not running and
// that have no live recovery job, under FOR UPDATE OF d SKIP LOCKED (a deployment another
// transaction holds, such as another process's sweep, is left to it), and per deployment:
//
//   - its server was deleted: it ends (deployment.target_deleted): failed when nothing was sent
//     (queued, precheck), rollback_failed when a send may have happened (the files may hold
//     either certificate; the Administrators are emailed);
//   - queued or precheck (nothing was sent) whose job ended without ending it (dead, failed,
//     cancelled, succeeded) or was pruned: it ends failed with the job's error code when that
//     fits the column (else deployment.interrupted); a job held for confirmation in lock
//     (blocked_license) or still queued is left alone;
//   - deploying or recovering (a send may have happened) once recover_after has passed: a
//     recovery job is queued as RequestRecovery does (recover_after = now + RecoveryRetryInterval,
//     the attempt counted, needs_attention and its single email after RecoveryAttentionAfter
//     attempts); after MaxRecoveryAttempts it ends rollback_failed (deployment.recovery_exhausted)
//     and asks for manual action.
//
// Every change is audited in the same transaction as RequestRecovery and FinishDeployment do. The
// sweep is idempotent (a deployment it handled has a live recovery job and a recover_after ahead,
// or is done) and safe to run concurrently. It returns how many deployments it handled.
func (s *Service) SweepDeployments(ctx context.Context) (int, error) {
	n := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		n = 0
		now := s.clock.Now().UTC()
		rows, err := tx.Query(ctx, `SELECT `+lockedDeploymentColumns+`, t.deleted_at IS NOT NULL, j.status, coalesce(j.last_error_code, '')
FROM deployments d
JOIN targets t ON t.id = d.target_id
LEFT JOIN jobs j ON j.id = d.job_id
WHERE d.state <> 'done'
  AND (j.status IS NULL OR j.status <> 'running')
  AND NOT EXISTS (SELECT 1 FROM jobs r WHERE r.dedupe_key = $3 || d.id::text AND r.status IN ('queued', 'running'))
  AND (t.deleted_at IS NOT NULL
    OR (d.state IN ('deploying', 'recovering') AND (d.recover_after IS NULL OR d.recover_after <= $1))
    OR (d.state IN ('queued', 'precheck') AND (j.status IS NULL OR j.status NOT IN ('queued', 'blocked_license'))))
ORDER BY d.created_at, d.id
LIMIT $2
FOR UPDATE OF d SKIP LOCKED`, now, sweepBatch, recoverDedupePrefix)
		if err != nil {
			return fmt.Errorf("inventory: find unfinished deployments: %w", err)
		}
		type found struct {
			d         lockedDeployment
			deleted   bool
			jobStatus *string
			jobCode   string
		}
		var list []found
		for rows.Next() {
			var x found
			if x.d, err = scanLocked(rows, &x.deleted, &x.jobStatus, &x.jobCode); err != nil {
				rows.Close()
				return err
			}
			list = append(list, x)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("inventory: find unfinished deployments: %w", err)
		}
		for _, x := range list {
			if err := s.sweepOne(ctx, tx, x.d, x.deleted, x.jobStatus, x.jobCode); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

func (s *Service) sweepOne(ctx context.Context, tx pgx.Tx, d lockedDeployment, deleted bool, jobStatus *string, jobCode string) error {
	nothingSent := d.state == DeployStateQueued || d.state == DeployStatePrecheck
	switch {
	case deleted:
		status := DeployStatusRollbackFailed
		if nothingSent {
			status = DeployStatusFailed
		}
		return s.finishLocked(ctx, tx, d, DeploymentFinish{Status: status, ErrorCode: "deployment.target_deleted"})
	case nothingSent:
		code := interruptedCode
		if jobStatus != nil {
			code = sanitizeCode(jobCode, interruptedCode)
		}
		return s.finishLocked(ctx, tx, d, DeploymentFinish{Status: DeployStatusFailed, ErrorCode: code})
	case d.attempts >= MaxRecoveryAttempts:
		return s.finishLocked(ctx, tx, d, DeploymentFinish{Status: DeployStatusRollbackFailed, ErrorCode: "deployment.recovery_exhausted"})
	}
	_, err := s.requestRecoveryLocked(ctx, tx, d)
	return err
}
