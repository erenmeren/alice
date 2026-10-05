package sshkeys

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// Reconciling unfinished deploy sends (controller ruling after the job handlers' fix round): a deploy job
// killed on its last attempt, or held and discarded after a send was recorded, never reaches its
// handler again, so a line may be on the server with a send on record and no outcome. The hourly task
// (DestroyRetiredKeys) finds such deploys and, once no send of theirs can still land (the S3 wait after
// the latest send), records the truth as far as it is known (sshkey.add_outcome_unknown) and queues a
// scan of the server, which brings the record in line with the file. It removes nothing from any server.
// The audit row is the mark: a request is reconciled exactly once.

const (
	// reconcileWindow bounds the jobs the task looks at: deploy jobs that finished this recently. The
	// task runs every hour; a deploy needs it minutes after its job ended.
	reconcileWindow = 7 * 24 * time.Hour
	// maxReconcileBatch bounds the jobs of one run (the rest waits for the next run).
	maxReconcileBatch = 1000
)

// finishActions are the audit actions that end a deploy's record: FinishDeploy's outcome (a line
// recorded, or a failure) and a reconciliation.
var finishActions = []string{"sshkey.added", "sshkey.add_failed", "sshkey.add_outcome_unknown"}

// reconcileDeploySends reconciles every deploy job that ended in the window with a send on record and no
// outcome, once the wait after its latest send is over.
func (s *Service) reconcileDeploySends(ctx context.Context) error {
	now := s.clock.Now().UTC()
	ids, err := s.unfinishedDeploys(ctx, now)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if err := s.reconcileDeploy(ctx, id); err != nil {
			s.log.Error("could not reconcile a deploy's send", "job_id", id.String(), "error_type", fmt.Sprintf("%T", err))
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// unfinishedDeploys lists the candidates: deploy jobs no longer live that ended in the window (index
// jobs_finished), whose record has a send and no finish, and whose latest send's wait is over. Their
// rows are read in one range scan of the audit log's primary key (from the oldest job's creation less
// sendLookupMargin).
func (s *Service) unfinishedDeploys(ctx context.Context, now time.Time) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		type ended struct {
			ID      uuid.UUID
			Created time.Time
		}
		rows, _ := tx.Query(ctx, `SELECT id, created_at FROM jobs WHERE finished_at >= $1 AND type = $2
  AND status IN ('succeeded', 'failed', 'cancelled', 'dead') ORDER BY finished_at, id LIMIT $3`, now.Add(-reconcileWindow), JobDeploy,
			maxReconcileBatch)
		jobsEnded, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ended])
		if err != nil || len(jobsEnded) == 0 {
			return err
		}
		ids, oldest := make([]string, 0, len(jobsEnded)), jobsEnded[0].Created
		for _, j := range jobsEnded {
			ids = append(ids, j.ID.String())
			if j.Created.Before(oldest) {
				oldest = j.Created
			}
		}
		floor, err := auditFloor(ctx, tx, oldest.Add(-sendLookupMargin))
		if err != nil {
			return err
		}
		type entry struct{ ID, Action, SentAt string }
		arows, _ := tx.Query(ctx, `SELECT request_id, action, coalesce(details->>'sent_at', '') FROM audit_log
WHERE seq > $1 AND request_id = ANY ($2) AND action = ANY ($3) ORDER BY seq`, floor, ids,
			append([]string{"sshkey.add_sent"}, finishActions...))
		entries, err := pgx.CollectRows(arows, pgx.RowToStructByPos[entry])
		if err != nil {
			return err
		}
		last, done := map[string]time.Time{}, map[string]bool{}
		for _, en := range entries {
			if en.Action != "sshkey.add_sent" {
				done[en.ID] = true
			} else if at, err := time.Parse(time.RFC3339Nano, en.SentAt); err == nil {
				last[en.ID] = at
			}
		}
		for _, id := range ids {
			if at, sent := last[id]; sent && !done[id] && !now.Before(at.Add(s.undoWait())) {
				out = append(out, uuid.MustParse(id))
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sshkeys: list ended deploys: %w", err)
	}
	return out, nil
}

// reconcileDeploy reconciles one deploy under its job row's lock (FOR UPDATE: a run of the job that
// comes back waits at its claim check, and a second reconciliation sees the first one's row), after
// checking again that the job is not live, that its record has a send and no finish, and that the wait
// after the latest send is over.
func (s *Service) reconcileDeploy(ctx context.Context, jobID uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var status string
		var target uuid.UUID
		if err := tx.QueryRow(ctx, "SELECT status, target_id FROM jobs WHERE id = $1 FOR UPDATE", jobID).Scan(&status, &target); err != nil {
			return fmt.Errorf("sshkeys: lock the deploy's job: %w", err)
		}
		if status == "queued" || status == "running" || status == "blocked_license" {
			return nil
		}
		rows, err := deployRows(ctx, tx, jobID, append([]string{"sshkey.add_sent", "sshkey.add_answered"}, finishActions...)...)
		if err != nil {
			return err
		}
		var sent deployRow
		for _, r := range rows {
			if slices.Contains(finishActions, r.action) {
				return nil // finished or reconciled meanwhile
			}
			if r.action == "sshkey.add_sent" {
				sent = r
			}
		}
		rec, err := sendRecord(rows)
		if err != nil {
			return err
		}
		if rec.Count == 0 || s.clock.Now().UTC().Before(rec.LastAt.Add(s.undoWait())) {
			return nil
		}
		answer := "none"
		switch {
		case rec.AnsweredAdded:
			answer = answerAdded
		case rec.AnsweredPresent:
			answer = answerPresent
		}
		coverage := string(rec.FirstCoverage)
		if coverage == "" {
			coverage = "none"
		}
		actor := audit.SystemActor("jobs")
		actor.RequestID = jobID.String()
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "sshkey.add_outcome_unknown", ObjectType: "ssh_key",
			ObjectID: sent.keyID, Result: audit.Failure, Details: map[string]string{"ssh_key_id": sent.keyID, "target_id": target.String(),
				"os_user": sent.osUser, "file_path": sent.filePath, "job_id": jobID.String(), "job_status": status,
				"send_count": strconv.Itoa(rec.Count), "last_sent_at": rec.LastAt.Format(time.RFC3339Nano), "coverage_before": coverage,
				"absent_before": strconv.FormatBool(rec.AbsentBefore), "answer": answer, "owned": strconv.FormatBool(rec.Owned())}}); err != nil {
			return err
		}
		return s.queueDiscovery(ctx, tx, target)
	})
}
