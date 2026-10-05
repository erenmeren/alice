package sshkeys

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// Reconciling unfinished deploy sends (controller rulings after the job handlers' fix round and the
// combined re-review, N-I1, N-m1, N-m3): a deploy job killed on its last attempt, or held and discarded
// after a send was recorded, never reaches its handler again, so a line may be on the server with a send
// on record and no outcome. The same holds for a deploy whose last attempt ended undo_failed or
// uncertain (its line's state is not known and its scan must wait for a stalled write). The hourly task
// (DestroyRetiredKeys) finds such deploys and, once no send of theirs can still land (the S3 wait after
// the latest send), records the truth as far as it is known (sshkey.add_outcome_unknown) and queues a
// scan of the server. It removes nothing from any server.
//
// There is no age limit: the task walks every ended deploy job once, oldest first, with a durable cursor
// (finished_at, id) in the settings table, so a deploy that ended before a licence lock or a downtime of
// any length is reconciled when the task runs again, and a deploy already looked at is never read again.
// It does not run in licence lock: the scan it queues is read-only work, which the lock cancels; it
// catches up after the renewal (and the task itself, a read-only job, does not run in lock).
// The audit row marks the request: a job that comes back and ends again is not reconciled twice.

const (
	// reconcileCursorKey is the settings key of the cursor: the (finished_at, id) of the last ended deploy
	// job the task has looked at.
	reconcileCursorKey = "sshkeys.deploy_reconcile_cursor"
	// reconcileSettle is how long after a job's finished_at the task waits before it looks at it: longer
	// than the S3 wait after its last send (the send precedes the finish), and long enough that a job
	// finished with an earlier timestamp has committed before the cursor passes it.
	reconcileSettle = time.Hour
	// reconcilePage is how many ended jobs one read takes; maxReconcilePages bounds the reads of one run.
	reconcilePage     = 500
	maxReconcilePages = 100
)

// reconcileBatch bounds the deploys one run reconciles (unreconciled ones only: finished deploys do not
// count; N-m3). The rest waits for the next run, which continues from the cursor. A variable for tests.
var reconcileBatch = 1000

// finishActions are the audit actions that end a deploy's record: FinishDeploy's outcome (a line
// recorded, or a failure) and a reconciliation. A failure with an unsettled reason does not end it.
var finishActions = []string{"sshkey.added", "sshkey.add_failed", "sshkey.add_outcome_unknown"}

// unsettledFailures are the sshkey.add_failed reasons after which the line's state is not known (the
// handler's undo failed, or the add's answer was lost and ownership was unknown): such a deploy is
// reconciled like one without an outcome (N-m1).
var unsettledFailures = []string{"sshkey.add_undo_failed", "sshkey.add_uncertain"}

// finishes reports whether an audit row ends a deploy's record.
func finishes(action, reason string) bool {
	return slices.Contains(finishActions, action) && (action != "sshkey.add_failed" || !slices.Contains(unsettledFailures, reason))
}

// reconcileCursor is the position of the walk.
type reconcileCursor struct {
	FinishedAt time.Time `json:"finished_at"`
	ID         uuid.UUID `json:"id"`
}

// endedDeploy is one ended deploy job of a page.
type endedDeploy struct {
	ID       uuid.UUID
	Created  time.Time
	Finished time.Time
}

// reconcileDeploySends walks the ended deploy jobs from the cursor and reconciles every one with a send
// on record and no outcome, at most reconcileBatch per run.
func (s *Service) reconcileDeploySends(ctx context.Context) error {
	if s.license.Allow(license.ClassReadOnly) != nil {
		return nil // the scan would be cancelled: catch up after the renewal
	}
	var cur reconcileCursor
	if _, err := settings.Get(ctx, s.pool, reconcileCursorKey, &cur); err != nil {
		return fmt.Errorf("sshkeys: read the reconciliation cursor: %w", err)
	}
	done, start := 0, cur
	defer func() {
		if cur != start {
			if err := settings.Set(context.WithoutCancel(ctx), s.pool, reconcileCursorKey, cur, s.clock.Now()); err != nil {
				s.log.Error("could not store the reconciliation cursor", "error_type", fmt.Sprintf("%T", err))
			}
		}
	}()
	settle := s.clock.Now().UTC().Add(-max(reconcileSettle, s.undoWait()))
	for range maxReconcilePages {
		page, todo, err := s.endedDeploys(ctx, cur, settle)
		if err != nil {
			return err
		}
		for _, j := range page {
			if todo[j.ID] {
				if done >= reconcileBatch {
					return nil
				}
				waiting, err := s.reconcileDeploy(ctx, j.ID)
				if err != nil {
					s.log.Error("could not reconcile a deploy's send", "job_id", j.ID.String(), "error_type", fmt.Sprintf("%T", err))
					return err // the cursor stays before it: the next run tries again
				}
				if waiting {
					return nil // its wait is not over (a clock step): the next run looks again
				}
				done++
			}
			cur = reconcileCursor{FinishedAt: j.Finished, ID: j.ID}
		}
		if len(page) < reconcilePage {
			break
		}
	}
	return nil
}

// endedDeploys reads the next page of ended deploy jobs after the cursor that finished before settle
// (index jobs_finished), and which of them need a reconciliation: a send on record and no finishing row.
// Their audit rows are read in one range scan of the audit log's primary key (from the oldest job's
// creation less sendLookupMargin).
func (s *Service) endedDeploys(ctx context.Context, cur reconcileCursor, settle time.Time) ([]endedDeploy, map[uuid.UUID]bool, error) {
	var page []endedDeploy
	todo := map[uuid.UUID]bool{}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, _ := tx.Query(ctx, `SELECT id, created_at, finished_at FROM jobs
WHERE finished_at <= $1 AND (finished_at, id) > ($2, $3) AND type = $4 AND status IN ('succeeded', 'failed', 'cancelled', 'dead')
ORDER BY finished_at, id LIMIT $5`, settle, cur.FinishedAt, cur.ID, JobDeploy, reconcilePage)
		var err error
		if page, err = pgx.CollectRows(rows, pgx.RowToStructByPos[endedDeploy]); err != nil || len(page) == 0 {
			return err
		}
		ids, oldest := make([]string, 0, len(page)), page[0].Created
		for _, j := range page {
			ids = append(ids, j.ID.String())
			if j.Created.Before(oldest) {
				oldest = j.Created
			}
		}
		floor, err := auditFloor(ctx, tx, oldest.Add(-sendLookupMargin))
		if err != nil {
			return err
		}
		type entry struct{ ID, Action, Reason string }
		arows, _ := tx.Query(ctx, `SELECT request_id, action, coalesce(details->>'reason', '') FROM audit_log
WHERE seq > $1 AND request_id = ANY ($2) AND action = ANY ($3) ORDER BY seq`, floor, ids, append([]string{"sshkey.add_sent"}, finishActions...))
		entries, err := pgx.CollectRows(arows, pgx.RowToStructByPos[entry])
		if err != nil {
			return err
		}
		sent, done := map[string]bool{}, map[string]bool{}
		for _, en := range entries {
			if en.Action == "sshkey.add_sent" {
				sent[en.ID] = true
			} else if finishes(en.Action, en.Reason) {
				done[en.ID] = true
			}
		}
		for _, j := range page {
			todo[j.ID] = sent[j.ID.String()] && !done[j.ID.String()]
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("sshkeys: list ended deploys: %w", err)
	}
	return page, todo, nil
}

// reconcileDeploy reconciles one deploy under its job row's lock (FOR UPDATE: a run of the job that
// comes back waits at its claim check, and a concurrent reconciliation then sees the first one's row),
// after checking again that the job is not live, that its record has a send and no finishing row, and
// that the wait after the latest send is over. waiting reports a wait that is not over yet.
func (s *Service) reconcileDeploy(ctx context.Context, jobID uuid.UUID) (waiting bool, err error) {
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		waiting = false
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
		lastReason := ""
		record := rows[:0:0]
		for _, r := range rows {
			switch {
			case finishes(r.action, r.reason):
				return nil // finished or reconciled meanwhile
			case r.action == "sshkey.add_failed":
				lastReason = r.reason // an unsettled failure: reconciled, and named
				continue
			case r.action == "sshkey.add_sent":
				sent = r
			}
			record = append(record, r)
		}
		rec, err := sendRecord(record)
		if err != nil {
			return err
		}
		if rec.Count == 0 {
			return nil
		}
		if s.clock.Now().UTC().Before(rec.LastAt.Add(s.undoWait())) {
			waiting = true
			return nil
		}
		answer := "none"
		switch {
		case rec.AnsweredAdded:
			answer = answerAdded
		case rec.AnsweredPresent:
			answer = answerPresent
		case rec.NotWritten == rec.Count:
			answer = answerNotWritten
		}
		if lastReason == "" {
			lastReason = "none"
		}
		actor := audit.SystemActor("jobs")
		actor.RequestID = jobID.String()
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "sshkey.add_outcome_unknown", ObjectType: "ssh_key",
			ObjectID: sent.keyID, Result: audit.Failure, Details: map[string]string{"ssh_key_id": sent.keyID, "target_id": target.String(),
				"os_user": sent.osUser, "file_path": sent.filePath, "job_id": jobID.String(), "job_status": status,
				"send_count": strconv.Itoa(rec.Count), "last_sent_at": rec.LastAt.Format(time.RFC3339Nano),
				"coverage_before": coverageText(rec.FirstCoverage), "absent_before": strconv.FormatBool(rec.AbsentBefore), "answer": answer,
				"owned": strconv.FormatBool(rec.Owned()), "last_reason": lastReason}}); err != nil {
			return err
		}
		return s.queueDiscovery(ctx, tx, target)
	})
	return waiting, err
}
