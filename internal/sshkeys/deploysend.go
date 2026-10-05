package sshkeys

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
)

// The durable send record of a deploy job (store request S-1). A deploy has no row of its own (its
// request is the queued job, whose payload the queue MACs), so every send is an append-only audit row
// sshkey.add_sent written in a claim-fenced transaction BEFORE the helper call: ssh_key_id, target_id,
// os_user, file_path, job_id, send_count, sent_at (the injected clock, RFC 3339 with nanoseconds). The
// job learns from it whether a send by THIS job is on record (a line found on a retry is its own only
// then) and when an undo may start (S3).

// DeploySend is the answer of BeginDeploySend.
type DeploySend struct {
	OperationID uuid.UUID // the operation id to send with (the job id: a re-send keeps it)
	SentAt      time.Time
	Resend      bool // an earlier send by this job is on record
	Count       int  // sends on record, this one included
}

// DeploySendRecord is what is on record of a job's sends.
type DeploySendRecord struct {
	Count                   int
	FirstAt, PrevAt, LastAt time.Time // zero when none (PrevAt: the send before the last)
}

// UndoNotBefore is when an undo of the job's line may start (S3): the latest send that has no
// definite answer + wait. latestAnswered says whether the handler holds a definite answer to the
// latest send; then the one before it is the latest that may still be running. Zero: no wait.
func (r DeploySendRecord) UndoNotBefore(wait time.Duration, latestAnswered bool) time.Time {
	switch {
	case r.Count == 0:
		return time.Time{}
	case !latestAnswered:
		return r.LastAt.Add(wait)
	case r.Count > 1:
		return r.PrevAt.Add(wait)
	}
	return time.Time{}
}

// UndoWait is how long after an unanswered add send its undo waits: the helper's budget plus 30 s
// (S3). Deploy and rotation handlers use it instead of copying the grace.
func (s *Service) UndoWait() time.Duration { return s.undoWait() }

// BeginDeploySend records a send of the deploy job before the helper call (claim-fenced: a job that
// lost its lease records nothing and must not send). The job's row lock (the claim check takes it)
// serializes the count.
func (s *Service) BeginDeploySend(ctx context.Context, jobID uuid.UUID, d DeployJob) (DeploySend, error) {
	var out DeploySend
	err := s.storeTx(ctx, func(tx pgx.Tx) error {
		rec, err := deploySends(ctx, tx, jobID)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		out = DeploySend{OperationID: jobID, SentAt: now, Resend: rec.Count > 0, Count: rec.Count + 1}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobActor(ctx), Action: "sshkey.add_sent", ObjectType: "ssh_key",
			ObjectID: d.KeyID.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": d.KeyID.String(),
				"target_id": d.TargetID.String(), "os_user": d.OSUser, "file_path": d.FilePath, "job_id": jobID.String(),
				"send_count": strconv.Itoa(out.Count), "sent_at": now.Format(time.RFC3339Nano)}})
		return err
	})
	if err != nil {
		return DeploySend{}, err
	}
	return out, nil
}

// DeploySends reads what is on record of the job's sends.
func (s *Service) DeploySends(ctx context.Context, jobID uuid.UUID) (DeploySendRecord, error) {
	var out DeploySendRecord
	err := s.storeTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = deploySends(ctx, tx, jobID)
		return err
	})
	return out, err
}

func deploySends(ctx context.Context, tx pgx.Tx, jobID uuid.UUID) (DeploySendRecord, error) {
	rows, err := tx.Query(ctx, `SELECT details->>'sent_at' FROM audit_log WHERE action = 'sshkey.add_sent' AND details->>'job_id' = $1
ORDER BY seq`, jobID.String())
	if err != nil {
		return DeploySendRecord{}, fmt.Errorf("sshkeys: read the deploy's sends: %w", err)
	}
	defer rows.Close()
	var r DeploySendRecord
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return DeploySendRecord{}, fmt.Errorf("sshkeys: read the deploy's sends: %w", err)
		}
		at, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return DeploySendRecord{}, fmt.Errorf("sshkeys: read the deploy's sends: %w", err)
		}
		if r.Count == 0 {
			r.FirstAt = at.UTC()
		}
		r.PrevAt, r.LastAt = r.LastAt, at.UTC()
		r.Count++
	}
	return r, rows.Err()
}
