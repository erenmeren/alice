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
	"alice/internal/inventory"
	"alice/internal/providers"
)

// The durable send record of a deploy job (store request S-1; fix round 4: A-I1, A-m6, A-m7). A deploy
// has no row of its own (its request is the queued job, whose payload the queue MACs) and the migration
// is closed, so the record is append-only audit rows, written in claim-fenced transactions:
//   - sshkey.add_sent, before every helper add: ssh_key_id, target_id, os_user, file_path, job_id,
//     attempt, send_count, sent_at (the injected clock, RFC 3339 with nanoseconds), and the FIRST send's
//     pre-send evidence: coverage_before (the listing's coverage of the deploy's file; "none" when no
//     listing) and absent_before (that listing read the file completely and the line was not in it).
//     A re-send repeats the first send's evidence; its own listing does not change it.
//   - sshkey.add_answered, when the helper answered an add: send_count and answer ("added" or
//     "already_present").
//
// The job learns from it whether a line found in the file is its own (DeploySendRecord.Owned) and when
// an undo may start (S3). Every row's request_id is the job id (the claim's).

// ErrNoJobClaim: a deploy's send or answer is recorded only by the job run that holds the deploy's job
// (the context's claim names that job, and the job is the sshkey.add of this deploy). Nothing was
// written. A caller bug, never a lost lease (that is inventory.ErrClaimLost).
var ErrNoJobClaim = errors.New("sshkeys: a deploy's send is recorded only by the run that holds its job")

// ErrNoSendOnRecord: an answer names a send this job never recorded. Nothing was written.
var ErrNoSendOnRecord = errors.New("sshkeys: no such send of the deploy is on record")

// sendLookupMargin is how far before its job's creation the send lookup reads (a clock stepped back
// after the job was created). The lookup reads the audit rows from there on, by the primary key.
const sendLookupMargin = 24 * time.Hour

// Answers of the helper to an add (sshkey.add_answered).
const (
	answerAdded      = "added"
	answerPresent    = "already_present"
	answerNotWritten = "not_written" // the helper call failed definitely before any write step (N-m2)
)

// DeployEvidence is what a listing taken right before a deploy's send proved about the deploy's line
// (A-I1). The zero value is "no listing": nothing is known.
type DeployEvidence struct {
	Coverage providers.CoverageState // the listing's coverage of the deploy's (user, file); "" without a listing
	Absent   bool                    // the line is proven absent: Coverage is complete and no line holds the key
}

// DeployEvidenceFrom is the evidence of a listing (err: the listing failed) for d's line.
func DeployEvidenceFrom(l providers.KeyListing, err error, d DeployJob) DeployEvidence {
	if err != nil {
		return DeployEvidence{}
	}
	return DeployEvidence{Coverage: l.Coverage(d.OSUser, d.FilePath), Absent: l.Absent(d.OSUser, d.FilePath, d.Fingerprint)}
}

// clean keeps only a proof of absence that a complete coverage supports, and a known coverage state.
func (e DeployEvidence) clean() DeployEvidence {
	if !slices.Contains([]providers.CoverageState{providers.CoverageComplete, providers.CoverageUnread, providers.CoveragePartial,
		providers.CoverageUnknown}, e.Coverage) {
		e.Coverage = ""
	}
	e.Absent = e.Absent && e.Coverage == providers.CoverageComplete
	return e
}

// DeploySend is the answer of BeginDeploySend.
type DeploySend struct {
	OperationID uuid.UUID // the operation id to send with (the job id: a re-send keeps it)
	SentAt      time.Time
	Resend      bool             // an earlier send by this job is on record
	Count       int              // sends on record, this one included
	Record      DeploySendRecord // the record with this send
}

// DeploySendRecord is what is on record of a job's sends.
type DeploySendRecord struct {
	Count                   int
	FirstAt, PrevAt, LastAt time.Time // zero when none (PrevAt: the send before the last)
	// The pre-send evidence of the first send that may have written (a send not known to have written
	// nothing; kept by every later send): its listing's coverage of the file ("" without a listing) and
	// whether that listing proved the line absent. Zero while every send is known not written.
	FirstCoverage providers.CoverageState
	AbsentBefore  bool
	// The helper's recorded answers to this job's adds (RecordDeployAnswer).
	AnsweredAdded, AnsweredPresent bool
	// NotWritten counts the sends known to have written nothing (RecordDeployNotWritten).
	NotWritten int
}

// Owned reports whether a line of the key in the deploy's file is this job's own, so that the job may
// remove it again (A-I1 and N-m12, controller rulings). Ownership arises in exactly two ways:
//   - a send that may have written is on record, and the listing taken right before the FIRST such send
//     read the file completely and proved the line absent (AbsentBefore);
//   - the helper itself answered that a send of this job added the line (AnsweredAdded; accepted as proof
//     without a listing).
//
// It falls (false) when the helper answered that the line was already there (AnsweredPresent, unless a
// send of the job added it), and when every send on record is known to have written nothing
// (NotWritten == Count; N-m2: a key added by hand between two attempts is not the job's). Everything
// else (a line present before the first send that may have written, a listing that did not read the
// file completely, no listing, no send) is "not known to be ours": never removed.
func (r DeploySendRecord) Owned() bool {
	if r.Count-r.NotWritten <= 0 {
		return false
	}
	return r.AnsweredAdded || (r.AbsentBefore && r.FirstCoverage == providers.CoverageComplete && !r.AnsweredPresent)
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

// BeginDeploySend records a send without pre-send evidence (as BeginDeploySendWith with the zero
// DeployEvidence: a line found later is never this job's unless the helper answers that it wrote it).
func (s *Service) BeginDeploySend(ctx context.Context, jobID uuid.UUID, d DeployJob) (DeploySend, error) {
	return s.BeginDeploySendWith(ctx, jobID, d, DeployEvidence{})
}

// BeginDeploySendWith records a send of the deploy job before the helper call, with the evidence of the
// listing taken right before it (DeployEvidenceFrom). Ownership uses the evidence of the first send not
// known to have written nothing; later sends keep it. It is claim-fenced: the context's claim must name
// jobID, the sshkey.add job of d (ErrNoJobClaim otherwise), and a run that lost its lease records nothing
// (inventory.ErrClaimLost) and must not send. The claim check reads the job row FOR SHARE, which keeps the
// reaper from taking the job back until the row is committed; it does not serialize two holders, and
// needs not: one claim has one holder.
func (s *Service) BeginDeploySendWith(ctx context.Context, jobID uuid.UUID, d DeployJob, before DeployEvidence) (DeploySend, error) {
	c, err := deployClaim(ctx, jobID)
	if err != nil {
		return DeploySend{}, err
	}
	var out DeploySend
	err = s.storeTx(ctx, func(tx pgx.Tx) error {
		if err := checkDeployJob(ctx, tx, jobID, d); err != nil {
			return err
		}
		rows, err := deployRows(ctx, tx, jobID, "sshkey.add_sent", "sshkey.add_answered")
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		ev := before.clean()
		this := deployRow{action: "sshkey.add_sent", sentAt: now.Format(time.RFC3339Nano), listedCoverage: coverageText(ev.Coverage),
			listedAbsent: strconv.FormatBool(ev.Absent)}
		rec, err := sendRecord(append(rows, this))
		if err != nil {
			return err
		}
		out = DeploySend{OperationID: jobID, SentAt: now, Resend: rec.Count > 1, Count: rec.Count, Record: rec}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobActor(ctx), Action: "sshkey.add_sent", ObjectType: "ssh_key",
			ObjectID: d.KeyID.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": d.KeyID.String(),
				"target_id": d.TargetID.String(), "os_user": d.OSUser, "file_path": d.FilePath, "job_id": jobID.String(),
				"attempt": strconv.Itoa(c.Attempt), "send_count": strconv.Itoa(out.Count), "sent_at": this.sentAt,
				"coverage_listed": this.listedCoverage, "absent_listed": this.listedAbsent,
				"coverage_before": coverageText(rec.FirstCoverage), "absent_before": strconv.FormatBool(rec.AbsentBefore)}})
		return err
	})
	if err != nil {
		return DeploySend{}, err
	}
	return out, nil
}

// coverageText is a coverage state for an audit row ("none": no listing).
func coverageText(c providers.CoverageState) string {
	if c == "" {
		return "none"
	}
	return string(c)
}

// RecordDeployAnswer records the helper's definite answer to the add of send (added: the helper wrote
// the line; false: it was already there) and returns the record with it. "Already there" makes the
// line not the job's (Owned) unless a send of the job wrote it. Claim-fenced as BeginDeploySendWith;
// ErrNoSendOnRecord when the send is not on record.
func (s *Service) RecordDeployAnswer(ctx context.Context, d DeployJob, send DeploySend, added bool) (DeploySendRecord, error) {
	answer := answerPresent
	if added {
		answer = answerAdded
	}
	return s.recordAnswer(ctx, d, send, answer)
}

// RecordDeployNotWritten records that the add of send wrote nothing: the helper call failed definitely
// before any write step (the handler's definite no-change failure). That send then does not count for
// ownership (Owned; re-review N-m2): if every send is known not written, a line found later is not the
// job's, and the evidence of the next send decides. Claim-fenced as BeginDeploySendWith;
// ErrNoSendOnRecord when the send is not on record.
func (s *Service) RecordDeployNotWritten(ctx context.Context, d DeployJob, send DeploySend) (DeploySendRecord, error) {
	return s.recordAnswer(ctx, d, send, answerNotWritten)
}

// recordAnswer appends sshkey.add_answered for send and returns the record with it.
func (s *Service) recordAnswer(ctx context.Context, d DeployJob, send DeploySend, answer string) (DeploySendRecord, error) {
	c, ok := inventory.ClaimFrom(ctx)
	if !ok {
		return DeploySendRecord{}, ErrNoJobClaim
	}
	var rec DeploySendRecord
	err := s.storeTx(ctx, func(tx pgx.Tx) error {
		if err := checkDeployJob(ctx, tx, c.JobID, d); err != nil {
			return err
		}
		rows, err := deployRows(ctx, tx, c.JobID, "sshkey.add_sent", "sshkey.add_answered")
		if err != nil {
			return err
		}
		n := strconv.Itoa(send.Count)
		if rec, err = sendRecord(append(rows, deployRow{action: "sshkey.add_answered", answer: answer, sendCount: n})); err != nil {
			return err
		}
		if send.Count < 1 || send.Count > rec.Count { // an answer never changes the count
			return ErrNoSendOnRecord
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobActor(ctx), Action: "sshkey.add_answered", ObjectType: "ssh_key",
			ObjectID: d.KeyID.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": d.KeyID.String(),
				"target_id": d.TargetID.String(), "os_user": d.OSUser, "file_path": d.FilePath, "job_id": c.JobID.String(),
				"attempt": strconv.Itoa(c.Attempt), "send_count": n, "answer": answer,
				"answered_at": s.clock.Now().UTC().Format(time.RFC3339Nano)}})
		return err
	})
	if err != nil {
		return DeploySendRecord{}, err
	}
	return rec, nil
}

// DeploySends reads what is on record of the job's sends and answers.
func (s *Service) DeploySends(ctx context.Context, jobID uuid.UUID) (DeploySendRecord, error) {
	var out DeploySendRecord
	err := s.storeTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = deploySends(ctx, tx, jobID)
		return err
	})
	return out, err
}

// deployClaim is the context's claim when it names jobID (A-m7).
func deployClaim(ctx context.Context, jobID uuid.UUID) (inventory.Claim, error) {
	c, ok := inventory.ClaimFrom(ctx)
	if !ok || c.JobID != jobID {
		return inventory.Claim{}, ErrNoJobClaim
	}
	return c, nil
}

// checkDeployJob refuses a deploy that is not the one of the job (its sshkey.add job names the same key,
// server, user and file).
func checkDeployJob(ctx context.Context, tx pgx.Tx, jobID uuid.UUID, d DeployJob) error {
	var one int
	err := tx.QueryRow(ctx, `SELECT 1 FROM jobs WHERE id = $1 AND type = $2 AND target_id = $3 AND payload->>'ssh_key_id' = $4
  AND payload->>'os_user' = $5 AND payload->>'file_path' = $6`, jobID, JobDeploy, d.TargetID, d.KeyID.String(), d.OSUser, d.FilePath).Scan(&one)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNoJobClaim
	case err != nil:
		return fmt.Errorf("sshkeys: read the deploy's job: %w", err)
	}
	return nil
}

// auditFloor is the seq of the latest audit row older than at (0: none), the lower bound of a lookup
// of rows written since (A-m6). No index of audit_log serves a lookup by job (request_id or
// details->>'job_id'; the migration is closed): the bound is the primary key, walked backwards from the
// newest row over the rows written since at, as audit.Append reads the chain's head.
func auditFloor(ctx context.Context, tx pgx.Tx, at time.Time) (int64, error) {
	var seq int64
	if err := tx.QueryRow(ctx, "SELECT coalesce((SELECT seq FROM audit_log WHERE at < $1 ORDER BY seq DESC LIMIT 1), 0)", at).Scan(&seq); err != nil {
		return 0, fmt.Errorf("sshkeys: read the deploy's sends: %w", err)
	}
	return seq, nil
}

// deployRow is one row of a deploy's record.
type deployRow struct {
	action, sentAt, coverage, absent, answer, sendCount string
	listedCoverage, listedAbsent, reason                string
	keyID, osUser, filePath                             string
}

// deployRows reads the deploy record's rows of the job (actions), in order, from the audit rows written
// since the job's creation less sendLookupMargin: a range scan of the primary key (A-m6). An unknown job
// has none.
func deployRows(ctx context.Context, tx pgx.Tx, jobID uuid.UUID, actions ...string) ([]deployRow, error) {
	var created time.Time
	err := tx.QueryRow(ctx, "SELECT created_at FROM jobs WHERE id = $1", jobID).Scan(&created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sshkeys: read the deploy's job: %w", err)
	}
	floor, err := auditFloor(ctx, tx, created.Add(-sendLookupMargin))
	if err != nil {
		return nil, err
	}
	rows, _ := tx.Query(ctx, `SELECT action, coalesce(details->>'sent_at', ''), coalesce(details->>'coverage_before', ''),
    coalesce(details->>'absent_before', ''), coalesce(details->>'answer', ''), coalesce(details->>'send_count', ''),
    coalesce(details->>'coverage_listed', ''), coalesce(details->>'absent_listed', ''), coalesce(details->>'reason', ''),
    coalesce(details->>'ssh_key_id', ''), coalesce(details->>'os_user', ''), coalesce(details->>'file_path', '')
FROM audit_log WHERE seq > $1 AND request_id = $2 AND action = ANY ($3) AND details->>'job_id' = $2 ORDER BY seq`,
		floor, jobID.String(), actions)
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (deployRow, error) {
		var d deployRow
		err := r.Scan(&d.action, &d.sentAt, &d.coverage, &d.absent, &d.answer, &d.sendCount, &d.listedCoverage, &d.listedAbsent,
			&d.reason, &d.keyID, &d.osUser, &d.filePath)
		return d, err
	})
	if err != nil {
		return nil, fmt.Errorf("sshkeys: read the deploy's sends: %w", err)
	}
	return out, nil
}

func deploySends(ctx context.Context, tx pgx.Tx, jobID uuid.UUID) (DeploySendRecord, error) {
	rows, err := deployRows(ctx, tx, jobID, "sshkey.add_sent", "sshkey.add_answered")
	if err != nil {
		return DeploySendRecord{}, err
	}
	return sendRecord(rows)
}

// sendRecord folds a deploy's sshkey.add_sent and sshkey.add_answered rows into its record (rows of
// other actions are not passed). A send's own evidence is coverage_listed/absent_listed; a first send
// written before those keys existed (round 4) carries it as coverage_before/absent_before.
func sendRecord(rows []deployRow) (DeploySendRecord, error) {
	type send struct {
		ev         DeployEvidence
		notWritten bool
	}
	var r DeploySendRecord
	var sends []send
	for _, d := range rows {
		if d.action != "sshkey.add_sent" { // sshkey.add_answered
			switch d.answer {
			case answerAdded:
				r.AnsweredAdded = true
			case answerPresent:
				r.AnsweredPresent = true
			case answerNotWritten:
				if n, err := strconv.Atoi(d.sendCount); err == nil && n >= 1 && n <= len(sends) && !sends[n-1].notWritten {
					sends[n-1].notWritten = true
					r.NotWritten++
				}
			}
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, d.sentAt)
		if err != nil {
			return DeploySendRecord{}, fmt.Errorf("sshkeys: read the deploy's sends: %w", err)
		}
		cov, absent := d.listedCoverage, d.listedAbsent
		if cov == "" && len(sends) == 0 {
			cov, absent = d.coverage, d.absent
		}
		sends = append(sends, send{ev: DeployEvidence{Coverage: providers.CoverageState(cov), Absent: absent == "true"}.clean()})
		if r.Count == 0 {
			r.FirstAt = at.UTC()
		}
		r.PrevAt, r.LastAt = r.LastAt, at.UTC()
		r.Count++
	}
	for _, sd := range sends {
		if !sd.notWritten {
			r.FirstCoverage, r.AbsentBefore = sd.ev.Coverage, sd.ev.Absent
			break
		}
	}
	return r, nil
}
