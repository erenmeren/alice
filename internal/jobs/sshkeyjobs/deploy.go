package sshkeyjobs

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/keymat"
	"alice/internal/sshkeys/plan"
)

// Reasons and notes of the sshkey.add job besides the store's (Task 13 gives the reasons codes and texts;
// the notes are shown with rotation.note.<note>).
const (
	// reasonVerifyFailed: the file read back after the add is not what was written.
	reasonVerifyFailed = "sshkey.verify_failed"
	// reasonUndoFailed: Alice could not remove a line it had added (and whose login failed).
	reasonUndoFailed = "sshkey.add_undo_failed"
	// reasonUncertain: the add's answer was lost and its line is not in the file (yet): the job waits until
	// the helper's budget after the send has passed, then starts over (S3).
	reasonUncertain = "sshkey.add_uncertain"
	// noteLoginRefused: a line that was already there does not log in (Alice leaves it).
	noteLoginRefused = "login_refused"
	// noteLoginUnavailable: the test login could not connect.
	noteLoginUnavailable = "login_unavailable"
)

// addState is what the add answered.
type addState int

const (
	addPresent   addState = iota // the line was there and no send of this job is on record: Alice never removes it
	addOwned                     // this job's send put the line there (this attempt's, or one on record)
	addUncertain                 // the write was sent and its answer lost: only an accepted login proves the line
)

// deploy is the sshkey.add handler (C9's decision table). The deploy is read again from the database
// (DeployJob: every rule of the request applies to the current state); every send is recorded before it
// is made (BeginDeploySend, claim-fenced) and carries the job id as operation id; a test login with the
// new key as the user decides; a line this job sent and whose login failed is removed again by its
// fingerprint (the undo never names another key). A line found in the file is this job's only when a
// send of this job is on record (review I1): one that was there before is never removed. An undo waits
// until the store says no unanswered send of this job can still land (S3, DeploySendRecord.UndoNotBefore).
// Only ids and public facts reach the result.
func (h *handlers) deploy(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (res map[string]any, err error) {
	actor := systemActor(j)
	// The deploy's records are written only while this run still holds the job (review M8).
	ctx = inventory.WithClaim(ctx, inventory.Claim{JobID: j.ID, Attempt: j.Attempt})
	d, err := h.d.Keys.DeployJob(ctx, j.ID, j.TargetID, j.Payload)
	if err != nil {
		f := deployRefusal(err)
		if pd, ok := payloadDeploy(j); ok {
			h.failed(ctx, j, actor, pd, f)
		}
		return nil, f
	}
	// S3 (review I2): an earlier send of this job may still land until the store's wait after it has
	// passed (anchored on the durable send record, so a restart, a lost lease or a shutdown cannot shorten
	// it). Nothing is sent again before that: an undo after this attempt's send then never races a stalled
	// earlier one.
	prior, err := h.d.Keys.DeploySends(ctx, j.ID)
	if err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	if prior.Count > 0 {
		if wait := prior.LastAt.Add(h.d.Keys.UndoWait()).Sub(h.d.Clock.Now()); wait > 0 {
			return map[string]any{"result": "uncertain", "ssh_key_id": d.KeyID.String()}, jobs.RetryAfter(reasonUncertain, nil, nil, wait)
		}
	}
	sess, err := h.open(ctx, d.TargetID)
	if err != nil {
		h.failed(ctx, j, actor, d, err)
		return nil, err
	}
	defer h.close(sess)
	send, err := h.d.Keys.BeginDeploySend(ctx, j.ID, d)
	if err != nil {
		if errors.Is(err, inventory.ErrClaimLost) {
			return nil, jobs.Retry("job.lease_expired", nil, err)
		}
		return nil, jobs.Retry("internal.unexpected", nil, err) // nothing was sent
	}
	recorded := false
	defer func() {
		// M7: the last attempt ends after a send without a final record: audited, and a scan is queued so
		// that the record catches up with the file.
		var f *jobs.Failure
		if !recorded && errors.As(err, &f) && f.Class == jobs.Retryable && j.Attempt >= j.MaxAttempts {
			h.finish(ctx, actor, d, sshkeys.DeployOutcome{Result: sshkeys.DeployFailed, Reason: f.Reason})
			h.discover(ctx, d.TargetID)
		}
	}()
	rec := &writeTracker{next: steps}
	ares, err := sess.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: send.OperationID, OSUser: d.OSUser, FilePath: d.FilePath,
		Line: d.Line, ProtectedFingerprints: d.Protected}, rec)
	if ctx.Err() != nil {
		return nil, jobs.Retry("ssh.timeout", nil, ctx.Err()) // F-39: the next attempt starts over
	}
	var st addState
	switch {
	case err != nil && definiteNoChange(rec.wrote, ares, err):
		h.recordIfConnection(ctx, d.TargetID, err)
		f := jobs.FromProvider(err)
		if recorded = h.failed(ctx, j, actor, d, f); recorded && send.Resend {
			h.discover(ctx, d.TargetID) // an earlier send of this job may have landed (M7)
		}
		var rf *jobs.Failure
		if errors.As(f, &rf) && rf.Class == jobs.Retryable {
			// The next attempt sends again only after this send's wait (S3): retry then, not sooner.
			return nil, jobs.RetryAfter(rf.Reason, rf.Params, err, h.d.Keys.UndoWait())
		}
		return nil, f
	case err != nil:
		st = addUncertain // the add's uncertainty, not the connection's state: not recorded on the target
	case ares.Changed && !ares.Verified:
		// §13.4 step 5: the re-read after the write shows other content.
		return h.undoDeploy(ctx, j, actor, d, sess, steps, reasonVerifyFailed, true)
	case ares.Changed || send.Resend:
		st = addOwned
	default:
		st = addPresent
	}
	outcome, lerr := h.login(ctx, sess, d.OSUser, d.KeyID)
	if ctx.Err() != nil {
		return nil, jobs.Retry("ssh.timeout", nil, ctx.Err())
	}
	out := sshkeys.DeployOutcome{LineNo: ares.LineNo, Backup: ares.Backup}
	switch {
	case st == addPresent:
		out.Result, out.Note = sshkeys.DeployAlreadyPresent, presentNote(outcome, lerr, d.Options)
	case lerr == nil && outcome == providers.KeyLoginAccepted:
		out.Result = sshkeys.DeployVerified
	case st == addUncertain:
		// Only an accepted login proves an uncertain line (a refusal with from= or an unprovable login
		// proves nothing): it is removed again, once no send of this job can still land.
		return h.undoDeploy(ctx, j, actor, d, sess, steps, sshkeys.ReasonLoginFailed, false)
	case lerr != nil:
		out.Result, out.Note = sshkeys.DeployUnverified, noteLoginUnavailable
	case outcome == providers.KeyLoginUnprovable:
		out.Result, out.Note = sshkeys.DeployUnverified, sshkeys.NoteLoginWithoutKey
	case keymat.HasFromOption(d.Options):
		out.Result, out.Note = sshkeys.DeployUnverified, plan.NoteFromOption // Alice cannot know whether from= excludes her
	default:
		return h.undoDeploy(ctx, j, actor, d, sess, steps, sshkeys.ReasonLoginFailed, true)
	}
	if err := h.d.Keys.FinishDeploy(ctx, actor, d, out); err != nil {
		// The line is in the file; the next attempt finds it (its send is on record) and records it.
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	if out.Result == sshkeys.DeployAlreadyPresent {
		h.discover(ctx, d.TargetID)
	}
	return deployResult(d, out), nil
}

// presentNote is the note of a line that was already there.
func presentNote(o providers.KeyLoginOutcome, lerr error, options string) string {
	switch {
	case lerr != nil:
		return noteLoginUnavailable
	case o == providers.KeyLoginAccepted:
		return ""
	case o == providers.KeyLoginUnprovable:
		return sshkeys.NoteLoginWithoutKey
	case keymat.HasFromOption(options):
		return plan.NoteFromOption
	}
	return noteLoginRefused
}

// undoDeploy removes the new key's line again (its fingerprint only) after its login failed or its
// read-back differed. latestAnswered says whether this attempt's send had a definite answer. While a send
// of this job without a definite answer may still land (S3: the store's UndoNotBefore from the durable
// send record, so a restart, a lost lease or a shutdown cannot shorten it), nothing is removed: the job
// is retried at that time and starts over; on the last attempt a person looks (undo_failed, no scan yet:
// a stalled write may still land, review M13).
func (h *handlers) undoDeploy(ctx context.Context, j jobs.Job, actor audit.Actor, d sshkeys.DeployJob, sess providers.Session,
	steps jobs.StepRecorder, reason string, latestAnswered bool) (map[string]any, error) {
	sends, err := h.d.Keys.DeploySends(ctx, j.ID)
	if err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err) // nothing removed; the next attempt starts over
	}
	if notBefore := sends.UndoNotBefore(h.d.Keys.UndoWait(), latestAnswered); h.d.Clock.Now().Before(notBefore) {
		if j.Attempt < j.MaxAttempts {
			return map[string]any{"result": "uncertain", "ssh_key_id": d.KeyID.String()},
				jobs.RetryAfter(reasonUncertain, nil, nil, notBefore.Sub(h.d.Clock.Now()))
		}
		out := sshkeys.DeployOutcome{Result: sshkeys.DeployUndoFailed, Reason: reasonUndoFailed}
		h.finish(ctx, actor, d, out)
		return deployResult(d, out), jobs.Attention(reasonUndoFailed, nil, nil)
	}
	rec := &writeTracker{next: steps}
	res, err := sess.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: j.ID, OSUser: d.OSUser, FilePath: d.FilePath,
		Fingerprint: d.Fingerprint, ProtectedFingerprints: d.Protected}, rec)
	if err == nil && (!res.Changed || res.Verified) {
		// Removed, or not there: no send of this job can land any more, so "not there" is the truth.
		out := sshkeys.DeployOutcome{Result: sshkeys.DeployUndone, Reason: reason, Backup: res.Backup}
		h.finish(ctx, actor, d, out)
		return deployResult(d, out), jobs.Fail(reason, nil, nil)
	}
	if err != nil {
		h.recordIfConnection(ctx, d.TargetID, err)
	}
	out := sshkeys.DeployOutcome{Result: sshkeys.DeployUndoFailed, Reason: reasonUndoFailed, Backup: res.Backup}
	h.finish(ctx, actor, d, out)
	h.discover(ctx, d.TargetID)
	return deployResult(d, out), jobs.Attention(reasonUndoFailed, nil, err)
}

// failed records a deploy that ends without a change, once: only when the failure is final (permanent,
// or the last attempt); a retryable one is audited by the attempt that ends the job (scan row 10).
// It reports whether it recorded.
func (h *handlers) failed(ctx context.Context, j jobs.Job, actor audit.Actor, d sshkeys.DeployJob, err error) bool {
	var f *jobs.Failure
	if !errors.As(jobs.FromProvider(err), &f) || (f.Class == jobs.Retryable && j.Attempt < j.MaxAttempts) {
		return false
	}
	h.finish(ctx, actor, d, sshkeys.DeployOutcome{Result: sshkeys.DeployFailed, Reason: f.Reason})
	return true
}

// finish records an outcome whose job ends anyway; a failure to record is logged (the audit row is
// missing, the job's own result says what happened).
func (h *handlers) finish(ctx context.Context, actor audit.Actor, d sshkeys.DeployJob, out sshkeys.DeployOutcome) {
	if err := h.d.Keys.FinishDeploy(context.WithoutCancel(ctx), actor, d, out); err != nil {
		h.d.Log.Error("could not record a deploy's outcome", "ssh_key_id", d.KeyID.String(), "result", out.Result, "error_type", errType(err))
	}
}

func deployResult(d sshkeys.DeployJob, out sshkeys.DeployOutcome) map[string]any {
	return map[string]any{"result": out.Result, "note": out.Note, "line_no": out.LineNo, "ssh_key_id": d.KeyID.String()}
}

// payloadDeploy is what the payload names, for the audit row of a refused deploy (the payload is the
// queue's, MAC-checked); false when the key cannot be named.
func payloadDeploy(j jobs.Job) (sshkeys.DeployJob, bool) {
	id, err := uuid.Parse(j.Payload["ssh_key_id"])
	if err != nil {
		return sshkeys.DeployJob{}, false
	}
	return sshkeys.DeployJob{KeyID: id, TargetID: j.TargetID, OSUser: j.Payload["os_user"], FilePath: j.Payload["file_path"]}, true
}

// deployRefusals are the reasons of the refusals DeployJob answers (the API's reasons of the same errors).
var deployRefusals = []struct {
	err    error
	reason string
}{
	{sshkeys.ErrNotManaged, "sshkey.not_managed"},
	{sshkeys.ErrRetired, "sshkey.retired"},
	{sshkeys.ErrDestroyed, "sshkey.private_key_destroyed"},
	{sshkeys.ErrConnectionAccount, "sshkey.connection_account"},
	{sshkeys.ErrConnectionFilesUnknown, sshkeys.ReasonConnectionFilesUnknown},
	{sshkeys.ErrNotAKeyFile, "sshkey.not_a_key_file"},
	{inventory.ErrNotFound, "system.not_found"},
	{inventory.ErrNotAServer, "system.not_found"},
	{inventory.ErrHostKeyUnconfirmed, "target.host_key_unconfirmed"},
	{inventory.ErrHostKeyChanged, "target.host_key_changed"},
	{inventory.ErrTargetDisabled, "target.disabled"},
	{inventory.ErrKeysManagedElsewhere, "ssh.keys_managed_elsewhere"},
	{inventory.ErrSSHDUnreadable, "sshkey.sshd_unreadable"},
}

// deployRefusal classifies an error of DeployJob: a refusal of the deploy's rules is permanent; a
// provider refusal (foreign options, S7) keeps its code; anything else (the database) is retried.
func deployRefusal(err error) error {
	for _, r := range deployRefusals {
		if errors.Is(err, r.err) {
			return jobs.Fail(r.reason, nil, err)
		}
	}
	var pe *providers.Error
	if errors.As(err, &pe) {
		return jobs.Fail(pe.Code, pe.Params, err)
	}
	return jobs.Retry("internal.unexpected", nil, err)
}
