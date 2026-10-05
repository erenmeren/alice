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
	addPresent   addState = iota // the line was there before this job: Alice did not add it, never removes it
	addOwned                     // this job's write put the line there (or may have, in an earlier attempt)
	addUncertain                 // the write was sent and its answer lost: only an accepted login proves the line
)

// deploy is the sshkey.add handler (C9's decision table). The deploy is read again from the database
// (DeployJob: every rule of the request applies to the current state); the line is added with the job id
// as operation id; a test login with the new key as the user decides; a line this job may have added and
// whose login failed is removed again by its fingerprint (the undo never names another key). A line that
// was there before the job is never removed. Only ids and public facts reach the result.
//
// An attempt after the first treats a line it finds as possibly its own: an earlier attempt may have
// written it before it died or before its answer was lost (and a retry after an uncertain write starts
// only once the helper's budget after that send has passed, so nothing of it lands later).
func (h *handlers) deploy(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
	actor := systemActor(j)
	d, err := h.d.Keys.DeployJob(ctx, j.ID, j.TargetID, j.Payload)
	if err != nil {
		f := deployRefusal(err)
		if pd, ok := payloadDeploy(j); ok {
			h.failed(ctx, j, actor, pd, f)
		}
		return nil, f
	}
	sess, err := h.open(ctx, d.TargetID)
	if err != nil {
		h.failed(ctx, j, actor, d, err)
		return nil, err
	}
	defer h.close(sess)
	rec := &writeTracker{next: steps}
	res, err := sess.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: j.ID, OSUser: d.OSUser, FilePath: d.FilePath, Line: d.Line,
		ProtectedFingerprints: d.Protected}, rec)
	var st addState
	switch {
	case err != nil && definiteNoChange(rec.wrote, res, err) && ctx.Err() == nil:
		h.recordIfConnection(ctx, d.TargetID, err)
		f := jobs.FromProvider(err)
		h.failed(ctx, j, actor, d, f)
		return nil, f
	case err != nil:
		h.recordIfConnection(ctx, d.TargetID, err)
		st = addUncertain
	case res.Changed && !res.Verified:
		// §13.4 step 5: the re-read after the write shows other content.
		return h.undoDeploy(ctx, j, actor, d, sess, steps, reasonVerifyFailed, false)
	case res.Changed || j.Attempt > 1:
		st = addOwned
	default:
		st = addPresent
	}
	if ctx.Err() != nil {
		return nil, h.interrupted(st, ctx.Err())
	}
	outcome, lerr := h.login(ctx, sess, d.OSUser, d.KeyID)
	if ctx.Err() != nil {
		return nil, h.interrupted(st, ctx.Err())
	}
	out := sshkeys.DeployOutcome{LineNo: res.LineNo, Backup: res.Backup}
	switch {
	case st == addPresent:
		out.Result, out.Note = sshkeys.DeployAlreadyPresent, presentNote(outcome, lerr, d.Options)
	case lerr == nil && outcome == providers.KeyLoginAccepted:
		out.Result = sshkeys.DeployVerified
	case st == addUncertain:
		// Only an accepted login proves an uncertain line (a refusal with from= or an unprovable login
		// proves nothing): it is removed again, after S3's wait when it is not there.
		return h.undoDeploy(ctx, j, actor, d, sess, steps, sshkeys.ReasonLoginFailed, true)
	case lerr != nil:
		out.Result, out.Note = sshkeys.DeployUnverified, noteLoginUnavailable
	case outcome == providers.KeyLoginUnprovable:
		out.Result, out.Note = sshkeys.DeployUnverified, sshkeys.NoteLoginWithoutKey
	case keymat.HasFromOption(d.Options):
		out.Result, out.Note = sshkeys.DeployUnverified, plan.NoteFromOption // Alice cannot know whether from= excludes her
	default:
		return h.undoDeploy(ctx, j, actor, d, sess, steps, sshkeys.ReasonLoginFailed, false)
	}
	if err := h.d.Keys.FinishDeploy(ctx, actor, d, out); err != nil {
		// The line is in the file; the next attempt finds it and records it.
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	if out.Result == sshkeys.DeployAlreadyPresent {
		h.discover(ctx, d.TargetID)
	}
	return deployResult(d, out), nil
}

// interrupted is the answer of a job whose context ended after the add (a shutdown or a lost lease): an
// uncertain write is retried only after S3's wait, anything else at the next attempt (which starts over).
func (h *handlers) interrupted(st addState, cause error) error {
	if st == addUncertain {
		return jobs.RetryAfter(reasonUncertain, nil, cause, h.d.HelperBudget+undoGrace)
	}
	return jobs.Retry("ssh.timeout", nil, cause)
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
// read-back differed. A line that is not there after an uncertain write is not concluded "undone" while
// the write may still land (S3): the job is retried after the helper's budget, and starts over; on the
// last attempt a person looks (undo_failed) and a discovery is queued.
func (h *handlers) undoDeploy(ctx context.Context, j jobs.Job, actor audit.Actor, d sshkeys.DeployJob, sess providers.Session,
	steps jobs.StepRecorder, reason string, uncertain bool) (map[string]any, error) {
	rec := &writeTracker{next: steps}
	res, err := sess.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: j.ID, OSUser: d.OSUser, FilePath: d.FilePath,
		Fingerprint: d.Fingerprint, ProtectedFingerprints: d.Protected}, rec)
	switch {
	case err == nil && res.Changed && !res.Verified:
	case err == nil && res.Removed == 0 && uncertain && j.Attempt < j.MaxAttempts:
		return map[string]any{"result": "uncertain", "ssh_key_id": d.KeyID.String()},
			jobs.RetryAfter(reasonUncertain, nil, nil, h.d.HelperBudget+undoGrace)
	case err == nil && (res.Removed > 0 || !uncertain):
		out := sshkeys.DeployOutcome{Result: sshkeys.DeployUndone, Reason: reason, Backup: res.Backup}
		h.finish(ctx, actor, d, out)
		return deployResult(d, out), jobs.Fail(reason, nil, nil)
	default:
		h.recordIfConnection(ctx, d.TargetID, err)
	}
	out := sshkeys.DeployOutcome{Result: sshkeys.DeployUndoFailed, Reason: reasonUndoFailed, Backup: res.Backup}
	h.finish(ctx, actor, d, out)
	h.discover(ctx, d.TargetID)
	return deployResult(d, out), jobs.Attention(reasonUndoFailed, nil, err)
}

// failed records a deploy that ends without a change, once: only when the failure is final (permanent,
// or the last attempt); a retryable one is audited by the attempt that ends the job (scan row 10).
func (h *handlers) failed(ctx context.Context, j jobs.Job, actor audit.Actor, d sshkeys.DeployJob, err error) {
	var f *jobs.Failure
	if !errors.As(jobs.FromProvider(err), &f) || (f.Class == jobs.Retryable && j.Attempt < j.MaxAttempts) {
		return
	}
	h.finish(ctx, actor, d, sshkeys.DeployOutcome{Result: sshkeys.DeployFailed, Reason: f.Reason})
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
