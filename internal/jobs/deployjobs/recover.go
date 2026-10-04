package deployjobs

import (
	"context"
	"errors"
	"regexp"
	"strconv"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
)

// recoverJob is the certificate.deploy_recover handler (one attempt; ClassAlways: a rollback is
// never held by the license, L-82). The sweep queues it for a deployment that may have sent
// (deploying or recovering) and paces the next one.
//
//	state at start           recorded                       job returns
//	-----------------------  -----------------------------  ------------------------------------------
//	no deployment id         nothing                        Fail system.not_found
//	ErrNotFound              nothing                        Fail system.not_found
//	other read error         nothing                        Retry internal.unexpected (ends failed
//	                                                        quietly: one attempt, never an alert)
//	job target != record's   nothing                        Fail internal.unexpected
//	done                     nothing (finished meanwhile)   success {outcome: status}
//	queued | precheck        nothing (nothing was sent;     success {outcome: state}
//	                         the deploy job or the sweep
//	                         ends it)
//	deploying | recovering   recoverDeployment              see recoverDeployment
func (h *handlers) recoverJob(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
	ctx = withClaim(ctx, j)
	id, err := deploymentID(j)
	if err != nil {
		return nil, err
	}
	d, err := h.d.Inventory.Deployment(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, jobs.Fail(reasonNotFound, nil, err)
	case err != nil:
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	case d.TargetID != j.TargetID:
		return nil, jobs.Fail(reasonUnexpected, nil, errors.New("deployjobs: the job's server is not the deployment's"))
	case d.State == inventory.DeployStateDone:
		return resultOf(d, recoveryJob)
	case d.State == inventory.DeployStateQueued || d.State == inventory.DeployStatePrecheck:
		return map[string]any{"deployment_id": d.ID.String(), "outcome": d.State}, nil
	}
	return h.recoverDeployment(ctx, d, steps, recoveryJob)
}

// recoverDeployment ends an interrupted deployment from the helper's journal (§8.8): the new
// certificate live and verified, the old one restored, or the deployment stays in recovery. It
// never sends the certificate again and never needs the private key. It runs in a recovery job, and
// in a deploy job that found a send may have happened (deploy-job mode: every failure is permanent,
// the runner never re-runs the deploy job; the sweep hands the deployment to a recovery job).
//
// "uncertain" below records RecordOutcome(uncertain, reason): the deployment stays recovering, the
// next recovery not before now + FirstRecovery (deploy-job mode; the pacing guard makes it now +
// RecoveryRetryInterval once a recovery was requested) or now + RecoveryRetryInterval (recovery job).
// "unresolved F" records nothing and returns F classified (recovery job: retryable or permanent,
// the job ends failed, never dead, never an email; deploy-job mode: permanent): the sweep queues
// the next recovery at recover_after, emails once after RecoveryAttentionAfter attempts and ends the
// deployment rollback_failed (outcome unknown) after MaxRecoveryAttempts.
//
//	step / journal (DeploymentStatus of the recorded operation)   recorded                                   job returns
//	------------------------------------------------------------  -----------------------------------------  ---------------------------
//	operation_id nil (the record shows nothing was sent)           finish failed deployment.interrupted       resultOf
//	DeploymentMaterial(id, false): ErrNotFound (a referenced row   rollback_failed deployment.outcome_unknown resultOf
//	  is unreadable; the row alone cannot verify or check a        at once (outcome-unknown email, M-8)
//	  rollback)
//	  other error                                                  nothing                                    unresolved internal.unexpected
//	open: refusal (host key changed or unconfirmed, disabled,      nothing                                    unresolved with its reason
//	  deleted) or provider error (recorded on the target)
//	DeploymentStatus: error (transport, ctx, sudo, protocol) or    nothing                                    unresolved with its reason
//	  a state that fails Validate
//	active, any phase (a helper holds the lock: this operation     uncertain nginx.busy                       resultOf (uncertain)
//	  still running, or another one)
//	fenced (an earlier recovery fenced it, then could not record)  failed deployment.interrupted (phase none) resultOf
//	none | prepared, no helper running, start record older than    rollback_failed deployment.outcome_unknown resultOf
//	  noJournalUnknownAfter (after an outage the helper may have   (outcome-unknown email)
//	  swept the journal of a change it made), or without a time
//	  (B2 m1)
//	none | prepared, no helper running, otherwise: FenceDeployment
//	  (AUD-05: a helper that starts late, after a sudo or PAM
//	  stall, must find the operation fenced):
//	    error (transport, BUSY, sudo, protocol) or a state that    nothing                                    unresolved with its reason
//	      fails Validate, or none/prepared (not fenced)
//	    active                                                     uncertain nginx.busy                       resultOf (uncertain)
//	    fenced                                                     failed deployment.interrupted (nothing     resultOf
//	                                                               was written and nothing will be; phase
//	                                                               the status read before the fence)
//	    any other phase (a journal after all)                      as that phase below
//	committed | unchanged: VerifyDeployment(VerifyRequest: the
//	  RECORDED fingerprint and chain length; never success from
//	  the journal alone):
//	    error (transport, ctx)                                     step verify failed                         unresolved with its reason
//	    OK, journal committed                                      succeeded (verified mode, the journal's    resultOf
//	                                                               new file hash)
//	    OK, journal unchanged                                      unchanged (likewise)                       resultOf
//	    !OK, journal unchanged (this operation wrote nothing)      failed with the verification reason        resultOf
//	                                                               (failed_step verify, verify_failed_*)
//	    !OK, journal committed                                     rollback, cause = the verification         as the rollback
//	                                                               reason (verify_failed_* recorded)
//	writing | restoring | restored                                 rollback, cause = the recorded             as the rollback
//	                                                               verification failure, else the last
//	                                                               verify:failed step's reason and port
//	                                                               (recorded before an inline restore, M-3),
//	                                                               else the helper's cause step's reason,
//	                                                               else interrupted
//	restore_failed                                                 rollback (this IS the one more             as the rollback
//	                                                               nginx-restore after the helper's
//	                                                               restore_failed), same cause
//
// rollback = RollbackDeployment(RollbackRequest: the recorded previous fingerprint and chain length),
// mapped by inventory.RollbackOutcomeRecord with the cause, once more when it answers restore_failed
// and this recovery has not sent its one extra restore yet:
//
//	rolled_back (files back; the previous certificate verified or not checkable)   rolled_back (error_code = cause)
//	rollback_failed, phase restored (verify_old: files back, another certificate   rollback_failed (restored_unverified email)
//	  served)
//	rollback_failed, phase restore_failed (again) / "" (file_changed)              rollback_failed (rollback_failed email)
//	no_change deployment.superseded (a later operation owns the files; final)      rollback_failed (superseded email)
//	no_change "nothing to restore" (prepared / unchanged): contradicts the         uncertain deployment.interrupted
//	  journal this recovery read (it is never sent for those phases)
//	no_change with an error (BUSY, IO_ERROR, sudo, UNKNOWN_OP: nothing was         uncertain with the reason; recovery job:
//	  restored)                                                                    the provider error, quietly
//	uncertain (transport, ctx, malformed)                                          uncertain with the reason; likewise
//
// Every RollbackDeployment is preceded by a fenced CheckClaim (a stale run restores nothing); every
// write is fenced to the job's claim; ErrClaimLost anywhere: nothing more is written or sent (the
// stale-run rule of deploy). A failed record write is unresolved internal.unexpected (nothing new
// was recorded; the next recovery reads the journal again).
func (h *handlers) recoverDeployment(ctx context.Context, d inventory.Deployment, steps jobs.StepRecorder, m mode) (map[string]any, error) {
	if d.OperationID == nil {
		return h.recordFor(ctx, d, failedRecord(reasonInterrupted, ""), m, nil)
	}
	mat, err := h.d.Inventory.DeploymentMaterial(ctx, d.ID, false)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		// M-8: the location, certificate or server row the record references is gone (they are
		// never deleted: foreign keys, no delete grant; a server is only marked deleted). The row
		// alone cannot verify or check a rollback (it holds no endpoints or SANs), so the outcome is
		// unknown now, not after a day of attempts: rollback_failed deployment.outcome_unknown
		// (the outcome-unknown email names the backup directory).
		return h.recordFor(ctx, d, outcomeUnknownRecord(), m, nil)
	case err != nil:
		return unresolved(m, jobs.Retry(reasonUnexpected, nil, err))
	}
	sess, err := h.open(ctx, d.TargetID)
	if err != nil {
		return unresolved(m, err)
	}
	defer h.close(sess)
	now := h.d.Clock.Now() // before the journal is read: the age check below is conservative (M-2)
	st, err := sess.DeploymentStatus(ctx, *d.OperationID)
	if err != nil {
		return unresolved(m, err)
	}
	if verr := st.Validate(); verr != nil {
		return unresolved(m, providers.NewError("ssh.protocol_error", false, verr, nil))
	}
	if st.Active {
		// A helper holds the lock (this operation's, still running, or another's): wait for it.
		return h.recordFor(ctx, d, uncertainRecord(reasonBusy), m, nil)
	}
	rec := h.recorder(ctx, d.ID, steps)
	switch st.Phase {
	case providers.PhaseFenced:
		// An earlier recovery fenced it and could not record: nothing was written, nothing will be.
		return h.recordFor(ctx, d, failedRecord(reasonInterrupted, providers.PhaseNone), m, nil)
	case providers.PhaseNone, providers.PhasePrepared:
		if d.StartedAt == nil || h.sentLongAgo(d, now) {
			// After an outage longer than a day the helper may have swept the journal of a change
			// it made: the outcome is unknown, never "nothing was written" (outcome-unknown email).
			// A start record without a time cannot be placed at all (B2 m1): the same.
			return h.recordFor(ctx, d, outcomeUnknownRecord(), m, nil)
		}
		// AUD-05: no journal proves nothing about a helper that has not started yet (a sudo or PAM
		// stall): the operation is fenced on the server first. Only a fence that answers fenced
		// makes "nothing was written" final; a journal it finds after all is acted on.
		fst, err := sess.FenceDeployment(ctx, *d.OperationID)
		if err != nil {
			return unresolved(m, err)
		}
		if verr := fst.Validate(); verr != nil {
			return unresolved(m, providers.NewError("ssh.protocol_error", false, verr, nil))
		}
		switch {
		case fst.Active:
			return h.recordFor(ctx, d, uncertainRecord(reasonBusy), m, nil)
		case fst.Phase == providers.PhaseFenced:
			return h.recordFor(ctx, d, failedRecord(reasonInterrupted, st.Phase), m, nil)
		case fst.Phase == providers.PhaseNone || fst.Phase == providers.PhasePrepared:
			// A fence that did not fence (it cannot answer these): proves nothing.
			return unresolved(m, providers.NewError("ssh.protocol_error", false, errors.New("deployjobs: the fence answered "+fst.Phase), nil))
		}
		st = fst
	}
	switch st.Phase {
	case providers.PhaseCommitted, providers.PhaseUnchanged:
		return h.verified(ctx, sess, d, mat, st, rec, m)
	}
	retries := 1
	if st.Phase == providers.PhaseRestoreFailed {
		retries = 0 // this rollback is the one more nginx-restore after the helper's restore_failed
	}
	return h.rollback(ctx, sess, d, mat, st, rec, m, rollbackCause{}, retries)
}

// verified checks a committed or unchanged journal with the recorded values (see recoverDeployment).
func (h *handlers) verified(ctx context.Context, sess providers.Session, d inventory.Deployment, mat inventory.Material, st providers.DeploymentState,
	rec *recorder, m mode) (map[string]any, error) {
	rec.Step(providers.StepNameVerify, providers.StepStarted, nil)
	vr, err := sess.VerifyDeployment(ctx, mat.VerifyRequest())
	if err != nil {
		rec.Step(providers.StepNameVerify, providers.StepFailed, nil)
		return unresolved(m, err)
	}
	if vr.OK {
		status := providers.StepOK
		if vr.Mode == "skipped" {
			status = providers.StepSkipped
		}
		rec.Step(providers.StepNameVerify, status, map[string]string{"mode": vr.Mode})
		f := inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded, Result: string(providers.DeployCommitted), Phase: st.Phase,
			Verified: vr.Mode, CertFileSHA256: st.NewCertSHA256, Params: map[string]string{}}
		if st.Phase == providers.PhaseUnchanged {
			f.Status, f.Result = inventory.DeployStatusUnchanged, string(providers.DeployUnchanged)
		}
		return h.recordFor(ctx, d, inventory.OutcomeRecord{Terminal: true, Finish: f}, m, nil)
	}
	rec.Step(providers.StepNameVerify, providers.StepFailed, map[string]string{"port": vr.Params["port"], "reason": vr.Reason})
	cause := rollbackCause{reason: vr.Reason, port: portOf(vr.Params), step: providers.StepNameVerify}
	if st.Phase == providers.PhaseUnchanged {
		// The files already held the new pair: this operation wrote nothing, nothing to roll back.
		return h.recordFor(ctx, d, inventory.OutcomeRecord{Terminal: true, Finish: inventory.DeploymentFinish{
			Status: inventory.DeployStatusFailed, Result: string(providers.DeployNoChange), Phase: providers.PhaseUnchanged,
			NothingWritten: true, FailedStep: providers.StepNameVerify, ErrorCode: vr.Reason, Params: vr.Params, VerifyFailedReason: vr.Reason,
			VerifyFailedPort: cause.port}}, m, nil)
	}
	return h.rollback(ctx, sess, d, mat, st, rec, m, cause, 1)
}

// rollbackCause is why a recovery rolls back: a verification it just made, or "" (the recorded one,
// or the journal's).
type rollbackCause struct {
	reason string
	port   *int
	step   string
}

// rollback restores the recorded operation's files and records the mapped outcome (see
// recoverDeployment). retries is how many more nginx-restores may follow a restore_failed answer.
func (h *handlers) rollback(ctx context.Context, sess providers.Session, d inventory.Deployment, mat inventory.Material, st providers.DeploymentState,
	rec *recorder, m mode, c rollbackCause, retries int) (map[string]any, error) {
	if c.reason == "" && d.VerifyFailedReason != "" {
		c = rollbackCause{reason: d.VerifyFailedReason, port: d.VerifyFailedPort, step: providers.StepNameVerify}
	}
	if c.reason == "" {
		c = verifyFailureOfSteps(d.Steps) // M-3: recorded as a step before a rollback that was cut off
	}
	if c.reason == "" {
		c.reason = causeReason(st.CauseStep, st.Error)
		c.step = st.CauseStep
	}
	from := inventory.DeploymentFinish{CauseStep: c.step, HelperError: st.Error}
	if c.step == providers.StepNameVerify {
		from.VerifyFailedReason, from.VerifyFailedPort = c.reason, c.port
	}
	var r inventory.OutcomeRecord
	var err error
	for {
		// Fenced (I-1): a stale run does not restore behind the back of the run that holds the job.
		if cerr := h.d.Inventory.CheckClaim(ctx); cerr != nil {
			if errors.Is(cerr, inventory.ErrClaimLost) {
				return staleRun(cerr)
			}
			return unresolved(m, jobs.Retry(reasonUnexpected, nil, cerr))
		}
		var out providers.RollbackOutcome
		out, err = sess.RollbackDeployment(ctx, mat.RollbackRequest(), rec)
		r = rollbackRecord(out, err, c.reason)
		if !r.RetryRollback || retries == 0 {
			break
		}
		retries--
	}
	keepCause(&r, from)
	return h.recordFor(ctx, d, r, m, err)
}

// rollbackRecord is inventory.RollbackOutcomeRecord, except that "nothing to restore" is uncertain:
// the engine restores only operations whose journal (or answer) says files were written, so that
// answer contradicts what it just read, and "failed" (nothing was written) is never recorded on a
// contradiction.
func rollbackRecord(out providers.RollbackOutcome, err error, cause string) inventory.OutcomeRecord {
	if out.Result == providers.DeployNoChange && (out.Phase == providers.PhasePrepared || out.Phase == providers.PhaseUnchanged) &&
		providers.CheckRollbackReturn(out, err) == nil {
		return uncertainRecord(reasonInterrupted)
	}
	return inventory.RollbackOutcomeRecord(out, err, cause)
}

// recordFor records rec with the retry time of the mode and answers what was recorded.
func (h *handlers) recordFor(ctx context.Context, d inventory.Deployment, rec inventory.OutcomeRecord, m mode, cause error) (map[string]any, error) {
	next := h.d.Clock.Now().Add(inventory.RecoveryRetryInterval)
	if m == deployJob {
		next = h.d.Clock.Now().Add(h.d.FirstRecovery)
	}
	res, err := h.record(ctx, d, rec, next, m, cause)
	if m == deployJob {
		return res, permanent(err)
	}
	return res, err
}

// unresolved answers a recovery that could not reach or use the server (see recoverDeployment).
func unresolved(m mode, err error) (map[string]any, error) {
	if m == deployJob {
		return nil, permanent(err)
	}
	return nil, failure(err)
}

// permanent makes a retryable failure permanent (deploy-job mode: the sweep, not the runner,
// decides when to look again); NeedsAttention and Permanent pass through.
func permanent(err error) error {
	if err == nil {
		return nil
	}
	f := failure(err)
	if f.Class == jobs.Retryable {
		return jobs.Fail(f.Reason, f.Params, f.Cause)
	}
	return f
}

func uncertainRecord(code string) inventory.OutcomeRecord {
	return inventory.OutcomeRecord{Finish: inventory.DeploymentFinish{Result: string(providers.DeployUncertain), ErrorCode: code,
		Params: map[string]string{}}}
}

// failedRecord ends a deployment failed with nothing written: its callers have that proof (no
// operation id recorded, or the fence found no journal and now refuses the operation).
func failedRecord(code, phase string) inventory.OutcomeRecord {
	return inventory.OutcomeRecord{Terminal: true, Finish: inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, ErrorCode: code,
		Phase: phase, Params: map[string]string{}, NothingWritten: true}}
}

// verifyFailureOfSteps is the last failed verification of the new certificate recorded as a step
// (step verify, failed, params reason and port), or none.
func verifyFailureOfSteps(steps []inventory.DeploymentStep) rollbackCause {
	for i := len(steps) - 1; i >= 0; i-- {
		st := steps[i]
		if st.Name == providers.StepNameVerify && st.Status == string(providers.StepFailed) && reasonRE.MatchString(st.Params["reason"]) {
			return rollbackCause{reason: st.Params["reason"], port: portOf(st.Params), step: providers.StepNameVerify}
		}
	}
	return rollbackCause{}
}

// reasonRE is the shape of a reason code read back from a step.
var reasonRE = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z0-9_.]{1,90}$`)

func portOf(params map[string]string) *int {
	p, err := strconv.Atoi(params["port"])
	if err != nil || p < 1 || p > 65535 {
		return nil
	}
	return &p
}

// outcomeUnknownRecord is the terminal record of a deployment whose outcome Alice cannot learn:
// rollback_failed with deployment.outcome_unknown (the outcome-unknown email names the backup
// directory; the location is released).
func outcomeUnknownRecord() inventory.OutcomeRecord {
	return inventory.OutcomeRecord{Terminal: true, Finish: inventory.DeploymentFinish{
		Status: inventory.DeployStatusRollbackFailed, ErrorCode: reasonOutcomeUnknown, Params: map[string]string{}}}
}
