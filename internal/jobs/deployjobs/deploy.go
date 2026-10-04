package deployjobs

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
)

// deploy is the certificate.deploy handler. Its decision table, by the record's state when the
// job starts and the result of each step ("finish failed R" = FinishDeployment(failed, R), detached
// from the job's context; "pre-send failure F" is defined below the table):
//
//	state at start / step            result                                  recorded                         job returns
//	-------------------------------  --------------------------------------  -------------------------------  -----------------------------
//	payload                          no deployment id                        nothing                          Fail system.not_found
//	Deployment(id)                   ErrNotFound                             nothing                          Fail system.not_found
//	                                 other error                             nothing                          Retry internal.unexpected
//	                                 job target != deployment target         nothing (the sweep ends it)      Fail internal.unexpected
//	done                             -                                       nothing                          resultOf(record)
//	deploying | recovering           a send may have happened                recoverDeployment (deploy-job    see recover.go; failures are
//	                                                                         mode): NEVER a send              permanent (the sweep paces)
//	queued | precheck:
//	 CheckRecoveryPending            ErrRecoveryPending (best-effort)        finish failed recovery_pending   Fail recovery_pending
//	                                 other error                             -                                pre-send failure
//	 BeginDeployment                 error                                   -                                pre-send failure
//	                                 returns a state other than precheck     -                                follow that state (above)
//	 DeploymentMaterial(id, true)    ErrDeploymentState (raced)              -                                follow the re-read state
//	                                 ErrNoPrivateKey / ErrNotFound           finish failed no_private_key /   Fail that reason
//	                                                                         system.not_found
//	                                 other error                             -                                pre-send failure
//	 vault step (a Key Vault deployment: Material.KV set; kv.go has its own table): the secret of
//	  the recorded version is read and checked BEFORE the SSH session is opened
//	                                 provider or inventory refusal           step kv_secret failed; finish    Fail the closed reason
//	                                 (azure.forbidden {role} F-41, kv.*,     failed (kv_secret) unless        (retryable: attempts left
//	                                 certificate.chain_unconfirmed F-17,     retryable with attempts left     retry, the next attempt
//	                                 certificate.expired ...)                                                 reads the vault again)
//	                                 ok                                      step kv_secret ok                continue below
//	 run-time checks (F-19)          now >= not_after / now < not_before     finish failed certificate.       Fail that reason
//	                                 configuration invalid / location        expired | not_yet_valid |
//	                                 not deployable                          nginx.config_invalid |
//	                                                                         nginx.location_unsupported
//	 open session                    target deleted, host key changed or     finish failed with the reason    Fail that reason
//	                                 unconfirmed, disabled (no dial)
//	                                 provider error (recorded on target)     -                                pre-send failure
//	 pre-check (VerifyDeployment     skip set                                step verify_current skipped      continue, nothing compared
//	  of PrecheckRequest: current    current leaf unknown (nothing to        step failed; finish failed       Fail deployment.verify_other
//	  fingerprint and key type;      compare: cannot check, F-06/F-07)       deployment.verify_other
//	  F-06, F-07)                    error (ssh, ctx)                        step failed                      pre-send failure
//	                                 !OK (verify_unreachable F-07,           step failed {port}; finish       Fail that reason
//	                                 verify_other F-06, verify_chain, ...)   failed with reason and params
//	                                 OK                                      step ok {mode}                   continue with served, chain
//	 context ended (lease, shutdown) before StartDeployment                  nothing (the record stays        Retry deployment.interrupted
//	                                                                         precheck; a re-run deploys)      (released by the runner)
//	 StartDeployment(SendValues)     ErrRecoveryPending                      finish failed recovery_pending   Fail recovery_pending
//	                                 ErrDeploymentState (raced)              -                                follow the re-read state
//	                                   (the re-read fails: B2-I1)            nothing (it may be deploying)    Retry internal.unexpected
//	                                 other error (may have committed)        -                                pre-send failure (a re-run
//	                                                                                                          finds deploying: recovers)
//	 context ended after the start   nothing was sent (known)                finish failed interrupted        Fail deployment.interrupted
//	  record, before the send
//	 CheckClaim (fenced, right       ErrClaimLost: another run holds the     nothing; NO send                 stale run
//	  before the send)               job now
//	                                 other error                             finish failed interrupted        Fail deployment.interrupted
//	 DeployCertificate(DeployRequest(v)); the key is zeroed as soon as it returns; then
//	 rec = DeployOutcomeRecord(out, err, false):
//	   committed / unchanged, verified                                       succeeded / unchanged with the   success {outcome, verified}
//	                                                                         new file's hash (NewCertSHA256)
//	   committed / unchanged without Verified                                uncertain (never a success       Attention deployment.interrupted
//	                                                                         unverified): recovering, first
//	                                                                         recovery at now + FirstRecovery
//	   no_change (a refusal: provider-side or a well-formed helper           failed with the reason           Fail reason
//	     refusal; nothing was written)
//	   no_change phase unchanged, verify failed (this call wrote nothing)    failed, verify_failed_reason     Fail reason
//	   rolled_back (helper's own rollback, or inline after a failed verify)  rolled_back                      Fail reason
//	   rollback_failed, phase restored (verify_old) or "" (file_changed)     rollback_failed                  Attention reason
//	   rollback_failed, phase restore_failed (rec.RetryRollback)             RollbackDeployment(Rollback-     by that record (as recovery's
//	                                                                         Request) ONCE more; record       rollback rows)
//	                                                                         RollbackOutcomeRecord of it
//	   uncertain (transport, timeout, kill, 137, malformed; ctx ended after  uncertain with the reason; the   Attention deployment.interrupted
//	     the command was sent; verify failed and the inline rollback could   verify failure kept
//	     not be done: Params failed_step verify)                             (verify_failed_reason)
//	   an outcome that breaks the contract (CheckDeployReturn)               uncertain interrupted            Attention deployment.interrupted
//	 RecordOutcome error                                                     nothing new (deploying)          Retry internal.unexpected: the
//	                                                                                                          re-run recovers from the journal
//	                                                                                                          (last attempt: Fail, I-3)
//	 RecordOutcome ErrClaimLost (this run stalled past its lease; another    nothing (the live run's record   stale run
//	   run holds the job)                                                    stands)
//	 the one more restore after restore_failed: CheckClaim first; lost →     nothing                          stale run
//	   no restore is sent
//	 a step write refused during the call (ErrClaimLost) cancels the        what the outcome maps to; its    stale run
//	   provider call: the provider sends no further command (its inline     write is refused too
//	   restore follows the recorded verify:failed step)
//
// Fencing (I-1): the job run's claim (job id, attempt) is on the context of every write
// (inventory.WithClaim); inventory checks it in the write's own transaction and refuses with
// ErrClaimLost when the job was taken back or claimed again. Every ErrClaimLost row is "stale run":
// record nothing more, send nothing more, return jobs.Retry(job.lease_expired), which the runner
// drops (its own writes are fenced to the claim too). Residual, for the security review: (1) the
// instant between a fenced check (CheckClaim, or the step write before the provider's inline
// restore) and the command it guards: a lease that ends exactly then is not seen; (2) a command
// already sent when the lease ends (nginx-deploy or nginx-restore in flight) completes; its outcome
// is not recorded by the stale run, and the live run reads it from the journal. In both cases the
// helper's own lock serialises the commands, and the record is only ever written by the run that
// holds the job.
//
// Last attempt (I-3): a retryable failure on the deploy job's last attempt is returned permanent
// (lastAttempt): a dead job's job.dead email would be a second alert next to the deployment's.
//
// pre-send failure F (nothing was sent): a retryable F with attempts left is returned as it is (the
// record stays precheck; the next attempt runs the whole pre-check again); otherwise (permanent, or
// the last attempt) the deployment ends failed with F's reason and the job answers Fail with it, so
// a deploy job never ends dead with a job.dead email for an outcome it recorded (the deployment's
// failed email is the one alert). A context that ended (lease lost, shutdown) records nothing and
// returns F: the runner releases the job, which runs again.
//
// What every recorded outcome returns is resultOf the record as read back, so the jobs row and the
// deployment agree.
func (h *handlers) deploy(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
	res, err := h.deployRun(withClaim(ctx, j), j, steps)
	return res, lastAttempt(j, err)
}

// lastAttempt makes a retryable failure on the deploy job's last attempt permanent (I-3): the
// runner would end it dead with a job.dead email, and the deployment ends with its own email
// anyway (before the send the sweep ends it failed; after it a recovery finishes it).
func lastAttempt(j jobs.Job, err error) error {
	var f *jobs.Failure
	if j.Attempt < j.MaxAttempts || !errors.As(err, &f) || f.Class != jobs.Retryable {
		return err
	}
	return jobs.Fail(f.Reason, f.Params, f.Cause)
}

func (h *handlers) deployRun(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
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
		// The job does not hold the deployment's server lock: touch nothing (the sweep ends the
		// deployment once the job ended).
		return nil, jobs.Fail(reasonUnexpected, nil, errors.New("deployjobs: the job's server is not the deployment's"))
	}
	return h.follow(ctx, j, d, steps, 0)
}

// maxFollow bounds how often a run re-reads a deployment whose state changed under it.
const maxFollow = 3

// follow continues a deploy job from the deployment's state.
func (h *handlers) follow(ctx context.Context, j jobs.Job, d inventory.Deployment, steps jobs.StepRecorder, depth int) (map[string]any, error) {
	switch {
	case depth >= maxFollow:
		return nil, jobs.Retry(reasonUnexpected, nil, errors.New("deployjobs: the deployment's state keeps changing"))
	case d.State == inventory.DeployStateDone:
		return resultOf(d, deployJob)
	case d.State == inventory.DeployStateDeploying || d.State == inventory.DeployStateRecovering:
		// A send may have happened (a run after a crash or a lost lease): never send again (§8.4, §8.8).
		return h.recoverDeployment(ctx, d, steps, deployJob)
	}
	return h.first(ctx, j, d, steps, depth)
}

// refollow re-reads the deployment and follows its state (a state that changed under this run).
func (h *handlers) refollow(ctx context.Context, j jobs.Job, d inventory.Deployment, steps jobs.StepRecorder, depth int) (map[string]any, error) {
	again, err := h.d.Inventory.Deployment(ctx, d.ID)
	if err != nil {
		// B2-I1: the state changed under this run and cannot be read: it may be deploying (a send
		// may have happened), so nothing is recorded; the job is retried (on its last attempt it
		// ends failed and the sweep finishes the deployment from its state).
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	}
	return h.follow(ctx, j, again, steps, depth+1)
}

// first runs the pre-check and the one send of a deployment that has sent nothing (queued or
// precheck). See deploy for the table.
func (h *handlers) first(ctx context.Context, j jobs.Job, d inventory.Deployment, steps jobs.StepRecorder, depth int) (map[string]any, error) {
	switch err := h.d.Inventory.CheckRecoveryPending(ctx, d.ID); {
	case errors.Is(err, inventory.ErrRecoveryPending):
		return h.refuse(ctx, d, reasonRecoveryPending, nil)
	case err != nil:
		return h.beforeSend(ctx, j, d, jobs.Retry(reasonUnexpected, nil, err))
	}
	begun, err := h.d.Inventory.BeginDeployment(ctx, d.ID)
	if err != nil {
		return h.beforeSend(ctx, j, d, jobs.Retry(reasonUnexpected, nil, err))
	}
	if begun.State != inventory.DeployStatePrecheck {
		return h.follow(ctx, j, begun, steps, depth+1)
	}
	m, err := h.d.Inventory.DeploymentMaterial(ctx, d.ID, true)
	switch {
	case errors.Is(err, inventory.ErrDeploymentState):
		return h.refollow(ctx, j, d, steps, depth)
	case errors.Is(err, inventory.ErrNoPrivateKey):
		return h.refuse(ctx, d, reasonNoPrivateKey, nil)
	case errors.Is(err, inventory.ErrNotFound):
		return h.refuse(ctx, d, reasonNotFound, nil)
	case err != nil:
		if reason, ok := kvRefusal(err); ok {
			return h.refuse(ctx, d, reason, nil) // a Key Vault deployment whose request no longer holds
		}
		return h.beforeSend(ctx, j, d, jobs.Retry(reasonUnexpected, nil, err))
	}
	// The key is handed out for this first send only; it is zeroed on every path (and right after
	// the send). DeployRequest shares its holder. The call reads m when the run ends, not now: a
	// Key Vault deployment's key arrives with the vault step below (D6).
	defer func() { m.PrivateKeyPEM.Zero() }()
	rec := h.recorder(ctx, d.ID, steps)
	if m.KV != nil {
		// What the record alone refuses is refused before the vault is asked for a key (and again below,
		// once the material is in: the record may have moved).
		if reason := h.runtimeRefusal(m); reason != "" {
			return h.refuse(ctx, d, reason, nil)
		}
		if _, err := h.serverRef(ctx, d.TargetID); err != nil {
			return h.beforeSend(ctx, j, d, err)
		}
		// A Key Vault deployment reads its secret before anything can touch the server (kv.go).
		rec.Step(stepKVSecret, providers.StepStarted, nil)
		stepOpen := true
		defer func() {
			if stepOpen { // a panic: the step is closed while it unwinds
				rec.Step(stepKVSecret, providers.StepFailed, map[string]string{"reason": reasonUnexpected})
			}
		}()
		out, err := h.kvMaterial(ctx, m)
		stepOpen = false
		switch {
		case errors.Is(err, inventory.ErrDeploymentState):
			rec.Step(stepKVSecret, providers.StepSkipped, map[string]string{"reason": "state_changed"})
			return h.refollow(ctx, j, d, steps, depth)
		case errors.Is(err, inventory.ErrClaimLost):
			return h.beforeSendAt(ctx, j, d, err, stepKVSecret) // a stale run records nothing
		case err != nil:
			rec.Step(stepKVSecret, providers.StepFailed, map[string]string{"reason": failure(err).Reason})
			return h.beforeSendAt(ctx, j, d, err, stepKVSecret)
		}
		m = out
		var params map[string]string
		if slices.Contains(m.Warnings, inventory.WarnChainIncomplete) {
			params = map[string]string{"reason": inventory.WarnChainIncomplete}
		}
		rec.Step(stepKVSecret, providers.StepOK, params)
	}
	if reason := h.runtimeRefusal(m); reason != "" {
		return h.refuse(ctx, d, reason, nil) // F-19, also at run time
	}
	sess, err := h.open(ctx, d.TargetID)
	if err != nil {
		return h.beforeSend(ctx, j, d, err)
	}
	defer h.close(sess)
	served, chain, err := h.precheck(ctx, sess, m, rec)
	if err != nil {
		// The pre-check is the step that refused (distinct from "verify", the check of the new
		// certificate: the verification-failure readers key off that name).
		return h.beforeSendAt(ctx, j, d, err, stepPrecheck)
	}
	if err := ctx.Err(); err != nil {
		return nil, jobs.Retry(reasonInterrupted, nil, err) // nothing recorded: a re-run deploys
	}
	v := m.SendValues(served, chain)
	switch err := h.d.Inventory.StartDeployment(ctx, d.ID, v); {
	case errors.Is(err, inventory.ErrRecoveryPending):
		return h.refuse(ctx, d, reasonRecoveryPending, nil)
	case errors.Is(err, inventory.ErrDeploymentState):
		return h.refollow(ctx, j, d, steps, depth)
	case err != nil:
		return h.beforeSend(ctx, j, d, jobs.Retry(reasonUnexpected, nil, err))
	}
	// From here the record says a send may have happened (deploying with the operation id); a
	// rollback restores and checks exactly what was recorded.
	m.PreviousFingerprint, m.PreviousChainLength = v.PreviousFingerprint, v.PreviousChainLength
	if err := ctx.Err(); err != nil {
		// Known: nothing was sent. Waiting for a recovery to read "no journal" would end the same.
		return h.refuseSent(ctx, d, reasonInterrupted)
	}
	// The last fenced check before the send (I-1): a run that lost its lease after the start record
	// does not send behind the back of the run (or recovery) that holds the job now.
	if err := h.d.Inventory.CheckClaim(ctx); err != nil {
		return h.lostBeforeSend(ctx, j, d, err)
	}
	sendCtx, stop := context.WithCancel(ctx)
	defer stop()
	rec.lost = stop
	out, derr := sess.DeployCertificate(sendCtx, m.DeployRequest(v), rec)
	if op, ok := pendingOperation(out, derr); ok {
		out, derr = h.recoverPending(sendCtx, m, v, sess, rec, op, out, derr)
	}
	m.PrivateKeyPEM.Zero()
	return h.afterSend(ctx, d, m, sess, rec, out, derr)
}

// runtimeRefusal is the reason the record alone refuses a send now ("" when it does not): the
// certificate expired or not yet valid (F-19, also at run time), the configuration invalid, the
// location no longer deployable.
func (h *handlers) runtimeRefusal(m inventory.Material) string {
	now := h.d.Clock.Now()
	switch {
	case !now.Before(m.NotAfter):
		return reasonExpired
	case now.Before(m.NotBefore):
		return reasonNotYetValid
	case !m.ConfigValid:
		return reasonConfigInvalid
	case !m.Location.Supported:
		return reasonUnsupported
	}
	return ""
}

// stepRecoverPending is the step of a deployment that met an interrupted operation Alice no
// longer tracks and restored it (param operation_id).
const stepRecoverPending = "recover_pending"

// pendingOperation is the operation a helper's RECOVERY_PENDING refusal names (it blocks the
// pair): a well-formed refusal, nothing was written by this deployment.
func pendingOperation(out providers.DeployOutcome, err error) (uuid.UUID, bool) {
	var pe *providers.Error
	if out.Result != providers.DeployNoChange || out.Reason != reasonRecoveryPending || !errors.As(err, &pe) {
		return uuid.Nil, false
	}
	op, perr := uuid.Parse(pe.Params["operation_id"])
	return op, perr == nil && op != uuid.Nil && op.String() == pe.Params["operation_id"]
}

// recoverPending handles a first send the helper refused because the pair's latest operation op
// is interrupted (final review fix rounds 1 and 2). The refusal wrote nothing.
//
//	OperationDeployment(op)                      result
//	-------------------------------------------  --------------------------------------------------------
//	error                                         the refusal as it is: failed deployment.recovery_pending
//	a deployment Alice has not finished           the refusal as it is (its recovery restores it)
//	a deployment of another server or location,   no restore; failed deployment.server_operation_pending
//	  or finished succeeded / unchanged /           {operation_id} (an honest helper never names those)
//	  rolled_back / failed
//	unknown to Alice, or a finished               step recover_pending started {operation_id}; CheckClaim
//	  rollback_failed deployment of this          (lost or failing: the refusal as it is, no restore sent);
//	  server and location (it may have left       RollbackDeployment(op) once (verify_old skipped):
//	  an unfinished change)
//	    files put back (rolled_back, or           step recover_pending ok; CheckClaim; the same operation
//	      rollback_failed phase restored)         id sent once more: success or the deployment's own
//	                                              rollback as usual; ANY refusal, or no send because the
//	                                              claim check failed: rolled_back
//	                                              deployment.pending_change_restored {operation_id}
//	    nothing to put back (prepared,            step recover_pending skipped; CheckClaim; sent once more;
//	      unchanged, superseded, unknown, or      its answer is the outcome (a refusal is truthful then);
//	      HASH_MISMATCH: someone else's file)     a second RECOVERY_PENDING: server_operation_pending
//	    anything else (restore_failed, IO_ERROR,  step recover_pending failed; failed
//	      BUSY, sudo, uncertain)                  deployment.server_operation_pending {operation_id}
//
// op's own deployment record is never touched: the restore and its steps are recorded under this
// deployment only. A crash after the restore and before the second send leaves this deployment
// deploying with no journal: its recovery fences it, finds the recover_pending ok step and records
// rolled_back deployment.pending_change_restored (pendingRestored in recover.go).
func (h *handlers) recoverPending(ctx context.Context, m inventory.Material, v inventory.SendValues, sess providers.Session, rec *recorder,
	op uuid.UUID, out providers.DeployOutcome, derr error) (providers.DeployOutcome, error) {
	owner, known, err := h.d.Inventory.OperationDeployment(ctx, op)
	switch {
	case err != nil:
		return out, derr
	case known && owner.State != inventory.DeployStateDone:
		return out, derr
	}
	params := map[string]string{"operation_id": op.String()}
	if known && (owner.TargetID != m.Deployment.TargetID || owner.LocationID != m.Deployment.LocationID ||
		owner.Status != inventory.DeployStatusRollbackFailed) {
		return serverOperationPending(out, params)
	}
	if err := h.d.Inventory.CheckClaim(ctx); err != nil {
		return out, derr // no restore is sent: the refusal is what happened
	}
	rec.Step(stepRecoverPending, providers.StepStarted, params)
	req := m.RollbackRequest()
	req.OperationID, req.OldFingerprint, req.OldChainLength, req.OldSANs = op, "", 0, nil
	rb, rerr := sess.RollbackDeployment(ctx, req, rec)
	if providers.CheckRollbackReturn(rb, rerr) != nil {
		rec.Step(stepRecoverPending, providers.StepFailed, params)
		return serverOperationPending(out, params)
	}
	putBack := rb.Result == providers.DeployRolledBack || (rb.Result == providers.DeployRollbackFailed && rb.Phase == providers.PhaseRestored)
	released := putBack || (rb.Result == providers.DeployNoChange && (rb.Phase == providers.PhasePrepared || rb.Phase == providers.PhaseUnchanged ||
		rb.Reason == reasonSuperseded || rb.Reason == reasonUnknownOperation)) ||
		(rb.Result == providers.DeployRollbackFailed && rb.Phase == "" && rb.Error == providers.DeployErrFileChanged)
	switch {
	case !released:
		rec.Step(stepRecoverPending, providers.StepFailed, params)
		return serverOperationPending(out, params)
	case putBack:
		rec.Step(stepRecoverPending, providers.StepOK, params)
	default:
		rec.Step(stepRecoverPending, providers.StepSkipped, params) // nothing was put back
	}
	if err := h.d.Inventory.CheckClaim(ctx); err != nil {
		if putBack {
			return pendingRestoredOutcome(params)
		}
		return out, derr
	}
	again, aerr := sess.DeployCertificate(ctx, m.DeployRequest(v), rec)
	if putBack && again.Result == providers.DeployNoChange && providers.CheckDeployReturn(again, aerr) == nil {
		// The website went back to the files from before op, and this certificate was not written.
		return pendingRestoredOutcome(params)
	}
	if _, still := pendingOperation(again, aerr); still {
		return serverOperationPending(out, params)
	}
	return again, aerr
}

// serverOperationPending is the refusal deployment.server_operation_pending: op blocks the pair and
// Alice did not (or could not) restore it; nothing was written by this deployment.
func serverOperationPending(out providers.DeployOutcome, params map[string]string) (providers.DeployOutcome, error) {
	e := providers.NewError(reasonServerOperationPending, false, nil, maps.Clone(params))
	return providers.DeployOutcome{Result: providers.DeployNoChange, Reason: e.Code, Params: maps.Clone(params), Backup: out.Backup}, e
}

// pendingRestoredOutcome is rolled_back deployment.pending_change_restored: Alice put back the files
// of the unfinished earlier change op (its step recover_pending), so the website serves the
// certificate from before op; this deployment's certificate was not written. rolled_back (the
// "failed, restored" headline), not failed ("nothing changed" would be false: the restore changed
// the server).
func pendingRestoredOutcome(params map[string]string) (providers.DeployOutcome, error) {
	return providers.DeployOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, FailedStep: stepRecoverPending,
		Reason: reasonPendingChangeRestored, Params: maps.Clone(params)}, nil
}

// precheck verifies what the website serves before any change (F-06, F-07): the location's current
// certificate on every endpoint (the provider compares each endpoint, and its key-typed second probe
// applies). It returns the served leaf and chain length to record, or a failure: a refusal
// (jobs.Fail with the verification reason and params) or the provider's error.
func (h *handlers) precheck(ctx context.Context, sess providers.Session, m inventory.Material, rec *recorder) (string, int, error) {
	const step = stepPrecheck
	if m.Verify.Skip {
		rec.Step(step, providers.StepSkipped, nil)
		return "", 0, nil
	}
	rec.Step(step, providers.StepStarted, nil)
	if m.CurrentFingerprint == "" {
		// Alice does not know which certificate the file holds, so it cannot check that the
		// website serves it: nothing is changed on a website Alice cannot check.
		rec.Step(step, providers.StepFailed, nil)
		return "", 0, jobs.Fail(reasonVerifyOther, nil, nil)
	}
	vr, err := sess.VerifyDeployment(ctx, m.PrecheckRequest())
	if err != nil {
		rec.Step(step, providers.StepFailed, nil)
		return "", 0, err
	}
	if !vr.OK {
		rec.Step(step, providers.StepFailed, map[string]string{"port": vr.Params["port"]})
		return "", 0, jobs.Fail(vr.Reason, vr.Params, nil)
	}
	rec.Step(step, providers.StepOK, map[string]string{"mode": vr.Mode})
	return vr.Served, vr.ServedChainLength, nil
}

// lostBeforeSend: the fenced check before the send failed. Nothing was sent. A stale run stops;
// otherwise (the check itself failed) the deployment ends failed, as for any known "nothing was
// sent" after the start record.
func (h *handlers) lostBeforeSend(ctx context.Context, _ jobs.Job, d inventory.Deployment, err error) (map[string]any, error) {
	if errors.Is(err, inventory.ErrClaimLost) {
		return staleRun(err)
	}
	return h.refuseSent(ctx, d, reasonInterrupted)
}

// beforeSend handles a failure before anything was sent (see deploy).
func (h *handlers) beforeSend(ctx context.Context, j jobs.Job, d inventory.Deployment, err error) (map[string]any, error) {
	return h.beforeSendAt(ctx, j, d, err, "")
}

// stepPrecheck is the step name of the pre-check (verify_current), also the failed step of a
// deployment the pre-check refused.
const stepPrecheck = "verify_current"

// beforeSendAt is beforeSend for a failure of step (the failed step the record keeps; "" when no
// step ran).
func (h *handlers) beforeSendAt(ctx context.Context, j jobs.Job, d inventory.Deployment, err error, step string) (map[string]any, error) {
	if errors.Is(err, inventory.ErrClaimLost) {
		return staleRun(err)
	}
	f := failure(err)
	if ctx.Err() != nil {
		return nil, f // the job's context ended: record nothing, the runner releases the job
	}
	if f.Class == jobs.Retryable && j.Attempt < j.MaxAttempts {
		return nil, f
	}
	return h.refuseAt(ctx, d, f.Reason, f.Params, step, false)
}

// refuse ends a deployment that has no start record yet: failed with reason. It claims no proof
// that nothing was written (NothingWritten false): inventory requires none before the start record,
// and refuses (ErrDeploymentState, nothing recorded) a deployment that may have sent.
func (h *handlers) refuse(ctx context.Context, d inventory.Deployment, reason string, params map[string]string) (map[string]any, error) {
	return h.refuseAt(ctx, d, reason, params, "", false)
}

// refuseSent ends a deployment after its start record whose send is known not to have happened
// (the context ended after the start record, or the fenced check before the send failed): the one
// pre-send refusal that carries the proof that nothing was written.
func (h *handlers) refuseSent(ctx context.Context, d inventory.Deployment, reason string) (map[string]any, error) {
	return h.refuseAt(ctx, d, reason, nil, "", true)
}

// refuseAt is refuse with the step that failed ("" when none did); proven is NothingWritten.
func (h *handlers) refuseAt(ctx context.Context, d inventory.Deployment, reason string, params map[string]string, step string,
	proven bool) (map[string]any, error) {
	wctx, cancel := detached(ctx)
	err := h.d.Inventory.FinishDeployment(wctx, d.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, ErrorCode: reason,
		Params: params, FailedStep: step, NothingWritten: proven})
	cancel()
	if errors.Is(err, inventory.ErrClaimLost) {
		return staleRun(err)
	}
	if err != nil {
		// Nothing was sent: a retry is safe (and on the last attempt the sweep ends it).
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	}
	return h.report(ctx, d.ID, deployJob, func() (map[string]any, error) {
		return map[string]any{"deployment_id": d.ID.String(), "outcome": inventory.DeployStatusFailed}, jobs.Fail(reason, jobParams(params), nil)
	})
}

// afterSend records what the one send returned (see deploy).
func (h *handlers) afterSend(ctx context.Context, d inventory.Deployment, m inventory.Material, sess providers.Session, rec *recorder,
	out providers.DeployOutcome, derr error) (map[string]any, error) {
	r := inventory.DeployOutcomeRecord(out, derr, false)
	if r.RetryRollback {
		// The helper's own rollback ended restore_failed: one more nginx-restore (Task 11 carry).
		r = h.rollbackAgain(ctx, sess, m, rec, r)
	}
	if r.Terminal && (r.Finish.Status == inventory.DeployStatusSucceeded || r.Finish.Status == inventory.DeployStatusUnchanged) {
		r.Finish.CertFileSHA256 = m.NewCertSHA256 // the helper writes the PEM sent verbatim
	}
	return h.record(ctx, d, r, h.d.Clock.Now().Add(h.d.FirstRecovery), deployJob, nil)
}

// rollbackAgain runs RollbackDeployment once after a helper restore_failed and maps its outcome; the
// first record's failed step, cause step and verification failure are kept when the new one has none.
func (h *handlers) rollbackAgain(ctx context.Context, sess providers.Session, m inventory.Material, rec *recorder,
	first inventory.OutcomeRecord) inventory.OutcomeRecord {
	cause := first.Finish.VerifyFailedReason
	if cause == "" {
		cause = causeReason(first.Finish.CauseStep, first.Finish.HelperError)
	}
	if c := rec.lastVerifyFailure(); cause == "" && c.reason != "" {
		// The rollback failed at a later step, so the outcome does not name the verification that
		// started it; the step recorded before the restore does (as the recovery reads it).
		cause = c.reason
		first.Finish.VerifyFailedReason, first.Finish.VerifyFailedPort = c.reason, c.port
	}
	if err := h.d.Inventory.CheckClaim(ctx); err != nil {
		if errors.Is(err, inventory.ErrClaimLost) {
			// A stale run restores nothing; its record write is refused the same way. The record of
			// the first answer (restore_failed) is kept as the outcome to try to write.
			return first
		}
		// B2 m3: the check itself failed: no restore is sent behind a claim that is not confirmed,
		// and restore_failed is not recorded without the one more restore. Uncertain: the recovery
		// reads the journal (restore_failed) and sends it.
		r := uncertainRecord(reasonInterrupted)
		r.Finish.VerifyFailedReason, r.Finish.VerifyFailedPort = first.Finish.VerifyFailedReason, first.Finish.VerifyFailedPort
		return r
	}
	out, err := sess.RollbackDeployment(ctx, m.RollbackRequest(), rec)
	r := rollbackRecord(out, err, cause)
	keepCause(&r, first.Finish)
	return r
}

// keepCause copies what an earlier record knew about why the deployment was rolled back: a
// rollback's outcome names no step of its own when it succeeded, so the step whose failure started
// the rollback is the failed step.
func keepCause(r *inventory.OutcomeRecord, from inventory.DeploymentFinish) {
	if r.Finish.FailedStep == "" && r.Terminal {
		r.Finish.FailedStep = from.CauseStep
	}
	if r.Finish.CauseStep == "" {
		r.Finish.CauseStep = from.CauseStep
	}
	if r.Finish.HelperError == "" {
		r.Finish.HelperError = from.HelperError
	}
	if r.Finish.VerifyFailedReason == "" {
		r.Finish.VerifyFailedReason, r.Finish.VerifyFailedPort = from.VerifyFailedReason, from.VerifyFailedPort
	}
}
