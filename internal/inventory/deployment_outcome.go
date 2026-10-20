package inventory

import (
	"errors"
	"strconv"

	"alice/internal/providers"
)

// OutcomeRecord is what one provider answer means for a deployment record (RecordOutcome writes
// it). Terminal: Finish is the final record (Finish.Status is terminal). Otherwise the outcome is
// uncertain: the deployment stays in recovery with Finish.Result "uncertain", Finish.ErrorCode
// saying why and Finish.VerifyFailed* holding an earlier verification failure; Finish.Status is "".
// RetryRollback: the helper's own rollback ended restore_failed; the engine runs
// RollbackDeployment once more before recording a terminal outcome (Task 11 carry).
type OutcomeRecord struct {
	Terminal      bool
	RetryRollback bool
	Finish        DeploymentFinish
}

// interruptedCode is the reason of an uncertain outcome that names none.
const interruptedCode = "deployment.interrupted"

// CancelledCode is the reason of a deployment whose job an Administrator discarded before anything
// was sent (the sweep ends it failed; no failure email).
const CancelledCode = "deployment.cancelled"

// providerCode is err's *providers.Error code, or "".
func providerCode(err error) string {
	var pe *providers.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func firstCode(codes ...string) string {
	for _, c := range codes {
		if errorCodeRE.MatchString(c) {
			return c
		}
	}
	return interruptedCode
}

func paramsOf(out map[string]string, err error) map[string]string {
	if len(out) > 0 {
		return out
	}
	var pe *providers.Error
	if errors.As(err, &pe) && len(pe.Params) > 0 {
		return pe.Params
	}
	return map[string]string{}
}

// verifyFailure fills the verification failure that decided the outcome (failed_step verify,
// in the outcome or, for an uncertain one, in its params): its reason and the port probed.
func verifyFailure(f *DeploymentFinish, failedStep, reason string, params map[string]string) {
	if failedStep != providers.StepNameVerify && params["failed_step"] != providers.StepNameVerify {
		return
	}
	f.VerifyFailedReason = sanitizeCode(reason, "")
	if p, err := strconv.Atoi(params["port"]); err == nil && p >= 1 && p <= 65535 {
		f.VerifyFailedPort = &p
	}
}

// uncertainCode is the code an uncertain outcome is recorded with. An answer Alice lost or could
// not read (a dropped connection, a killed helper, malformed output: ssh.protocol_error, and
// ssh.helper_missing for an exit status without JSON, which a killed helper also produces) says
// nothing true about a deployment that is being recovered, so it is recorded as "not known yet".
// Causes that name something real stay: ssh.unreachable, ssh.timeout, nginx.busy, and a verification
// reason. A final state never goes through here.
func uncertainCode(code string) string {
	switch code {
	case "ssh.protocol_error", "ssh.helper_missing":
		return interruptedCode
	}
	return firstCode(code)
}

func uncertainRecord(code string, params map[string]string) OutcomeRecord {
	if params == nil {
		params = map[string]string{}
	}
	return OutcomeRecord{Finish: DeploymentFinish{Result: string(providers.DeployUncertain), ErrorCode: uncertainCode(code), Params: params}}
}

// DeployOutcomeRecord maps what DeployCertificate returned (outcome.go's shapes) to the record:
//
//	committed, verified                      succeeded        (result committed)
//	unchanged, verified                      unchanged        (result unchanged)
//	committed or unchanged, not verified     uncertain        (a success is never recorded unverified)
//	no_change (a refusal; or phase unchanged failed     (nothing was written by this call; reason,
//	  with a failed verification)                             params; the verification failure)
//	rolled_back                              rolled_back      (failed_step, cause_step, helper error)
//	rollback_failed                          rollback_failed  (RetryRollback for phase restore_failed)
//	uncertain                                uncertain        (reason or the error's code; the
//	                                                          verification failure it carries)
//
// resent: the operation id was sent before (a re-send); then no_change means only "this call
// changed nothing" and is uncertain. An outcome that fails CheckDeployReturn (an invalid shape, an
// illegal pairing with err, ErrUnsupported) is uncertain with reason deployment.interrupted.
func DeployOutcomeRecord(o providers.DeployOutcome, err error, resent bool) OutcomeRecord {
	if providers.CheckDeployReturn(o, err) != nil {
		return uncertainRecord("", nil)
	}
	f := DeploymentFinish{Result: string(o.Result), Phase: o.Phase, FailedStep: o.FailedStep, CauseStep: o.CauseStep, HelperError: o.Error,
		Verified: o.Verified, Params: paramsOf(o.Params, err), Trust: o.Trust}
	switch o.Result {
	case providers.DeployCommitted, providers.DeployUnchanged:
		if oneOf(o.Verified, verifies) == "" {
			return uncertainRecord("", nil)
		}
		f.Status, f.Params = DeployStatusSucceeded, map[string]string{}
		if o.Result == providers.DeployUnchanged {
			f.Status = DeployStatusUnchanged
		}
		return OutcomeRecord{Terminal: true, Finish: f}
	case providers.DeployNoChange:
		if resent {
			return uncertainRecord(firstCode(o.Reason, providerCode(err)), paramsOf(o.Params, err))
		}
		// The helper's well-formed refusal or no_change answer: this operation wrote nothing.
		f.Status, f.ErrorCode, f.NothingWritten = DeployStatusFailed, firstCode(o.Reason, providerCode(err)), true
		verifyFailure(&f, o.FailedStep, o.Reason, f.Params)
		return OutcomeRecord{Terminal: true, Finish: f}
	case providers.DeployRolledBack, providers.DeployRollbackFailed:
		f.Status, f.ErrorCode = DeployStatusRolledBack, firstCode(o.Reason)
		if o.Result == providers.DeployRollbackFailed {
			f.Status = DeployStatusRollbackFailed
		}
		verifyFailure(&f, o.FailedStep, o.Reason, f.Params)
		return OutcomeRecord{Terminal: true, RetryRollback: o.Phase == providers.PhaseRestoreFailed, Finish: f}
	}
	// Uncertain (CheckDeployReturn admits no other result).
	r := uncertainRecord(firstCode(o.Reason, providerCode(err)), paramsOf(o.Params, err))
	verifyFailure(&r.Finish, "", o.Reason, r.Finish.Params)
	return r
}

// RollbackOutcomeRecord maps what RollbackDeployment returned to the record; cause is why the
// deployment was rolled back (the recorded verification failure, or "" for an interruption):
//
//	rolled_back                               rolled_back      (error_code = cause)
//	rollback_failed                           rollback_failed  (RetryRollback for restore_failed)
//	no_change, phase prepared or unchanged    failed           (the helper: nothing to restore, the
//	  ("nothing to restore")                                   operation wrote nothing; error_code = cause)
//	no_change deployment.superseded           rollback_failed  (final: a later operation replaced the
//	                                                           files; Alice cannot say what they hold)
//	other no_change (busy, unknown operation, uncertain        (nothing was restored; the journal and
//	  sudo, ...)                                               a later recovery decide)
//	uncertain, or an invalid return           uncertain
func RollbackOutcomeRecord(o providers.RollbackOutcome, err error, cause string) OutcomeRecord {
	if providers.CheckRollbackReturn(o, err) != nil {
		return uncertainRecord("", nil)
	}
	causeCode := firstCode(cause)
	f := DeploymentFinish{Result: string(o.Result), Phase: o.Phase, FailedStep: o.FailedStep, CauseStep: o.CauseStep, HelperError: o.Error,
		Verified: o.Verified, Params: paramsOf(o.Params, err)}
	switch o.Result {
	case providers.DeployRolledBack:
		f.Status, f.ErrorCode = DeployStatusRolledBack, causeCode
		return OutcomeRecord{Terminal: true, Finish: f}
	case providers.DeployRollbackFailed:
		f.Status, f.ErrorCode = DeployStatusRollbackFailed, firstCode(o.Reason)
		return OutcomeRecord{Terminal: true, RetryRollback: o.Phase == providers.PhaseRestoreFailed, Finish: f}
	case providers.DeployNoChange:
		switch {
		case o.Phase != "":
			// "Nothing to restore": the helper's journal says the operation wrote nothing.
			f.Status, f.ErrorCode, f.NothingWritten = DeployStatusFailed, causeCode, true
			return OutcomeRecord{Terminal: true, Finish: f}
		case o.Reason == "deployment.superseded":
			f.Status, f.ErrorCode = DeployStatusRollbackFailed, o.Reason
			return OutcomeRecord{Terminal: true, Finish: f}
		}
	}
	return uncertainRecord(firstCode(o.Reason, providerCode(err)), paramsOf(o.Params, err))
}
