package windows

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/google/uuid"

	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
)

// Reasons of a rollback besides mapHelper's.
const (
	reasonRollbackFailed    = "deployment.rollback_failed" // params store, previous_sha1
	reasonNothingToRestore  = "deployment.nothing_to_restore"
	reasonVerifyUnreachable = "deployment.verify_unreachable"
)

// restoreResult is one iis-restore sorted: a refusal (refusal != nil, code), or an answer (phase,
// failedStep, causeStep and class as the helper gave them, this call's steps). An uncertain call is
// restore's error.
type restoreResult struct {
	refusal                      *providers.Error
	code                         string
	phase                        string
	failedStep, causeStep, class string
	steps                        []providers.DeployStep
}

// restore runs iis-restore of op once on a fresh connection, with the guard's lists on stdin (always
// both, W2 Ruling 11: the helper checks them with its journal's on every restore), and checks the
// answer against the helper's contract; the error is an uncertain outcome. The steps are reported to
// log. A helper below WriteMinVersion is refused before anything is sent (W2 Ruling 3).
func (s *session) restore(ctx context.Context, op uuid.UUID, guard providers.RollbackGuard, log providers.StepLogger) (restoreResult, error) {
	const sub = winproto.SubIISRestore
	if err := s.writeReady(); err != nil {
		return restoreResult{refusal: asProviderError(err)}, nil
	}
	if !validGuard(guard) {
		return restoreResult{refusal: providers.NewError(reasonUnexpected, false, errors.New("windows: the rollback guard is not a list the helper takes"), nil)}, nil
	}
	in := restoreInput(guard)
	c := runWrite[winproto.RestoreResponse](ctx, s, sub, in, restoreRefusals, winproto.ArgOp, op.String())
	clear(in)
	switch {
	case c.uncertain != nil:
		return restoreResult{}, c.uncertain
	case c.refusal != nil:
		return restoreResult{refusal: c.refusal, code: c.code}, nil
	}
	a := c.answer
	steps, ok := toSteps(a.Steps)
	if !ok {
		return restoreResult{}, protocolError(sub, "steps outside the helper's vocabulary")
	}
	switch a.Phase {
	case winproto.PhaseFenced:
		// Fenced by a recovery (AUD-05): the operation never ran, nothing was restored (as for an
		// unknown operation: a refusal, never "nothing to restore" of a journal that exists).
		if len(steps) > 0 {
			return restoreResult{}, protocolError(sub, "a fenced operation with steps")
		}
		return restoreResult{refusal: providers.NewError(reasonUnknownOperation, false, nil, nil), code: winproto.CodeUnknownOp}, nil
	case winproto.PhasePrepared, winproto.PhaseUnchanged:
		if len(steps) > 0 {
			return restoreResult{}, protocolError(sub, "nothing to restore, with steps")
		}
	case winproto.PhaseRestored:
		// failed_step, cause_step and error echo the deployment's journal: not this call's.
		if anyFailed(steps) {
			return restoreResult{}, protocolError(sub, "restored with a failed step")
		}
	case winproto.PhaseRestoreFailed:
		if !restoreFailedShape(a.FailedStep, a.CauseStep, a.Error) {
			return restoreResult{}, protocolError(sub, "a restore_failed answer outside the helper's contract")
		}
	case winproto.PhaseRestoreForbidden:
		// R48: the guard refused the restore (now, or in an earlier call: answered as recorded).
		if !forbiddenShape(a.FailedStep, a.CauseStep, a.Error) || slices.ContainsFunc(steps, func(st providers.DeployStep) bool { return st.Status != providers.StepFailed }) {
			return restoreResult{}, protocolError(sub, "a restore_forbidden answer outside the helper's contract")
		}
	default:
		return restoreResult{}, protocolError(sub, "an unknown phase")
	}
	logSteps(log, steps)
	return restoreResult{phase: a.Phase, failedStep: a.FailedStep, causeStep: a.CauseStep, class: a.Error, steps: steps}, nil
}

// backupParams are a rollback failure's params (W2 Ruling 17): where the previous certificate is, from
// the location's details as discovery read them (store, cert_sha1), each only when known. Alice's own
// values, never text from this call's answer.
func backupParams(loc providers.CertLocation) map[string]string {
	out := map[string]string{}
	for key, name := range map[string]string{"store": "store", "cert_sha1": "previous_sha1"} {
		if v, ok := loc.Details[key].(string); ok && v != "" {
			out[name] = cleanValue(v, maxStoreLength)
		}
	}
	return out
}

// restoreFailedReason is the reason of a restore_failed by its class: the Windows conditions named, any
// other failure deployment.rollback_failed.
func restoreFailedReason(class string) string {
	switch class {
	case winproto.ErrBackupMissing:
		return ReasonBackupMissing
	case winproto.ErrKeyUnusable:
		return ReasonKeyUnusable
	case winproto.ErrStore:
		return ReasonStoreError
	}
	return reasonRollbackFailed
}

// RollbackDeployment puts the previous certificate back on the binding (iis-restore: one whole-record
// update back to the record the journal holds, read back, under the guard the helper checks itself)
// and verifies the previous certificate (req.OldFingerprint, req.OldChainLength). It is idempotent: a
// restored operation answers restored again without a write. Every return is a legal shape
// (providers.RollbackOutcome.Validate, CheckRollbackReturn):
//
//   - restored, the previous certificate verified (or not checkable): rolled_back, Phase restored,
//     no failed_step, cause_step or error (the helper echoes the deployment's; they are dropped);
//   - restored, another certificate served: rollback_failed, Phase restored, FailedStep verify_old;
//   - restore_failed: rollback_failed, Phase restore_failed, the helper's failed_step, cause_step and
//     error (file_changed: the binding names a third certificate or is gone, nothing written), the
//     reason by its class (restoreFailedReason), params store and previous_sha1;
//   - BACKUP_MISSING (the previous certificate is not in its store with a usable key; nothing written):
//     rollback_failed windows.backup_missing, Phase "", FailedStep restore, Error backup_missing,
//     params store and previous_sha1;
//   - restore_forbidden (R48, the helper's guard): rollback_failed deployment.rollback_forbidden,
//     failed_step restore, error forbidden, cause_step the journal's;
//   - nothing to restore (prepared, unchanged): no_change with that Phase and a nil error;
//   - UNKNOWN_OP (and a fenced operation), SUPERSEDED, a W1 helper (windows.helper_outdated, refused
//     before sending or by its UNKNOWN_SUBCOMMAND), BUSY and every other well-formed refusal, and a
//     refusal before sending: no_change, Phase "", a *providers.Error;
//   - anything else: uncertain with the error.
func (s *session) RollbackDeployment(ctx context.Context, req providers.RollbackRequest, log providers.StepLogger) (providers.RollbackOutcome, error) {
	refuse := func(e *providers.Error) (providers.RollbackOutcome, error) {
		return providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: e.Code, Params: maps.Clone(e.Params)}, e
	}
	if !s.caps.Has(providers.CapDeployCertificate) {
		return providers.RollbackOutcome{}, providers.ErrUnsupported
	}
	if err := s.open(); err != nil {
		return refuse(asProviderError(err))
	}
	r, err := s.restore(ctx, req.OperationID, req.Guard, log)
	if err != nil {
		return providers.RollbackOutcome{Result: providers.DeployUncertain}, err
	}
	if r.phase == winproto.PhaseRestoreForbidden {
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreForbidden, FailedStep: providers.StepNameRestore,
			CauseStep: r.causeStep, Error: providers.DeployErrForbidden, Steps: r.steps, Reason: providers.ReasonRollbackForbidden, Params: map[string]string{}}, nil
	}
	backup := backupParams(req.Location)
	if r.refusal != nil {
		if r.code == winproto.CodeBackupMissing {
			return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: providers.StepNameRestore,
				Error: winproto.ErrBackupMissing, Reason: ReasonBackupMissing, Params: backup}, nil
		}
		return refuse(r.refusal)
	}
	switch r.phase {
	case winproto.PhasePrepared, winproto.PhaseUnchanged:
		return providers.RollbackOutcome{Result: providers.DeployNoChange, Phase: r.phase, Reason: reasonNothingToRestore}, nil
	case winproto.PhaseRestoreFailed:
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: r.failedStep,
			CauseStep: r.causeStep, Error: r.class, Steps: r.steps, Reason: restoreFailedReason(r.class), Params: backup}, nil
	}
	out := providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Steps: r.steps}
	v, ok := s.checkOld(ctx, log, providers.VerifyRequest{Location: req.Location, Fingerprint: req.OldFingerprint, ChainLength: req.OldChainLength,
		SANs: req.OldSANs, KeyType: req.KeyType, Verify: req.Verify})
	out.Steps = append(out.Steps, v.step)
	if !ok {
		out.Result, out.FailedStep, out.Reason, out.Params = providers.DeployRollbackFailed, providers.StepNameVerifyOld, reasonRollbackFailed, backup
		return out, nil
	}
	out.Verified = v.mode
	return out, nil
}

// oldCheck is the result of checking the previous certificate after a rollback.
type oldCheck struct {
	step providers.DeployStep
	mode string // Verified: "remote", "local", "skipped" or "" (not checked)
}

// verifyDeployment is the session's verification (VerifyDeployment), or the test seam.
func (s *session) verifyDeployment(ctx context.Context, req providers.VerifyRequest) (providers.VerifyResult, error) {
	if s.verify != nil {
		return s.verify(ctx, req)
	}
	return s.VerifyDeployment(ctx, req)
}

// checkOld verifies the previous certificate (step verify_old), as the Nginx provider does. ok is false
// only when the website serves another certificate; nothing to compare (no previous fingerprint), a
// skipped verification and a website that cannot be checked (also a verification that errs) are ok
// with mode "skipped" or "".
func (s *session) checkOld(ctx context.Context, log providers.StepLogger, vreq providers.VerifyRequest) (oldCheck, bool) {
	if vreq.Fingerprint == "" {
		step(log, providers.StepNameVerifyOld, providers.StepSkipped, nil)
		return oldCheck{step: providers.DeployStep{Name: providers.StepNameVerifyOld, Status: providers.StepSkipped}}, true
	}
	step(log, providers.StepNameVerifyOld, providers.StepStarted, nil)
	vr, err := s.verifyDeployment(ctx, vreq)
	if err != nil {
		vr = providers.VerifyResult{Reason: reasonVerifyUnreachable, Params: map[string]string{"port": locatorPort(vreq.Location)},
			Failure: providers.VerifyFailureNetwork}
	}
	failed := oldCheck{step: providers.DeployStep{Name: providers.StepNameVerifyOld, Status: providers.StepFailed}}
	switch {
	case !vr.OK && vr.Reason == reasonVerifyUnreachable:
		step(log, providers.StepNameVerifyOld, providers.StepFailed, map[string]string{"port": vr.Params["port"]})
		return failed, true
	case !vr.OK:
		step(log, providers.StepNameVerifyOld, providers.StepFailed, map[string]string{"port": vr.Params["port"]})
		return failed, false
	case vr.Mode == "skipped":
		step(log, providers.StepNameVerifyOld, providers.StepSkipped, nil)
		return oldCheck{step: providers.DeployStep{Name: providers.StepNameVerifyOld, Status: providers.StepSkipped}, mode: vr.Mode}, true
	}
	step(log, providers.StepNameVerifyOld, providers.StepOK, map[string]string{"mode": vr.Mode})
	return oldCheck{step: providers.DeployStep{Name: providers.StepNameVerifyOld, Status: providers.StepOK}, mode: vr.Mode}, true
}

// locatorPort is the port a location's locator names ("" when it names none).
func locatorPort(loc providers.CertLocation) string {
	switch p := loc.Locator["port"].(type) {
	case int:
		return fmt.Sprint(p)
	case int64:
		return fmt.Sprint(p)
	case float64:
		if p == float64(int64(p)) {
			return fmt.Sprint(int64(p))
		}
	}
	return ""
}
