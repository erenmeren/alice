package providers

import (
	"errors"
	"fmt"
	"slices"
)

// The invariants below are what Validate and the Check*Return functions enforce; they are the
// contract between providers and the deploy engine.
//
// DeployOutcome by Result (Steps may always be set, each with a name and a known status):
//
//	committed        Phase "" or committed; no failed_step, cause_step, error or reason
//	unchanged        Phase "" or unchanged; no failed_step, cause_step, error or reason
//	no_change        a refusal before any change: no phase, steps, failed_step, cause_step or
//	                 error; reason required. One exception: the helper answered unchanged and the
//	                 verification then failed: Phase unchanged, failed_step verify, a failed verify
//	                 step in Steps (other steps allowed), no cause_step or error, reason required
//	rolled_back      Phase "" or restored; failed_step and reason required
//	rollback_failed  Phase "", restore_failed, restored or restore_forbidden; failed_step and
//	                 reason required. Phase restored means the files ARE back and only the
//	                 verification of the old certificate failed (failed_step must be verify_old);
//	                 restore_failed means they are not (fully) back; restore_forbidden (R48) means
//	                 the guard refused the restore and nothing was put back (failed_step restore,
//	                 error forbidden)
//	uncertain        no phase, failed_step, cause_step or error
//
// Any other Result, including "", is invalid.
//
// Legal shapes the Nginx provider maps (Result; Phase; FailedStep; CauseStep; error returned):
//
//	provider-side refusal before the helper (location unsupported)
//	                              no_change; ""; ""; ""; *Error
//	helper refusal                no_change; ""; ""; ""; *Error
//	helper committed, verify ok   committed; committed; ""; ""; nil
//	helper unchanged, verify ok   unchanged; unchanged; ""; ""; nil
//	helper unchanged, verify bad  no_change; unchanged; verify; ""; *Error (Verified "")
//	committed, verify bad, rolled back, old certificate verifies
//	                              rolled_back; restored; verify; verify; nil
//	committed, verify bad, files back, old certificate does not verify
//	                              rollback_failed; restored; verify_old; verify; nil
//	helper restored (its own nginx -t or reload failed)
//	                              rolled_back; restored; <failed step>; <same>; nil, Error = its class
//	helper restore_failed (file_changed with the starting step as failed_step and Error
//	file_changed; the restore step; rollback_reload; rollback_config_test)
//	                              rollback_failed; restore_failed; <that step>; <cause>; nil
//	the guard refused the restore (the helper's restore_forbidden, R48)
//	                              rollback_failed; restore_forbidden; restore; <cause>; nil, Error forbidden
//	the guard refused the restore before anything was sent (a helper that cannot check it)
//	                              rollback_failed; ""; restore; <cause>; nil, Error forbidden
//	anything unknown              uncertain; ""; ""; ""; non-nil error
//
// RollbackDeployment: an unknown operation and SUPERSEDED are no_change with phase "" and a *Error;
// the helper's "nothing to restore" is no_change with phase prepared or unchanged and a nil error;
// HASH_MISMATCH on restore is rollback_failed with phase "", failed_step restore and Error
// file_changed; restored with a failing old verification is rollback_failed with phase restored
// and failed_step verify_old.
//
// The session method returns the outcome together with an error as follows (CheckDeployReturn):
// committed, unchanged, rolled_back and rollback_failed come with a nil error (a known change is
// an outcome, never an error); no_change comes with a non-nil *Error (a well-formed refusal);
// uncertain comes with a non-nil error (why Alice does not know). ErrUnsupported is none of these.
//
// no_change means "this call changed nothing". On a RE-SENT operation ID (the same operation sent
// again, e.g. after an uncertain outcome) it does not mean that the files are unchanged since before
// the first send: an earlier send of the operation may have changed them. Read DeploymentStatus
// before re-sending an operation, and never conclude from a re-send's no_change that nothing
// happened.
//
// A caller must treat an outcome that fails Validate or CheckDeployReturn, a blank or unknown
// Result, or any error the provider did not map to one of the above, as uncertain: it reads the
// truth with DeploymentStatus and never as "no change".

// restoredNeedsVerifyOld: rollback_failed with Phase restored means the helper put the files back
// and only the verification of the old certificate failed, so the failed step is verify_old; any
// other failure leaves the files not (fully) back, which is Phase restore_failed (or "").
func restoredNeedsVerifyOld(phase, failedStep string) error {
	if phase == PhaseRestored && failedStep != StepNameVerifyOld {
		return fmt.Errorf("rollback_failed with phase restored: failed_step must be %s, got %q", StepNameVerifyOld, failedStep)
	}
	return nil
}

// forbiddenNeedsRestore: rollback_failed with Phase restore_forbidden (R48) is the guard's refusal
// of the restore step: failed_step restore and error forbidden; and error forbidden names that
// refusal only (failed_step restore, Phase "" or restore_forbidden).
func forbiddenNeedsRestore(phase, failedStep, class string) error {
	switch {
	case phase == PhaseRestoreForbidden && (failedStep != StepNameRestore || class != DeployErrForbidden):
		return fmt.Errorf("rollback_failed with phase restore_forbidden: failed_step must be %s and error %s, got %q and %q",
			StepNameRestore, DeployErrForbidden, failedStep, class)
	case class == DeployErrForbidden && (failedStep != StepNameRestore || (phase != "" && phase != PhaseRestoreForbidden)):
		return fmt.Errorf("rollback_failed with error %s: failed_step must be %s and phase blank or %s", DeployErrForbidden, StepNameRestore,
			PhaseRestoreForbidden)
	}
	return nil
}

func orBlank(s string) string {
	if s == "" {
		return "blank"
	}
	return s
}

func checkSteps(steps []DeployStep) error {
	for i, st := range steps {
		if st.Name == "" {
			return fmt.Errorf("step %d: no name", i)
		}
		switch st.Status {
		case StepStarted, StepOK, StepFailed, StepSkipped:
		default:
			return fmt.Errorf("step %d: unknown status %q", i, st.Status)
		}
	}
	return nil
}

func forbid(rule string, fields map[string]string) error {
	for _, name := range []string{"phase", "failed_step", "cause_step", "error", "reason"} {
		if v, ok := fields[name]; ok && v != "" {
			return fmt.Errorf("%s: %s must be empty, got %q", rule, name, v)
		}
	}
	return nil
}

func require(rule, name, v string) error {
	if v == "" {
		return fmt.Errorf("%s: %s is required", rule, name)
	}
	return nil
}

func phaseIn(rule, phase string, allowed ...string) error {
	if phase != "" && !slices.Contains(allowed, phase) {
		return fmt.Errorf("%s: phase %q is not one of %v", rule, phase, allowed)
	}
	return nil
}

// Validate checks the invariants documented above; the error names the violated rule.
func (o DeployOutcome) Validate() error {
	if err := checkSteps(o.Steps); err != nil {
		return fmt.Errorf("providers: deploy outcome: %w", err)
	}
	f := map[string]string{"failed_step": o.FailedStep, "cause_step": o.CauseStep, "error": o.Error}
	var err error
	switch o.Result {
	case DeployCommitted, DeployUnchanged:
		want := PhaseCommitted
		if o.Result == DeployUnchanged {
			want = PhaseUnchanged
		}
		f["reason"] = o.Reason
		err = errors.Join(phaseIn(string(o.Result), o.Phase, want), forbid(string(o.Result), f))
	case DeployNoChange:
		if o.Phase == PhaseUnchanged {
			// The helper said "unchanged" and the verification then failed.
			rule := "no_change with phase unchanged"
			if o.FailedStep != StepNameVerify {
				err = fmt.Errorf("%s: failed_step must be %s, got %q", rule, StepNameVerify, o.FailedStep)
			}
			if !slices.ContainsFunc(o.Steps, func(st DeployStep) bool { return st.Name == StepNameVerify && st.Status == StepFailed }) {
				err = errors.Join(err, fmt.Errorf("%s: steps must hold the failed %s step", rule, StepNameVerify))
			}
			err = errors.Join(err, forbid(rule, map[string]string{"cause_step": o.CauseStep, "error": o.Error}),
				require("no_change", "reason", o.Reason))
			break
		}
		f["phase"] = o.Phase
		if len(o.Steps) > 0 {
			err = fmt.Errorf("no_change: steps must be empty, got %d", len(o.Steps))
		}
		err = errors.Join(err, forbid("no_change", f), require("no_change", "reason", o.Reason))
	case DeployRolledBack, DeployRollbackFailed:
		rule := string(o.Result)
		if o.Result == DeployRolledBack {
			err = phaseIn(rule, o.Phase, PhaseRestored)
		} else {
			err = errors.Join(phaseIn(rule, o.Phase, PhaseRestoreFailed, PhaseRestored, PhaseRestoreForbidden),
				restoredNeedsVerifyOld(o.Phase, o.FailedStep), forbiddenNeedsRestore(o.Phase, o.FailedStep, o.Error))
		}
		err = errors.Join(err, require(rule, "failed_step", o.FailedStep), require(rule, "reason", o.Reason))
	case DeployUncertain:
		f["phase"] = o.Phase
		err = forbid("uncertain", f)
	default:
		err = fmt.Errorf("blank or unknown result %q", string(o.Result))
	}
	if err != nil {
		return fmt.Errorf("providers: deploy outcome: %w", err)
	}
	return nil
}

// Validate checks RollbackOutcome's invariants (Result by case; Steps may always be set):
//
//	rolled_back      Phase "" or restored; no failed_step, cause_step, error or reason
//	rollback_failed  Phase "", restore_failed, restored (verify_old failed) or restore_forbidden
//	                 (the guard refused, R48: failed_step restore, error forbidden); failed_step and
//	                 reason required
//	no_change        Phase "", prepared or unchanged; no steps, failed_step, cause_step or
//	                 error; reason required. Phase prepared or unchanged is the helper's answer
//	                 "nothing to restore"; Phase "" is a refusal such as SUPERSEDED
//	uncertain        no phase, failed_step, cause_step or error
//
// committed, unchanged and any other Result, including "", are invalid. An outcome that fails
// Validate is treated as uncertain by the caller (see DeployOutcome).
func (o RollbackOutcome) Validate() error {
	if err := checkSteps(o.Steps); err != nil {
		return fmt.Errorf("providers: rollback outcome: %w", err)
	}
	f := map[string]string{"failed_step": o.FailedStep, "cause_step": o.CauseStep, "error": o.Error}
	var err error
	switch o.Result {
	case DeployRolledBack:
		f["reason"] = o.Reason
		err = errors.Join(phaseIn("rolled_back", o.Phase, PhaseRestored), forbid("rolled_back", f))
	case DeployRollbackFailed:
		err = errors.Join(phaseIn("rollback_failed", o.Phase, PhaseRestoreFailed, PhaseRestored, PhaseRestoreForbidden),
			restoredNeedsVerifyOld(o.Phase, o.FailedStep), forbiddenNeedsRestore(o.Phase, o.FailedStep, o.Error),
			require("rollback_failed", "failed_step", o.FailedStep), require("rollback_failed", "reason", o.Reason))
	case DeployNoChange:
		if len(o.Steps) > 0 {
			err = fmt.Errorf("no_change: steps must be empty, got %d", len(o.Steps))
		}
		err = errors.Join(err, phaseIn("no_change", o.Phase, PhasePrepared, PhaseUnchanged),
			forbid("no_change", f), require("no_change", "reason", o.Reason))
	case DeployUncertain:
		f["phase"] = o.Phase
		err = forbid("uncertain", f)
	case DeployCommitted, DeployUnchanged:
		err = fmt.Errorf("result %q is not a rollback result", string(o.Result))
	default:
		err = fmt.Errorf("blank or unknown result %q", string(o.Result))
	}
	if err != nil {
		return fmt.Errorf("providers: rollback outcome: %w", err)
	}
	return nil
}

// Validate checks DeploymentState's invariants: Phase is one of the Phase* values (a blank or
// unknown phase is invalid and is treated as uncertain by the caller); phase none means no
// journal, so it carries no failed_step, cause_step, error, hashes or backup directory (Active may
// still be true: another operation holds the lock); phase fenced (a tombstone) carries no
// failed_step, cause_step, error or hash; committed and unchanged carry no failed_step,
// cause_step or error.
func (s DeploymentState) Validate() error {
	var err error
	switch s.Phase {
	case PhaseNone:
		for _, v := range []string{s.FailedStep, s.CauseStep, s.Error, s.NewCertSHA256, s.CurrentCertSHA256, s.BackupDir} {
			if v != "" {
				err = errors.New("none: no journal, so no step, error, hash or backup directory may be set")
				break
			}
		}
	case PhaseFenced:
		for _, v := range []string{s.FailedStep, s.CauseStep, s.Error, s.NewCertSHA256, s.CurrentCertSHA256} {
			if v != "" {
				err = errors.New("fenced: a tombstone, so no step, error or hash may be set")
				break
			}
		}
	case PhaseCommitted, PhaseUnchanged:
		err = forbid(s.Phase, map[string]string{"failed_step": s.FailedStep, "cause_step": s.CauseStep, "error": s.Error})
	case PhasePrepared, PhaseWriting, PhaseRestoring, PhaseRestored, PhaseRestoreFailed, PhaseRestoreForbidden:
	default:
		err = fmt.Errorf("blank or unknown phase %q", orBlank(s.Phase))
	}
	if err != nil {
		return fmt.Errorf("providers: deployment state: %w", err)
	}
	return nil
}

func isProviderError(err error) bool {
	var pe *Error
	return errors.As(err, &pe)
}

// CheckDeployReturn checks what DeployCertificate returned: Validate, then the relation between
// the Result and the error (see the invariants above). A caller treats a non-nil answer as an
// uncertain outcome.
func CheckDeployReturn(out DeployOutcome, err error) error {
	if errors.Is(err, ErrUnsupported) {
		return errors.New("providers: deploy: ErrUnsupported is not an outcome")
	}
	if verr := out.Validate(); verr != nil {
		return verr
	}
	switch {
	case err == nil && out.Result == DeployNoChange:
		return errors.New("providers: deploy: no_change without an error: a refusal carries a *providers.Error")
	case err == nil && out.Result == DeployUncertain:
		return errors.New("providers: deploy: uncertain without an error")
	case err != nil && out.Result != DeployNoChange && out.Result != DeployUncertain:
		return fmt.Errorf("providers: deploy: %s with an error: a known change is an outcome, not an error", out.Result)
	case err != nil && out.Result == DeployNoChange && !isProviderError(err):
		return errors.New("providers: deploy: no_change needs a *providers.Error")
	}
	return nil
}

// CheckRollbackReturn checks what RollbackDeployment returned: Validate, then the relation
// between the Result and the error. Like CheckDeployReturn, except that no_change with Phase
// prepared or unchanged is an answer ("nothing to restore") with a nil error, and any other
// no_change (such as SUPERSEDED) is a refusal with a non-nil *Error.
func CheckRollbackReturn(out RollbackOutcome, err error) error {
	if errors.Is(err, ErrUnsupported) {
		return errors.New("providers: rollback: ErrUnsupported is not an outcome")
	}
	if verr := out.Validate(); verr != nil {
		return verr
	}
	nothing := out.Result == DeployNoChange && out.Phase != ""
	switch {
	case err == nil && out.Result == DeployNoChange && !nothing:
		return errors.New("providers: rollback: refusal needs a *providers.Error")
	case err == nil && out.Result == DeployUncertain:
		return errors.New("providers: rollback: uncertain without an error")
	case err != nil && nothing:
		return errors.New("providers: rollback: nothing to restore is an answer, not an error")
	case err != nil && out.Result != DeployNoChange && out.Result != DeployUncertain:
		return fmt.Errorf("providers: rollback: %s with an error: a known change is an outcome, not an error", out.Result)
	case err != nil && out.Result == DeployNoChange && !isProviderError(err):
		return errors.New("providers: rollback: refusal needs a *providers.Error")
	}
	return nil
}
