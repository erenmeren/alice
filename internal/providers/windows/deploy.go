package windows

import (
	"context"
	"encoding/json"
	"slices"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/windows/winproto"
)

// The write subcommands' contract on Alice's side (R61, W2 Task 7), mirroring the Nginx provider's
// (internal/providers/nginx/deploy.go): the refusal tables, the sorting of one call into answer,
// refusal or uncertain, and the helper's vocabulary of steps, phases and error classes.

// Refusal codes per subcommand with the exit status the helper gives each (winhelper's write
// subcommands, W2 Task 3: usage and input at 2, preconditions at 3, failures before the first change at
// 4). Only such an answer (well-formed JSON, ok false, a code of the table at its exit status) is a
// refusal that changed nothing; any other code, or a known code at another exit status, is an answer
// Alice does not understand: uncertain. OUTCOME_UNKNOWN (the budget ended after the helper's first
// durable write) is in no table on purpose. UNKNOWN_SUBCOMMAND at 2 is a W1 helper's answer (W2 Ruling
// 3): it changes nothing.
var (
	inputRefusals = map[string]int{
		winproto.CodeUsage: winproto.ExitRefused, winproto.CodeUnknownSubcommand: winproto.ExitRefused,
		winproto.CodeInvalidArgument: winproto.ExitRefused, winproto.CodeBadContent: winproto.ExitRefused,
		winproto.CodeTooLarge: winproto.ExitRefused, winproto.CodeNotElevated: winproto.ExitRefused,
		winproto.CodeBusy: winproto.ExitFailed, winproto.CodeJournalFailed: winproto.ExitFailed,
		winproto.CodeIOError: winproto.ExitFailed, winproto.CodeStoreError: winproto.ExitFailed,
	}
	deployRefusals = withCodes(inputRefusals, winproto.ExitPrecondition, winproto.CodeHashMismatch, winproto.CodeFenced,
		winproto.CodeOperationExists, winproto.CodeRecoveryPending, winproto.CodeBindingNotFound, winproto.CodeKeyUnusable)
	restoreRefusals = withCodes(inputRefusals, winproto.ExitPrecondition, winproto.CodeUnknownOp, winproto.CodeSuperseded,
		winproto.CodeBackupMissing, winproto.CodeCCSPathUnsupported)
	// ccs-deploy (W5 Ruling 14): iis-deploy's refusals and the CCS preconditions, each changing nothing.
	ccsDeployRefusals = withCodes(deployRefusals, winproto.ExitPrecondition, winproto.CodeCCSDisabled, winproto.CodeCCSPathChanged,
		winproto.CodeCCSPathUnsupported, winproto.CodeCCSPasswordMismatch, winproto.CodeCCSFileNotFound)
)

// withCodes is base with codes added at exit.
func withCodes(base map[string]int, exit int, codes ...string) map[string]int {
	out := make(map[string]int, len(base)+len(codes))
	for k, v := range base {
		out[k] = v
	}
	for _, c := range codes {
		out[c] = exit
	}
	return out
}

// The helper's vocabulary of a transaction answer: the step names, the steps that can start a restore
// (the cause), the steps a restore fails at, the error classes, and the journal phases.
var (
	helperSteps = []string{winproto.StepImportChain, winproto.StepImportCertificate, winproto.StepBind, winproto.StepJournal,
		winproto.StepRestore, winproto.StepWriteFile}
	causeSteps = []string{winproto.StepImportChain, winproto.StepImportCertificate, winproto.StepBind, winproto.StepJournal,
		winproto.StepWriteFile}
	helperErrors = []string{winproto.ErrKeyUnusable, winproto.ErrReadBack, winproto.ErrStore, winproto.ErrFileChanged,
		winproto.ErrForbidden, winproto.ErrBackupMissing, winproto.ErrIO}
	helperPhases = []string{winproto.PhaseNone, winproto.PhasePrepared, winproto.PhaseWriting, winproto.PhaseCommitted,
		winproto.PhaseUnchanged, winproto.PhaseRestoring, winproto.PhaseRestored, winproto.PhaseRestoreFailed, winproto.PhaseFenced,
		winproto.PhaseRestoreForbidden}
)

// maxAnswerSteps bounds the steps of one answer (the helper trims its journal's list to 64).
const maxAnswerSteps = 64

// knownClass: an error class of the helper or "".
func knownClass(c string) bool { return c == "" || slices.Contains(helperErrors, c) }

// knownCause: a step that can start a restore, or "" (a restore of a committed operation).
func knownCause(c string) bool { return c == "" || slices.Contains(causeSteps, c) }

// restoreFailedShape: restore_failed at the restore (any class but forbidden) or at the bind (the record
// was gone at the bind: file_changed, its own cause), with a known cause.
func restoreFailedShape(failed, cause, class string) bool {
	switch {
	case !knownClass(class) || class == "" || class == winproto.ErrForbidden || !knownCause(cause):
		return false
	case failed == winproto.StepRestore:
		return true
	}
	return failed == winproto.StepBind && cause == winproto.StepBind && class == winproto.ErrFileChanged
}

// forbiddenShape: the helper's guard refused a restore (R48): failed_step restore, error forbidden, a
// known cause.
func forbiddenShape(failed, cause, class string) bool {
	return failed == winproto.StepRestore && class == winproto.ErrForbidden && knownCause(cause)
}

// toSteps checks the steps of an answer against the helper's vocabulary and converts them.
func toSteps(in []winproto.Step) ([]providers.DeployStep, bool) {
	if len(in) > maxAnswerSteps {
		return nil, false
	}
	var out []providers.DeployStep // nil for none
	for _, st := range in {
		var status providers.StepStatus
		switch st.Status {
		case winproto.StepOK:
			status = providers.StepOK
		case winproto.StepFailed:
			status = providers.StepFailed
		default:
			return nil, false
		}
		if !slices.Contains(helperSteps, st.Name) || !knownClass(st.Error) {
			return nil, false
		}
		out = append(out, providers.DeployStep{Name: st.Name, Status: status, Error: st.Error})
	}
	return out, true
}

func anyFailed(steps []providers.DeployStep) bool {
	return slices.ContainsFunc(steps, func(st providers.DeployStep) bool { return st.Status == providers.StepFailed })
}

// step reports one step to the logger (nil: none).
func step(log providers.StepLogger, name string, status providers.StepStatus, params map[string]string) {
	if log != nil {
		log.Step(name, status, params)
	}
}

// logSteps reports the steps of a helper answer, each once with its final status (param error = its
// class when it has one).
func logSteps(log providers.StepLogger, steps []providers.DeployStep) {
	for _, st := range steps {
		var params map[string]string
		if st.Error != "" {
			params = map[string]string{"error": st.Error}
		}
		step(log, st.Name, st.Status, params)
	}
}

// validGuard: the lists are what the helper accepts (winproto.ValidForbidden).
func validGuard(g providers.RollbackGuard) bool {
	return winproto.ValidForbidden(g.ForbiddenSPKI) && winproto.ValidForbidden(g.ForbiddenLeaf)
}

// restoreInput is the JSON of winproto.RestoreInput for a guard: both members always, empty arrays
// when the guard lists nothing (the helper requires both, W2 Ruling 4).
func restoreInput(g providers.RollbackGuard) []byte {
	in := winproto.RestoreInput{ForbiddenSPKI: g.ForbiddenSPKI, ForbiddenLeaf: g.ForbiddenLeaf}
	if in.ForbiddenSPKI == nil {
		in.ForbiddenSPKI = []string{}
	}
	if in.ForbiddenLeaf == nil {
		in.ForbiddenLeaf = []string{}
	}
	raw, _ := json.Marshal(in) // strings only: cannot fail
	return raw
}

// writeCall is one write subcommand's result sorted into the three situations: an answer (exit 0,
// decoded), a refusal that changed nothing (refusal != nil, mapped; code the helper's, "" for Alice's
// own before sending) or an uncertain outcome (uncertain != nil).
type writeCall[T any] struct {
	answer    T
	code      string
	refusal   *providers.Error
	uncertain error
}

// runWrite runs one write subcommand on a fresh connection of its own (W1 Ruling 5: Pool.AcquireFresh,
// one Run, closed after) with stdin, and sorts the result (decodeCall). Everything before the command
// can have been sent is a refusal: a command that cannot be built, a connection that cannot be opened
// (nothing reached the helper), a context that ended before Run. The command's copy of stdin is wiped
// after the call; the caller clears its own.
func runWrite[T any](ctx context.Context, s *session, sub string, stdin []byte, refusals map[string]int, args ...string) writeCall[T] {
	c, err := cmd(sub, stdin, args...)
	if err != nil {
		return writeCall[T]{refusal: providers.NewError(reasonUnexpected, false, err, map[string]string{"subcommand": sub})}
	}
	defer c.WipeInput()
	conn, release, err := s.pool.AcquireFresh(ctx, s.target, s.cfg, s.cred)
	if err != nil {
		return writeCall[T]{refusal: asProviderError(err)}
	}
	if err := ctx.Err(); err != nil {
		release(false)
		return writeCall[T]{refusal: providers.NewError("ssh.timeout", true, err, map[string]string{"subcommand": sub})}
	}
	res, runErr := conn.Run(ctx, c)
	release(false)
	return decodeCall[T](res, runErr, sub, refusals)
}

// decodeCall sorts what Conn.Run returned for a write subcommand. A refusal is only the helper's JSON
// error with a code of refusals at the exit status the table gives it. Everything else that is not an
// exit-0 answer is uncertain: a transport error, a timeout or cancellation after the command was sent,
// a helper killed at a crash point (no answer: exit 255, ssh.helper_missing → windows.helper_missing),
// any other status without JSON, malformed JSON (ssh.protocol_error), an unknown code, or a known code
// at the wrong exit status (OUTCOME_UNKNOWN among them).
func decodeCall[T any](res linuxssh.Result, runErr error, sub string, refusals map[string]int) writeCall[T] {
	if runErr != nil {
		return writeCall[T]{uncertain: mapHelper(runErr)}
	}
	v, err := linuxssh.DecodeHelper[T](res, sub)
	if err == nil {
		return writeCall[T]{answer: v}
	}
	pe := asProviderError(err)
	code := pe.Params["helper_code"]
	switch exit, known := refusals[code]; {
	case code == "":
		return writeCall[T]{uncertain: mapHelper(pe)}
	case !known || exit != res.ExitCode:
		u := protocolError(sub, "a refusal outside the helper's contract")
		u.Params["helper_code"] = code
		u.Cause = pe
		return writeCall[T]{uncertain: u}
	}
	return writeCall[T]{code: code, refusal: asProviderError(mapHelper(pe))}
}
