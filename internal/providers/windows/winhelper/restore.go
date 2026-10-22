package winhelper

import (
	"context"
	"errors"
	"slices"

	"alice/internal/providers/windows/winproto"
)

// restoreKind is what a restore of an operation would do now (planRestore).
type restoreKind int

const (
	restoreWrite      restoreKind = iota // write the previous record back
	restoreDone                          // the record is the previous one already: nothing to write
	restoreForeign                       // the record names a third certificate or is gone: file_changed
	restoreNoBackup                      // the previous certificate is not in its store with a usable key
	restoreForbidden                     // the guard forbids the previous certificate (R48)
	restoreUnreadable                    // the record could not be read (after the gate only)
	restoreStoreError                    // the store could not be opened (after the gate only)
)

// planRestore reads, never writes, what a restore of j does now (W2 Ruling 12, design §6.5). The
// record must still name the new certificate; when it names the previous one, nothing is written (an
// interrupted operation, partial, has its record written back unless it is exactly the previous
// one: the base may have been replaced and the Ex parameters not). The previous certificate is read
// from the store, never from the journal: its DER must be the one the journal names, with a usable
// key, and the guard (journal lists with the call's) must not list it. Errors are the host's.
func planRestore(ctx context.Context, h WriteHost, j journal, g guard) (restoreKind, error) {
	cur, found, err := h.Binding(ctx, j.Locator)
	if err != nil {
		return 0, err
	}
	if !found {
		return restoreForeign, nil
	}
	partial := j.Phase != winproto.PhaseCommitted
	switch {
	case sameRecord(cur, j.Previous):
		return restoreDone, nil
	case cur.CertSHA1 == j.PreviousSHA1 && !partial:
		return restoreDone, nil // someone else put it back: theirs is left as it is
	case cur.CertSHA1 != j.NewSHA1 && cur.CertSHA1 != j.PreviousSHA1:
		return restoreForeign, nil
	}
	der, usable, found, err := storeCert(ctx, h, j.Store, j.PreviousSHA1)
	if err != nil {
		return 0, err
	}
	if !found || !usable || der == nil || sum256(der) != j.PreviousSHA256 {
		return restoreNoBackup, nil
	}
	if g.forbids(der) {
		return restoreForbidden, nil
	}
	return restoreWrite, nil
}

// applyRestore carries out a planned restore after the gate and records its outcome in the journal.
// The error is errKilled, or a journal that could not say restoring (nothing was written then; the
// answer is OUTCOME_UNKNOWN and iis-status reads the journal as it was).
func applyRestore(ctx context.Context, h WriteHost, j journal, kind restoreKind) (journal, error) {
	j.Steps = trimSteps(j.Steps)
	failRestore := func(class string) (journal, error) {
		j.Steps = append(j.Steps, stepFailed(winproto.StepRestore, class))
		j.Phase, j.FailedStep, j.Error = winproto.PhaseRestoreFailed, winproto.StepRestore, class
		_ = writeJournal(h, j) // the outcome is answered; a journal left at restoring is read as interrupted
		return j, nil
	}
	restored := func() (journal, error) {
		j.Steps = append(j.Steps, stepOK(winproto.StepRestore))
		j.Phase, j.FailedStep = winproto.PhaseRestored, j.CauseStep
		if j.CauseStep == "" {
			j.Error = "" // a restore of a committed operation: no class of an earlier failure applies
		}
		_ = writeJournal(h, j)
		return j, nil
	}
	switch kind {
	case restoreDone:
		return restored()
	case restoreForeign:
		return failRestore(winproto.ErrFileChanged)
	case restoreNoBackup:
		return failRestore(winproto.ErrBackupMissing)
	case restoreStoreError:
		return failRestore(winproto.ErrStore)
	case restoreUnreadable:
		return failRestore("")
	case restoreForbidden:
		j.Steps = append(j.Steps, stepFailed(winproto.StepRestore, winproto.ErrForbidden))
		j.Phase, j.FailedStep, j.Error = winproto.PhaseRestoreForbidden, winproto.StepRestore, winproto.ErrForbidden
		_ = writeJournal(h, j)
		return j, nil
	}
	j.Phase = winproto.PhaseRestoring
	if err := writeJournal(h, j); err != nil {
		return j, err
	}
	if err := point(h, "restore.restoring"); err != nil {
		return j, err
	}
	switch err := h.UpdateBinding(ctx, j.Previous); {
	case errors.Is(err, ErrKeyUnusable):
		return failRestore(winproto.ErrKeyUnusable)
	case errors.Is(err, ErrBindingNotFound):
		return failRestore(winproto.ErrFileChanged)
	case err != nil:
		return failRestore("")
	}
	if err := point(h, "restore.bound"); err != nil {
		return j, err
	}
	back, found, err := h.Binding(ctx, j.Locator)
	if err != nil || !found || !sameRecord(back, j.Previous) {
		return failRestore(winproto.ErrReadBack)
	}
	j, _ = restored()
	if err := point(h, "restore.restored"); err != nil {
		return j, err
	}
	h.Event(eventRestored, eventText(j, j.NewSHA256, j.PreviousSHA256))
	return j, nil
}

// cmdIISRestore answers "iis-restore --op <id>" with a winproto.RestoreInput on stdin (design §6.5,
// W2 Rulings 11 and 12): only the binding's latest operation, from committed, writing, restoring,
// restore_failed or restore_forbidden (re-checked: the guard decides on every path), under the guard
// of the journal's lists and the input's.
func cmdIISRestore(ctx context.Context, c *call) (any, error) {
	op, err := opArg(c.args, winproto.SubIISRestore)
	if err != nil {
		return nil, err
	}
	extra, err := parseRestoreInput(c.input)
	if err != nil {
		return nil, err
	}
	h := c.host
	release, err := lockHelper(ctx, h)
	if err != nil {
		return nil, err
	}
	defer release()
	j, found, err := readJournal(h, op)
	switch {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the journal of this operation cannot be read")
	case !found:
		return nil, precondition(winproto.CodeUnknownOp, "there is no deployment with this operation id")
	}
	answer := func(j journal, from int) winproto.RestoreResponse {
		return winproto.RestoreResponse{OK: true, Phase: j.Phase, FailedStep: j.FailedStep, CauseStep: j.CauseStep, Error: j.Error,
			Steps: slices.Clone(j.Steps[min(from, len(j.Steps)):])}
	}
	switch j.Phase {
	case winproto.PhasePrepared, winproto.PhaseUnchanged, winproto.PhaseRestored, winproto.PhaseFenced:
		return answer(j, len(j.Steps)), nil
	}
	switch sup, err := superseded(h, j); {
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the record of the binding's latest operation cannot be read")
	case sup:
		return nil, precondition(winproto.CodeSuperseded, "a later deployment changed this binding; this one is not rolled back")
	}
	g := guard{SPKI: j.ForbiddenSPKI, Leaf: j.ForbiddenLeaf}.with(extra)
	kind, err := planRestore(ctx, h, j, g)
	switch {
	case errors.Is(err, ErrStore):
		return nil, failed(winproto.CodeStoreError, "a certificate store could not be opened")
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the binding or the previous certificate could not be read")
	case kind == restoreNoBackup:
		return nil, precondition(winproto.CodeBackupMissing, "the previous certificate is not in its store with a usable key")
	case kind == restoreForeign && j.Phase == winproto.PhaseRestoreFailed && j.Error == winproto.ErrFileChanged,
		kind == restoreForbidden && j.Phase == winproto.PhaseRestoreForbidden:
		return answer(j, len(j.Steps)), nil // the same outcome again: nothing rewritten
	}
	wctx, err := c.gate.enter()
	if err != nil {
		return nil, err
	}
	j.Steps = trimSteps(j.Steps)
	before := len(j.Steps)
	j, err = applyRestore(wctx, h, j, kind)
	if err != nil {
		return nil, err
	}
	return answer(j, before), nil
}
