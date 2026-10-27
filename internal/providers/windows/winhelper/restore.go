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
	if j.Kind == winproto.JournalKindCCS {
		return planRestoreCCS(ctx, h, j, g)
	}
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

// planRestoreCCS is planRestore for a CCS journal (W5 Ruling 15). The file must still be the bytes
// this operation wrote; when it is the previous bytes nothing is written. An interrupted operation may
// also have left no file (a ReplaceFileW that failed after moving it aside); a committed one without
// its file was changed by someone. The backup must hold the previous file's bytes, and the guard is
// checked on the journal's previous leaf and SPKI hashes, which those bytes stand for (the backup's
// key is never opened again: a restore has no password).
func planRestoreCCS(ctx context.Context, h WriteHost, j journal, g guard) (restoreKind, error) {
	c := j.CCS
	// The journal's folder is checked again: one that became a reparse point is never written to (W5
	// Ruling 3); ListCCS answers ErrCCSFolderUnsupported for it.
	if _, err := h.ListCCS(ctx, c.Path); err != nil {
		return 0, err
	}
	cur, found, err := ccsFileSum(ctx, h, c.Path, c.File)
	if err != nil {
		return 0, err
	}
	switch {
	case found && cur == c.PreviousFileSHA256:
		return restoreDone, nil
	case found && cur != c.NewFileSHA256, !found && j.Phase == winproto.PhaseCommitted:
		return restoreForeign, nil
	}
	bak, found, err := ccsFileSum(ctx, h, c.Path, c.Backup)
	if err != nil {
		return 0, err
	}
	if !found || bak != c.PreviousFileSHA256 {
		return restoreNoBackup, nil
	}
	if slices.Contains(g.Leaf, j.PreviousSHA256) || slices.Contains(g.SPKI, c.PreviousSPKISHA256) {
		return restoreForbidden, nil
	}
	return restoreWrite, nil
}

// applyRestore carries out a planned restore after the gate and records its outcome in the journal.
// The error is errKilled, or a journal that could not say restoring (nothing was written then; the
// answer is OUTCOME_UNKNOWN and iis-status reads the journal as it was).
func applyRestore(ctx context.Context, h WriteHost, j journal, kind restoreKind, g guard) (journal, error) {
	j.Steps = trimSteps(j.Steps)
	failRestore := func(class string) (journal, error) {
		j.Steps = append(j.Steps, stepFailed(winproto.StepRestore, class))
		j.Phase, j.FailedStep, j.Error = winproto.PhaseRestoreFailed, winproto.StepRestore, class
		_ = writeJournal(h, j) // the outcome is answered; a journal left at restoring is read as interrupted
		return j, nil
	}
	restored := func() (journal, error) {
		j.Steps = append(j.Steps, stepOK(winproto.StepRestore))
		// The cause's class, not a failed earlier restore's (a restore of a committed operation has none).
		j.Phase, j.FailedStep, j.Error = winproto.PhaseRestored, j.CauseStep, j.CauseError
		if j.CCS != nil {
			// IIS serves the file put back only after a refresh (F15, ruling W5-10), also when it was put
			// back before (restoreDone: a restore killed before its refresh).
			c := *j.CCS
			_, err := h.RefreshCCSRecords(ctx)
			c.RefreshFailed = err != nil
			j.CCS = &c
		}
		_ = writeJournal(h, j)
		if j.CCS != nil {
			_ = h.RemoveCCS(ctx, j.CCS.Path, j.CCS.Temp) // best effort: an interrupted write's temporary file; pruning removes it otherwise
		}
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
		return failRestore(winproto.ErrIO)
	case restoreForbidden:
		j.Steps = append(j.Steps, stepFailed(winproto.StepRestore, winproto.ErrForbidden))
		j.Phase, j.FailedStep, j.Error = winproto.PhaseRestoreForbidden, winproto.StepRestore, winproto.ErrForbidden
		// The guard only grows (R48, Linux's final restore_forbidden): the lists that forbade this
		// restore are kept, so no later call with shorter lists puts the certificate back. Past
		// MaxForbidden the outcome is final instead.
		if len(g.SPKI) <= winproto.MaxForbidden && len(g.Leaf) <= winproto.MaxForbidden {
			j.ForbiddenSPKI, j.ForbiddenLeaf = g.SPKI, g.Leaf
		} else {
			j.ForbiddenFinal = true
		}
		// Unlike the other outcomes this write is load-bearing: a restore_forbidden answered while the
		// journal keeps the shorter lists would let a later call restore. Always after the gate, so the
		// error is answered OUTCOME_UNKNOWN (nothing of the record was written).
		if err := writeJournal(h, j); err != nil {
			return j, err
		}
		return j, nil
	}
	// A restore write changes what is served: the binding record keeps no chain from then on.
	if err := clearChain(h, j.Binding); err != nil {
		return j, err
	}
	j.Phase = winproto.PhaseRestoring
	if err := writeJournal(h, j); err != nil {
		return j, err
	}
	if err := point(h, "restore.restoring"); err != nil {
		return j, err
	}
	if c := j.CCS; c != nil {
		// The backup goes back over the file (MoveFileEx), then the file must read back as the previous bytes.
		if err := h.RestoreCCS(ctx, c.Path, c.Backup, c.File); err != nil {
			return failRestore(winproto.ErrIO)
		}
		if err := point(h, "restore.bound"); err != nil {
			return j, err
		}
		if sum, found, err := ccsFileSum(ctx, h, c.Path, c.File); err != nil || !found || sum != c.PreviousFileSHA256 {
			return failRestore(winproto.ErrReadBack)
		}
	} else {
		switch err := h.UpdateBinding(ctx, j.Previous); {
		case errors.Is(err, ErrKeyUnusable):
			return failRestore(winproto.ErrKeyUnusable)
		case errors.Is(err, ErrBindingNotFound):
			return failRestore(winproto.ErrFileChanged)
		case err != nil:
			return failRestore(winproto.ErrIO)
		}
		if err := point(h, "restore.bound"); err != nil {
			return j, err
		}
		back, found, err := h.Binding(ctx, j.Locator)
		if err != nil || !found || !sameRecord(back, j.Previous) {
			return failRestore(winproto.ErrReadBack)
		}
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
			Steps: slices.Clone(j.Steps[min(from, len(j.Steps)):]), CCSRefreshFailed: j.CCS != nil && j.CCS.RefreshFailed}
	}
	switch {
	case j.Phase == winproto.PhasePrepared, j.Phase == winproto.PhaseUnchanged, j.Phase == winproto.PhaseRestored,
		j.Phase == winproto.PhaseFenced, j.Phase == winproto.PhaseRestoreForbidden && j.ForbiddenFinal:
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
	case errors.Is(err, ErrCCSFolderUnsupported):
		return nil, precondition(winproto.CodeCCSPathUnsupported, "the CCS folder is not a local folder Alice manages")
	case errors.Is(err, ErrStore):
		return nil, failed(winproto.CodeStoreError, "a certificate store could not be opened")
	case err != nil:
		return nil, failed(winproto.CodeIOError, "the binding or the previous certificate could not be read")
	case kind == restoreNoBackup:
		return nil, precondition(winproto.CodeBackupMissing, "the previous certificate is not in its store with a usable key")
	case kind == restoreForeign && j.Phase == winproto.PhaseRestoreFailed && j.Error == winproto.ErrFileChanged,
		kind == restoreForbidden && j.Phase == winproto.PhaseRestoreForbidden:
		return answer(j, len(j.Steps)), nil // the same outcome again: nothing rewritten
	case kind == restoreForeign && j.Kind == winproto.JournalKindCCS && j.Phase == winproto.PhaseCommitted:
		// A CCS file this operation did not leave is someone else's (W5 Ruling 15): never overwritten.
		// An interrupted operation ends restore_failed file_changed instead (applyRestore), as in W2, so
		// it no longer holds up the next deployment.
		return nil, precondition(winproto.CodeSuperseded, "the CCS file was changed after this deployment; it is not rolled back")
	}
	wctx, err := c.gate.enter()
	if err != nil {
		return nil, err
	}
	j.Steps = trimSteps(j.Steps)
	before := len(j.Steps)
	j, err = applyRestore(wctx, h, j, kind, g)
	if err != nil {
		return nil, err
	}
	return answer(j, before), nil
}
