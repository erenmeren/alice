package acmejobs

import (
	"context"
	"errors"
	"fmt"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dns01"
	"alice/internal/acme/solver/http01"
	"alice/internal/inventory"
	"alice/internal/jobs"
)

// cleanup removes the challenge records an ended order still lists (acme.cleanup, ClassAlways: it runs in lock too,
// A12). Each record is removed through what published it: the hook (a deleted hook's row and secret are still used;
// the solver's allow-list is the record's own name, since Alice only removes what she published) or the Nginx server
// (a session on it). A removed record is taken out of the order's list at once. When records are left the attempt's
// code is recorded on the order and the job fails retryably (five attempts on the queue's backoff; the last one writes
// the audit row acme.order.cleanup_failed, and the sweep queues the cleanup again an hour later); when none is left the
// order records the cleanup (audit acme.order.cleaned_up). A running order is not touched: its own job cleans up, or
// the sweep ends it first.
func (h *handlers) cleanup(ctx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	id, err := orderID(j)
	if err != nil {
		return nil, err
	}
	w, err := h.d.Inventory.ACMECleanupWork(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, jobs.Fail(reasonNotFound, nil, err)
	case err != nil:
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	case w.Running:
		return map[string]any{"order_id": id.String(), "state": inventory.ACMEOrderRunning}, nil
	case len(w.Records) == 0:
		return map[string]any{"order_id": id.String(), "removed": 0}, nil
	}
	removed := 0
	var failure error
	for _, rec := range w.Records {
		if err := h.removeRecord(ctx, rec); err != nil {
			failure = err
			continue
		}
		dctx, cancel := detached(ctx)
		err := h.d.Inventory.RemoveACMEPresented(dctx, id, rec)
		cancel()
		if err != nil {
			failure = err
			continue
		}
		removed++
	}
	dctx, cancel := detached(ctx)
	defer cancel()
	params := map[string]string{"order_id": id.String()}
	if failure == nil {
		if err := h.d.Inventory.RecordACMECleanup(dctx, id, "", true); err != nil {
			return nil, jobs.Retry(reasonUnexpected, params, err)
		}
		return map[string]any{"order_id": id.String(), "removed": removed}, nil
	}
	code, _ := inventory.ACMEOrderErrorCode(failure)
	final := j.Attempt >= j.MaxAttempts
	if err := h.d.Inventory.RecordACMECleanup(dctx, id, code, final); err != nil {
		h.d.Log.Error("could not record a failed ACME cleanup", "order_id", id.String(), "error_type", fmt.Sprintf("%T", err))
	}
	if final {
		h.d.Log.Warn("challenge records of an ACME order are still published; the sweep tries again in an hour", "order_id", id.String(),
			"event", "acme_cleanup_failed", "reason", code)
	}
	return nil, jobs.Retry(code, params, failure)
}

// removeRecord removes one record through the hook or the server that published it.
func (h *handlers) removeRecord(ctx context.Context, rec inventory.ACMEPresented) error {
	var s solver.Solver
	closeFn := func() {}
	switch {
	case rec.Challenge.Type == solver.DNS01 && rec.HookID != nil:
		cfg, err := h.d.Inventory.ACMEHookCleanupConfig(ctx, *rec.HookID)
		if errors.Is(err, inventory.ErrNotFound) {
			return inventory.ErrACMEChallengeUnavailable
		}
		if err != nil {
			return err
		}
		cfg.AllowedSuffixes = []string{rec.Challenge.Domain}
		ds, err := dns01.New(cfg)
		cfg.Secret.Zero()
		if err != nil {
			return &acme.Error{Reason: acme.ReasonHookRefused}
		}
		s = ds
	case rec.Challenge.Type == solver.HTTP01 && rec.TargetID != nil:
		pub, closePub, err := h.openPublisher(ctx, *rec.TargetID)
		if err != nil {
			return err
		}
		closeFn = closePub
		hs, err := h.newHTTP01(http01.Config{Publisher: pub, AllowedSuffixes: []string{rec.Challenge.Domain}})
		if err != nil {
			closeFn()
			return inventory.ErrACMEChallengeUnavailable
		}
		s = hs
	default:
		return inventory.ErrACMEChallengeUnavailable
	}
	defer closeFn()
	return s.CleanUp(ctx, rec.Challenge)
}
