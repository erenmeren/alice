package acmejobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
)

// SweepTask is the periodic acme.sweep (ClassAlways: it runs in every license state, so leftover challenge records
// are removed in lock too). It runs on the leader only (the scheduler's lock) and does two things each tick:
//
//  1. A running order that no job holds and that started more than StaleAfter ago (a crash, a lost worker) is ended.
//     An issue order with its key and its CA URL is first resumed from the CA while the gate allows changes
//     (acme.Client.ResumeOrder: an order the CA issued is downloaded, a ready one finalized; then FinishACMEOrder);
//     anything else, or a resume that fails, is failed with acme.order_abandoned (its key is deleted); a CA that
//     cannot be reached is asked again on the next ticks for ResumeFor.
//  2. Every ended order that still lists challenge records, never cleaned or last tried more than CleanupRetry ago,
//     gets an acme.cleanup job.
//
// Each step's errors are logged by type and the tick returns errSweepFailed; the next tick tries again.
func SweepTask(d Deps, every time.Duration) jobs.Task {
	if d.Inventory == nil || d.Gate == nil || d.Clock == nil {
		panic("acmejobs: SweepTask needs Deps.Inventory, Deps.Gate and Deps.Clock")
	}
	h := newHandlers(d)
	return jobs.Task{Type: jobs.ACMESweep, Every: every, Run: h.sweep}
}

// errSweepFailed is the error of a tick in which a step failed (the steps' own errors are logged by type).
var errSweepFailed = errors.New("acmejobs: the ACME sweep failed for some orders")

// sweep is one acme.sweep tick.
func (h *handlers) sweep(ctx context.Context) error {
	failed := false
	stale, err := h.d.Inventory.StaleACMEOrders(ctx, StaleAfter)
	if err != nil {
		h.d.Log.Error("listing the abandoned ACME orders failed", "error_type", fmt.Sprintf("%T", err))
		failed = true
	}
	for _, o := range stale {
		if err := h.endStale(ctx, o); err != nil {
			h.d.Log.Error("ending an abandoned ACME order failed", "order_id", o.ID.String(), "error_type", fmt.Sprintf("%T", err))
			failed = true
		}
	}
	n, err := h.d.Inventory.EnqueueACMECleanups(ctx, CleanupRetry)
	if err != nil {
		h.d.Log.Error("queueing ACME cleanups failed", "error_type", fmt.Sprintf("%T", err))
		failed = true
	}
	if n > 0 {
		h.d.Log.Info("queued the cleanup of ACME challenge records", "count", n)
	}
	if failed {
		return errSweepFailed
	}
	return nil
}

// endStale finishes an abandoned issue order from the CA when it can, and fails it otherwise.
func (h *handlers) endStale(ctx context.Context, o inventory.ACMEStaleOrder) error {
	if o.Kind == inventory.ACMEOrderIssue && o.HasKey && o.OrderURL != "" && h.d.Gate.Allow(license.ClassChange) == nil {
		issued, err := h.resume(ctx, o)
		if err == nil {
			h.d.Log.Info("finished an interrupted ACME order from the certificate authority", "order_id", o.ID.String(),
				"certificate_id", issued.CertificateID.String())
			return h.d.Inventory.EnqueueACMECleanup(ctx, o.ID)
		}
		if errors.Is(err, errStore) {
			return err // the database failed: the next tick tries again
		}
		code, _ := inventory.ACMEOrderErrorCode(err)
		if code == acme.ReasonProviderUnreachable && h.d.Clock.Now().Sub(o.StartedAt) < ResumeFor {
			return nil // the CA is down: it may hold an issued certificate; the next tick asks again
		}
		h.d.Log.Info("an interrupted ACME order cannot be finished; it is abandoned", "order_id", o.ID.String(), "reason", code)
	}
	err := h.d.Inventory.FailACMEOrder(ctx, o.ID, inventory.ACMEOrderAbandoned, 0)
	if errors.Is(err, inventory.ErrACMEOrderNotRunning) {
		return nil // its job ended it meanwhile
	}
	return err
}

// ResumeFor is how long the sweep keeps asking an unreachable CA for an interrupted order before it abandons it.
const ResumeFor = 24 * time.Hour

// errStore marks a FinishACMEOrder failure that is not a refusal (the database).
var errStore = errors.New("acmejobs: the issued certificate could not be stored")

// resume asks the CA for the order with its persisted key and stores what it issued.
func (h *handlers) resume(ctx context.Context, o inventory.ACMEStaleOrder) (inventory.ACMEIssued, error) {
	signer, err := h.d.Inventory.LoadPendingKey(ctx, o.ID)
	if err != nil {
		return inventory.ACMEIssued{}, err
	}
	client, err := h.d.Inventory.ACMEOrderClient(ctx, o.ID)
	if err != nil {
		return inventory.ACMEIssued{}, err
	}
	csr, err := keygen.NewCSR(signer, o.Names)
	if err != nil {
		return inventory.ACMEIssued{}, err
	}
	chain, err := client.ResumeOrder(ctx, o.OrderURL, o.Names, csr)
	if err != nil {
		return inventory.ACMEIssued{}, err
	}
	issued, err := h.d.Inventory.FinishACMEOrder(ctx, o.ID, chain)
	if err != nil && !inventory.ACMEFinishRefused(err) {
		return inventory.ACMEIssued{}, errors.Join(errStore, err)
	}
	return issued, err
}
