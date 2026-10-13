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
//  1. A running order that no job holds and that started more than StaleAfter ago (a crash, a lost worker, a
//     shutdown) is ended. An issue order with its key and its CA URL is resumed from the CA while the gate allows
//     changes (acme.Client.ResumeOrder: an order the CA issued is downloaded, a ready one finalized; then
//     FinishACMEOrder). It is abandoned (acme.order_abandoned: its key is deleted, its cleanup queued) only for good
//     reasons (endStale); temporary failures are tried again on the next ticks for ResumeFor.
//  2. Every ended order that still lists challenge records, never cleaned or last tried more than CleanupRetry ago,
//     gets an acme.cleanup job, until CleanupGiveUp after the order ended.
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
	n, err := h.d.Inventory.EnqueueACMECleanups(ctx, CleanupRetry, CleanupGiveUp)
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

// endStale finishes an interrupted issue order from the CA when it can, and abandons an order only for good reasons:
// it cannot be resumed (a test run, no key or no CA URL, a deleted definition), the CA or the order refused it for
// good (definitiveResumeFailure), or ResumeFor has passed. Anything else (a database, the CA or an account that is
// not available right now) is tried again on the next tick. In lock no CA is contacted: the order waits while nothing
// of it is published, and is abandoned when records are published (so the cleanup removes them) or ResumeFor passed.
func (h *handlers) endStale(ctx context.Context, o inventory.ACMEStaleOrder) error {
	resumable := o.Kind == inventory.ACMEOrderIssue && o.HasKey && o.OrderURL != "" && !o.Deleted
	expired := h.d.Clock.Now().Sub(o.StartedAt) >= ResumeFor
	switch {
	case !resumable:
		return h.abandon(ctx, o, "not_resumable")
	case h.d.Gate.Allow(license.ClassChange) != nil:
		if o.Presented > 0 || expired {
			return h.abandon(ctx, o, "locked")
		}
		return nil
	}
	issued, err := h.resume(ctx, o)
	switch {
	case err == nil:
		h.d.Log.Info("finished an interrupted ACME order from the certificate authority", "order_id", o.ID.String(),
			"certificate_id", issued.CertificateID.String())
		return h.d.Inventory.EnqueueACMECleanup(ctx, o.ID)
	case definitiveResumeFailure(err) || expired:
		code, _ := inventory.ACMEOrderErrorCode(err)
		return h.abandon(ctx, o, code)
	}
	code, _ := inventory.ACMEOrderErrorCode(err)
	h.d.Log.Info("an interrupted ACME order could not be resumed yet; the sweep tries again", "order_id", o.ID.String(), "reason", code)
	if errors.Is(err, errStore) {
		return err
	}
	return nil
}

// definitiveResumeFailure reports whether a resume failed for good: the CA's order cannot be finished any more, its
// certificate does not fit the order, the order's key is gone or unreadable, the order ended meanwhile or its definition
// is gone, or the key or names cannot make a CSR. A database error, an unreachable or rate-limiting CA, a trust
// problem, an account that is busy or settling a key change are temporary.
func definitiveResumeFailure(err error) bool {
	if errors.Is(err, errStore) {
		return false
	}
	for _, d := range []error{acme.ErrOrderNotResumable, acme.ErrCSRMismatch, acme.ErrBadAnswer, inventory.ErrACMEPendingKey,
		inventory.ErrACMEOrderNotRunning, inventory.ErrNotFound, keygen.ErrKeyPolicy, keygen.ErrNames, keygen.ErrKey} {
		if errors.Is(err, d) {
			return true
		}
	}
	return inventory.ACMEFinishRefused(err)
}

// abandon fails an interrupted order with acme.order_abandoned (its key is deleted, its cleanup queued); an order its
// job ended meanwhile is left as it is.
func (h *handlers) abandon(ctx context.Context, o inventory.ACMEStaleOrder, why string) error {
	h.d.Log.Info("an interrupted ACME order is abandoned", "order_id", o.ID.String(), "reason", why)
	err := h.d.Inventory.FailACMEOrder(ctx, o.ID, inventory.ACMEOrderAbandoned, 0)
	if errors.Is(err, inventory.ErrACMEOrderNotRunning) {
		return nil
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
