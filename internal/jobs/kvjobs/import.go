package kvjobs

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
)

// importToKV is kv.import: one import of a certificate and its key into a vault (spec §11.8, R40 row
// 25). The vault has no idempotency key, so a request that may have reached it is NEVER sent again:
// the only send is made after MarkImportSent has committed (queued becomes running), a run that finds
// the import running (a retry, a redelivery after a lost lease, a crash after the mark) records it as
// uncertain and does not open a session at all, and a poll settles an uncertain import by the
// thumbprint (inventory.resolveImports) or the 24 hour rule ends it.
//
//	import_id (payload)             not a UUID                              Fail internal.unexpected
//	Import (the record)             unknown / of another vault              Fail system.not_found
//	                                other error                             Retry internal.unexpected
//	state succeeded/failed/uncertain  nothing to do                         the result of the record
//	state running                   a send may have happened                FinishImport(uncertain); Fail
//	                                                                        azure.unexpected_response {state:
//	                                                                        uncertain}; NO session, NO send
//	resolve the vault               deleted / disabled / not a vault /      FailQueuedImport (the closed code);
//	                                no provider in this build               Fail the same code
//	Open                            a provider failure                      nothing was sent: Retry while
//	                                                                        attempts are left and the failure is
//	                                                                        retryable; else FinishImport(refused)
//	                                                                        (failed, can retry when unreachable)
//	                                                                        and Fail
//	ImportMaterial (the key)        no key / expired / unsupported key /    FinishImport(refused, the closed
//	                                the certificate changed                 code); Fail
//	                                vault vanished meanwhile                FailQueuedImport; Fail
//	                                import no longer queued                 ends quietly, never sends
//	                                claim lost                              Retry job.lease_expired
//	                                other error                             Retry internal.unexpected (the last
//	                                                                        attempt: FinishImport(refused))
//	MarkImportSent                  claim lost                              Retry job.lease_expired, no send
//	                                not queued any more                     ends quietly, no send
//	                                other error                             Retry internal.unexpected, no send
//	ImportCertificate (ONCE)        created / refused / uncertain           FinishImport on a context detached
//	                                                                        from the job's (bounded), then:
//	                                                                        succeeded: the result; refused: Fail
//	                                                                        with the provider's code and params;
//	                                                                        uncertain: Fail with its code and
//	                                                                        {state: uncertain}
//	FinishImport                    claim lost / other error                Retry (the next run finds the import
//	                                                                        running and never sends)
//
// The PFX is zeroed by a deferred call as soon as ImportMaterial handed it out, on every path, a panic
// included (the runner recovers it as a retryable failure, and the rerun is the "running" row above).
func (h *handlers) importToKV(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
	ctx = inventory.WithClaim(ctx, inventory.Claim{JobID: j.ID, Attempt: j.Attempt})
	id, err := uuid.Parse(j.Payload["import_id"])
	if err != nil {
		return nil, jobs.Fail(reasonUnexpected, nil, err)
	}
	im, err := h.d.Inventory.Import(ctx, j.TargetID, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, jobs.Fail(reasonNotFound, nil, err)
	case err != nil:
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	}
	switch im.State {
	case inventory.ImportQueued:
	case inventory.ImportRunning:
		// A send may have happened (or the run died right after the mark): never send again.
		return nil, h.settleUncertain(ctx, id)
	default:
		return importResult(im), nil
	}
	last := j.Attempt >= j.MaxAttempts

	p, ref, err := h.resolve(ctx, j.TargetID)
	if err != nil {
		return nil, h.endQueued(ctx, id, err, last)
	}
	sess, err := h.openSession(ctx, p, ref, false)
	if err != nil {
		return nil, h.beforeSend(ctx, id, err, last)
	}
	defer h.close(sess)

	m, err := h.d.Inventory.ImportMaterial(ctx, id)
	if err != nil {
		return h.materialFailure(ctx, j.TargetID, id, err, last)
	}
	defer m.Request.PFX.Zero()

	if err := h.d.Inventory.MarkImportSent(ctx, id); err != nil {
		switch {
		case errors.Is(err, inventory.ErrClaimLost):
			return nil, jobs.Retry(reasonLeaseExpired, nil, err)
		case errors.Is(err, inventory.ErrImportState):
			return h.quietly(ctx, j.TargetID, id), nil // somebody else sent it
		}
		return nil, h.beforeSend(ctx, id, jobs.Retry(reasonUnexpected, nil, err), last)
	}
	// From here on the request may reach the vault: this is the only send.
	ictx, cancel := context.WithTimeout(ctx, importTimeout)
	res, sendErr := sess.ImportCertificate(ictx, m.Request, steps)
	cancel()
	m.Request.PFX.Zero()

	// Recorded on a context detached from the job's: a lease lost, or a shutdown, during the send must
	// not erase what the send did. The claim travels with the context (the record is fenced by it).
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer rcancel()
	done, err := h.d.Inventory.FinishImport(rctx, id, res, sendErr)
	switch {
	case errors.Is(err, inventory.ErrClaimLost):
		return nil, jobs.Retry(reasonLeaseExpired, nil, err)
	case err != nil:
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	}
	return outcome(done, res, sendErr)
}

// outcome is the job's result for the import's state after FinishImport (which may have turned a
// result that broke the provider's contract into uncertain).
func outcome(done inventory.KVImport, res providers.ImportResult, sendErr error) (map[string]any, error) {
	switch done.State {
	case inventory.ImportSucceeded:
		return importResult(done), nil
	case inventory.ImportUncertain:
		code := reasonUnexpectedResp // a result that broke the provider's contract: the answer could not be used
		if providers.CheckImportReturn(res, sendErr) == nil {
			code = closedCode(sendErr)
		}
		return nil, jobs.Fail(code, map[string]string{"state": inventory.ImportUncertain}, sendErr)
	}
	// Refused: nothing was created. The reason is the provider's own, with its allowlisted params.
	var pe *providers.Error
	if errors.As(sendErr, &pe) {
		return nil, jobs.Fail(pe.Code, pe.Params, sendErr)
	}
	return nil, jobs.Fail(reasonUnexpected, nil, sendErr)
}

// closedCode is the provider's code of an error, or azure.unexpected_response when the error is none
// (the import's outcome is uncertain, and the reason says the answer could not be used).
func closedCode(err error) string {
	var pe *providers.Error
	if errors.As(err, &pe) && pe.Code != "" {
		return pe.Code
	}
	return reasonUnexpectedResp
}

// settleUncertain is a run that finds its import running: the earlier run may have sent the request.
// The import is recorded uncertain and nothing is sent.
func (h *handlers) settleUncertain(ctx context.Context, id uuid.UUID) error {
	cause := providers.NewError(reasonUnexpectedResp, true, providers.ErrUnexpectedAnswer, nil)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	_, err := h.d.Inventory.FinishImport(rctx, id, providers.ImportResult{Outcome: providers.ImportUncertain}, cause)
	switch {
	case errors.Is(err, inventory.ErrClaimLost):
		return jobs.Retry(reasonLeaseExpired, nil, err)
	case errors.Is(err, inventory.ErrImportState):
		// Finished meanwhile (a poll settled it, or another run recorded it): still nothing to send.
	case err != nil:
		return jobs.Retry(reasonUnexpected, nil, err)
	}
	return jobs.Fail(reasonUnexpectedResp, map[string]string{"state": inventory.ImportUncertain}, cause)
}

// quietly ends a run whose import is no longer queued: its result is the record as it is now.
func (h *handlers) quietly(ctx context.Context, vault, id uuid.UUID) map[string]any {
	if im, err := h.d.Inventory.Import(ctx, vault, id); err == nil {
		return importResult(im)
	}
	return map[string]any{"state": inventory.ImportRunning}
}

func importResult(im inventory.KVImport) map[string]any {
	out := map[string]any{"state": im.State}
	if im.Version != "" {
		out["version"] = im.Version
	}
	return out
}

// endQueued ends a queued import whose vault cannot be used at all (deleted, disabled, not a vault, no
// provider in this build): nothing was sent and nothing will be, and a queued import would block its
// name. A failure that is retryable (the database) leaves it queued while attempts are left; the last
// attempt ends it too.
func (h *handlers) endQueued(ctx context.Context, id uuid.UUID, cause error, last bool) error {
	var f *jobs.Failure
	if !errors.As(cause, &f) || (f.Class != jobs.Permanent && !last) {
		return cause
	}
	return h.failQueued(ctx, id, f.Reason, cause)
}

func (h *handlers) failQueued(ctx context.Context, id uuid.UUID, code string, cause error) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	switch _, err := h.d.Inventory.FailQueuedImport(rctx, id, code); {
	case errors.Is(err, inventory.ErrClaimLost):
		return jobs.Retry(reasonLeaseExpired, nil, err)
	case errors.Is(err, inventory.ErrImportState), err == nil:
		return cause
	default:
		return jobs.Retry(reasonUnexpected, nil, err)
	}
}

// beforeSend handles a failure after which nothing was sent (Open, the mark): a retryable failure with
// attempts left is retried from the start; otherwise the import ends failed with the provider's closed
// code, which for an unreachable vault means "can retry" (a new request is safe). The refusal is built
// without the cause: a deadline in the chain would make it an uncertain outcome by the provider
// contract, and nothing was sent.
func (h *handlers) beforeSend(ctx context.Context, id uuid.UUID, err error, last bool) error {
	if ctx.Err() != nil {
		return jobs.Retry(reasonLeaseExpired, nil, ctx.Err())
	}
	var f *jobs.Failure
	var pe *providers.Error
	code, params := reasonUnexpected, map[string]string(nil)
	retryable := true
	switch {
	case errors.As(err, &pe):
		code, params, retryable = pe.Code, pe.Params, pe.Retryable
	case errors.As(err, &f):
		code, params, retryable = f.Reason, f.Params, f.Class == jobs.Retryable
	}
	if retryable && !last {
		return jobs.Retry(code, params, err)
	}
	return h.refuse(ctx, id, code, params, err)
}

// refuse records the import as refused (failed, nothing created) with the closed code and returns the
// job's permanent failure with it.
func (h *handlers) refuse(ctx context.Context, id uuid.UUID, code string, params map[string]string, cause error) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	refusal := providers.NewError(code, false, nil, params)
	switch _, err := h.d.Inventory.FinishImport(rctx, id, providers.ImportResult{Outcome: providers.ImportRefused}, refusal); {
	case errors.Is(err, inventory.ErrClaimLost):
		return jobs.Retry(reasonLeaseExpired, nil, err)
	case errors.Is(err, inventory.ErrImportState), err == nil:
		return jobs.Fail(code, params, cause)
	default:
		return jobs.Retry(reasonUnexpected, nil, err)
	}
}

// permanentMaterial lists what ImportMaterial refuses for good, with the closed reason each ends the import with.
var permanentMaterial = []struct {
	err  error
	code string
}{
	{inventory.ErrNoPrivateKey, "certificate.no_private_key"},
	{inventory.ErrCertificateExpired, inventory.ReasonCertificateExpired},
	{inventory.ErrCertificateNotYetValid, inventory.ReasonNotYetValid},
	{inventory.ErrUnsupportedKey, "certificate.unsupported_key"},
	{inventory.ErrKeyMismatch, "certificate.key_mismatch"},
	{inventory.ErrImportChanged, providers.CodeKVImportInvalid},
	{inventory.ErrAdminRequired, "auth.forbidden"},
}

// materialFailure maps what ImportMaterial refuses (nothing was sent).
func (h *handlers) materialFailure(ctx context.Context, vault, id uuid.UUID, err error, last bool) (map[string]any, error) {
	switch {
	case errors.Is(err, inventory.ErrClaimLost):
		return nil, jobs.Retry(reasonLeaseExpired, nil, err)
	case errors.Is(err, inventory.ErrImportState):
		return h.quietly(ctx, vault, id), nil
	case errors.Is(err, inventory.ErrNotFound):
		return nil, h.failQueued(ctx, id, reasonNotFound, jobs.Fail(reasonNotFound, nil, err))
	case errors.Is(err, inventory.ErrVaultUnavailable):
		return nil, h.failQueued(ctx, id, reasonDisabled, jobs.Fail(reasonDisabled, nil, err))
	}
	// What the key, the certificate or the requester can no longer give is permanent and nothing was sent:
	// the queued import ends through FailQueuedImport (it is the call that accepts a queued import).
	for _, r := range permanentMaterial {
		if errors.Is(err, r.err) {
			return nil, h.failQueued(ctx, id, r.code, jobs.Fail(r.code, nil, err))
		}
	}
	return nil, h.beforeSend(ctx, id, jobs.Retry(reasonUnexpected, nil, err), last)
}
