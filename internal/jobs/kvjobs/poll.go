package kvjobs

import (
	"context"
	"errors"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
)

// poll is kv.poll: one poll of a vault. Steps and what each can fail with:
//
//	resolve the vault               deleted / disabled / not a vault /   Fail (nothing recorded on the vault)
//	                                no provider in this build
//	AcquireKVPoll (2 slots)         the job's context ended              Retry job.lease_expired
//	KVPollRequest                   deleted / disabled meanwhile         Fail system.not_found / target.disabled
//	                                other error                          Retry internal.unexpected
//	Open, Discover (12 minute       a provider failure (the whole vault) RecordKVFailure; the provider's class
//	 deadline, the provider's own   the job's context ended              Retry job.lease_expired (not recorded)
//	 budget is 11)                  (the provider returns a list that failed, an unreachable or throttled
//	                                answer among them, as rows of the result, not as an error)
//	ReconcileKV (under the claim)   claim lost                           Retry job.lease_expired
//	                                vault deleted meanwhile              Fail system.not_found
//	                                a result past the bounds             RecordKVFailure; Fail internal.unexpected
//	                                other error                          Retry internal.unexpected (not recorded)
//	                                vault deleted / disabled meanwhile   the job ends quietly ({dropped})
//
// The slot is released by a deferred call, so a panic (the runner recovers it) never leaks one. A
// poll's failure is carried by the vault (status, last error, its own email) and the poll interval's
// back-off, so the job type does not alert when it ends (jobs.AlertsWhenExhausted). Settling uncertain
// imports and the poll's other bookkeeping happen inside ReconcileKV; the automatic deployment planner
// is the periodic kv.auto_deploy task, not part of the poll.
func (h *handlers) poll(ctx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	ctx = inventory.WithClaim(ctx, inventory.Claim{JobID: j.ID, Attempt: j.Attempt})
	p, ref, err := h.resolve(ctx, j.TargetID)
	if err != nil {
		return nil, err
	}
	release, err := h.d.Inventory.AcquireKVPoll(ctx)
	if err != nil {
		return nil, jobs.Retry(reasonLeaseExpired, nil, err)
	}
	defer release()

	req, err := h.d.Inventory.KVPollRequest(ctx, j.TargetID)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, jobs.Fail(reasonNotFound, nil, err)
	case errors.Is(err, inventory.ErrTargetNotReady):
		return nil, jobs.Fail(reasonDisabled, nil, err)
	case err != nil:
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	}
	res, err := h.discover(ctx, p, ref, req)
	if err != nil {
		return nil, err
	}
	sum, err := h.d.Inventory.ReconcileKV(ctx, j.TargetID, res)
	var pe *providers.Error
	switch {
	case errors.Is(err, inventory.ErrClaimLost) || (err != nil && ctx.Err() != nil):
		return nil, jobs.Retry(reasonLeaseExpired, nil, err)
	case errors.Is(err, inventory.ErrNotFound):
		return nil, jobs.Fail(reasonNotFound, nil, err) // deleted while it was read
	case errors.As(err, &pe):
		return nil, h.providerFailure(ctx, j.TargetID, err, true)
	case err != nil:
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	case sum.Dropped != "":
		return map[string]any{"dropped": sum.Dropped}, nil
	}
	return map[string]any{"certificates": sum.Certificates, "new_certificates": sum.NewCertificates, "new_versions": sum.NewVersions,
		"held_versions": sum.HeldVersions, "removed": sum.MissingCertificates, "keys": sum.Keys, "secrets": sum.Secrets,
		"status": sum.Status}, nil
}

// discover opens the session and reads the vault under pollTimeout; the session is closed before the
// result is stored.
func (h *handlers) discover(ctx context.Context, p providers.Provider, ref providers.TargetRef, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	sess, err := h.openSession(ctx, p, ref, true)
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	defer h.close(sess)
	dctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	res, err := sess.Discover(dctx, req)
	if err != nil {
		return providers.DiscoveryResult{}, h.providerFailure(ctx, ref.ID, err, true)
	}
	return res, nil
}
