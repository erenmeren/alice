package deployjobs

import (
	"context"
	"errors"
	"time"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
)

// The vault step of a Key Vault deployment (R40 row 18; rulings S3, S7; findings F-41, D5, D6).
//
// A deployment whose certificate comes from a vault version (Material.KV set) reads the version's
// secret (the certificate and its private key, as PFX or PEM) from the vault before anything else
// can fail for an external reason: before the SSH session is opened, before the pre-check, before the
// start record. A vault that refuses the read (the role Key Vault Secrets User is missing, F-41), a
// version that was disabled or deleted meanwhile, or a secret that is not the recorded version ends
// the deployment with its closed reason and the website unchanged: no SSH call was made at all.
//
//	step kv_secret                   result                                   recorded                      job returns
//	-------------------------------  ---------------------------------------  ----------------------------  ---------------------
//	vault target (TargetRef)         deleted                                  finish failed                 Fail kv.certificate_
//	                                                                                                        not_found
//	                                 disabled                                 finish failed target.disabled Fail target.disabled
//	                                 other error                              -                             pre-send failure
//	azurekv provider                 none registered                          finish failed                 Fail internal.unexpected
//	                                                                          internal.unexpected
//	Open + ReadCertificateSecret     provider error (closed code, allowlisted step failed; finish failed    Fail that reason (the
//	 (one minute for both, S3;       params, F-41: azure.forbidden {role})    with it unless retryable      provider's class; a
//	 name and exact version of the                                            with attempts left            retryable one is retried)
//	 deployment's record)            the budget ran out                       step failed                   Retry azure.unreachable
//	                                 the job's context ended                  step failed (no finish)       Retry deployment.interrupted
//	KVDeployMaterial                 ErrSecretMismatch / ErrSecretUnreadable  step failed; finish failed    Fail kv.secret_mismatch /
//	                                                                                                        kv.secret_unreadable
//	                                 ErrChainUnconfirmed (F-17; an automatic  step failed; finish failed    Fail certificate.
//	                                  deployment's version is held too)                                     chain_unconfirmed
//	                                 ErrCertificateExpired (F-19)             step failed; finish failed    Fail certificate.expired
//	                                 ErrPFXBusy                               step failed                   Retry certificate.pfx_busy
//	                                 ErrNotFound (the version row is gone)    step failed; finish failed    Fail system.not_found
//	                                 ErrDeploymentState (raced)               -                             follow the re-read state
//	                                 ErrClaimLost                             nothing                       stale run
//	                                 other error                              step failed                   pre-send failure
//	                                 ok                                       step ok ({reason:             the Phase 4 run continues
//	                                                                           chain_incomplete} for an
//	                                                                           Administrator-confirmed
//	                                                                           incomplete chain)
//
// "pre-send failure" and "finish failed" are those of deploy: a retryable failure with attempts left
// leaves the record in its pre-check and the next attempt reads the vault again; a permanent one, or
// the last attempt (I-3), ends the deployment failed with the step kv_secret as its failed step.
//
// The secret is never stored. The vault session is opened, used once and closed before KVDeployMaterial
// runs; the secret value is zeroed by KVDeployMaterial on every path and, whatever it does, by the
// deferred zeroing here (also while a panic unwinds). The key KVDeployMaterial returns is zeroed by
// first's deferred call on every path. A deployment that crashed after its start record never
// reads the vault again: recovery works from the journal and the record (DeploymentMaterial(id,
// false)), never from the secret.

// stepKVSecret is the deployment step that reads and checks the vault secret.
const stepKVSecret = "kv_secret"

// kvReadBudget is the whole budget of the vault session of a deployment, Open and the secret read
// together (S3: a throttled vault must not hold the Nginx server's target lock for the vault's whole
// throttling window). It is a variable only so a test can shorten it.
var kvReadBudget = time.Minute

// Reasons the vault step produces itself (the rest are the provider's closed codes).
const (
	reasonKVMismatch       = "kv.secret_mismatch"
	reasonKVUnreadable     = "kv.secret_unreadable"
	reasonKVNotFound       = "kv.certificate_not_found"
	reasonChainUnconfirmed = "certificate.chain_unconfirmed"
	reasonPFXBusy          = "certificate.pfx_busy"
	reasonDisabled         = "target.disabled"
	reasonUnreachable      = "azure.unreachable"
)

// kvMaterial reads the backing secret of a Key Vault deployment's version and returns the material of
// the first send (see the table above). m is the Phase 4 material (it names the vault source and has no
// key); on success the returned material has the delivered chain and the key, which the caller zeroes.
func (h *handlers) kvMaterial(ctx context.Context, m inventory.Material) (inventory.Material, error) {
	src := m.KV
	ref, t, err := h.d.Inventory.TargetRef(ctx, src.VaultID)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return m, jobs.Fail(reasonKVNotFound, nil, err)
	case err != nil:
		return m, jobs.Retry(reasonUnexpected, nil, err)
	case t.Status == inventory.StatusDisabled:
		return m, jobs.Fail(reasonDisabled, nil, nil)
	}
	p, ok := h.d.Registry.Get(providers.KindAzureKV)
	if !ok {
		return m, jobs.Fail(reasonUnexpected, nil, errors.New("deployjobs: no Key Vault provider in this build"))
	}
	sec, err := h.readSecret(ctx, p, ref, src)
	if err != nil {
		return m, err
	}
	// KVDeployMaterial zeroes the value on every path; this covers a panic before it gets there and
	// an inventory that did not.
	defer sec.Value.Zero()
	out, err := h.d.Inventory.KVDeployMaterial(ctx, m.Deployment.ID, sec)
	switch {
	case err == nil:
		return out, nil
	case errors.Is(err, inventory.ErrClaimLost), errors.Is(err, inventory.ErrDeploymentState):
		return m, err // the caller: a stale run, or a state to follow
	case ctx.Err() != nil:
		return m, jobs.Retry(reasonInterrupted, nil, ctx.Err())
	case errors.Is(err, inventory.ErrPFXBusy):
		return m, jobs.Retry(reasonPFXBusy, nil, err)
	case errors.Is(err, inventory.ErrSecretMismatch):
		return m, jobs.Fail(reasonKVMismatch, nil, err)
	case errors.Is(err, inventory.ErrSecretUnreadable):
		return m, jobs.Fail(reasonKVUnreadable, nil, err)
	case errors.Is(err, inventory.ErrChainUnconfirmed):
		return m, jobs.Fail(reasonChainUnconfirmed, nil, err)
	case errors.Is(err, inventory.ErrCertificateExpired):
		return m, jobs.Fail(reasonExpired, nil, err)
	case errors.Is(err, inventory.ErrNotFound):
		return m, jobs.Fail(reasonNotFound, nil, err)
	}
	return m, err // a database error: retryable, as DeploymentMaterial's
}

// readSecret opens one vault session, reads the exact version the deployment names and closes the
// session, all inside kvReadBudget. A value that comes back with an error is zeroed here.
func (h *handlers) readSecret(ctx context.Context, p providers.Provider, ref providers.TargetRef, src *inventory.KVSource) (providers.CertificateSecret, error) {
	rctx, cancel := context.WithTimeout(ctx, kvReadBudget)
	defer cancel()
	sess, err := p.Open(rctx, ref, h.d.Inventory.VaultCredentials(src.VaultID), providers.Env{Clock: h.d.Clock, Log: h.d.Log})
	if err != nil {
		return providers.CertificateSecret{}, readFailure(ctx, rctx, err)
	}
	sec, err := sess.ReadCertificateSecret(rctx, providers.SecretRequest{Name: src.Name, Version: src.Version})
	h.close(sess)
	if err != nil {
		sec.Value.Zero()
		return providers.CertificateSecret{}, readFailure(ctx, rctx, err)
	}
	return sec, nil
}

// readFailure classifies a failed Open or read: the job's own context ending is an interruption
// (the runner releases the job, nothing is recorded as the outcome); a budget that ran out under a
// raw context error is a retryable "unreachable"; anything else is the provider's error as it is.
func readFailure(ctx, rctx context.Context, err error) error {
	var pe *providers.Error
	switch {
	case ctx.Err() != nil:
		return jobs.Retry(reasonInterrupted, nil, ctx.Err())
	case !errors.As(err, &pe) && rctx.Err() != nil:
		return jobs.Retry(reasonUnreachable, nil, err)
	}
	return err
}
