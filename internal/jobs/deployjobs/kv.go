package deployjobs

import (
	"context"
	"errors"
	"sync"
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
//	before the step (record only)    expired by the stored row, not yet      finish failed with the        Fail that reason; the
//	                                 valid, configuration invalid, location  reason (no step, no vault    vault is never called
//	                                 unsupported, server target deleted /    call)
//	                                 disabled / host key changed
//	step kv_secret                   result                                   recorded                      job returns
//	-------------------------------  ---------------------------------------  ----------------------------  ---------------------
//	KVDeployPrecheck (read-only,     ErrBindingGone, ErrAutoDeployOff,        step failed; finish failed    Fail kv.binding_gone, kv.
//	 before any vault call)          ErrVaultUnavailable, ErrKVCertificate-   (kv_secret)                   auto_deploy_off, kv.vault_
//	                                 Missing, ErrVersionDisabled, ErrVersion-                               unavailable, kv.certificate_
//	                                 Held, ErrCertificateExpired / NotYet-                                  not_found, kv.version_
//	                                 Valid, ErrNotFound                                                     disabled, kv.version_held,
//	                                                                                                        certificate.expired /
//	                                                                                                        not_yet_valid, system.not_found
//	                                 ErrDeploymentState                       step skipped {state_changed}  follow the re-read state
//	                                 ErrClaimLost                             nothing                       stale run
//	                                 an error nobody knows (database)         step failed                   Retry internal.unexpected
//	                                                                                                        (nothing was read: cheap)
//	vault target (TargetRef)         deleted or disabled                      finish failed                 Fail kv.vault_unavailable
//	                                 other error                              -                             pre-send failure
//	azurekv provider                 none registered                          finish failed                 Fail internal.unexpected
//	vault credential (AzureIdentity  ErrVaultCredentialUnreadable (the sealed step failed; finish failed    Fail kv.credential_
//	 inside Open)                     credential does not open: secrets.                                    unreadable (replace the
//	                                  ErrDecrypt)                                                           vault's credentials)
//	Open + ReadCertificateSecret     provider error (closed code, allowlisted step failed; finish failed    Fail that reason (the
//	 (one minute for both, S3;       params, F-41: azure.forbidden {role})    with it unless retryable      provider's class; a
//	 name and exact version of the                                            with attempts left            retryable one is retried)
//	 deployment's record)            the budget ran out                       step failed                   Retry azure.unreachable
//	                                 the job's context ended                  step failed (no finish)       Retry deployment.interrupted
//	KVDeployMaterial                 the refusals of the pre-check again      as above                      as above (permanent)
//	                                 ErrSecretMismatch / ErrSecretUnreadable  step failed; finish failed    Fail kv.secret_mismatch /
//	                                                                                                        kv.secret_unreadable
//	                                 ErrChainUnconfirmed (F-17; an automatic  step failed; finish failed    Fail certificate.
//	                                  deployment's version is held too)                                     chain_unconfirmed
//	                                 ErrPFXBusy                               step failed                   Retry certificate.pfx_busy
//	                                 ErrClaimLost                             nothing                       stale run
//	                                 any other error (the secret was read)    step failed; the record        Retry internal.unexpected (the
//	                                                                          stays in its pre-check         next attempt reads again; the
//	                                                                          unless the last attempt        last attempt fails, I-3)
//	                                 material of another deployment, version  step failed; finish failed    Fail internal.unexpected
//	                                  or location (checked here); key zeroed
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
	reasonKVMismatch         = "kv.secret_mismatch"
	reasonKVUnreadable       = "kv.secret_unreadable"
	reasonKVSignInUnreadable = "kv.credential_unreadable"
	reasonVaultGone          = inventory.ReasonVaultUnavailable
	reasonChainUnconfirmed   = inventory.ReasonChainUnconfirmed
	reasonPFXBusy            = "certificate.pfx_busy"
	reasonUnreachable        = "azure.unreachable"
)

// kvRefusals maps every refusal the inventory can give for a Key Vault deployment (the pre-check, the
// material step and DeploymentMaterial) to its closed reason. The reasons the automatic deployment
// planner treats as neutral (it neither counts them toward its three-failure stop nor stops for them)
// are inventory's own constants, so the planner and this engine cannot drift apart
// (TestEveryNeutralReasonCanBeProducedByTheEngine). The words are the vault's: a disabled
// vault is not a disabled server. Each is permanent: the state the deployment was requested in no
// longer holds, and a retry would only ask again.
var kvRefusals = []struct {
	err    error
	reason string
}{
	{inventory.ErrBindingGone, inventory.ReasonBindingGone},
	{inventory.ErrAutoDeployOff, inventory.ReasonAutoDeployOff},
	{inventory.ErrVaultUnavailable, reasonVaultGone},
	{inventory.ErrKVCertificateMissing, inventory.ReasonCertificateMissing},
	{inventory.ErrVersionDisabled, inventory.ReasonVersionDisabled},
	{inventory.ErrVersionHeld, inventory.ReasonVersionHeld},
	{inventory.ErrVersionSuperseded, inventory.ReasonVersionSuperseded},
	{inventory.ErrWaveStopped, inventory.ReasonWaveStopped},
	{inventory.ErrCertificateExpired, reasonExpired},
	{inventory.ErrCertificateNotYetValid, reasonNotYetValid},
	{inventory.ErrSecretMismatch, reasonKVMismatch},
	{inventory.ErrSecretUnreadable, reasonKVUnreadable},
	{inventory.ErrChainUnconfirmed, reasonChainUnconfirmed},
	{inventory.ErrNotFound, reasonNotFound},
}

// kvRefusal is the closed reason of an inventory refusal in kvRefusals.
func kvRefusal(err error) (string, bool) {
	for _, r := range kvRefusals {
		if errors.Is(err, r.err) {
			return r.reason, true
		}
	}
	return "", false
}

// kvMaterial reads the backing secret of a Key Vault deployment's version and returns the material of
// the first send (see the table above). m is the Phase 4 material (it names the vault source and has no
// key); on success the returned material has the delivered chain and the key, which the caller zeroes.
func (h *handlers) kvMaterial(ctx context.Context, m inventory.Material) (inventory.Material, error) {
	src := m.KV
	// Before any vault call: is the deployment still what was requested? Read-only, so an error nobody
	// knows is retried (nothing was read yet); the refusals are final.
	if err := h.d.Inventory.KVDeployPrecheck(ctx, m.Deployment.ID); err != nil {
		switch reason, known := kvRefusal(err); {
		case errors.Is(err, inventory.ErrClaimLost), errors.Is(err, inventory.ErrDeploymentState):
			return m, err
		case ctx.Err() != nil:
			return m, jobs.Retry(reasonInterrupted, nil, ctx.Err())
		case known:
			return m, jobs.Fail(reason, nil, err)
		}
		return m, jobs.Retry(reasonUnexpected, nil, err)
	}
	ref, t, err := h.d.Inventory.TargetRef(ctx, src.VaultID)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return m, jobs.Fail(reasonVaultGone, nil, err)
	case err != nil:
		return m, jobs.Retry(reasonUnexpected, nil, err)
	case t.Status == inventory.StatusDisabled:
		return m, jobs.Fail(reasonVaultGone, nil, nil)
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
	if err != nil {
		// The secret was read. A known refusal is final; anything else (a serialization failure, a
		// connection blip) is not the vault's or the certificate's fault and is retried within the
		// runner's attempts: at most two more reads, which is the normal resume, the key zeroed on every
		// path (the last attempt ends the deployment through the engine's I-3 rule).
		reason, known := kvRefusal(err)
		switch {
		case errors.Is(err, inventory.ErrClaimLost), errors.Is(err, inventory.ErrDeploymentState):
			return m, err // the caller: a stale run, or a state to follow
		case ctx.Err() != nil:
			return m, jobs.Retry(reasonInterrupted, nil, ctx.Err())
		case errors.Is(err, inventory.ErrPFXBusy):
			return m, jobs.Retry(reasonPFXBusy, nil, err)
		case known:
			return m, jobs.Fail(reason, nil, err)
		}
		return m, jobs.Retry(reasonUnexpected, nil, err)
	}
	// Defence in depth: what comes back is this deployment's material (the inventory is trusted, a
	// mix-up is not): else no send, and the key is zeroed here.
	if out.Deployment.ID != m.Deployment.ID || out.Fingerprint != m.Fingerprint || out.Location.CertPath != m.Location.CertPath ||
		out.Location.KeyPath != m.Location.KeyPath || out.KV == nil || out.KV.VersionID != src.VersionID {
		out.PrivateKeyPEM.Zero()
		return m, jobs.Fail(reasonUnexpected, nil, errors.New("deployjobs: the vault material is not the deployment's"))
	}
	return out, nil
}

// readSecret opens one vault session, reads the exact version the deployment names and closes the
// session, all inside kvReadBudget. A value that comes back with an error, or while Close panics, is
// zeroed here.
func (h *handlers) readSecret(ctx context.Context, p providers.Provider, ref providers.TargetRef, src *inventory.KVSource) (providers.CertificateSecret, error) {
	rctx, cancel := context.WithTimeout(ctx, kvReadBudget)
	defer cancel()
	var cred providers.CredentialSource
	watch := &credentialWatch{}
	if vs := h.d.Inventory.VaultCredentials(src.VaultID); vs != nil {
		watch.VaultCredentialSource = vs
		cred = watch
	}
	sess, err := p.Open(rctx, ref, cred, providers.Env{Clock: h.d.Clock, Log: h.d.Log})
	if err != nil {
		if ctx.Err() == nil && errors.Is(watch.failure(), inventory.ErrVaultCredentialUnreadable) {
			// The provider reports this as its own internal error; only a new credential helps.
			return providers.CertificateSecret{}, jobs.Fail(reasonKVSignInUnreadable, nil, inventory.ErrVaultCredentialUnreadable)
		}
		return providers.CertificateSecret{}, readFailure(ctx, rctx, err)
	}
	sec, err := sess.ReadCertificateSecret(rctx, providers.SecretRequest{Name: src.Name, Version: src.Version})
	handedOver := false
	// Registered before Close runs: a panic in Close, or a value that came back with an error, leaves
	// nothing behind. Once handed over the caller owns the value.
	defer func() {
		if !handedOver {
			sec.Value.Zero()
		}
	}()
	h.close(sess)
	if err != nil {
		return providers.CertificateSecret{}, readFailure(ctx, rctx, err)
	}
	handedOver = true
	return sec, nil
}

// credentialWatch hands the vault's credential source to the provider unchanged and remembers the
// error its AzureIdentity returned, so the vault step can tell a sealed credential this master key cannot
// open (kv.credential_unreadable) from the provider's other failures, which it reports as they are.
type credentialWatch struct {
	inventory.VaultCredentialSource
	mu  sync.Mutex
	err error
}

func (w *credentialWatch) AzureIdentity(ctx context.Context) (providers.AzureIdentity, func(), error) {
	id, release, err := w.VaultCredentialSource.AzureIdentity(ctx)
	if err != nil {
		w.mu.Lock()
		w.err = err
		w.mu.Unlock()
	}
	return id, release, err
}

func (w *credentialWatch) failure() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
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
