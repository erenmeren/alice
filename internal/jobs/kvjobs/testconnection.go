package kvjobs

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
)

// testConnection is kv.test_connection: the access check of a vault (spec §11.4). Steps and what each
// can fail with:
//
//	payload read_secret_of (optional)   not a UUID                          Fail internal.unexpected
//	the certificate (read_secret_of)    gone                                Fail kv.certificate_not_found
//	                                    no current version / not exportable Fail kv.version_not_deployable
//	                                    other error                         Retry internal.unexpected
//	resolve the vault                   deleted / disabled / not a vault /  Fail (nothing recorded)
//	                                    no provider in this build
//	Open, TestConnection                a provider failure                  RecordKVFailure; the provider's
//	                                                                        class (one attempt)
//	ReadCertificateSecret (optional)    403 / firewall                      the row read_secret is forbidden
//	                                                                        (the check ran: not a failure)
//	                                    another provider failure            the report is stored with the row
//	                                                                        not_checked, then the job fails
//	                                                                        with that reason (nothing recorded
//	                                                                        about the vault's sign-in)
//	                                    ok                                  the row is ok; the value is zeroed
//	RecordKVConnection                  vault deleted meanwhile             Fail system.not_found
//	                                    other error                         Retry internal.unexpected
//
// The result has the object id, the permission model and every row of the check.
func (h *handlers) testConnection(ctx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	ctx = inventory.WithClaim(ctx, inventory.Claim{JobID: j.ID, Attempt: j.Attempt})
	var cert inventory.KVCertificate
	if raw := j.Payload["read_secret_of"]; raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, jobs.Fail(reasonUnexpected, nil, err)
		}
		d, err := h.d.Inventory.KVCertificate(ctx, j.TargetID, id)
		switch {
		case errors.Is(err, inventory.ErrNotFound):
			return nil, jobs.Fail(reasonCertNotFound, nil, err)
		case err != nil:
			return nil, jobs.Retry(reasonUnexpected, nil, err)
		case d.CurrentVersion == "" || d.Exportable == nil || !*d.Exportable:
			return nil, jobs.Fail(reasonNotDeployable, nil, nil)
		}
		cert = d.KVCertificate
	}
	p, ref, err := h.resolve(ctx, j.TargetID)
	if err != nil {
		return nil, err
	}
	sess, err := h.openSession(ctx, p, ref, true)
	if err != nil {
		return nil, err
	}
	defer h.close(sess)

	tctx, cancel := context.WithTimeout(ctx, testTimeout)
	rep, err := sess.TestConnection(tctx)
	cancel()
	if err != nil {
		return nil, h.providerFailure(ctx, j.TargetID, err, true)
	}
	if rep.Azure == nil {
		// A provider that answers an access check without one is a bug, not the vault's state.
		return nil, jobs.Fail(reasonUnexpected, nil, errors.New("kvjobs: the access check has no rows"))
	}
	var readErr error
	if cert.ID != uuid.Nil {
		rep.Azure.Checks, readErr = h.readSecretRow(ctx, sess, cert, slices.Clone(rep.Azure.Checks))
	}
	if err := h.d.Inventory.RecordKVConnection(ctx, j.TargetID, rep); errors.Is(err, inventory.ErrNotFound) {
		return nil, jobs.Fail(reasonNotFound, nil, err) // deleted while it was checked
	} else if err != nil {
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	}
	if readErr != nil {
		return nil, readErr
	}
	checks := make([]map[string]string, 0, len(rep.Azure.Checks))
	for _, c := range rep.Azure.Checks {
		row := map[string]string{"name": c.Name, "result": c.Result}
		if c.Reason != "" {
			row["reason"] = c.Reason
		}
		if c.Role != "" {
			row["role"] = c.Role
		}
		checks = append(checks, row)
	}
	return map[string]any{"object_id": rep.Azure.ObjectID, "permission_model": rep.Azure.PermissionModel, "checks": checks}, nil
}

// readSecretRow reads the secret of the certificate's current version once, which proves the role Key
// Vault Secrets User, and returns the checks with the read_secret row decided. A refusal (403 or the
// firewall) is the check's result. Any other failure leaves the row as it was (not checked: a throttled
// or unreachable vault is not a missing role) and is returned for the job to end with. The value is
// zeroed on every path, a panic included.
func (h *handlers) readSecretRow(ctx context.Context, sess providers.Session, cert inventory.KVCertificate, checks []providers.AzureCheck) ([]providers.AzureCheck, error) {
	rctx, cancel := context.WithTimeout(ctx, secretTimeout)
	defer cancel()
	sec, err := sess.ReadCertificateSecret(rctx, providers.SecretRequest{Name: cert.Name, Version: cert.CurrentVersion})
	defer sec.Value.Zero()
	row := providers.AzureCheck{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultOK}
	if err != nil {
		if ctx.Err() != nil {
			return checks, jobs.Retry(reasonLeaseExpired, nil, ctx.Err())
		}
		var pe *providers.Error
		if !errors.As(err, &pe) {
			pe = providers.NewError(reasonUnreachable, true, err, nil)
		}
		switch pe.Code {
		case reasonForbidden:
			row = providers.AzureCheck{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultForbidden, Reason: pe.Code,
				Role: providers.RoleKeyVaultSecretsUser}
		case reasonFirewall:
			row = providers.AzureCheck{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultForbidden, Reason: pe.Code}
		default:
			return checks, jobs.FromProvider(pe)
		}
	}
	for i := range checks {
		if checks[i].Name == providers.AzureCheckReadSecret {
			checks[i] = row
			return checks, nil
		}
	}
	return append(checks, row), nil
}
