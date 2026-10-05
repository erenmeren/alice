package inventory

// Key Vault deployments through the Phase 4 request path (spec §11.6; R40 rows 18, 19), and the
// release of a held version. A Key Vault deployment is a Phase 4 deployment whose certificate is
// the leaf row of a STORED version of the binding's vault certificate: the request names the
// version by its id, never "the latest" (what a poll saw as current may have moved since, and the
// vault is not asked at request time). The deployment engine reads the vault secret itself when the
// job runs (KVDeployMaterial); a version Alice has no details of is not deployable.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// KVDeployInput asks for one stored version of a binding's certificate on websites of the binding.
// LocationIDs empty means every website of the binding. ConfirmIncompleteChain is the
// Administrator's confirmation of F-17 (an Operator's counts for nothing): it is recorded with each
// deployment and read when the secret is (KVDeployMaterial), because only the vault's secret
// carries the chain the websites will be sent.
type KVDeployInput struct {
	BindingID, VersionID   uuid.UUID
	LocationIDs            []uuid.UUID
	ConfirmIncompleteChain bool
	// StrictSession says the caller authenticated the Administrator strongly (a fresh step-up, no API token).
	// A HELD version is refused inside the transaction unless the actor is an Administrator AND this is true
	// (ErrHeldNeedsStepUp): a hold can appear between the caller's read and this call. Not-held versions
	// ignore it.
	StrictSession bool
}

// deployVersion is a stored version as a deployment needs it.
type deployVersion struct {
	id, certificate uuid.UUID
	certificateRow  *uuid.UUID // the leaf's certificates row; nil until Alice read the version's details
	version         string
	enabled         bool
	exportable      *bool
	held            bool
	heldReason      string
	chainIncomplete bool // the last read of its secret found the chain incomplete
}

// versionRefusal decides whether a stored version can be deployed by this actor, in this order:
// another certificate's version (ErrVersionNotDeployable), a certificate the vault no longer lists
// (ErrKVCertificateMissing), a version without details (ErrVersionNotDeployable), a key the vault
// cannot export (ErrNotExportable), a disabled version (ErrVersionDisabled), and then the validity of
// the leaf as RequestDeployment judges it: expired (ErrCertificateExpired), not yet valid
// (ErrCertificateNotYetValid), a key that is not RSA or ECDSA (ErrUnsupportedKey). A held version
// is deployed by an Administrator only (ErrHeldNeedsAdmin; ruling S6): the hold stays.
func versionRefusal(v deployVersion, c kvCertInfo, leaf deployCertificate, a Actor, now time.Time) (string, error) {
	switch {
	case v.certificate != c.id:
		return "version_not_deployable", ErrVersionNotDeployable
	case c.missing:
		return "certificate_missing", ErrKVCertificateMissing
	case v.certificateRow == nil:
		return "version_not_deployable", ErrVersionNotDeployable
	case v.exportable != nil && !*v.exportable:
		return "not_exportable", ErrNotExportable
	case !v.enabled:
		return "version_disabled", ErrVersionDisabled
	case !now.Before(leaf.notAfter):
		return "expired", ErrCertificateExpired
	case now.Before(leaf.notBefore):
		return "not_yet_valid", ErrCertificateNotYetValid
	case leaf.algorithm != "rsa" && leaf.algorithm != "ecdsa":
		return "unsupported_key", ErrUnsupportedKey
	case v.held && a.Role != rbac.Admin:
		return "held_needs_admin", ErrHeldNeedsAdmin
	}
	return "", nil
}

// RequestKVDeployment queues one deployment per website of the binding (the whole binding, or the
// named websites) of one stored version: all or nothing, in one transaction with the certificate.deploy
// jobs, trigger "manual", the deployment naming its binding and version. Refusals, in this order:
// validation; the license lock; ErrNotFound (unknown binding or version); versionRefusal; then per website,
// after locking as CreateBinding does: *LocationRefusalError(ErrNotFound) for a website that is not the
// binding's (or not there, or whose server was deleted), then Phase 4's checkDeployLocation
// (ErrLocationUnsupported, ErrTargetNotReady, ErrNginxConfigInvalid, ErrLocationNeedsDiscovery,
// *KeyTypeMismatchError, ErrRecoveryPending, ErrDeploymentInProgress, F-15). Each refusal is audited
// deployment.denied after the rollback. F-17 (an incomplete chain) is decided here only when an earlier read of
// the version's secret found the chain incomplete (ErrChainUnconfirmed without an Administrator's confirmation,
// held or released alike); otherwise the chain is known only once the secret is read (KVDeployMaterial refuses
// an incomplete one without the confirmation, ruling S7). Deploying a held version does not release it.
func (s *Service) RequestKVDeployment(ctx context.Context, a Actor, in KVDeployInput) ([]RequestedDeployment, error) {
	var errs validate.Errors
	if in.BindingID == uuid.Nil {
		errs.Add("binding_id", validate.Pattern, nil)
	}
	if in.VersionID == uuid.Nil {
		errs.Add("version_id", validate.Required, nil)
	}
	if len(in.LocationIDs) > 0 {
		errs = append(errs, validateLocationIDs(in.LocationIDs, MaxBindingLocations)...)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	kv := func() map[string]string {
		return map[string]string{"binding_id": in.BindingID.String(), "version_id": in.VersionID.String()}
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		return nil, s.auditLicenseRefusal(ctx, a, err, "deployment.denied", "binding", in.BindingID, kv())
	}
	var (
		out    []RequestedDeployment
		denial *bindingDenial
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		out, denial = nil, nil
		vault, b, err := lockBinding(ctx, tx, in.BindingID)
		if err != nil {
			return err
		}
		var vaultStatus string
		if err := tx.QueryRow(ctx, "SELECT status FROM targets WHERE id = $1", vault.id).Scan(&vaultStatus); err != nil {
			return fmt.Errorf("inventory: read the vault's status: %w", err)
		}
		if vaultStatus == StatusDisabled {
			return denyWith(&denial, "vault_disabled", uuid.Nil, ErrVaultUnavailable)
		}
		c, err := kvCertificateOf(ctx, tx, b.certificate)
		if err != nil {
			return err
		}
		v := deployVersion{id: in.VersionID}
		err = tx.QueryRow(ctx, `SELECT kv_certificate_id, certificate_id, version, enabled, exportable, held, held_reason, chain_incomplete
FROM kv_certificate_versions WHERE id = $1 FOR SHARE`, in.VersionID).Scan(&v.certificate, &v.certificateRow, &v.version, &v.enabled, &v.exportable,
			&v.held, &v.heldReason, &v.chainIncomplete)
		if errors.Is(err, pgx.ErrNoRows) {
			return denyWith(&denial, "version_not_found", uuid.Nil, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("inventory: read the version: %w", err)
		}
		now := s.clock.Now().UTC()
		var leaf deployCertificate
		if v.certificate == c.id && v.certificateRow != nil {
			if leaf, err = readDeployCertificate(ctx, tx, *v.certificateRow); err != nil {
				return err
			}
		}
		if reason, err := versionRefusal(v, c, leaf, a, now); err != nil {
			return denyWith(&denial, reason, uuid.Nil, err)
		}
		if v.held && !in.StrictSession {
			return denyWith(&denial, "held_needs_step_up", uuid.Nil, ErrHeldNeedsStepUp)
		}
		// F-17 as far as Alice knows it: a read of this version's secret found the chain incomplete. Releasing a hold
		// does not confirm it; every manual deployment needs an Administrator's confirmation.
		if v.chainIncomplete && !(in.ConfirmIncompleteChain && a.Role == rbac.Admin) {
			return denyWith(&denial, "chain_unconfirmed", uuid.Nil, ErrChainUnconfirmed)
		}
		ids := in.LocationIDs
		if len(ids) == 0 {
			rows, err := tx.Query(ctx, "SELECT id FROM certificate_locations WHERE binding_id = $1 ORDER BY id", in.BindingID)
			if err != nil {
				return fmt.Errorf("inventory: read the binding's websites: %w", err)
			}
			if ids, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
				return fmt.Errorf("inventory: read the binding's websites: %w", err)
			}
			if len(ids) == 0 {
				return denyWith(&denial, "no_websites", uuid.Nil, ErrNotFound)
			}
		}
		targets, locs, err := s.lockDeployTargets(ctx, tx, ids)
		if err != nil {
			return denyWith(&denial, "location_not_found", locationOfRefusal(err), err)
		}
		bound, err := lockedBindingsOf(ctx, tx, ids)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if bound[id] == nil || *bound[id] != in.BindingID {
				return denyWith(&denial, "location_not_in_binding", id, ErrNotFound)
			}
		}
		for _, id := range ids {
			l := locs[id]
			if reason, err := s.checkDeployLocation(ctx, tx, leaf, l, targets[l.target]); err != nil {
				return denyWith(&denial, reason, id, err)
			}
		}
		// The confirmation is kept unless the chain is known to be complete in a row a vault read keeps current:
		// only a source azure_kv row is rewritten by the next read; a complete uploaded or discovered row with
		// the same leaf says nothing about what the vault will deliver.
		var source string
		if v.certificateRow != nil {
			if err := tx.QueryRow(ctx, "SELECT source FROM certificates WHERE id = $1", *v.certificateRow).Scan(&source); err != nil {
				return fmt.Errorf("inventory: read the leaf's source: %w", err)
			}
		}
		knownComplete := leaf.chainComplete && source == "azure_kv"
		src := deploySource{Trigger: "manual", BindingID: &in.BindingID, KVVersionID: &in.VersionID, Version: v.version,
			Confirmed: in.ConfirmIncompleteChain && a.Role == rbac.Admin && !knownComplete}
		for _, id := range ids {
			r, err := s.insertDeployment(ctx, tx, a, leaf, locs[id], src, now)
			if errors.Is(err, ErrDeploymentInProgress) {
				return denyWith(&denial, "in_progress", id, err)
			}
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, s.finishDenial(ctx, a, err, denial, "deployment.denied", "binding", in.BindingID, kv())
	}
	return out, nil
}

// ReleaseInput names a held version. ConfirmIncompleteChain is the Administrator's confirmation (F-17)
// that a version held for its incomplete chain may be deployed automatically.
type ReleaseInput struct {
	VaultID, KVCertificateID uuid.UUID // the version must belong to this certificate of this vault
	VersionID                uuid.UUID
	ConfirmIncompleteChain   bool
}

// ReleaseVersion lifts the hold of a version (spec §11.6 item 8): held and held_reason are cleared together.
// Only an Administrator may (ErrHeldNeedsAdmin: a version held because the license gate was closed,
// ruling S8, or because its chain was incomplete, ruling S7); the license gate must be open
// (license.ErrLocked otherwise: a version held for the license is not released while the license still
// refuses changes); ErrNotFound for an unknown version or one of a deleted vault; ErrVersionNotHeld; and
// a version held for its incomplete chain needs ConfirmIncompleteChain (ErrChainUnconfirmed: F-17 is not
// relaxed). A release is also the trace the planner reads: it sets notified_at (if unset), and the planner
// never holds a version again that has it, so a released version is not held again by the reopening rule. Releasing deploys nothing and does not turn automatic deployment on: it only lets the
// planner see the version again, which may hold it again if the chain is still incomplete when the
// secret is read. Audited kv.version.released (who, which version, which reason was released); a
// refusal that is a matter of authority, the lock or the confirmation is audited kv.version.release_denied.
func (s *Service) ReleaseVersion(ctx context.Context, a Actor, in ReleaseInput) (KVVersion, error) {
	var errs validate.Errors
	if in.VaultID == uuid.Nil {
		errs.Add("vault_id", validate.Required, nil)
	}
	if in.KVCertificateID == uuid.Nil {
		errs.Add("kv_certificate_id", validate.Required, nil)
	}
	if in.VersionID == uuid.Nil {
		errs.Add("version_id", validate.Required, nil)
	}
	if len(errs) > 0 {
		return KVVersion{}, errs
	}
	kv := func() map[string]string {
		return map[string]string{"version_id": in.VersionID.String(), "kv_certificate_id": in.KVCertificateID.String()}
	}
	deny := func(reason string, err error) (KVVersion, error) {
		s.auditBindingDenial(ctx, a, "kv.version.release_denied", "kv_certificate_version", in.VersionID, denialDetails(bindingDenial{reason: reason}, kv()))
		return KVVersion{}, err
	}
	if a.Role != rbac.Admin {
		return deny("held_needs_admin", ErrHeldNeedsAdmin)
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		return KVVersion{}, s.auditLicenseRefusal(ctx, a, err, "kv.version.release_denied", "kv_certificate_version", in.VersionID, kv())
	}
	var (
		out    KVVersion
		denial *bindingDenial
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		denial = nil
		var cert uuid.UUID
		err := tx.QueryRow(ctx, "SELECT kv_certificate_id FROM kv_certificate_versions WHERE id = $1", in.VersionID).Scan(&cert)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inventory: find the version's certificate: %w", err)
		}
		vaultID, err := vaultOfCertificate(ctx, tx, cert)
		if err != nil {
			return err
		}
		if cert != in.KVCertificateID || vaultID != in.VaultID { // the route named another certificate or vault
			return ErrNotFound
		}
		if _, err := lockVault(ctx, tx, vaultID); err != nil {
			return err
		}
		var (
			name, version, reason string
			held                  bool
		)
		err = tx.QueryRow(ctx, `SELECT kc.name, v.version, v.held, v.held_reason FROM kv_certificate_versions v
JOIN kv_certificates kc ON kc.id = v.kv_certificate_id WHERE v.id = $1 FOR UPDATE OF v`, in.VersionID).Scan(&name, &version, &held, &reason)
		if err != nil {
			return fmt.Errorf("inventory: lock the version: %w", err)
		}
		switch {
		case !held:
			return ErrVersionNotHeld
		case reason == heldIncompleteChain && !in.ConfirmIncompleteChain:
			return denyWith(&denial, "chain_unconfirmed", uuid.Nil, ErrChainUnconfirmed)
		}
		if _, err := tx.Exec(ctx, `UPDATE kv_certificate_versions SET held = false, held_reason = '', notified_at = coalesce(notified_at, $2) WHERE id = $1`, in.VersionID, s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("inventory: release the version: %w", err)
		}
		details := map[string]string{"kv_certificate_id": cert.String(), "certificate_name": name, "version": version, "reason": reason, "held": "false"}
		if reason == heldIncompleteChain {
			details["confirm_incomplete_chain"] = "true"
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "kv.version.released", ObjectType: "kv_certificate_version",
			ObjectID: in.VersionID.String(), Result: audit.Success, Details: details}); err != nil {
			return err
		}
		out, err = readKVVersion(ctx, tx, in.VersionID)
		return err
	})
	if err != nil {
		if denial != nil {
			return deny(denial.reason, err)
		}
		return KVVersion{}, err
	}
	return out, nil
}

// Held reasons (kv_certificate_versions.held_reason).
const (
	heldLicense         = "license"
	heldIncompleteChain = "incomplete_chain"
)

func readKVVersion(ctx context.Context, q db.Querier, id uuid.UUID) (KVVersion, error) {
	var v KVVersion
	err := q.QueryRow(ctx, `SELECT id, version, thumbprint, certificate_id, enabled, not_before, expires, kv_created_at, exportable, key_type,
content_type, detected_at, held, held_reason, notified_at, skipped_notified_at, chain_incomplete FROM kv_certificate_versions WHERE id = $1`, id).Scan(&v.ID,
		&v.Version, &v.Thumbprint, &v.CertificateID, &v.Enabled, &v.NotBefore, &v.Expires, &v.KVCreatedAt, &v.Exportable, &v.KeyType,
		&v.ContentType, &v.DetectedAt, &v.Held, &v.HeldReason, &v.NotifiedAt, &v.SkippedNotifiedAt, &v.ChainIncomplete)
	if errors.Is(err, pgx.ErrNoRows) {
		return KVVersion{}, ErrNotFound
	}
	if err != nil {
		return KVVersion{}, fmt.Errorf("inventory: read the version: %w", err)
	}
	v.NotBefore, v.Expires, v.KVCreatedAt, v.DetectedAt = utcPtr(v.NotBefore), utcPtr(v.Expires), utcPtr(v.KVCreatedAt), v.DetectedAt.UTC()
	v.NotifiedAt, v.SkippedNotifiedAt = utcPtr(v.NotifiedAt), utcPtr(v.SkippedNotifiedAt)
	return v, nil
}
