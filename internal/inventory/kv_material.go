package inventory

// The material step of a Key Vault deployment (spec §11.6; R40 row 18; rulings S3, S7): the
// engine reads the backing secret of the deployment's version from the vault and hands it to
// KVDeployMaterial, which checks that it is the recorded version, builds what the first send
// needs and records what was read. Nothing of the secret is stored: the chain goes to the certificate
// row (public data), the key stays in memory and is the caller's to zero.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/certs"
	"alice/internal/platform/azureid"
	"alice/internal/platform/db"
	"alice/internal/providers"
)

// KVSource names the vault object a Key Vault deployment deploys: the vault, the certificate, the
// stored version (id and vault version string) and its SHA-1 thumbprint as Azure shows it.
type KVSource struct {
	VaultID, KVCertificateID, VersionID uuid.UUID
	Name, Version, Thumbprint           string
}

// Warning of the material step (Material.Warnings).
const WarnChainIncomplete = "chain_incomplete"

// KVDeployMaterial checks the backing secret of a Key Vault deployment's version and returns the
// material of its first send: the chain as the vault delivered it without a self-signed root, and the
// key as PEM, only in memory (the caller zeroes Material.PrivateKeyPEM). secret.Value is zeroed on
// every path. The deployment must be queued or in its pre-check (ErrDeploymentState otherwise: after
// the first send nothing is read again) and from a vault (ErrDeploymentState). KVDeployPrecheck runs
// first: its refusals read, write and audit nothing. After it, a refusal does not change the database
// except for a failure row of kv.secret_read (closed reason secret_mismatch, secret_unreadable, not_exportable,
// expired, chain_unconfirmed or pfx_busy; not written by a run that lost its claim) and, for a secret with the
// certificates but no key (not_exportable, answered as ErrSecretUnreadable), the certificate and the version
// stored as not exportable: ErrPFXBusy (retryable: the PFX decode slots are taken); ErrSecretUnreadable (not a
// certificate with a matching key in a known container, or too large); ErrCertificateExpired (the
// secret's leaf expired); ErrSecretMismatch (another leaf, thumbprint or key type than the recorded
// version); ErrChainUnconfirmed (the chain is incomplete and an Administrator did not confirm it when
// requesting, F-17, ruling S7); ErrClaimLost (the job run lost its job). For an incomplete chain of an
// automatic deployment (trigger kv_renewal) the version is also held with held_reason
// "incomplete_chain" (audited kv.version.held; a hold of another reason is kept: the first reason wins),
// so that it is never deployed automatically until an Administrator releases or deploys it. On success
// the leaf's certificates row (source azure_kv only; an uploaded or discovered row with the same leaf
// is never changed) gets the delivered chain as pem_chain and its completeness, and kv.secret_read
// (purpose deploy) is audited, both fenced to the job's claim. A chain longer than the certificate
// row holds is ErrSecretUnreadable.
func (s *Service) KVDeployMaterial(ctx context.Context, id uuid.UUID, secret providers.CertificateSecret) (Material, error) {
	defer secret.Value.Zero()
	// A secret is in hand from here on: every refusal is audited as a failed read with a closed reason
	// (R40 row 34), also those that come before the shared check; a deployment that does not exist is the
	// one thing there is nothing to audit about.
	m, err := s.DeploymentMaterial(ctx, id, false)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrClaimLost) {
			return Material{}, err
		}
		return Material{}, s.refuseUnattributed(ctx, id, nil, "material_unavailable", err)
	}
	if m.KV == nil || m.Recorded {
		return Material{}, s.refuseUnattributed(ctx, id, m.KV, "deployment_state", ErrDeploymentState)
	}
	// From here on the vault's secret is in Alice's memory (the engine read it, ideally after its own
	// KVDeployPrecheck): every refusal, the shared check's included, is audited (R40 row 34) and the
	// secret is zeroed.
	// The refusal reaches the caller as itself even when its audit row cannot be written (the engine maps
	// the sentinel); the failed write is joined to it and logged by type.
	refuse := func(reason string, err error) (Material, error) {
		if aerr := s.auditSecretReadFailure(ctx, m, reason); aerr != nil {
			s.log.Error("could not audit a refused secret read", "reason", reason, "error_type", fmt.Sprintf("%T", aerr))
			return Material{}, errors.Join(err, aerr)
		}
		return Material{}, err
	}
	if err := s.KVDeployPrecheck(ctx, id); err != nil {
		return refuse(precheckReason(err), err)
	}
	release, ok := acquirePFXSlot()
	if !ok {
		return refuse("pfx_busy", ErrPFXBusy)
	}
	v, err := s.parseKVSecret(secret)
	release()
	if err != nil {
		if errors.Is(err, certs.ErrExpired) {
			return refuse("expired", ErrCertificateExpired)
		}
		if errors.Is(err, certs.ErrNoKey) {
			// The certificates without the key: the policy became non-exportable without a new version,
			// which no poll notices. Store it, so the next request is refused as not exportable and the
			// page shows Monitor only; this attempt ends as an unreadable secret.
			merr := s.markNotExportable(ctx, m)
			if merr != nil {
				s.log.Error("could not mark a vault certificate not exportable", "error_type", fmt.Sprintf("%T", merr))
			}
			m2, rerr := refuse("not_exportable", ErrSecretUnreadable)
			return m2, errors.Join(rerr, merr)
		}
		return refuse("secret_unreadable", ErrSecretUnreadable)
	}
	defer v.PrivateKeyDER.Zero()
	if kvMaterialHook != nil {
		kvMaterialHook("der", v.PrivateKeyDER.Bytes())
	}
	if v.Fingerprint != m.Fingerprint || azureid.ThumbprintOf(v.Leaf.Raw) != m.KV.Thumbprint || v.Algorithm != m.KeyType {
		return refuse("secret_mismatch", ErrSecretMismatch)
	}
	if !v.ChainComplete && !m.Deployment.ConfirmIncompleteChain {
		var herr error
		if m.Deployment.Trigger == triggerKVRenewal {
			if herr = s.holdIncompleteChain(ctx, m); herr != nil {
				s.log.Error("could not hold a version for its incomplete chain", "error_type", fmt.Sprintf("%T", herr))
			}
		} else if herr = s.markChainIncomplete(ctx, m); herr != nil {
			s.log.Error("could not mark a version's chain incomplete", "error_type", fmt.Sprintf("%T", herr))
		}
		m2, rerr := refuse("chain_unconfirmed", ErrChainUnconfirmed)
		return m2, errors.Join(rerr, herr)
	}
	if len(v.PEMChain) > maxPEMChain {
		return refuse("secret_unreadable", ErrSecretUnreadable)
	}
	key, err := certs.KeyPEM(v.PrivateKeyDER)
	if err != nil {
		return refuse("secret_unreadable", ErrSecretUnreadable)
	}
	handedOut := false
	defer func() {
		if !handedOut { // an error, or a panic: the key PEM never leaves
			key.Zero()
		}
	}()
	if kvMaterialHook != nil {
		kvMaterialHook("pem", key.Bytes())
	}
	if err := s.recordSecretRead(ctx, m, v); err != nil {
		return Material{}, err
	}
	m.CertificatePEM = []byte(v.PEMChain)
	m.NewChainLength = chainLength(m.CertificatePEM)
	m.NewCertSHA256 = newCertSHA256(m.Location.Kind, m.CertificatePEM)
	m.PrivateKeyPEM = key
	if !v.ChainComplete {
		m.Warnings = append(m.Warnings, WarnChainIncomplete)
	}
	handedOut = true
	return m, nil
}

// kvMaterialHook observes the buffers KVDeployMaterial wipes: "der" (the decoded key, right after the
// secret was decoded; runs before the comparison with the recorded version) and "pem" (the key PEM
// that is handed to the caller on success). Tests only: it is nil in production.
var kvMaterialHook func(stage string, b []byte)

// precheckReason is the closed reason an audit row gives for a refusal of KVDeployPrecheck.
func precheckReason(err error) string {
	switch {
	case errors.Is(err, ErrBindingGone):
		return "binding_gone"
	case errors.Is(err, ErrAutoDeployOff):
		return "auto_deploy_off"
	case errors.Is(err, ErrVaultUnavailable):
		return "vault_unavailable"
	case errors.Is(err, ErrKVCertificateMissing):
		return "certificate_missing"
	case errors.Is(err, ErrVersionDisabled):
		return "version_disabled"
	case errors.Is(err, ErrCertificateExpired):
		return "expired"
	case errors.Is(err, ErrCertificateNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, ErrVersionHeld):
		return "version_held"
	case errors.Is(err, ErrVersionSuperseded):
		return "version_superseded"
	case errors.Is(err, ErrWaveStopped):
		return "wave_stopped"
	}
	return "refused"
}

// KVDeployPrecheck judges, without reading the vault, whether the deployment may still have its secret
// read and its key handed out. The engine calls it before it reads the secret (so no key reaches memory
// and no sibling of a wave reads in vain); KVDeployMaterial calls it again as its own first step.
// Nothing is written. Refusals, in this order: ErrNotFound (no such deployment); ErrDeploymentState (not a
// Key Vault deployment, or past its pre-check: only a queued or pre-check deployment may read); ErrBindingGone (the binding was removed, or the website no longer belongs to
// it); ErrAutoDeployOff (an automatic deployment of a binding whose automatic deployment is off);
// ErrVaultUnavailable (vault disabled or deleted); ErrKVCertificateMissing; ErrVersionDisabled;
// ErrCertificateExpired and ErrCertificateNotYetValid (as far as the stored rows know); and
// ErrVersionHeld: an automatic deployment never deploys a held version, a manual one only when the user
// who requested it is still an enabled Administrator (the request recorded who asked: an Operator can
// request only a version that was not held, so a hold that came later stops it).
func (s *Service) KVDeployPrecheck(ctx context.Context, id uuid.UUID) error {
	var (
		trigger, state                    string
		binding, locBinding               *uuid.UUID
		bindingLive, auto, vaultDeleted   bool
		certMissing, enabled, held, admin bool
		vaultStatus                       string
		current, stoppedVersion, version  string
		createdAt                         time.Time
		autoSince                         *time.Time
		vExpires, vNotBefore              *time.Time
		cNotBefore, cNotAfter             time.Time
	)
	err := s.pool.QueryRow(ctx, `SELECT d.trigger, d.state, d.binding_id, l.binding_id, b.id IS NOT NULL AND b.deleted_at IS NULL, coalesce(b.auto_deploy, false),
    vt.status, vt.deleted_at IS NOT NULL, kc.missing_since IS NOT NULL, v.enabled, v.expires, v.not_before, v.held,
    c.not_before, c.not_after, coalesce(u.role = 'admin' AND u.disabled_at IS NULL, false), kc.current_version, v.version, coalesce(b.stopped_version, ''), d.created_at, b.auto_since
FROM deployments d
JOIN kv_certificate_versions v ON v.id = d.kv_version_id
JOIN kv_certificates kc ON kc.id = v.kv_certificate_id
JOIN targets vt ON vt.id = kc.target_id
JOIN certificate_locations l ON l.id = d.location_id
JOIN certificates c ON c.id = d.certificate_id
LEFT JOIN bindings b ON b.id = d.binding_id
LEFT JOIN users u ON u.id = d.requested_by
WHERE d.id = $1`, id).Scan(&trigger, &state, &binding, &locBinding, &bindingLive, &auto, &vaultStatus, &vaultDeleted, &certMissing, &enabled,
		&vExpires, &vNotBefore, &held, &cNotBefore, &cNotAfter, &admin, &current, &version, &stoppedVersion, &createdAt, &autoSince)
	if errors.Is(err, pgx.ErrNoRows) {
		var one int
		if e := s.pool.QueryRow(ctx, "SELECT 1 FROM deployments WHERE id = $1", id).Scan(&one); e == nil {
			return ErrDeploymentState // a deployment without a vault version
		}
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("inventory: judge the deployment's vault source: %w", err)
	}
	now := s.clock.Now().UTC()
	switch {
	case state != DeployStateQueued && state != DeployStatePrecheck:
		return ErrDeploymentState
	// bindingLive alone is unreachable (a soft-deleted binding releases its websites, so the website check
	// answers first); it is kept as the direct statement of the rule.
	case binding == nil || !bindingLive || locBinding == nil || *locBinding != *binding:
		return ErrBindingGone
	case trigger == triggerKVRenewal && !auto:
		return ErrAutoDeployOff
	case trigger == triggerKVRenewal && autoSince != nil && createdAt.Before(*autoSince):
		// Created in an automatic-deployment period that ended (off, then on again): the "deploy manually"
		// mail said this version would not be deployed.
		return ErrAutoDeployOff
	case trigger == triggerKVRenewal && version != current: // a newer version replaced it since the planner queued it
		return ErrVersionSuperseded
	case trigger == triggerKVRenewal && stoppedVersion == version:
		return ErrWaveStopped
	case vaultDeleted || vaultStatus == StatusDisabled:
		return ErrVaultUnavailable
	case certMissing:
		return ErrKVCertificateMissing
	case !enabled:
		return ErrVersionDisabled
	case !now.Before(cNotAfter) || (vExpires != nil && !now.Before(*vExpires)):
		return ErrCertificateExpired
	case now.Before(cNotBefore) || (vNotBefore != nil && now.Before(*vNotBefore)):
		return ErrCertificateNotYetValid
	case held && (trigger == triggerKVRenewal || !admin):
		return ErrVersionHeld
	}
	return nil
}

// refuseUnattributed audits a refusal that came before the version was known (kv may be nil), and returns
// err, joined with the failure of the audit write if there was one.
func (s *Service) refuseUnattributed(ctx context.Context, id uuid.UUID, kv *KVSource, reason string, err error) error {
	details := map[string]string{"purpose": "deploy", "deployment_id": id.String(), "reason": reason}
	if kv != nil {
		details["kv_certificate_id"], details["certificate_name"], details["version"] = kv.KVCertificateID.String(), kv.Name, kv.Version
	}
	aerr := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.secret_read", ObjectType: "deployment", ObjectID: id.String(),
			Result: audit.Failure, Details: details})
		return err
	})
	if aerr != nil {
		s.log.Error("could not audit a refused secret read", "reason", reason, "error_type", fmt.Sprintf("%T", aerr))
		return errors.Join(err, aerr)
	}
	return err
}

// auditSecretReadFailure audits a read of the vault's secret that ended in a refusal: result failure
// and the closed reason, fenced to the job's claim (a run that lost its job writes nothing and gets
// ErrClaimLost).
func (s *Service) auditSecretReadFailure(ctx context.Context, m Material, reason string) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.secret_read", ObjectType: "deployment", ObjectID: m.Deployment.ID.String(),
			Result: audit.Failure, Details: map[string]string{"purpose": "deploy", "deployment_id": m.Deployment.ID.String(),
				"kv_certificate_id": m.KV.KVCertificateID.String(), "certificate_name": m.KV.Name, "version": m.KV.Version, "reason": reason}})
		return err
	})
}

// triggerKVRenewal is the trigger of a deployment the planner created (migration 00006).
const triggerKVRenewal = "kv_renewal"

// parseKVSecret decodes the secret; a panic of a decoder is a closed refusal, never a crash (only the
// panic's type is logged).
func (s *Service) parseKVSecret(secret providers.CertificateSecret) (v certs.Validated, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("a vault secret crashed the decoder", slog.String("panic_type", fmt.Sprintf("%T", r)))
			v, err = certs.Validated{}, errDecoderPanic
		}
	}()
	return certs.ParseKVSecret(secret.ContentType, secret.Value.Bytes(), s.clock.Now().UTC(), s.roots)
}

// recordSecretRead stores the delivered chain on the version's leaf row and audits the read, in one
// fenced transaction.
func (s *Service) recordSecretRead(ctx context.Context, m Material, v certs.Validated) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE certificates SET pem_chain = $2, chain_complete = $3 WHERE id = $1 AND source = 'azure_kv'",
			m.Deployment.CertificateID, v.PEMChain, v.ChainComplete); err != nil {
			return fmt.Errorf("inventory: store the delivered chain: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE kv_certificate_versions SET chain_incomplete = $2 WHERE id = $1", m.KV.VersionID, !v.ChainComplete); err != nil {
			return fmt.Errorf("inventory: store what the read found about the chain: %w", err)
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.secret_read", ObjectType: "deployment", ObjectID: m.Deployment.ID.String(),
			Result: audit.Success, Details: map[string]string{"purpose": "deploy", "deployment_id": m.Deployment.ID.String(),
				"kv_certificate_id": m.KV.KVCertificateID.String(), "certificate_name": m.KV.Name, "version": m.KV.Version}})
		return err
	})
}

// markChainIncomplete stores that a read of the deployment's version found its chain incomplete (a manual deployment
// without the confirmation), fenced to the job's claim, so the next manual request asks for the confirmation.
func (s *Service) markChainIncomplete(ctx context.Context, m Material) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "UPDATE kv_certificate_versions SET chain_incomplete = true WHERE id = $1", m.KV.VersionID)
		return err
	})
}

// markNotExportable stores the deployment's certificate and version as not exportable (a secret read
// returned the certificates without the key), under the vault's lock, fenced to the job's claim. A
// later poll that reads the certificate's policy stores what the policy says.
func (s *Service) markNotExportable(ctx context.Context, m Material) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		if _, err := lockVault(ctx, tx, m.KV.VaultID); err != nil {
			if errors.Is(err, ErrNotFound) { // the vault was deleted meanwhile: nothing to mark
				return nil
			}
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE kv_certificate_versions SET exportable = false WHERE id = $1", m.KV.VersionID); err != nil {
			return fmt.Errorf("inventory: mark the version not exportable: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE kv_certificates SET exportable = false WHERE id = $1", m.KV.KVCertificateID); err != nil {
			return fmt.Errorf("inventory: mark the certificate not exportable: %w", err)
		}
		return nil
	})
}

// A new hold is a new episode: notified_at is cleared in the same statement so that its mail goes out once.
// The planner's reopening rule cannot re-hold such a version: this hold exists because a deployment of it
// does, and that rule applies only to a version without any deployment.
// holdIncompleteChain holds the deployment's version for its incomplete chain (first reason wins),
// under the vault's lock, fenced to the job's claim.
func (s *Service) holdIncompleteChain(ctx context.Context, m Material) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		if _, err := lockVault(ctx, tx, m.KV.VaultID); err != nil {
			if errors.Is(err, ErrNotFound) { // the vault was deleted meanwhile: nothing to hold
				return nil
			}
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE kv_certificate_versions SET chain_incomplete = true WHERE id = $1", m.KV.VersionID); err != nil {
			return fmt.Errorf("inventory: mark the version's chain incomplete: %w", err)
		}
		tag, err := tx.Exec(ctx, "UPDATE kv_certificate_versions SET held = true, held_reason = $2, notified_at = NULL WHERE id = $1 AND NOT held",
			m.KV.VersionID, heldIncompleteChain)
		if err != nil {
			return fmt.Errorf("inventory: hold the version: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.version.held", ObjectType: "kv_certificate",
			ObjectID: m.KV.KVCertificateID.String(), Result: audit.Success, Details: map[string]string{"kv_certificate_id": m.KV.KVCertificateID.String(),
				"certificate_name": m.KV.Name, "version": m.KV.Version, "reason": heldIncompleteChain, "held": strconv.FormatBool(true),
				"deployment_id": m.Deployment.ID.String()}})
		return err
	})
}
