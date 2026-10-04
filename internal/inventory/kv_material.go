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
// except for a failure row of kv.secret_read (closed reason secret_mismatch, secret_unreadable, expired,
// chain_unconfirmed or pfx_busy; not written by a run that lost its claim): ErrPFXBusy (retryable: the PFX decode slots are taken); ErrSecretUnreadable (not a
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
	m, err := s.DeploymentMaterial(ctx, id, false)
	if err != nil {
		return Material{}, err
	}
	if m.KV == nil || m.Recorded {
		return Material{}, ErrDeploymentState
	}
	// Whatever the request relied on is judged again before the secret is looked at (C1, I1): a
	// refusal here reads nothing, writes nothing and audits nothing.
	// From here on the vault's secret is in Alice's memory (the engine read it, ideally after its own
	// KVDeployPrecheck): every refusal, the shared check's included, is audited (R40 row 34) and the
	// secret is zeroed.
	refuse := func(reason string, err error) (Material, error) {
		if aerr := s.auditSecretReadFailure(ctx, m, reason); aerr != nil {
			return Material{}, aerr
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
		if m.Deployment.Trigger == triggerKVRenewal {
			if err := s.holdIncompleteChain(ctx, m); err != nil {
				return Material{}, err
			}
		}
		return refuse("chain_unconfirmed", ErrChainUnconfirmed)
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
	m.NewCertSHA256 = sha256Hex(m.CertificatePEM)
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
		vExpires, vNotBefore              *time.Time
		cNotBefore, cNotAfter             time.Time
	)
	err := s.pool.QueryRow(ctx, `SELECT d.trigger, d.state, d.binding_id, l.binding_id, b.id IS NOT NULL AND b.deleted_at IS NULL, coalesce(b.auto_deploy, false),
    vt.status, vt.deleted_at IS NOT NULL, kc.missing_since IS NOT NULL, v.enabled, v.expires, v.not_before, v.held,
    c.not_before, c.not_after, coalesce(u.role = 'admin' AND u.disabled_at IS NULL, false)
FROM deployments d
JOIN kv_certificate_versions v ON v.id = d.kv_version_id
JOIN kv_certificates kc ON kc.id = v.kv_certificate_id
JOIN targets vt ON vt.id = kc.target_id
JOIN certificate_locations l ON l.id = d.location_id
JOIN certificates c ON c.id = d.certificate_id
LEFT JOIN bindings b ON b.id = d.binding_id
LEFT JOIN users u ON u.id = d.requested_by
WHERE d.id = $1`, id).Scan(&trigger, &state, &binding, &locBinding, &bindingLive, &auto, &vaultStatus, &vaultDeleted, &certMissing, &enabled,
		&vExpires, &vNotBefore, &held, &cNotBefore, &cNotAfter, &admin)
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
	case binding == nil || !bindingLive || locBinding == nil || *locBinding != *binding:
		return ErrBindingGone
	case trigger == triggerKVRenewal && !auto:
		return ErrAutoDeployOff
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
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.secret_read", ObjectType: "deployment", ObjectID: m.Deployment.ID.String(),
			Result: audit.Success, Details: map[string]string{"purpose": "deploy", "deployment_id": m.Deployment.ID.String(),
				"kv_certificate_id": m.KV.KVCertificateID.String(), "certificate_name": m.KV.Name, "version": m.KV.Version}})
		return err
	})
}

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
		tag, err := tx.Exec(ctx, "UPDATE kv_certificate_versions SET held = true, held_reason = $2 WHERE id = $1 AND NOT held",
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
