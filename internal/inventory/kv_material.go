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
// the first send nothing is read again) and from a vault (ErrDeploymentState). Refusals, none of which
// writes anything: ErrPFXBusy (retryable: the PFX decode slots are taken); ErrSecretUnreadable (not a
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
	release, ok := acquirePFXSlot()
	if !ok {
		return Material{}, ErrPFXBusy
	}
	v, err := s.parseKVSecret(secret)
	release()
	if err != nil {
		if errors.Is(err, certs.ErrExpired) {
			return Material{}, ErrCertificateExpired
		}
		return Material{}, ErrSecretUnreadable
	}
	defer v.PrivateKeyDER.Zero()
	if v.Fingerprint != m.Fingerprint || azureid.ThumbprintOf(v.Leaf.Raw) != m.KV.Thumbprint || v.Algorithm != m.KeyType {
		return Material{}, ErrSecretMismatch
	}
	if !v.ChainComplete && !m.Deployment.ConfirmIncompleteChain {
		if m.Deployment.Trigger == triggerKVRenewal {
			if err := s.holdIncompleteChain(ctx, m); err != nil {
				return Material{}, err
			}
		}
		return Material{}, ErrChainUnconfirmed
	}
	if len(v.PEMChain) > maxPEMChain {
		return Material{}, ErrSecretUnreadable
	}
	key, err := certs.KeyPEM(v.PrivateKeyDER)
	if err != nil {
		return Material{}, ErrSecretUnreadable
	}
	if err := s.recordSecretRead(ctx, m, v); err != nil {
		key.Zero()
		return Material{}, err
	}
	m.CertificatePEM = []byte(v.PEMChain)
	m.NewChainLength = chainLength(m.CertificatePEM)
	m.NewCertSHA256 = sha256Hex(m.CertificatePEM)
	m.PrivateKeyPEM = key
	if !v.ChainComplete {
		m.Warnings = append(m.Warnings, WarnChainIncomplete)
	}
	return m, nil
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
