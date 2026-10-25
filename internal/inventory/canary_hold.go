package inventory

// The holding state of a canary rollout's wave-1 deployments (R65, design
// docs/superpowers/specs/2026-10-24-canary-deployment-design.md §8, §10):
//
//	deploying/recovering -> holding [running]   a wave-1 verified success (finishLocked -> enterHold): every final value
//	                                            of the success except state, status and finished_at; the file hash a
//	                                            success writes to the location is kept in held_cert_file_sha256; the
//	                                            location is NOT updated; its canary_checks row starts the rounds now
//	holding -> done [succeeded]                 ReleaseHold: the stored values finish it as a success does (the location
//	                                            update, deployment.succeeded with hold_cause, every side effect)
//	holding -> recovering (revert_reason)       RequestRevert: the recovery path rolls the committed operation back with
//	                                            the R48 guard read right before it (deployjobs recoverDeployment)
//
// The engine never reads the rollout: a wave-1 success always holds, and the canary decides what happens to it. A hold
// keeps its location busy (deployments_one_active), drift and discovery treat it as unfinished, and the sweep leaves it.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/providers"
)

// The error codes of a reverted (or never sent) wave-1 deployment (ALC-DEP-0031..0033).
const (
	ReasonCanaryCheckFailed = "deployment.canary_check_failed"
	ReasonCanaryAborted     = "deployment.canary_aborted"
	ReasonCanaryWaveFailed  = "deployment.canary_wave_failed"
)

// The causes of a release (the deployment.succeeded audit row's hold_cause).
const (
	HoldCauseRelease       = "release"
	HoldCauseIncident      = "incident"
	HoldCauseTargetDeleted = "target_deleted"
)

// enterHold records a wave-1 deployment's verified success as a hold (see the table above). d and its location are
// locked by the caller (finishLocked).
func (s *Service) enterHold(ctx context.Context, tx pgx.Tx, d lockedDeployment, f DeploymentFinish, verified string, params []byte,
	trust providers.Trust, trustPort *int, now time.Time) error {
	fileSHA := ""
	if hex64RE.MatchString(f.CertFileSHA256) {
		fileSHA = f.CertFileSHA256
	}
	var port *int
	if f.VerifyFailedPort != nil && *f.VerifyFailedPort >= 1 && *f.VerifyFailedPort <= 65535 {
		port = f.VerifyFailedPort
	}
	if _, err := tx.Exec(ctx, `UPDATE deployments SET state = $2, status = $3, result = $4, phase = $5, error_code = '', error_params = $6,
    failed_step = '', cause_step = $7, helper_error = $8, verified = $9,
    verify_failed_reason = CASE WHEN $10::text = '' THEN verify_failed_reason ELSE $10::text END,
    verify_failed_port = coalesce($11::integer, verify_failed_port), recover_after = NULL,
    trust_status = $12, trust_error = $13, trust_port = $14, trust_store = $15, trust_enforced = $16, held_cert_file_sha256 = $17
WHERE id = $1`, d.id, DeployStateHolding, DeployStatusRunning, oneOf(f.Result, results), oneOf(f.Phase, phases), params,
		stepOrBlank(f.CauseStep), stepOrBlank(f.HelperError), verified, sanitizeCode(f.VerifyFailedReason, ""), port,
		trust.Status, trust.Error, trustPort, trust.Store, trust.Enforced, fileSHA); err != nil {
		return fmt.Errorf("inventory: record the hold: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO canary_checks (deployment_id, rollout_id, next_check_at) VALUES ($1, $2, $3)
ON CONFLICT (deployment_id) DO NOTHING`, d.id, *d.rollout, now); err != nil {
		return fmt.Errorf("inventory: start the canary rounds: %w", err)
	}
	return s.appendAudit(ctx, tx, "deployment.holding", audit.Success, d.id, map[string]string{"rollout_id": d.rollout.String(),
		"new_fingerprint": d.newFingerprint, "verified": verified})
}

// lockForHold locks a deployment's location then the deployment (FinishDeployment's order) in tx.
func lockForHold(ctx context.Context, tx pgx.Tx, id uuid.UUID) (lockedDeployment, error) {
	var location uuid.UUID
	err := tx.QueryRow(ctx, "SELECT location_id FROM deployments WHERE id = $1", id).Scan(&location)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedDeployment{}, ErrNotFound
	}
	if err != nil {
		return lockedDeployment{}, fmt.Errorf("inventory: read deployment: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT 1 FROM certificate_locations WHERE id = $1 FOR NO KEY UPDATE", location); err != nil {
		return lockedDeployment{}, fmt.Errorf("inventory: lock the location: %w", err)
	}
	return lockDeployment(ctx, tx, id)
}

// ReleaseHold finishes a holding deployment as the success it was (design §8.1) in tx: the values stored when it
// entered holding, the location update, deployment.succeeded with hold_cause (HoldCause*). A deployment that is not
// holding is ErrDeploymentState; one whose deployed certificate is revoked or compromised is ErrCertificateRevoked or
// ErrCertificateCompromised and stays holding (design §20.3: it is reverted, never released).
func (s *Service) ReleaseHold(ctx context.Context, tx pgx.Tx, id uuid.UUID, cause string) error {
	d, err := lockForHold(ctx, tx, id)
	if err != nil {
		return err
	}
	if d.state != DeployStateHolding {
		return ErrDeploymentState
	}
	var (
		revoked, compromised bool
		f                    = DeploymentFinish{Status: DeployStatusSucceeded, Params: map[string]string{}, release: true, holdCause: cause}
		trustPort            *int
	)
	err = tx.QueryRow(ctx, `SELECT d.result, d.phase, d.verified, d.trust_status, d.trust_error, d.trust_port, d.trust_store, d.trust_enforced,
    d.held_cert_file_sha256, c.revoked_at IS NOT NULL, c.compromised_at IS NOT NULL
FROM deployments d JOIN certificates c ON c.id = d.certificate_id WHERE d.id = $1`, id).Scan(&f.Result, &f.Phase, &f.Verified,
		&f.Trust.Status, &f.Trust.Error, &trustPort, &f.Trust.Store, &f.Trust.Enforced, &f.CertFileSHA256, &revoked, &compromised)
	if err != nil {
		return fmt.Errorf("inventory: read the hold: %w", err)
	}
	switch {
	case compromised:
		return ErrCertificateCompromised
	case revoked:
		return ErrCertificateRevoked
	}
	if trustPort != nil {
		f.Trust.Port = *trustPort
	}
	return s.finishLocked(ctx, tx, d, f)
}

// RequestRevert hands a holding deployment to the recovery path (design §8.1, §10) in tx: recovering with
// revert_reason and error_code reason, a certificate.deploy_recover job queued now (requestRecoveryLocked; the next
// one is paced as any recovery), audited deployment.revert_requested. A deployment that is not holding is
// ErrDeploymentState. The recovery rolls the committed operation back with the rollback guard read right before.
func (s *Service) RequestRevert(ctx context.Context, tx pgx.Tx, id uuid.UUID, reason string) error {
	if !errorCodeRE.MatchString(reason) {
		return errors.New("inventory: not a revert reason")
	}
	d, err := lockForHold(ctx, tx, id)
	if err != nil {
		return err
	}
	if d.state != DeployStateHolding {
		return ErrDeploymentState
	}
	if _, err := tx.Exec(ctx, `UPDATE deployments SET state = $2, revert_reason = $3, error_code = $3, recover_after = $4 WHERE id = $1`,
		id, DeployStateRecovering, reason, s.clock.Now().UTC()); err != nil {
		return fmt.Errorf("inventory: request the revert: %w", err)
	}
	if err := s.appendAudit(ctx, tx, "deployment.revert_requested", audit.Success, id, map[string]string{"reason": reason,
		"rollout_id": d.rollout.String()}); err != nil {
		return err
	}
	d.state, d.revertReason, d.errorCode = DeployStateRecovering, reason, reason
	_, err = s.requestRecoveryLocked(ctx, tx, d)
	return err
}
