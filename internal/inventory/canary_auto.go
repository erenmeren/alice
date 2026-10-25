package inventory

// Canary rollouts of the automatic planners (R65, design §12): the ACME and Key Vault planners stay the deciders; a
// snapshot field (canaryPlanState) adds one rule to each pure plan function, and a failed or aborted rollout stops the
// automatic deployment it belongs to (stopAutomaticSource) with the planners' existing stop mark, audit row and notice.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/authz"
)

// canaryPlanState is what a planner's pure decision knows about the canary of one source key.
type canaryPlanState struct {
	settings authz.CanarySettings
	enabled  bool // the source service's policy enables the canary
	version  int  // its policy version
	// rollout is the newest rollout of this source key (origin acme or key_vault), nil when none.
	rollout *Rollout
	// currentNotAfter is the not_after of each bound location's current certificate (absent when unknown).
	currentNotAfter map[uuid.UUID]time.Time
	// reserved are the locations of every other rollout (any origin) in wave1 or hold: never a candidate.
	reserved map[uuid.UUID]bool
}

// rolloutWaves is a rollout a plan asks to create.
type rolloutWaves struct{ wave1, wave2 []uuid.UUID }

// canaryFilter applies the canary to a planner's candidates (design §12), in order:
//
//   - the reserved locations are never candidates (a person's rollout in wave1 or hold is never overtaken);
//   - no enabled canary: the candidates stand;
//   - the source key's rollout is in wave1 or hold: only its wave-1 locations not yet attempted (attempted) are deployed,
//     nothing else; wave-1 failures are not retried (the rollout fails);
//   - its rollout completed, was preempted or stopped: today's plan over the rest;
//   - otherwise (no rollout, or a failed or aborted one that was re-armed): two or more candidates and the expiry guard
//     passing create a rollout and deploy wave 1; a current certificate ending within hold + 24 h deploys all at once
//     (skip "expiry"); one candidate deploys as today.
//
// It answers the locations to deploy (in order), the rollout to create (nil when none) and why the canary was skipped.
func canaryFilter(c *canaryPlanState, candidates []uuid.UUID, attempted func(uuid.UUID) bool, now time.Time) ([]uuid.UUID,
	*rolloutWaves, string) {
	if c == nil {
		return candidates, nil, ""
	}
	var out []uuid.UUID
	for _, l := range candidates {
		if !c.reserved[l] {
			out = append(out, l)
		}
	}
	if !c.enabled {
		return out, nil, ""
	}
	if r := c.rollout; r != nil {
		switch r.State {
		case RolloutWave1, RolloutHold:
			var wave1 []uuid.UUID
			for _, l := range out {
				if slices.Contains(r.Wave1, l) && !attempted(l) {
					wave1 = append(wave1, l)
				}
			}
			return wave1, nil, ""
		case RolloutCompleted, RolloutPreempted, RolloutStopped, RolloutWave2:
			return out, nil, ""
		}
	}
	if len(out) < 2 {
		return out, nil, ""
	}
	if _, at, ok := earliestExpiry(out, c.currentNotAfter); ok && at.Before(now.Add(c.settings.Hold+CanaryExpiryMargin)) {
		return out, nil, CanarySkipExpiry
	}
	w1, w2 := authz.CanaryWaves(out, c.settings)
	return w1, &rolloutWaves{wave1: w1, wave2: w2}, ""
}

// readCanaryPlanState reads the canary of one automatic source key in tx: the source service's policy, the newest
// rollout of the key (keyColumn = keyValue AND certColumn = certValue, origin), the reserved locations and the current
// certificates of the bound locations.
func readCanaryPlanState(ctx context.Context, tx pgx.Tx, service uuid.UUID, origin, keyColumn string, keyValue, certColumnValue uuid.UUID,
	certColumn string, locations []uuid.UUID) (*canaryPlanState, error) {
	p, version, err := loadPolicyVersion(ctx, tx, service)
	if err != nil {
		return nil, err
	}
	c := &canaryPlanState{version: version, reserved: map[uuid.UUID]bool{}}
	c.settings, c.enabled = p.CanarySettings()
	r, err := scanRollout(tx.QueryRow(ctx, "SELECT "+rolloutColumns+" FROM deployment_rollouts WHERE origin = $1 AND "+keyColumn+" = $2 AND "+
		certColumn+" = $3 ORDER BY created_at DESC, id DESC LIMIT 1", origin, keyValue, certColumnValue))
	switch {
	case err == nil:
		c.rollout = &r
	case !errors.Is(err, ErrRolloutNotFound):
		return nil, err
	}
	own := uuid.Nil
	if c.rollout != nil {
		own = c.rollout.ID
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT unnest(wave1_location_ids || wave2_location_ids) FROM deployment_rollouts
WHERE finished_at IS NULL AND state IN ('wave1', 'hold') AND id <> $1`, own)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the reserved locations: %w", err)
	}
	reserved, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("inventory: read the reserved locations: %w", err)
	}
	for _, l := range reserved {
		c.reserved[l] = true
	}
	if c.currentNotAfter, err = currentNotAfter(ctx, tx, locations); err != nil {
		return nil, err
	}
	return c, nil
}

// createAutomaticRollout creates the rollout a planner's plan asks for (actor: the planner).
func (s *Service) createAutomaticRollout(ctx context.Context, tx pgx.Tx, c *canaryPlanState, w *rolloutWaves, certificate, service uuid.UUID,
	src rolloutSource, now time.Time) (*Rollout, error) {
	svc := service
	r := Rollout{ID: uuid.Must(uuid.NewV7()), CertificateID: certificate, ServiceID: &svc, PolicyVersion: c.version, Settings: c.settings,
		Origin: src.origin, ACMECertificateID: src.acmeCertificateID, BindingID: src.bindingID, KVVersionID: src.kvVersionID, State: RolloutWave1,
		ReasonParams: map[string]string{}, Wave1: w.wave1, Wave2: w.wave2, Skipped: []RolloutSkip{}, CreatedAt: now, Version: 1}
	if err := s.createRollout(ctx, tx, Actor{Audit: jobsActor}, r); err != nil {
		return nil, err
	}
	return &r, nil
}

// auditCanarySkipped records that a planner deployed all at once because of the expiry guard.
func (s *Service) auditCanarySkipped(ctx context.Context, tx pgx.Tx, c *canaryPlanState, certificate uuid.UUID, locations []uuid.UUID) error {
	loc, at, _ := earliestExpiry(locations, c.currentNotAfter)
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "deployment.canary_skipped", ObjectType: "certificate",
		ObjectID: certificate.String(), Result: audit.Success, Details: map[string]string{"certificate_id": certificate.String(), "reason": CanarySkipExpiry,
			"location_id": loc.String(), "not_after": at.UTC().Format(time.RFC3339), "policy_version": strconv.Itoa(c.version),
			"location_ids": joinIDs(locations)}})
	return err
}

// stopAutomaticSource sets the stop mark of the automatic deployment a failed or aborted rollout belongs to (design
// §12), in tx: an ACME rollout stops its ACME certificate's current certificate, a Key Vault rollout its binding's
// version; a person's rollout stops every ACME certificate whose current certificate it deployed with a binding at one of
// its locations, and every Key Vault binding with one of its locations whose current version's leaf it deployed (the
// planner would otherwise roll the same certificate out again within the hour). The planners' existing audit rows and
// notices go with each mark, once; the error reason is the revert reason.
func (s *Service) stopAutomaticSource(ctx context.Context, tx pgx.Tx, r Rollout, reason string, _ audit.Actor) error {
	locations := append(slices.Clone(r.Wave1), r.Wave2...)
	var acme []uuid.UUID
	switch {
	case r.Origin == RolloutOriginACME && r.ACMECertificateID != nil:
		acme = []uuid.UUID{*r.ACMECertificateID}
	case r.Origin == RolloutOriginManual:
		rows, err := tx.Query(ctx, `SELECT DISTINCT c.id FROM acme_certificates c JOIN acme_bindings b ON b.acme_certificate_id = c.id
WHERE c.deleted_at IS NULL AND c.current_certificate_id = $1 AND b.location_id = ANY($2) ORDER BY c.id`, r.CertificateID, locations)
		if err != nil {
			return fmt.Errorf("inventory: read the ACME certificates to stop: %w", err)
		}
		if acme, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
			return fmt.Errorf("inventory: read the ACME certificates to stop: %w", err)
		}
	}
	for _, id := range acme {
		var names []string
		if err := tx.QueryRow(ctx, "SELECT names FROM acme_certificates WHERE id = $1", id).Scan(&names); err != nil {
			return fmt.Errorf("inventory: read the ACME certificate: %w", err)
		}
		if _, err := s.stopACMEDeploy(ctx, tx, id, r.CertificateID, names, len(r.Wave1), reason); err != nil {
			return err
		}
	}
	type kvStop struct {
		binding, vault, kvCert uuid.UUID
		version                string
	}
	var kv []kvStop
	query := `SELECT b.id, b.kv_target_id, b.kv_certificate_id, v.version FROM bindings b
JOIN kv_certificates kc ON kc.id = b.kv_certificate_id
JOIN kv_certificate_versions v ON v.kv_certificate_id = kc.id AND v.version = kc.current_version
WHERE b.deleted_at IS NULL AND v.certificate_id = $1 AND EXISTS (SELECT 1 FROM certificate_locations l WHERE l.binding_id = b.id AND l.id = ANY($2))
ORDER BY b.id`
	args := []any{r.CertificateID, locations}
	switch {
	case r.Origin == RolloutOriginKeyVault && r.BindingID != nil && r.KVVersionID != nil:
		query = `SELECT b.id, b.kv_target_id, b.kv_certificate_id, v.version FROM bindings b JOIN kv_certificate_versions v ON v.id = $2
WHERE b.id = $1 AND b.deleted_at IS NULL`
		args = []any{*r.BindingID, *r.KVVersionID}
	case r.Origin != RolloutOriginManual:
		return nil
	}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("inventory: read the bindings to stop: %w", err)
	}
	kv, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (kvStop, error) {
		var k kvStop
		return k, row.Scan(&k.binding, &k.vault, &k.kvCert, &k.version)
	})
	if err != nil {
		return fmt.Errorf("inventory: read the bindings to stop: %w", err)
	}
	for _, k := range kv {
		tag, err := tx.Exec(ctx, "UPDATE bindings SET stopped_version = $2, version = version + 1 WHERE id = $1 AND stopped_version <> $2", k.binding, k.version)
		if err != nil {
			return fmt.Errorf("inventory: stop the wave: %w", err)
		}
		if tag.RowsAffected() != 1 {
			continue
		}
		var vaultName, certName, vaultURL string
		if err := tx.QueryRow(ctx, `SELECT t.name::text, coalesce(t.config->>'vault_url', ''), kc.name FROM targets t, kv_certificates kc
WHERE t.id = $1 AND kc.id = $2`, k.vault, k.kvCert).Scan(&vaultName, &vaultURL, &certName); err != nil {
			return fmt.Errorf("inventory: read the vault: %w", err)
		}
		if s.notifier != nil {
			if err := s.notifyTarget(ctx, tx, k.vault, TemplateKVAutoDeployStopped, map[string]string{"target_name": vaultName,
				"certificate_name": certName, "count": strconv.Itoa(len(r.Wave1)), "error_reason": reason}); err != nil {
				return fmt.Errorf("inventory: queue the stop notice: %w", err)
			}
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.auto_deploy.stopped", ObjectType: "binding",
			ObjectID: k.binding.String(), Result: audit.Success, Details: map[string]string{"binding_id": k.binding.String(),
				"kv_certificate_id": k.kvCert.String(), "certificate_name": certName, "version": k.version, "failed_count": strconv.Itoa(len(r.Wave1)),
				"vault_url": vaultURL, "error_code": reason, "rollout_id": r.ID.String()}}); err != nil {
			return err
		}
	}
	return nil
}
