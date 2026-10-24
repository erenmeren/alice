package inventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/acme"
	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
)

// The incident engine and the actions of a person on an incident (see incidents.go).

// AdvanceIncidents advances every open incident once, oldest first (at most incidentAdvanceBatch); it is the periodic
// incident.advance task. It returns how many incidents changed. An incident another process advances is skipped (row
// lock); the errors of single incidents are joined and the others still advance. While the licence gate refuses
// changes, nothing is requested of a server or a CA: deployments and orders already running are still followed.
func (s *Service) AdvanceIncidents(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM certificate_incidents WHERE finished_at IS NULL ORDER BY created_at, id LIMIT $1`, incidentAdvanceBatch)
	if err != nil {
		return 0, fmt.Errorf("inventory: list open incidents: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, fmt.Errorf("inventory: list open incidents: %w", err)
	}
	changed := 0
	var errs []error
	for _, id := range ids {
		if ctx.Err() != nil {
			return changed, ctx.Err()
		}
		ok, err := s.AdvanceIncident(ctx, id)
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			changed++
		}
	}
	return changed, errors.Join(errs...)
}

// AdvanceIncident advances one incident as far as it can go now and reports whether it changed.
func (s *Service) AdvanceIncident(ctx context.Context, id uuid.UUID) (bool, error) {
	changed := false
	for range 4 { // a few steps in one run (ordering -> deploying -> revoking -> completed), each its own transaction
		i, err := getIncident(ctx, s.pool, id)
		if err != nil {
			return changed, err
		}
		if i.FinishedAt != nil {
			return changed, nil
		}
		step, err := s.incidentStep(ctx, i)
		if err != nil {
			return changed, err
		}
		if !step {
			return changed, nil
		}
		changed = true
	}
	return changed, nil
}

// incidentStep runs what the incident's state calls for and reports whether anything changed.
func (s *Service) incidentStep(ctx context.Context, i Incident) (bool, error) {
	revoked := false
	if i.RevokeMode == IncidentRevokeNow && i.Revocation == IncidentRevocationPending && i.State != IncidentRevoking {
		var err error
		if revoked, err = s.incidentRevoke(ctx, i); err != nil {
			return false, err
		}
		if revoked {
			return true, nil
		}
	}
	switch i.State {
	case IncidentOrdering:
		return s.incidentOrdering(ctx, i)
	case IncidentDeploying:
		return s.incidentDeploying(ctx, i)
	case IncidentRevoking:
		return s.incidentRevoke(ctx, i)
	}
	return false, nil // awaiting_replacement and needs_attention wait for a person
}

// incidentUpdate changes an open incident's row (state and the given columns) in tx, and returns false when the row was
// finished or moved meanwhile (the expected state no longer holds).
func incidentUpdate(ctx context.Context, tx pgx.Tx, id uuid.UUID, from string, set string, args ...any) (bool, error) {
	all := append([]any{id, from}, args...)
	tag, err := tx.Exec(ctx, "UPDATE certificate_incidents SET "+set+" WHERE id = $1 AND state = $2 AND finished_at IS NULL", all...)
	if err != nil {
		return false, fmt.Errorf("inventory: update the incident: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// incidentAudit appends an audit row of the incident engine.
func (s *Service) incidentAudit(ctx context.Context, tx pgx.Tx, a audit.Actor, action string, id uuid.UUID, result audit.Result,
	details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	details["incident_id"] = id.String()
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: action, ObjectType: "certificate_incident", ObjectID: id.String(),
		Result: result, Details: details})
	return err
}

// attention puts the incident in needs_attention with code (audited incident.needs_attention).
func (s *Service) attention(ctx context.Context, i Incident, code string) (bool, error) {
	var moved bool
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		moved, err = incidentUpdate(ctx, tx, i.ID, i.State, "state = 'needs_attention', attention_code = $3, updated_at = $4", code, s.clock.Now().UTC())
		if err != nil || !moved {
			return err
		}
		return s.incidentAudit(ctx, tx, incidentActor, "incident.needs_attention", i.ID, audit.Failure,
			map[string]string{"reason": code, "previous_state": i.State})
	})
	return moved, err
}

// incidentOrdering follows the order of the replacement (see the file comment of incidents.go).
func (s *Service) incidentOrdering(ctx context.Context, i Incident) (bool, error) {
	if i.ACMECertificateID == nil {
		return false, nil
	}
	if adopted, err := s.adoptNewerVersion(ctx, i); adopted || err != nil {
		return adopted, err
	}
	switch {
	case i.OrderID == nil:
		if s.license.Allow(license.ClassChange) != nil {
			return false, nil
		}
		var started bool
		err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
			if err := s.startIncidentOrder(ctx, tx, Actor{Audit: incidentActor}, i.ID, *i.ACMECertificateID); err != nil {
				return err
			}
			var order *uuid.UUID
			if err := tx.QueryRow(ctx, "SELECT order_id FROM certificate_incidents WHERE id = $1", i.ID).Scan(&order); err != nil {
				return fmt.Errorf("inventory: read the incident's order: %w", err)
			}
			started = order != nil
			return nil
		})
		switch {
		case errors.Is(err, ErrACMEAccountState), errors.Is(err, ErrACMERolloverPending), errors.Is(err, ErrNotFound):
			return s.attention(ctx, i, IncidentRefusalCode(err))
		case err != nil:
			return false, err
		}
		return started, nil
	case i.OrderState == ACMEOrderRunning:
		return false, nil
	case i.OrderState == ACMEOrderFailed:
		code := i.OrderErrorCode
		if code == "" {
			code = "acme.order_abandoned"
		}
		return s.attention(ctx, i, code)
	}
	// Succeeded: the issued certificate is the replacement.
	var cert *uuid.UUID
	if err := s.pool.QueryRow(ctx, "SELECT certificate_id FROM acme_orders WHERE id = $1", *i.OrderID).Scan(&cert); err != nil {
		return false, fmt.Errorf("inventory: read the incident's order: %w", err)
	}
	if cert == nil {
		return s.attention(ctx, i, "acme.order_abandoned")
	}
	return s.setReplacement(ctx, i, *cert, incidentActor)
}

// adoptNewerVersion takes the ACME certificate's current certificate as the replacement when it was issued after the
// incident began with another key (the renewal planner ordered it first, or the incident's order succeeded): reported
// true when it did.
func (s *Service) adoptNewerVersion(ctx context.Context, i Incident) (bool, error) {
	var cur uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT x.id FROM acme_certificates a JOIN certificates x ON x.id = a.current_certificate_id
WHERE a.id = $1 AND x.public_key_sha256 <> $2 AND x.revoked_at IS NULL AND x.compromised_at IS NULL AND x.created_at >= $3`,
		*i.ACMECertificateID, i.PublicKeySHA256, i.CreatedAt).Scan(&cur)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inventory: read the ACME certificate's current certificate: %w", err)
	}
	return s.setReplacement(ctx, i, cur, incidentActor)
}

// replacementRefusal is why a certificate cannot replace the incident's ("" when it can).
func replacementRefusal(ctx context.Context, q db.Querier, i Incident, cert uuid.UUID, now time.Time) (string, error) {
	var (
		key                  string
		hasKey, kv           bool
		notBefore, notAfter  time.Time
		revoked, compromised bool
	)
	err := q.QueryRow(ctx, `SELECT public_key_sha256, private_key_id IS NOT NULL, source = 'azure_kv', not_before, not_after,
    revoked_at IS NOT NULL, compromised_at IS NOT NULL FROM certificates WHERE id = $1`, cert).
		Scan(&key, &hasKey, &kv, &notBefore, &notAfter, &revoked, &compromised)
	if errors.Is(err, pgx.ErrNoRows) {
		return IncidentCodeReplacementGone, nil
	}
	if err != nil {
		return "", fmt.Errorf("inventory: read the replacement: %w", err)
	}
	switch {
	case key == i.PublicKeySHA256:
		return IncidentCodeKeyReused, nil
	case !hasKey || kv || revoked || compromised || !now.Before(notAfter) || now.Before(notBefore):
		return IncidentCodeReplacementGone, nil
	}
	return "", nil
}

// setReplacement records the replacement and moves the incident to deploying (audited incident.replacement_chosen).
func (s *Service) setReplacement(ctx context.Context, i Incident, cert uuid.UUID, a audit.Actor) (bool, error) {
	now := s.clock.Now().UTC()
	code, err := replacementRefusal(ctx, s.pool, i, cert, now)
	if err != nil {
		return false, err
	}
	if code != "" {
		return s.attention(ctx, i, code)
	}
	var moved bool
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		moved, err = incidentUpdate(ctx, tx, i.ID, i.State, `state = 'deploying', attention_code = '', replacement_certificate_id = $3,
    updated_at = $4`, cert, now)
		if err != nil || !moved {
			return err
		}
		return s.incidentAudit(ctx, tx, a, "incident.replacement_chosen", i.ID, audit.Success,
			map[string]string{"certificate_id": cert.String()})
	})
	return moved, err
}

// incidentLocationRow is one location of an incident as the engine reads it.
type incidentLocationRow struct {
	location     uuid.UUID
	status       string
	deployment   *uuid.UUID
	attempts     int
	depState     string
	depStatus    string
	depVerified  string
	depCode      string
	depCert      *uuid.UUID
	activeDep    *uuid.UUID // the unfinished deployment of the location, if any
	activeDepCrt *uuid.UUID
}

// incidentDeploying requests and follows the deployments of the replacement.
func (s *Service) incidentDeploying(ctx context.Context, i Incident) (bool, error) {
	if i.ReplacementCertificateID == nil {
		return false, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT l.location_id, l.status, l.deployment_id, l.attempts, coalesce(d.state, ''), coalesce(d.status, ''),
    coalesce(d.verified, ''), coalesce(d.error_code, ''), d.certificate_id, a.id, a.certificate_id
FROM certificate_incident_locations l
LEFT JOIN deployments d ON d.id = l.deployment_id
LEFT JOIN deployments a ON a.location_id = l.location_id AND a.state <> 'done'
WHERE l.incident_id = $1 ORDER BY l.location_id`, i.ID)
	if err != nil {
		return false, fmt.Errorf("inventory: read the incident's locations: %w", err)
	}
	locs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (incidentLocationRow, error) {
		var l incidentLocationRow
		return l, r.Scan(&l.location, &l.status, &l.deployment, &l.attempts, &l.depState, &l.depStatus, &l.depVerified, &l.depCode, &l.depCert,
			&l.activeDep, &l.activeDepCrt)
	})
	if err != nil {
		return false, fmt.Errorf("inventory: read the incident's locations: %w", err)
	}
	changed := false
	gateOpen := s.license.Allow(license.ClassChange) == nil
	open := 0
	for _, l := range locs {
		switch l.status {
		case IncidentLocationPending:
			open++
			if !gateOpen {
				continue
			}
			c, err := s.requestIncidentDeployment(ctx, i, l)
			if err != nil {
				return changed, err
			}
			changed = changed || c
		case IncidentLocationDeploying:
			open++
			c, err := s.followIncidentDeployment(ctx, i, l)
			if err != nil {
				return changed, err
			}
			changed = changed || c
		}
	}
	if changed || open > 0 {
		return changed, nil
	}
	// Every location is settled.
	counts := map[string]int{}
	for _, l := range locs {
		counts[l.status]++
	}
	switch {
	case counts[IncidentLocationFailed] > 0:
		return s.attention(ctx, i, IncidentCodeDeploymentsFailed)
	case counts[IncidentLocationUnverified] > 0 && i.Revocation == IncidentRevocationPending:
		return s.attention(ctx, i, IncidentCodeUnverified)
	case i.Revocation == IncidentRevocationPending:
		return s.moveIncident(ctx, i, IncidentRevoking, "incident.deployed", nil)
	}
	return s.complete(ctx, i)
}

// moveIncident moves the incident from its state to next (audited action).
func (s *Service) moveIncident(ctx context.Context, i Incident, next, action string, details map[string]string) (bool, error) {
	var moved bool
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		moved, err = incidentUpdate(ctx, tx, i.ID, i.State, "state = $3, attention_code = '', updated_at = $4", next, s.clock.Now().UTC())
		if err != nil || !moved || action == "" {
			return err
		}
		return s.incidentAudit(ctx, tx, incidentActor, action, i.ID, audit.Success, details)
	})
	return moved, err
}

// complete finishes the incident as completed (audited incident.completed).
func (s *Service) complete(ctx context.Context, i Incident) (bool, error) {
	var moved bool
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.clock.Now().UTC()
		var err error
		moved, err = incidentUpdate(ctx, tx, i.ID, i.State, "state = 'completed', attention_code = '', updated_at = $3, finished_at = $3", now)
		if err != nil || !moved {
			return err
		}
		return s.incidentAudit(ctx, tx, incidentActor, "incident.completed", i.ID, audit.Success,
			map[string]string{"revocation": i.Revocation})
	})
	return moved, err
}

// setLocation changes one location of an open incident. A place that settles (any final state: verified, unverified,
// failed) queues, in the same transaction, the certificate cleanup of its server when it is a Windows binding
// (queueIncidentCleanupTx; R62 W3 Ruling 9, §15 Q7): the compromised certificate leaves the machine store at once
// instead of with the daily run, and the last place to settle has a job that sees every place of the server settled.
func (s *Service) setLocation(ctx context.Context, incident, location uuid.UUID, from, status string, deployment *uuid.UUID, code string,
	attempts int) (bool, error) {
	now := s.clock.Now().UTC()
	if !incidentPlaceFinal(status) {
		return setLocationIn(ctx, s.pool, now, incident, location, from, status, deployment, code, attempts)
	}
	var moved bool
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		if moved, err = setLocationIn(ctx, tx, now, incident, location, from, status, deployment, code, attempts); err != nil || !moved {
			return err
		}
		return s.queueIncidentCleanupTx(ctx, tx, incident, location)
	})
	return moved, err
}

// incidentPlaceFinal reports whether an incident place in status has settled: every status but pending and deploying.
func incidentPlaceFinal(status string) bool {
	return status != IncidentLocationPending && status != IncidentLocationDeploying
}

// setLocationIn is setLocation through q (the pool, or a transaction that does more with the change) at now.
func setLocationIn(ctx context.Context, q db.Querier, now time.Time, incident, location uuid.UUID, from, status string, deployment *uuid.UUID,
	code string, attempts int) (bool, error) {
	tag, err := q.Exec(ctx, `UPDATE certificate_incident_locations SET status = $4, deployment_id = coalesce($5, deployment_id), error_code = $6,
    attempts = $7, updated_at = $8 WHERE incident_id = $1 AND location_id = $2 AND status = $3`,
		incident, location, from, status, deployment, code, attempts, now)
	if err != nil {
		return false, fmt.Errorf("inventory: update the incident's location: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// requestIncidentDeployment requests the replacement's deployment to one pending location (RequestDeployment: the
// person's path, with the incident engine as the actor; no incomplete chain is ever confirmed). A deployment of the
// replacement already running there (the ACME automatic deployment) is followed instead; a busy location waits a few
// runs; any other refusal fails the location with its code.
func (s *Service) requestIncidentDeployment(ctx context.Context, i Incident, l incidentLocationRow) (bool, error) {
	if l.activeDep != nil && l.activeDepCrt != nil && *l.activeDepCrt == *i.ReplacementCertificateID {
		return s.setLocation(ctx, i.ID, l.location, IncidentLocationPending, IncidentLocationDeploying, l.activeDep, "", l.attempts)
	}
	// An incident replaces a key that is already there: no trust is needed (R49, design §5.6).
	got, err := s.RequestDeployment(ctx, Actor{Audit: incidentActor}, DeployRequestInput{CertificateID: *i.ReplacementCertificateID,
		LocationIDs: []uuid.UUID{l.location}, incident: true})
	switch {
	case err == nil:
		return s.setLocation(ctx, i.ID, l.location, IncidentLocationPending, IncidentLocationDeploying, &got[0].ID, "", l.attempts+1)
	case license.DenialReason(err) != "":
		return false, nil // the gate closed meanwhile: the next run
	case errors.Is(err, ErrDeploymentInProgress), errors.Is(err, ErrRecoveryPending), errors.Is(err, ErrTargetNotReady):
		if l.attempts+1 >= incidentBusyAttempts {
			return s.setLocation(ctx, i.ID, l.location, IncidentLocationPending, IncidentLocationFailed, nil, IncidentCodeLocationBusy, l.attempts+1)
		}
		return s.setLocation(ctx, i.ID, l.location, IncidentLocationPending, IncidentLocationPending, nil, "", l.attempts+1)
	}
	if !IsIncidentRefusal(err) {
		return false, err
	}
	return s.setLocation(ctx, i.ID, l.location, IncidentLocationPending, IncidentLocationFailed, nil, IncidentRefusalCode(err), l.attempts+1)
}

// followIncidentDeployment settles a location whose deployment ended (setLocation queues a Windows server's cleanup).
func (s *Service) followIncidentDeployment(ctx context.Context, i Incident, l incidentLocationRow) (bool, error) {
	if l.depState != DeployStateDone {
		return false, nil
	}
	switch l.depStatus {
	case DeployStatusSucceeded, DeployStatusUnchanged:
		status := IncidentLocationVerified
		if l.depVerified != "remote" && l.depVerified != "local" {
			status = IncidentLocationUnverified
		}
		return s.setLocation(ctx, i.ID, l.location, IncidentLocationDeploying, status, nil, "", l.attempts)
	}
	code := l.depCode
	if code == "" {
		code = "deployment." + l.depStatus
	}
	return s.setLocation(ctx, i.ID, l.location, IncidentLocationDeploying, IncidentLocationFailed, nil, code, l.attempts)
}

// incidentRevoke revokes the ACME versions with the compromised key (reason keyCompromise). It reports a change when it
// revoked them all (or moved the incident on a failure).
func (s *Service) incidentRevoke(ctx context.Context, i Incident) (bool, error) {
	if i.ACMECertificateID == nil || i.Revocation != IncidentRevocationPending {
		return false, nil
	}
	now := s.clock.Now().UTC()
	if i.NextAttemptAt != nil && now.Before(*i.NextAttemptAt) {
		return false, nil
	}
	if s.license.Allow(license.ClassChange) != nil {
		return false, nil
	}
	versions, err := acmeVersionsWithKey(ctx, s.pool, *i.ACMECertificateID, i.PublicKeySHA256, now)
	if err != nil {
		return false, err
	}
	reason := acme.RevokeKeyCompromise.String()
	for _, v := range versions {
		t, err := readRevocationTarget(ctx, s.pool, *i.ACMECertificateID, &v)
		if err != nil {
			return false, err
		}
		if err := s.revokeAtCA(ctx, t, acme.RevokeKeyCompromise); err != nil {
			return s.revokeFailed(ctx, i, err)
		}
		err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
			marked, err := markRevokedTx(ctx, tx, v, reason, i.StartedBy, s.clock.Now().UTC())
			if err != nil || !marked {
				return err
			}
			d := revocationDetails(t, reason)
			d["incident_id"] = i.ID.String()
			_, err = s.audit.Append(ctx, tx, audit.Event{Actor: incidentActor, Action: "acme.certificate.revoked", ObjectType: "acme_certificate",
				ObjectID: t.acmeCertID.String(), Result: audit.Success, Details: d})
			return err
		})
		if err != nil {
			return false, err
		}
	}
	var moved bool
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		at := s.clock.Now().UTC()
		tag, err := tx.Exec(ctx, `UPDATE certificate_incidents SET revocation = 'revoked', revoked_at = $2, next_attempt_at = NULL, updated_at = $2
WHERE id = $1 AND revocation = 'pending' AND finished_at IS NULL`, i.ID, at)
		if err != nil {
			return fmt.Errorf("inventory: record the incident's revocation: %w", err)
		}
		if moved = tag.RowsAffected() == 1; !moved {
			return nil
		}
		if err := s.incidentAudit(ctx, tx, incidentActor, "incident.revoked", i.ID, audit.Success,
			map[string]string{"versions": strconv.Itoa(len(versions)), "revoke_mode": i.RevokeMode}); err != nil {
			return err
		}
		if i.State == IncidentRevoking {
			_, err = incidentUpdate(ctx, tx, i.ID, IncidentRevoking, "state = 'completed', updated_at = $3, finished_at = $3", at)
			if err != nil {
				return err
			}
			return s.incidentAudit(ctx, tx, incidentActor, "incident.completed", i.ID, audit.Success, map[string]string{"revocation": "revoked"})
		}
		return nil
	})
	return moved, err
}

// revokeFailed records a failed revocation: a CA outage is tried again (1, 2, 4 ... minutes, at most an hour) up to
// incidentRevokeAttempts times, then (and at once for any other failure) the incident needs attention.
func (s *Service) revokeFailed(ctx context.Context, i Incident, cause error) (bool, error) {
	code := revokeErrorCode(cause)
	attempts := i.RevokeAttempts + 1
	transient := acme.FailureClass(cause) == acme.ClassTransient
	if transient && attempts < incidentRevokeAttempts {
		wait := min(incidentRevokeBackoff<<min(attempts-1, 10), incidentRevokeMaxWait)
		var ae *ACMEError
		if errors.As(cause, &ae) && ae.RetryAfter > wait {
			wait = min(ae.RetryAfter, incidentRevokeMaxWait)
		}
		_, err := s.pool.Exec(ctx, `UPDATE certificate_incidents SET revoke_attempts = $2, next_attempt_at = $3, updated_at = $4
WHERE id = $1 AND finished_at IS NULL`, i.ID, attempts, s.clock.Now().UTC().Add(wait), s.clock.Now().UTC())
		if err != nil {
			return false, fmt.Errorf("inventory: record the incident's revocation attempt: %w", err)
		}
		return false, nil
	}
	var moved bool
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.clock.Now().UTC()
		tag, err := tx.Exec(ctx, `UPDATE certificate_incidents SET revocation = 'failed', revoke_attempts = $2, next_attempt_at = NULL,
    state = 'needs_attention', attention_code = $3, updated_at = $4 WHERE id = $1 AND finished_at IS NULL`, i.ID, attempts, code, now)
		if err != nil {
			return fmt.Errorf("inventory: record the failed revocation: %w", err)
		}
		if moved = tag.RowsAffected() == 1; !moved {
			return nil
		}
		return s.incidentAudit(ctx, tx, incidentActor, "incident.revoke_failed", i.ID, audit.Failure,
			map[string]string{"reason": code, "attempts": strconv.Itoa(attempts)})
	})
	return moved, err
}

// The actions of a person (an Administrator with a fresh step-up: the API's certificates.incident).

// RetryIncident takes an incident out of needs_attention: a failed order is ordered again, failed locations are
// requested again, a failed revocation is tried again (audited incident.retried). ErrIncidentState otherwise. The
// advance task does the work.
func (s *Service) RetryIncident(ctx context.Context, a Actor, id uuid.UUID) (Incident, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Incident{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		i, err := getIncident(ctx, tx, id)
		if err != nil {
			return err
		}
		if i.State != IncidentNeedsAttention {
			return ErrIncidentState
		}
		now := s.clock.Now().UTC()
		next := IncidentDeploying
		order := i.OrderID
		switch {
		case i.ReplacementCertificateID == nil && i.ACMECertificateID != nil:
			next, order = IncidentOrdering, nil
		case i.ReplacementCertificateID == nil:
			next = IncidentAwaitingReplacement
		}
		revocation := i.Revocation
		if revocation == IncidentRevocationFailed {
			revocation = IncidentRevocationPending
		}
		if _, err := incidentUpdate(ctx, tx, id, IncidentNeedsAttention, `state = $3, attention_code = '', order_id = $4, revocation = $5,
    revoke_attempts = 0, next_attempt_at = NULL, updated_at = $6`, next, order, revocation, now); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE certificate_incident_locations SET status = 'pending', error_code = '', attempts = 0, updated_at = $2
WHERE incident_id = $1 AND status = 'failed'`, id, now)
		if err != nil {
			return fmt.Errorf("inventory: retry the failed locations: %w", err)
		}
		return s.incidentAudit(ctx, tx, a.Audit, "incident.retried", id, audit.Success, map[string]string{"previous_reason": i.AttentionCode,
			"locations_retried": strconv.FormatInt(tag.RowsAffected(), 10), "next_state": next})
	})
	if err != nil {
		return Incident{}, err
	}
	return s.GetIncident(ctx, id)
}

// RevokeIncidentNow is "revoke now regardless": the compromised ACME versions are revoked at the next run, whatever the
// deployments' state (audited incident.revoke_now). ErrIncidentNotRevocable for another source; ErrIncidentState when
// the incident is finished or the revocation is no longer pending or failed.
func (s *Service) RevokeIncidentNow(ctx context.Context, a Actor, id uuid.UUID) (Incident, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Incident{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		i, err := getIncident(ctx, tx, id)
		if err != nil {
			return err
		}
		switch {
		case i.FinishedAt != nil:
			return ErrIncidentState
		case i.ACMECertificateID == nil:
			return ErrIncidentNotRevocable
		case i.Revocation != IncidentRevocationPending && i.Revocation != IncidentRevocationFailed:
			return ErrIncidentState
		}
		state := i.State
		code := i.AttentionCode
		if i.State == IncidentNeedsAttention && (i.AttentionCode == IncidentCodeUnverified || i.Revocation == IncidentRevocationFailed) {
			// The person accepts the unverified locations, or tries the refused revocation again: revoke now.
			state, code = IncidentRevoking, ""
		}
		if _, err := incidentUpdate(ctx, tx, id, i.State, `revoke_mode = 'now', revocation = 'pending', revoke_attempts = 0, next_attempt_at = NULL,
    state = $3, attention_code = $4, updated_at = $5`, state, code, s.clock.Now().UTC()); err != nil {
			return err
		}
		return s.incidentAudit(ctx, tx, a.Audit, "incident.revoke_now", id, audit.Success, map[string]string{"state": i.State})
	})
	if err != nil {
		return Incident{}, err
	}
	return s.GetIncident(ctx, id)
}

// ChooseIncidentReplacement sets the replacement of an incident of another source (awaiting_replacement, or
// needs_attention without a usable replacement): a certificate Alice holds the key of, with another key, neither
// revoked nor compromised, valid now (ErrIncidentReplacement otherwise). Audited incident.replacement_chosen.
func (s *Service) ChooseIncidentReplacement(ctx context.Context, a Actor, id, certificateID uuid.UUID) (Incident, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Incident{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		i, err := getIncident(ctx, tx, id)
		if err != nil {
			return err
		}
		if i.ACMECertificateID != nil || (i.State != IncidentAwaitingReplacement && i.State != IncidentNeedsAttention) || i.FinishedAt != nil {
			return ErrIncidentState
		}
		now := s.clock.Now().UTC()
		code, err := replacementRefusal(ctx, tx, i, certificateID, now)
		if err != nil {
			return err
		}
		if code != "" || certificateID == i.CertificateID {
			return ErrIncidentReplacement
		}
		if _, err := incidentUpdate(ctx, tx, id, i.State, `state = 'deploying', attention_code = '', replacement_certificate_id = $3, updated_at = $4`,
			certificateID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE certificate_incident_locations SET status = 'pending', error_code = '', attempts = 0, updated_at = $2
WHERE incident_id = $1 AND status = 'failed'`, id, now); err != nil {
			return fmt.Errorf("inventory: retry the failed locations: %w", err)
		}
		return s.incidentAudit(ctx, tx, a.Audit, "incident.replacement_chosen", id, audit.Success,
			map[string]string{"certificate_id": certificateID.String()})
	})
	if err != nil {
		return Incident{}, err
	}
	return s.GetIncident(ctx, id)
}

// CloseIncident finishes an open incident as it stands (closed; audited incident.closed). Deployments it requested go on;
// nothing is revoked any more. ErrIncidentState for a finished incident. It changes nothing on a server or a CA, so it
// needs no licence.
func (s *Service) CloseIncident(ctx context.Context, a Actor, id uuid.UUID) (Incident, error) {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		i, err := getIncident(ctx, tx, id)
		if err != nil {
			return err
		}
		if i.FinishedAt != nil {
			return ErrIncidentState
		}
		now := s.clock.Now().UTC()
		moved, err := incidentUpdate(ctx, tx, id, i.State, "state = 'closed', closed_by = $3, updated_at = $4, finished_at = $4",
			nullableUser(a.UserID), now)
		if err != nil {
			return err
		}
		if !moved {
			return ErrIncidentState
		}
		return s.incidentAudit(ctx, tx, a.Audit, "incident.closed", id, audit.Success, map[string]string{"state": i.State,
			"revocation": i.Revocation})
	})
	if err != nil {
		return Incident{}, err
	}
	return s.GetIncident(ctx, id)
}

// IsIncidentRefusal reports a refusal of RequestDeployment that belongs to the location or the certificate (a code is kept on
// the location), as opposed to a failure of the database.
func IsIncidentRefusal(err error) bool {
	var lr *LocationRefusalError
	var km *KeyTypeMismatchError
	return errors.As(err, &lr) || errors.As(err, &km) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrLocationUnsupported) ||
		errors.Is(err, ErrNginxConfigInvalid) || errors.Is(err, ErrLocationNeedsDiscovery) || errors.Is(err, ErrChainUnconfirmed) ||
		errors.Is(err, ErrCertificateExpired) || errors.Is(err, ErrCertificateNotYetValid) || errors.Is(err, ErrNoPrivateKey) ||
		errors.Is(err, ErrUnsupportedKey) || errors.Is(err, ErrCertificateRevoked) || errors.Is(err, ErrCertificateCompromised) ||
		errors.Is(err, ErrTargetDisabled)
}

// IncidentRefusalCode is the closed code of an inventory refusal (the API's reason of the same error; locked against the
// API catalogue by internal/api:TestIncidentRefusalCodesMatchTheCatalogue, R64).
func IncidentRefusalCode(err error) string {
	var km *KeyTypeMismatchError
	switch {
	case errors.As(err, &km):
		return IncidentCodeNotDeployable // the place needs another key type (the stored code has no params to name them)
	case errors.Is(err, ErrLocationUnsupported):
		return "nginx.location_unsupported"
	case errors.Is(err, ErrNginxConfigInvalid):
		return "nginx.config_invalid"
	case errors.Is(err, ErrLocationNeedsDiscovery):
		return "deployment.rescan_needed"
	case errors.Is(err, ErrChainUnconfirmed):
		return "certificate.chain_unconfirmed"
	case errors.Is(err, ErrCertificateExpired):
		return "certificate.expired"
	case errors.Is(err, ErrCertificateNotYetValid):
		return "certificate.not_yet_valid"
	case errors.Is(err, ErrNoPrivateKey):
		return "certificate.no_private_key"
	case errors.Is(err, ErrUnsupportedKey):
		return "certificate.unsupported_key"
	case errors.Is(err, ErrCertificateRevoked):
		return ReasonCertificateRevoked
	case errors.Is(err, ErrCertificateCompromised):
		return ReasonCertificateCompromised
	case errors.Is(err, ErrTargetDisabled):
		return "target.disabled"
	case errors.Is(err, ErrTargetNotReady):
		return "deployment.target_not_ready"
	case errors.Is(err, ErrACMEAccountState):
		return "acme.account_state"
	case errors.Is(err, ErrACMERolloverPending):
		return "acme.rollover_pending"
	case errors.Is(err, ErrNotFound):
		return "system.not_found"
	}
	return "internal.unexpected"
}
