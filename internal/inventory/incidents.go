package inventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// Key-compromise incidents (owner decision 2026-10-20, docs/superpowers/rulings/certificate-revocation.md): "this
// private key leaked — which servers are affected, and how do I replace them all safely?"
//
// An Administrator (fresh step-up) starts an incident for a certificate of any source. In the starting transaction every
// certificate with the same key is marked compromised (final: none of them is ever deployed again), the affected
// certificate files on managed servers become the incident's locations (pending: Alice replaces them; skipped, with the
// reason: another certificate made with the same key, a file that follows a Key Vault certificate or another ACME
// certificate, a file Alice cannot deploy to), and for a certificate Alice ordered over ACME a new order of its ACME
// certificate starts (every order generates a new key, so the compromised key is never reused).
//
// The incident advances in the periodic incident.advance task (AdvanceIncidents), so it survives restarts: its state is
// the record. ordering waits for the order (adopting a newer certificate of the ACME certificate with another key if
// the renewal planner got one first); deploying requests one deployment per pending location through RequestDeployment
// (the deployment engine: journals, verification, rollback) and follows it to verified, unverified (deployed, the
// verification was skipped) or failed; revoking asks the CA to revoke every unexpired ACME version with the
// compromised key (reason keyCompromise) once every location is verified, or at once when a person chose "revoke now
// regardless". A failure puts the incident in needs_attention with its code; a person retries, revokes regardless,
// chooses the replacement (another source) or closes the incident. A certificate from another source is never revoked
// by Alice (revocation not_possible): its incident waits for a person to choose the replacement (awaiting_replacement)
// and says that the issuing CA must revoke it.

// Incident states (certificate_incidents.state).
const (
	IncidentAwaitingReplacement = "awaiting_replacement"
	IncidentOrdering            = "ordering"
	IncidentDeploying           = "deploying"
	IncidentRevoking            = "revoking"
	IncidentNeedsAttention      = "needs_attention"
	IncidentCompleted           = "completed"
	IncidentClosed              = "closed"
)

// Revocation states of an incident (certificate_incidents.revocation) and its modes (revoke_mode).
const (
	IncidentRevocationPending     = "pending"
	IncidentRevocationRevoked     = "revoked"
	IncidentRevocationFailed      = "failed"
	IncidentRevocationNotPossible = "not_possible"

	IncidentRevokeAfterVerified = "after_verified"
	IncidentRevokeNow           = "now"
)

// Location states of an incident (certificate_incident_locations.status).
const (
	IncidentLocationPending    = "pending"
	IncidentLocationDeploying  = "deploying"
	IncidentLocationVerified   = "verified"
	IncidentLocationUnverified = "unverified"
	IncidentLocationFailed     = "failed"
	IncidentLocationSkipped    = "skipped"
)

// Closed codes of an incident (attention_code, a location's error_code). The codes of a failed deployment, an order or
// a revocation are their own closed reasons.
const (
	IncidentCodeOtherCertificate  = "incident.other_certificate"
	IncidentCodeNotDeployable     = "incident.not_deployable"
	IncidentCodeFollowsKeyVault   = "incident.follows_key_vault"
	IncidentCodeFollowsOtherACME  = "incident.follows_other_acme"
	IncidentCodeLocationBusy      = "incident.location_busy"
	IncidentCodeDeploymentsFailed = "incident.deployments_failed"
	IncidentCodeUnverified        = "incident.deployments_unverified"
	IncidentCodeKeyReused         = "incident.key_reused"
	IncidentCodeReplacementGone   = "incident.replacement_unusable"
)

// IncidentCodes lists the incident's own closed codes (the API registers each).
func IncidentCodes() []string {
	return []string{IncidentCodeOtherCertificate, IncidentCodeNotDeployable, IncidentCodeFollowsKeyVault, IncidentCodeFollowsOtherACME,
		IncidentCodeLocationBusy, IncidentCodeDeploymentsFailed, IncidentCodeUnverified, IncidentCodeKeyReused, IncidentCodeReplacementGone}
}

// JobIncidentAdvance is the periodic task that advances open incidents (jobs registers it).
const JobIncidentAdvance = "incident.advance"

// Refusals of the incident actions.
var (
	// ErrIncidentOpen: the certificate has an open incident already.
	ErrIncidentOpen = errors.New("inventory: the certificate has an open incident")
	// ErrIncidentState: the action does not apply to the incident in its state (or the incident is finished).
	ErrIncidentState = errors.New("inventory: the incident is not in a state that allows this")
	// ErrIncidentReplacement: the chosen replacement cannot replace the certificate (the same key, no private key,
	// revoked, compromised, expired or not yet valid).
	ErrIncidentReplacement = errors.New("inventory: the certificate cannot replace the compromised one")
	// ErrIncidentNotRevocable: Alice cannot revoke this certificate at its CA (not ordered over ACME).
	ErrIncidentNotRevocable = errors.New("inventory: Alice cannot revoke this certificate at its certificate authority")
)

// Pacing of the advance task.
const (
	// incidentAdvanceBatch: open incidents advanced per run (oldest first).
	incidentAdvanceBatch = 50
	// incidentBusyAttempts: requests of a location that is busy (an unfinished deployment of another certificate, a
	// recovery on its server, a server not ready) before it fails with IncidentCodeLocationBusy.
	incidentBusyAttempts = 30
	// incidentRevokeAttempts: revocations the CA did not answer (transient) before the incident needs attention.
	incidentRevokeAttempts = 5
	incidentRevokeBackoff  = time.Minute
	incidentRevokeMaxWait  = time.Hour
)

// incidentActor is the audit actor of the incident engine.
var incidentActor = audit.SystemActor("incident")

// Incident is the view of an incident.
type Incident struct {
	ID                       uuid.UUID
	CertificateID            uuid.UUID
	CertificateName          string
	Fingerprint              string
	Source                   string
	PublicKeySHA256          string
	ACMECertificateID        *uuid.UUID
	State                    string
	RevokeMode               string
	Revocation               string
	OrderID                  *uuid.UUID
	OrderState               string // "" without an order
	OrderErrorCode           string
	ReplacementCertificateID *uuid.UUID
	ReplacementFingerprint   string
	AttentionCode            string
	RevokeAttempts           int
	NextAttemptAt            *time.Time
	RevokedAt                *time.Time
	StartedBy                *uuid.UUID
	StartedByName            string
	ClosedBy                 *uuid.UUID
	CreatedAt                time.Time
	UpdatedAt                time.Time
	FinishedAt               *time.Time
	Counts                   map[string]int // locations by status
	Locations                []IncidentLocation
}

// IncidentLocation is one affected location of an incident.
type IncidentLocation struct {
	LocationID   uuid.UUID
	TargetID     uuid.UUID
	TargetName   string
	CertPath     string
	Status       string
	DeploymentID *uuid.UUID
	ErrorCode    string
	Attempts     int
	UpdatedAt    time.Time
	// OutcomeUncertain (R48): the location's deployment was sent but Alice has not confirmed how it ended (its recovery
	// cannot reach the server, or the answer was lost); UncertainCode is why (the deployment's code, "" when none). Such a
	// place is never counted as replaced: it stays deploying until the recovery confirms it or gives up (failed).
	OutcomeUncertain bool
	UncertainCode    string
}

// IncidentInput starts an incident: RevokeMode "" or after_verified (revoke once every location is verified) or now.
type IncidentInput struct {
	RevokeMode string
}

const incidentSelect = `SELECT i.id, i.certificate_id, coalesce(nullif(c.label, ''), nullif(c.subject_cn, ''), left(c.fingerprint_sha256, 16)),
    c.fingerprint_sha256, c.source, i.public_key_sha256, i.acme_certificate_id, i.state, i.revoke_mode, i.revocation, i.order_id,
    coalesce(o.state, ''), coalesce(o.error_code, ''), i.replacement_certificate_id, coalesce(r.fingerprint_sha256, ''), i.attention_code,
    i.revoke_attempts, i.next_attempt_at, i.revoked_at, i.started_by, coalesce(u.display_name, ''), i.closed_by, i.created_at, i.updated_at,
    i.finished_at,
    (SELECT coalesce(jsonb_object_agg(s.status, s.n), '{}') FROM (SELECT status, count(*) AS n FROM certificate_incident_locations
     WHERE incident_id = i.id GROUP BY status) s)
FROM certificate_incidents i
JOIN certificates c ON c.id = i.certificate_id
LEFT JOIN certificates r ON r.id = i.replacement_certificate_id
LEFT JOIN acme_orders o ON o.id = i.order_id
LEFT JOIN users u ON u.id = i.started_by`

func scanIncident(row pgx.Row) (Incident, error) {
	var i Incident
	var counts map[string]int
	err := row.Scan(&i.ID, &i.CertificateID, &i.CertificateName, &i.Fingerprint, &i.Source, &i.PublicKeySHA256, &i.ACMECertificateID, &i.State,
		&i.RevokeMode, &i.Revocation, &i.OrderID, &i.OrderState, &i.OrderErrorCode, &i.ReplacementCertificateID, &i.ReplacementFingerprint,
		&i.AttentionCode, &i.RevokeAttempts, &i.NextAttemptAt, &i.RevokedAt, &i.StartedBy, &i.StartedByName, &i.ClosedBy, &i.CreatedAt,
		&i.UpdatedAt, &i.FinishedAt, &counts)
	if errors.Is(err, pgx.ErrNoRows) {
		return Incident{}, ErrNotFound
	}
	if err != nil {
		return Incident{}, fmt.Errorf("inventory: read the incident: %w", err)
	}
	i.NextAttemptAt, i.RevokedAt, i.FinishedAt = utcPtr(i.NextAttemptAt), utcPtr(i.RevokedAt), utcPtr(i.FinishedAt)
	i.CreatedAt, i.UpdatedAt, i.Counts = i.CreatedAt.UTC(), i.UpdatedAt.UTC(), counts
	if i.Counts == nil {
		i.Counts = map[string]int{}
	}
	return i, nil
}

func getIncident(ctx context.Context, q db.Querier, id uuid.UUID) (Incident, error) {
	return scanIncident(q.QueryRow(ctx, incidentSelect+" WHERE i.id = $1", id))
}

// GetIncident returns an incident with its locations (ErrNotFound).
func (s *Service) GetIncident(ctx context.Context, id uuid.UUID) (Incident, error) {
	i, err := getIncident(ctx, s.pool, id)
	if err != nil {
		return Incident{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT l.location_id, cl.target_id, t.name::text, cl.cert_path, l.status, l.deployment_id, l.error_code, l.attempts,
    l.updated_at, l.status = 'deploying' AND coalesce(d.state, '') = 'recovering', CASE WHEN d.state = 'recovering' THEN d.error_code ELSE '' END
FROM certificate_incident_locations l JOIN certificate_locations cl ON cl.id = l.location_id JOIN targets t ON t.id = cl.target_id
LEFT JOIN deployments d ON d.id = l.deployment_id
WHERE l.incident_id = $1 ORDER BY t.name, cl.cert_path, l.location_id LIMIT $2`, id, MaxImpactRows)
	if err != nil {
		return Incident{}, fmt.Errorf("inventory: read the incident's locations: %w", err)
	}
	i.Locations, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (IncidentLocation, error) {
		var l IncidentLocation
		err := r.Scan(&l.LocationID, &l.TargetID, &l.TargetName, &l.CertPath, &l.Status, &l.DeploymentID, &l.ErrorCode, &l.Attempts, &l.UpdatedAt,
			&l.OutcomeUncertain, &l.UncertainCode)
		l.UpdatedAt = l.UpdatedAt.UTC()
		return l, err
	})
	if err != nil {
		return Incident{}, fmt.Errorf("inventory: read the incident's locations: %w", err)
	}
	return i, nil
}

// MaxIncidentsListed bounds ListIncidents.
const MaxIncidentsListed = 200

// ListIncidents returns the newest incidents (open ones only when openOnly), of one certificate when certificateID is
// not nil; at most limit (1..MaxIncidentsListed, 0 = 50).
func (s *Service) ListIncidents(ctx context.Context, certificateID *uuid.UUID, openOnly bool, limit int) ([]Incident, error) {
	return s.ListIncidentsIn(ctx, certificateID, openOnly, limit, authz.Everywhere())
}

// ListIncidentsIn is ListIncidents over the incidents visible from the services in reach (R49 Phase 2: the
// certificate's service or one in service_ids); the limit counts those only.
func (s *Service) ListIncidentsIn(ctx context.Context, certificateID *uuid.UUID, openOnly bool, limit int, reach authz.Reach) ([]Incident, error) {
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > MaxIncidentsListed {
		return nil, validate.Errors{{Field: "limit", Code: validate.OutOfRange,
			Params: map[string]string{"min": "1", "max": strconv.Itoa(MaxIncidentsListed)}}}
	}
	rows, err := s.pool.Query(ctx, incidentSelect+`
WHERE ($1::uuid IS NULL OR i.certificate_id = $1) AND (NOT $2 OR i.finished_at IS NULL) AND `+authz.IncidentVisible("i", "$4")+`
ORDER BY i.created_at DESC, i.id DESC LIMIT $3`, certificateID, openOnly, limit, reach.SQL())
	if err != nil {
		return nil, fmt.Errorf("inventory: list incidents: %w", err)
	}
	defer rows.Close()
	out := []Incident{}
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// incidentACME is the live ACME certificate that ordered the certificate (nil for another source or a deleted one).
func incidentACME(ctx context.Context, q db.Querier, certificateID uuid.UUID) (*uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `SELECT a.id FROM acme_orders o JOIN acme_certificates a ON a.id = o.acme_certificate_id AND a.deleted_at IS NULL
JOIN certificates c ON c.id = o.certificate_id AND c.source = 'acme'
WHERE o.certificate_id = $1 AND o.state = 'succeeded' ORDER BY o.started_at DESC LIMIT 1`, certificateID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read the certificate's ACME certificate: %w", err)
	}
	return &id, nil
}

// StartIncident starts a key-compromise incident for a certificate (see the file comment). Without a revoke mode the
// certificate's service's policy chooses it (incident.revoke_mode, R55), else after_verified. Refusals: the revoke mode
// (validate.Errors); the licence gate (ClassChange); ErrNotFound; ErrIncidentOpen; for an ACME certificate whose provider
// has no usable account ErrACMEAccountState or ErrACMERolloverPending (an order already running is waited for).
// Audited incident.started and certificate.compromised (with the number of certificates marked).
func (s *Service) StartIncident(ctx context.Context, a Actor, certificateID uuid.UUID, in IncidentInput) (Incident, error) {
	mode := in.RevokeMode
	if mode == "" {
		mode = IncidentRevokeAfterVerified
	}
	if mode != IncidentRevokeAfterVerified && mode != IncidentRevokeNow {
		return Incident{}, validate.Errors{{Field: "revoke_mode", Code: validate.OneOf, Params: map[string]string{"values": "after_verified, now"}}}
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Incident{}, err
	}
	id := uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var key, fingerprint string
		var service uuid.UUID
		err := tx.QueryRow(ctx, "SELECT public_key_sha256, fingerprint_sha256, service_id FROM certificates WHERE id = $1 FOR UPDATE", certificateID).
			Scan(&key, &fingerprint, &service)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inventory: lock the certificate: %w", err)
		}
		if in.RevokeMode == "" { // R55: the certificate's service's policy sets the default
			policy, err := authz.LoadPolicy(ctx, tx, service)
			if err != nil {
				return err
			}
			if m := policy.RevokeMode(); m != "" {
				mode = m
			}
		}
		acmeID, err := incidentACME(ctx, tx, certificateID)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		state, revocation := IncidentAwaitingReplacement, IncidentRevocationNotPossible
		var revoked *time.Time
		if acmeID != nil {
			state, revocation = IncidentOrdering, IncidentRevocationPending
			left, err := acmeVersionsWithKey(ctx, tx, *acmeID, key, now)
			if err != nil {
				return err
			}
			if len(left) == 0 {
				revocation, revoked = IncidentRevocationRevoked, &now // nothing left to revoke (revoked or expired already)
			}
		}
		sp, err := tx.Begin(ctx)
		if err != nil {
			return fmt.Errorf("inventory: open a savepoint: %w", err)
		}
		// service_ids (R49): the certificate's service and every service of a server holding a certificate with the key.
		_, err = sp.Exec(ctx, `INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, acme_certificate_id, state, revoke_mode, revocation,
    revoked_at, started_by, created_at, updated_at, service_ids) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10,
    ARRAY(SELECT c.service_id FROM certificates c WHERE c.id = $2
          UNION SELECT t.service_id FROM certificate_locations l JOIN certificates k ON k.id = l.certificate_id JOIN targets t ON t.id = l.target_id
              WHERE k.public_key_sha256 = $3 AND l.missing_since IS NULL AND t.deleted_at IS NULL))`,
			id, certificateID, key, acmeID, state, mode, revocation, revoked, nullableUser(a.UserID), now)
		if db.IsUniqueViolationOn(err, "certificate_incidents_one_open") {
			_ = sp.Rollback(ctx)
			return ErrIncidentOpen
		}
		if err != nil {
			_ = sp.Rollback(ctx)
			return fmt.Errorf("inventory: store the incident: %w", err)
		}
		if err := sp.Commit(ctx); err != nil {
			return fmt.Errorf("inventory: release a savepoint: %w", err)
		}
		tag, err := tx.Exec(ctx, `UPDATE certificates SET compromised_at = $2, compromised_by = $3 WHERE public_key_sha256 = $1 AND compromised_at IS NULL`,
			key, now, nullableUser(a.UserID))
		if err != nil {
			return fmt.Errorf("inventory: mark the certificates compromised: %w", err)
		}
		pending, skipped, err := s.insertIncidentLocations(ctx, tx, id, certificateID, fingerprint, key, acmeID, now)
		if err != nil {
			return err
		}
		if acmeID != nil {
			if err := s.startIncidentOrder(ctx, tx, a, id, *acmeID); err != nil {
				return err
			}
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "certificate.compromised", ObjectType: "certificate",
			ObjectID: certificateID.String(), Result: audit.Success, Details: map[string]string{"incident_id": id.String(),
				"spki_sha256": key, "certificates_marked": strconv.FormatInt(tag.RowsAffected(), 10)}}); err != nil {
			return err
		}
		details := map[string]string{"incident_id": id.String(), "certificate_id": certificateID.String(), "fingerprint": fingerprint,
			"revoke_mode": mode, "revocation": revocation, "locations_pending": strconv.Itoa(pending), "locations_skipped": strconv.Itoa(skipped)}
		if acmeID != nil {
			details["acme_certificate_id"] = acmeID.String()
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "incident.started", ObjectType: "certificate_incident",
			ObjectID: id.String(), Result: audit.Success, Details: details})
		return err
	})
	if err != nil {
		return Incident{}, err
	}
	return s.GetIncident(ctx, id)
}

// acmeVersionsWithKey lists the unexpired, unrevoked versions of the ACME certificate made with the key.
func acmeVersionsWithKey(ctx context.Context, q db.Querier, acmeID uuid.UUID, key string, now time.Time) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT x.id FROM certificates x JOIN acme_orders o ON o.certificate_id = x.id AND o.state = 'succeeded'
WHERE o.acme_certificate_id = $1 AND x.public_key_sha256 = $2 AND x.source = 'acme' AND x.revoked_at IS NULL AND x.not_after > $3 ORDER BY x.id`,
		acmeID, key, now)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the versions to revoke: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// insertIncidentLocations writes the affected places of live servers (files and Windows bindings: deployLocation's
// deployable rule, as a deployment request decides) as the incident's locations and returns how many are
// pending (Alice replaces them) and skipped.
func (s *Service) insertIncidentLocations(ctx context.Context, tx pgx.Tx, id, certificateID uuid.UUID, fingerprint, key string,
	acmeID *uuid.UUID, now time.Time) (pending, skipped int, err error) {
	rows, err := tx.Query(ctx, `SELECT l.id, t.type, coalesce(x.fingerprint_sha256 = $2 OR l.deployed_fingerprint = $2, false),
    b.acme_certificate_id, l.binding_id IS NOT NULL, `+deployableColumns+`
FROM certificate_locations l
JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
LEFT JOIN certificates x ON x.id = l.certificate_id
LEFT JOIN acme_bindings b ON b.location_id = l.id
WHERE l.missing_since IS NULL
  AND (x.public_key_sha256 = $1 OR l.deployed_fingerprint IN (SELECT y.fingerprint_sha256 FROM certificates y WHERE y.public_key_sha256 = $1)
       OR ($3::uuid IS NOT NULL AND b.acme_certificate_id = $3))
ORDER BY l.id LIMIT $4`, key, fingerprint, acmeID, MaxImpactRows)
	if err != nil {
		return 0, 0, fmt.Errorf("inventory: read the affected locations: %w", err)
	}
	type affected struct {
		loc              uuid.UUID
		typ              string
		same, deployable bool
		bound            *uuid.UUID
		kvBound          bool
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (affected, error) {
		var x affected
		var dl deployLocation
		err := r.Scan(append([]any{&x.loc, &x.typ, &x.same, &x.bound, &x.kvBound}, dl.deployableDest()...)...)
		x.deployable = dl.deployable()
		return x, err
	})
	if err != nil {
		return 0, 0, fmt.Errorf("inventory: read the affected locations: %w", err)
	}
	for _, x := range list {
		ours := acmeID != nil && x.bound != nil && *x.bound == *acmeID
		status, code := IncidentLocationPending, ""
		switch {
		case x.kvBound:
			status, code = IncidentLocationSkipped, IncidentCodeFollowsKeyVault
		case x.bound != nil && !ours:
			status, code = IncidentLocationSkipped, IncidentCodeFollowsOtherACME
		case !x.same && !ours:
			status, code = IncidentLocationSkipped, IncidentCodeOtherCertificate
		case !x.deployable || !s.canDeploy(x.typ):
			status, code = IncidentLocationSkipped, IncidentCodeNotDeployable
		}
		if _, err := tx.Exec(ctx, `INSERT INTO certificate_incident_locations (incident_id, location_id, status, error_code, updated_at)
VALUES ($1, $2, $3, $4, $5)`, id, x.loc, status, code, now); err != nil {
			return 0, 0, fmt.Errorf("inventory: store an affected location: %w", err)
		}
		if status == IncidentLocationPending {
			pending++
		} else {
			skipped++
		}
	}
	return pending, skipped, nil
}

// startIncidentOrder starts the order of the incident's replacement in a savepoint: an order already running is waited
// for (the advance task starts one once it ended); a provider without a usable account refuses.
func (s *Service) startIncidentOrder(ctx context.Context, tx pgx.Tx, a Actor, id, acmeID uuid.UUID) error {
	c, err := getACMECert(ctx, tx, acmeID, true)
	if err != nil {
		return err
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("inventory: open a savepoint: %w", err)
	}
	o, err := s.startOrderTx(ctx, sp, a, c, ACMEOrderIssue, ACMETriggerManual)
	switch {
	case errors.Is(err, ErrACMEOrderRunning):
		return sp.Rollback(ctx)
	case err != nil:
		_ = sp.Rollback(ctx)
		return err
	}
	if err := sp.Commit(ctx); err != nil {
		return fmt.Errorf("inventory: release a savepoint: %w", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE certificate_incidents SET order_id = $2, updated_at = $3 WHERE id = $1", id, o.ID, s.clock.Now().UTC()); err != nil {
		return fmt.Errorf("inventory: link the incident's order: %w", err)
	}
	return nil
}
