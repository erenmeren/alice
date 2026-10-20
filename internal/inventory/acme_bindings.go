package inventory

// Bindings of ACME certificates to locations (plan 2026-10-13 Task 12; design row 7; amendments A2, A9, A13) and the
// person's "Deploy now".
//
// A binding says that a location (a certificate file pair on a managed Nginx server) follows an ACME certificate: the
// planner (acme_autodeploy.go) deploys each new current certificate there when automatic deployment is on for the
// certificate and for the binding. A location follows ONE source: one ACME certificate (acme_bindings_location is
// unique) and never a Key Vault binding as well (certificate_locations.binding_id). Both kinds of binding are written
// while the location's row is locked (lockDeployTargets: the server, then the location), so a Key Vault binding and an
// ACME binding of one location serialize, and each checks the other in a statement of its own after the lock.
//
// Editing bindings changes nothing on a server, so it needs no licence (the planner and Deploy now ask the gate); an
// Operator may do it (A9: AcmeOperate) — except switching UNATTENDED deployment on (a new binding with automatic
// deployment on, or switching it on), which is an Administrator's act under the licence gate (unattendedAllowed; ruling
// of Task 12 fix round 1, like the Key Vault ruling S6).
// "Deploy now" is a thin wrapper of RequestDeployment (trigger manual): there is no second deploy path.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/acme/keygen"
	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Refusals of the ACME bindings and Deploy now.
var (
	// ErrACMENotIssued: the ACME certificate has no issued certificate yet (nothing to bind or deploy).
	ErrACMENotIssued = errors.New("inventory: the ACME certificate has no issued certificate yet")
	// ErrACMELocationBound: the location already follows another certificate (another ACME certificate or a vault
	// certificate); a location follows one source only.
	ErrACMELocationBound = errors.New("inventory: the location already follows another certificate")
	// ErrACMELocationNotBound: Deploy now named a location that is not bound to the ACME certificate.
	ErrACMELocationNotBound = errors.New("inventory: the location is not bound to the ACME certificate")
	// ErrACMENoBindings: Deploy now named no location and the ACME certificate is bound to none.
	ErrACMENoBindings = errors.New("inventory: the ACME certificate is bound to no location")
	// ErrACMETooManyBindings: Deploy now named no location and the certificate is bound to more locations than one
	// request may deploy to (MaxDeployLocations): the locations must be named.
	ErrACMETooManyBindings = errors.New("inventory: the ACME certificate is bound to more locations than one deployment request takes")
)

// Binding states (ACMEBinding.State). Since R52 a binding is current only while no observation newer than the
// deployment of the current certificate disagrees with it: a past success alone no longer makes it current
// (Observation.Health says how it is observed today).
const (
	ACMEBindingCurrent   = "current"   // the location got the current certificate and no newer observation disagrees
	ACMEBindingPending   = "pending"   // it does not have it yet
	ACMEBindingAttention = "attention" // the last automatic deployment of the current certificate to it failed
	ACMEBindingDrifted   = "drifted"   // it had the current certificate and a newer observation found another one (R52)
)

// ACMEBinding is the view of a binding.
type ACMEBinding struct {
	ACMECertificateID   uuid.UUID  `json:"acme_certificate_id"`
	LocationID          uuid.UUID  `json:"location_id"`
	TargetID            uuid.UUID  `json:"target_id"`
	TargetName          string     `json:"target_name"`
	CertPath            string     `json:"cert_path"`
	AutoDeploy          bool       `json:"auto_deploy"`
	State               string     `json:"state"`
	AttentionAt         *time.Time `json:"attention_at,omitempty"`
	AttentionCode       string     `json:"attention_code"`
	ServedCertificateID *uuid.UUID `json:"served_certificate_id,omitempty"`
	CreatedBy           *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	// Observation is the location's observation model and health (R52).
	Observation *LocationObservation `json:"-"`
}

// ACMEDeployInput is a person's Deploy now: the bound locations (none: every bound location; at most
// MaxDeployLocations) and, for an incomplete chain, an Administrator's confirmation (as RequestDeployment).
type ACMEDeployInput struct {
	LocationIDs            []uuid.UUID
	ConfirmIncompleteChain bool
}

const acmeBindingSelect = `SELECT b.acme_certificate_id, b.location_id, l.target_id, t.name::text, l.cert_path, b.auto_deploy, b.attention_at,
b.attention_code, l.certificate_id, b.created_by, b.created_at,
l.certificate_id IS NOT DISTINCT FROM c.current_certificate_id OR EXISTS (SELECT 1 FROM deployments d WHERE d.location_id = l.id
    AND d.certificate_id = c.current_certificate_id AND d.status IN ('succeeded', 'unchanged'))
FROM acme_bindings b JOIN acme_certificates c ON c.id = b.acme_certificate_id
JOIN certificate_locations l ON l.id = b.location_id JOIN targets t ON t.id = l.target_id`

func scanACMEBinding(row pgx.Row) (ACMEBinding, error) {
	var (
		b       ACMEBinding
		current bool
	)
	err := row.Scan(&b.ACMECertificateID, &b.LocationID, &b.TargetID, &b.TargetName, &b.CertPath, &b.AutoDeploy, &b.AttentionAt, &b.AttentionCode,
		&b.ServedCertificateID, &b.CreatedBy, &b.CreatedAt, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEBinding{}, ErrNotFound
	}
	if err != nil {
		return ACMEBinding{}, fmt.Errorf("inventory: read an ACME binding: %w", err)
	}
	b.CreatedAt, b.AttentionAt = b.CreatedAt.UTC(), utcPtr(b.AttentionAt)
	switch {
	case b.AttentionAt != nil:
		b.State = ACMEBindingAttention
	case current:
		b.State = ACMEBindingCurrent
	default:
		b.State = ACMEBindingPending
	}
	return b, nil
}

// ListACMEBindings returns the bindings of a live ACME certificate in location order (ErrNotFound for an unknown or
// deleted certificate). Locations of deleted servers are listed too (their binding stays until it is removed).
func (s *Service) ListACMEBindings(ctx context.Context, id uuid.UUID) ([]ACMEBinding, error) {
	if _, err := getACMECert(ctx, s.pool, id, false); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, acmeBindingSelect+" WHERE b.acme_certificate_id = $1 ORDER BY b.location_id", id)
	if err != nil {
		return nil, fmt.Errorf("inventory: list the ACME bindings: %w", err)
	}
	defer rows.Close()
	out := []ACMEBinding{}
	for rows.Next() {
		b, err := scanACMEBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return out, s.withACMEObservations(ctx, out)
}

// withACMEObservations attaches each binding's observation model (R52) and makes a binding whose location drifted
// drifted (an attention mark stays first: the failed deployment is the newer news).
func (s *Service) withACMEObservations(ctx context.Context, list []ACMEBinding) error {
	ids := make([]uuid.UUID, 0, len(list))
	for _, b := range list {
		ids = append(ids, b.LocationID)
	}
	m, err := s.locationObservations(ctx, s.pool, ids)
	if err != nil {
		return err
	}
	for i := range list {
		o, ok := m[list[i].LocationID]
		if !ok {
			continue
		}
		list[i].Observation = &o
		if o.Health == HealthDrifted && list[i].State != ACMEBindingAttention {
			list[i].State = ACMEBindingDrifted
		}
	}
	return nil
}

// policyAlgorithm is the key algorithm ("rsa", "ecdsa") of an ACME key policy.
func policyAlgorithm(policy string) string {
	alg, _, err := keygen.KeyPolicy(policy).Algorithm()
	if err != nil {
		return policy
	}
	return alg
}

// AddACMEBinding binds a location to an ACME certificate, or changes the automatic deployment of the binding it has
// (PUT semantics: binding the same location again only sets autoDeploy). In ONE transaction: the ACME certificate's row
// lock (FOR UPDATE: a key type change, a deletion and other bindings of it wait), then, in statements of their own,
// the refusals in this order: ErrNotFound (no live ACME certificate); ErrACMENotIssued (no current certificate);
// the location (lockDeployTargets: the server, then the location, both locked; *LocationRefusalError with ErrNotFound
// for an unknown location or a deleted server); ErrACMELocationBound (the location follows a vault certificate or
// another ACME certificate); ErrLocationUnsupported (missing at the last scan, unsupported, a path the helper cannot
// take, not an Nginx server); *KeyTypeMismatchError (the location's certificate has another key type than the ACME
// certificate's key policy or its current certificate: A13); then, when the binding would newly deploy UNATTENDED
// (autoDeploy true for a new binding or switched on), ErrAdminRequired for anyone but an Administrator and the licence
// gate's refusal (unattendedAllowed). A binding with automatic deployment off needs no licence and may be an
// Operator's (nothing changes on a server). Audit
// acme.binding.added (or acme.binding.updated when only automatic deployment changed; nothing when nothing changed).
func (s *Service) AddACMEBinding(ctx context.Context, a Actor, id, location uuid.UUID, autoDeploy bool) (ACMEBinding, error) {
	return s.AddACMEBindingStrict(ctx, a, id, location, autoDeploy, true)
}

// AddACMEBindingStrict is AddACMEBinding with the strength of the caller's session stated (as the Key Vault's
// UpdateBindingLocationsStrict): switching unattended deployment on is refused INSIDE the transaction, after the
// binding's automatic state was read under the certificate's row lock, unless the actor is an Administrator
// (ErrAdminRequired) AND strictSession is true (ErrAutoDeployNeedsStepUp: a browser session with a fresh step-up, never
// an API token), so a switch-off between the API's own read and this call cannot let a request without the step-up
// switch it on again. AddACMEBinding is this with strictSession true: its caller vouches for the step-up.
func (s *Service) AddACMEBindingStrict(ctx context.Context, a Actor, id, location uuid.UUID, autoDeploy, strictSession bool) (ACMEBinding, error) {
	if location == uuid.Nil {
		return ACMEBinding{}, validate.Errors{{Field: "location_id", Code: validate.Pattern}}
	}
	var out ACMEBinding
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var locked uuid.UUID
		err := tx.QueryRow(ctx, "SELECT id FROM acme_certificates WHERE id = $1 AND deleted_at IS NULL FOR UPDATE", id).Scan(&locked)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inventory: lock the ACME certificate: %w", err)
		}
		// Separate statements from here on: they see everything committed before the lock was granted.
		c, err := getACMECert(ctx, tx, id, false)
		if err != nil {
			return err
		}
		if c.CurrentCertificateID == nil {
			return ErrACMENotIssued
		}
		cur, err := readDeployCertificate(ctx, tx, *c.CurrentCertificateID)
		if err != nil {
			return err
		}
		targets, locs, err := s.lockDeployTargets(ctx, tx, []uuid.UUID{location})
		if err != nil {
			return err
		}
		l, t := locs[location], targets[locs[location].target]
		var (
			kvBound    bool
			acmeBound  *uuid.UUID
			autoBefore bool
		)
		if err := tx.QueryRow(ctx, "SELECT binding_id IS NOT NULL FROM certificate_locations WHERE id = $1", location).Scan(&kvBound); err != nil {
			return fmt.Errorf("inventory: read the location's binding: %w", err)
		}
		err = tx.QueryRow(ctx, "SELECT acme_certificate_id, auto_deploy FROM acme_bindings WHERE location_id = $1", location).Scan(&acmeBound, &autoBefore)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inventory: read the location's ACME binding: %w", err)
		}
		switch {
		case kvBound || (acmeBound != nil && *acmeBound != id):
			return &LocationRefusalError{LocationID: location, Err: ErrACMELocationBound}
		case l.missing || !l.supported || !deployablePath(l.certPath) || !deployablePath(l.keyPath), !s.canDeploy(t.Type):
			return &LocationRefusalError{LocationID: location, Err: ErrLocationUnsupported}
		}
		for _, alg := range []string{policyAlgorithm(c.KeyType), cur.algorithm} {
			if l.keyType != "" && l.keyType != alg {
				return &LocationRefusalError{LocationID: location, Err: &KeyTypeMismatchError{Expected: l.keyType, Actual: alg}}
			}
		}
		// R49 (design §5.6 (c)): the server's service accepts the ACME certificate's keys (a new binding; an existing
		// one keeps working until it deploys, where the planner and the engine check again).
		if acmeBound == nil {
			if err := authz.CheckTrust(ctx, tx, c.ServiceID, t.ServiceID); err != nil {
				return &LocationRefusalError{LocationID: location, Err: err}
			}
		}
		if autoDeploy && (acmeBound == nil || !autoBefore) {
			if err := s.unattendedAllowed(a, strictSession); err != nil {
				return err
			}
		}
		now := s.clock.Now().UTC()
		action := "acme.binding.added"
		switch {
		case acmeBound == nil:
			_, err := tx.Exec(ctx, `INSERT INTO acme_bindings (acme_certificate_id, location_id, auto_deploy, created_by, created_at)
VALUES ($1, $2, $3, $4, $5)`, id, location, autoDeploy, nullableUser(a.UserID), now)
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" { // the unique index: the backstop of the lock
				return &LocationRefusalError{LocationID: location, Err: ErrACMELocationBound}
			}
			if err != nil {
				return fmt.Errorf("inventory: store the ACME binding: %w", err)
			}
		case autoBefore != autoDeploy:
			action = "acme.binding.updated"
			if _, err := tx.Exec(ctx, "UPDATE acme_bindings SET auto_deploy = $3 WHERE acme_certificate_id = $1 AND location_id = $2", id, location,
				autoDeploy); err != nil {
				return fmt.Errorf("inventory: update the ACME binding: %w", err)
			}
		default:
			action = ""
		}
		if action != "" {
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: action, ObjectType: "acme_certificate", ObjectID: id.String(),
				Result: audit.Success, Details: map[string]string{"acme_certificate_id": id.String(), "location_id": location.String(),
					"target_id": l.target.String(), "cert_path": l.certPath, "auto_deploy": strconv.FormatBool(autoDeploy),
					"names": truncRunes(strings.Join(c.Names, ","), maxAuditNames)}}); err != nil {
				return err
			}
		}
		out, err = scanACMEBinding(tx.QueryRow(ctx, acmeBindingSelect+" WHERE b.acme_certificate_id = $1 AND b.location_id = $2", id, location))
		return err
	})
	if err != nil {
		return ACMEBinding{}, err
	}
	list := []ACMEBinding{out}
	if err := s.withACMEObservations(ctx, list); err != nil {
		return ACMEBinding{}, err
	}
	return list[0], nil
}

// unattendedAllowed is the rule for switching UNATTENDED deployment on (ruling of Task 12 fix round 1, as the Key Vault
// ruling S6): only an Administrator (ErrAdminRequired; the API also requires a fresh step-up) and only while the licence
// gate allows changes (license.ErrLocked and its kin). Switching it off, removing a binding, a binding with automatic
// deployment off and Deploy now are not gated by it.
func (s *Service) unattendedAllowed(a Actor, strictSession bool) error {
	switch {
	case a.Role != rbac.Admin:
		return ErrAdminRequired
	case !strictSession:
		return ErrAutoDeployNeedsStepUp
	}
	return s.license.Allow(license.ClassChange)
}

// RemoveACMEBinding removes the binding of a location from a live ACME certificate (ErrNotFound when there is none),
// under the certificate's row lock, with the audit row acme.binding.removed. An unfinished deployment to the location
// runs on (a person or the planner asked for it while it was bound). No licence is needed.
func (s *Service) RemoveACMEBinding(ctx context.Context, a Actor, id, location uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		c, err := getACMECert(ctx, tx, id, true)
		if err != nil {
			return err
		}
		var auto bool
		err = tx.QueryRow(ctx, "DELETE FROM acme_bindings WHERE acme_certificate_id = $1 AND location_id = $2 RETURNING auto_deploy", id, location).Scan(&auto)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inventory: remove the ACME binding: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.binding.removed", ObjectType: "acme_certificate", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"acme_certificate_id": id.String(), "location_id": location.String(),
				"auto_deploy": strconv.FormatBool(auto), "names": truncRunes(strings.Join(c.Names, ","), maxAuditNames)}})
		return err
	})
}

// DeployACMENow is a person's "Deploy now" of an ACME certificate's current certificate to its bound locations: the
// named ones (each must be bound: *LocationRefusalError with ErrACMELocationNotBound) or, when none is named, every
// bound location. It is RequestDeployment with trigger manual and nothing else (A2: the same checks, the licence lock,
// deployment.requested / deployment.denied audit rows, ErrChainUnconfirmed unless an Administrator confirms an
// incomplete chain). ErrNotFound, ErrACMENotIssued; with no location named, ErrACMENoBindings (none bound) or ErrACMETooManyBindings (more than MaxDeployLocations bound: name them).
func (s *Service) DeployACMENow(ctx context.Context, a Actor, id uuid.UUID, in ACMEDeployInput) ([]RequestedDeployment, error) {
	c, err := getACMECert(ctx, s.pool, id, false)
	if err != nil {
		return nil, err
	}
	if c.CurrentCertificateID == nil {
		return nil, ErrACMENotIssued
	}
	rows, err := s.pool.Query(ctx, "SELECT location_id FROM acme_bindings WHERE acme_certificate_id = $1 ORDER BY location_id", id)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the ACME bindings: %w", err)
	}
	bound, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("inventory: read the ACME bindings: %w", err)
	}
	locations := in.LocationIDs
	if len(locations) == 0 {
		switch {
		case len(bound) == 0:
			return nil, ErrACMENoBindings
		case len(bound) > MaxDeployLocations:
			return nil, ErrACMETooManyBindings
		}
		locations = bound
	}
	isBound := map[uuid.UUID]bool{}
	for _, l := range bound {
		isBound[l] = true
	}
	for _, l := range locations {
		if !isBound[l] {
			return nil, &LocationRefusalError{LocationID: l, Err: ErrACMELocationNotBound}
		}
	}
	// The key is the ACME certificate's: its service is the source (R49, design §5.6).
	return s.RequestDeployment(ctx, a, DeployRequestInput{CertificateID: *c.CurrentCertificateID, LocationIDs: locations,
		ConfirmIncompleteChain: in.ConfirmIncompleteChain, source: &c.ServiceID})
}

// ReleaseACMEDeployHold releases the current certificate of a live ACME certificate from the licence hold (an
// Administrator's act: the API gates it), so the planner deploys it under the normal rules; audit
// acme.auto_deploy.released. A certificate that is not held is left as it is (no audit row). A certificate held for an
// incomplete chain is not released (ErrChainUnconfirmed: the planner never confirms a chain; Deploy now with the
// confirmation deploys it). ErrNotFound.
func (s *Service) ReleaseACMEDeployHold(ctx context.Context, a Actor, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		c, err := getACMECert(ctx, tx, id, true)
		if err != nil {
			return err
		}
		var (
			held   *uuid.UUID
			reason string
		)
		if err := tx.QueryRow(ctx, "SELECT deploy_held_certificate_id, deploy_held_reason FROM acme_certificates WHERE id = $1", id).Scan(&held,
			&reason); err != nil {
			return fmt.Errorf("inventory: read the hold: %w", err)
		}
		if held == nil || c.CurrentCertificateID == nil || *held != *c.CurrentCertificateID {
			return nil
		}
		if reason == ACMEHoldChainIncomplete {
			return ErrChainUnconfirmed
		}
		if _, err := tx.Exec(ctx, `UPDATE acme_certificates SET deploy_released_certificate_id = deploy_held_certificate_id,
deploy_held_certificate_id = NULL, deploy_held_reason = '' WHERE id = $1`, id); err != nil {
			return fmt.Errorf("inventory: release the hold: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.auto_deploy.released", ObjectType: "acme_certificate",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"acme_certificate_id": id.String(), "certificate_id": held.String(),
				"names": truncRunes(strings.Join(c.Names, ","), maxAuditNames), "reason": reason}})
		return err
	})
}
