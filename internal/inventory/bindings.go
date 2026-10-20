package inventory

// Bindings (spec §11.7; R40 rows 22-24): a vault certificate connected to websites, that is to
// certificate locations of Nginx servers. A binding is the only link between the two worlds: it
// names the websites a version is deployed to, and whether new versions go out by themselves.
//
// Locks, always in this order (the order DeleteVault, the poll's batches and discovery already
// use): the vault target (FOR NO KEY UPDATE), the binding (FOR UPDATE), the Nginx servers (id
// order), their locations (id order). Every writer of a binding takes the vault first, so binding
// changes, a vault's deletion, a poll's batches and the planning of a deployment are serialised
// per vault.
//
// Websites on a server that was deleted afterwards stay marked with their binding (DeleteTarget
// does not know bindings); they are not counted, not listed and not deployable, and the binding's
// next change of locations releases them.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// MaxBindingLocations is how many websites one binding may connect.
const MaxBindingLocations = 200

// Per-location states of a binding (BindingLocation.State).
const (
	BindingLocationNotDeployed = "not_deployed"
	BindingLocationPending     = "pending"  // an unfinished deployment of the binding
	BindingLocationDeployed    = "deployed" // a version is served or was deployed (Version says which)
	BindingLocationFailed      = "failed"   // the last deployment did not succeed
	BindingLocationStopped     = "stopped"  // the automatic wave of the current version stopped (stopped_version)
)

// BindingInput connects one vault certificate to websites.
type BindingInput struct {
	KVCertificateID uuid.UUID
	LocationIDs     []uuid.UUID // 1..MaxBindingLocations
}

// BindingLocation is one connected website and what Alice knows of its deployment.
type BindingLocation struct {
	LocationID, TargetID uuid.UUID
	TargetName, CertPath string
	State                string     // BindingLocation*
	Version              string     // the vault version served or deployed ("" unless State is deployed)
	DeploymentID         *uuid.UUID // the latest deployment of this binding to the website
	// AttentionCode is why automatic deployment holds the website ("" for nothing): ReasonServiceUntrusted when its
	// server's service does not accept the vault's keys (R49).
	AttentionCode string
}

// Binding is a vault certificate's connection to websites. Locations is filled by Binding (and
// by the operations that return a binding), not by ListBindings.
type Binding struct {
	BindingSummary
	KVCertificateID, VaultID   uuid.UUID
	CertificateName, VaultName string
	CreatedBy                  *uuid.UUID
	Locations                  []BindingLocation
}

// BindingFilter selects live bindings, newest first. Cursor is the NextCursor of the previous page;
// Limit is 1..200 (0 = 50).
type BindingFilter struct {
	VaultID, KVCertificateID uuid.UUID
	Cursor                   string
	Limit                    int
}

// BindingPage is one page of bindings.
type BindingPage struct {
	Items      []Binding
	NextCursor string
}

// bindingDenial is a refusal audited after its transaction rolled back.
type bindingDenial struct {
	reason   string
	location uuid.UUID
}

func validateLocationIDs(ids []uuid.UUID, max int) validate.Errors {
	var errs validate.Errors
	if n := len(ids); n < 1 || n > max {
		errs.Add("location_ids", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(max)})
		return errs
	}
	seen := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		if seen[id] || id == uuid.Nil {
			errs.Add("location_ids", validate.Pattern, nil)
			break
		}
		seen[id] = true
	}
	return errs
}

// auditBindingDenial records a refusal in its own transaction (the request's was rolled back); like
// auditDeployDenial it outlives the request for at most detachedTimeout.
func (s *Service) auditBindingDenial(ctx context.Context, a Actor, action, objectType string, objectID uuid.UUID, details map[string]string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: action, ObjectType: objectType, ObjectID: objectID.String(),
			Result: audit.Denied, Details: details})
		return err
	})
	if err != nil {
		s.log.Error("could not audit a refusal", "action", action, "error_type", fmt.Sprintf("%T", err))
	}
}

// denialDetails is the audit detail map of a denial.
func denialDetails(d bindingDenial, kv map[string]string) map[string]string {
	kv["reason"] = d.reason
	if d.location != uuid.Nil {
		kv["location_id"] = d.location.String()
	}
	return kv
}

// auditLicenseRefusal audits a refusal of the license gate (locked, lock due, unverified) and returns err.
func (s *Service) auditLicenseRefusal(ctx context.Context, a Actor, err error, action, objectType string, objectID uuid.UUID, kv map[string]string) error {
	if reason := license.DenialReason(err); reason != "" {
		s.auditBindingDenial(ctx, a, action, objectType, objectID, denialDetails(bindingDenial{reason: reason}, kv))
	}
	return err
}

// mapBindingError turns the database's refusals into closed errors: a second live binding of one
// certificate, and a certificate or vault the composite key does not know.
func mapBindingError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == "23505" && pgErr.ConstraintName == "bindings_one_live":
			return ErrBindingExists
		case pgErr.Code == "23503" && pgErr.ConstraintName == "bindings_vault":
			return ErrKVCertificateMissing
		case pgErr.Code == "23503": // another foreign key (a user, a website): not "the certificate is not in the vault"
			return fmt.Errorf("inventory: the database refused the binding: %w", err)
		}
	}
	return err
}

// lockedVault is what the lock of a vault target returns.
type lockedVault struct {
	id        uuid.UUID
	name, url string
	service   uuid.UUID // the vault's service (R49): the source of the keys its bindings deploy
}

// lockVault locks a live vault (FOR NO KEY UPDATE: the poll's batches take the same lock, DeleteVault
// a stronger one). A deleted or unknown vault is ErrNotFound.
func lockVault(ctx context.Context, tx pgx.Tx, id uuid.UUID) (lockedVault, error) {
	v := lockedVault{id: id}
	err := tx.QueryRow(ctx, `SELECT name::text, coalesce(config->>'vault_url', ''), service_id FROM targets
WHERE id = $1 AND type = 'azure_key_vault' AND deleted_at IS NULL FOR NO KEY UPDATE`, id).Scan(&v.name, &v.url, &v.service)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedVault{}, ErrNotFound
	}
	if err != nil {
		return lockedVault{}, fmt.Errorf("inventory: lock the vault: %w", err)
	}
	return v, nil
}

// lockedBinding is a live binding read under its lock.
type lockedBinding struct {
	id, certificate uuid.UUID
	certificateName string
	autoDeploy      bool
	version         int
}

// lockBinding locks the vault of a live binding, then the binding (the order of the file comment).
// A deleted or unknown binding, or one whose vault was deleted, is ErrNotFound.
func lockBinding(ctx context.Context, tx pgx.Tx, id uuid.UUID) (lockedVault, lockedBinding, error) {
	var vault uuid.UUID
	err := tx.QueryRow(ctx, "SELECT kv_target_id FROM bindings WHERE id = $1 AND deleted_at IS NULL", id).Scan(&vault)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedVault{}, lockedBinding{}, ErrNotFound
	}
	if err != nil {
		return lockedVault{}, lockedBinding{}, fmt.Errorf("inventory: find the binding's vault: %w", err)
	}
	v, err := lockVault(ctx, tx, vault)
	if err != nil {
		return lockedVault{}, lockedBinding{}, err
	}
	b := lockedBinding{id: id}
	err = tx.QueryRow(ctx, `SELECT b.kv_certificate_id, kc.name, b.auto_deploy, b.version FROM bindings b
JOIN kv_certificates kc ON kc.id = b.kv_certificate_id
WHERE b.id = $1 AND b.deleted_at IS NULL FOR UPDATE OF b`, id).Scan(&b.certificate, &b.certificateName, &b.autoDeploy, &b.version)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedVault{}, lockedBinding{}, ErrNotFound
	}
	if err != nil {
		return lockedVault{}, lockedBinding{}, fmt.Errorf("inventory: lock the binding: %w", err)
	}
	return v, b, nil
}

// kvCertInfo is what binding a vault certificate needs to know of it.
type kvCertInfo struct {
	id, vault  uuid.UUID
	name       string
	current    string // current_version: "" until Alice read the certificate's details
	exportable *bool
	keyType    string
	missing    bool
}

// kvCertificateOf reads a vault certificate under a share lock. ErrNotFound when unknown.
func kvCertificateOf(ctx context.Context, tx pgx.Tx, id uuid.UUID) (kvCertInfo, error) {
	c := kvCertInfo{id: id}
	err := tx.QueryRow(ctx, `SELECT target_id, name, current_version, exportable, key_type, missing_since IS NOT NULL FROM kv_certificates WHERE id = $1 FOR SHARE`,
		id).Scan(&c.vault, &c.name, &c.current, &c.exportable, &c.keyType, &c.missing)
	if errors.Is(err, pgx.ErrNoRows) {
		return kvCertInfo{}, ErrNotFound
	}
	if err != nil {
		return kvCertInfo{}, fmt.Errorf("inventory: read the vault certificate: %w", err)
	}
	return c, nil
}

// vaultOfCertificate is the (unlocked) vault of a certificate: the first step of the lock order.
func vaultOfCertificate(ctx context.Context, tx pgx.Tx, id uuid.UUID) (uuid.UUID, error) {
	var vault uuid.UUID
	err := tx.QueryRow(ctx, "SELECT target_id FROM kv_certificates WHERE id = $1", id).Scan(&vault)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("inventory: find the certificate's vault: %w", err)
	}
	return vault, nil
}

// certificateRefusal is the refusal of a vault certificate as such (before any website).
func certificateRefusal(c kvCertInfo) (string, error) {
	switch {
	case c.missing:
		return "certificate_missing", ErrKVCertificateMissing
	case c.exportable != nil && !*c.exportable:
		return "not_exportable", ErrNotExportable
	case c.keyType != "" && c.keyType != "rsa" && c.keyType != "ecdsa":
		return "unsupported_key", ErrUnsupportedKey
	}
	return "", nil
}

// acmeBoundMark is what lockedBindingsOf reports for a location bound to an ACME certificate: an id no Key Vault binding
// has, so checkBindable refuses the location (ErrLocationBound) like one bound to another vault certificate.
var acmeBoundMark = uuid.Max

// lockedLocations reads which binding each location belongs to (the locations are locked): its Key Vault binding, or
// acmeBoundMark when it follows an ACME certificate (acme_bindings; a location follows one source only, and AddACMEBinding
// holds the same location lock while it checks binding_id).
func lockedBindingsOf(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) (map[uuid.UUID]*uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT l.id, CASE WHEN EXISTS (SELECT 1 FROM acme_bindings a WHERE a.location_id = l.id) THEN $2::uuid ELSE l.binding_id END
FROM certificate_locations l WHERE l.id = ANY($1)`, ids, acmeBoundMark)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the locations' bindings: %w", err)
	}
	defer rows.Close()
	out := make(map[uuid.UUID]*uuid.UUID, len(ids))
	for rows.Next() {
		var id uuid.UUID
		var b *uuid.UUID
		if err := rows.Scan(&id, &b); err != nil {
			return nil, fmt.Errorf("inventory: read a location's binding: %w", err)
		}
		out[id] = b
	}
	return out, rows.Err()
}

// checkBindable is the refusal of a website for a binding (self is the binding it would join, or the
// zero id for a new one), in the order the websites were named: already connected elsewhere, then
// not deployable at all (missing at the last scan, unsupported, a path the helper cannot take, a
// server whose provider does not deploy), then a key type the website's certificate does not have.
// Whether the server is reachable right now is not a property of the binding: every deployment
// checks it.
func (s *Service) checkBindable(c kvCertInfo, ids []uuid.UUID, self uuid.UUID, targets map[uuid.UUID]Target, locs map[uuid.UUID]deployLocation,
	bound map[uuid.UUID]*uuid.UUID) (string, uuid.UUID, error) {
	for _, id := range ids {
		l, t := locs[id], targets[locs[id].target]
		switch {
		case bound[id] != nil && *bound[id] != self:
			return "location_bound", id, ErrLocationBound
		case l.missing || !l.supported || !deployablePath(l.certPath) || !deployablePath(l.keyPath),
			!s.canDeploy(t.Type):
			return "location_unsupported", id, ErrLocationUnsupported
		case l.keyType != "" && c.keyType != "" && l.keyType != c.keyType:
			return "key_type_mismatch", id, &KeyTypeMismatchError{Expected: l.keyType, Actual: c.keyType}
		}
	}
	return "", uuid.Nil, nil
}

// denyWith records the denial and returns its error.
func denyWith(denial **bindingDenial, reason string, loc uuid.UUID, err error) error {
	*denial = &bindingDenial{reason: reason, location: loc}
	return err
}

// finishDenial audits a denial after the transaction and names the website in the error.
func (s *Service) finishDenial(ctx context.Context, a Actor, err error, denial *bindingDenial, action, objectType string, objectID uuid.UUID,
	kv map[string]string) error {
	if denial == nil {
		return err
	}
	s.auditBindingDenial(ctx, a, action, objectType, objectID, denialDetails(*denial, kv))
	var lr *LocationRefusalError
	if err != nil && denial.location != uuid.Nil && !errors.As(err, &lr) {
		err = &LocationRefusalError{LocationID: denial.location, Err: err}
	}
	return err
}

// checkBindingTrust is design §5.6 (c) for websites joining a binding (R49): the server of each must be in the source
// service (the vault's, the ACME certificate's) or its service must accept the source's keys. It returns the first
// website refused and its *authz.UntrustedError.
func checkBindingTrust(ctx context.Context, tx pgx.Tx, source uuid.UUID, ids []uuid.UUID, targets map[uuid.UUID]Target,
	locs map[uuid.UUID]deployLocation) (uuid.UUID, error) {
	for _, id := range ids {
		if err := authz.CheckTrust(ctx, tx, source, targets[locs[id].target].ServiceID); err != nil {
			return id, err
		}
	}
	return uuid.Nil, nil
}

// locationRefusal reads the website named by a lockDeployTargets failure.
func locationOfRefusal(err error) uuid.UUID {
	var lr *LocationRefusalError
	if errors.As(err, &lr) {
		return lr.LocationID
	}
	return uuid.Nil
}

// CreateBinding connects a vault certificate to websites (R40 row 22): one live binding per
// certificate, one binding per website. Refusals, in this order: the license lock; the certificate
// (ErrKVCertificateMissing: unknown, deleted vault, or no longer listed by its vault; ErrNotExportable,
// F-45: the vault says its key cannot be read; ErrUnsupportedKey); ErrBindingExists; then per website
// (checkBindable) with *LocationRefusalError naming it: ErrNotFound (unknown, or its server deleted),
// ErrLocationBound, ErrLocationUnsupported, *KeyTypeMismatchError. All or nothing. Each refusal after
// validation is audited binding.denied after the rollback; success is binding.created. Automatic
// deployment starts off.
func (s *Service) CreateBinding(ctx context.Context, a Actor, in BindingInput) (Binding, error) {
	errs := validateLocationIDs(in.LocationIDs, MaxBindingLocations)
	if in.KVCertificateID == uuid.Nil {
		errs.Add("kv_certificate_id", validate.Pattern, nil)
	}
	if len(errs) > 0 {
		return Binding{}, errs
	}
	kvDetails := func() map[string]string { return map[string]string{"kv_certificate_id": in.KVCertificateID.String()} }
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Binding{}, s.auditLicenseRefusal(ctx, a, err, "binding.denied", "kv_certificate", in.KVCertificateID, kvDetails())
	}
	var (
		out    Binding
		denial *bindingDenial
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		out, denial = Binding{}, nil
		vaultID, err := vaultOfCertificate(ctx, tx, in.KVCertificateID)
		if errors.Is(err, ErrNotFound) {
			return denyWith(&denial, "certificate_missing", uuid.Nil, ErrKVCertificateMissing)
		}
		if err != nil {
			return err
		}
		vault, err := lockVault(ctx, tx, vaultID)
		if errors.Is(err, ErrNotFound) { // the vault was deleted
			return denyWith(&denial, "certificate_missing", uuid.Nil, ErrKVCertificateMissing)
		}
		if err != nil {
			return err
		}
		c, err := kvCertificateOf(ctx, tx, in.KVCertificateID)
		if err != nil {
			return err
		}
		if reason, err := certificateRefusal(c); err != nil {
			return denyWith(&denial, reason, uuid.Nil, err)
		}
		if c.current == "" {
			// Baseline rule: a certificate Alice has no details of yet cannot be bound, so that no version
			// can later "appear after the binding" that was only read late (see the planner's rule, kv_created_at).
			return denyWith(&denial, "no_current_version", uuid.Nil, ErrVersionNotDeployable)
		}
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM bindings WHERE kv_certificate_id = $1 AND deleted_at IS NULL)", c.id).Scan(&exists); err != nil {
			return fmt.Errorf("inventory: look for the certificate's binding: %w", err)
		}
		if exists {
			return denyWith(&denial, "binding_exists", uuid.Nil, ErrBindingExists)
		}
		targets, locs, err := s.lockDeployTargets(ctx, tx, in.LocationIDs)
		if err != nil {
			return denyWith(&denial, "location_not_found", locationOfRefusal(err), err)
		}
		bound, err := lockedBindingsOf(ctx, tx, in.LocationIDs)
		if err != nil {
			return err
		}
		if reason, loc, err := s.checkBindable(c, in.LocationIDs, uuid.Nil, targets, locs, bound); err != nil {
			return denyWith(&denial, reason, loc, err)
		}
		if loc, err := checkBindingTrust(ctx, tx, vault.service, in.LocationIDs, targets, locs); err != nil {
			return denyWith(&denial, ReasonServiceUntrusted, loc, err)
		}
		now := s.clock.Now().UTC()
		id := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO bindings (id, kv_certificate_id, kv_target_id, created_by, created_at) VALUES ($1, $2, $3, $4, $5)`,
			id, c.id, c.vault, nullableUser(a.UserID), now); err != nil {
			return mapBindingError(fmt.Errorf("inventory: store the binding: %w", err))
		}
		if _, err := tx.Exec(ctx, "UPDATE certificate_locations SET binding_id = $2 WHERE id = ANY($1)", in.LocationIDs, id); err != nil {
			return fmt.Errorf("inventory: connect the websites: %w", err)
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "binding.created", ObjectType: "binding", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"binding_id": id.String(), "kv_certificate_id": c.id.String(), "certificate_name": c.name,
				"vault_url": vault.url, "location_count": strconv.Itoa(len(in.LocationIDs))}}); err != nil {
			return err
		}
		out, err = readBinding(ctx, tx, id, true)
		return err
	})
	if err = mapBindingError(err); err != nil {
		return Binding{}, s.finishDenial(ctx, a, err, denial, "binding.denied", "kv_certificate", in.KVCertificateID, kvDetails())
	}
	return out, nil
}

// UpdateBindingLocations replaces the websites of a binding by the given set (1..MaxBindingLocations;
// a binding with no website is removed with DeleteBinding). ifVersion is the binding's version as the
// caller read it (ErrVersionMismatch otherwise). Websites that are no longer named are released (an
// unfinished deployment to one of them runs on: the deployment keeps its binding id); websites that
// are new are checked as CreateBinding does. Adding websites to a binding that deploys
// automatically puts them under automatic deployment, so it needs an Administrator (ErrAdminRequired,
// ruling S6); releasing websites does not. Naming the same set changes nothing. Audited
// binding.locations_changed.
func (s *Service) UpdateBindingLocations(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, locations []uuid.UUID) (Binding, error) {
	return s.UpdateBindingLocationsStrict(ctx, a, id, ifVersion, locations, true)
}

// UpdateBindingLocationsStrict is UpdateBindingLocations with the strength of the caller's session stated:
// adding websites to a binding that deploys automatically is refused inside the transaction unless the
// actor is an Administrator AND strictSession is true (ErrAutoDeployNeedsStepUp; the binding's automatic
// state is read under its lock, so a switch-on between the caller's check and this call is caught).
// UpdateBindingLocations is this with strictSession true: its caller vouches for the step-up.
func (s *Service) UpdateBindingLocationsStrict(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, locations []uuid.UUID, strictSession bool) (Binding, error) {
	if errs := validateLocationIDs(locations, MaxBindingLocations); len(errs) > 0 {
		return Binding{}, errs
	}
	kvDetails := func() map[string]string { return map[string]string{"binding_id": id.String()} }
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Binding{}, s.auditLicenseRefusal(ctx, a, err, "binding.denied", "binding", id, kvDetails())
	}
	var (
		out    Binding
		denial *bindingDenial
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		out, denial = Binding{}, nil
		vault, b, err := lockBinding(ctx, tx, id)
		if err != nil {
			return err
		}
		if b.version != ifVersion {
			return ErrVersionMismatch
		}
		c, err := kvCertificateOf(ctx, tx, b.certificate)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT id FROM certificate_locations WHERE binding_id = $1 ORDER BY id", id)
		if err != nil {
			return fmt.Errorf("inventory: read the binding's websites: %w", err)
		}
		current, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return fmt.Errorf("inventory: read the binding's websites: %w", err)
		}
		var added, removed []uuid.UUID
		for _, l := range locations {
			if !slices.Contains(current, l) {
				added = append(added, l)
			}
		}
		for _, l := range current {
			if !slices.Contains(locations, l) {
				removed = append(removed, l)
			}
		}
		if len(added) == 0 && len(removed) == 0 {
			out, err = readBinding(ctx, tx, id, true)
			return err
		}
		if len(added) > 0 {
			if b.autoDeploy && a.Role != rbac.Admin {
				return denyWith(&denial, "admin_required", uuid.Nil, ErrAdminRequired)
			}
			if b.autoDeploy && !strictSession {
				return denyWith(&denial, "step_up_required", uuid.Nil, ErrAutoDeployNeedsStepUp)
			}
			if reason, err := certificateRefusal(c); err != nil && reason != "certificate_missing" {
				return denyWith(&denial, reason, uuid.Nil, err)
			}
			targets, locs, err := s.lockDeployTargets(ctx, tx, added)
			if err != nil {
				return denyWith(&denial, "location_not_found", locationOfRefusal(err), err)
			}
			bound, err := lockedBindingsOf(ctx, tx, added)
			if err != nil {
				return err
			}
			if reason, loc, err := s.checkBindable(c, added, id, targets, locs, bound); err != nil {
				return denyWith(&denial, reason, loc, err)
			}
			if loc, err := checkBindingTrust(ctx, tx, vault.service, added, targets, locs); err != nil {
				return denyWith(&denial, ReasonServiceUntrusted, loc, err)
			}
			if _, err := tx.Exec(ctx, "UPDATE certificate_locations SET binding_id = $2 WHERE id = ANY($1)", added, id); err != nil {
				return fmt.Errorf("inventory: connect the websites: %w", err)
			}
		}
		if len(removed) > 0 {
			// Row locks in id order, like every other writer of websites.
			if _, err := tx.Exec(ctx, "SELECT 1 FROM certificate_locations WHERE id = ANY($1) ORDER BY id FOR NO KEY UPDATE", removed); err != nil {
				return fmt.Errorf("inventory: lock the websites to release: %w", err)
			}
			if _, err := tx.Exec(ctx, `UPDATE certificate_locations SET binding_id = NULL, binding_attention_code = '', binding_attention_at = NULL
WHERE id = ANY($1) AND binding_id = $2`, removed, id); err != nil {
				return fmt.Errorf("inventory: release the websites: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE bindings SET version = version + 1 WHERE id = $1", id); err != nil {
			return fmt.Errorf("inventory: update the binding: %w", err)
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "binding.locations_changed", ObjectType: "binding", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"binding_id": id.String(), "kv_certificate_id": b.certificate.String(),
				"certificate_name": b.certificateName, "added_count": strconv.Itoa(len(added)), "removed_count": strconv.Itoa(len(removed)),
				"location_count": strconv.Itoa(len(locations))}}); err != nil {
			return err
		}
		out, err = readBinding(ctx, tx, id, true)
		return err
	})
	if err = mapBindingError(err); err != nil {
		return Binding{}, s.finishDenial(ctx, a, err, denial, "binding.denied", "binding", id, kvDetails())
	}
	return out, nil
}

// SetAutoDeploy switches automatic deployment of a binding. Only an Administrator may (ErrAdminRequired,
// audited binding.denied; ruling S6: there is no weaker path than the API's Administrator and
// step-up). Switching on is a change the license lock refuses; switching off and removing a binding
// are safety actions that work in lock. On records auto_since (the planner deploys only versions
// detected after it) and clears stopped_version; that does NOT make a stopped version deployable again
// (the new auto_since is later than it, so it stays "deploy manually": Deploy now is the way); a certificate whose key the vault cannot export
// (ErrNotExportable) cannot be switched on. Switching on never releases a held version. ifVersion is
// the binding's version as the caller read it; a request that changes nothing is a success without an
// audit row. Audited binding.auto_deploy_changed.
func (s *Service) SetAutoDeploy(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, enabled bool) (Binding, error) {
	kvDetails := func() map[string]string { return map[string]string{"binding_id": id.String()} }
	if a.Role != rbac.Admin {
		s.auditBindingDenial(ctx, a, "binding.denied", "binding", id, denialDetails(bindingDenial{reason: "admin_required"}, kvDetails()))
		return Binding{}, ErrAdminRequired
	}
	if enabled {
		if err := s.license.Allow(license.ClassChange); err != nil {
			return Binding{}, s.auditLicenseRefusal(ctx, a, err, "binding.denied", "binding", id, kvDetails())
		}
	}
	var (
		out    Binding
		denial *bindingDenial
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		out, denial = Binding{}, nil
		_, b, err := lockBinding(ctx, tx, id)
		if err != nil {
			return err
		}
		if b.version != ifVersion {
			return ErrVersionMismatch
		}
		if b.autoDeploy == enabled {
			out, err = readBinding(ctx, tx, id, true)
			return err
		}
		if enabled {
			c, err := kvCertificateOf(ctx, tx, b.certificate)
			if err != nil {
				return err
			}
			if c.exportable != nil && !*c.exportable {
				return denyWith(&denial, "not_exportable", uuid.Nil, ErrNotExportable)
			}
		}
		var since *time.Time
		if enabled {
			now := s.clock.Now().UTC()
			since = &now
		}
		if _, err := tx.Exec(ctx, `UPDATE bindings SET auto_deploy = $2, auto_since = $3,
    stopped_version = CASE WHEN $2 THEN '' ELSE stopped_version END, version = version + 1 WHERE id = $1`, id, enabled, since); err != nil {
			return fmt.Errorf("inventory: switch automatic deployment: %w", err)
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "binding.auto_deploy_changed", ObjectType: "binding", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"binding_id": id.String(), "kv_certificate_id": b.certificate.String(),
				"certificate_name": b.certificateName, "enabled": strconv.FormatBool(enabled)}}); err != nil {
			return err
		}
		out, err = readBinding(ctx, tx, id, true)
		return err
	})
	if err != nil {
		return Binding{}, s.finishDenial(ctx, a, err, denial, "binding.denied", "binding", id, kvDetails())
	}
	return out, nil
}

// releaseBindingTx soft-deletes a locked binding and releases its websites (certificate_locations.binding_id
// = NULL), writing binding.deleted with the given details plus binding_id and location_count. It is
// the one code path that removes a binding: DeleteVault(removeBindings) and DeleteBinding both use it.
func (s *Service) releaseBindingTx(ctx context.Context, tx pgx.Tx, a Actor, id uuid.UUID, now time.Time, details map[string]string) error {
	if _, err := tx.Exec(ctx, "UPDATE bindings SET deleted_at = $2, version = version + 1 WHERE id = $1", id, now); err != nil {
		return fmt.Errorf("inventory: remove a binding: %w", err)
	}
	tag, err := tx.Exec(ctx, "UPDATE certificate_locations SET binding_id = NULL, binding_attention_code = '', binding_attention_at = NULL WHERE binding_id = $1", id)
	if err != nil {
		return fmt.Errorf("inventory: release a binding's locations: %w", err)
	}
	details["binding_id"] = id.String()
	details["location_count"] = strconv.FormatInt(tag.RowsAffected(), 10)
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "binding.deleted", ObjectType: "binding", ObjectID: id.String(),
		Result: audit.Success, Details: details})
	return err
}

// DeleteBinding removes a binding: it is soft-deleted, its websites are released and the certificate
// can be connected again. Nothing on the websites changes. A deployment of the binding that is
// still unfinished is left alone: it keeps its binding id and version, the engine finishes it
// (DeploymentMaterial still reads its vault source), and it keeps blocking a new deployment to its
// website (F-15) until it ends. Works in lock (a safety action). Audited binding.deleted
// (reason "removed").
func (s *Service) DeleteBinding(ctx context.Context, a Actor, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		v, b, err := lockBinding(ctx, tx, id)
		if err != nil {
			return err
		}
		return s.releaseBindingTx(ctx, tx, a, id, s.clock.Now().UTC(), map[string]string{"kv_certificate_id": b.certificate.String(),
			"certificate_name": b.certificateName, "vault_url": v.url, "reason": "removed"})
	})
}

// bindingColumns reads a Binding without its websites; LocationCount counts the websites on live servers.
const bindingColumns = `SELECT b.id, b.kv_certificate_id, b.kv_target_id, kc.name, t.name::text, b.auto_deploy, b.auto_since, b.stopped_version,
b.version, b.created_at, b.created_by,
(SELECT count(*) FROM certificate_locations l JOIN targets lt ON lt.id = l.target_id AND lt.deleted_at IS NULL WHERE l.binding_id = b.id)
FROM bindings b
JOIN kv_certificates kc ON kc.id = b.kv_certificate_id
JOIN targets t ON t.id = b.kv_target_id`

func scanBinding(row pgx.Row) (Binding, error) {
	var b Binding
	err := row.Scan(&b.ID, &b.KVCertificateID, &b.VaultID, &b.CertificateName, &b.VaultName, &b.AutoDeploy, &b.AutoSince, &b.StoppedVersion,
		&b.Version, &b.CreatedAt, &b.CreatedBy, &b.LocationCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, ErrNotFound
	}
	if err != nil {
		return Binding{}, fmt.Errorf("inventory: read a binding: %w", err)
	}
	b.AutoSince, b.CreatedAt = utcPtr(b.AutoSince), b.CreatedAt.UTC()
	return b, nil
}

// Binding returns a live binding with its websites and what is known of each one's deployment
// (ErrNotFound for an unknown or removed binding).
func (s *Service) Binding(ctx context.Context, id uuid.UUID) (Binding, error) {
	return readBinding(ctx, s.pool, id, true)
}

func readBinding(ctx context.Context, q db.Querier, id uuid.UUID, withLocations bool) (Binding, error) {
	b, err := scanBinding(q.QueryRow(ctx, bindingColumns+" WHERE b.id = $1 AND b.deleted_at IS NULL", id))
	if err != nil {
		return Binding{}, err
	}
	if withLocations {
		if b.Locations, err = readBindingLocations(ctx, q, b); err != nil {
			return Binding{}, err
		}
	}
	return b, nil
}

// readBindingLocations reads the websites of a binding and decides each one's state: pending (an
// unfinished deployment of this binding), deployed (the website serves the current version or a
// deployment of it succeeded), stopped (the automatic wave of the current version stopped and it is
// not there), failed (the last deployment of the binding did not succeed), deployed with an older
// version, or not deployed. "Serves" means the location's certificate has the leaf of a stored
// version.
func readBindingLocations(ctx context.Context, q db.Querier, b Binding) ([]BindingLocation, error) {
	var current string
	if err := q.QueryRow(ctx, "SELECT current_version FROM kv_certificates WHERE id = $1", b.KVCertificateID).Scan(&current); err != nil {
		return nil, fmt.Errorf("inventory: read the certificate's current version: %w", err)
	}
	rows, err := q.Query(ctx, `SELECT l.id, l.target_id, t.name::text, l.cert_path,
    (SELECT d.id FROM deployments d WHERE d.location_id = l.id AND d.binding_id = $1 AND d.state <> 'done'
     ORDER BY d.created_at DESC, d.id DESC LIMIT 1),
    (SELECT d.id FROM deployments d WHERE d.location_id = l.id AND d.binding_id = $1 ORDER BY d.created_at DESC, d.id DESC LIMIT 1),
    coalesce((SELECT d.status FROM deployments d WHERE d.location_id = l.id AND d.binding_id = $1 ORDER BY d.created_at DESC, d.id DESC LIMIT 1), ''),
    coalesce((SELECT v.version FROM kv_certificate_versions v
              JOIN certificates vc ON vc.id = v.certificate_id
              JOIN certificates lc ON lc.id = l.certificate_id AND lc.fingerprint_sha256 = vc.fingerprint_sha256
              WHERE v.kv_certificate_id = $2 ORDER BY v.detected_at DESC, v.id DESC LIMIT 1), ''),
    coalesce((SELECT v.version FROM deployments d JOIN kv_certificate_versions v ON v.id = d.kv_version_id
              WHERE d.location_id = l.id AND v.kv_certificate_id = $2 AND d.status IN ('succeeded', 'unchanged')
              ORDER BY d.created_at DESC, d.id DESC LIMIT 1), ''),
    l.binding_attention_code
FROM certificate_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
WHERE l.binding_id = $1
ORDER BY lower(t.name::text COLLATE "C"), l.cert_path COLLATE "C", l.id`, b.ID, b.KVCertificateID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the binding's websites: %w", err)
	}
	defer rows.Close()
	out := []BindingLocation{}
	for rows.Next() {
		var (
			l                          BindingLocation
			pending, latest            *uuid.UUID
			latestStatus, served, done string
		)
		if err := rows.Scan(&l.LocationID, &l.TargetID, &l.TargetName, &l.CertPath, &pending, &latest, &latestStatus, &served, &done,
			&l.AttentionCode); err != nil {
			return nil, fmt.Errorf("inventory: read a binding website: %w", err)
		}
		deployed := served
		if deployed == "" {
			deployed = done
		}
		l.DeploymentID = latest
		switch {
		case pending != nil:
			l.State, l.DeploymentID = BindingLocationPending, pending
		case deployed != "" && deployed == current:
			l.State, l.Version = BindingLocationDeployed, deployed
		case b.StoppedVersion != "" && b.StoppedVersion == current:
			l.State = BindingLocationStopped
		case latest != nil && !slices.Contains([]string{DeployStatusSucceeded, DeployStatusUnchanged}, latestStatus):
			l.State = BindingLocationFailed
		case deployed != "":
			l.State, l.Version = BindingLocationDeployed, deployed
		default:
			l.State = BindingLocationNotDeployed
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListBindings pages live bindings (newest first), optionally of one vault or one certificate. The
// items carry counts, not websites.
func (s *Service) ListBindings(ctx context.Context, f BindingFilter) (BindingPage, error) {
	var errs validate.Errors
	limit := f.Limit
	switch {
	case limit == 0:
		limit = 50
	case limit < 1 || limit > 200:
		errs.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": "200"})
	}
	var afterAt *time.Time
	afterID := uuid.Nil
	if f.Cursor != "" {
		at, id, err := decodeCursor(f.Cursor)
		if err != nil {
			errs.Add("cursor", validate.Pattern, nil)
		} else {
			afterAt, afterID = &at, id
		}
	}
	if len(errs) > 0 {
		return BindingPage{}, errs
	}
	rows, err := s.pool.Query(ctx, bindingColumns+`
WHERE b.deleted_at IS NULL AND ($1::uuid IS NULL OR b.kv_target_id = $1) AND ($2::uuid IS NULL OR b.kv_certificate_id = $2)
  AND ($3::timestamptz IS NULL OR (b.created_at, b.id) < ($3::timestamptz, $4::uuid))
ORDER BY b.created_at DESC, b.id DESC LIMIT $5`, nullID(f.VaultID), nullID(f.KVCertificateID), afterAt, afterID, limit+1)
	if err != nil {
		return BindingPage{}, fmt.Errorf("inventory: list bindings: %w", err)
	}
	defer rows.Close()
	page := BindingPage{Items: []Binding{}}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return BindingPage{}, err
		}
		page.Items = append(page.Items, b)
	}
	if err := rows.Err(); err != nil {
		return BindingPage{}, fmt.Errorf("inventory: list bindings: %w", err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	return page, nil
}
