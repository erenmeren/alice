// Package services keeps the services, environments, trusts and assignment of scoped access (R49, design
// docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md §4, §5.6, §8.1). Every change is a
// global Administrator's (services.manage, services.assign, services.trust: step-up, never a token) and writes its
// audit row in its own transaction.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// Errors of the services module (the API maps each to its ALC-SVC code).
var (
	ErrNotFound            = errors.New("services: service not found")
	ErrEnvironmentNotFound = errors.New("services: environment not found")
	ErrTrustNotFound       = errors.New("services: trust not found")
	ErrNameTaken           = errors.New("services: a service with this name exists")
	ErrEnvironmentKeyTaken = errors.New("services: an environment with this key exists")
	ErrDefaultProtected    = errors.New("services: the Default service cannot be deleted")
	ErrEnvironmentInUse    = errors.New("services: a service or a role binding uses the environment")
	ErrTrustExists         = errors.New("services: the trust exists")
	ErrVersionMismatch     = errors.New("services: the row changed since it was read")
	// ErrPolicyVersion: the policy changed since the caller read it (the body's version is not the current one).
	ErrPolicyVersion = errors.New("services: the policy changed since it was read")
	// ErrDomainsGlobalOnly: the policy's domains change, and the caller holds services.policy on the service only (a
	// service Administrator widening their own service's names would defeat the rule, design §7.3).
	ErrDomainsGlobalOnly = errors.New("services: the policy's domains are changed by a global Administrator only")
)

// NotEmptyError refuses deleting a service that still owns resources: how many of each kind.
type NotEmptyError struct {
	Counts Counts
}

func (e *NotEmptyError) Error() string { return "services: the service owns resources" }

// Bounds of design §4.1 (refused with validation.out_of_range).
const (
	MaxServices          = 500
	MaxEnvironments      = 50
	MaxTrustsPerService  = 200
	maxServiceNameRunes  = 100
	maxDescriptionRunes  = 500
	maxEnvironmentRunes  = 60
	maxEnvironmentSort   = 32767
	defaultPolicyVersion = 1
)

// Actor is the person who changes services: the audit identity and the user recorded as created_by.
type Actor struct {
	Audit  audit.Actor
	UserID uuid.UUID
}

func (a Actor) createdBy() *uuid.UUID {
	if a.UserID == uuid.Nil {
		return nil
	}
	return &a.UserID
}

// Store reads and changes services, environments and trusts.
type Store struct {
	pool  *pgxpool.Pool
	audit *audit.Log
	clock clock.Clock
}

// New returns a Store.
func New(pool *pgxpool.Pool, log *audit.Log, c clock.Clock) *Store {
	return &Store{pool: pool, audit: log, clock: c}
}

// Environment is one environment label and how many services carry it.
type Environment struct {
	ID        uuid.UUID
	Key       string
	Name      string
	Sort      int
	Version   int
	Services  int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Counts are the resources a service owns (live ones: a deleted server, ACME certificate or scan scope is history).
type Counts struct {
	Servers          int
	KeyVaults        int
	Certificates     int
	SigningRequests  int
	ACMECertificates int
	SSHKeys          int
	DiscoveryScopes  int
}

// Total is the sum of the counts.
func (c Counts) Total() int {
	return c.Servers + c.KeyVaults + c.Certificates + c.SigningRequests + c.ACMECertificates + c.SSHKeys + c.DiscoveryScopes
}

// Service is one service with its environment and the counts of what it owns.
type Service struct {
	ID            uuid.UUID
	Name          string
	Description   string
	Environment   *authz.EnvironmentRef
	IsDefault     bool
	PolicyVersion int
	Version       int
	Counts        Counts
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Ref is the service as a row shows it.
func (s Service) Ref() authz.ServiceRef {
	return authz.ServiceRef{ID: s.ID, Name: s.Name, Environment: s.Environment}
}

// Policy is one version of a service's policy (version 1 is the empty policy {"schema":1}; SetPolicy writes later ones).
type Policy struct {
	Version       int
	Document      json.RawMessage
	CreatedBy     *uuid.UUID
	CreatedByName string
	CreatedAt     time.Time
}

// validName reports whether a name has no control or format characters and no surrounding space.
func validName(name string) bool {
	if !utf8.ValidString(name) || name != strings.TrimSpace(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func checkName(v *validate.Errors, field, name string, max int) {
	switch n := utf8.RuneCountInString(name); {
	case strings.TrimSpace(name) == "":
		v.Add(field, validate.Required, nil)
	case n > max:
		v.Add(field, validate.TooLong, map[string]string{"max": strconv.Itoa(max)})
	case !validName(name):
		v.Add(field, validate.Pattern, nil)
	}
}

func checkDescription(v *validate.Errors, d string) {
	switch {
	case utf8.RuneCountInString(d) > maxDescriptionRunes:
		v.Add("description", validate.TooLong, map[string]string{"max": strconv.Itoa(maxDescriptionRunes)})
	case !validate.StorableText(d):
		v.Add("description", validate.Pattern, nil)
	}
}

func uniqueViolation(err error, constraint string) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == constraint
}

// Environments lists every environment by its order, then its key.
func (s *Store) Environments(ctx context.Context) ([]Environment, error) {
	rows, err := s.pool.Query(ctx, `SELECT e.id, e.key, e.name, e.sort, e.version, e.created_at, e.updated_at,
    (SELECT count(*) FROM services sv WHERE sv.environment_id = e.id)
FROM environments e ORDER BY e.sort, e.key`)
	if err != nil {
		return nil, fmt.Errorf("services: list the environments: %w", err)
	}
	return pgx.CollectRows(rows, scanEnvironment)
}

func scanEnvironment(r pgx.CollectableRow) (Environment, error) {
	var e Environment
	err := r.Scan(&e.ID, &e.Key, &e.Name, &e.Sort, &e.Version, &e.CreatedAt, &e.UpdatedAt, &e.Services)
	return e, err
}

func getEnvironment(ctx context.Context, q db.Querier, id uuid.UUID, lock bool) (Environment, error) {
	sql := `SELECT e.id, e.key, e.name, e.sort, e.version, e.created_at, e.updated_at,
    (SELECT count(*) FROM services sv WHERE sv.environment_id = e.id)
FROM environments e WHERE e.id = $1`
	if lock {
		sql += " FOR UPDATE"
	}
	rows, err := q.Query(ctx, sql, id)
	if err != nil {
		return Environment{}, fmt.Errorf("services: read the environment: %w", err)
	}
	e, err := pgx.CollectExactlyOneRow(rows, scanEnvironment)
	if errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, ErrEnvironmentNotFound
	}
	if err != nil {
		return Environment{}, fmt.Errorf("services: read the environment: %w", err)
	}
	return e, nil
}

// EnvironmentInput is a new environment.
type EnvironmentInput struct {
	Key  string
	Name string
	Sort int
}

// EnvironmentPatch changes an environment's name or order (its key is fixed: bindings and the UI's translations name it).
type EnvironmentPatch struct {
	Name *string
	Sort *int
}

func checkSort(v *validate.Errors, sort int) {
	if sort < 0 || sort > maxEnvironmentSort {
		v.Add("sort", validate.OutOfRange, map[string]string{"min": "0", "max": strconv.Itoa(maxEnvironmentSort)})
	}
}

// CreateEnvironment adds an environment (at most MaxEnvironments); audit environment.created. ErrEnvironmentKeyTaken.
func (s *Store) CreateEnvironment(ctx context.Context, a Actor, in EnvironmentInput) (Environment, error) {
	var v validate.Errors
	if !environmentKeyRE(in.Key) {
		v.Add("key", validate.Pattern, nil)
	}
	checkName(&v, "name", in.Name, maxEnvironmentRunes)
	checkSort(&v, in.Sort)
	if err := v.Err(); err != nil {
		return Environment{}, err
	}
	now := s.clock.Now().UTC()
	id := uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockTable(ctx, tx, "environments"); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM environments").Scan(&n); err != nil {
			return fmt.Errorf("services: count the environments: %w", err)
		}
		if n >= MaxEnvironments {
			return validate.Errors{{Field: "key", Code: validate.OutOfRange, Params: map[string]string{"min": "0", "max": strconv.Itoa(MaxEnvironments)}}}
		}
		_, err := tx.Exec(ctx, `INSERT INTO environments (id, key, name, sort, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5)`,
			id, in.Key, in.Name, in.Sort, now)
		if uniqueViolation(err, "environments_key_key") {
			return ErrEnvironmentKeyTaken
		}
		if err != nil {
			return fmt.Errorf("services: store the environment: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "environment.created", "environment", id, map[string]string{"environment": in.Key, "name": in.Name})
	})
	if err != nil {
		return Environment{}, err
	}
	return getEnvironment(ctx, s.pool, id, false)
}

// environmentKeyRE is environments.key's CHECK.
func environmentKeyRE(k string) bool {
	if len(k) < 1 || len(k) > 32 || k[0] < 'a' || k[0] > 'z' {
		return false
	}
	for i := 1; i < len(k); i++ {
		c := k[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// UpdateEnvironment renames or reorders an environment; audit environment.updated with the old and new values.
// ErrEnvironmentNotFound, ErrVersionMismatch.
func (s *Store) UpdateEnvironment(ctx context.Context, a Actor, id uuid.UUID, version int, p EnvironmentPatch) (Environment, error) {
	var v validate.Errors
	if p.Name != nil {
		checkName(&v, "name", *p.Name, maxEnvironmentRunes)
	}
	if p.Sort != nil {
		checkSort(&v, *p.Sort)
	}
	if err := v.Err(); err != nil {
		return Environment{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getEnvironment(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return ErrVersionMismatch
		}
		name, sort := cur.Name, cur.Sort
		details := map[string]string{"environment": cur.Key}
		if p.Name != nil && *p.Name != cur.Name {
			details["old_name"], details["name"] = cur.Name, *p.Name
			name = *p.Name
		}
		if p.Sort != nil && *p.Sort != cur.Sort {
			details["old_sort"], details["sort"] = strconv.Itoa(cur.Sort), strconv.Itoa(*p.Sort)
			sort = *p.Sort
		}
		if len(details) == 1 {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE environments SET name = $2, sort = $3, version = version + 1, updated_at = $4 WHERE id = $1`,
			id, name, sort, s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("services: change the environment: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "environment.updated", "environment", id, details)
	})
	if err != nil {
		return Environment{}, err
	}
	return getEnvironment(ctx, s.pool, id, false)
}

// DeleteEnvironment removes an environment no service and no role binding uses; audit environment.deleted.
// ErrEnvironmentNotFound, ErrVersionMismatch, ErrEnvironmentInUse.
func (s *Store) DeleteEnvironment(ctx context.Context, a Actor, id uuid.UUID, version int) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getEnvironment(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return ErrVersionMismatch
		}
		var used bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM services WHERE environment_id = $1)
    OR EXISTS (SELECT 1 FROM role_bindings WHERE environment_id = $1)`, id).Scan(&used); err != nil {
			return fmt.Errorf("services: read the environment's use: %w", err)
		}
		if used {
			return ErrEnvironmentInUse
		}
		if _, err := tx.Exec(ctx, "DELETE FROM environments WHERE id = $1", id); err != nil {
			return fmt.Errorf("services: delete the environment: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "environment.deleted", "environment", id, map[string]string{"environment": cur.Key, "name": cur.Name})
	})
}

// lockTable serializes the creations of one kind (the bounds are counted under it). SHARE ROW EXCLUSIVE conflicts
// with itself and with every row change, so two creations cannot both pass the count.
func lockTable(ctx context.Context, tx pgx.Tx, table string) error {
	if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{table}.Sanitize()+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return fmt.Errorf("services: lock %s: %w", table, err)
	}
	return nil
}

func (s *Store) appendAudit(ctx context.Context, tx pgx.Tx, a Actor, action, objectType string, id uuid.UUID, details map[string]string) error {
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: action, ObjectType: objectType, ObjectID: id.String(),
		Result: audit.Success, Details: details})
	return err
}

// serviceSelect reads Service rows (scanService's order) with the counts of what each owns.
const serviceSelect = `SELECT sv.id, sv.name::text, sv.description, sv.is_default, sv.policy_version, sv.version, sv.created_at, sv.updated_at,
    e.id, coalesce(e.key, ''), coalesce(e.name, ''),
    (SELECT count(*) FROM targets t WHERE t.service_id = sv.id AND t.deleted_at IS NULL AND t.type <> 'azure_key_vault'),
    (SELECT count(*) FROM targets t WHERE t.service_id = sv.id AND t.deleted_at IS NULL AND t.type = 'azure_key_vault'),
    (SELECT count(*) FROM certificates c WHERE c.service_id = sv.id),
    (SELECT count(*) FROM csr_requests r WHERE r.service_id = sv.id),
    (SELECT count(*) FROM acme_certificates ac WHERE ac.service_id = sv.id AND ac.deleted_at IS NULL),
    (SELECT count(*) FROM ssh_keys k WHERE k.service_id = sv.id),
    (SELECT count(*) FROM discovery_scopes ds WHERE ds.service_id = sv.id AND ds.deleted_at IS NULL)
FROM services sv LEFT JOIN environments e ON e.id = sv.environment_id`

func scanService(r pgx.CollectableRow) (Service, error) {
	var (
		sv      Service
		envID   *uuid.UUID
		key, nm string
	)
	err := r.Scan(&sv.ID, &sv.Name, &sv.Description, &sv.IsDefault, &sv.PolicyVersion, &sv.Version, &sv.CreatedAt, &sv.UpdatedAt,
		&envID, &key, &nm, &sv.Counts.Servers, &sv.Counts.KeyVaults, &sv.Counts.Certificates, &sv.Counts.SigningRequests,
		&sv.Counts.ACMECertificates, &sv.Counts.SSHKeys, &sv.Counts.DiscoveryScopes)
	if envID != nil {
		sv.Environment = &authz.EnvironmentRef{ID: *envID, Key: key, Name: nm}
	}
	return sv, err
}

// Services lists every service: the Default service first, then by name.
func (s *Store) Services(ctx context.Context) ([]Service, error) {
	rows, err := s.pool.Query(ctx, serviceSelect+" ORDER BY sv.is_default DESC, lower(sv.name::text), sv.id")
	if err != nil {
		return nil, fmt.Errorf("services: list the services: %w", err)
	}
	return pgx.CollectRows(rows, scanService)
}

// Service reads one service. ErrNotFound.
func (s *Store) Service(ctx context.Context, id uuid.UUID) (Service, error) {
	return getService(ctx, s.pool, id, false)
}

func getService(ctx context.Context, q db.Querier, id uuid.UUID, lock bool) (Service, error) {
	if lock {
		if _, err := q.Exec(ctx, "SELECT 1 FROM services WHERE id = $1 FOR UPDATE", id); err != nil {
			return Service{}, fmt.Errorf("services: lock the service: %w", err)
		}
	}
	rows, err := q.Query(ctx, serviceSelect+" WHERE sv.id = $1", id)
	if err != nil {
		return Service{}, fmt.Errorf("services: read the service: %w", err)
	}
	sv, err := pgx.CollectExactlyOneRow(rows, scanService)
	if errors.Is(err, pgx.ErrNoRows) {
		return Service{}, ErrNotFound
	}
	if err != nil {
		return Service{}, fmt.Errorf("services: read the service: %w", err)
	}
	return sv, nil
}

// Refs is every service as rows show it, by id (at most MaxServices: the API reads it once per answer).
func (s *Store) Refs(ctx context.Context) (map[uuid.UUID]authz.ServiceRef, error) {
	return readRefs(ctx, s.pool)
}

func readRefs(ctx context.Context, q db.Querier) (map[uuid.UUID]authz.ServiceRef, error) {
	rows, err := q.Query(ctx, `SELECT sv.id, sv.name::text, e.id, coalesce(e.key, ''), coalesce(e.name, '')
FROM services sv LEFT JOIN environments e ON e.id = sv.environment_id`)
	if err != nil {
		return nil, fmt.Errorf("services: read the services: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]authz.ServiceRef{}
	for rows.Next() {
		var (
			ref     authz.ServiceRef
			envID   *uuid.UUID
			key, nm string
		)
		if err := rows.Scan(&ref.ID, &ref.Name, &envID, &key, &nm); err != nil {
			return nil, fmt.Errorf("services: read a service: %w", err)
		}
		if envID != nil {
			ref.Environment = &authz.EnvironmentRef{ID: *envID, Key: key, Name: nm}
		}
		out[ref.ID] = ref
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("services: read the services: %w", err)
	}
	return out, nil
}

// ServiceInput is a new service.
type ServiceInput struct {
	Name          string
	Description   string
	EnvironmentID *uuid.UUID
}

// ServicePatch changes a service's name, description or environment (SetEnvironment with EnvironmentID nil removes it).
// Relabelling changes which environment bindings reach the service, so it is audited with both environments.
type ServicePatch struct {
	Name           *string
	Description    *string
	SetEnvironment bool
	EnvironmentID  *uuid.UUID
}

// checkEnvironment refuses an unknown environment as an unknown reference (422 on the field).
func checkEnvironment(ctx context.Context, q db.Querier, id *uuid.UUID) error {
	if id == nil {
		return nil
	}
	var one int
	err := q.QueryRow(ctx, "SELECT 1 FROM environments WHERE id = $1 FOR KEY SHARE", *id).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return validate.Errors{{Field: "environment_id", Code: validate.Required}}
	}
	if err != nil {
		return fmt.Errorf("services: read the environment: %w", err)
	}
	return nil
}

// CreateService adds a service (at most MaxServices) with its policy version 1; audit service.created. ErrNameTaken.
func (s *Store) CreateService(ctx context.Context, a Actor, in ServiceInput) (Service, error) {
	var v validate.Errors
	checkName(&v, "name", in.Name, maxServiceNameRunes)
	checkDescription(&v, in.Description)
	if err := v.Err(); err != nil {
		return Service{}, err
	}
	now := s.clock.Now().UTC()
	id := uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkEnvironment(ctx, tx, in.EnvironmentID); err != nil {
			return err
		}
		if err := lockTable(ctx, tx, "services"); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM services").Scan(&n); err != nil {
			return fmt.Errorf("services: count the services: %w", err)
		}
		if n >= MaxServices {
			return validate.Errors{{Field: "name", Code: validate.OutOfRange, Params: map[string]string{"min": "0", "max": strconv.Itoa(MaxServices)}}}
		}
		_, err := tx.Exec(ctx, `INSERT INTO services (id, name, description, environment_id, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $6)`, id, in.Name, in.Description, in.EnvironmentID, a.createdBy(), now)
		if uniqueViolation(err, "services_name") {
			return ErrNameTaken
		}
		if err != nil {
			return fmt.Errorf("services: store the service: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO service_policies (service_id, version, body, created_by, created_at) VALUES ($1, $2, '{"schema":1}', $3, $4)`,
			id, defaultPolicyVersion, a.createdBy(), now); err != nil {
			return fmt.Errorf("services: store the service's policy: %w", err)
		}
		details := map[string]string{"name": in.Name}
		if in.EnvironmentID != nil {
			details["environment_id"] = in.EnvironmentID.String()
		}
		return s.appendAudit(ctx, tx, a, "service.created", "service", id, details)
	})
	if err != nil {
		return Service{}, err
	}
	return s.Service(ctx, id)
}

// UpdateService changes a service; audit service.updated with each changed field's old and new value.
// ErrNotFound, ErrVersionMismatch, ErrNameTaken.
func (s *Store) UpdateService(ctx context.Context, a Actor, id uuid.UUID, version int, p ServicePatch) (Service, error) {
	var v validate.Errors
	if p.Name != nil {
		checkName(&v, "name", *p.Name, maxServiceNameRunes)
	}
	if p.Description != nil {
		checkDescription(&v, *p.Description)
	}
	if err := v.Err(); err != nil {
		return Service{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getService(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return ErrVersionMismatch
		}
		name, desc := cur.Name, cur.Description
		var env *uuid.UUID
		if cur.Environment != nil {
			env = &cur.Environment.ID
		}
		details := map[string]string{}
		if p.Name != nil && *p.Name != cur.Name {
			details["old_name"], details["name"] = cur.Name, *p.Name
			name = *p.Name
		}
		if p.Description != nil && *p.Description != cur.Description {
			details["description_changed"] = "true"
			desc = *p.Description
		}
		if p.SetEnvironment && !sameEnvironment(env, p.EnvironmentID) {
			if err := checkEnvironment(ctx, tx, p.EnvironmentID); err != nil {
				return err
			}
			details["old_environment_id"], details["environment_id"] = idText(env), idText(p.EnvironmentID)
			env = p.EnvironmentID
		}
		if len(details) == 0 {
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE services SET name = $2, description = $3, environment_id = $4, version = version + 1, updated_at = $5
WHERE id = $1`, id, name, desc, env, s.clock.Now().UTC())
		if uniqueViolation(err, "services_name") {
			return ErrNameTaken
		}
		if err != nil {
			return fmt.Errorf("services: change the service: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "service.updated", "service", id, details)
	})
	if err != nil {
		return Service{}, err
	}
	return s.Service(ctx, id)
}

func sameEnvironment(a, b *uuid.UUID) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func idText(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// DeleteService removes a service that owns no live resource (its deleted servers, ACME certificates and scan scopes
// are history: they move to the Default service); its policy history, trusts, bindings and owner entries go with it;
// audit service.deleted. ErrNotFound, ErrVersionMismatch, ErrDefaultProtected, *NotEmptyError.
func (s *Store) DeleteService(ctx context.Context, a Actor, id uuid.UUID, version int) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getService(ctx, tx, id, true)
		if err != nil {
			return err
		}
		switch {
		case cur.Version != version:
			return ErrVersionMismatch
		case cur.IsDefault:
			return ErrDefaultProtected
		case cur.Counts.Total() > 0:
			return &NotEmptyError{Counts: cur.Counts}
		}
		var moved int64
		for _, table := range []string{"targets", "acme_certificates", "discovery_scopes"} {
			tag, err := tx.Exec(ctx, "UPDATE "+table+" SET service_id = default_service_id() WHERE service_id = $1", id)
			if err != nil {
				return fmt.Errorf("services: move the history of %s: %w", table, err)
			}
			moved += tag.RowsAffected()
		}
		if _, err := tx.Exec(ctx, "DELETE FROM services WHERE id = $1", id); err != nil {
			return fmt.Errorf("services: delete the service: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "service.deleted", "service", id, map[string]string{"name": cur.Name,
			"history_moved_count": strconv.FormatInt(moved, 10)})
	})
}

// Policy reads a service's current policy. ErrNotFound.
func (s *Store) Policy(ctx context.Context, id uuid.UUID) (Policy, error) {
	rows, err := s.pool.Query(ctx, policySelect+" WHERE p.service_id = $1 AND p.version = (SELECT policy_version FROM services WHERE id = $1)", id)
	if err != nil {
		return Policy{}, fmt.Errorf("services: read the policy: %w", err)
	}
	p, err := pgx.CollectExactlyOneRow(rows, scanPolicy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("services: read the policy: %w", err)
	}
	return p, nil
}

// PolicyVersions lists every version of a service's policy, newest first. ErrNotFound.
func (s *Store) PolicyVersions(ctx context.Context, id uuid.UUID) ([]Policy, error) {
	if _, err := s.Service(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, policySelect+" WHERE p.service_id = $1 ORDER BY p.version DESC", id)
	if err != nil {
		return nil, fmt.Errorf("services: list the policy versions: %w", err)
	}
	return pgx.CollectRows(rows, scanPolicy)
}

const policySelect = `SELECT p.version, p.body, p.created_by, coalesce(u.display_name, ''), p.created_at
FROM service_policies p LEFT JOIN users u ON u.id = p.created_by`

func scanPolicy(r pgx.CollectableRow) (Policy, error) {
	var p Policy
	var body []byte
	err := r.Scan(&p.Version, &body, &p.CreatedBy, &p.CreatedByName, &p.CreatedAt)
	p.Document = body
	return p, err
}

// SetPolicy saves a new version of a service's policy (R55, design §7.3): body is the whole document (authz.ParsePolicy:
// validate.Errors, authz.ErrPolicyMalformed, *authz.FieldUnavailableError), version the policy version the caller read
// (ErrPolicyVersion when it is not the current one). The domains change only with domainsGlobal (the caller holds a
// global grant; ErrDomainsGlobalOnly otherwise). Every ACME provider named must exist (a field error otherwise). The
// version is stored as policy_version + 1 with the caller as its author, and audited service.policy_changed with the
// top-level keys that changed; a document equal to the current one stores nothing and answers the current version.
// ErrNotFound.
func (s *Store) SetPolicy(ctx context.Context, a Actor, id uuid.UUID, version int, body json.RawMessage, domainsGlobal bool) (Policy, error) {
	next, err := authz.ParsePolicy(body, "body.")
	if err != nil {
		return Policy{}, err
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getService(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.PolicyVersion != version {
			return ErrPolicyVersion
		}
		old, err := authz.LoadPolicy(ctx, tx, id)
		if err != nil {
			return err
		}
		if !domainsGlobal && !authz.SameDomains(old, next) {
			return ErrDomainsGlobalOnly
		}
		if err := checkPolicyProviders(ctx, tx, next); err != nil {
			return err
		}
		keys := authz.ChangedKeys(old, next)
		if len(keys) == 0 {
			return nil
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO service_policies (service_id, version, body, created_by, created_at) VALUES ($1, $2, $3, $4, $5)`,
			id, version+1, []byte(next.Document()), a.createdBy(), now); err != nil {
			return fmt.Errorf("services: store the policy: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE services SET policy_version = $2 WHERE id = $1", id, version+1); err != nil {
			return fmt.Errorf("services: change the policy version: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "service.policy_changed", "service", id, map[string]string{"name": cur.Name,
			"old_version": strconv.Itoa(version), "version": strconv.Itoa(version + 1), "fields": strings.Join(keys, ",")})
	})
	if err != nil {
		return Policy{}, err
	}
	return s.Policy(ctx, id)
}

// checkPolicyProviders refuses an ACME provider the policy names that does not exist (or was deleted), as an unknown
// reference: a field error on body.acme.providers.N. The rows are key-share locked, so a deletion waits for the save.
func checkPolicyProviders(ctx context.Context, tx pgx.Tx, p authz.Policy) error {
	if p.ACME == nil || len(p.ACME.Providers) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, "SELECT id FROM acme_providers WHERE id = ANY($1) AND deleted_at IS NULL FOR KEY SHARE", p.ACME.Providers)
	if err != nil {
		return fmt.Errorf("services: read the ACME providers: %w", err)
	}
	found, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return fmt.Errorf("services: read the ACME providers: %w", err)
	}
	var v validate.Errors
	for i, id := range p.ACME.Providers {
		if !slices.Contains(found, id) {
			v.Add("body.acme.providers."+strconv.Itoa(i), validate.Required, nil)
		}
	}
	return v.Err()
}
