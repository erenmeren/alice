package oidc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/auth/oidc/claims"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Mapping gives the members of one group of a provider a role (SEC-014).
type Mapping struct {
	ID         uuid.UUID
	ProviderID uuid.UUID
	Group      string
	Role       rbac.Role
	CreatedAt  time.Time
}

// mappingError turns a claims validation error into the API's field error.
func mappingError(err error) error {
	switch {
	case errors.Is(err, claims.ErrGroupEmpty):
		return validate.Errors{{Field: "group", Code: validate.Required}}
	case errors.Is(err, claims.ErrGroupTooLong):
		return validate.Errors{{Field: "group", Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(claims.MaxGroupRunes)}}}
	case errors.Is(err, claims.ErrRole):
		return validate.Errors{{Field: "role", Code: validate.OneOf, Params: map[string]string{"values": "admin, operator, auditor"}}}
	default:
		return validate.Errors{{Field: "group", Code: validate.Pattern}}
	}
}

// Mappings lists a provider's group mappings by group value.
func (s *Service) Mappings(ctx context.Context, providerID uuid.UUID) ([]Mapping, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, provider_id, group_claim_value, role, created_at FROM oidc_group_mappings
WHERE provider_id = $1 ORDER BY group_claim_value`, providerID)
	if err != nil {
		return nil, fmt.Errorf("oidc: list group mappings: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Mapping, error) {
		var m Mapping
		var role string
		err := r.Scan(&m.ID, &m.ProviderID, &m.Group, &role, &m.CreatedAt)
		m.Role, m.CreatedAt = rbac.Role(role), m.CreatedAt.UTC()
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: list group mappings: %w", err)
	}
	return out, nil
}

func mappingDetails(m Mapping) map[string]string {
	return map[string]string{"mapping_id": m.ID.String(), "provider_id": m.ProviderID.String(), "group": m.Group, "role": string(m.Role)}
}

// groupMappingConstraint is the unique constraint on (provider_id, group_claim_value) of oidc_group_mappings
// (migrations/00011_alerts_dashboard_sso.sql); only its violation is a duplicate group (review L-14).
const groupMappingConstraint = "oidc_group_mappings_provider_id_group_claim_value_key"

// CreateMapping maps a group of a provider to a role. Administrator is refused while "SSO users may be Admin" is
// off (ErrAdminMappingDisabled, audited as sso.mapping.denied); the switch row is locked first (S-5). A group is
// mapped once per provider.
func (s *Service) CreateMapping(ctx context.Context, a audit.Actor, providerID uuid.UUID, group string, role rbac.Role) (Mapping, error) {
	m := Mapping{ID: uuid.Must(uuid.NewV7()), ProviderID: providerID, Group: group, Role: role, CreatedAt: s.clock.Now().UTC()}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		sw, err := s.lockSwitch(ctx, tx)
		if err != nil {
			return err
		}
		if err := claims.ValidateMapping(claims.Mapping{Group: group, Role: role}, sw.Allow); errors.Is(err, claims.ErrAdminNotAllowed) {
			return ErrAdminMappingDisabled
		} else if err != nil {
			return mappingError(err)
		}
		var n int
		var exists, dup bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM oidc_providers WHERE id = $1),
(SELECT count(*) FROM oidc_group_mappings WHERE provider_id = $1),
EXISTS (SELECT 1 FROM oidc_group_mappings WHERE provider_id = $1 AND group_claim_value = $2)`, providerID, group).Scan(&exists, &n, &dup); err != nil {
			return fmt.Errorf("oidc: read the group mappings: %w", err)
		}
		switch {
		case !exists:
			return ErrNotFound
		case dup:
			return validate.Errors{{Field: "group", Code: validate.Duplicate}}
		case n >= MaxMappings:
			return ErrTooMany
		}
		if _, err := tx.Exec(ctx, `INSERT INTO oidc_group_mappings (id, provider_id, group_claim_value, role, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6)`, m.ID, providerID, group, string(role), userID(a), m.CreatedAt); err != nil {
			if db.IsUniqueViolationOn(err, groupMappingConstraint) {
				return validate.Errors{{Field: "group", Code: validate.Duplicate}}
			}
			return fmt.Errorf("oidc: store the group mapping: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "sso.mapping_created", ObjectType: "oidc_group_mapping",
			ObjectID: m.ID.String(), Result: audit.Success, Details: mappingDetails(m)})
		return err
	})
	if errors.Is(err, ErrAdminMappingDisabled) {
		if aerr := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
			_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "sso.mapping.denied", ObjectType: "oidc_group_mapping",
				Result: audit.Denied, Details: map[string]string{"provider_id": providerID.String(), "group": group, "role": string(role),
					"reason": "admin_disabled"}})
			return err
		}); aerr != nil {
			return Mapping{}, aerr
		}
	}
	if err != nil {
		return Mapping{}, err
	}
	return m, nil
}

// DeleteMapping removes a group mapping, audited as sso.mapping_deleted.
func (s *Service) DeleteMapping(ctx context.Context, a audit.Actor, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var m Mapping
		var role string
		err := tx.QueryRow(ctx, "DELETE FROM oidc_group_mappings WHERE id = $1 RETURNING id, provider_id, group_claim_value, role", id).
			Scan(&m.ID, &m.ProviderID, &m.Group, &role)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("oidc: delete the group mapping: %w", err)
		}
		m.Role = rbac.Role(role)
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "sso.mapping_deleted", ObjectType: "oidc_group_mapping",
			ObjectID: id.String(), Result: audit.Success, Details: mappingDetails(m)})
		return err
	})
}

// mappingsFor returns a provider's mappings as claims.Mapping values for ResolveRole.
func mappingsFor(ctx context.Context, q db.Querier, providerID uuid.UUID) ([]claims.Mapping, error) {
	rows, err := q.Query(ctx, "SELECT group_claim_value, role FROM oidc_group_mappings WHERE provider_id = $1", providerID)
	if err != nil {
		return nil, fmt.Errorf("oidc: read the group mappings: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (claims.Mapping, error) {
		var m claims.Mapping
		var role string
		err := r.Scan(&m.Group, &role)
		m.Role = rbac.Role(role)
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: read the group mappings: %w", err)
	}
	return out, nil
}
