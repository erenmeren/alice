package ldap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/auth/oidc/claims"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// MaxGroupRunes is the longest group value: a group DN may be as long as the DN settings (migrations/00015_ldap.sql).
const MaxGroupRunes = 1024

// groupMappingConstraint is the unique constraint on (directory_id, group_value) of ldap_group_mappings.
const groupMappingConstraint = "ldap_group_mappings_directory_id_group_value_key"

// Mapping gives the members of one directory group a role. Group is the value exactly as the group search returns
// it (a DN, or the group name attribute's value); matching is exact and case-sensitive.
type Mapping struct {
	ID          uuid.UUID
	DirectoryID uuid.UUID
	Group       string
	Role        rbac.Role
	CreatedAt   time.Time
}

// validateMapping refuses an empty group, white space at its ends or invisible characters, a group longer than
// MaxGroupRunes, an unknown role and Administrator while the switch is off (claims.ValidateMapping's rules with the
// directory's longer limit).
func validateMapping(group string, role rbac.Role, adminAllowed bool) error {
	switch {
	case strings.TrimSpace(group) == "":
		return validate.Errors{{Field: "group", Code: validate.Required}}
	case !utf8.ValidString(group) || group != strings.TrimSpace(group) ||
		strings.IndexFunc(group, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError }) >= 0:
		return validate.Errors{{Field: "group", Code: validate.Pattern}}
	case utf8.RuneCountInString(group) > MaxGroupRunes:
		return validate.Errors{{Field: "group", Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(MaxGroupRunes)}}}
	}
	// The role and the switch: claims' rule, with a short stand-in group (its length rule is the OIDC one).
	switch err := claims.ValidateMapping(claims.Mapping{Group: "g", Role: role}, adminAllowed); {
	case errors.Is(err, claims.ErrAdminNotAllowed):
		return ErrAdminMappingDisabled
	case err != nil:
		return validate.Errors{{Field: "role", Code: validate.OneOf, Params: map[string]string{"values": "admin, operator, auditor"}}}
	}
	return nil
}

// Mappings lists a directory's group mappings by group value.
func (s *Service) Mappings(ctx context.Context, directoryID uuid.UUID) ([]Mapping, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, directory_id, group_value, role, created_at FROM ldap_group_mappings
WHERE directory_id = $1 ORDER BY group_value`, directoryID)
	if err != nil {
		return nil, fmt.Errorf("ldap: list group mappings: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Mapping, error) {
		var m Mapping
		var role string
		err := r.Scan(&m.ID, &m.DirectoryID, &m.Group, &role, &m.CreatedAt)
		m.Role, m.CreatedAt = rbac.Role(role), m.CreatedAt.UTC()
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("ldap: list group mappings: %w", err)
	}
	return out, nil
}

func mappingDetails(m Mapping) map[string]string {
	return map[string]string{"mapping_id": m.ID.String(), "directory_id": m.DirectoryID.String(), "group": m.Group, "role": string(m.Role)}
}

// switchValue is the stored "SSO users may be Admin" setting (AllowAdminKey); absent means off.
type switchValue struct {
	Allow   bool `json:"allow"`
	Version int  `json:"version"`
}

// lockSwitch creates the switch row when it is missing and locks it FOR UPDATE, exactly as the oidc package does: an
// Admin mapping and the switch-off are serialized.
func (s *Service) lockSwitch(ctx context.Context, tx pgx.Tx) (switchValue, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ($1, '{"allow": false, "version": 0}', $2)
ON CONFLICT (key) DO NOTHING`, AllowAdminKey, s.clock.Now().UTC()); err != nil {
		return switchValue{}, fmt.Errorf("ldap: create the Admin switch: %w", err)
	}
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT value FROM settings WHERE key = $1 FOR UPDATE", AllowAdminKey).Scan(&raw); err != nil {
		return switchValue{}, fmt.Errorf("ldap: lock the Admin switch: %w", err)
	}
	var v switchValue
	if err := json.Unmarshal(raw, &v); err != nil {
		return switchValue{}, fmt.Errorf("ldap: read the Admin switch: %w", err)
	}
	return v, nil
}

// adminAllowed reads the switch without a lock (role resolution before a sign-in; internal/auth caps the role again
// under the lock).
func (s *Service) adminAllowed(ctx context.Context, q db.Querier) (bool, error) {
	var v switchValue
	if _, err := settings.Get(ctx, q, AllowAdminKey, &v); err != nil {
		return false, err
	}
	return v.Allow, nil
}

// CreateMapping maps a directory group to a role. Administrator is refused while "SSO users may be Admin" is off
// (ErrAdminMappingDisabled, audited as ldap.mapping.denied); the switch row is locked first. A group is mapped once
// per directory, at most MaxMappings per directory.
func (s *Service) CreateMapping(ctx context.Context, a audit.Actor, directoryID uuid.UUID, group string, role rbac.Role) (Mapping, error) {
	m := Mapping{ID: uuid.Must(uuid.NewV7()), DirectoryID: directoryID, Group: group, Role: role, CreatedAt: s.clock.Now().UTC()}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		sw, err := s.lockSwitch(ctx, tx)
		if err != nil {
			return err
		}
		if err := validateMapping(group, role, sw.Allow); err != nil {
			return err
		}
		var n int
		var exists, dup bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ldap_directories WHERE id = $1),
(SELECT count(*) FROM ldap_group_mappings WHERE directory_id = $1),
EXISTS (SELECT 1 FROM ldap_group_mappings WHERE directory_id = $1 AND group_value = $2)`, directoryID, group).Scan(&exists, &n, &dup); err != nil {
			return fmt.Errorf("ldap: read the group mappings: %w", err)
		}
		switch {
		case !exists:
			return ErrNotFound
		case dup:
			return validate.Errors{{Field: "group", Code: validate.Duplicate}}
		case n >= MaxMappings:
			return ErrTooMany
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ldap_group_mappings (id, directory_id, group_value, role, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6)`, m.ID, directoryID, group, string(role), userID(a), m.CreatedAt); err != nil {
			if db.IsUniqueViolationOn(err, groupMappingConstraint) {
				return validate.Errors{{Field: "group", Code: validate.Duplicate}}
			}
			if pg := (*pgconn.PgError)(nil); errors.As(err, &pg) && pg.Code == foreignKeyCode {
				return ErrNotFound // deleted since the check
			}
			return fmt.Errorf("ldap: store the group mapping: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "ldap.mapping_created", ObjectType: "ldap_group_mapping",
			ObjectID: m.ID.String(), Result: audit.Success, Details: mappingDetails(m)})
		return err
	})
	if errors.Is(err, ErrAdminMappingDisabled) {
		if aerr := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
			_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "ldap.mapping.denied", ObjectType: "ldap_group_mapping",
				Result: audit.Denied, Details: map[string]string{"directory_id": directoryID.String(), "group": group, "role": string(role),
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

// DeleteMapping removes a group mapping, audited as ldap.mapping_deleted.
func (s *Service) DeleteMapping(ctx context.Context, a audit.Actor, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var m Mapping
		var role string
		err := tx.QueryRow(ctx, "DELETE FROM ldap_group_mappings WHERE id = $1 RETURNING id, directory_id, group_value, role", id).
			Scan(&m.ID, &m.DirectoryID, &m.Group, &role)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("ldap: delete the group mapping: %w", err)
		}
		m.Role = rbac.Role(role)
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "ldap.mapping_deleted", ObjectType: "ldap_group_mapping",
			ObjectID: id.String(), Result: audit.Success, Details: mappingDetails(m)})
		return err
	})
}

// mappingsFor returns a directory's mappings as claims.Mapping values for ResolveRole.
func mappingsFor(ctx context.Context, q db.Querier, directoryID uuid.UUID) ([]claims.Mapping, error) {
	rows, err := q.Query(ctx, "SELECT group_value, role FROM ldap_group_mappings WHERE directory_id = $1", directoryID)
	if err != nil {
		return nil, fmt.Errorf("ldap: read the group mappings: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (claims.Mapping, error) {
		var m claims.Mapping
		var role string
		err := r.Scan(&m.Group, &role)
		m.Role = rbac.Role(role)
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("ldap: read the group mappings: %w", err)
	}
	return out, nil
}
