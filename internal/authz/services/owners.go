package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/authz"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// MaxOwnersPerService bounds a service's owner team (design §4.1).
const MaxOwnersPerService = 50

// ErrOwnersVersion: the service changed since the caller read its owners (the body's version is not the service's).
var ErrOwnersVersion = errors.New("services: the service changed since its owners were read")

// OwnerNotAPersonError refuses an automation account as an owner (design §7.1: owners are people and directory
// groups); Field names the entry (owners.N.user_id).
type OwnerNotAPersonError struct{ Field string }

func (e *OwnerNotAPersonError) Error() string {
	return "services: an automation account cannot own a service: " + e.Field
}

// Owner is one entry of a service's owner team (R56, design §7.1): a person or a directory group. Ownership gives no
// access: owners receive the service's e-mails (design §7.2) and are shown as responsible.
type Owner struct {
	ID          uuid.UUID
	UserID      *uuid.UUID
	Username    string // the person's
	DisplayName string
	Disabled    bool // the person is disabled: receives nothing
	HasEmail    bool // the person has an address: receives the e-mails
	// DirectoryGroupID and Group name a group owner; Members counts the people of its provider or directory who were in
	// it at their last sign-in (receivers: those enabled with an address).
	DirectoryGroupID *uuid.UUID
	Group            *GroupRef
	Members          int
	// ReachesService: a person holds a role that reaches the service (globally, by a binding, through a group); a group
	// has a binding on the service or its environment, or is mapped to a global role. The editor warns when not.
	ReachesService bool
	CreatedAt      time.Time
}

// Owners is a service's owner team and the service's version, which a change names.
type Owners struct {
	Version int
	Items   []Owner
}

// OwnerInput is one entry of a new owner team: a person (UserID) or a directory group (DirectoryGroupID).
type OwnerInput struct {
	UserID           uuid.UUID
	DirectoryGroupID uuid.UUID
}

const ownerSelect = `SELECT o.id, o.user_id, coalesce(u.username::text, ''), coalesce(u.display_name, ''), u.disabled_at IS NOT NULL,
    coalesce(u.email <> '', false), o.directory_group_id, coalesce(g.source, ''), coalesce(op.name, ld.name, ''), coalesce(g.value, ''),
    coalesce(g.label, ''),
    CASE WHEN g.id IS NULL THEN 0 ELSE (SELECT count(*) FROM user_directory_groups ug JOIN users m ON m.id = ug.user_id
     WHERE ug.value = g.value AND ((g.source = 'oidc' AND m.oidc_provider_id = g.oidc_provider_id)
                                OR (g.source = 'ldap' AND m.ldap_directory_id = g.ldap_directory_id))) END,
    g.id IS NOT NULL AND (
        EXISTS (SELECT 1 FROM role_bindings rb WHERE rb.directory_group_id = g.id
                AND (rb.service_id = o.service_id OR rb.environment_id = (SELECT environment_id FROM services WHERE id = o.service_id)))
        OR (g.source = 'oidc' AND EXISTS (SELECT 1 FROM oidc_group_mappings mp WHERE mp.provider_id = g.oidc_provider_id AND mp.group_claim_value = g.value))
        OR (g.source = 'ldap' AND EXISTS (SELECT 1 FROM ldap_group_mappings mp WHERE mp.directory_id = g.ldap_directory_id AND mp.group_value = g.value))),
    o.created_at
FROM service_owners o
LEFT JOIN users u ON u.id = o.user_id
LEFT JOIN directory_groups g ON g.id = o.directory_group_id
LEFT JOIN oidc_providers op ON op.id = g.oidc_provider_id
LEFT JOIN ldap_directories ld ON ld.id = g.ldap_directory_id
WHERE o.service_id = $1
ORDER BY o.directory_group_id IS NOT NULL, lower(coalesce(u.display_name, '')), lower(coalesce(u.username::text, '')), g.value, o.id`

// Owners reads a service's owner team: people first, by name, then groups by value. ErrNotFound.
func (s *Store) Owners(ctx context.Context, id uuid.UUID) (Owners, error) {
	return readOwners(ctx, s.pool, id)
}

func readOwners(ctx context.Context, q db.Querier, id uuid.UUID) (Owners, error) {
	var out Owners
	err := q.QueryRow(ctx, "SELECT version FROM services WHERE id = $1", id).Scan(&out.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Owners{}, ErrNotFound
	}
	if err != nil {
		return Owners{}, fmt.Errorf("services: read the service: %w", err)
	}
	rows, err := q.Query(ctx, ownerSelect, id)
	if err != nil {
		return Owners{}, fmt.Errorf("services: read the owners: %w", err)
	}
	out.Items, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Owner, error) {
		var (
			o                           Owner
			source, srcName, val, label string
		)
		err := r.Scan(&o.ID, &o.UserID, &o.Username, &o.DisplayName, &o.Disabled, &o.HasEmail, &o.DirectoryGroupID, &source, &srcName,
			&val, &label, &o.Members, &o.ReachesService, &o.CreatedAt)
		if o.DirectoryGroupID != nil {
			o.Group = &GroupRef{Source: source, SourceName: srcName, Value: val, Label: label}
		}
		o.CreatedAt = o.CreatedAt.UTC()
		return o, err
	})
	if err != nil {
		return Owners{}, fmt.Errorf("services: read the owners: %w", err)
	}
	// A person reaches the service through any of their grants (the global role, their bindings, their groups').
	for i, o := range out.Items {
		if o.UserID == nil {
			continue
		}
		var role *string
		if err := q.QueryRow(ctx, "SELECT role FROM users WHERE id = $1", *o.UserID).Scan(&role); err != nil {
			return Owners{}, fmt.Errorf("services: read the owner's role: %w", err)
		}
		if role != nil {
			out.Items[i].ReachesService = true
			continue
		}
		grants, err := authz.LoadGrants(ctx, q, *o.UserID)
		if err != nil {
			return Owners{}, err
		}
		for _, g := range grants {
			if slices.Contains(g.Services, id) {
				out.Items[i].ReachesService = true
				break
			}
		}
	}
	return out, nil
}

// SetOwners replaces a service's owner team as a whole (R56, design §7.1): at most MaxOwnersPerService entries, each a
// person (an automation account is refused, *OwnerNotAPersonError) or a declared directory group, each once. version
// is the service's version the caller read (ErrOwnersVersion when it is not the current one); a change raises it.
// Audit service.owners_changed with the entries added and removed; the same team changes nothing. An unknown person or
// group is a validation error on its field. ErrNotFound.
func (s *Store) SetOwners(ctx context.Context, a Actor, id uuid.UUID, version int, in []OwnerInput) (Owners, error) {
	var v validate.Errors
	if len(in) > MaxOwnersPerService {
		v.Add("owners", validate.TooLong, map[string]string{"max": strconv.Itoa(MaxOwnersPerService)})
		return Owners{}, v
	}
	for i, o := range in {
		field := "owners." + strconv.Itoa(i)
		switch {
		case o.UserID == uuid.Nil && o.DirectoryGroupID == uuid.Nil:
			v.Add(field+".user_id", validate.Required, nil)
		case o.UserID != uuid.Nil && o.DirectoryGroupID != uuid.Nil:
			v.Add(field+".directory_group_id", validate.Pattern, nil) // one owner per entry, never both
		case slices.Contains(in[:i], o):
			if o.UserID != uuid.Nil {
				v.Add(field+".user_id", validate.Duplicate, nil)
			} else {
				v.Add(field+".directory_group_id", validate.Duplicate, nil)
			}
		}
	}
	if err := v.Err(); err != nil {
		return Owners{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getService(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return ErrOwnersVersion
		}
		// Every person and group named exists (key-share locked, so neither is deleted before this commits).
		for i, o := range in {
			field := "owners." + strconv.Itoa(i)
			if o.UserID != uuid.Nil {
				var source string
				err := tx.QueryRow(ctx, "SELECT auth_source FROM users WHERE id = $1 FOR KEY SHARE", o.UserID).Scan(&source)
				if errors.Is(err, pgx.ErrNoRows) {
					return validate.Errors{{Field: field + ".user_id", Code: validate.Required}}
				}
				if err != nil {
					return fmt.Errorf("services: read the owner: %w", err)
				}
				if source == "automation" {
					return &OwnerNotAPersonError{Field: field + ".user_id"}
				}
				continue
			}
			var one int
			err := tx.QueryRow(ctx, "SELECT 1 FROM directory_groups WHERE id = $1 FOR KEY SHARE", o.DirectoryGroupID).Scan(&one)
			if errors.Is(err, pgx.ErrNoRows) {
				return validate.Errors{{Field: field + ".directory_group_id", Code: validate.Required}}
			}
			if err != nil {
				return fmt.Errorf("services: read the owner group: %w", err)
			}
		}
		rows, err := tx.Query(ctx, "SELECT user_id, directory_group_id FROM service_owners WHERE service_id = $1", id)
		if err != nil {
			return fmt.Errorf("services: read the owners: %w", err)
		}
		old, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (OwnerInput, error) {
			var u, g *uuid.UUID
			err := r.Scan(&u, &g)
			var o OwnerInput
			if u != nil {
				o.UserID = *u
			}
			if g != nil {
				o.DirectoryGroupID = *g
			}
			return o, err
		})
		if err != nil {
			return fmt.Errorf("services: read the owners: %w", err)
		}
		var added, removed []string
		for _, o := range in {
			if !slices.Contains(old, o) {
				added = append(added, ownerText(o))
			}
		}
		for _, o := range old {
			if !slices.Contains(in, o) {
				removed = append(removed, ownerText(o))
			}
		}
		if len(added) == 0 && len(removed) == 0 {
			return nil
		}
		now := s.clock.Now().UTC()
		for _, o := range old {
			if !slices.Contains(in, o) {
				if _, err := tx.Exec(ctx, `DELETE FROM service_owners WHERE service_id = $1 AND user_id IS NOT DISTINCT FROM $2
AND directory_group_id IS NOT DISTINCT FROM $3`, id, nullID(o.UserID), nullID(o.DirectoryGroupID)); err != nil {
					return fmt.Errorf("services: remove an owner: %w", err)
				}
			}
		}
		for _, o := range in {
			if slices.Contains(old, o) {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO service_owners (id, service_id, user_id, directory_group_id, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6)`, uuid.Must(uuid.NewV7()), id, nullID(o.UserID), nullID(o.DirectoryGroupID), a.createdBy(), now); err != nil {
				return fmt.Errorf("services: add an owner: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE services SET version = version + 1, updated_at = $2 WHERE id = $1", id, now); err != nil {
			return fmt.Errorf("services: change the service's version: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "service.owners_changed", "service", id, map[string]string{"name": cur.Name,
			"added": strings.Join(added, ","), "removed": strings.Join(removed, ","), "owner_count": strconv.Itoa(len(in))})
	})
	if err != nil {
		return Owners{}, err
	}
	return s.Owners(ctx, id)
}

// ownerText is an owner as the audit row names it: user:<id> or group:<id>.
func ownerText(o OwnerInput) string {
	if o.UserID != uuid.Nil {
		return "user:" + o.UserID.String()
	}
	return "group:" + o.DirectoryGroupID.String()
}

func nullID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
