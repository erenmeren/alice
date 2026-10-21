package services

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// Errors of the directory groups (R49 Phase 3, R54; the API maps each to its ALC-ACC code).
var (
	ErrDirectoryGroupNotFound = errors.New("services: directory group not found")
	ErrDirectoryGroupExists   = errors.New("services: the directory group is declared already")
)

// Directory group sources (directory_groups.source).
const (
	SourceOIDC = "oidc"
	SourceLDAP = "ldap"
)

// Bounds of the directory groups.
const (
	// MaxDirectoryGroups bounds the groups an installation declares (design §4.1 sets none; the bound keeps the Groups
	// tab and the binding form small).
	MaxDirectoryGroups = 1000
	// maxGroupValueRunes is the longest group value (the column's CHECK; an LDAP DN may be that long).
	maxGroupValueRunes = 1024
	maxGroupLabelRunes = 100
	// maxSeenGroups bounds the values seen at sign-in that the Groups tab offers, most members first.
	maxSeenGroups = 500
)

// DirectoryGroup is a group of an SSO provider or a directory that Alice refers to (design §6.1): role bindings and
// owner teams name it. Value is exactly what the provider's groups claim or the directory's group search returns
// (case-sensitive). Members counts the people of that provider or directory who were in the group at their last sign-in.
type DirectoryGroup struct {
	ID            uuid.UUID
	Source        string     // SourceOIDC or SourceLDAP
	ProviderID    *uuid.UUID // the SSO provider (SourceOIDC)
	DirectoryID   *uuid.UUID // the directory (SourceLDAP)
	SourceName    string     // the provider's or the directory's name
	Value         string
	Label         string
	Members       int
	Bindings      int
	CreatedBy     *uuid.UUID
	CreatedByName string
	CreatedAt     time.Time
}

// SeenGroup is a group value seen at the sign-ins of a provider or directory, with how many people had it, and the
// declared group of that value when there is one.
type SeenGroup struct {
	Source      string
	ProviderID  *uuid.UUID
	DirectoryID *uuid.UUID
	SourceName  string
	Value       string
	Users       int
	GroupID     *uuid.UUID
}

// DirectoryGroupInput declares a group: its source, the provider (SourceOIDC) or the directory (SourceLDAP), the value
// and an optional label.
type DirectoryGroupInput struct {
	Source      string
	ProviderID  *uuid.UUID
	DirectoryID *uuid.UUID
	Value       string
	Label       string
}

// GroupRemoval is what deleting a directory group took with it.
type GroupRemoval struct {
	Bindings int
	Owners   int
}

const groupSelect = `SELECT g.id, g.source, g.oidc_provider_id, g.ldap_directory_id, coalesce(op.name, ld.name, ''), g.value, g.label,
    (SELECT count(*) FROM user_directory_groups ug JOIN users u ON u.id = ug.user_id
     WHERE ug.value = g.value AND ((g.source = 'oidc' AND u.oidc_provider_id = g.oidc_provider_id)
                                OR (g.source = 'ldap' AND u.ldap_directory_id = g.ldap_directory_id))),
    (SELECT count(*) FROM role_bindings rb WHERE rb.directory_group_id = g.id),
    g.created_by, coalesce(cb.display_name, ''), g.created_at
FROM directory_groups g
LEFT JOIN oidc_providers op ON op.id = g.oidc_provider_id
LEFT JOIN ldap_directories ld ON ld.id = g.ldap_directory_id
LEFT JOIN users cb ON cb.id = g.created_by`

func scanGroup(r pgx.CollectableRow) (DirectoryGroup, error) {
	var g DirectoryGroup
	err := r.Scan(&g.ID, &g.Source, &g.ProviderID, &g.DirectoryID, &g.SourceName, &g.Value, &g.Label, &g.Members, &g.Bindings,
		&g.CreatedBy, &g.CreatedByName, &g.CreatedAt)
	g.CreatedAt = g.CreatedAt.UTC()
	return g, err
}

// DirectoryGroups lists the declared groups by provider or directory name, then value, and the values seen at sign-in
// (at most maxSeenGroups, most people first) for the form that declares one.
func (s *Store) DirectoryGroups(ctx context.Context) ([]DirectoryGroup, []SeenGroup, error) {
	rows, err := s.pool.Query(ctx, groupSelect+` ORDER BY lower(coalesce(op.name, ld.name, '')), g.value, g.id`)
	if err != nil {
		return nil, nil, fmt.Errorf("services: list the directory groups: %w", err)
	}
	groups, err := pgx.CollectRows(rows, scanGroup)
	if err != nil {
		return nil, nil, fmt.Errorf("services: list the directory groups: %w", err)
	}
	rows, err = s.pool.Query(ctx, `SELECT u.auth_source, u.oidc_provider_id, u.ldap_directory_id, coalesce(op.name, ld.name, ''), ug.value,
    count(*), (SELECT g.id FROM directory_groups g WHERE g.value = ug.value AND g.source = u.auth_source
               AND g.oidc_provider_id IS NOT DISTINCT FROM u.oidc_provider_id AND g.ldap_directory_id IS NOT DISTINCT FROM u.ldap_directory_id)
FROM user_directory_groups ug JOIN users u ON u.id = ug.user_id
LEFT JOIN oidc_providers op ON op.id = u.oidc_provider_id
LEFT JOIN ldap_directories ld ON ld.id = u.ldap_directory_id
WHERE u.auth_source IN ('oidc', 'ldap')
GROUP BY u.auth_source, u.oidc_provider_id, u.ldap_directory_id, op.name, ld.name, ug.value
ORDER BY count(*) DESC, ug.value LIMIT $1`, maxSeenGroups)
	if err != nil {
		return nil, nil, fmt.Errorf("services: list the groups seen at sign-in: %w", err)
	}
	seen, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (SeenGroup, error) {
		var g SeenGroup
		err := r.Scan(&g.Source, &g.ProviderID, &g.DirectoryID, &g.SourceName, &g.Value, &g.Users, &g.GroupID)
		return g, err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("services: list the groups seen at sign-in: %w", err)
	}
	return groups, seen, nil
}

// DirectoryGroup reads one declared group. ErrDirectoryGroupNotFound.
func (s *Store) DirectoryGroup(ctx context.Context, id uuid.UUID) (DirectoryGroup, error) {
	return getGroup(ctx, s.pool, id)
}

func getGroup(ctx context.Context, q db.Querier, id uuid.UUID) (DirectoryGroup, error) {
	rows, err := q.Query(ctx, groupSelect+" WHERE g.id = $1", id)
	if err != nil {
		return DirectoryGroup{}, fmt.Errorf("services: read the directory group: %w", err)
	}
	g, err := pgx.CollectExactlyOneRow(rows, scanGroup)
	if errors.Is(err, pgx.ErrNoRows) {
		return DirectoryGroup{}, ErrDirectoryGroupNotFound
	}
	if err != nil {
		return DirectoryGroup{}, fmt.Errorf("services: read the directory group: %w", err)
	}
	return g, nil
}

// invisibleRune is a character a group value cannot hold at its ends or anywhere (control, format, invalid).
func invisibleRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError
}

func checkGroupInput(in DirectoryGroupInput) validate.Errors {
	var v validate.Errors
	switch in.Source {
	case SourceOIDC:
		if in.ProviderID == nil {
			v.Add("provider_id", validate.Required, nil)
		}
		if in.DirectoryID != nil {
			v.Add("directory_id", validate.Pattern, nil) // the provider's group, not a directory's
		}
	case SourceLDAP:
		if in.DirectoryID == nil {
			v.Add("directory_id", validate.Required, nil)
		}
		if in.ProviderID != nil {
			v.Add("provider_id", validate.Pattern, nil)
		}
	default:
		v.Add("source", validate.OneOf, map[string]string{"values": "oidc, ldap"})
	}
	switch {
	case strings.TrimSpace(in.Value) == "":
		v.Add("value", validate.Required, nil)
	case !utf8.ValidString(in.Value) || in.Value != strings.TrimSpace(in.Value) || strings.IndexFunc(in.Value, invisibleRune) >= 0:
		v.Add("value", validate.Pattern, nil)
	case utf8.RuneCountInString(in.Value) > maxGroupValueRunes:
		v.Add("value", validate.TooLong, map[string]string{"max": strconv.Itoa(maxGroupValueRunes)})
	}
	switch {
	case !validate.StorableText(in.Label) || strings.IndexFunc(in.Label, unicode.IsControl) >= 0:
		v.Add("label", validate.Pattern, nil)
	case utf8.RuneCountInString(in.Label) > maxGroupLabelRunes:
		v.Add("label", validate.TooLong, map[string]string{"max": strconv.Itoa(maxGroupLabelRunes)})
	}
	return v
}

// CreateDirectoryGroup declares a group of an SSO provider or a directory (design §6.1; free text or a value seen at
// sign-in): the value under the rules of the group mappings (exact, case-sensitive, no white space at its ends, no
// invisible characters). An unknown provider or directory is a validation error on its field. Audit
// access.directory_group_added. ErrDirectoryGroupExists for the same value of the same provider or directory.
func (s *Store) CreateDirectoryGroup(ctx context.Context, a Actor, in DirectoryGroupInput) (DirectoryGroup, error) {
	if err := checkGroupInput(in).Err(); err != nil {
		return DirectoryGroup{}, err
	}
	id := uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockTable(ctx, tx, "directory_groups"); err != nil { // the bound counts one creation after the other
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM directory_groups").Scan(&n); err != nil {
			return fmt.Errorf("services: count the directory groups: %w", err)
		}
		if n >= MaxDirectoryGroups {
			return validate.Errors{{Field: "value", Code: validate.OutOfRange, Params: map[string]string{"min": "0", "max": strconv.Itoa(MaxDirectoryGroups)}}}
		}
		details := map[string]string{"source": in.Source, "value": in.Value}
		var exists bool
		switch in.Source {
		case SourceOIDC:
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM oidc_providers WHERE id = $1 FOR KEY SHARE)", *in.ProviderID).Scan(&exists); err != nil {
				return fmt.Errorf("services: read the SSO provider: %w", err)
			}
			if !exists {
				return validate.Errors{{Field: "provider_id", Code: validate.Required}}
			}
			details["provider_id"] = in.ProviderID.String()
		case SourceLDAP:
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM ldap_directories WHERE id = $1 FOR KEY SHARE)", *in.DirectoryID).Scan(&exists); err != nil {
				return fmt.Errorf("services: read the directory: %w", err)
			}
			if !exists {
				return validate.Errors{{Field: "directory_id", Code: validate.Required}}
			}
			details["directory_id"] = in.DirectoryID.String()
		}
		_, err := tx.Exec(ctx, `INSERT INTO directory_groups (id, source, oidc_provider_id, ldap_directory_id, value, label, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, in.Source, in.ProviderID, in.DirectoryID, in.Value, in.Label, a.createdBy(), s.clock.Now().UTC())
		if db.IsUniqueViolation(err) { // the only unique constraint besides the new id: source, provider or directory, value
			return ErrDirectoryGroupExists
		}
		if err != nil {
			return fmt.Errorf("services: store the directory group: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "access.directory_group_added", "directory_group", id, details)
	})
	if err != nil {
		return DirectoryGroup{}, err
	}
	return s.DirectoryGroup(ctx, id)
}

// DeleteDirectoryGroup removes a declared group with its role bindings and owner entries (the foreign keys cascade;
// design §8.1): the people it gave a role lose it at their next request. Audit access.directory_group_removed with the
// counts. ErrDirectoryGroupNotFound.
func (s *Store) DeleteDirectoryGroup(ctx context.Context, a Actor, id uuid.UUID) (GroupRemoval, error) {
	var out GroupRemoval
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var source, value string
		err := tx.QueryRow(ctx, "SELECT source, value FROM directory_groups WHERE id = $1 FOR UPDATE", id).Scan(&source, &value)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDirectoryGroupNotFound
		}
		if err != nil {
			return fmt.Errorf("services: lock the directory group: %w", err)
		}
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM role_bindings WHERE directory_group_id = $1),
    (SELECT count(*) FROM service_owners WHERE directory_group_id = $1)`, id).Scan(&out.Bindings, &out.Owners); err != nil {
			return fmt.Errorf("services: count what the directory group holds: %w", err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM directory_groups WHERE id = $1", id); err != nil {
			return fmt.Errorf("services: delete the directory group: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "access.directory_group_removed", "directory_group", id, map[string]string{"source": source,
			"value": value, "bindings_removed": strconv.Itoa(out.Bindings), "owners_removed": strconv.Itoa(out.Owners)})
	})
	return out, err
}
