package services

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/authz"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Errors of the role bindings (R49 Phase 2; the API maps each to its ALC-ACC code).
var (
	ErrBindingNotFound  = errors.New("services: role binding not found")
	ErrBindingDuplicate = errors.New("services: the subject holds this role there already")
	ErrBindingLimit     = errors.New("services: the subject holds the most role bindings allowed")
)

// MaxBindingsPerSubject bounds the bindings of one person (design §4.1).
const MaxBindingsPerSubject = 200

// Binding is a role a person holds on one service or on every service of an environment (design §4.1, §5.1). The
// global role is not a binding: it stays users.role. Directory group subjects come with Phase 3; a group binding
// written by other means is listed with its group id.
type Binding struct {
	ID               uuid.UUID
	UserID           *uuid.UUID
	Username         string // the person's user name ("" for a group binding)
	DisplayName      string
	DirectoryGroupID *uuid.UUID
	Role             rbac.Role
	Service          *authz.ServiceRef     // set for a binding on one service
	Environment      *authz.EnvironmentRef // set for a binding on an environment
	// Services are the services the binding covers at the time of reading: its service, or every service that carries
	// its environment now (an environment binding reaches a service created in that environment later at once).
	Services      []authz.ServiceRef
	CreatedBy     *uuid.UUID
	CreatedByName string
	CreatedAt     time.Time
}

// BindingFilter narrows Bindings; every set field must match. ServiceID also matches the environment bindings that
// reach the service through its environment (the service page's Access tab).
type BindingFilter struct {
	UserID           *uuid.UUID
	DirectoryGroupID *uuid.UUID
	ServiceID        *uuid.UUID
	EnvironmentID    *uuid.UUID
}

// BindingInput is a new binding: a person, a role and either a service or an environment.
type BindingInput struct {
	UserID        uuid.UUID
	Role          string
	ServiceID     *uuid.UUID
	EnvironmentID *uuid.UUID
}

const bindingSelect = `SELECT rb.id, rb.user_id, coalesce(u.username::text, ''), coalesce(u.display_name, ''), rb.directory_group_id,
    rb.role, rb.created_by, coalesce(cb.display_name, ''), rb.created_at,
    sv.id, coalesce(sv.name::text, ''), se.id, coalesce(se.key, ''), coalesce(se.name, ''),
    e.id, coalesce(e.key, ''), coalesce(e.name, ''),
    CASE WHEN rb.service_id IS NOT NULL THEN ARRAY[rb.service_id]
         ELSE ARRAY(SELECT s2.id FROM services s2 WHERE s2.environment_id = rb.environment_id) END
FROM role_bindings rb
LEFT JOIN users u ON u.id = rb.user_id
LEFT JOIN users cb ON cb.id = rb.created_by
LEFT JOIN services sv ON sv.id = rb.service_id LEFT JOIN environments se ON se.id = sv.environment_id
LEFT JOIN environments e ON e.id = rb.environment_id`

func scanBinding(r pgx.CollectableRow) (Binding, error) {
	var (
		b                  Binding
		role               string
		svID, svEnv, envID *uuid.UUID
		svName             string
		seKey, seName      string
		eKey, eName        string
		covered            []uuid.UUID
	)
	err := r.Scan(&b.ID, &b.UserID, &b.Username, &b.DisplayName, &b.DirectoryGroupID, &role, &b.CreatedBy, &b.CreatedByName, &b.CreatedAt,
		&svID, &svName, &svEnv, &seKey, &seName, &envID, &eKey, &eName, &covered)
	if err != nil {
		return Binding{}, err
	}
	b.Role = rbac.Role(role)
	b.CreatedAt = b.CreatedAt.UTC()
	if svID != nil {
		b.Service = &authz.ServiceRef{ID: *svID, Name: svName}
		if svEnv != nil {
			b.Service.Environment = &authz.EnvironmentRef{ID: *svEnv, Key: seKey, Name: seName}
		}
	}
	if envID != nil {
		b.Environment = &authz.EnvironmentRef{ID: *envID, Key: eKey, Name: eName}
	}
	b.Services = make([]authz.ServiceRef, 0, len(covered))
	for _, id := range covered {
		b.Services = append(b.Services, authz.ServiceRef{ID: id})
	}
	return b, nil
}

// withRefs fills the services a binding covers with their names and environments.
func withRefs(bs []Binding, refs map[uuid.UUID]authz.ServiceRef) {
	for i := range bs {
		covered := bs[i].Services
		for j, s := range covered {
			if ref, ok := refs[s.ID]; ok {
				covered[j] = ref
			}
		}
		slices.SortFunc(covered, func(a, b authz.ServiceRef) int { return compareIDs(a.ID, b.ID) })
	}
}

// Bindings lists the role bindings that match f: by subject, then role, then where.
func (s *Store) Bindings(ctx context.Context, f BindingFilter) ([]Binding, error) {
	rows, err := s.pool.Query(ctx, bindingSelect+`
WHERE ($1::uuid IS NULL OR rb.user_id = $1)
  AND ($2::uuid IS NULL OR rb.directory_group_id = $2)
  AND ($3::uuid IS NULL OR rb.service_id = $3 OR rb.environment_id = (SELECT environment_id FROM services WHERE id = $3))
  AND ($4::uuid IS NULL OR rb.environment_id = $4)
ORDER BY lower(coalesce(u.username::text, '')), rb.directory_group_id NULLS FIRST, rb.role, lower(coalesce(sv.name::text, '')),
    coalesce(e.sort, 0), rb.id`, f.UserID, f.DirectoryGroupID, f.ServiceID, f.EnvironmentID)
	if err != nil {
		return nil, fmt.Errorf("services: list the role bindings: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanBinding)
	if err != nil {
		return nil, fmt.Errorf("services: list the role bindings: %w", err)
	}
	refs, err := readRefs(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	withRefs(out, refs)
	return out, nil
}

// Binding reads one role binding. ErrBindingNotFound.
func (s *Store) Binding(ctx context.Context, id uuid.UUID) (Binding, error) {
	return getBinding(ctx, s.pool, id)
}

func getBinding(ctx context.Context, q db.Querier, id uuid.UUID) (Binding, error) {
	rows, err := q.Query(ctx, bindingSelect+" WHERE rb.id = $1", id)
	if err != nil {
		return Binding{}, fmt.Errorf("services: read the role binding: %w", err)
	}
	b, err := pgx.CollectExactlyOneRow(rows, scanBinding)
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, ErrBindingNotFound
	}
	if err != nil {
		return Binding{}, fmt.Errorf("services: read the role binding: %w", err)
	}
	refs, err := readRefs(ctx, q)
	if err != nil {
		return Binding{}, err
	}
	bs := []Binding{b}
	withRefs(bs, refs)
	return bs[0], nil
}

// CreateBinding gives a person a role on one service or on every service of an environment (design §8.2): at most
// MaxBindingsPerSubject per person; audit access.binding_added with the subject, the role and where. It takes effect at
// the person's next request (grants are read per request, SEC-017). An unknown person, service or environment is a
// validation error on its field. ErrBindingDuplicate, ErrBindingLimit.
func (s *Store) CreateBinding(ctx context.Context, a Actor, in BindingInput) (Binding, error) {
	var v validate.Errors
	if in.UserID == uuid.Nil {
		v.Add("user_id", validate.Required, nil)
	}
	role, ok := rbac.ParseRole(in.Role)
	if !ok {
		v.Add("role", validate.OneOf, map[string]string{"values": "admin, operator, auditor"})
	}
	switch {
	case in.ServiceID == nil && in.EnvironmentID == nil:
		v.Add("service_id", validate.Required, nil)
	case in.ServiceID != nil && in.EnvironmentID != nil:
		v.Add("environment_id", validate.Pattern, nil) // one of the two, never both
	}
	if err := v.Err(); err != nil {
		return Binding{}, err
	}
	id := uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// The person's row is locked: two additions for one person count their bindings one after the other.
		var username string
		err := tx.QueryRow(ctx, "SELECT username::text FROM users WHERE id = $1 FOR UPDATE", in.UserID).Scan(&username)
		if errors.Is(err, pgx.ErrNoRows) {
			return validate.Errors{{Field: "user_id", Code: validate.Required}}
		}
		if err != nil {
			return fmt.Errorf("services: lock the person: %w", err)
		}
		where := map[string]string{}
		if in.ServiceID != nil {
			var one int
			err := tx.QueryRow(ctx, "SELECT 1 FROM services WHERE id = $1 FOR KEY SHARE", *in.ServiceID).Scan(&one)
			if errors.Is(err, pgx.ErrNoRows) {
				return validate.Errors{{Field: "service_id", Code: validate.Required}}
			}
			if err != nil {
				return fmt.Errorf("services: read the service: %w", err)
			}
			where["service_id"] = in.ServiceID.String()
		}
		if in.EnvironmentID != nil {
			if err := checkEnvironment(ctx, tx, in.EnvironmentID); err != nil {
				return err
			}
			where["environment_id"] = in.EnvironmentID.String()
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM role_bindings WHERE user_id = $1", in.UserID).Scan(&n); err != nil {
			return fmt.Errorf("services: count the role bindings: %w", err)
		}
		if n >= MaxBindingsPerSubject {
			return ErrBindingLimit
		}
		_, err = tx.Exec(ctx, `INSERT INTO role_bindings (id, user_id, role, service_id, environment_id, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, in.UserID, string(role), in.ServiceID, in.EnvironmentID, a.createdBy(), s.clock.Now().UTC())
		if db.IsUniqueViolation(err) { // the only unique constraint besides the new id: subject, role and where
			return ErrBindingDuplicate
		}
		if err != nil {
			return fmt.Errorf("services: store the role binding: %w", err)
		}
		details := map[string]string{"user_id": in.UserID.String(), "username": username, "role": string(role)}
		for k, val := range where {
			details[k] = val
		}
		return s.appendAudit(ctx, tx, a, "access.binding_added", "role_binding", id, details)
	})
	if err != nil {
		return Binding{}, err
	}
	return s.Binding(ctx, id)
}

// DeleteBinding removes a role binding; audit access.binding_removed with the subject, the role and where. It takes
// effect at the person's next request. ErrBindingNotFound.
func (s *Store) DeleteBinding(ctx context.Context, a Actor, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		b, err := getBinding(ctx, tx, id)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM role_bindings WHERE id = $1", id)
		if err != nil {
			return fmt.Errorf("services: delete the role binding: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrBindingNotFound
		}
		details := map[string]string{"role": string(b.Role)}
		if b.UserID != nil {
			details["user_id"], details["username"] = b.UserID.String(), b.Username
		}
		if b.DirectoryGroupID != nil {
			details["directory_group_id"] = b.DirectoryGroupID.String()
		}
		if b.Service != nil {
			details["service_id"] = b.Service.ID.String()
		}
		if b.Environment != nil {
			details["environment_id"] = b.Environment.ID.String()
		}
		return s.appendAudit(ctx, tx, a, "access.binding_removed", "role_binding", id, details)
	})
}

// UserAccess is a person's effective access and where each part comes from (GET /api/v1/users/{id}/access): the
// global role, every binding with the services it covers now, and whether the "SSO users may be Admin" cap lowers
// their Administrator bindings to Operator.
type UserAccess struct {
	GlobalRole rbac.Role // "" for none
	Bindings   []Binding
	AdminCap   bool
	// Grants are the bindings as the authorization check sees them (rbac.ScopedGrant: one per role, the union of its
	// services, the cap applied).
	Grants []rbac.ScopedGrant
}

// Access reads a person's access. ErrUserNotFound.
func (s *Store) Access(ctx context.Context, userID uuid.UUID) (UserAccess, error) {
	var out UserAccess
	var role string
	var source string
	err := s.pool.QueryRow(ctx, "SELECT coalesce(role, ''), auth_source FROM users WHERE id = $1", userID).Scan(&role, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserAccess{}, ErrUserNotFound
	}
	if err != nil {
		return UserAccess{}, fmt.Errorf("services: read the person: %w", err)
	}
	out.GlobalRole = rbac.Role(role)
	if out.Bindings, err = s.Bindings(ctx, BindingFilter{UserID: &userID}); err != nil {
		return UserAccess{}, err
	}
	if out.Grants, err = authz.LoadGrants(ctx, s.pool, userID); err != nil {
		return UserAccess{}, err
	}
	if source == "oidc" || source == "ldap" {
		var allow bool
		err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM settings WHERE key = $1 AND value->'allow' = 'true'::jsonb)`,
			authz.SSOAllowAdminKey).Scan(&allow)
		if err != nil {
			return UserAccess{}, fmt.Errorf("services: read the SSO Admin switch: %w", err)
		}
		out.AdminCap = !allow
	}
	return out, nil
}

// Grants are a person's grants as the authorization check reads them (authz.LoadGrants), for the access of a session
// that was just opened.
func (s *Store) Grants(ctx context.Context, userID uuid.UUID) ([]rbac.ScopedGrant, error) {
	return authz.LoadGrants(ctx, s.pool, userID)
}

// ErrUserNotFound: the person whose access was asked for does not exist.
var ErrUserNotFound = errors.New("services: person not found")
