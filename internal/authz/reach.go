package authz

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"alice/internal/platform/db"
	"alice/internal/rbac"
)

// Reach is where a caller may use one permission (design §3, §5.1): every service, or the listed ones. It is what the
// list, count, export and dashboard functions filter by (design §5.8) and what a service function checks a resource
// against under its row lock (design §5.4).
//
// The zero value is every service: Alice's own work (jobs, e-mails, the planners) and every caller from before scoped
// access pass it, and the API always computes a caller's Reach from the request's grants (the scoped IDOR test of the
// route table checks that no list answers rows outside it). Limited with no services reaches nothing.
type Reach struct {
	// Limited is false for every service (a global grant, or Alice itself); true when Services is the whole reach.
	Limited bool
	// Services, when Limited: sorted, without repeats; empty: none.
	Services []uuid.UUID
}

// Everywhere is the reach of a global grant and of Alice's own work.
func Everywhere() Reach { return Reach{} }

// Only is a reach limited to the given services (sorted and without repeats; none: nothing at all).
func Only(services ...uuid.UUID) Reach {
	out := append([]uuid.UUID{}, services...)
	slices.SortFunc(out, compareID)
	return Reach{Limited: true, Services: slices.Compact(out)}
}

// ReachOf is where subject may use permission p (rbac.Reach as a Reach).
func ReachOf(p rbac.Permission, subject rbac.Subject) Reach {
	all, services := rbac.Reach(p, subject)
	if all {
		return Everywhere()
	}
	return Only(services...)
}

// All reports whether the reach is every service.
func (r Reach) All() bool { return !r.Limited }

// None reports whether the reach is no service at all.
func (r Reach) None() bool { return r.Limited && len(r.Services) == 0 }

// Contains reports whether service is in the reach.
func (r Reach) Contains(service uuid.UUID) bool {
	return !r.Limited || slices.Contains(r.Services, service)
}

// ContainsAny reports whether one of services is in the reach.
func (r Reach) ContainsAny(services []uuid.UUID) bool {
	if !r.Limited {
		return true
	}
	for _, s := range services {
		if slices.Contains(r.Services, s) {
			return true
		}
	}
	return false
}

// SQL is the reach as a query parameter: NULL for every service, otherwise the array of its services (possibly
// empty). Queries test it as `($n::uuid[] IS NULL OR service_id = ANY($n))`.
func (r Reach) SQL() []uuid.UUID {
	if !r.Limited {
		return nil
	}
	if r.Services == nil {
		return []uuid.UUID{}
	}
	return r.Services
}

// Narrow intersects a list filter of services (nil: no filter, the convention of the R49 service_id and
// environment_id filters) with the reach: nil when neither limits, otherwise the services both allow (possibly none).
func (r Reach) Narrow(filter []uuid.UUID) []uuid.UUID {
	switch {
	case !r.Limited:
		return filter
	case filter == nil:
		return r.SQL()
	}
	out := []uuid.UUID{}
	for _, s := range filter {
		if slices.Contains(r.Services, s) {
			out = append(out, s)
		}
	}
	return out
}

// String is the reach for an audit row's details: "all" or the service ids joined by commas ("" for none).
func (r Reach) String() string {
	if !r.Limited {
		return "all"
	}
	var b bytes.Buffer
	for i, s := range r.Services {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s.String())
	}
	return b.String()
}

func compareID(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }

// Access is a caller's grants as a service function sees them (design §5.4): it answers the reach of any permission.
// The zero value is unrestricted (Alice's own work, a caller from before scoped access); the API builds every person's
// and token's with AccessOf.
type Access struct {
	limited bool
	subject rbac.Subject
}

// AccessOf is the access of an authenticated subject (its global role, scoped grants and token scope).
func AccessOf(subject rbac.Subject) Access { return Access{limited: true, subject: subject} }

// Reach is where the caller may use permission p.
func (a Access) Reach(p rbac.Permission) Reach {
	if !a.limited {
		return Everywhere()
	}
	return ReachOf(p, a.subject)
}

// Allows reports whether the caller may use permission p on service (the step-up window is the route's business).
func (a Access) Allows(p rbac.Permission, service uuid.UUID) bool {
	return a.Reach(p).Contains(service)
}

// LoadGrants reads a person's scoped grants (design §5.1 steps 2, 4 and 5): every role binding of the user, an
// environment binding expanded to the services that carry the environment now, one grant per role with the union of its
// services. For an SSO or directory user, while "SSO users may be Admin" is off, an Administrator binding counts as an
// Operator one (the cap SEC-014 puts on the global role). Called on every request with the session or token lookup
// (SEC-017: nothing is cached beyond the request). Bindings of directory groups come with Phase 3.
func LoadGrants(ctx context.Context, q db.Querier, userID uuid.UUID) ([]rbac.ScopedGrant, error) {
	rows, err := q.Query(ctx, `SELECT CASE WHEN rb.role = 'admin' AND u.auth_source IN ('oidc', 'ldap') AND NOT EXISTS (
        SELECT 1 FROM settings st WHERE st.key = $2 AND st.value->'allow' = 'true'::jsonb) THEN 'operator' ELSE rb.role END,
    CASE WHEN rb.service_id IS NOT NULL THEN ARRAY[rb.service_id]
         ELSE ARRAY(SELECT s.id FROM services s WHERE s.environment_id = rb.environment_id) END
FROM role_bindings rb JOIN users u ON u.id = rb.user_id
WHERE rb.user_id = $1`, userID, SSOAllowAdminKey)
	if err != nil {
		return nil, fmt.Errorf("authz: read the role bindings: %w", err)
	}
	defer rows.Close()
	byRole := map[rbac.Role][]uuid.UUID{}
	for rows.Next() {
		var role string
		var services []uuid.UUID
		if err := rows.Scan(&role, &services); err != nil {
			return nil, fmt.Errorf("authz: read the role bindings: %w", err)
		}
		r, ok := rbac.ParseRole(role)
		if !ok {
			continue // the CHECK admits only the three roles
		}
		byRole[r] = append(byRole[r], services...)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz: read the role bindings: %w", err)
	}
	var out []rbac.ScopedGrant
	for _, r := range rbac.Roles() {
		services, ok := byRole[r]
		if !ok {
			continue
		}
		slices.SortFunc(services, compareID)
		out = append(out, rbac.ScopedGrant{Role: r, Services: slices.Compact(services)})
	}
	return out, nil
}

// SSOAllowAdminKey is the settings key of "SSO users may be Admin" (auth.SSOAllowAdminKey: authz knows the platform
// only, a test of internal/auth pins the two together).
const SSOAllowAdminKey = "sso.allow_admin_role"
