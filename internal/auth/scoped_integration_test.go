//go:build integration

package auth_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/authz"
	"alice/internal/rbac"
)

func TestSSOAllowAdminKeyIsAuthz(t *testing.T) {
	assert.Equal(t, auth.SSOAllowAdminKey, authz.SSOAllowAdminKey, "authz reads the same switch")
}

// A person without a global role (R49 Phase 2): created and signed in as before, their session carries their role
// bindings as grants, read on every request; a token is possible only while some grant allows its scope; the
// break-glass account never loses its global role; the last-administrator rule still holds.
func TestPersonWithoutAGlobalRole(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	u := e.createUser(t, admin, "olga", auth.NoGlobalRole)
	assert.Equal(t, auth.NoGlobalRole, u.Role)
	listed, err := e.svc.ListUsers(e.ctx)
	require.NoError(t, err)
	assert.Len(t, listed, 2, "a NULL role reads as none")

	_, res := e.enroll(t, "olga", adminPassword)
	p := e.principal(t, res.Token)
	assert.Equal(t, rbac.UserSession, p.Kind)
	assert.Equal(t, rbac.Role(""), p.Role)
	assert.Empty(t, p.Grants)
	_, _, err = e.svc.CreateToken(e.ctx, p, meta, auth.NewToken{Name: "x", Scope: rbac.ScopeRead, ExpiresInDays: 1})
	assert.ErrorIs(t, err, auth.ErrTokenScopeNotAllowed, "no grant, no token")

	var def uuid.UUID
	require.NoError(t, e.db.App.QueryRow(e.ctx, "SELECT id FROM services WHERE is_default").Scan(&def))
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO role_bindings (id, user_id, role, service_id, created_at) VALUES (gen_random_uuid(), $1, 'operator', $2, now())`,
		u.ID, def)
	require.NoError(t, err)
	p = e.principal(t, res.Token)
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Operator, Services: []uuid.UUID{def}}}, p.Grants, "read on the next request")
	secret, _, err := e.svc.CreateToken(e.ctx, p, meta, auth.NewToken{Name: "ci", Scope: rbac.ScopeOperate, ExpiresInDays: 1})
	require.NoError(t, err, "an Operator binding allows an operate token")
	tp, err := e.svc.AuthenticateToken(e.ctx, secret)
	require.NoError(t, err)
	assert.Equal(t, p.Grants, tp.Grants, "the token acts with its owner's grants")

	_, err = e.db.Owner.Exec(e.ctx, "DELETE FROM role_bindings WHERE user_id = $1", u.ID)
	require.NoError(t, err)
	_, err = e.svc.AuthenticateToken(e.ctx, secret)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "the token stops when no grant allows its scope any more")

	// Removing and giving back a global role; the break-glass account keeps one.
	op := e.createUser(t, admin, "omer", rbac.Operator)
	none := auth.NoGlobalRole
	got, err := e.svc.UpdateUser(e.ctx, admin, meta, op.ID, auth.UserUpdate{Role: &none})
	require.NoError(t, err)
	assert.Equal(t, auth.NoGlobalRole, got.Role)
	var details map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT details FROM audit_log WHERE action = 'user.updated' ORDER BY seq DESC LIMIT 1").Scan(&details))
	assert.Equal(t, "operator", details["role_from"])
	assert.Equal(t, "none", details["role_to"])
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, admin.UserID, auth.UserUpdate{Role: &none})
	assert.ErrorIs(t, err, auth.ErrLastAdmin, "the last administrator comes first")
	second := e.createUser(t, admin, "ayla", rbac.Admin)
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, admin.UserID, auth.UserUpdate{Role: &none})
	assert.ErrorIs(t, err, auth.ErrBreakGlassGlobalRole)
	assert.Equal(t, 1, e.reasons(t, "user.updated")["break_glass_global_role"], "the refusal is audited")
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, second.ID, auth.UserUpdate{Role: &none})
	require.NoError(t, err, "another administrator may lose the global role")
}
