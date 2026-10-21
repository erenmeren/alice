//go:build integration

package ldap_test

import (
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/authz"
	"alice/internal/rbac"
	"alice/internal/testutil/fakeldap"
)

// signInScoped is the API's directory sign-in: the directory checks the password and returns the groups, the
// mappings give a global role or none, and auth signs the person in (without MFA) when a mapping or a role binding
// lets them.
func (x *harness) signInScoped(t *testing.T, u fakeldap.User) (uuid.UUID, error) {
	t.Helper()
	id, err := x.verify(u.Login, u.Password)
	require.NoError(t, err)
	role, mapped, err := x.svc.ResolveRole(x.ctx, x.dir.ID, id.Groups)
	require.NoError(t, err)
	if !mapped {
		role = auth.NoGlobalRole
	}
	res, err := x.auth.SignInLDAP(x.ctx, auth.LDAPIdentity{DirectoryID: x.dir.ID, UniqueID: id.UniqueID, Login: id.Login,
		DisplayName: id.DisplayName, Email: id.Email, Groups: id.Groups}, role, false, auth.Meta{})
	if err != nil {
		return uuid.Nil, err
	}
	p, err := x.auth.AuthenticatePassive(x.ctx, res.SessionToken)
	require.NoError(t, err)
	return p.UserID, nil
}

// R54 acceptance against a real OpenLDAP (design §12 Phase 3): a person in group G bound operator@B signs in with no
// global mapping and reaches B only; taken out of G in the directory, the next sign-in is refused no_access; a person
// with neither a mapping nor a binding is refused as before.
func TestDirectoryGroupBindingOverOpenLDAP(t *testing.T) {
	x := newHarness(t)
	name := "alice-pay-" + uuid.NewString()[:8] // the container serves every test of the process: a group of this test's own
	groupDN := "cn=" + name + "," + fakeldap.GroupsDN
	x.srv.Add(t, groupDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {name}, "member": {fakeldap.Grace.DN}})
	t.Cleanup(func() { _ = x.srv.Admin(t).Del(goldap.NewDelRequest(groupDN, nil)) })

	b, other := uuid.New(), uuid.New()
	for _, sv := range []uuid.UUID{b, other} {
		_, err := x.d.Owner.Exec(x.ctx, "INSERT INTO services (id, name, created_at, updated_at) VALUES ($1, $2, now(), now())", sv, "svc-"+sv.String()[:8])
		require.NoError(t, err)
	}
	group := uuid.New()
	_, err := x.d.Owner.Exec(x.ctx, `INSERT INTO directory_groups (id, source, ldap_directory_id, value, created_at) VALUES ($1, 'ldap', $2, $3, now())`,
		group, x.dir.ID, name)
	require.NoError(t, err)
	_, err = x.d.Owner.Exec(x.ctx, `INSERT INTO role_bindings (id, directory_group_id, role, service_id, created_at) VALUES (gen_random_uuid(), $1, 'operator', $2, now())`,
		group, b)
	require.NoError(t, err)

	// No mapping of any group, only the binding of the group grace is in.
	grace, err := x.signInScoped(t, fakeldap.Grace)
	require.NoError(t, err, "a group binding lets a directory user without a mapped group in")
	var role *string
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, "SELECT role FROM users WHERE id = $1", grace).Scan(&role))
	assert.Nil(t, role, "no global role")
	grants, err := authz.LoadGrants(x.ctx, x.d.App, grace)
	require.NoError(t, err)
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Operator, Services: []uuid.UUID{b}}}, grants, "B only")

	// Ada is in alice-ops, which nothing maps or binds: refused as before.
	_, err = x.signInScoped(t, fakeldap.Ada)
	assert.ErrorIs(t, err, auth.ErrNoAccess)

	// Grace leaves the group in the directory: the next sign-in is refused, and the refusal ends her access.
	require.NoError(t, x.srv.Admin(t).Modify(&goldap.ModifyRequest{DN: groupDN,
		Changes: []goldap.Change{{Operation: goldap.ReplaceAttribute, Modification: goldap.PartialAttribute{Type: "member", Vals: []string{fakeldap.Cigdem.DN}}}}}))
	_, err = x.signInScoped(t, fakeldap.Grace)
	assert.ErrorIs(t, err, auth.ErrNoAccess)
	id, err := x.verify(fakeldap.Grace.Login, fakeldap.Grace.Password)
	require.NoError(t, err)
	require.NoError(t, x.auth.RefuseLDAP(x.ctx, auth.LDAPIdentity{DirectoryID: x.dir.ID, UniqueID: id.UniqueID, Login: id.Login}, "no_access", auth.Meta{}))
	grants, err = authz.LoadGrants(x.ctx, x.d.App, grace)
	require.NoError(t, err)
	assert.Empty(t, grants, "the group's binding reaches her no more")
	assert.Zero(t, x.count(t, "SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL", grace))
}
