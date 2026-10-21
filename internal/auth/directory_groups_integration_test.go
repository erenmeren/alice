//go:build integration

package auth_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// service inserts a service (scoped access, R49) and returns its id.
func (e *env) service(t *testing.T, name string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, "INSERT INTO services (id, name, created_at, updated_at) VALUES ($1, $2, now(), now())", id, name)
	require.NoError(t, err)
	return id
}

// group declares a directory group of an SSO provider (source oidc) or a directory (source ldap) and binds it to role
// on service.
func (e *env) groupBinding(t *testing.T, source string, from uuid.UUID, value, role string, service uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	column := "oidc_provider_id"
	if source == "ldap" {
		column = "ldap_directory_id"
	}
	_, err := e.db.Owner.Exec(e.ctx, fmt.Sprintf(`INSERT INTO directory_groups (id, source, %s, value, created_at)
VALUES ($1, $2, $3, $4, now()) ON CONFLICT DO NOTHING`, column), id, source, from, value)
	require.NoError(t, err)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, fmt.Sprintf("SELECT id FROM directory_groups WHERE source = $1 AND %s = $2 AND value = $3", column),
		source, from, value).Scan(&id))
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO role_bindings (id, directory_group_id, role, service_id, created_at)
VALUES (gen_random_uuid(), $1, $2, $3, now())`, id, role, service)
	require.NoError(t, err)
	return id
}

func (e *env) seenGroups(t *testing.T, userID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM user_directory_groups WHERE user_id = $1", userID).Scan(&n))
	return n
}

// The sign-in refusal of design §6.1 (R54) for SSO users: a user none of whose groups is mapped signs in without a
// global role when a role binding reaches them, through a directory group of their own provider or their own binding;
// without one the sign-in is ErrNoAccess and nobody is provisioned. The groups are kept at every sign-in and step-up,
// the first 1000 only; the SSO Admin cap lowers an Administrator binding of a group to Operator.
func TestSSOSignInWithGroupBindings(t *testing.T) {
	e := newEnv(t)
	p, other := e.provider(t), e.provider(t)
	b, c := e.service(t, "Payments"), e.service(t, "Billing")
	e.groupBinding(t, "oidc", p, "pay-ops", "operator", b)
	e.groupBinding(t, "oidc", other, "billing-ops", "operator", c) // another provider's group of the same value is not theirs

	id := identity(p, "sub-1", "ada", "ada@example.com")
	id.Groups = []string{"pay-ops", "billing-ops", "pay-ops"}
	res, err := e.svc.SignInOIDC(e.ctx, id, auth.NoGlobalRole, meta)
	require.NoError(t, err, "a group binding lets a user without a mapped group in")
	pr := e.principal(t, res.Token)
	assert.Equal(t, rbac.Role(""), pr.Role, "no global role")
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Operator, Services: []uuid.UUID{b}}}, pr.Grants, "only the own provider's group")
	assert.Equal(t, 2, e.seenGroups(t, pr.UserID), "the groups are kept once each")
	assert.Equal(t, 1, e.countAction(t, "user.provisioned", "success"))

	// An Administrator binding of a group counts as Operator while SSO users may not be Admin.
	e.groupBinding(t, "oidc", p, "pay-ops", "admin", c)
	pr = e.principal(t, res.Token)
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Operator, Services: sortedIDs(b, c)}}, pr.Grants, "capped at Operator")
	e.allowAdmin(t, true)
	pr = e.principal(t, res.Token)
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Admin, Services: []uuid.UUID{c}}, {Role: rbac.Operator, Services: []uuid.UUID{b}}}, pr.Grants)
	e.allowAdmin(t, false)

	// Out of the group at the provider: the next step-up and sign-in are refused, the step-up first.
	id.Groups = []string{"engineering"}
	_, err = e.svc.StepUpOIDC(e.ctx, pr.SessionHash, pr.UserID, id, auth.NoGlobalRole, meta)
	assert.ErrorIs(t, err, auth.ErrNoAccess)
	_, err = e.svc.SignInOIDC(e.ctx, id, auth.NoGlobalRole, meta)
	assert.ErrorIs(t, err, auth.ErrNoAccess)
	assert.Equal(t, 2, e.seenGroups(t, pr.UserID), "a refused sign-in changes nothing")
	require.NoError(t, e.svc.RefuseOIDC(e.ctx, id, "no_access", meta))
	assert.Zero(t, e.liveSessions(t, pr.UserID), "the refusal ends the sessions")
	assert.Zero(t, e.seenGroups(t, pr.UserID), "and forgets the groups: no group binding reaches the user any more")

	// The user's own binding lets them in without any group.
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO role_bindings (id, user_id, role, service_id, created_at) VALUES (gen_random_uuid(), $1, 'auditor', $2, now())`,
		pr.UserID, c)
	require.NoError(t, err)
	res, err = e.svc.SignInOIDC(e.ctx, id, auth.NoGlobalRole, meta)
	require.NoError(t, err)
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Auditor, Services: []uuid.UUID{c}}}, e.principal(t, res.Token).Grants)

	// A user with neither a mapped group nor a binding is refused as before, and nobody is provisioned.
	stranger := identity(p, "sub-2", "grace", "")
	stranger.Groups = []string{"engineering"}
	_, err = e.svc.SignInOIDC(e.ctx, stranger, auth.NoGlobalRole, meta)
	assert.ErrorIs(t, err, auth.ErrNoAccess)
	assert.Equal(t, 1, e.countAction(t, "user.provisioned", "success"))

	// More than 1000 groups: the first 1000 are kept, a binding of a later one gives nothing (fewer rights, never
	// more) and the sign-in is audited user.groups_truncated. A mapped role still signs the user in.
	many := make([]string, 0, 1005)
	for i := range 1005 {
		many = append(many, fmt.Sprintf("g-%04d", i))
	}
	e.groupBinding(t, "oidc", p, "g-1002", "operator", b)
	big := identity(p, "sub-3", "mallory", "")
	big.Groups = many
	_, err = e.svc.SignInOIDC(e.ctx, big, auth.NoGlobalRole, meta)
	assert.ErrorIs(t, err, auth.ErrNoAccess, "the group past the bound does not count")
	res, err = e.svc.SignInOIDC(e.ctx, big, rbac.Auditor, meta)
	require.NoError(t, err)
	pr = e.principal(t, res.Token)
	assert.Equal(t, auth.MaxDirectoryGroups, e.seenGroups(t, pr.UserID))
	assert.Empty(t, pr.Grants)
	assert.Equal(t, "5", *e.lastDetail(t, "user.groups_truncated", "groups_dropped"))
	assert.Equal(t, "1000", *e.lastDetail(t, "user.groups_truncated", "groups_kept"))
}

// The same rule for directory users (SignInLDAP, StepUpLDAP): a directory group binding lets them in, the groups are
// kept, a step-up without the group is refused before any code is checked.
func TestDirectorySignInWithGroupBindings(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	b := e.service(t, "Payments")
	e.groupBinding(t, "ldap", dir, "CN=Pay,DC=example,DC=test", "operator", b)
	id := ldapIdentity(dir, "0a0b0c", "sukru", "sukru@example.test")
	id.Groups = []string{"CN=Pay,DC=example,DC=test"}
	pr := e.signInLDAP(t, id, auth.NoGlobalRole)
	assert.Equal(t, rbac.Role(""), pr.Role)
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Operator, Services: []uuid.UUID{b}}}, pr.Grants)
	assert.Equal(t, 1, e.seenGroups(t, pr.UserID))

	// Case matters for directory groups, as for the mappings.
	id.Groups = []string{"cn=pay,dc=example,dc=test"}
	_, err := e.svc.StepUpLDAP(e.ctx, pr, id, auth.NoGlobalRole, "", false, meta)
	assert.ErrorIs(t, err, auth.ErrNoAccess)
	_, err = e.svc.SignInLDAP(e.ctx, id, auth.NoGlobalRole, true, meta)
	assert.ErrorIs(t, err, auth.ErrNoAccess, "with MFA too, before the pending session")

	// A mapped role keeps working as before, and the groups follow.
	id.Groups = nil
	pr = e.signInLDAP(t, id, rbac.Operator)
	assert.Equal(t, rbac.Operator, pr.Role)
	assert.Zero(t, e.seenGroups(t, pr.UserID))
}

func sortedIDs(ids ...uuid.UUID) []uuid.UUID {
	out := append([]uuid.UUID{}, ids...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j].String() < out[i].String() {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Automation accounts (design §6.2, R54): made and changed by an Administrator, never a global Administrator, never
// signed in (the password form answers as for an unknown name), changed only through their own functions; their
// tokens are made by an Administrator and work within their grants; disabling revokes them.
func TestAutomationAccounts(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	b, c := e.service(t, "Payments"), e.service(t, "Billing")

	_, err := e.svc.CreateAutomationAccount(e.ctx, admin, meta, auth.NewAutomationAccount{Username: "ci", DisplayName: "CI", Role: rbac.Admin})
	assert.ErrorIs(t, err, auth.ErrAutomationAdmin)
	_, err = e.svc.CreateAutomationAccount(e.ctx, admin, meta, auth.NewAutomationAccount{Username: "admin", DisplayName: "CI"})
	assert.ErrorIs(t, err, auth.ErrUsernameTaken, "one name space with people")
	_, err = e.svc.CreateAutomationAccount(e.ctx, admin, meta, auth.NewAutomationAccount{Username: "x y", DisplayName: ""})
	var v validate.Errors
	require.ErrorAs(t, err, &v)
	acct, err := e.svc.CreateAutomationAccount(e.ctx, admin, meta, auth.NewAutomationAccount{Username: "ci-deployer", DisplayName: "CI deployer",
		Description: "Ödeme hattının dağıtımları"})
	require.NoError(t, err)
	assert.Equal(t, auth.NoGlobalRole, acct.Role)
	assert.Equal(t, "Ödeme hattının dağıtımları", acct.Description)
	assert.Equal(t, "none", *e.lastDetail(t, "automation.created", "role"))

	people, err := e.svc.ListUsers(e.ctx)
	require.NoError(t, err)
	for _, u := range people {
		assert.NotEqual(t, acct.ID, u.ID, "People & access lists people only")
	}
	accounts, err := e.svc.ListAutomationAccounts(e.ctx)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	_, err = e.svc.GetAutomationAccount(e.ctx, admin.UserID)
	assert.ErrorIs(t, err, auth.ErrNotFound, "a person is no automation account")

	// It never signs in: the password form answers as for an unknown name.
	_, err = e.svc.Login(e.ctx, "ci-deployer", "anything at all, really", meta)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
	assert.Equal(t, 1, e.reasons(t, "auth.login")["unknown_user"])
	// People & access cannot change what only a person has.
	op := rbac.Operator
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, acct.ID, auth.UserUpdate{Role: &op})
	assert.ErrorIs(t, err, auth.ErrAutomationAccount)
	assert.ErrorIs(t, e.svc.ResetPassword(e.ctx, admin, meta, acct.ID, "a long enough new password"), auth.ErrAutomationAccount)
	assert.ErrorIs(t, e.svc.ResetMFA(e.ctx, admin, meta, acct.ID), auth.ErrAutomationAccount)
	adm := rbac.Admin
	_, err = e.svc.UpdateAutomationAccount(e.ctx, admin, meta, acct.ID, auth.AutomationUpdate{Role: &adm})
	assert.ErrorIs(t, err, auth.ErrAutomationAdmin)

	// Tokens: within the account's grants.
	in := auth.NewToken{Name: "pipeline", Scope: rbac.ScopeOperate, ExpiresInDays: 30}
	_, _, err = e.svc.CreateAutomationToken(e.ctx, admin, meta, acct.ID, in)
	assert.ErrorIs(t, err, auth.ErrTokenScopeNotAllowed, "no grant, no token")
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO role_bindings (id, user_id, role, service_id, created_at) VALUES (gen_random_uuid(), $1, 'admin', $2, now())`,
		acct.ID, b)
	require.NoError(t, err, "an automation account may be an Administrator of a service")
	in.ServiceIDs = []uuid.UUID{c}
	_, _, err = e.svc.CreateAutomationToken(e.ctx, admin, meta, acct.ID, in)
	assert.ErrorIs(t, err, auth.ErrTokenServiceNotAllowed, "not on a service the account holds nothing on")
	in.ServiceIDs = nil
	secret, tok, err := e.svc.CreateAutomationToken(e.ctx, admin, meta, acct.ID, in)
	require.NoError(t, err)
	assert.Equal(t, acct.ID, tok.UserID)
	assert.Equal(t, acct.ID.String(), *e.lastDetail(t, "token.created", "account_id"))
	var actor string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT actor_id::text FROM audit_log WHERE action = 'token.created' ORDER BY seq DESC LIMIT 1").Scan(&actor))
	assert.Equal(t, admin.UserID.String(), actor, "the Administrator made it")
	tp, err := e.svc.AuthenticateToken(e.ctx, secret)
	require.NoError(t, err)
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Admin, Services: []uuid.UUID{b}}}, tp.Grants)
	assert.Equal(t, rbac.Allow, rbac.DecideIn(rbac.TargetsManage, tp.Subject(e.clk.Now()), b), "its operate token manages B's servers")
	listed, err := e.svc.ListAutomationTokens(e.ctx, acct.ID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	_, err = e.svc.ListAutomationTokens(e.ctx, admin.UserID)
	assert.ErrorIs(t, err, auth.ErrNotFound)
	other, err := e.svc.CreateAutomationAccount(e.ctx, admin, meta, auth.NewAutomationAccount{Username: "backup-bot", DisplayName: "Backup",
		Role: rbac.Auditor})
	require.NoError(t, err)
	assert.ErrorIs(t, e.svc.RevokeAutomationToken(e.ctx, admin, meta, other.ID, tok.ID), auth.ErrNotFound, "another account's token")

	// Disabling revokes the tokens for good and refuses new ones.
	yes := true
	got, err := e.svc.UpdateAutomationAccount(e.ctx, admin, meta, acct.ID, auth.AutomationUpdate{Disabled: &yes})
	require.NoError(t, err)
	assert.True(t, got.Disabled)
	assert.Zero(t, got.Tokens)
	_, err = e.svc.AuthenticateToken(e.ctx, secret)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	assert.Equal(t, "1", *e.lastDetail(t, "automation.updated", "revoked_tokens_count"))
	_, _, err = e.svc.CreateAutomationToken(e.ctx, admin, meta, acct.ID, in)
	assert.ErrorIs(t, err, auth.ErrAutomationDisabled)
	no := false
	_, err = e.svc.UpdateAutomationAccount(e.ctx, admin, meta, acct.ID, auth.AutomationUpdate{Disabled: &no})
	require.NoError(t, err)
	_, err = e.svc.AuthenticateToken(e.ctx, secret)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "enabling again brings no token back")
}

// Tokens limited to services (design §6.3, R54): the owner's grants now ∩ the scope ∩ the services. A global
// Administrator's token limited to B holds the Administrator role on B only and no global role; a service the owner
// holds nothing on, or one that does not exist, is refused; the token shrinks with its owner's grants.
func TestTokensLimitedToServices(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	b, c := e.service(t, "Payments"), e.service(t, "Billing")

	in := auth.NewToken{Name: "deploy B", Scope: rbac.ScopeOperate, ExpiresInDays: 7, ServiceIDs: []uuid.UUID{b, b}}
	secret, tok, err := e.svc.CreateToken(e.ctx, admin, meta, in)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{b}, tok.ServiceIDs)
	assert.Equal(t, b.String(), *e.lastDetail(t, "token.created", "service_ids"))
	tp, err := e.svc.AuthenticateToken(e.ctx, secret)
	require.NoError(t, err)
	assert.Equal(t, rbac.Role(""), tp.Role, "no global role: no platform route")
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Admin, Services: []uuid.UUID{b}}}, tp.Grants)
	assert.Equal(t, []uuid.UUID{b}, tp.TokenServices)
	listed, err := e.svc.ListTokens(e.ctx, admin, meta, uuid.Nil)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, []uuid.UUID{b}, listed[0].ServiceIDs)

	in.ServiceIDs = []uuid.UUID{uuid.New()}
	_, _, err = e.svc.CreateToken(e.ctx, admin, meta, in)
	assert.ErrorIs(t, err, auth.ErrTokenServiceNotAllowed, "an unknown service")
	in.ServiceIDs = []uuid.UUID{}
	_, _, err = e.svc.CreateToken(e.ctx, admin, meta, in)
	var v validate.Errors
	require.ErrorAs(t, err, &v, "an empty limit")
	assert.Equal(t, "service_ids", v[0].Field)

	// A person with a binding on B only: a limit to B works, to C is refused; removing the binding stops the token.
	u := e.createUser(t, admin, "olga", auth.NoGlobalRole)
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO role_bindings (id, user_id, role, service_id, created_at) VALUES (gen_random_uuid(), $1, 'operator', $2, now())`,
		u.ID, b)
	require.NoError(t, err)
	_, res := e.enroll(t, "olga", adminPassword)
	p := e.principal(t, res.Token)
	in.ServiceIDs = []uuid.UUID{c}
	_, _, err = e.svc.CreateToken(e.ctx, p, meta, in)
	assert.ErrorIs(t, err, auth.ErrTokenServiceNotAllowed)
	in.ServiceIDs = []uuid.UUID{b}
	opSecret, _, err := e.svc.CreateToken(e.ctx, p, meta, in)
	require.NoError(t, err)
	tp, err = e.svc.AuthenticateToken(e.ctx, opSecret)
	require.NoError(t, err)
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Operator, Services: []uuid.UUID{b}}}, tp.Grants)
	_, err = e.db.Owner.Exec(e.ctx, "DELETE FROM role_bindings WHERE user_id = $1", u.ID)
	require.NoError(t, err)
	_, err = e.svc.AuthenticateToken(e.ctx, opSecret)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "the next request after the binding goes")
}
