//go:build integration

package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/rbac"
)

func identity(p uuid.UUID, sub, user, email string) auth.OIDCIdentity {
	return auth.OIDCIdentity{ProviderID: p, Issuer: "https://idp.example.com", Subject: sub, Username: user, DisplayName: "Ada Yılmaz", Email: email}
}

// liveSessions counts the sessions of a user that are not revoked.
func (e *env) liveSessions(t *testing.T, userID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, userID).Scan(&n))
	return n
}

// O-09: an SSO user is matched by provider and subject (S-8); e-mail and role follow the provider at every sign-in.
func TestSignInOIDCProvisionsAndMatchesBySubject(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	res, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "ada", "ada@example.com"), rbac.Operator, meta)
	require.NoError(t, err)
	pr := e.principal(t, res.Token)
	assert.Equal(t, rbac.Operator, pr.Role)
	assert.Equal(t, "oidc", pr.AuthSource)
	assert.True(t, pr.Subject(e.clk.Now()).StepUp, "the IdP just authenticated the user: the step-up window is open")
	assert.Equal(t, "oidc", res.Info.AuthSource)
	require.NotNil(t, res.Info.SSOProviderID)
	assert.Equal(t, p, *res.Info.SSOProviderID)
	assert.Equal(t, "oidc", res.Info.User.AuthSource)
	var source, roleSource, issuer, locale string
	var hash *string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT auth_source, role_source, password_hash, oidc_issuer, locale FROM users WHERE id = $1`, pr.UserID).
		Scan(&source, &roleSource, &hash, &issuer, &locale))
	assert.Equal(t, [2]string{"oidc", "oidc_mapping"}, [2]string{source, roleSource})
	assert.Nil(t, hash, "no password")
	assert.Equal(t, "https://idp.example.com", issuer, "the issuer is kept for display")
	assert.Equal(t, "en", locale, "no locale.default setting: English")

	res2, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "ada.new", "ada@new.example.com"), rbac.Auditor, meta)
	require.NoError(t, err)
	pr2 := e.principal(t, res2.Token)
	assert.Equal(t, pr.UserID, pr2.UserID, "same provider and subject: same user")
	assert.Equal(t, rbac.Auditor, pr2.Role, "the role follows the mapping")
	assert.Equal(t, rbac.Auditor, e.principal(t, res.Token).Role, "an open session reads the new role at once")
	u, err := e.svc.GetUser(e.ctx, pr.UserID)
	require.NoError(t, err)
	assert.Equal(t, "ada@new.example.com", u.Email)
	assert.Equal(t, "ada", u.Username, "the user name is kept")
	assert.Equal(t, "Ada Yılmaz", u.DisplayName)
	require.NotNil(t, u.LastLoginAt)
	assert.Contains(t, e.actions(t), "user.provisioned:success")
	assert.Contains(t, e.actions(t), "user.role_synced:success")
	assert.Equal(t, 2, e.countAction(t, "auth.login", "success"))
	var method, providerID, role string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'method', details->>'provider_id', details->>'role' FROM audit_log
WHERE action = 'auth.login' ORDER BY seq DESC LIMIT 1`).Scan(&method, &providerID, &role))
	assert.Equal(t, [3]string{"oidc", p.String(), "auditor"}, [3]string{method, providerID, role})
	var from, to, actorType string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'from_role', details->>'to_role', actor_type FROM audit_log
WHERE action = 'user.role_synced'`).Scan(&from, &to, &actorType))
	assert.Equal(t, [3]string{"operator", "auditor", "oidc"}, [3]string{from, to, actorType})

	// Another subject with a taken user name gets a suffix; the default locale applies to new users.
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('locale.default', '"tr"', now())`)
	require.NoError(t, err)
	res3, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-2", "ada", ""), rbac.Auditor, meta)
	require.NoError(t, err)
	u3, err := e.svc.GetUser(e.ctx, e.principal(t, res3.Token).UserID)
	require.NoError(t, err)
	assert.Equal(t, "ada-2", u3.Username)
	assert.Equal(t, "tr", u3.Locale)
	res4, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-3", "ADA", ""), rbac.Auditor, meta)
	require.NoError(t, err)
	u4, err := e.svc.GetUser(e.ctx, e.principal(t, res4.Token).UserID)
	require.NoError(t, err)
	assert.Equal(t, "ADA-3", u4.Username, "user names compare case-insensitively")
}

// A user name at the 64-byte limit is cut to leave room for the suffix; a blank display name becomes the user name.
func TestSignInOIDCLongNamesAndBlankDisplayName(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	long := "a234567890123456789012345678901234567890123456789012345678901234"
	require.Len(t, long, 64)
	_, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", long, ""), rbac.Operator, meta)
	require.NoError(t, err)
	id := identity(p, "sub-2", long, "")
	id.DisplayName = "  "
	res, err := e.svc.SignInOIDC(e.ctx, id, rbac.Operator, meta)
	require.NoError(t, err)
	u, err := e.svc.GetUser(e.ctx, e.principal(t, res.Token).UserID)
	require.NoError(t, err)
	assert.Equal(t, long[:62]+"-2", u.Username)
	assert.Equal(t, u.Username, u.DisplayName)

	// An identity without a name, with an address that is not a plain address and an overlong
	// display name; an unsupported default locale.
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('locale.default', '"de"', now())`)
	require.NoError(t, err)
	odd := identity(p, "sub-4", "", "Ada <ada@example.com>")
	odd.DisplayName = strings.Repeat("Ş", 120)
	res, err = e.svc.SignInOIDC(e.ctx, odd, rbac.Operator, meta)
	require.NoError(t, err)
	u, err = e.svc.GetUser(e.ctx, e.principal(t, res.Token).UserID)
	require.NoError(t, err)
	assert.Equal(t, "sso-user", u.Username)
	assert.Empty(t, u.Email, "only a plain address is stored")
	assert.Equal(t, strings.Repeat("Ş", 100), u.DisplayName)
	assert.Equal(t, "en", u.Locale)
	// A name is cut on a character boundary.
	res, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-5", strings.Repeat("b", 63)+"Ş", ""), rbac.Operator, meta)
	require.NoError(t, err)
	u, err = e.svc.GetUser(e.ctx, e.principal(t, res.Token).UserID)
	require.NoError(t, err)
	assert.Equal(t, strings.Repeat("b", 63), u.Username)

	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "", "x", ""), rbac.Operator, meta)
	require.Error(t, err, "no subject")
	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-3", "x", ""), rbac.Role("root"), meta)
	require.Error(t, err, "an unknown role")
}

// S-8: two providers at one issuer never share users.
func TestSignInOIDCMatchesByProviderNotIssuer(t *testing.T) {
	e := newEnv(t)
	p1, p2 := e.provider(t), e.provider(t)
	res1, err := e.svc.SignInOIDC(e.ctx, identity(p1, "sub-1", "ada", ""), rbac.Operator, meta)
	require.NoError(t, err)
	res2, err := e.svc.SignInOIDC(e.ctx, identity(p2, "sub-1", "ada", ""), rbac.Auditor, meta)
	require.NoError(t, err)
	a, b := e.principal(t, res1.Token), e.principal(t, res2.Token)
	assert.NotEqual(t, a.UserID, b.UserID)
	assert.Equal(t, rbac.Operator, a.Role, "the other provider's role never reaches this user")
}

// O-10: never a link to a local account; local sign-in of an SSO user fails like any wrong password.
func TestO10NoLinkToLocalAccounts(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	local := e.createUser(t, admin, "ada", rbac.Operator)
	_, err := e.svc.UpdateUser(e.ctx, admin, meta, local.ID, auth.UserUpdate{Email: ptr("ada@example.com")})
	require.NoError(t, err)
	p := e.provider(t)
	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "ada-corp", "ADA@example.com"), rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrOIDCEmailInUse)
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM users WHERE auth_source = 'oidc'`).Scan(&n))
	assert.Zero(t, n, "nothing created")

	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-9", "sso-user", "sso@example.com"), rbac.Operator, meta)
	require.NoError(t, err)
	_, err = e.svc.Login(e.ctx, "sso-user", adminPassword, meta)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials, "an SSO user has no local sign-in")
}

// S-7: a known SSO user cannot take a local user's e-mail address at a later sign-in either.
func TestS7EmailUpdateKeepsTheCollisionRule(t *testing.T) {
	e := newEnv(t)
	e.adminPrincipal(t) // the local Administrator's address is ayse@example.com
	p := e.provider(t)
	res, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "ada", "ada@corp.example.com"), rbac.Operator, meta)
	require.NoError(t, err)
	pr := e.principal(t, res.Token)
	before := e.liveSessions(t, pr.UserID)
	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "ada", "Ayse@Example.com"), rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrOIDCEmailInUse, "ayse@example.com is the local Administrator's")
	assert.Equal(t, before, e.liveSessions(t, pr.UserID), "no session issued")
	u, err := e.svc.GetUser(e.ctx, pr.UserID)
	require.NoError(t, err)
	assert.Equal(t, "ada@corp.example.com", u.Email)

	// The same address in another case is not a change.
	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "ada", "ADA@corp.example.com"), rbac.Operator, meta)
	require.NoError(t, err)
}

func TestSSOUserRulesAndBreakGlass(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	p := e.provider(t)
	res, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "boss", "boss@example.com"), rbac.Admin, meta)
	require.NoError(t, err)
	sso := e.principal(t, res.Token)
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, sso.UserID, auth.UserUpdate{Role: ptr(rbac.Auditor)})
	assert.ErrorIs(t, err, auth.ErrSSOUser)
	err = e.svc.ResetPassword(e.ctx, admin, meta, sso.UserID, adminPassword)
	assert.ErrorIs(t, err, auth.ErrSSOUser)
	assert.ErrorIs(t, e.svc.ResetMFA(e.ctx, admin, meta, sso.UserID), auth.ErrSSOUser)
	assert.Equal(t, map[string]int{"sso_user": 1}, e.reasons(t, "user.updated"))
	assert.Equal(t, map[string]int{"sso_user": 1}, e.reasons(t, "user.password_reset"))
	assert.Equal(t, map[string]int{"sso_user": 1}, e.reasons(t, "user.mfa_reset"))
	var hash *string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT password_hash FROM users WHERE id = $1`, sso.UserID).Scan(&hash))
	assert.Nil(t, hash)
	assert.Equal(t, 1, e.liveSessions(t, sso.UserID), "a refused change ends nothing")

	// No TOTP step-up and no password change for an SSO user, and neither counts as a failure.
	_, err = e.svc.StepUp(e.ctx, sso, "123456", meta)
	assert.ErrorIs(t, err, auth.ErrSSOUser)
	_, err = e.svc.ChangePassword(e.ctx, sso, "x", adminPassword+" new", meta)
	assert.ErrorIs(t, err, auth.ErrSSOUser)
	assert.Zero(t, e.failedLogins(t, "boss"))

	// B-s3-01: checked while the SSO Administrator is still enabled.
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, admin.UserID, auth.UserUpdate{Role: ptr(rbac.Operator)})
	assert.ErrorIs(t, err, auth.ErrLastAdmin, "an SSO Administrator is never the break-glass account")
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, sso.UserID, auth.UserUpdate{Disabled: ptr(true)})
	require.NoError(t, err, "an SSO user can be disabled")
	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "boss", "boss@example.com"), rbac.Admin, meta)
	assert.ErrorIs(t, err, auth.ErrOIDCUserDisabled)
	users, err := e.svc.ListUsers(e.ctx)
	require.NoError(t, err)
	sources := map[string]string{}
	for _, u := range users {
		sources[u.Username] = u.AuthSource
		if u.AuthSource == "oidc" {
			assert.Equal(t, &p, u.SSOProviderID)
		} else {
			assert.Nil(t, u.SSOProviderID)
		}
	}
	assert.Equal(t, map[string]string{"admin": "local", "boss": "oidc"}, sources)
}

// O-08, R42 row 21: a refused SSO sign-in of a known user ends that user's sessions.
func TestRefuseOIDCEndsSessions(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	id := identity(p, "sub-1", "ada", "")
	res, err := e.svc.SignInOIDC(e.ctx, id, rbac.Operator, meta)
	require.NoError(t, err)
	require.NoError(t, e.svc.RefuseOIDC(e.ctx, id, "no_access", meta))
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	assert.Equal(t, map[string]int{"no_access": 1}, e.reasons(t, "auth.oidc.denied"))
	assert.Contains(t, e.actions(t), "user.sessions_ended:success")
	var ended, actorType, providerID string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'ended_count' FROM audit_log WHERE action = 'user.sessions_ended'`).Scan(&ended))
	assert.Equal(t, "1", ended)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT actor_type, details->>'provider_id' FROM audit_log WHERE action = 'auth.oidc.denied'`).
		Scan(&actorType, &providerID))
	assert.Equal(t, [2]string{"oidc", p.String()}, [2]string{actorType, providerID})

	// Other reasons only audit: a token problem is no statement about the user's access.
	res2, err := e.svc.SignInOIDC(e.ctx, id, rbac.Operator, meta)
	require.NoError(t, err)
	require.NoError(t, e.svc.RefuseOIDC(e.ctx, id, "login_invalid", meta))
	e.principal(t, res2.Token)
	require.NoError(t, e.svc.RefuseOIDC(e.ctx, identity(p, "unknown", "x", ""), "no_access", meta), "an unknown identity is only audited")
	require.NoError(t, e.svc.RefuseOIDC(e.ctx, auth.OIDCIdentity{ProviderID: p}, "login_expired", meta), "no identity at all")
	assert.Equal(t, map[string]int{"no_access": 2, "login_invalid": 1, "login_expired": 1}, e.reasons(t, "auth.oidc.denied"))
	assert.Equal(t, 1, e.countAction(t, "user.sessions_ended", "success"))
}

// SEC-009, R42 row 22, S-1: an SSO user's step-up is a fresh IdP sign-in of the same identity, on a live session,
// with the role re-evaluated.
func TestStepUpOIDC(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t) // bootstrap refuses once any user exists
	p := e.provider(t)
	id := identity(p, "sub-1", "ada", "")
	res, err := e.svc.SignInOIDC(e.ctx, id, rbac.Operator, meta)
	require.NoError(t, err)
	e.clk.Advance(auth.StepUpWindow + time.Second)
	pr := e.principal(t, res.Token)
	require.False(t, pr.Subject(e.clk.Now()).StepUp)
	_, err = e.svc.StepUpOIDC(e.ctx, pr.SessionHash, pr.UserID, identity(p, "sub-2", "x", ""), rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrOIDCOtherUser)
	other := e.provider(t)
	_, err = e.svc.StepUpOIDC(e.ctx, pr.SessionHash, pr.UserID, identity(other, "sub-1", "ada", ""), rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrOIDCOtherUser, "the same subject at another provider is another identity")
	up, err := e.svc.StepUpOIDC(e.ctx, pr.SessionHash, pr.UserID, id, rbac.Auditor, meta)
	require.NoError(t, err)
	stepped := e.principal(t, up.Token)
	assert.True(t, stepped.Subject(e.clk.Now()).StepUp)
	assert.Equal(t, rbac.Auditor, stepped.Role, "S-1: the step-up re-evaluates the role")
	assert.Equal(t, 1, e.countAction(t, "user.role_synced", "success"))
	var method string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'method' FROM audit_log WHERE action = 'auth.stepup'`).Scan(&method))
	assert.Equal(t, "oidc", method)
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "the session ID was rotated")

	_, err = e.svc.StepUpOIDC(e.ctx, admin.SessionHash, admin.UserID, id, rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrNotSSOUser)
	_, err = e.svc.StepUpOIDC(e.ctx, admin.SessionHash, uuid.Must(uuid.NewV7()), id, rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "an unknown user")
}

// S-1: a session ended by RefuseOIDC, by idle expiry or by disabling is never resurrected by a step-up in flight.
func TestStepUpOIDCNeedsALiveSession(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	id := identity(p, "sub-1", "ada", "")
	res, err := e.svc.SignInOIDC(e.ctx, id, rbac.Operator, meta)
	require.NoError(t, err)
	pr := e.principal(t, res.Token)
	require.NoError(t, e.svc.RefuseOIDC(e.ctx, id, "groups_overage", meta))
	_, err = e.svc.StepUpOIDC(e.ctx, pr.SessionHash, pr.UserID, id, rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	assert.Zero(t, e.liveSessions(t, pr.UserID), "the revoked session stays revoked")

	res, err = e.svc.SignInOIDC(e.ctx, id, rbac.Operator, meta)
	require.NoError(t, err)
	pr = e.principal(t, res.Token)
	e.clk.Advance(auth.SessionIdle + time.Second)
	_, err = e.svc.StepUpOIDC(e.ctx, pr.SessionHash, pr.UserID, id, rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "an idle-expired session")

	res, err = e.svc.SignInOIDC(e.ctx, id, rbac.Operator, meta)
	require.NoError(t, err)
	pr = e.principal(t, res.Token)
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, pr.UserID)
	require.NoError(t, err)
	_, err = e.svc.StepUpOIDC(e.ctx, pr.SessionHash, pr.UserID, id, rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrOIDCUserDisabled)
}

// O-13, R42 row 24: switching SSO Administrators off demotes them to Auditor and ends their sessions.
func TestDemoteSSOAdmins(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	res, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "boss", ""), rbac.Admin, meta)
	require.NoError(t, err)
	res2, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-2", "op", ""), rbac.Operator, meta)
	require.NoError(t, err)
	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	demoted, ended, err := e.svc.DemoteSSOAdmins(e.ctx, tx, audit.SystemActor("test"))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(e.ctx))
	assert.Equal(t, [2]int{1, 1}, [2]int{demoted, ended})
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	e.principal(t, res2.Token)
	var role, from, to string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT role FROM users WHERE username = 'boss'`).Scan(&role))
	assert.Equal(t, "auditor", role)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'from_role', details->>'to_role' FROM audit_log WHERE action = 'user.demoted'`).
		Scan(&from, &to))
	assert.Equal(t, [2]string{"admin", "auditor"}, [2]string{from, to})

	tx, err = e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	demoted, ended, err = e.svc.DemoteSSOAdmins(e.ctx, tx, audit.SystemActor("test"))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(e.ctx))
	assert.Equal(t, [2]int{0, 0}, [2]int{demoted, ended}, "nothing left to demote")
}

// SEC-020, R42 row 25: a lockout queues auth.lockout once, in the lockout's transaction.
func TestLockoutEmailsTheAdministrators(t *testing.T) {
	e := newEnv(t)
	e.adminPrincipal(t)
	for i := 0; i < auth.LockThreshold; i++ {
		_, _ = e.svc.Login(context.Background(), "admin", "wrong password here", meta)
		e.clk.Advance(auth.MaxDelay)
	}
	assert.Equal(t, []string{"auth.lockout failed_logins=10,minutes=15,username=admin"}, e.notes.all())
	assert.Equal(t, []string{auth.TemplateLockout}, auth.Templates())
}

// The lockout and its e-mail commit together: a mail that cannot be queued rolls the lockout back.
func TestLockoutEmailIsInTheLockoutTransaction(t *testing.T) {
	e := newEnv(t)
	e.adminPrincipal(t)
	e.setFailures(t, "admin", auth.LockThreshold-1)
	e.notes.fail = errors.New("outbox unavailable")
	_, err := e.svc.Login(e.ctx, "admin", "wrong password here", meta)
	require.Error(t, err)
	assert.NotErrorIs(t, err, auth.ErrInvalidCredentials)
	assert.Equal(t, auth.LockThreshold-1, e.failedLogins(t, "admin"), "nothing committed")
	assert.Zero(t, e.countAction(t, "auth.lockout", "failure"))
}
