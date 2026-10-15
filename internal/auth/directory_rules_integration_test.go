//go:build integration

package auth_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// directory inserts an LDAP directory row (the directory users' foreign key).
func (e *env) directory(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO ldap_directories (id, name, addresses, user_base_dn, user_filter, login_attribute,
unique_id_attribute, display_name_attribute, email_attribute, bind_dn, group_base_dn, group_filter, group_name_attribute, enabled,
created_at, updated_at)
VALUES ($1, $2, '{ldaps://dc1.example.test}', 'dc=example,dc=test', '(sAMAccountName={login})', 'sAMAccountName', 'objectGUID',
'displayName', 'mail', 'cn=alice,dc=example,dc=test', 'dc=example,dc=test', '(member={dn})', 'cn', true, now(), now())`,
		id, "Corp "+id.String()[:8])
	require.NoError(t, err)
	return id
}

// directoryUser inserts a directory user row as SignInLDAP stores one.
func (e *env) directoryUser(t *testing.T, dir uuid.UUID, uniqueID, username string, role rbac.Role) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO users (id, username, display_name, auth_source, password_hash, role, role_source,
ldap_directory_id, ldap_unique_id, created_at, updated_at) VALUES ($1, $2, $7, 'ldap', NULL, $3, 'ldap_mapping', $4, $5, $6, $6)`,
		id, username, string(role), dir, uniqueID, e.clk.Now(), username)
	require.NoError(t, err)
	return id
}

// rawSession stores a session of the given kind for a user and returns its cookie value.
func (e *env) rawSession(t *testing.T, userID uuid.UUID, kind string) string {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	now := e.clk.Now()
	expires := now.Add(auth.SessionAbsolute)
	idle := now.Add(auth.SessionIdle)
	if kind == "pending" {
		expires, idle = now.Add(auth.PendingLifetime), now.Add(auth.PendingLifetime)
	}
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO sessions (id_hash, user_id, kind, created_at, last_seen_at, expires_at, idle_expires_at)
VALUES ($1, $2, $3, $4, $4, $5, $6)`, h[:], userID, kind, now, expires, idle)
	require.NoError(t, err)
	return token
}

// A directory user is like an SSO user where the rule is the same (no password, no manual role, no API token, no TOTP
// step-up: each refused with ErrDirectoryUser and audited as directory_user) and unlike one where the TOTP is
// concerned: it is Alice's, so it enrolls, verifies, regenerates its recovery codes and is reset by an Administrator.
func TestDirectoryUserRules(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	dir := e.directory(t)
	uid := e.directoryUser(t, dir, "0a1b2c3d", "ada", rbac.Operator)

	// The TOTP enrolment of a pending directory session completes with the existing VerifyMFA.
	pending := e.principal(t, e.rawSession(t, uid, "pending"))
	enr, err := e.svc.EnrollMFA(e.ctx, pending, meta)
	require.NoError(t, err)
	res, err := e.svc.VerifyMFA(e.ctx, pending, auth.MFAInput{Code: code(t, enr.Secret, e.clk.Now())}, meta)
	require.NoError(t, err)
	assert.Len(t, res.RecoveryCodes, 10)
	pr := e.principal(t, res.Token)
	assert.Equal(t, auth.AuthLDAP, pr.AuthSource)
	assert.Equal(t, dir, pr.LDAPDirectoryID, "the principal carries the directory")
	assert.Equal(t, uuid.Nil, admin.LDAPDirectoryID)
	require.NotNil(t, res.Info.User.LDAPDirectoryID)
	assert.Equal(t, dir, *res.Info.User.LDAPDirectoryID)
	assert.Nil(t, res.Info.User.SSOProviderID)
	assert.True(t, res.Info.User.MFAEnrolled)

	// Refused for a directory user, never counted as a failure.
	_, err = e.svc.ChangePassword(e.ctx, pr, "x", adminPassword+" new", meta)
	assert.ErrorIs(t, err, auth.ErrDirectoryUser)
	_, err = e.svc.StepUp(e.ctx, pr, code(t, enr.Secret, e.clk.Now().Add(30*time.Second)), meta)
	assert.ErrorIs(t, err, auth.ErrDirectoryUser, "a directory user steps up with StepUpLDAP")
	assert.Zero(t, e.failedLogins(t, "ada"))
	assert.NotErrorIs(t, err, auth.ErrSSOUser)
	err = e.svc.ResetPassword(e.ctx, admin, meta, uid, adminPassword)
	assert.ErrorIs(t, err, auth.ErrDirectoryUser)
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, uid, auth.UserUpdate{Role: ptr(rbac.Auditor)})
	assert.ErrorIs(t, err, auth.ErrDirectoryUser)
	for _, scope := range []rbac.Scope{rbac.ScopeRead, rbac.ScopeOperate} {
		_, _, err = e.svc.CreateToken(e.ctx, pr, meta, auth.NewToken{Name: "deploy", Scope: scope, ExpiresInDays: 1})
		assert.ErrorIs(t, err, auth.ErrDirectoryUser, scope)
	}
	forged := pr
	forged.AuthSource = auth.AuthLocal
	_, _, err = e.svc.CreateToken(e.ctx, forged, meta, auth.NewToken{Name: "deploy", Scope: rbac.ScopeRead, ExpiresInDays: 1})
	assert.ErrorIs(t, err, auth.ErrDirectoryUser, "the stored row decides, not the principal")
	assert.Equal(t, map[string]int{"directory_user": 1}, e.reasons(t, "user.updated"))
	assert.Equal(t, map[string]int{"directory_user": 1}, e.reasons(t, "user.password_reset"))
	var hash *string
	var role string
	var tokens int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT password_hash, role, (SELECT count(*) FROM api_tokens WHERE user_id = u.id)
FROM users u WHERE id = $1`, uid).Scan(&hash, &role, &tokens))
	assert.Nil(t, hash, "no password")
	assert.Equal(t, "operator", role)
	assert.Zero(t, tokens)
	assert.Equal(t, 1, e.liveSessions(t, uid), "a refused change ends nothing")

	// Allowed: the same role (no change), the profile, recovery codes, an MFA reset and disabling.
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, uid, auth.UserUpdate{Role: ptr(rbac.Operator), DisplayName: ptr("Ada Y.")})
	require.NoError(t, err, "an unchanged role is no role change")
	codes, err := e.svc.RegenerateRecoveryCodes(e.ctx, pr, meta)
	require.NoError(t, err, "a directory user's recovery codes are Alice's")
	assert.Len(t, codes, 10)
	require.NoError(t, e.svc.ResetMFA(e.ctx, admin, meta, uid))
	var mfaRows, codeRows int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT (SELECT count(*) FROM user_mfa WHERE user_id = $1),
(SELECT count(*) FROM recovery_codes WHERE user_id = $1)`, uid).Scan(&mfaRows, &codeRows))
	assert.Equal(t, [2]int{0, 0}, [2]int{mfaRows, codeRows})
	assert.Zero(t, e.liveSessions(t, uid), "an MFA reset ends the sessions")
	assert.Empty(t, e.reasons(t, "user.mfa_reset"))
	assert.Equal(t, 1, e.countAction(t, "user.mfa_reset", "success"))

	// The host-root CLI path too.
	pending = e.principal(t, e.rawSession(t, uid, "pending"))
	enr, err = e.svc.EnrollMFA(e.ctx, pending, meta)
	require.NoError(t, err)
	e.clk.Advance(30 * time.Second)
	_, err = e.svc.VerifyMFA(e.ctx, pending, auth.MFAInput{Code: code(t, enr.Secret, e.clk.Now())}, meta)
	require.NoError(t, err)
	require.NoError(t, e.svc.ResetMFAByUsername(e.ctx, "ada"))
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM user_mfa WHERE user_id = $1`, uid).Scan(&mfaRows))
	assert.Zero(t, mfaRows)

	_, err = e.svc.UpdateUser(e.ctx, admin, meta, uid, auth.UserUpdate{Disabled: ptr(true)})
	require.NoError(t, err, "a directory user can be disabled")

	u, err := e.svc.GetUser(e.ctx, uid)
	require.NoError(t, err)
	assert.Equal(t, auth.AuthLDAP, u.AuthSource)
	require.NotNil(t, u.LDAPDirectoryID)
	assert.Equal(t, dir, *u.LDAPDirectoryID)
	users, err := e.svc.ListUsers(e.ctx)
	require.NoError(t, err)
	for _, u := range users {
		if u.AuthSource != auth.AuthLDAP {
			assert.Nil(t, u.LDAPDirectoryID, u.Username)
		}
	}
}

// The SSO user rules keep ErrSSOUser (not ErrDirectoryUser) and the sso_user audit reason.
func TestSSOUserRefusalsKeepTheirError(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	res, err := e.svc.SignInOIDC(e.ctx, identity(e.provider(t), "sub-1", "boss", ""), rbac.Operator, meta)
	require.NoError(t, err)
	sso := e.principal(t, res.Token)
	assert.Equal(t, uuid.Nil, sso.LDAPDirectoryID)
	_, _, err = e.svc.CreateToken(e.ctx, sso, meta, auth.NewToken{Name: "deploy", Scope: rbac.ScopeRead, ExpiresInDays: 1})
	assert.ErrorIs(t, err, auth.ErrSSOUser)
	assert.NotErrorIs(t, err, auth.ErrDirectoryUser)
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, sso.UserID, auth.UserUpdate{Role: ptr(rbac.Auditor)})
	assert.ErrorIs(t, err, auth.ErrSSOUser)
	assert.ErrorIs(t, e.svc.ResetMFAByUsername(e.ctx, "boss"), auth.ErrSSOUser, "an SSO user has no TOTP here")
	assert.Equal(t, map[string]int{"sso_user": 1}, e.reasons(t, "user.updated"))
}

// Switching "SSO users may be Admin" off demotes directory Administrators too (plan ruling 8); they are never the
// break-glass account (lockAdmins counts local Administrators only).
func TestDemoteSSOAdminsCoversDirectoryUsers(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	dir := e.directory(t)
	boss := e.directoryUser(t, dir, "aa01", "boss", rbac.Admin)
	op := e.directoryUser(t, dir, "aa02", "op", rbac.Operator)
	bossToken, opToken := e.rawSession(t, boss, "full"), e.rawSession(t, op, "full")

	_, err := e.svc.UpdateUser(e.ctx, admin, meta, admin.UserID, auth.UserUpdate{Role: ptr(rbac.Operator)})
	assert.ErrorIs(t, err, auth.ErrLastAdmin, "a directory Administrator is never the break-glass account")

	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	demoted, ended, err := e.svc.DemoteSSOAdmins(e.ctx, tx, audit.SystemActor("test"))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(e.ctx))
	assert.Equal(t, [2]int{1, 1}, [2]int{demoted, ended})
	_, err = e.svc.Authenticate(e.ctx, bossToken)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	e.principal(t, opToken)
	var role string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT role FROM users WHERE id = $1`, boss).Scan(&role))
	assert.Equal(t, "auditor", role)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT role FROM users WHERE id = $1`, admin.UserID).Scan(&role))
	assert.Equal(t, "admin", role, "the local Administrator stays")
}

// Local sign-in never matches a directory user: a directory user's name typed into the local form fails exactly like
// an unknown name (the dummy Argon2 check, the unknown_user audit row, no session, nothing counted).
func TestLocalLoginNeverMatchesADirectoryUser(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	uid := e.directoryUser(t, dir, "bb01", "ada", rbac.Operator)
	var ops []string
	auth.SetHashHook(e.hasher, func(op string) { ops = append(ops, op) })
	defer auth.SetHashHook(e.hasher, nil)

	_, err := e.svc.Login(e.ctx, "ada", adminPassword, meta)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
	_, err2 := e.svc.Login(e.ctx, "nobody", adminPassword, meta)
	assert.ErrorIs(t, err2, auth.ErrInvalidCredentials)
	assert.Equal(t, err2.Error(), err.Error(), "the same answer as an unknown name")
	assert.Equal(t, []string{auth.HashOpDummy, auth.HashOpDummy}, ops)
	assert.Equal(t, map[string]int{"unknown_user": 2}, e.reasons(t, "auth.login"))
	var objectIDs, actorIDs int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FILTER (WHERE object_id <> ''), count(*) FILTER (WHERE actor_id IS NOT NULL)
FROM audit_log WHERE action = 'auth.login'`).Scan(&objectIDs, &actorIDs))
	assert.Equal(t, [2]int{0, 0}, [2]int{objectIDs, actorIDs}, "the directory user is not named")
	var sessions int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, uid).Scan(&sessions))
	assert.Zero(t, sessions)
	assert.Zero(t, e.failedLogins(t, "ada"))
	assert.False(t, strings.Contains(strings.Join(e.actions(t), ","), "success"))
}
