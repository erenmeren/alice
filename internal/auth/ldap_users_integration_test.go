//go:build integration

package auth_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
)

func ldapIdentity(dir uuid.UUID, uniqueID, login, email string) auth.LDAPIdentity {
	return auth.LDAPIdentity{DirectoryID: dir, UniqueID: uniqueID, Login: login, DisplayName: "Şükrü Öztürk", Email: email}
}

// signInLDAP signs a directory user in without MFA and returns the full session's principal.
func (e *env) signInLDAP(t *testing.T, id auth.LDAPIdentity, role rbac.Role) auth.Principal {
	t.Helper()
	res, err := e.svc.SignInLDAP(e.ctx, id, role, false, meta)
	require.NoError(t, err)
	require.Equal(t, auth.StatusSignedIn, res.Status)
	return e.principal(t, res.SessionToken)
}

// sessionKinds counts a user's stored sessions by kind.
func (e *env) sessionKinds(t *testing.T, userID uuid.UUID) map[string]int {
	t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, `SELECT kind, count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL GROUP BY kind`, userID)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		require.NoError(t, rows.Scan(&k, &n))
		out[k] = n
	}
	require.NoError(t, rows.Err())
	return out
}

// A first directory sign-in creates the user (name from the transliteration table, no password, the role from the
// mappings); later sign-ins follow the directory's role, e-mail and display name and are matched by unique id only.
func TestSignInLDAPProvisionsAndFollowsTheDirectory(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	dir := e.directory(t)
	id := ldapIdentity(dir, "0a1b2c3d4e5f", "Şükrü.Öztürk", "sukru@corp.example.com")
	res, err := e.svc.SignInLDAP(e.ctx, id, rbac.Operator, false, meta)
	require.NoError(t, err)
	assert.Equal(t, auth.StatusSignedIn, res.Status)
	require.NotNil(t, res.Session)
	assert.Equal(t, res.SessionToken, res.Session.Token)
	assert.Equal(t, auth.AuthLDAP, res.Session.Info.AuthSource)
	require.NotNil(t, res.Session.Info.User.LDAPDirectoryID)
	assert.Equal(t, dir, *res.Session.Info.User.LDAPDirectoryID)
	pr := e.principal(t, res.SessionToken)
	assert.Equal(t, rbac.Operator, pr.Role)
	assert.Equal(t, auth.AuthLDAP, pr.AuthSource)
	assert.Equal(t, dir, pr.LDAPDirectoryID)
	assert.Equal(t, "sukru.ozturk", pr.Username)
	assert.True(t, pr.Subject(e.clk.Now()).StepUp, "the directory password was just typed: the step-up window is open")
	assert.False(t, pr.Subject(e.clk.Now().Add(auth.StepUpWindow)).StepUp)
	var source, roleSource, uniqueID, locale, display string
	var hash *string
	var lastLogin *time.Time
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT auth_source, role_source, password_hash, ldap_unique_id, locale, display_name, last_login_at
FROM users WHERE id = $1`, pr.UserID).Scan(&source, &roleSource, &hash, &uniqueID, &locale, &display, &lastLogin))
	assert.Equal(t, [2]string{"ldap", "ldap_mapping"}, [2]string{source, roleSource})
	assert.Nil(t, hash, "no password")
	assert.Equal(t, "0a1b2c3d4e5f", uniqueID)
	assert.Equal(t, "en", locale)
	assert.Equal(t, "Şükrü Öztürk", display)
	require.NotNil(t, lastLogin)
	var provActor, provDir, loginMethod, loginDir string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT actor_type, details->>'directory_id' FROM audit_log WHERE action = 'user.provisioned'`).
		Scan(&provActor, &provDir))
	assert.Equal(t, [2]string{"user", dir.String()}, [2]string{provActor, provDir})
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'method', details->>'directory_id' FROM audit_log
WHERE action = 'auth.login' AND details->>'method' = 'ldap'`).
		Scan(&loginMethod, &loginDir))
	assert.Equal(t, [2]string{"ldap", dir.String()}, [2]string{loginMethod, loginDir})
	assert.Equal(t, map[string]int{"full": 1}, e.sessionKinds(t, pr.UserID), "no pending session without MFA")

	// Second sign-in: a new role, e-mail and display name, and a changed login name: the same user.
	e.clk.Advance(time.Minute)
	id2 := ldapIdentity(dir, "0a1b2c3d4e5f", "sozturk", "Sukru@New.example.com")
	id2.DisplayName = "  "
	pr2 := e.signInLDAP(t, id2, rbac.Auditor)
	assert.Equal(t, pr.UserID, pr2.UserID, "same directory and unique id: same user")
	assert.Equal(t, rbac.Auditor, pr2.Role)
	assert.Equal(t, rbac.Auditor, e.principal(t, res.SessionToken).Role, "an open session reads the new role at once")
	u, err := e.svc.GetUser(e.ctx, pr.UserID)
	require.NoError(t, err)
	assert.Equal(t, "sukru.ozturk", u.Username, "the user name is kept")
	assert.Equal(t, "Sukru@New.example.com", u.Email)
	assert.Equal(t, "sukru.ozturk", u.DisplayName, "a blank display name becomes the user name")
	assert.True(t, u.LastLoginAt.After(*lastLogin))
	var from, to, syncActor string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'from_role', details->>'to_role', actor_type FROM audit_log
WHERE action = 'user.role_synced'`).Scan(&from, &to, &syncActor))
	assert.Equal(t, [3]string{"operator", "auditor", "user"}, [3]string{from, to, syncActor})

	// Third sign-in with the same role: no role_synced row.
	e.signInLDAP(t, id2, rbac.Auditor)
	assert.Equal(t, 1, e.countAction(t, "user.role_synced", "success"))
	assert.Equal(t, 1, e.countAction(t, "user.provisioned", "success"))
	var ldapLogins int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND details->>'method' = 'ldap'`).
		Scan(&ldapLogins))
	assert.Equal(t, 3, ldapLogins)

	// Other people: a Turkish name, a name a local user has, a name with nothing usable, the default locale.
	e.createUser(t, admin, "jsmith", rbac.Operator)
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('locale.default', '"tr"', now())`)
	require.NoError(t, err)
	for _, c := range []struct{ uid, login, want string }{
		{"aa01", "Işıl.Çağlar", "isil.caglar"},
		{"aa02", "jsmith", "jsmith-2"},
		{"aa03", "JSMITH", "jsmith-3"},
		{"5e6f7a8b9c0d1e2f", "админ", "ldap-5e6f7a8b9c0d"},
	} {
		p := e.signInLDAP(t, ldapIdentity(dir, c.uid, c.login, ""), rbac.Operator)
		assert.Equal(t, c.want, p.Username, c.login)
		assert.Equal(t, "tr", p.Locale, c.login)
	}
}

// Two directories never share users, even with the same unique id.
func TestSignInLDAPMatchesByDirectoryAndUniqueID(t *testing.T) {
	e := newEnv(t)
	d1, d2 := e.directory(t), e.directory(t)
	a := e.signInLDAP(t, ldapIdentity(d1, "0102", "ada", ""), rbac.Operator)
	b := e.signInLDAP(t, ldapIdentity(d2, "0102", "ada", ""), rbac.Auditor)
	assert.NotEqual(t, a.UserID, b.UserID)
	assert.Equal(t, "ada-2", b.Username)
	assert.Equal(t, rbac.Operator, e.principal(t, mustSignIn(t, e, ldapIdentity(d1, "0102", "ada", ""), rbac.Operator)).Role)
	assert.Equal(t, rbac.Auditor, b.Role, "the other directory's role never reaches this user")
}

func mustSignIn(t *testing.T, e *env, id auth.LDAPIdentity, role rbac.Role) string {
	t.Helper()
	res, err := e.svc.SignInLDAP(e.ctx, id, role, false, meta)
	require.NoError(t, err)
	return res.SessionToken
}

// Never a link to a local account (plan ruling 2): a local user's e-mail address refuses a first sign-in and a later
// e-mail change; an empty or unusable address is fine.
func TestSignInLDAPEmailRule(t *testing.T) {
	e := newEnv(t)
	e.adminPrincipal(t) // the local Administrator's address is ayse@example.com
	dir := e.directory(t)
	_, err := e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, "01", "ayse", "AYSE@example.com"), rbac.Operator, false, meta)
	assert.ErrorIs(t, err, auth.ErrLDAPEmailInUse)
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM users WHERE auth_source = 'ldap'`).Scan(&n))
	assert.Zero(t, n, "nothing created")

	pr := e.signInLDAP(t, ldapIdentity(dir, "01", "ayse", ""), rbac.Operator)
	before := e.liveSessions(t, pr.UserID)
	_, err = e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, "01", "ayse", "ayse@example.com"), rbac.Operator, false, meta)
	assert.ErrorIs(t, err, auth.ErrLDAPEmailInUse)
	assert.Equal(t, before, e.liveSessions(t, pr.UserID), "no session issued")
	odd := e.signInLDAP(t, ldapIdentity(dir, "02", "odd", "Odd <odd@example.com>"), rbac.Operator)
	u, err := e.svc.GetUser(e.ctx, odd.UserID)
	require.NoError(t, err)
	assert.Empty(t, u.Email, "only a plain address is stored")

	// An SSO user's or another directory user's address is no local address.
	_, err = e.svc.SignInOIDC(e.ctx, identity(e.provider(t), "sub-1", "x", "shared@example.com"), rbac.Operator, meta)
	require.NoError(t, err)
	e.signInLDAP(t, ldapIdentity(dir, "03", "shared", "shared@example.com"), rbac.Operator)
	e.signInLDAP(t, ldapIdentity(e.directory(t), "03", "shared", "shared@example.com"), rbac.Operator)
}

// A user disabled in Alice is refused and gets no session; an identity Alice cannot store is refused before any work.
func TestSignInLDAPRefusals(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	dir := e.directory(t)
	pr := e.signInLDAP(t, ldapIdentity(dir, "0c", "ada", ""), rbac.Operator)
	_, err := e.svc.UpdateUser(e.ctx, admin, meta, pr.UserID, auth.UserUpdate{Disabled: ptr(true)})
	require.NoError(t, err)
	for _, mfa := range []bool{false, true} {
		_, err = e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, "0c", "ada", ""), rbac.Operator, mfa, meta)
		assert.ErrorIs(t, err, auth.ErrLDAPUserDisabled)
	}
	assert.Empty(t, e.sessionKinds(t, pr.UserID))

	for name, id := range map[string]auth.LDAPIdentity{
		"no directory":   ldapIdentity(uuid.Nil, "0c", "x", ""),
		"no unique id":   ldapIdentity(dir, "", "x", ""),
		"upper case":     ldapIdentity(dir, "0C", "x", ""),
		"odd length":     ldapIdentity(dir, "0c1", "x", ""),
		"not hex":        ldapIdentity(dir, "zz", "x", ""),
		"over 254":       ldapIdentity(dir, strings.Repeat("ab", 128), "x", ""),
		"with a newline": ldapIdentity(dir, "0c\n", "x", ""),
	} {
		_, err = e.svc.SignInLDAP(e.ctx, id, rbac.Operator, false, meta)
		assert.ErrorIs(t, err, auth.ErrLDAPIdentityInvalid, name)
	}
	_, err = e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, strings.Repeat("ab", 127), "x", ""), rbac.Operator, false, meta)
	require.NoError(t, err, "254 hex digits fit")
	_, err = e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, "0d", "x", ""), rbac.Role("root"), false, meta)
	assert.ErrorIs(t, err, auth.ErrLDAPIdentityInvalid, "an unknown role")
	_, err = e.svc.StepUpLDAP(e.ctx, pr, ldapIdentity(dir, "0c", "x", ""), rbac.Role("root"), "", false, meta)
	assert.ErrorIs(t, err, auth.ErrLDAPIdentityInvalid, "an unknown role")
}

// The "SSO users may be Admin" switch covers directory users (plan ruling 8), in the sign-in's own transaction.
func TestSignInLDAPCapsAdminWhileTheSwitchIsOff(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	id := ldapIdentity(dir, "0e", "boss", "")
	assert.Equal(t, rbac.Operator, e.signInLDAP(t, id, rbac.Admin).Role, "no setting: the switch is off")
	e.allowAdmin(t, true)
	pr := e.signInLDAP(t, id, rbac.Admin)
	assert.Equal(t, rbac.Admin, pr.Role)
	e.allowAdmin(t, false)
	pr = e.signInLDAP(t, id, rbac.Admin)
	assert.Equal(t, rbac.Operator, pr.Role)
	up, err := e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Admin, "", false, meta)
	require.NoError(t, err)
	assert.Equal(t, rbac.Operator, e.principal(t, up.Token).Role, "the step-up caps the same way")
}

// MFA per directory (plan ruling 7): on, the sign-in opens a pending session that the existing enrolment and
// verification complete; off, a full session at once. A stored TOTP stays when the setting flips.
func TestSignInLDAPWithAndWithoutMFA(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	id := ldapIdentity(dir, "0f", "ada", "")
	lr, err := e.svc.SignInLDAP(e.ctx, id, rbac.Operator, true, meta)
	require.NoError(t, err)
	assert.Equal(t, auth.StatusMFAEnrollmentRequired, lr.Status)
	assert.Nil(t, lr.Session)
	pending := e.principal(t, lr.SessionToken)
	assert.Equal(t, rbac.PendingSession, pending.Kind)
	assert.Equal(t, map[string]int{"pending": 1}, e.sessionKinds(t, pending.UserID))
	assert.Zero(t, e.countAction(t, "auth.login", "success"), "auth.login is written when MFA completes")
	var pendingExpiry time.Time
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT expires_at FROM sessions WHERE user_id = $1`, pending.UserID).Scan(&pendingExpiry))
	assert.True(t, e.clk.Now().Add(auth.PendingLifetime).Equal(pendingExpiry))
	enr, err := e.svc.EnrollMFA(e.ctx, pending, meta)
	require.NoError(t, err)
	res, err := e.svc.VerifyMFA(e.ctx, pending, auth.MFAInput{Code: code(t, enr.Secret, e.clk.Now())}, meta)
	require.NoError(t, err)
	assert.Len(t, res.RecoveryCodes, 10)
	full := e.principal(t, res.Token)
	assert.Equal(t, rbac.UserSession, full.Kind)
	assert.Equal(t, auth.AuthLDAP, full.AuthSource)
	assert.Equal(t, map[string]int{"full": 1}, e.sessionKinds(t, full.UserID))

	// With a TOTP: mfa_required.
	e.clk.Advance(30 * time.Second)
	lr, err = e.svc.SignInLDAP(e.ctx, id, rbac.Operator, true, meta)
	require.NoError(t, err)
	assert.Equal(t, auth.StatusMFARequired, lr.Status)
	_, err = e.svc.VerifyMFA(e.ctx, e.principal(t, lr.SessionToken), auth.MFAInput{Code: code(t, enr.Secret, e.clk.Now())}, meta)
	require.NoError(t, err)

	// The directory's MFA switched off: a full session without the code; the TOTP row is untouched.
	var enrolledBefore, enrolledAfter time.Time
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT enrolled_at FROM user_mfa WHERE user_id = $1`, full.UserID).Scan(&enrolledBefore))
	pr := e.signInLDAP(t, id, rbac.Operator)
	assert.Equal(t, full.UserID, pr.UserID)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT enrolled_at FROM user_mfa WHERE user_id = $1`, full.UserID).Scan(&enrolledAfter))
	assert.True(t, enrolledBefore.Equal(enrolledAfter))
	var codes int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = $1`, full.UserID).Scan(&codes))
	assert.Equal(t, 10, codes)
	// And on again: the same TOTP is asked for.
	lr, err = e.svc.SignInLDAP(e.ctx, id, rbac.Operator, true, meta)
	require.NoError(t, err)
	assert.Equal(t, auth.StatusMFARequired, lr.Status)
	methods := map[string]int{}
	rows, err := e.db.Owner.Query(e.ctx, `SELECT details->>'method' FROM audit_log WHERE action = 'auth.login' AND result = 'success'`)
	require.NoError(t, err)
	for rows.Next() {
		var m string
		require.NoError(t, rows.Scan(&m))
		methods[m]++
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, map[string]int{"totp": 2, "ldap": 1}, methods)
}

// The TOTP failure counters, delay and lockout of a directory user's second factor are the local user's.
func TestSignInLDAPTOTPFailuresCount(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	id := ldapIdentity(dir, "10", "ada", "")
	lr, err := e.svc.SignInLDAP(e.ctx, id, rbac.Operator, true, meta)
	require.NoError(t, err)
	p := e.principal(t, lr.SessionToken)
	enr, err := e.svc.EnrollMFA(e.ctx, p, meta)
	require.NoError(t, err)
	_, err = e.svc.VerifyMFA(e.ctx, p, auth.MFAInput{Code: code(t, enr.Secret, e.clk.Now())}, meta)
	require.NoError(t, err)

	for i := range auth.LockThreshold {
		e.clk.Advance(auth.MaxDelay)
		lr, err := e.svc.SignInLDAP(e.ctx, id, rbac.Operator, true, meta)
		require.NoError(t, err, "the directory accepted the password: a pending session (%d)", i)
		_, err = e.svc.VerifyMFA(e.ctx, e.principal(t, lr.SessionToken), auth.MFAInput{Code: "000000"}, meta)
		require.ErrorIs(t, err, auth.ErrMFAInvalid)
	}
	assert.Equal(t, auth.LockThreshold, e.failedLogins(t, "ada"))
	assert.Equal(t, 1, e.countAction(t, "auth.lockout", "failure"))
	lr, err = e.svc.SignInLDAP(e.ctx, id, rbac.Operator, true, meta)
	require.NoError(t, err)
	_, err = e.svc.VerifyMFA(e.ctx, e.principal(t, lr.SessionToken), auth.MFAInput{Code: code(t, enr.Secret, e.clk.Now())}, meta)
	assert.ErrorIs(t, err, auth.ErrMFAInvalid, "locked: even the right code is refused")
	assert.Equal(t, map[string]int{"bad_totp": auth.LockThreshold, "locked": 1}, e.reasons(t, "auth.mfa_verify"))
}

// The directory step-up (plan ruling 6): the same identity, the role read again, the TOTP when the directory asks for
// it (counted), a live full session; the session ID rotates with a 5-minute window.
func TestStepUpLDAP(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	dir := e.directory(t)
	id := ldapIdentity(dir, "11", "ada", "")
	token := mustSignIn(t, e, id, rbac.Operator)
	e.clk.Advance(auth.StepUpWindow + time.Second)
	pr := e.principal(t, token)
	require.False(t, pr.Subject(e.clk.Now()).StepUp, "the sign-in's window has passed")

	_, err := e.svc.StepUpLDAP(e.ctx, pr, ldapIdentity(dir, "12", "ada", ""), rbac.Operator, "", false, meta)
	assert.ErrorIs(t, err, auth.ErrLDAPOtherUser)
	_, err = e.svc.StepUpLDAP(e.ctx, pr, ldapIdentity(e.directory(t), "11", "ada", ""), rbac.Operator, "", false, meta)
	assert.ErrorIs(t, err, auth.ErrLDAPOtherUser, "the same unique id in another directory is another identity")
	_, err = e.svc.StepUpLDAP(e.ctx, admin, id, rbac.Operator, "", false, meta)
	assert.ErrorIs(t, err, auth.ErrLDAPOtherUser, "a local user is no directory identity")

	up, err := e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Auditor, "", false, meta)
	require.NoError(t, err)
	stepped := e.principal(t, up.Token)
	assert.True(t, stepped.Subject(e.clk.Now()).StepUp)
	assert.True(t, e.clk.Now().Add(auth.StepUpWindow).Equal(stepped.StepUpUntil), "a 5-minute window")
	assert.Equal(t, rbac.Auditor, stepped.Role, "the step-up re-evaluates the role")
	assert.Equal(t, 1, e.countAction(t, "user.role_synced", "success"))
	var method, actorType string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'method', actor_type FROM audit_log WHERE action = 'auth.stepup'`).
		Scan(&method, &actorType))
	assert.Equal(t, [2]string{"ldap", "user"}, [2]string{method, actorType})
	_, err = e.svc.Authenticate(e.ctx, token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "the session ID was rotated")
	_, err = e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Auditor, "", false, meta)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "the old session ID was rotated away")

	// A pending session cannot step up.
	lr, err := e.svc.SignInLDAP(e.ctx, id, rbac.Auditor, true, meta)
	require.NoError(t, err)
	_, err = e.svc.StepUpLDAP(e.ctx, e.principal(t, lr.SessionToken), id, rbac.Auditor, "", false, meta)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)

	// Disabled in Alice.
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, stepped.UserID)
	require.NoError(t, err)
	_, err = e.svc.StepUpLDAP(e.ctx, stepped, id, rbac.Auditor, "", false, meta)
	assert.ErrorIs(t, err, auth.ErrLDAPUserDisabled)
}

// With the directory's mfa_required on, the step-up also needs the TOTP: a wrong or missing code is counted like a
// failed StepUp, a right one opens the window and clears the counter. Off, the bind alone is enough.
func TestStepUpLDAPWithTOTP(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	id := ldapIdentity(dir, "13", "ada", "")
	lr, err := e.svc.SignInLDAP(e.ctx, id, rbac.Operator, true, meta)
	require.NoError(t, err)
	p := e.principal(t, lr.SessionToken)
	enr, err := e.svc.EnrollMFA(e.ctx, p, meta)
	require.NoError(t, err)
	res, err := e.svc.VerifyMFA(e.ctx, p, auth.MFAInput{Code: code(t, enr.Secret, e.clk.Now())}, meta)
	require.NoError(t, err)
	pr := e.principal(t, res.Token)

	e.clk.Advance(30 * time.Second)
	for _, bad := range []string{"", "000000"} {
		_, err = e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Operator, bad, true, meta)
		assert.ErrorIs(t, err, auth.ErrMFAInvalid, "%q", bad)
	}
	assert.Equal(t, 2, e.failedLogins(t, "ada"))
	assert.Equal(t, map[string]int{"bad_totp": 2}, e.reasons(t, "auth.stepup"))
	e.principal(t, res.Token) // a failed step-up keeps the session
	up, err := e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Operator, code(t, enr.Secret, e.clk.Now()), true, meta)
	require.NoError(t, err)
	assert.Zero(t, e.failedLogins(t, "ada"), "a good code clears the counter")
	pr = e.principal(t, up.Token)

	// The same code again is a replay.
	_, err = e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Operator, code(t, enr.Secret, e.clk.Now()), true, meta)
	assert.ErrorIs(t, err, auth.ErrMFAInvalid)
	// Locked: refused without checking the code.
	e.setFailures(t, "ada", auth.LockThreshold-1)
	e.clk.Advance(30 * time.Second)
	_, err = e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Operator, "111111", true, meta)
	assert.ErrorIs(t, err, auth.ErrMFAInvalid)
	assert.Equal(t, 1, e.countAction(t, "auth.lockout", "failure"))
	_, err = e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Operator, code(t, enr.Secret, e.clk.Now()), true, meta)
	assert.ErrorIs(t, err, auth.ErrMFAInvalid)
	assert.Equal(t, 1, e.reasons(t, "auth.stepup")["locked"])

	// The directory's MFA off: the bind alone; the lockout is the TOTP's and does not apply.
	up, err = e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Operator, "", false, meta)
	require.NoError(t, err)
	assert.True(t, e.principal(t, up.Token).Subject(e.clk.Now()).StepUp)

	// A user without a TOTP while the directory asks for one (the setting was switched on during the session).
	other := ldapIdentity(dir, "14", "bob", "")
	bob := e.signInLDAP(t, other, rbac.Operator)
	_, err = e.svc.StepUpLDAP(e.ctx, bob, other, rbac.Operator, "123456", true, meta)
	assert.ErrorIs(t, err, auth.ErrMFAInvalid)
	assert.Equal(t, 1, e.failedLogins(t, "bob"))
}

// RefuseLDAP audits auth.ldap.denied with the reason, the directory and the sign-in name; a known user is the actor,
// an unknown one is recorded as the system. no_access and provider_disabled end a known user's sessions and tokens;
// other reasons only audit.
func TestRefuseLDAP(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	id := ldapIdentity(dir, "15", "ada", "")
	pr := e.signInLDAP(t, id, rbac.Operator)
	tokens := e.ssoTokens(t, pr.UserID, rbac.ScopeRead, 2)

	require.NoError(t, e.svc.RefuseLDAP(e.ctx, auth.LDAPIdentity{DirectoryID: dir, Login: "nobody"}, "bad_credentials", meta))
	require.NoError(t, e.svc.RefuseLDAP(e.ctx, auth.LDAPIdentity{DirectoryID: dir, Login: "x\x00y"}, "login_invalid", meta))
	require.NoError(t, e.svc.RefuseLDAP(e.ctx, auth.LDAPIdentity{DirectoryID: dir, Login: strings.Repeat("ş", 200)}, "directory_unreachable", meta))
	require.NoError(t, e.svc.RefuseLDAP(e.ctx, auth.LDAPIdentity{DirectoryID: dir, UniqueID: "99", Login: "ghost"}, "no_access", meta),
		"an unknown identity is only audited")
	require.NoError(t, e.svc.RefuseLDAP(e.ctx, id, "user_disabled", meta))
	e.principal(t, tokenOfSession(t, e, pr))
	assert.True(t, e.tokenWorks(t, tokens[0]), "a refusal that says nothing about access ends nothing")

	type row struct{ actorType, actorName, objectID, dir, login string }
	read := func() []row {
		rows, err := e.db.Owner.Query(e.ctx, `SELECT actor_type, actor_name, object_id, details->>'directory_id', coalesce(details->>'login_name', '-')
FROM audit_log WHERE action = 'auth.ldap.denied' ORDER BY seq`)
		require.NoError(t, err)
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			require.NoError(t, rows.Scan(&r.actorType, &r.actorName, &r.objectID, &r.dir, &r.login))
			out = append(out, r)
		}
		require.NoError(t, rows.Err())
		return out
	}
	d := dir.String()
	assert.Equal(t, []row{
		{"system", "(unknown user)", "", d, "nobody"},
		{"system", "(unknown user)", "", d, "-"},
		{"system", "(unknown user)", "", d, strings.Repeat("ş", 128)},
		{"system", "(unknown user)", "", d, "ghost"},
		{"user", "ada", pr.UserID.String(), d, "ada"},
	}, read())
	assert.Equal(t, map[string]int{"bad_credentials": 1, "login_invalid": 1, "directory_unreachable": 1, "no_access": 1, "user_disabled": 1},
		e.reasons(t, "auth.ldap.denied"))
	assert.Zero(t, e.countAction(t, "user.sessions_ended", "success"))

	// no_access for the known user: sessions and tokens end.
	require.NoError(t, e.svc.RefuseLDAP(e.ctx, id, "no_access", meta))
	assert.Zero(t, e.liveSessions(t, pr.UserID))
	for _, s := range tokens {
		assert.False(t, e.tokenWorks(t, s))
	}
	assert.Equal(t, "2", *e.lastDetail(t, "user.sessions_ended", "revoked_tokens_count"))
	assert.Equal(t, "no_access", *e.lastDetail(t, "user.sessions_ended", "reason"))
	for _, r := range e.tokenRevocations(t, pr.UserID) {
		assert.Equal(t, [2]string{"no_access", "ada"}, [2]string{r.reason, r.actor})
	}
	// A step-up in flight on the ended session is refused: the session is not resurrected.
	_, err := e.svc.StepUpLDAP(e.ctx, pr, id, rbac.Operator, "", false, meta)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)

	// provider_disabled ends them too.
	pr = e.signInLDAP(t, id, rbac.Operator)
	require.NoError(t, e.svc.RefuseLDAP(e.ctx, id, "provider_disabled", meta))
	assert.Zero(t, e.liveSessions(t, pr.UserID))
	assert.Equal(t, 2, e.countAction(t, "user.sessions_ended", "success"))
}

// tokenOfSession checks p's session is still live and returns a fresh cookie of the same user (a new sign-in), so the
// caller can assert it authenticates.
func tokenOfSession(t *testing.T, e *env, p auth.Principal) string {
	t.Helper()
	require.Equal(t, 1, e.liveSessions(t, p.UserID))
	var dir uuid.UUID
	var uid string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT ldap_directory_id, ldap_unique_id FROM users WHERE id = $1`, p.UserID).Scan(&dir, &uid))
	return mustSignIn(t, e, ldapIdentity(dir, uid, p.Username, ""), p.Role)
}

// No audit row of a directory sign-in, step-up or refusal carries a password, a code or a secret: the details keys
// are the closed ones, and no value holds the TOTP secret or a code that was typed.
func TestLDAPAuditRowsCarryNoSecrets(t *testing.T) {
	e := newEnv(t)
	e.allowAdmin(t, true)
	dir := e.directory(t)
	id := ldapIdentity(dir, "16", "ada", "")
	lr, err := e.svc.SignInLDAP(e.ctx, id, rbac.Admin, true, meta)
	require.NoError(t, err)
	p := e.principal(t, lr.SessionToken)
	enr, err := e.svc.EnrollMFA(e.ctx, p, meta)
	require.NoError(t, err)
	first := code(t, enr.Secret, e.clk.Now())
	res, err := e.svc.VerifyMFA(e.ctx, p, auth.MFAInput{Code: first}, meta)
	require.NoError(t, err)
	e.clk.Advance(30 * time.Second)
	second := code(t, enr.Secret, e.clk.Now())
	_, err = e.svc.StepUpLDAP(e.ctx, e.principal(t, res.Token), id, rbac.Operator, second, true, meta)
	require.NoError(t, err)
	require.NoError(t, e.svc.RefuseLDAP(e.ctx, id, "no_access", meta))
	require.NoError(t, e.svc.RefuseLDAP(e.ctx, auth.LDAPIdentity{DirectoryID: dir, Login: "ada"}, "bad_credentials", meta))

	rows, err := e.db.Owner.Query(e.ctx, `SELECT action, k, v FROM audit_log, jsonb_each_text(details) AS d(k, v)`)
	require.NoError(t, err)
	defer rows.Close()
	allowed := map[string]bool{"username": true, "role": true, "directory_id": true, "method": true, "from_role": true, "to_role": true,
		"reason": true, "login_name": true, "ended_count": true, "revoked_tokens_count": true}
	n := 0
	for rows.Next() {
		var action, k, v string
		require.NoError(t, rows.Scan(&action, &k, &v))
		n++
		assert.True(t, allowed[k], "%s: unexpected details key %s", action, k)
		for _, secret := range []string{enr.Secret, first, second} {
			assert.NotContains(t, v, secret, "%s.%s", action, k)
		}
	}
	require.NoError(t, rows.Err())
	assert.Greater(t, n, 10)
}

// Concurrent first sign-ins of one identity create one user (the per-identity lock); concurrent first sign-ins of
// different identities with one name each get their own name.
func TestConcurrentFirstLDAPSignIns(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	const n = 8
	errs := parallel(n, func() error {
		_, err := e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, "17", "jsmith", ""), rbac.Operator, false, meta)
		return err
	})
	for i, err := range errs {
		require.NoError(t, err, "sign-in %d", i)
	}
	var users int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM users WHERE auth_source = 'ldap'`).Scan(&users))
	assert.Equal(t, 1, users)
	assert.Equal(t, 1, e.countAction(t, "user.provisioned", "success"))
	assert.Equal(t, n, e.countAction(t, "auth.login", "success"))

	var wg sync.WaitGroup
	errs = make([]error, n)
	for i := range n {
		wg.Go(func() {
			_, errs[i] = e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, fmt.Sprintf("%02x", 0x20+i), "ayse", ""), rbac.Operator, false, meta)
		})
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "sign-in %d", i)
	}
	rows, err := e.db.Owner.Query(e.ctx, `SELECT username::text FROM users WHERE auth_source = 'ldap' AND username::text LIKE 'ayse%' ORDER BY 1`)
	require.NoError(t, err)
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		names[s] = true
	}
	require.NoError(t, rows.Err())
	want := map[string]bool{"ayse": true}
	for i := 2; i <= n; i++ {
		want[fmt.Sprintf("ayse-%d", i)] = true
	}
	assert.Equal(t, want, names)
}

// The per-identity lock does not cover the user name (review M-2): a first directory sign-in whose free name is taken
// by another transaction between the check and the INSERT gets the next free name.
func TestSignInLDAPRetriesAUserNameTakenMeanwhile(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	other, err := e.db.Owner.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = other.Rollback(e.ctx) }()
	_, err = other.Exec(e.ctx, `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'jsmith', 'J. Smith', 'x', 'operator', now(), now())`, uuid.Must(uuid.NewV7()))
	require.NoError(t, err)
	type result struct {
		token string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		res, err := e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, "18", "jsmith", ""), rbac.Operator, false, meta)
		done <- result{res.SessionToken, err}
	}()
	e.waitForBlockedInsert(t)
	require.NoError(t, other.Commit(e.ctx))
	r := <-done
	require.NoError(t, r.err)
	assert.Equal(t, "jsmith-2", e.principal(t, r.token).Username)
}
