//go:build integration

package auth_test

import (
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

func ptr[T any](v T) *T { return &v }

// adminPrincipal bootstraps the first admin and returns its principal.
func (e *env) adminPrincipal(t *testing.T) (auth.Principal, string) {
	t.Helper()
	secret, res := e.bootstrap(t)
	return e.principal(t, res.Token), secret
}

func (e *env) createUser(t *testing.T, admin auth.Principal, username string, role rbac.Role) auth.User {
	t.Helper()
	u, err := e.svc.CreateUser(e.ctx, admin, meta, auth.NewUser{Username: username, DisplayName: username, Role: role, Password: adminPassword})
	require.NoError(t, err)
	return u
}

func TestCreateUserKeepsTurkishNamesAndTreatsUsernamesCaseInsensitively(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)

	u, err := e.svc.CreateUser(e.ctx, admin, meta, auth.NewUser{Username: "Operator1", DisplayName: "Işıl Çağlar Öztürk",
		Email: "isil@example.com", Role: rbac.Operator, Password: adminPassword})
	require.NoError(t, err)
	assert.Equal(t, "Işıl Çağlar Öztürk", u.DisplayName, "Turkish text is stored byte-for-byte")
	assert.Equal(t, "Operator1", u.Username)
	assert.False(t, u.MFAEnrolled)

	_, err = e.svc.CreateUser(e.ctx, admin, meta, auth.NewUser{Username: "ADMIN", DisplayName: "x", Role: rbac.Auditor, Password: adminPassword})
	require.ErrorIs(t, err, auth.ErrUsernameTaken)

	var v validate.Errors
	_, err = e.svc.CreateUser(e.ctx, admin, meta, auth.NewUser{Username: "İsmail", DisplayName: "İsmail", Role: rbac.Auditor, Password: adminPassword})
	require.ErrorAs(t, err, &v)
	assert.Equal(t, validate.Pattern, v[0].Code)
	_, err = e.svc.CreateUser(e.ctx, admin, meta, auth.NewUser{Username: "x2", DisplayName: "x", Role: "root", Password: adminPassword})
	require.ErrorAs(t, err, &v)
	assert.Equal(t, "role", v[0].Field)
	_, err = e.svc.CreateUser(e.ctx, admin, meta, auth.NewUser{Username: "x3", DisplayName: "x", Role: rbac.Auditor, Password: "passwordpassword"})
	require.ErrorIs(t, err, auth.ErrPasswordBreached)

	e.enroll(t, "OPERATOR1", adminPassword) // login is case-insensitive
	users, err := e.svc.ListUsers(e.ctx)
	require.NoError(t, err)
	require.Len(t, users, 2)
	assert.Equal(t, "admin", users[0].Username)
	_, err = e.svc.GetUser(e.ctx, uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, auth.ErrNotFound)
	assert.Contains(t, e.actions(t), "user.created:success")
	assert.Contains(t, e.actions(t), "user.created:failure")
}

func TestRoleChangeAndDisableEndSessions(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	op := e.createUser(t, admin, "op", rbac.Operator)
	secret, res := e.enroll(t, "op", adminPassword)

	u, err := e.svc.UpdateUser(e.ctx, admin, meta, op.ID, auth.UserUpdate{DisplayName: ptr("Ömer"), Email: ptr("omer@example.com")})
	require.NoError(t, err)
	assert.Equal(t, "Ömer", u.DisplayName)
	e.principal(t, res.Token) // profile changes keep sessions

	u, err = e.svc.UpdateUser(e.ctx, admin, meta, op.ID, auth.UserUpdate{Role: ptr(rbac.Auditor)})
	require.NoError(t, err)
	assert.Equal(t, rbac.Auditor, u.Role)
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "a role change ends the user's sessions (A-05)")
	var from, to string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'role_from', details->>'role_to' FROM audit_log
WHERE action = 'user.updated' ORDER BY seq DESC LIMIT 1`).Scan(&from, &to))
	assert.Equal(t, []string{"operator", "auditor"}, []string{from, to})

	res = e.signIn(t, "op", adminPassword, secret)
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, op.ID, auth.UserUpdate{Disabled: ptr(true)})
	require.NoError(t, err)
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "disabling ends sessions")
	_, err = e.svc.Login(e.ctx, "op", adminPassword, meta)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
	u, err = e.svc.UpdateUser(e.ctx, admin, meta, op.ID, auth.UserUpdate{Disabled: ptr(false)})
	require.NoError(t, err)
	assert.False(t, u.Disabled)
	_, err = e.svc.Login(e.ctx, "op", adminPassword, meta)
	assert.NoError(t, err)

	_, err = e.svc.UpdateUser(e.ctx, admin, meta, uuid.Must(uuid.NewV7()), auth.UserUpdate{DisplayName: ptr("x")})
	assert.ErrorIs(t, err, auth.ErrNotFound)
}

func TestTheOnlyAdminCannotBeDisabledOrDemoted(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	_, err := e.svc.UpdateUser(e.ctx, admin, meta, admin.UserID, auth.UserUpdate{Disabled: ptr(true)})
	require.ErrorIs(t, err, auth.ErrLastAdmin)
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, admin.UserID, auth.UserUpdate{Role: ptr(rbac.Operator)})
	require.ErrorIs(t, err, auth.ErrLastAdmin)
	assert.Contains(t, e.actions(t), "user.updated:failure")
}

func TestConcurrentMutualDemotionKeepsOneAdmin(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	second := e.createUser(t, admin, "admin2", rbac.Admin)
	demote := auth.UserUpdate{Role: ptr(rbac.Operator)}
	disable := auth.UserUpdate{Disabled: ptr(true)}
	// Two administrators remove each other at the same moment: by demotion, by
	// disabling, or one of each (Review Focus #2).
	pairs := [][2]auth.UserUpdate{{demote, demote}, {disable, disable}, {demote, disable}, {disable, demote}}
	for round := range 3 * len(pairs) {
		ids := []uuid.UUID{admin.UserID, second.ID}
		changes := pairs[round%len(pairs)]
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, id := range ids {
			wg.Go(func() {
				<-start
				_, errs[i] = e.svc.UpdateUser(e.ctx, admin, meta, id, changes[i])
			})
		}
		close(start)
		wg.Wait()
		var ok, last int
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case assert.ErrorIs(t, err, auth.ErrLastAdmin, "round %d", round):
				last++
			}
		}
		require.Equal(t, 1, ok, "round %d", round)
		require.Equal(t, 1, last, "round %d", round)
		var admins int
		require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL").Scan(&admins))
		require.Equal(t, 1, admins, "round %d", round)
		for _, id := range ids { // restore both admins for the next round
			_, err := e.db.Owner.Exec(e.ctx, "UPDATE users SET role = 'admin', disabled_at = NULL WHERE id = $1", id)
			require.NoError(t, err)
		}
	}
}

func TestResetMFAPasswordAndSessions(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	op := e.createUser(t, admin, "op", rbac.Operator)
	_, res := e.enroll(t, "op", adminPassword)

	require.NoError(t, e.svc.ResetMFA(e.ctx, admin, meta, op.ID))
	_, err := e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	lr, err := e.svc.Login(e.ctx, "op", adminPassword, meta)
	require.NoError(t, err)
	assert.Equal(t, auth.StatusMFAEnrollmentRequired, lr.Status)

	_, err = e.db.Owner.Exec(e.ctx, "UPDATE users SET failed_logins = 10, locked_until = now() + interval '1 hour' WHERE id = $1", op.ID)
	require.NoError(t, err)
	require.ErrorIs(t, e.svc.ResetPassword(e.ctx, admin, meta, op.ID, "short"), auth.ErrPasswordTooShort)
	require.NoError(t, e.svc.ResetPassword(e.ctx, admin, meta, op.ID, "a brand new long password"))
	_, err = e.svc.Login(e.ctx, "op", adminPassword, meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	_, res = e.enroll(t, "op", "a brand new long password")

	require.NoError(t, e.svc.RevokeSessions(e.ctx, admin, meta, op.ID))
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	assert.ErrorIs(t, e.svc.RevokeSessions(e.ctx, admin, meta, uuid.Must(uuid.NewV7())), auth.ErrNotFound)

	actions := e.actions(t)
	for _, a := range []string{"user.mfa_reset:success", "user.password_reset:success", "user.sessions_revoked:success"} {
		assert.Contains(t, actions, a)
	}
}

func TestResetMFAByUsernameIsAuditedAsCLI(t *testing.T) {
	e := newEnv(t)
	e.adminPrincipal(t)
	require.NoError(t, e.svc.ResetMFAByUsername(e.ctx, "ADMIN"))
	require.ErrorIs(t, e.svc.ResetMFAByUsername(e.ctx, "nobody"), auth.ErrNotFound)
	var actorType, actorName, via string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT actor_type, actor_name, details->>'via' FROM audit_log
WHERE action = 'user.mfa_reset'`).Scan(&actorType, &actorName, &via))
	assert.Equal(t, []string{"system", "cli", "cli"}, []string{actorType, actorName, via})
	lr, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.NoError(t, err)
	assert.Equal(t, auth.StatusMFAEnrollmentRequired, lr.Status)
}

func TestAdminSetPasswordsAreNormalized(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	// Full-width letters are NFKC-equal to ASCII: the stored hash must be of the normalized form.
	_, err := e.svc.CreateUser(e.ctx, admin, meta, auth.NewUser{Username: "nfkc", DisplayName: "n", Role: rbac.Operator,
		Password: "ｃｏｒｒｅｃｔ horse battery staple"})
	require.NoError(t, err)
	_, err = e.svc.Login(e.ctx, "nfkc", adminPassword, meta)
	require.NoError(t, err)

	id := e.insertUser(t, "reset", rbac.Operator, adminPassword)
	require.NoError(t, e.svc.ResetPassword(e.ctx, admin, meta, id, "ａ brand new long password"))
	_, err = e.svc.Login(e.ctx, "reset", "a brand new long password", meta)
	require.NoError(t, err)
}
