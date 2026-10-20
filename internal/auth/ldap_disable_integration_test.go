//go:build integration

package auth_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/rbac"
)

// switchOff switches a directory off as ldap.UpdateDirectory does: the directory's row first, then
// EndDirectoryAccess in the same transaction.
func (e *env) switchOff(t *testing.T, a audit.Actor, dir uuid.UUID) int {
	t.Helper()
	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(e.ctx) }()
	_, err = tx.Exec(e.ctx, "UPDATE ldap_directories SET enabled = false, version = version + 1 WHERE id = $1", dir)
	require.NoError(t, err)
	n, err := e.svc.EndDirectoryAccess(e.ctx, tx, a, dir)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(e.ctx))
	return n
}

// Switching a directory off ends, at once, every session (full and pending) and API token of its users, audited by
// the Administrator with reason provider_disabled; users of another directory and local users keep theirs, and a user
// of the directory who had nothing to end gets no row.
func TestEndDirectoryAccess(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	adminActor := admin.Actor(meta)
	dir, other := e.directory(t), e.directory(t)
	ada := e.signInLDAP(t, ldapIdentity(dir, "a1", "ada", ""), rbac.Operator)
	e.signInLDAP(t, ldapIdentity(dir, "a1", "ada", ""), rbac.Operator) // a second session
	adaTokens := e.ssoTokens(t, ada.UserID, rbac.ScopeRead, 2)
	pending, err := e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, "b2", "berk", ""), rbac.Auditor, true, meta)
	require.NoError(t, err)
	require.Equal(t, auth.StatusMFAEnrollmentRequired, pending.Status)
	idle := e.directoryUser(t, dir, "c3", "cem", rbac.Auditor) // never signed in
	elsewhere := e.signInLDAP(t, ldapIdentity(other, "a1", "ayse", ""), rbac.Operator)

	assert.Equal(t, 2, e.switchOff(t, adminActor, dir), "Ada and Berk had something to end")

	assert.Zero(t, e.liveSessions(t, ada.UserID))
	for _, s := range adaTokens {
		assert.False(t, e.tokenWorks(t, s))
	}
	assert.Empty(t, e.sessionKinds(t, pendingUser(t, e, dir, "b2")), "a pending session ends too")
	assert.Equal(t, 1, e.liveSessions(t, elsewhere.UserID), "another directory's user keeps the session")
	assert.Equal(t, 1, e.liveSessions(t, admin.UserID), "a local user keeps the session")

	rows, err := e.db.Owner.Query(e.ctx, `SELECT object_id, actor_name, details->>'reason', details->>'ended_count',
details->>'revoked_tokens_count' FROM audit_log WHERE action = 'user.sessions_ended' ORDER BY seq`)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([5]string, error) {
		var v [5]string
		err := r.Scan(&v[0], &v[1], &v[2], &v[3], &v[4])
		return v, err
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, [][5]string{
		{ada.UserID.String(), "admin", "provider_disabled", "2", "2"},
		{pendingUser(t, e, dir, "b2").String(), "admin", "provider_disabled", "1", "0"},
	}, got)
	assert.NotContains(t, []string{got[0][0], got[1][0]}, idle.String())
	for _, r := range e.tokenRevocations(t, ada.UserID) {
		assert.Equal(t, [2]string{"provider_disabled", "admin"}, [2]string{r.reason, r.actor})
	}

	// A second switch-off ends nothing and writes nothing.
	assert.Zero(t, e.switchOff(t, adminActor, dir))
	assert.Equal(t, 2, e.countAction(t, "user.sessions_ended", "success"))
}

// A sign-in whose transaction starts after the switch-off committed is refused (the directory's check of the password
// happened before), so no session can outlive a switch-off.
func TestSignInLDAPRefusedOnceTheDirectoryIsOff(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	dir := e.directory(t)
	e.switchOff(t, admin.Actor(meta), dir)
	for _, mfa := range []bool{false, true} {
		_, err := e.svc.SignInLDAP(e.ctx, ldapIdentity(dir, "a1", "ada", ""), rbac.Operator, mfa, meta)
		assert.ErrorIs(t, err, auth.ErrLDAPDirectoryDisabled)
	}
	_, err := e.svc.SignInLDAP(e.ctx, ldapIdentity(uuid.Must(uuid.NewV7()), "a1", "ada", ""), rbac.Operator, false, meta)
	assert.ErrorIs(t, err, auth.ErrLDAPDirectoryDisabled, "a directory that is gone")
	assert.Zero(t, e.countAction(t, "user.provisioned", "success"))
}

func pendingUser(t *testing.T, e *env, dir uuid.UUID, uniqueID string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM users WHERE ldap_directory_id = $1 AND ldap_unique_id = $2", dir, uniqueID).Scan(&id))
	return id
}

// The lockout row names the user of an entry the directory found (actor and object, with the sign-in name), and
// nobody for a name nothing matched: no name is stored then.
func TestRecordLDAPLockout(t *testing.T) {
	e := newEnv(t)
	dir := e.directory(t)
	ada := e.signInLDAP(t, ldapIdentity(dir, "a1", "ada", ""), rbac.Operator)
	require.NoError(t, e.svc.RecordLDAPLockout(e.ctx, auth.LDAPIdentity{DirectoryID: dir, UniqueID: "a1", Login: "ADA"}, "name,account", 45, meta))
	require.NoError(t, e.svc.RecordLDAPLockout(e.ctx, auth.LDAPIdentity{DirectoryID: dir, Login: "secret-typed-as-a-name"}, "name", 45, meta))
	require.NoError(t, e.svc.RecordLDAPLockout(e.ctx, auth.LDAPIdentity{DirectoryID: dir, UniqueID: "ff", Login: "ghost"}, "account", 45, meta))

	rows, err := e.db.Owner.Query(e.ctx, `SELECT actor_type, actor_name, object_id, result, details->>'directory_id', details->>'scope',
details->>'minutes', coalesce(details->>'login_name', '-') FROM audit_log WHERE action = 'auth.ldap.lockout' ORDER BY seq`)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([8]string, error) {
		var v [8]string
		err := r.Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7])
		return v, err
	})
	require.NoError(t, err)
	d := dir.String()
	assert.Equal(t, [][8]string{
		{"user", "ada", ada.UserID.String(), "failure", d, "name,account", "45", "ADA"},
		{"system", "(unknown user)", "", "failure", d, "name", "45", "-"},
		{"system", "(unknown user)", "", "failure", d, "account", "45", "ghost"},
	}, got)
}

// An Administrator's unlock is recorded under the user's row lock with what peek reports; a local user is refused and
// a missing one is not found, and neither calls peek.
func TestUnlockDirectorySignIn(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	dir := e.directory(t)
	ada := e.signInLDAP(t, ldapIdentity(dir, "a1", "ada.lovelace", ""), rbac.Operator)

	var seen []auth.LDAPIdentity
	peek := func(id auth.LDAPIdentity) map[string]string {
		seen = append(seen, id)
		return map[string]string{"name_locked": "true", "account_locked": "false"}
	}
	id, err := e.svc.UnlockDirectorySignIn(e.ctx, admin, meta, ada.UserID, peek)
	require.NoError(t, err)
	want := auth.LDAPIdentity{DirectoryID: dir, UniqueID: "a1", Login: "ada.lovelace"}
	assert.Equal(t, want, id)
	assert.Equal(t, []auth.LDAPIdentity{want}, seen)
	assert.Equal(t, "true", *e.lastDetail(t, "user.directory_unlocked", "name_locked"))
	assert.Equal(t, "false", *e.lastDetail(t, "user.directory_unlocked", "account_locked"))
	assert.Equal(t, dir.String(), *e.lastDetail(t, "user.directory_unlocked", "directory_id"))

	_, err = e.svc.UnlockDirectorySignIn(e.ctx, admin, meta, admin.UserID, peek)
	assert.ErrorIs(t, err, auth.ErrNotDirectoryUser)
	_, err = e.svc.UnlockDirectorySignIn(e.ctx, admin, meta, uuid.Must(uuid.NewV7()), peek)
	assert.ErrorIs(t, err, auth.ErrNotFound)
	assert.Len(t, seen, 1)
	assert.Equal(t, 1, e.countAction(t, "user.directory_unlocked", "success"))
}
