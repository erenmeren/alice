//go:build integration

package auth_test

import (
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
)

// newTokens creates n read tokens for the signed-in principal and returns their secrets and IDs.
func (e *env) newTokens(t *testing.T, p auth.Principal, n int) ([]string, []string) {
	t.Helper()
	var secrets, ids []string
	for i := range n {
		secret, tok, err := e.svc.CreateToken(e.ctx, p, meta, auth.NewToken{Name: "ci-" + string(rune('a'+i)), Scope: rbac.ScopeRead, ExpiresInDays: 30})
		require.NoError(t, err)
		secrets, ids = append(secrets, secret), append(ids, tok.ID.String())
	}
	return secrets, ids
}

// tokenWorks reports whether an API token still authenticates.
func (e *env) tokenWorks(t *testing.T, secret string) bool {
	t.Helper()
	_, err := e.svc.AuthenticateToken(e.ctx, secret)
	if err != nil {
		require.ErrorIs(t, err, auth.ErrUnauthenticated)
		return false
	}
	return true
}

// lastDetail returns details->>key of the newest audit row with action.
func (e *env) lastDetail(t *testing.T, action, key string) *string {
	t.Helper()
	var v *string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>$2 FROM audit_log WHERE action = $1 ORDER BY seq DESC LIMIT 1`,
		action, key).Scan(&v))
	return v
}

// tokenRevocation is one token.revoked audit row.
type tokenRevocation struct{ objectID, tokenID, ownerID, reason, actor string }

// tokenRevocations returns the token.revoked audit rows for owner's tokens, ordered by token ID.
func (e *env) tokenRevocations(t *testing.T, owner uuid.UUID) []tokenRevocation {
	t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, `SELECT object_id, details->>'token_id', details->>'owner_id', coalesce(details->>'reason', ''), actor_name
FROM audit_log WHERE action = 'token.revoked' AND result = 'success' AND details->>'owner_id' = $1 ORDER BY object_id`, owner.String())
	require.NoError(t, err)
	defer rows.Close()
	var out []tokenRevocation
	for rows.Next() {
		var r tokenRevocation
		require.NoError(t, rows.Scan(&r.objectID, &r.tokenID, &r.ownerID, &r.reason, &r.actor))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// requireRevokedBy checks that exactly the tokens ids were revoked by actor for reason, each
// audited by ID (never by secret).
func requireRevokedBy(t *testing.T, got []tokenRevocation, owner uuid.UUID, ids []string, reason, actor string) {
	t.Helper()
	want := make([]tokenRevocation, 0, len(ids))
	for _, id := range slices.Sorted(slices.Values(ids)) {
		want = append(want, tokenRevocation{objectID: id, tokenID: id, ownerID: owner.String(), reason: reason, actor: actor})
	}
	require.Equal(t, want, got)
}

// TestAdminPasswordResetRevokesTheUsersAPITokens is the audit's AUD-12 PoC inverted: an
// administrator's password reset ends the user's sessions and revokes every live API token of
// that user in the same transaction, audited by ID and count; other users' tokens are untouched.
func TestAdminPasswordResetRevokesTheUsersAPITokens(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	op := e.createUser(t, admin, "op", rbac.Operator)
	opSecret, res := e.enroll(t, "op", adminPassword)
	opP := e.principal(t, res.Token)
	live, liveIDs := e.newTokens(t, opP, 2)
	gone, goneIDs := e.newTokens(t, opP, 1)
	require.NoError(t, e.svc.RevokeToken(e.ctx, opP, meta, uuid.MustParse(goneIDs[0])))
	adminTokens, _ := e.newTokens(t, admin, 1)

	require.NoError(t, e.svc.ResetPassword(e.ctx, admin, meta, op.ID, "a brand new long password"))

	_, err := e.svc.Authenticate(e.ctx, res.Token)
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "sessions end")
	for _, s := range append(live, gone...) {
		assert.False(t, e.tokenWorks(t, s), "the user's tokens are refused at once")
	}
	assert.True(t, e.tokenWorks(t, adminTokens[0]), "another user's token is untouched")
	assert.Equal(t, "2", *e.lastDetail(t, "user.password_reset", "revoked_token_count"), "an already revoked token is not counted again")
	revs := e.tokenRevocations(t, op.ID)
	revs = slices.DeleteFunc(revs, func(r tokenRevocation) bool { return r.tokenID == goneIDs[0] }) // the user's own earlier revocation
	requireRevokedBy(t, revs, op.ID, liveIDs, "password_reset", "admin")
	var leaked int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'", auth.TokenPrefix).Scan(&leaked))
	assert.Zero(t, leaked, "no token secret is written to the audit log")
	list, err := e.svc.ListTokens(e.ctx, admin, meta, op.ID)
	require.NoError(t, err)
	assert.Empty(t, list)

	// The user signs in with the new password and may create new tokens.
	fresh, _ := e.newTokens(t, e.principal(t, e.signIn(t, "op", "a brand new long password", opSecret).Token), 1)
	assert.True(t, e.tokenWorks(t, fresh[0]))
}

// TestSignOutEverywhereRevokesTheUsersAPITokens: "sign out everywhere" revokes every API token
// of the user too, also when administrators use it on themselves; with no tokens the count is 0.
func TestSignOutEverywhereRevokesTheUsersAPITokens(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	op := e.createUser(t, admin, "op", rbac.Operator)
	_, res := e.enroll(t, "op", adminPassword)
	opTokens, opIDs := e.newTokens(t, e.principal(t, res.Token), 2)
	adminTokens, adminIDs := e.newTokens(t, admin, 1)

	require.NoError(t, e.svc.RevokeSessions(e.ctx, admin, meta, op.ID))
	for _, s := range opTokens {
		assert.False(t, e.tokenWorks(t, s))
	}
	assert.True(t, e.tokenWorks(t, adminTokens[0]))
	assert.Equal(t, "2", *e.lastDetail(t, "user.sessions_revoked", "revoked_token_count"))
	requireRevokedBy(t, e.tokenRevocations(t, op.ID), op.ID, opIDs, "sessions_revoked", "admin")

	require.NoError(t, e.svc.RevokeSessions(e.ctx, admin, meta, op.ID))
	assert.Equal(t, "0", *e.lastDetail(t, "user.sessions_revoked", "revoked_token_count"), "nothing left to revoke")

	// An administrator signing themselves out everywhere loses their own tokens as well.
	require.NoError(t, e.svc.RevokeSessions(e.ctx, admin, meta, admin.UserID))
	assert.False(t, e.tokenWorks(t, adminTokens[0]))
	requireRevokedBy(t, e.tokenRevocations(t, admin.UserID), admin.UserID, adminIDs, "sessions_revoked", "admin")
}

// TestOwnPasswordChangeKeepsAPITokens: a user changing their own password ends their other
// sessions but keeps their API tokens (plan decision 9).
func TestOwnPasswordChangeKeepsAPITokens(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	op := e.createUser(t, admin, "op", rbac.Operator)
	_, res := e.enroll(t, "op", adminPassword)
	opP := e.principal(t, res.Token)
	tokens, _ := e.newTokens(t, opP, 1)

	_, err := e.svc.ChangePassword(e.ctx, opP, adminPassword, "another long passphrase", meta)
	require.NoError(t, err)
	assert.True(t, e.tokenWorks(t, tokens[0]))
	assert.Empty(t, e.tokenRevocations(t, op.ID))
	assert.Nil(t, e.lastDetail(t, "auth.password_changed", "revoked_token_count"))
}

// TestATokenReadBeforeTheRevocationCommitsIsRefusedAfterIt: a request that reads the token
// while the revocation is still running is served (it read the committed state); the first
// read after the revocation commits is refused. Nothing caches a token between requests.
func TestATokenReadBeforeTheRevocationCommitsIsRefusedAfterIt(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	op := e.createUser(t, admin, "op", rbac.Operator)
	opSecret, _ := e.enroll(t, "op", adminPassword)

	for _, c := range []struct {
		name   string
		revoke func() error
	}{
		{"sign out everywhere", func() error { return e.svc.RevokeSessions(e.ctx, admin, meta, op.ID) }},
		{"password reset", func() error { return e.svc.ResetPassword(e.ctx, admin, meta, op.ID, adminPassword+" again") }},
	} {
		password := adminPassword
		if e.countAction(t, "user.password_reset", "success") > 0 {
			password += " again"
		}
		tokens, ids := e.newTokens(t, e.principal(t, e.signIn(t, "op", password, opSecret).Token), 1)
		// Use the token once so its last use is recorded and a second use within the minute
		// writes nothing (it would otherwise wait for the revocation's row lock).
		require.True(t, e.tokenWorks(t, tokens[0]))

		// Hold the audit chain lock, so the revocation stops after its updates and before it
		// commits (its audit rows are appended last).
		holder, err := e.db.Owner.Begin(e.ctx)
		require.NoError(t, err)
		_, err = holder.Exec(e.ctx, "SELECT pg_advisory_xact_lock($1)", auditChainLockKey)
		require.NoError(t, err)
		done := make(chan error, 1)
		go func() { done <- c.revoke() }()
		e.waitForBlockedAdvisoryLock(t)

		var pending bool
		require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT revoked_at IS NULL FROM api_tokens WHERE id = $1", ids[0]).Scan(&pending))
		require.True(t, pending, "%s: the revocation has not committed yet", c.name)
		assert.True(t, e.tokenWorks(t, tokens[0]), "%s: a read before the commit sees the token as it was", c.name)

		require.NoError(t, holder.Rollback(e.ctx))
		require.NoError(t, <-done)
		assert.False(t, e.tokenWorks(t, tokens[0]), "%s: the first read after the commit is refused", c.name)
	}
}
