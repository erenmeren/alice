//go:build integration

package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

func TestTokenLifecycle(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)

	secret, tok, err := e.svc.CreateToken(e.ctx, admin, meta, auth.NewToken{Name: "CI yedekleme", Scope: rbac.ScopeRead, ExpiresInDays: 30})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(secret, auth.TokenPrefix))
	assert.Equal(t, secret[:12], tok.Prefix)
	assert.Equal(t, e.clk.Now().Add(30*24*time.Hour), tok.ExpiresAt)

	var stored []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT token_hash FROM api_tokens WHERE id = $1", tok.ID).Scan(&stored))
	assert.Len(t, stored, 32, "only the SHA-256 is stored")
	assert.NotContains(t, string(stored), secret)

	p, err := e.svc.AuthenticateToken(e.ctx, secret)
	require.NoError(t, err)
	assert.Equal(t, rbac.APIToken, p.Kind)
	assert.Equal(t, rbac.ScopeRead, p.Scope)
	assert.Equal(t, tok.ID, p.TokenID)
	assert.Equal(t, rbac.Admin, p.Role)

	list, err := e.svc.ListTokens(e.ctx, admin, uuid.Nil)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.NotNil(t, list[0].LastUsedAt, "use is recorded")

	require.NoError(t, e.svc.RevokeToken(e.ctx, admin, meta, tok.ID))
	_, err = e.svc.AuthenticateToken(e.ctx, secret)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	list, err = e.svc.ListTokens(e.ctx, admin, uuid.Nil)
	require.NoError(t, err)
	assert.Empty(t, list)
	assert.ErrorIs(t, e.svc.RevokeToken(e.ctx, admin, meta, tok.ID), auth.ErrNotFound, "already revoked")

	_, _, err = e.svc.CreateToken(e.ctx, p, meta, auth.NewToken{Name: "minted", Scope: rbac.ScopeRead, ExpiresInDays: 1})
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "a token cannot mint tokens")

	for _, bad := range []string{"", "alice_", "alice_nope", tok.Prefix, secret[:len(secret)-1], "Bearer " + secret, strings.TrimPrefix(secret, auth.TokenPrefix)} {
		_, err = e.svc.AuthenticateToken(e.ctx, bad)
		assert.ErrorIs(t, err, auth.ErrUnauthenticated, bad)
	}
	actions := e.actions(t)
	assert.Contains(t, actions, "token.created:success")
	assert.Contains(t, actions, "token.revoked:success")
}

func TestTokenValidation(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	fields := func(err error) []string {
		var v validate.Errors
		require.ErrorAs(t, err, &v)
		var out []string
		for _, f := range v {
			out = append(out, f.Field+":"+f.Code)
		}
		return out
	}
	_, _, err := e.svc.CreateToken(e.ctx, admin, meta, auth.NewToken{Name: " ", Scope: "write", ExpiresInDays: 0})
	assert.Equal(t, []string{"name:validation.required", "scope:validation.one_of", "expires_in_days:validation.out_of_range"}, fields(err))
	_, _, err = e.svc.CreateToken(e.ctx, admin, meta, auth.NewToken{Name: "x", Scope: rbac.ScopeRead, ExpiresInDays: auth.MaxTokenDays + 1})
	assert.Equal(t, []string{"expires_in_days:validation.out_of_range"}, fields(err))
}

func TestTokenObjectLevelAccess(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	e.createUser(t, admin, "op", rbac.Operator)
	_, res := e.enroll(t, "op", adminPassword)
	op := e.principal(t, res.Token)

	_, adminTok, err := e.svc.CreateToken(e.ctx, admin, meta, auth.NewToken{Name: "a", Scope: rbac.ScopeOperate, ExpiresInDays: 1})
	require.NoError(t, err)
	_, opTok, err := e.svc.CreateToken(e.ctx, op, meta, auth.NewToken{Name: "b", Scope: rbac.ScopeOperate, ExpiresInDays: 1})
	require.NoError(t, err)

	_, err = e.svc.ListTokens(e.ctx, op, admin.UserID)
	assert.ErrorIs(t, err, auth.ErrNotFound, "operators cannot see other users' tokens")
	assert.ErrorIs(t, e.svc.RevokeToken(e.ctx, op, meta, adminTok.ID), auth.ErrNotFound)

	list, err := e.svc.ListTokens(e.ctx, admin, op.UserID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, opTok.ID, list[0].ID)
	require.NoError(t, e.svc.RevokeToken(e.ctx, admin, meta, opTok.ID), "admins may revoke anyone's token")
}

func TestTokenScopeFollowsTheOwnersRole(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	e.createUser(t, admin, "aud", rbac.Auditor)
	_, res := e.enroll(t, "aud", adminPassword)
	auditor := e.principal(t, res.Token)
	_, _, err := e.svc.CreateToken(e.ctx, auditor, meta, auth.NewToken{Name: "x", Scope: rbac.ScopeOperate, ExpiresInDays: 1})
	require.ErrorIs(t, err, auth.ErrTokenScopeNotAllowed)

	op := e.createUser(t, admin, "op", rbac.Operator)
	_, res = e.enroll(t, "op", adminPassword)
	opP := e.principal(t, res.Token)
	operate, _, err := e.svc.CreateToken(e.ctx, opP, meta, auth.NewToken{Name: "w", Scope: rbac.ScopeOperate, ExpiresInDays: 1})
	require.NoError(t, err)
	read, _, err := e.svc.CreateToken(e.ctx, opP, meta, auth.NewToken{Name: "r", Scope: rbac.ScopeRead, ExpiresInDays: 1})
	require.NoError(t, err)

	// The owner's current role is re-read at creation: a principal resolved before a
	// demotion cannot mint a token above the new role.
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE users SET role = 'auditor' WHERE id = $1", op.ID)
	require.NoError(t, err)
	_, _, err = e.svc.CreateToken(e.ctx, opP, meta, auth.NewToken{Name: "stale", Scope: rbac.ScopeOperate, ExpiresInDays: 1})
	require.ErrorIs(t, err, auth.ErrTokenScopeNotAllowed)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE users SET role = 'operator' WHERE id = $1", op.ID)
	require.NoError(t, err)

	_, err = e.svc.UpdateUser(e.ctx, admin, meta, op.ID, auth.UserUpdate{Role: ptr(rbac.Auditor)})
	require.NoError(t, err)
	_, err = e.svc.AuthenticateToken(e.ctx, operate)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "an operate token stops working when the owner becomes an auditor")
	p, err := e.svc.AuthenticateToken(e.ctx, read)
	require.NoError(t, err)
	assert.Equal(t, rbac.Auditor, p.Role)

	_, err = e.svc.UpdateUser(e.ctx, admin, meta, op.ID, auth.UserUpdate{Disabled: ptr(true)})
	require.NoError(t, err)
	_, err = e.svc.AuthenticateToken(e.ctx, read)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "disabled owner")
	_, _, err = e.svc.CreateToken(e.ctx, opP, meta, auth.NewToken{Name: "late", Scope: rbac.ScopeRead, ExpiresInDays: 1})
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "a disabled owner cannot create tokens")
}

func TestExpiredTokenIsRejected(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	secret, _, err := e.svc.CreateToken(e.ctx, admin, meta, auth.NewToken{Name: "x", Scope: rbac.ScopeRead, ExpiresInDays: 1})
	require.NoError(t, err)
	e.clk.Advance(24*time.Hour - time.Second)
	_, err = e.svc.AuthenticateToken(e.ctx, secret)
	require.NoError(t, err)
	e.clk.Advance(time.Second)
	_, err = e.svc.AuthenticateToken(e.ctx, secret)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
}
