package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
)

var tokenID = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000aa")

func sampleToken(owner uuid.UUID) auth.Token {
	return auth.Token{ID: tokenID, UserID: owner, Name: "CI pipeline", Prefix: "alice_Xy12Ab", Scope: rbac.ScopeRead,
		ExpiresAt: testNow.Add(90 * 24 * time.Hour), CreatedAt: testNow}
}

func TestListTokensDefaultsToCaller(t *testing.T) {
	d := testDeps(t, nil)
	var asked uuid.UUID
	var askedMeta auth.Meta
	d.Auth.(*fakeAuth).ListTokensFn = func(_ context.Context, _ auth.Principal, m auth.Meta, userID uuid.UUID) ([]auth.Token, error) {
		asked, askedMeta = userID, m
		if userID != operatorID {
			return nil, auth.ErrNotFound
		}
		return []auth.Token{sampleToken(operatorID)}, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/tokens", "operator", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, operatorID, asked)
	assert.JSONEq(t, `{"items":[{"id":"0190f5a0-0000-7000-8000-0000000000aa","user_id":"0190f5a0-0000-7000-8000-000000000002",
	  "name":"CI pipeline","prefix":"alice_Xy12Ab","scope":"read","expires_at":"2026-12-29T12:00:00Z","last_used_at":null,
	  "created_at":"2026-09-30T12:00:00Z"}]}`, rec.Body.String())

	assert.NotEmpty(t, askedMeta.RequestID, "the service gets the request meta")

	// AUD-06: another user's list is refused by the API itself (404, as for an unknown user), and
	// recorded through the coalescer; the service is not asked.
	asked = uuid.Nil
	rec = call(h, http.MethodGet, "/api/v1/tokens?user_id="+adminID.String(), "operator", "")
	assert.Equal(t, http.StatusNotFound, rec.Code, "another user's tokens are invisible to non-admins")
	assert.Equal(t, uuid.Nil, asked)
	denied := d.Audit.(*fakeAudit).Events()
	require.Len(t, denied, 1)
	assert.Equal(t, "authz.denied", denied[0].Action)
	assert.Equal(t, "user", denied[0].ObjectType)
	assert.Equal(t, adminID.String(), denied[0].ObjectID)
	assert.Equal(t, "not_owner", denied[0].Details["reason"])

	call(h, http.MethodGet, "/api/v1/tokens?user_id="+adminID.String(), "admin", "")
	assert.Equal(t, adminID, asked, "an administrator's request goes to the service")

	rec = call(h, http.MethodGet, "/api/v1/tokens?user_id=garbage", "operator", "")
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// AUD-06: enumerating user IDs is one row per window, and the summary counts the distinct IDs.
func TestForeignTokenListsAreCoalesced(t *testing.T) {
	d := testDeps(t, nil)
	fa := d.Audit.(*fakeAudit)
	s := New(d)
	h := s.Handler()
	for range 50 {
		rec := call(h, http.MethodGet, "/api/v1/tokens?user_id="+uuid.NewString(), "operator", "")
		require.Equal(t, http.StatusNotFound, rec.Code)
	}
	require.Equal(t, 1, fa.Count("authz.denied"))
	s.FlushDenials(context.Background())
	sums := eventsWith(fa, "authz.denied", "suppressed_count")
	require.Len(t, sums, 1)
	assert.Equal(t, "49", sums[0].Details["suppressed_count"])
	assert.Equal(t, "50", sums[0].Details["distinct_object_count"])
	assert.Equal(t, "not_owner", sums[0].Details["reason"])
	assert.Equal(t, "/api/v1/tokens", sums[0].Details["path"])
	assert.Empty(t, sums[0].ObjectID, "the summary stands for many objects")
}

func TestCreateTokenReturnsSecretOnce(t *testing.T) {
	d := testDeps(t, nil)
	var got auth.NewToken
	d.Auth.(*fakeAuth).CreateTokenFn = func(_ context.Context, _ auth.Principal, _ auth.Meta, in auth.NewToken) (string, auth.Token, error) {
		got = in
		if in.Scope == rbac.ScopeOperate {
			return "", auth.Token{}, auth.ErrTokenScopeNotAllowed
		}
		return "alice_Xy12AbSECRETSECRETSECRETSECRETSECRETSEC", sampleToken(auditorID), nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/tokens", "auditor-stepup", `{"name":"CI pipeline","scope":"read","expires_in_days":90}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, auth.NewToken{Name: "CI pipeline", Scope: rbac.ScopeRead, ExpiresInDays: 90}, got)
	assert.Contains(t, rec.Body.String(), `"token":"alice_Xy12AbSECRETSECRETSECRETSECRETSECRETSEC"`)
	assert.Contains(t, rec.Body.String(), `"item":{"id":"0190f5a0-0000-7000-8000-0000000000aa"`)

	rec = call(h, http.MethodPost, "/api/v1/tokens", "auditor-stepup", `{"name":"x","scope":"operate","expires_in_days":90}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "ALC-TOK-0001", decodeErr(t, rec).Error.Code)

	rec = call(h, http.MethodPost, "/api/v1/tokens", "auditor-stepup", `{"name":"x","scope":"admin","expires_in_days":90}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), `"field":"scope","code":"validation.one_of"`)

	rec = call(h, http.MethodPost, "/api/v1/tokens", "auditor", `{"name":"x","scope":"read","expires_in_days":90}`)
	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, "creating a token needs step-up")
}

func TestRevokeToken(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth.(*fakeAuth).RevokeTokenFn = func(_ context.Context, p auth.Principal, _ auth.Meta, id uuid.UUID) error {
		if id != tokenID || p.UserID != operatorID {
			return auth.ErrNotFound
		}
		return nil
	}
	h := NewHandler(d)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, "/api/v1/tokens/"+tokenID.String(), "operator", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodDelete, "/api/v1/tokens/"+tokenID.String(), "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodDelete, "/api/v1/tokens/xyz", "operator", "").Code)
}
