package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
)

type lockoutRow struct {
	id      auth.LDAPIdentity
	scope   string
	minutes int
}

// The third failed password of a name and an account records the lockout once, naming the entry the directory found
// and both keys; the fourth attempt is refused by the lock and records nothing more.
func TestDirectoryLockoutStartIsAudited(t *testing.T) {
	d, _, fa := ldapDeps(t)
	var rows []lockoutRow
	fa.RecordLDAPLockoutFn = func(_ context.Context, id auth.LDAPIdentity, scope string, minutes int, _ auth.Meta) error {
		rows = append(rows, lockoutRow{id, scope, minutes})
		return nil
	}
	s := newServer(d)
	s.ldapRefusalFloor = 0
	h := s.handler(s.apiRoutes())
	login := "/api/v1/auth/ldap/" + testDirectoryID.String() + "/login"
	for i := range 3 {
		assert.Equal(t, http.StatusUnauthorized, call(h, http.MethodPost, login, "", `{"username":"deniz","password":"pw-2"}`).Code)
		if i < 2 {
			assert.Empty(t, rows, "no lock before the third failure")
		}
	}
	require.Len(t, rows, 1)
	assert.Equal(t, lockoutRow{auth.LDAPIdentity{DirectoryID: testDirectoryID, UniqueID: "0a0b", Login: "deniz"}, "name,account", 45}, rows[0])
	assert.Equal(t, http.StatusTooManyRequests, call(h, http.MethodPost, login, "", `{"username":"deniz","password":"pw-1"}`).Code)

	// Unknown names lock their name key only, and no entry is named.
	rows = nil
	for range 3 {
		call(h, http.MethodPost, login, "", `{"username":"nobody","password":"pw-2"}`)
	}
	require.Len(t, rows, 1)
	assert.Equal(t, lockoutRow{auth.LDAPIdentity{DirectoryID: testDirectoryID, Login: "nobody"}, "name", 45}, rows[0])
}

// An Administrator sees a directory user's lockout in the user list and the user, and ends it: the unlock is recorded
// with which keys were locked, then both keys are cleared, so the right password signs in at once. A local user is 409
// ALC-LDAP-0009 and nothing is cleared; a failure to record clears nothing.
func TestDirectoryUnlock(t *testing.T) {
	d, _, fa := ldapDeps(t)
	dirID := testDirectoryID
	deniz := auth.User{ID: operatorID, Username: "deniz", Role: rbac.Operator, AuthSource: auth.AuthLDAP, LDAPDirectoryID: &dirID,
		LDAPUniqueID: "0a0b", LDAPLogin: "deniz"}
	local := auth.User{ID: adminID, Username: "admin", Role: rbac.Admin, AuthSource: auth.AuthLocal}
	fa.ListUsersFn = func(context.Context) ([]auth.User, error) { return []auth.User{local, deniz}, nil }
	fa.GetUserFn = func(_ context.Context, id uuid.UUID) (auth.User, error) {
		if id == operatorID {
			return deniz, nil
		}
		return local, nil
	}
	var recorded []map[string]string
	var refuse error
	fa.UnlockDirectorySignInFn = func(_ context.Context, p auth.Principal, _ auth.Meta, id uuid.UUID, peek func(auth.LDAPIdentity) map[string]string) (auth.LDAPIdentity, error) {
		if id != operatorID {
			return auth.LDAPIdentity{}, auth.ErrNotDirectoryUser
		}
		ident := auth.LDAPIdentity{DirectoryID: testDirectoryID, UniqueID: "0a0b", Login: "deniz"}
		recorded = append(recorded, peek(ident))
		return ident, refuse
	}
	s := newServer(d)
	s.ldapRefusalFloor = 0
	h := s.handler(s.apiRoutes())
	login := "/api/v1/auth/ldap/" + testDirectoryID.String() + "/login"
	unlock := "/api/v1/users/" + operatorID.String() + "/actions/unlock-directory-sign-in"

	lockedUntil := func() *time.Time {
		rec := call(h, http.MethodGet, "/api/v1/users/"+operatorID.String(), "admin-stepup", "")
		require.Equal(t, http.StatusOK, rec.Code)
		var u userDTO
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &u))
		return u.DirectorySignInLockedUntil
	}
	assert.Nil(t, lockedUntil())
	assert.NotContains(t, call(h, http.MethodGet, "/api/v1/users", "admin-stepup", "").Body.String(), "directory_sign_in_locked_until")

	// Three wrong passwords lock the name and the account.
	for range 3 {
		call(h, http.MethodPost, login, "", `{"username":"deniz","password":"pw-2"}`)
	}
	until := lockedUntil()
	require.NotNil(t, until)
	assert.Equal(t, d.Clock.Now().Add(ldapLockoutFor).UTC(), *until)
	assert.Contains(t, call(h, http.MethodGet, "/api/v1/users", "admin-stepup", "").Body.String(), `"directory_sign_in_locked_until":"`)

	// Recording fails: nothing is cleared.
	refuse = auth.ErrNotFound
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodPost, unlock, "admin-stepup", "").Code)
	assert.NotNil(t, lockedUntil())

	refuse = nil
	recorded = nil
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, unlock, "admin-stepup", "").Code)
	assert.Equal(t, []map[string]string{{"name_locked": "true", "account_locked": "true"}}, recorded)
	assert.Nil(t, lockedUntil())
	assert.Equal(t, http.StatusOK, call(h, http.MethodPost, login, "", `{"username":"deniz","password":"pw-1"}`).Code)

	recorded = nil
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, unlock, "admin-stepup", "").Code, "idempotent")
	assert.Equal(t, []map[string]string{{"name_locked": "false", "account_locked": "false"}}, recorded)

	rec := call(h, http.MethodPost, "/api/v1/users/"+adminID.String()+"/actions/unlock-directory-sign-in", "admin-stepup", "")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-LDAP-0009", decodeErr(t, rec).Error.Code)
}
