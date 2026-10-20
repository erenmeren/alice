package api

import (
	"net/http"
	"strconv"
	"time"

	"alice/internal/auth"
	"alice/internal/auth/ldap/ldapx"
)

// directoryLockedUntil is when the directory sign-in lockout of a directory user ends in this process: the later of
// its account key and the name key of its stored sign-in name, or nil when neither is locked (and for every other
// user).
func (s *server) directoryLockedUntil(u auth.User) *time.Time {
	if u.AuthSource != auth.AuthLDAP || u.LDAPDirectoryID == nil || u.LDAPUniqueID == "" {
		return nil
	}
	var out *time.Time
	consider := func(until time.Time, locked bool) {
		if locked && (out == nil || until.After(*out)) {
			t := until.UTC()
			out = &t
		}
	}
	consider(s.ldapAccountLockout.LockedUntil(ldapAccountKey(*u.LDAPDirectoryID, u.LDAPUniqueID)))
	if ldapx.ValidLoginName(u.LDAPLogin) {
		consider(s.ldapLockout.LockedUntil(ldapLoginKey(*u.LDAPDirectoryID, u.LDAPLogin)))
	}
	return out
}

// adminUserJSON is a user as the user administration shows it: userJSON plus the directory sign-in lockout.
func (s *server) adminUserJSON(u auth.User) userDTO {
	dto := userJSON(u)
	dto.DirectorySignInLockedUntil = s.directoryLockedUntil(u)
	return dto
}

// directoryLockoutKeys are the lockout keys an Administrator's unlock clears: the name key of the sign-in name the
// directory last returned and the account key of the entry.
func directoryLockoutKeys(ident auth.LDAPIdentity) (name, account string) {
	return ldapLoginKey(ident.DirectoryID, ident.Login), ldapAccountKey(ident.DirectoryID, ident.UniqueID)
}

// unlockDirectorySignIn ends a directory user's sign-in lockout (an Administrator with step-up): the lock and the
// failures of the user's account key and of the name key of the stored sign-in name. The unlock is recorded first
// (user.directory_unlocked, with which keys were locked) and the keys are cleared only once the row is written. The
// lockout is this process's (kept in memory); the action is idempotent and answers 204 whether or not a key was
// locked. A user who does not sign in through a directory is 409 ALC-LDAP-0009. Other spellings or aliases of the
// account keep their own name keys until they expire; the account key they share is cleared.
func (s *server) unlockDirectorySignIn(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	ident, err := s.deps.Auth.UnlockDirectorySignIn(r.Context(), principalFrom(r.Context()), s.meta(r), id, func(ident auth.LDAPIdentity) map[string]string {
		name, account := directoryLockoutKeys(ident)
		_, nameLocked := s.ldapLockout.LockedUntil(name)
		_, accountLocked := s.ldapAccountLockout.LockedUntil(account)
		return map[string]string{"name_locked": strconv.FormatBool(nameLocked), "account_locked": strconv.FormatBool(accountLocked)}
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	name, account := directoryLockoutKeys(ident)
	s.ldapLockout.Clear(name)
	s.ldapAccountLockout.Clear(account)
	noContent(w)
}
