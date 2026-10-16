package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/auth/ldap/ldapx"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Errors of directory (LDAP) sign-in.
var (
	// ErrLDAPEmailInUse: the directory user's e-mail address belongs to a local user (plan ruling 2).
	ErrLDAPEmailInUse = errors.New("auth: the directory user's e-mail address belongs to a local user")
	// ErrLDAPUserDisabled: the directory user is disabled in Alice.
	ErrLDAPUserDisabled = errors.New("auth: the directory user is disabled")
	// ErrLDAPOtherUser: a directory step-up was answered by another identity than the session's user (or the
	// session's user is not a directory user).
	ErrLDAPOtherUser = errors.New("auth: the step-up was answered for another directory identity")
	// ErrLDAPIdentityInvalid: the caller passed an identity or role Alice cannot store (no directory, a unique id that
	// is not 2 to 254 lower-case hex digits of whole bytes, an unknown role).
	ErrLDAPIdentityInvalid = errors.New("auth: the directory identity or role is not valid")
	// ErrLDAPUserLocked: the directory user is in a delay or lockout after failed TOTP codes; the sign-in is refused
	// whether or not the directory asks for MFA (audit reason locked).
	ErrLDAPUserLocked = errors.New("auth: the directory user is locked")
	// ErrLDAPEnrolmentRequired: a directory step-up needs the TOTP (mfa_required) but the user has none enrolled (the
	// setting was switched on during the session); nothing is counted, and the person signs in again to enrol.
	ErrLDAPEnrolmentRequired = errors.New("auth: the directory user must enrol a TOTP first")
)

// ldapIdentityLockNamespace is the first key of the per-identity advisory lock SignInLDAP takes, so two first
// sign-ins of one directory identity provision one user (the second waits and finds it).
const ldapIdentityLockNamespace int32 = 0x616c6333 // "alc3"

// maxDeniedLoginRunes bounds the sign-in name recorded in an auth.ldap.denied row.
const maxDeniedLoginRunes = 128

// ldapSessionEndingReasons are the directory refusals that say a known user no longer has access: they end the user's
// sessions and revoke the user's API tokens (as sessionEndingReasons for SSO).
var ldapSessionEndingReasons = []string{"no_access", "provider_disabled"}

// uniqueIDRE is the stored form of a directory unique id (ldapx.UniqueID; migration 00015): the lower-case hex of 1 to
// 127 bytes.
var uniqueIDRE = regexp.MustCompile(`^(?:[0-9a-f]{2}){1,127}$`)

// LDAPIdentity is a directory user whose password the directory just accepted. A directory user is matched by
// (DirectoryID, UniqueID) only, never by name or e-mail, and never joined to a local account.
type LDAPIdentity struct {
	DirectoryID uuid.UUID
	UniqueID    string // ldapx.UniqueID: the lower-case hex of the unique id attribute's bytes
	Login       string // the sign-in name as the directory holds it: the base of the user name (ldapx.Username), stored as ldap_login
	DisplayName string
	Email       string
}

// normalized returns the identity's values as Alice stores them: an e-mail address that is not a plain address is
// dropped, a blank display name is dropped (the user name stands in) and the display name is cut to its maximum
// length.
func (id LDAPIdentity) normalized() (LDAPIdentity, error) {
	// The sign-in name is stored (ldap_login) and sent to the directory at a step-up: it must be one Verify accepts.
	if id.DirectoryID == uuid.Nil || !uniqueIDRE.MatchString(id.UniqueID) || !ldapx.ValidLoginName(id.Login) {
		return LDAPIdentity{}, ErrLDAPIdentityInvalid
	}
	var v validate.Errors
	validateEmail(&v, id.Email)
	if v.Err() != nil || !validate.StorableText(id.Email) {
		id.Email = ""
	}
	if !validate.StorableText(id.DisplayName) || strings.TrimSpace(id.DisplayName) == "" {
		id.DisplayName = ""
	}
	if r := []rune(id.DisplayName); len(r) > maxDisplayName {
		id.DisplayName = string(r[:maxDisplayName])
	}
	return id, nil
}

// displayNameOr is the identity's display name, or name when it has none.
func (id LDAPIdentity) displayNameOr(name string) string {
	if id.DisplayName == "" {
		return name
	}
	return id.DisplayName
}

func checkLDAPRole(role rbac.Role) error {
	if _, ok := rbac.ParseRole(string(role)); !ok {
		return ErrLDAPIdentityInvalid
	}
	return nil
}

// ldapUser is a directory user's row, read under its row lock.
type ldapUser struct {
	ssoUser
	enrolled    bool       // a TOTP is enrolled
	lockedUntil *time.Time // the delay or lockout of failed TOTP codes
}

// lockLDAPUser reads the user of a directory identity with FOR UPDATE; found is false when there is none.
func lockLDAPUser(ctx context.Context, tx pgx.Tx, directoryID uuid.UUID, uniqueID string) (ldapUser, bool, error) {
	var u ldapUser
	var role string
	err := tx.QueryRow(ctx, `SELECT u.id, u.username::text, u.role, u.email::text, u.disabled_at IS NOT NULL,
EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enrolled_at IS NOT NULL), u.locked_until
FROM users u WHERE u.ldap_directory_id = $1 AND u.ldap_unique_id = $2 FOR UPDATE OF u`, directoryID, uniqueID).
		Scan(&u.id, &u.username, &role, &u.email, &u.disabled, &u.enrolled, &u.lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return ldapUser{}, false, nil
	}
	if err != nil {
		return ldapUser{}, false, fmt.Errorf("read directory user: %w", err)
	}
	u.role = rbac.Role(role)
	return u, true, nil
}

// provisionLDAPUser inserts a new directory user (provisionUser): no password, the role from the group mappings.
// lastLogin is set only when the sign-in opens a full session (nil while MFA is pending; VerifyMFA sets it).
func provisionLDAPUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID, id LDAPIdentity, role rbac.Role, locale string, now time.Time, lastLogin *time.Time) (string, error) {
	return provisionUser(ctx, tx, ldapx.Username(id.Login, id.UniqueID), func(q pgx.Tx, name string) error {
		_, err := q.Exec(ctx, `INSERT INTO users (id, username, email, display_name, auth_source, password_hash, role, role_source,
locale, ldap_directory_id, ldap_unique_id, ldap_login, last_login_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'ldap', NULL, $5, 'ldap_mapping', $6, $7, $8, $11, $10, $9, $9)`,
			userID, name, id.Email, id.displayNameOr(name), string(role), locale, id.DirectoryID, id.UniqueID, now, lastLogin, id.Login)
		return err
	})
}

func ldapRoleSynced(u ssoUser, role rbac.Role, m Meta) audit.Event {
	return audit.Event{Actor: userActor(u.id, u.username, m), Action: "user.role_synced", ObjectType: "user", ObjectID: u.id.String(),
		Result: audit.Success, Details: map[string]string{"from_role": string(u.role), "to_role": string(role)}}
}

// SignInLDAP signs in the user of an identity the directory just authenticated, with the role its group mappings
// resolved. The caller talks to the directory first: this function holds a transaction and never calls out. In one
// transaction it finds the user by directory and unique id or provisions one (user name by ldapx.Username, -2, -3 on
// a clash; never linking a local account: ErrLDAPEmailInUse), refuses a disabled user (ErrLDAPUserDisabled) and a user
// in a delay or lockout after failed TOTP codes (ErrLDAPUserLocked, in both MFA modes), follows
// the directory's role (capped by "SSO users may be Admin"), display name and e-mail (under the same collision rule),
// and opens a session: when mfaRequired, a pending session that the existing EnrollMFA and VerifyMFA complete
// (StatusMFAEnrollmentRequired or StatusMFARequired, by whether the user has a TOTP); otherwise a full session at once
// (StatusSignedIn, with Session set). A stored TOTP is left as it is either way.
func (s *Service) SignInLDAP(ctx context.Context, id LDAPIdentity, role rbac.Role, mfaRequired bool, m Meta) (LoginResult, error) {
	id, err := id.normalized()
	if err != nil {
		return LoginResult{}, err
	}
	if err := checkLDAPRole(role); err != nil {
		return LoginResult{}, err
	}
	var (
		userID uuid.UUID
		res    LoginResult
	)
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1, hashtext($2))", ldapIdentityLockNamespace,
			id.DirectoryID.String()+"\n"+id.UniqueID); err != nil {
			return fmt.Errorf("lock directory identity: %w", err)
		}
		if role, err = capRole(ctx, tx, role); err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		u, found, err := lockLDAPUser(ctx, tx, id.DirectoryID, id.UniqueID)
		if err != nil {
			return err
		}
		// last_login_at moves when a full session opens: here without MFA, in VerifyMFA with it (as for local users).
		var lastLogin *time.Time
		if !mfaRequired {
			lastLogin = &now
		}
		var events []audit.Event
		if !found {
			if inUse, err := localEmailInUse(ctx, tx, id.Email); err != nil || inUse {
				return cmpErr(err, ErrLDAPEmailInUse)
			}
			locale, err := defaultLocale(ctx, tx)
			if err != nil {
				return err
			}
			u = ldapUser{ssoUser: ssoUser{id: uuid.Must(uuid.NewV7()), role: role}}
			if u.username, err = provisionLDAPUser(ctx, tx, u.id, id, role, locale, now, lastLogin); err != nil {
				return err
			}
			events = append(events, audit.Event{Actor: userActor(u.id, u.username, m), Action: "user.provisioned", ObjectType: "user",
				ObjectID: u.id.String(), Result: audit.Success,
				Details: map[string]string{"username": u.username, "role": string(role), "directory_id": id.DirectoryID.String()}})
		} else {
			if u.disabled {
				return ErrLDAPUserDisabled
			}
			if u.lockedUntil != nil && now.Before(*u.lockedUntil) {
				// Failed TOTP codes put the account in a delay or lockout: refused in both MFA modes, so switching the
				// directory's MFA off is no way around it.
				return ErrLDAPUserLocked
			}
			if !strings.EqualFold(id.Email, u.email) {
				if inUse, err := localEmailInUse(ctx, tx, id.Email); err != nil || inUse {
					return cmpErr(err, ErrLDAPEmailInUse)
				}
			}
			// A full session (no MFA) also clears the failure count, as VerifyMFA does after a good code.
			if _, err := tx.Exec(ctx, `UPDATE users SET role = $2, email = $3, display_name = $4, updated_at = $5,
last_login_at = coalesce($6, last_login_at),
failed_logins = CASE WHEN $6::timestamptz IS NULL THEN failed_logins ELSE 0 END,
locked_until = CASE WHEN $6::timestamptz IS NULL THEN locked_until ELSE NULL END, ldap_login = $7 WHERE id = $1`,
				u.id, string(role), id.Email, id.displayNameOr(u.username), now, lastLogin, id.Login); err != nil {
				return fmt.Errorf("update directory user: %w", err)
			}
			if role != u.role {
				events = append(events, ldapRoleSynced(u.ssoUser, role, m))
			}
		}
		userID = u.id
		if mfaRequired {
			// The pending session can only complete MFA; VerifyMFA writes auth.login when it does.
			token, err := s.insertSession(ctx, tx, newSession{userID: u.id, kind: "pending", createdAt: now, expiresAt: now.Add(PendingLifetime)}, m)
			if err != nil {
				return err
			}
			res = LoginResult{Status: StatusMFARequired, SessionToken: token}
			if !u.enrolled {
				res.Status = StatusMFAEnrollmentRequired
			}
		} else {
			token, err := s.startFullSession(ctx, tx, u.id, m)
			if err != nil {
				return err
			}
			res = LoginResult{Status: StatusSignedIn, SessionToken: token}
			events = append(events, audit.Event{Actor: userActor(u.id, u.username, m), Action: "auth.login", ObjectType: "user", ObjectID: u.id.String(),
				Result: audit.Success, Details: map[string]string{"method": "ldap", "directory_id": id.DirectoryID.String(), "role": string(role)}})
		}
		// Audit rows last, after every row lock of this transaction.
		return s.appendAll(ctx, tx, events)
	})
	if err != nil {
		return LoginResult{}, err
	}
	if res.Status == StatusSignedIn {
		sr, err := s.resultFor(ctx, userID, res.SessionToken, nil)
		if err != nil {
			return LoginResult{}, err
		}
		res.Session = &sr
	}
	return res, nil
}

// StepUpLDAP completes a directory user's step-up: the caller has just repeated the bind with the directory password
// for the same identity (directory and unique id; otherwise ErrLDAPOtherUser) and resolved the role from the groups
// again; when the directory has mfa_required, mfaCode must also be a valid TOTP code, checked and counted like StepUp's
// (a wrong code is ErrMFAInvalid, the delay and lockout apply). The session must still be a live full session (a
// session ended by RefuseLDAP, DemoteSSOAdmins, disabling or idle expiry is never resurrected) and the user enabled.
// The role is synchronized as SignInLDAP does, and the session ID is rotated with a new 5-minute step-up window.
func (s *Service) StepUpLDAP(ctx context.Context, p Principal, id LDAPIdentity, role rbac.Role, mfaCode string, mfaRequired bool, m Meta) (SessionResult, error) {
	if p.Kind != rbac.UserSession {
		return SessionResult{}, ErrUnauthenticated
	}
	id, err := id.normalized()
	if err != nil {
		return SessionResult{}, err
	}
	if err := checkLDAPRole(role); err != nil {
		return SessionResult{}, err
	}
	actor := p.Actor(m)
	var (
		token  string
		failed bool
	)
	err = s.withCredentialSlot(ctx, func() error {
		return s.credentialTx(ctx, func(tx pgx.Tx) error {
			// Lock order (M-3): the "SSO users may be Admin" row FOR SHARE first, then the user row, as SignInLDAP
			// and the switch-off take them.
			var err error
			if role, err = capRole(ctx, tx, role); err != nil {
				return err
			}
			a, err := lockAccountByID(ctx, tx, p.UserID)
			if err != nil {
				return err
			}
			var (
				directoryID *uuid.UUID
				uniqueID    *string
				curRole     string
			)
			if err := tx.QueryRow(ctx, "SELECT ldap_directory_id, ldap_unique_id, role FROM users WHERE id = $1", p.UserID).
				Scan(&directoryID, &uniqueID, &curRole); err != nil {
				return fmt.Errorf("read directory user: %w", err)
			}
			switch {
			case a.source != AuthLDAP || directoryID == nil || *directoryID != id.DirectoryID || uniqueID == nil || *uniqueID != id.UniqueID:
				return ErrLDAPOtherUser
			case a.disabled:
				return ErrLDAPUserDisabled
			}
			now := s.clock.Now().UTC()
			live, err := sessionLive(ctx, tx, p, "full", now)
			if err != nil {
				return err
			}
			if !live {
				return ErrUnauthenticated
			}
			if mfaRequired {
				row, found, err := loadMFA(ctx, tx, p.UserID)
				if err != nil {
					return err
				}
				if !found || !row.enrolled {
					// No TOTP to check: not a guess, so nothing is counted; the person signs in again to enrol.
					return ErrLDAPEnrolmentRequired
				}
				if a.blocked(now) {
					failed = true
					return s.auditFailure(ctx, tx, actor, "auth.stepup", p.UserID.String(), "locked")
				}
				ok, err := s.checkTOTP(ctx, tx, p.UserID, row, mfaCode, false)
				if err != nil {
					return err
				}
				if !ok {
					failed = true
					return s.recordFailure(ctx, tx, actor, p.UserID, "auth.stepup", "bad_totp")
				}
				if _, err := tx.Exec(ctx, "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1", p.UserID); err != nil {
					return fmt.Errorf("reset failures: %w", err)
				}
			}
			var events []audit.Event
			if cur := rbac.Role(curRole); role != cur {
				if _, err := tx.Exec(ctx, "UPDATE users SET role = $2, updated_at = $3 WHERE id = $1", p.UserID, string(role), now); err != nil {
					return fmt.Errorf("update directory user: %w", err)
				}
				events = append(events, ldapRoleSynced(ssoUser{id: p.UserID, username: a.name, role: cur}, role, m))
			}
			stepUp := now.Add(StepUpWindow)
			if token, err = s.rotateSession(ctx, tx, p.SessionHash, p.UserID, &stepUp, m); err != nil {
				return err
			}
			events = append(events, audit.Event{Actor: userActor(p.UserID, a.name, m), Action: "auth.stepup", ObjectType: "user", ObjectID: p.UserID.String(),
				Result: audit.Success, Details: map[string]string{"method": "ldap"}})
			return s.appendAll(ctx, tx, events)
		})
	})
	if err != nil {
		return SessionResult{}, err
	}
	if failed {
		return SessionResult{}, ErrMFAInvalid
	}
	return s.resultFor(ctx, p.UserID, token, nil)
}

// RefuseLDAP records a refused directory sign-in or step-up (auth.ldap.denied, result failure) with the closed reason,
// the directory and, only when the directory resolved the name to an entry or to several (deniedLoginName), the
// sign-in name. id.DirectoryID is required; id.UniqueID is known only once the directory accepted the password,
// and with it the user, when one exists, is the actor and the object (audit.ActorUser); an unknown user is recorded
// with audit.ActorSystem. For a known user and a reason that says the user no longer has access (no_access,
// provider_disabled) it also ends all of the user's sessions and revokes all of the user's API tokens in the same
// transaction, as RefuseOIDC does.
func (s *Service) RefuseLDAP(ctx context.Context, id LDAPIdentity, reason string, m Meta) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var (
			u     ldapUser
			found bool
			err   error
		)
		if id.DirectoryID != uuid.Nil && uniqueIDRE.MatchString(id.UniqueID) {
			if u, found, err = lockLDAPUser(ctx, tx, id.DirectoryID, id.UniqueID); err != nil {
				return err
			}
		}
		details := map[string]string{"directory_id": id.DirectoryID.String(), "reason": reason}
		if login := deniedLoginName(id, reason); login != "" {
			details["login_name"] = login
		}
		actor := audit.Actor{Type: audit.ActorSystem, Name: unknownUserName, IP: m.IP, RequestID: m.RequestID}
		objectID := ""
		if found {
			actor, objectID = userActor(u.id, u.username, m), u.id.String()
		}
		events := []audit.Event{{Actor: actor, Action: "auth.ldap.denied", ObjectType: "user", ObjectID: objectID,
			Result: audit.Failure, Details: details}}
		if found && slices.Contains(ldapSessionEndingReasons, reason) {
			ended, err := s.endAccess(ctx, tx, actor, u.id, reason)
			if err != nil {
				return err
			}
			events = append(events, ended)
		}
		return s.appendAll(ctx, tx, events)
	})
}

// deniedLoginName is the sign-in name an auth.ldap.denied row records. It is recorded only when the directory
// resolved the name to an entry (the identity has a unique id) or to more than one (ambiguous_user), cut to
// maxDeniedLoginRunes; for every other refusal (an unknown name, login_invalid, an unreachable or misconfigured or
// disabled directory) it is left out. People paste passwords into the name field, the audit log is append-only and
// every Auditor reads it, so a name nothing in the directory matched is never stored (local Login records "(unknown
// user)" for the same reason). The rule lives here so that no caller can get it wrong.
func deniedLoginName(id LDAPIdentity, reason string) string {
	if id.UniqueID == "" && reason != "ambiguous_user" {
		return ""
	}
	if reason == "login_invalid" || !validate.StorableText(id.Login) {
		return ""
	}
	if r := []rune(id.Login); len(r) > maxDeniedLoginRunes {
		return string(r[:maxDeniedLoginRunes])
	}
	return id.Login
}
