package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Errors of single sign-on (C10).
var (
	// ErrOIDCEmailInUse: the identity's e-mail address belongs to a local user (O-10, S-7).
	ErrOIDCEmailInUse = errors.New("auth: the e-mail address belongs to a local user")
	// ErrOIDCUserDisabled: the SSO user is disabled in Alice.
	ErrOIDCUserDisabled = errors.New("auth: the SSO user is disabled")
	// ErrOIDCOtherUser: a step-up was answered by another identity than the session's user.
	ErrOIDCOtherUser = errors.New("auth: the step-up was answered for another identity")
	// ErrNotSSOUser: an SSO step-up for a local user.
	ErrNotSSOUser = errors.New("auth: not an SSO user")
	// ErrSSOUser: a manual role change, password or MFA operation on an SSO user, whose role,
	// password and second factor belong to the identity provider (ALC-USR-0003).
	ErrSSOUser = errors.New("auth: the identity provider manages this SSO user")
	// ErrDirectoryUser: a password change or reset, a manual role change, an API token or a TOTP step-up of a
	// directory (LDAP) user. The directory owns the password and the groups that give the role; the user's TOTP is
	// Alice's (MFA reset and recovery codes stay allowed) and a step-up repeats the directory bind (StepUpLDAP).
	ErrDirectoryUser = errors.New("auth: this change is not possible for a directory user")
	// ErrOIDCIdentityInvalid: the caller passed an identity or role Alice cannot store (no provider or
	// subject, a subject over 255 or an issuer over 500 characters, an unknown role).
	ErrOIDCIdentityInvalid = errors.New("auth: the SSO identity or role is not valid")
)

// SSOAllowAdminKey is the setting "SSO users may be Admin" ({"allow": bool, "version": n}); the oidc
// package writes it, SignInOIDC and StepUpOIDC read it to cap the role (O-13).
const SSOAllowAdminKey = "sso.allow_admin_role"

// Limits of the stored identity (migration 00011).
const (
	maxSubjectChars = 255
	maxIssuerChars  = 500
)

// OIDCIdentity is a user the identity provider authenticated. SSO users are matched by
// (ProviderID, Subject) only (S-8); Issuer is stored for display.
type OIDCIdentity struct {
	ProviderID  uuid.UUID
	Issuer      string
	Subject     string
	Username    string // claims.Username
	DisplayName string
	Email       string
	// AuthTime is the ID token's auth_time (zero when it had none). A sign-in opens the step-up window only when
	// it is within StepUpWindow of Alice's clock: a silent sign-in at the provider proves no fresh credential (I-1).
	AuthTime time.Time
}

// sessionEndingReasons are the refusals that say the user no longer has access: they end the
// user's sessions (O-08, R42 row 21). Other refusals (a bad token, an expired state, …) say
// nothing about the user and are only audited.
var sessionEndingReasons = []string{"no_access", "groups_overage", "provider_disabled"}

// oidcIdentityLockNamespace is the first key of the per-identity advisory lock SignInOIDC takes,
// so two first sign-ins of one identity provision one user (the second waits and finds it).
const oidcIdentityLockNamespace int32 = 0x616c6332 // "alc2"

// maxUsernameBytes is the longest user name in bytes (an SSO user name is cut on a character boundary).
const maxUsernameBytes = 64

// maxUsernameSuffix bounds the "-2" … "-99" suffixes tried for a taken user name.
const maxUsernameSuffix = 99

// ssoFallbackName is the user name of an identity that brought none.
const ssoFallbackName = "sso-user"

func oidcActor(userID uuid.UUID, name string, m Meta) audit.Actor {
	return audit.Actor{Type: audit.ActorOIDC, ID: userID, Name: name, IP: m.IP, RequestID: m.RequestID}
}

// ssoUser is an SSO user's row, read under its row lock.
type ssoUser struct {
	id       uuid.UUID
	username string
	role     rbac.Role
	email    string
	disabled bool
}

// lockSSOUser reads the user of an identity with FOR UPDATE; found is false when there is none.
func lockSSOUser(ctx context.Context, tx pgx.Tx, providerID uuid.UUID, subject string) (ssoUser, bool, error) {
	var u ssoUser
	var role string
	err := tx.QueryRow(ctx, `SELECT id, username::text, role, email::text, disabled_at IS NOT NULL FROM users
WHERE oidc_provider_id = $1 AND oidc_subject = $2 FOR UPDATE`, providerID, subject).Scan(&u.id, &u.username, &role, &u.email, &u.disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return ssoUser{}, false, nil
	}
	if err != nil {
		return ssoUser{}, false, fmt.Errorf("read SSO user: %w", err)
	}
	u.role = rbac.Role(role)
	return u, true, nil
}

// localEmailInUse reports whether a local user has the (non-empty) address; citext compares
// it case-insensitively.
func localEmailInUse(ctx context.Context, tx pgx.Tx, email string) (bool, error) {
	if email == "" {
		return false, nil
	}
	var used bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE auth_source = 'local' AND email = $1)`, email).Scan(&used); err != nil {
		return false, fmt.Errorf("check e-mail: %w", err)
	}
	return used, nil
}

// cutBytes shortens s to at most n bytes on a rune boundary.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// freeUsername returns name, or name with the first free suffix -2 … -99, within 64 bytes;
// user names compare case-insensitively (citext).
func freeUsername(ctx context.Context, tx pgx.Tx, name string) (string, error) {
	for i := 1; i <= maxUsernameSuffix; i++ {
		candidate := cutBytes(name, maxUsernameBytes)
		if i > 1 {
			suffix := "-" + strconv.Itoa(i)
			candidate = cutBytes(name, maxUsernameBytes-len(suffix)) + suffix
		}
		var taken bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", candidate).Scan(&taken); err != nil {
			return "", fmt.Errorf("check user name: %w", err)
		}
		if !taken {
			return candidate, nil
		}
	}
	return "", ErrUsernameTaken
}

// maxProvisionAttempts bounds how often provisionUser picks another name after its pick was taken meanwhile; each
// retry means another sign-in or user creation took that name in the meantime.
const maxProvisionAttempts = 20

// provisionUser inserts a new SSO or directory user under the first free user name based on base; insert runs the
// INSERT with the name it is given. The per-identity lock does not cover the name: another identity's first sign-in,
// or a local user created at the same moment, can take the name between freeUsername's check and the INSERT. The
// INSERT runs in a savepoint, so that violation of the user-name constraint rolls back only the INSERT and the next
// free name is tried; read committed lets the next check see the committed name (review M-2).
func provisionUser(ctx context.Context, tx pgx.Tx, base string, insert func(q pgx.Tx, name string) error) (string, error) {
	for attempt := 1; ; attempt++ {
		name, err := freeUsername(ctx, tx, base)
		if err != nil {
			return "", err
		}
		sp, err := tx.Begin(ctx)
		if err != nil {
			return "", fmt.Errorf("provision user: %w", err)
		}
		err = insert(sp, name)
		if err == nil {
			if err := sp.Commit(ctx); err != nil {
				return "", fmt.Errorf("provision user: %w", err)
			}
			return name, nil
		}
		if rerr := sp.Rollback(ctx); rerr != nil {
			return "", fmt.Errorf("provision user: %w", rerr)
		}
		if !db.IsUniqueViolationOn(err, UsernameConstraint) || attempt >= maxProvisionAttempts {
			return "", fmt.Errorf("provision user: %w", err)
		}
	}
}

// provisionSSOUser inserts a new SSO user (provisionUser).
func provisionSSOUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID, id OIDCIdentity, role rbac.Role, locale string, now time.Time) (string, error) {
	return provisionUser(ctx, tx, id.Username, func(q pgx.Tx, name string) error {
		_, err := q.Exec(ctx, `INSERT INTO users (id, username, email, display_name, auth_source, password_hash, role, role_source,
locale, oidc_provider_id, oidc_issuer, oidc_subject, last_login_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'oidc', NULL, $5, 'oidc_mapping', $6, $7, $8, $9, $10, $10, $10)`,
			userID, name, id.Email, displayName(id, name), string(role), locale, id.ProviderID, id.Issuer, id.Subject, now)
		return err
	})
}

// defaultLocale is the locale.default setting for a new SSO user, English when unset.
func defaultLocale(ctx context.Context, tx pgx.Tx) (string, error) {
	var loc string
	found, err := settings.Get(ctx, tx, "locale.default", &loc)
	if err != nil {
		return "", err
	}
	if !found || !slices.Contains(SupportedLocales, loc) {
		return "en", nil
	}
	return loc, nil
}

// normalized returns the identity's values as Alice stores them: an e-mail address that is
// not a plain address is dropped, a blank display name becomes the user name, and the
// display name is cut to its maximum length.
func (id OIDCIdentity) normalized() (OIDCIdentity, error) {
	if id.ProviderID == uuid.Nil || id.Subject == "" || !validate.StorableText(id.Subject) || !validate.StorableText(id.Issuer) ||
		utf8.RuneCountInString(id.Subject) > maxSubjectChars || utf8.RuneCountInString(id.Issuer) > maxIssuerChars {
		return OIDCIdentity{}, ErrOIDCIdentityInvalid
	}
	if id.Username == "" || !validate.StorableText(id.Username) {
		id.Username = ssoFallbackName
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

func checkRole(role rbac.Role) error {
	if _, ok := rbac.ParseRole(string(role)); !ok {
		return ErrOIDCIdentityInvalid
	}
	return nil
}

// capRole lowers Administrator to Operator while "SSO users may be Admin" is off; the switch covers SSO and directory
// users alike (SignInOIDC, StepUpOIDC, SignInLDAP and StepUpLDAP call it). It reads the
// switch FOR SHARE in the caller's transaction, so a switch-off (which locks the row FOR UPDATE and
// demotes the SSO Administrators in its own transaction) and this sign-in are ordered: a role the
// caller resolved before the switch went off never commits as Administrator after it (O-13).
func capRole(ctx context.Context, tx pgx.Tx, role rbac.Role) (rbac.Role, error) {
	if role != rbac.Admin {
		return role, nil
	}
	var sw struct {
		Allow bool `json:"allow"`
	}
	var raw []byte
	err := tx.QueryRow(ctx, "SELECT value FROM settings WHERE key = $1 FOR SHARE", SSOAllowAdminKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return rbac.Operator, nil
	}
	if err != nil {
		return "", fmt.Errorf("read the SSO Admin switch: %w", err)
	}
	if err := json.Unmarshal(raw, &sw); err != nil || !sw.Allow {
		return rbac.Operator, nil //nolint:nilerr // an unreadable switch is off
	}
	return role, nil
}

// SignInOIDC signs in the user of an identity the provider just authenticated, with the role
// its group mappings resolved (C10). In one transaction it finds the user by provider and
// subject or provisions one (never linking a local account: ErrOIDCEmailInUse), refuses a
// disabled user, follows the provider's role, display name and e-mail (the e-mail under the
// same collision rule, S-7), and opens a full session. Its step-up window is open only when
// the ID token's auth_time shows the provider authenticated the user within StepUpWindow
// (ssoStepUpUntil); a silent sign-in leaves it closed, and a stepped-up action then needs the
// provider's step-up (prompt=login, max_age=0).
func (s *Service) SignInOIDC(ctx context.Context, id OIDCIdentity, role rbac.Role, m Meta) (SessionResult, error) {
	id, err := id.normalized()
	if err != nil {
		return SessionResult{}, err
	}
	if err := checkRole(role); err != nil {
		return SessionResult{}, err
	}
	var (
		userID uuid.UUID
		token  string
	)
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1, hashtext($2))", oidcIdentityLockNamespace,
			id.ProviderID.String()+"\n"+id.Subject); err != nil {
			return fmt.Errorf("lock SSO identity: %w", err)
		}
		if role, err = capRole(ctx, tx, role); err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		u, found, err := lockSSOUser(ctx, tx, id.ProviderID, id.Subject)
		if err != nil {
			return err
		}
		var events []audit.Event
		if !found {
			if inUse, err := localEmailInUse(ctx, tx, id.Email); err != nil || inUse {
				return cmpErr(err, ErrOIDCEmailInUse)
			}
			locale, err := defaultLocale(ctx, tx)
			if err != nil {
				return err
			}
			u = ssoUser{id: uuid.Must(uuid.NewV7()), role: role}
			name, err := provisionSSOUser(ctx, tx, u.id, id, role, locale, now)
			if err != nil {
				return err
			}
			u.username = name
			events = append(events, audit.Event{Actor: oidcActor(u.id, name, m), Action: "user.provisioned", ObjectType: "user", ObjectID: u.id.String(),
				Result: audit.Success, Details: map[string]string{"username": name, "role": string(role), "provider_id": id.ProviderID.String()}})
		} else {
			if u.disabled {
				return ErrOIDCUserDisabled
			}
			if !strings.EqualFold(id.Email, u.email) {
				if inUse, err := localEmailInUse(ctx, tx, id.Email); err != nil || inUse {
					return cmpErr(err, ErrOIDCEmailInUse)
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE users SET role = $2, email = $3, display_name = $4, last_login_at = $5, updated_at = $5 WHERE id = $1`,
				u.id, string(role), id.Email, displayName(id, u.username), now); err != nil {
				return fmt.Errorf("update SSO user: %w", err)
			}
			if role != u.role {
				events = append(events, roleSynced(u, role, m))
			}
		}
		userID = u.id
		if token, err = s.insertSession(ctx, tx, newSession{userID: u.id, kind: "full", createdAt: now, expiresAt: now.Add(SessionAbsolute),
			stepUp: ssoStepUpUntil(now, id.AuthTime)}, m); err != nil {
			return err
		}
		// Audit rows last, after every row lock of this transaction.
		events = append(events, audit.Event{Actor: userActor(u.id, u.username, m), Action: "auth.login", ObjectType: "user", ObjectID: u.id.String(),
			Result: audit.Success, Details: map[string]string{"method": "oidc", "provider_id": id.ProviderID.String(), "role": string(role)}})
		return s.appendAll(ctx, tx, events)
	})
	if err != nil {
		return SessionResult{}, err
	}
	return s.resultFor(ctx, userID, token, nil)
}

// authTimeSkew is the clock skew accepted on an auth_time in the future, as claims.Leeway.
const authTimeSkew = time.Minute

// ssoStepUpUntil is the end of the step-up window an SSO sign-in opens: authTime + StepUpWindow,
// never later than now + StepUpWindow, and nil (closed) when the token had no auth_time, when
// auth_time is in the future beyond the skew, or when the window has already passed (I-1).
func ssoStepUpUntil(now, authTime time.Time) *time.Time {
	if authTime.IsZero() || authTime.After(now.Add(authTimeSkew)) {
		return nil
	}
	until := authTime.UTC().Add(StepUpWindow)
	if limit := now.Add(StepUpWindow); until.After(limit) {
		until = limit
	}
	if !now.Before(until) {
		return nil
	}
	return &until
}

// cmpErr returns err when set, else refusal.
func cmpErr(err, refusal error) error {
	if err != nil {
		return err
	}
	return refusal
}

func displayName(id OIDCIdentity, username string) string {
	if id.DisplayName == "" {
		return username
	}
	return id.DisplayName
}

func roleSynced(u ssoUser, role rbac.Role, m Meta) audit.Event {
	return audit.Event{Actor: oidcActor(u.id, u.username, m), Action: "user.role_synced", ObjectType: "user", ObjectID: u.id.String(),
		Result: audit.Success, Details: map[string]string{"from_role": string(u.role), "to_role": string(role)}}
}

func (s *Service) appendAll(ctx context.Context, tx pgx.Tx, events []audit.Event) error {
	for _, e := range events {
		if _, err := s.audit.Append(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

// StepUpOIDC completes an SSO user's step-up: a fresh sign-in at the identity provider of the
// same identity (SEC-009, R42 row 22). The session must still be live (S-1: a session ended by
// RefuseOIDC, DemoteSSOAdmins, disabling or idle expiry is never resurrected) and the user
// enabled; role is the one the group mappings resolved for this sign-in, synchronized as
// SignInOIDC does. The session ID is rotated with a new 5-minute step-up window.
func (s *Service) StepUpOIDC(ctx context.Context, sessionHash []byte, userID uuid.UUID, id OIDCIdentity, role rbac.Role, m Meta) (SessionResult, error) {
	if err := checkRole(role); err != nil {
		return SessionResult{}, err
	}
	var token string
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Lock order (M-3): the "SSO users may be Admin" row FOR SHARE first, then the user row, as SignInOIDC does
		// and as the switch-off takes them (switch FOR UPDATE, then the SSO Administrators' rows); the reverse order
		// could deadlock a step-up against a switch-off.
		var err error
		if role, err = capRole(ctx, tx, role); err != nil {
			return err
		}
		var (
			u          ssoUser
			source     string
			providerID *uuid.UUID
			subject    *string
			curRole    string
		)
		err = tx.QueryRow(ctx, `SELECT username::text, role, auth_source, oidc_provider_id, oidc_subject, disabled_at IS NOT NULL
FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&u.username, &curRole, &source, &providerID, &subject, &u.disabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnauthenticated
		}
		if err != nil {
			return fmt.Errorf("read user: %w", err)
		}
		u.id, u.role = userID, rbac.Role(curRole)
		switch {
		case source != AuthOIDC:
			return ErrNotSSOUser
		case providerID == nil || *providerID != id.ProviderID || subject == nil || *subject != id.Subject:
			return ErrOIDCOtherUser
		case u.disabled:
			return ErrOIDCUserDisabled
		}
		now := s.clock.Now().UTC()
		live, err := sessionLive(ctx, tx, Principal{SessionHash: sessionHash, UserID: userID}, "full", now)
		if err != nil {
			return err
		}
		if !live {
			return ErrUnauthenticated
		}
		var events []audit.Event
		if role != u.role {
			if _, err := tx.Exec(ctx, "UPDATE users SET role = $2, updated_at = $3 WHERE id = $1", userID, string(role), now); err != nil {
				return fmt.Errorf("update SSO user: %w", err)
			}
			events = append(events, roleSynced(u, role, m))
		}
		stepUp := now.Add(StepUpWindow)
		if token, err = s.rotateSession(ctx, tx, sessionHash, userID, &stepUp, m); err != nil {
			return err
		}
		events = append(events, audit.Event{Actor: userActor(userID, u.username, m), Action: "auth.stepup", ObjectType: "user", ObjectID: userID.String(),
			Result: audit.Success, Details: map[string]string{"method": "oidc"}})
		return s.appendAll(ctx, tx, events)
	})
	if err != nil {
		return SessionResult{}, err
	}
	return s.resultFor(ctx, userID, token, nil)
}

// RefuseOIDC records a refused SSO sign-in or step-up (auth.oidc.denied, result failure, with
// the closed reason). For a known user and a reason that says the user no longer has access
// (no_access, groups_overage, provider_disabled) it also ends all of that user's sessions and
// revokes all of the user's API tokens in the same transaction (O-08, R42 row 21, controller
// ruling). id may carry only the provider when the refusal
// came before any identity was known.
func (s *Service) RefuseOIDC(ctx context.Context, id OIDCIdentity, reason string, m Meta) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var (
			u     ssoUser
			found bool
			err   error
		)
		if id.ProviderID != uuid.Nil && id.Subject != "" && validate.StorableText(id.Subject) {
			if u, found, err = lockSSOUser(ctx, tx, id.ProviderID, id.Subject); err != nil {
				return err
			}
		}
		name, objectID := id.Username, ""
		if found {
			name, objectID = u.username, u.id.String()
		}
		if name == "" || !validate.StorableText(name) {
			name = unknownUserName
		}
		actor := oidcActor(u.id, name, m)
		events := []audit.Event{{Actor: actor, Action: "auth.oidc.denied", ObjectType: "user", ObjectID: objectID,
			Result: audit.Failure, Details: map[string]string{"provider_id": id.ProviderID.String(), "reason": reason}}}
		if found && slices.Contains(sessionEndingReasons, reason) {
			ended, err := s.endAccess(ctx, tx, actor, u.id, reason)
			if err != nil {
				return err
			}
			events = append(events, ended)
		}
		return s.appendAll(ctx, tx, events)
	})
}

// endAccess ends every session of a user whose access ended at the identity provider or the directory and revokes
// every API token of the user, inside the caller's transaction, which holds the user's row lock. Each token is
// audited as token.revoked with reason (appended here); the returned user.sessions_ended event (reason, ended_count,
// revoked_tokens_count) is the caller's to append last (O-08, R42 row 21).
func (s *Service) endAccess(ctx context.Context, tx pgx.Tx, actor audit.Actor, userID uuid.UUID, reason string) (audit.Event, error) {
	now := s.clock.Now().UTC()
	tag, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL", userID, now)
	if err != nil {
		return audit.Event{}, fmt.Errorf("end sessions: %w", err)
	}
	details := map[string]string{"reason": reason, "ended_count": strconv.FormatInt(tag.RowsAffected(), 10)}
	// Access ended at the identity provider ends every credential Alice issued on it: the
	// API tokens too, each audited as token.revoked with the refusal's reason.
	if err := s.revokeUserTokens(ctx, tx, actor, userID, now, reason, details); err != nil {
		return audit.Event{}, err
	}
	return audit.Event{Actor: actor, Action: "user.sessions_ended", ObjectType: "user", ObjectID: userID.String(),
		Result: audit.Success, Details: details}, nil
}

// DemoteSSOAdmins makes every SSO and directory Administrator an Auditor and ends their sessions, inside the
// caller's transaction (switching "SSO users may be Admin" off, O-13, R42 row 24; the switch covers directory users,
// plan ruling 8). Each
// demotion is audited as user.demoted by a. API tokens stay: AuthenticateToken reads the
// owner's current role on every request and refuses a scope that role no longer allows, so a
// demoted user's tokens act as an Auditor's at once.
func (s *Service) DemoteSSOAdmins(ctx context.Context, tx pgx.Tx, a audit.Actor) (demoted, ended int, err error) {
	now := s.clock.Now().UTC()
	// The rows are locked in ID order, so two demotions cannot deadlock each other.
	rows, err := tx.Query(ctx, `UPDATE users SET role = 'auditor', updated_at = $1 WHERE id IN (
SELECT id FROM users WHERE auth_source IN ('oidc', 'ldap') AND role = 'admin' ORDER BY id FOR UPDATE) RETURNING id`, now)
	if err != nil {
		return 0, 0, fmt.Errorf("demote SSO administrators: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, 0, fmt.Errorf("demote SSO administrators: %w", err)
	}
	if len(ids) == 0 {
		return 0, 0, nil
	}
	slices.SortFunc(ids, func(x, y uuid.UUID) int { return bytes.Compare(x[:], y[:]) })
	tag, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = $2 WHERE user_id = ANY($1) AND revoked_at IS NULL", ids, now)
	if err != nil {
		return 0, 0, fmt.Errorf("end sessions: %w", err)
	}
	for _, id := range ids {
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "user.demoted", ObjectType: "user", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"from_role": string(rbac.Admin), "to_role": string(rbac.Auditor)}}); err != nil {
			return 0, 0, err
		}
	}
	return len(ids), int(tag.RowsAffected()), nil
}
