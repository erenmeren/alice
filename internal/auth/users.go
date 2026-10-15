package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Errors of the user administration and token functions.
var (
	ErrUsernameTaken        = errors.New("auth: username already taken")
	ErrLastAdmin            = errors.New("auth: the last enabled local administrator cannot be removed")
	ErrTokenScopeNotAllowed = errors.New("auth: token scope exceeds the owner's role")
)

// NewUser is the input of CreateUser.
type NewUser struct {
	Username, DisplayName, Email string
	Role                         rbac.Role
	Password                     string
}

// UserUpdate changes selected fields; nil fields stay unchanged.
type UserUpdate struct {
	DisplayName *string
	Email       *string
	Role        *rbac.Role
	Disabled    *bool
}

func validateRole(v *validate.Errors, r rbac.Role) {
	if _, ok := rbac.ParseRole(string(r)); !ok {
		v.Add("role", validate.OneOf, map[string]string{"values": "admin, operator, auditor"})
	}
}

// ListUsers returns all users ordered by username.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+userColumns+" FROM users u ORDER BY u.username")
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return out, nil
}

// GetUser returns one user or ErrNotFound.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (User, error) {
	return getUser(ctx, s.pool, id)
}

// UsernameConstraint is the unique constraint on users.username (migrations/00002_core.sql); only its violation means
// "this user name is taken".
const UsernameConstraint = "users_username_key"

// CreateUser adds a local user. The user enrolls TOTP at first login.
func (s *Service) CreateUser(ctx context.Context, p Principal, m Meta, in NewUser) (User, error) {
	v := ValidateProfile(in.Username, in.DisplayName, in.Email)
	validateRole(&v, in.Role)
	if err := v.Err(); err != nil {
		return User{}, err
	}
	if err := CheckPasswordPolicy(in.Password); err != nil {
		return User{}, err
	}
	hash, err := s.hasher.Hash(ctx, NormalizePassword(in.Password))
	if err != nil {
		return User{}, err
	}
	id := uuid.Must(uuid.NewV7())
	now := s.clock.Now().UTC()
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, username, email, display_name, auth_source, password_hash, role, password_changed_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'local', $5, $6, $7, $7, $7)`, id, in.Username, in.Email, in.DisplayName, hash, string(in.Role), now); err != nil {
			if db.IsUniqueViolationOn(err, UsernameConstraint) {
				return ErrUsernameTaken
			}
			return fmt.Errorf("create user: %w", err)
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "user.created", ObjectType: "user", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"username": in.Username, "role": string(in.Role)}})
		return err
	})
	if errors.Is(err, ErrUsernameTaken) {
		if aerr := s.adminFailure(ctx, p, m, "user.created", "", "username_taken"); aerr != nil {
			return User{}, aerr
		}
		return User{}, ErrUsernameTaken
	}
	if err != nil {
		return User{}, err
	}
	return getUser(ctx, s.pool, id)
}

// adminFailure audits a refused administrative change.
func (s *Service) adminFailure(ctx context.Context, p Principal, m Meta, action, objectID, reason string) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: action, ObjectType: "user", ObjectID: objectID,
			Result: audit.Failure, Details: map[string]string{"reason": reason}})
		return err
	})
}

// lockAdmins locks every enabled local administrator row in a fixed order and returns their IDs.
// Every change that could remove an administrator takes these locks first, so concurrent
// changes serialize and the break-glass rule (R10) cannot be raced.
func lockAdmins(ctx context.Context, tx pgx.Tx) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM users WHERE role = 'admin' AND disabled_at IS NULL AND auth_source = 'local'
ORDER BY id FOR UPDATE`)
	if err != nil {
		return nil, fmt.Errorf("lock administrators: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("lock administrators: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("lock administrators: %w", err)
	}
	return ids, nil
}

// UpdateUser changes profile, role or enabled state. A role change or disabling ends the
// user's sessions. The last enabled local administrator cannot be demoted or disabled.
func (s *Service) UpdateUser(ctx context.Context, p Principal, m Meta, id uuid.UUID, in UserUpdate) (User, error) {
	var v validate.Errors
	if in.DisplayName != nil {
		validateDisplayName(&v, *in.DisplayName)
	}
	if in.Email != nil {
		validateEmail(&v, *in.Email)
	}
	if in.Role != nil {
		validateRole(&v, *in.Role)
	}
	if err := v.Err(); err != nil {
		return User{}, err
	}
	now := s.clock.Now().UTC()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Only a role or enabled-state change can remove an administrator, so only those take
		// the administrator set; profile-only edits lock just the target row.
		var admins []uuid.UUID
		if in.Role != nil || in.Disabled != nil {
			var err error
			if admins, err = lockAdmins(ctx, tx); err != nil {
				return err
			}
		}
		// The target row is locked after the administrator set, in the same order as every
		// other change, and before any update; credential checks on this account (which hold
		// the same row lock, see lockAccount) finish first.
		cur, err := scanUser(tx.QueryRow(ctx, "SELECT "+userColumns+" FROM users u WHERE u.id = $1 FOR UPDATE OF u", id))
		if err != nil {
			return err
		}
		roleChanged := in.Role != nil && *in.Role != cur.Role
		if roleChanged && cur.AuthSource != AuthLocal {
			// An SSO or directory user's role follows the group mappings at every sign-in (SEC-014).
			return sourceRefusal(cur.AuthSource)
		}
		disable := in.Disabled != nil && *in.Disabled && !cur.Disabled
		if (roleChanged || disable) && slices.Contains(admins, id) && len(admins) <= 1 {
			return ErrLastAdmin
		}
		details := map[string]string{}
		if in.DisplayName != nil && *in.DisplayName != cur.DisplayName {
			details["display_name"] = "changed"
			if _, err := tx.Exec(ctx, "UPDATE users SET display_name = $2 WHERE id = $1", id, *in.DisplayName); err != nil {
				return fmt.Errorf("update user: %w", err)
			}
		}
		if in.Email != nil && *in.Email != cur.Email {
			details["email"] = "changed"
			if _, err := tx.Exec(ctx, "UPDATE users SET email = $2 WHERE id = $1", id, *in.Email); err != nil {
				return fmt.Errorf("update user: %w", err)
			}
		}
		if roleChanged {
			details["role_from"], details["role_to"] = string(cur.Role), string(*in.Role)
			if _, err := tx.Exec(ctx, "UPDATE users SET role = $2 WHERE id = $1", id, string(*in.Role)); err != nil {
				return fmt.Errorf("update user: %w", err)
			}
		}
		if in.Disabled != nil && *in.Disabled != cur.Disabled {
			details["disabled"] = strconv.FormatBool(*in.Disabled)
			var at any
			if *in.Disabled {
				at = now
			}
			if _, err := tx.Exec(ctx, "UPDATE users SET disabled_at = $2 WHERE id = $1", id, at); err != nil {
				return fmt.Errorf("update user: %w", err)
			}
		}
		if len(details) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET updated_at = $2 WHERE id = $1", id, now); err != nil {
			return fmt.Errorf("update user: %w", err)
		}
		if roleChanged || disable {
			if err := revokeUserSessions(ctx, tx, id); err != nil {
				return err
			}
		}
		if disable {
			// Disabling revokes the user's API tokens for good: re-enabling does not bring
			// them back. A role change keeps them; their scope is checked on every use.
			if err := s.revokeUserTokens(ctx, tx, p.Actor(m), id, now, "user_disabled", details); err != nil {
				return err
			}
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "user.updated", ObjectType: "user", ObjectID: id.String(),
			Result: audit.Success, Details: details})
		return err
	})
	if errors.Is(err, ErrLastAdmin) {
		if aerr := s.adminFailure(ctx, p, m, "user.updated", id.String(), "last_admin"); aerr != nil {
			return User{}, aerr
		}
		return User{}, ErrLastAdmin
	}
	if err := s.auditSSORefusal(ctx, p, m, err, "user.updated", id); err != nil {
		return User{}, err
	}
	return getUser(ctx, s.pool, id)
}

// sourceRefusal is the refusal of a change that only a local user can have (a password, a manual role, an API
// token, a TOTP step-up): nil for a local user, ErrDirectoryUser for a directory user and ErrSSOUser for an SSO user
// (and for any other source, which no row can hold).
func sourceRefusal(source string) error {
	switch source {
	case AuthLocal:
		return nil
	case AuthLDAP:
		return ErrDirectoryUser
	default:
		return ErrSSOUser
	}
}

// authSourceOf reads a user's users.auth_source. The caller holds the user's row lock (adminChange).
func authSourceOf(ctx context.Context, tx pgx.Tx, id uuid.UUID) (string, error) {
	var source string
	if err := tx.QueryRow(ctx, "SELECT auth_source FROM users WHERE id = $1", id).Scan(&source); err != nil {
		return "", fmt.Errorf("read user: %w", err)
	}
	return source, nil
}

// refuseSSOUser returns ErrSSOUser for an SSO user: their MFA lives at the identity provider. A directory user's
// TOTP is Alice's and passes. The caller holds the user's row lock (adminChange).
func refuseSSOUser(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	source, err := authSourceOf(ctx, tx, id)
	if err != nil {
		return err
	}
	if source == AuthOIDC {
		return ErrSSOUser
	}
	return nil
}

// refuseNonLocalUser returns sourceRefusal for a user without an Alice password: ErrSSOUser for an SSO user,
// ErrDirectoryUser for a directory user. The caller holds the user's row lock (adminChange).
func refuseNonLocalUser(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	source, err := authSourceOf(ctx, tx, id)
	if err != nil {
		return err
	}
	return sourceRefusal(source)
}

// auditSSORefusal audits an ErrSSOUser or ErrDirectoryUser refusal like the action's other refusals (reason sso_user
// or directory_user) and returns err unchanged.
func (s *Service) auditSSORefusal(ctx context.Context, p Principal, m Meta, err error, action string, id uuid.UUID) error {
	reason := ""
	switch {
	case errors.Is(err, ErrSSOUser):
		reason = "sso_user"
	case errors.Is(err, ErrDirectoryUser):
		reason = "directory_user"
	default:
		return err
	}
	if aerr := s.adminFailure(ctx, p, m, action, id.String(), reason); aerr != nil {
		return aerr
	}
	return err
}

// adminChange runs fn for an existing user inside a transaction and audits action. It
// holds the user's row lock (the lock every credential check takes, see lockAccount), so
// a reset never interleaves with a login, MFA verification or step-up on that account:
// a password reset cannot be undone by a concurrent failure count, and an MFA reset
// cannot race a running enrollment. The audit row is appended last.
func (s *Service) adminChange(ctx context.Context, actor audit.Actor, id uuid.UUID, action string, details map[string]string, fn func(tx pgx.Tx) error) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var locked uuid.UUID
		err := tx.QueryRow(ctx, "SELECT id FROM users WHERE id = $1 FOR UPDATE", id).Scan(&locked)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock user: %w", err)
		}
		if err := fn(tx); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, ObjectType: "user", ObjectID: id.String(), Result: audit.Success, Details: details})
		return err
	})
}

func resetMFA(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	if err := refuseSSOUser(ctx, tx, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM user_mfa WHERE user_id = $1", id); err != nil {
		return fmt.Errorf("reset MFA: %w", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM recovery_codes WHERE user_id = $1", id); err != nil {
		return fmt.Errorf("reset MFA: %w", err)
	}
	return revokeUserSessions(ctx, tx, id)
}

// ResetMFA removes a user's TOTP and recovery codes; they enroll again at next login.
// An SSO user has no MFA here: ErrSSOUser. A directory user's TOTP is Alice's and is reset.
func (s *Service) ResetMFA(ctx context.Context, p Principal, m Meta, id uuid.UUID) error {
	err := s.adminChange(ctx, p.Actor(m), id, "user.mfa_reset", map[string]string{"via": "ui"}, func(tx pgx.Tx) error { return resetMFA(ctx, tx, id) })
	return s.auditSSORefusal(ctx, p, m, err, "user.mfa_reset", id)
}

// ResetMFAByUsername is the host-root CLI break-glass path (R18).
func (s *Service) ResetMFAByUsername(ctx context.Context, username string) error {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, "SELECT id FROM users WHERE username = $1", username).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read user: %w", err)
	}
	return s.adminChange(ctx, audit.SystemActor("cli"), id, "user.mfa_reset", map[string]string{"via": "cli"}, func(tx pgx.Tx) error { return resetMFA(ctx, tx, id) })
}

// UnlockByUsername is the host-root CLI path out of a login delay or lockout: it
// clears the failure count and the block so the next sign-in is checked normally.
// It changes nothing else; the counting rules of SEC-020 stay as they are.
func (s *Service) UnlockByUsername(ctx context.Context, username string) error {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, "SELECT id FROM users WHERE username = $1", username).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read user: %w", err)
	}
	details := map[string]string{"via": "cli"}
	return s.adminChange(ctx, audit.SystemActor("cli"), id, "user.unlocked", details, func(tx pgx.Tx) error {
		var failed int
		if err := tx.QueryRow(ctx, "SELECT failed_logins FROM users WHERE id = $1", id).Scan(&failed); err != nil {
			return fmt.Errorf("unlock user: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = $2 WHERE id = $1",
			id, s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("unlock user: %w", err)
		}
		details["failed_logins"] = strconv.Itoa(failed)
		return nil
	})
}

// ResetPassword sets a new password chosen by an administrator, clears the lockout, ends the
// user's sessions and revokes every API token of the user, all in one transaction (AUD-12, R39):
// it is the administrator's answer to a suspected takeover, and a token is another way in. A
// user changing their own password (ChangePassword) keeps their tokens. An SSO user has no
// password here (ErrSSOUser), nor has a directory user (ErrDirectoryUser).
func (s *Service) ResetPassword(ctx context.Context, p Principal, m Meta, id uuid.UUID, password string) error {
	if err := CheckPasswordPolicy(password); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(ctx, NormalizePassword(password))
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	actor := p.Actor(m)
	details := map[string]string{}
	err = s.adminChange(ctx, actor, id, "user.password_reset", details, func(tx pgx.Tx) error {
		if err := refuseNonLocalUser(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, password_changed_at = $3, updated_at = $3,
failed_logins = 0, locked_until = NULL WHERE id = $1`, id, hash, now); err != nil {
			return fmt.Errorf("reset password: %w", err)
		}
		return s.signOutEverywhere(ctx, tx, actor, id, now, "password_reset", details)
	})
	return s.auditSSORefusal(ctx, p, m, err, "user.password_reset", id)
}

// RevokeSessions signs a user out everywhere: it ends every session and revokes every API
// token of the user in one transaction (AUD-12, R39).
func (s *Service) RevokeSessions(ctx context.Context, p Principal, m Meta, id uuid.UUID) error {
	now := s.clock.Now().UTC()
	actor := p.Actor(m)
	details := map[string]string{}
	return s.adminChange(ctx, actor, id, "user.sessions_revoked", details, func(tx pgx.Tx) error {
		return s.signOutEverywhere(ctx, tx, actor, id, now, "sessions_revoked", details)
	})
}

// signOutEverywhere ends every session of a user and revokes every live API token, inside the
// caller's transaction (which holds the user's row lock, see adminChange). Token lookups read
// the database on every request, so the tokens are refused as soon as the transaction commits;
// a token creation or recovery-code regeneration waiting for the row lock re-checks its
// session afterwards and is refused (sessionLive).
func (s *Service) signOutEverywhere(ctx context.Context, tx pgx.Tx, actor audit.Actor, id uuid.UUID, now time.Time, reason string, details map[string]string) error {
	if err := revokeUserSessions(ctx, tx, id); err != nil {
		return err
	}
	return s.revokeUserTokens(ctx, tx, actor, id, now, reason, details)
}

// revokeUserTokens revokes every live API token of a user inside the caller's transaction,
// which holds the user's row lock. Each revoked token is audited as token.revoked by its ID
// with reason (password_reset, sessions_revoked or user_disabled), and details, the caller's
// own audit row, gets revoked_tokens_count (AUD-12). The audit rows come after every row
// update, so the chain lock is never held while waiting for a row.
func (s *Service) revokeUserTokens(ctx context.Context, tx pgx.Tx, actor audit.Actor, id uuid.UUID, now time.Time, reason string, details map[string]string) error {
	rows, err := tx.Query(ctx, "UPDATE api_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL RETURNING id", id, now)
	if err != nil {
		return fmt.Errorf("revoke tokens: %w", err)
	}
	tokens, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return fmt.Errorf("revoke tokens: %w", err)
	}
	slices.SortFunc(tokens, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	for _, tok := range tokens {
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "token.revoked", ObjectType: "api_token", ObjectID: tok.String(),
			Result: audit.Success, Details: map[string]string{"token_id": tok.String(), "owner_id": id.String(), "reason": reason}}); err != nil {
			return err
		}
	}
	details["revoked_tokens_count"] = strconv.Itoa(len(tokens))
	return nil
}
