package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// AuthAutomation is the source of an automation account (R49 Phase 3, R54; design §6.2): a non-person that never signs
// in and only holds API tokens, which a global Administrator makes on its page.
const AuthAutomation = "automation"

// Errors of the automation accounts.
var (
	// ErrAutomationAdmin: an automation account never holds the global Administrator role (design §6.2, Q8; the CHECK of
	// migration 00026 holds it too). A role binding as Administrator on a service is allowed.
	ErrAutomationAdmin = errors.New("auth: an automation account cannot be a global Administrator")
	// ErrAutomationAccount: a change only a person can have (a password, a manual role through People & access, MFA,
	// a personal token) asked of an automation account; its own routes change it.
	ErrAutomationAccount = errors.New("auth: this change is not possible for an automation account")
	// ErrAutomationDisabled: a token asked for a disabled automation account.
	ErrAutomationDisabled = errors.New("auth: the automation account is disabled")
)

// maxDescription bounds an automation account's description (users.description, migration 00026).
const maxDescription = 500

// AutomationAccount is an automation account as its page shows it: who it is, its global role (NoGlobalRole for
// none), whether it is disabled, and how many live tokens it holds with the last time one was used.
type AutomationAccount struct {
	ID          uuid.UUID
	Username    string
	DisplayName string
	Description string
	Role        rbac.Role
	Disabled    bool
	Tokens      int
	LastUsedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewAutomationAccount is the input of CreateAutomationAccount. Role is NoGlobalRole, Operator or Auditor.
type NewAutomationAccount struct {
	Username, DisplayName, Description string
	Role                               rbac.Role
}

// AutomationUpdate changes selected fields of an automation account; nil fields stay unchanged.
type AutomationUpdate struct {
	DisplayName *string
	Description *string
	Role        *rbac.Role
	Disabled    *bool
}

const automationColumns = `u.id, u.username::text, u.display_name, u.description, coalesce(u.role, ''), u.disabled_at IS NOT NULL,
(SELECT count(*) FROM api_tokens t WHERE t.user_id = u.id AND t.revoked_at IS NULL AND t.expires_at > now()),
(SELECT max(t.last_used_at) FROM api_tokens t WHERE t.user_id = u.id), u.created_at, u.updated_at`

func scanAutomation(row pgx.Row) (AutomationAccount, error) {
	var a AutomationAccount
	var role string
	err := row.Scan(&a.ID, &a.Username, &a.DisplayName, &a.Description, &role, &a.Disabled, &a.Tokens, &a.LastUsedAt, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AutomationAccount{}, ErrNotFound
	}
	if err != nil {
		return AutomationAccount{}, fmt.Errorf("read automation account: %w", err)
	}
	a.Role = rbac.Role(role)
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	if a.LastUsedAt != nil {
		t := a.LastUsedAt.UTC()
		a.LastUsedAt = &t
	}
	return a, nil
}

// validateAutomationRole admits no global role, Operator and Auditor; Administrator is ErrAutomationAdmin.
func validateAutomationRole(v *validate.Errors, r rbac.Role) error {
	if r == rbac.Admin {
		return ErrAutomationAdmin
	}
	validateRole(v, r)
	return nil
}

func validateDescription(v *validate.Errors, d string) {
	switch {
	case !validate.StorableText(d):
		v.Add("description", validate.Pattern, nil)
	case utf8.RuneCountInString(d) > maxDescription:
		v.Add("description", validate.TooLong, map[string]string{"max": strconv.Itoa(maxDescription)})
	}
}

// ListAutomationAccounts lists every automation account by user name. People are not in it (ListUsers lists them).
func (s *Service) ListAutomationAccounts(ctx context.Context) ([]AutomationAccount, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+automationColumns+" FROM users u WHERE u.auth_source = 'automation' ORDER BY u.username")
	if err != nil {
		return nil, fmt.Errorf("list automation accounts: %w", err)
	}
	defer rows.Close()
	out := []AutomationAccount{}
	for rows.Next() {
		a, err := scanAutomation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list automation accounts: %w", err)
	}
	return out, nil
}

// GetAutomationAccount reads one automation account; a person or an unknown id is ErrNotFound.
func (s *Service) GetAutomationAccount(ctx context.Context, id uuid.UUID) (AutomationAccount, error) {
	return getAutomation(ctx, s.pool, id)
}

func getAutomation(ctx context.Context, q db.Querier, id uuid.UUID) (AutomationAccount, error) {
	return scanAutomation(q.QueryRow(ctx, "SELECT "+automationColumns+" FROM users u WHERE u.id = $1 AND u.auth_source = 'automation'", id))
}

// CreateAutomationAccount adds an automation account (design §6.2): a user name under the user name rule (one name space
// with people: the name stays taken for good, an account is never deleted), a display name, a description and a global
// role of none, Operator or Auditor (ErrAutomationAdmin for Administrator). It has no password, no e-mail address and no
// MFA, and never signs in. Audit automation.created. ErrUsernameTaken.
func (s *Service) CreateAutomationAccount(ctx context.Context, p Principal, m Meta, in NewAutomationAccount) (AutomationAccount, error) {
	v := ValidateProfile(in.Username, in.DisplayName, "")
	validateDescription(&v, in.Description)
	if err := validateAutomationRole(&v, in.Role); err != nil {
		return AutomationAccount{}, err
	}
	if err := v.Err(); err != nil {
		return AutomationAccount{}, err
	}
	id := uuid.Must(uuid.NewV7())
	now := s.clock.Now().UTC()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, username, display_name, description, auth_source, password_hash, role, role_source,
created_at, updated_at) VALUES ($1, $2, $3, $4, 'automation', NULL, $5, 'manual', $6, $6)`,
			id, in.Username, in.DisplayName, in.Description, roleParam(in.Role), now); err != nil {
			if db.IsUniqueViolationOn(err, UsernameConstraint) {
				return ErrUsernameTaken
			}
			return fmt.Errorf("create automation account: %w", err)
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "automation.created", ObjectType: "user", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"username": in.Username, "role": roleLabel(in.Role)}})
		return err
	})
	if errors.Is(err, ErrUsernameTaken) {
		if aerr := s.adminFailure(ctx, p, m, "automation.created", "", "username_taken"); aerr != nil {
			return AutomationAccount{}, aerr
		}
		return AutomationAccount{}, ErrUsernameTaken
	}
	if err != nil {
		return AutomationAccount{}, err
	}
	return getAutomation(ctx, s.pool, id)
}

// UpdateAutomationAccount changes an automation account's display name, description, global role (none, Operator or
// Auditor) or enabled state. Disabling revokes every token of the account for good (as for a person, SEC-019, R39 item
// 5); enabling it again brings none back. Audit automation.updated with what changed. A person's id is ErrNotFound.
func (s *Service) UpdateAutomationAccount(ctx context.Context, p Principal, m Meta, id uuid.UUID, in AutomationUpdate) (AutomationAccount, error) {
	var v validate.Errors
	if in.DisplayName != nil {
		validateDisplayName(&v, *in.DisplayName)
	}
	if in.Description != nil {
		validateDescription(&v, *in.Description)
	}
	if in.Role != nil {
		if err := validateAutomationRole(&v, *in.Role); err != nil {
			return AutomationAccount{}, err
		}
	}
	if err := v.Err(); err != nil {
		return AutomationAccount{}, err
	}
	now := s.clock.Now().UTC()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := scanAutomation(tx.QueryRow(ctx, "SELECT "+automationColumns+" FROM users u WHERE u.id = $1 AND u.auth_source = 'automation' FOR UPDATE OF u", id))
		if err != nil {
			return err
		}
		details := map[string]string{}
		if in.DisplayName != nil && *in.DisplayName != cur.DisplayName {
			details["display_name"] = "changed"
			if _, err := tx.Exec(ctx, "UPDATE users SET display_name = $2 WHERE id = $1", id, *in.DisplayName); err != nil {
				return fmt.Errorf("update automation account: %w", err)
			}
		}
		if in.Description != nil && *in.Description != cur.Description {
			details["description"] = "changed"
			if _, err := tx.Exec(ctx, "UPDATE users SET description = $2 WHERE id = $1", id, *in.Description); err != nil {
				return fmt.Errorf("update automation account: %w", err)
			}
		}
		if in.Role != nil && *in.Role != cur.Role {
			details["role_from"], details["role_to"] = roleLabel(cur.Role), roleLabel(*in.Role)
			if _, err := tx.Exec(ctx, "UPDATE users SET role = $2 WHERE id = $1", id, roleParam(*in.Role)); err != nil {
				return fmt.Errorf("update automation account: %w", err)
			}
		}
		disable := in.Disabled != nil && *in.Disabled && !cur.Disabled
		if in.Disabled != nil && *in.Disabled != cur.Disabled {
			details["disabled"] = strconv.FormatBool(*in.Disabled)
			var at any
			if *in.Disabled {
				at = now
			}
			if _, err := tx.Exec(ctx, "UPDATE users SET disabled_at = $2 WHERE id = $1", id, at); err != nil {
				return fmt.Errorf("update automation account: %w", err)
			}
		}
		if len(details) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET updated_at = $2 WHERE id = $1", id, now); err != nil {
			return fmt.Errorf("update automation account: %w", err)
		}
		if disable {
			if err := s.revokeUserTokens(ctx, tx, p.Actor(m), id, now, "user_disabled", details); err != nil {
				return err
			}
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "automation.updated", ObjectType: "user", ObjectID: id.String(),
			Result: audit.Success, Details: details})
		return err
	})
	if err != nil {
		return AutomationAccount{}, err
	}
	return getAutomation(ctx, s.pool, id)
}

// CreateAutomationToken issues a token for an automation account (design §6.2, §6.3): a global Administrator's act
// (the API asks access.manage with step-up); the secret is returned once. The rules of SEC-026 hold (name, scope, at
// most MaxTokenDays), the account's grants now must allow the scope somewhere (ErrTokenScopeNotAllowed) and must hold
// every service the token is limited to (ErrTokenServiceNotAllowed). The audit row token.created names the
// Administrator as the actor and the account (account_id, account). A disabled account is ErrAutomationDisabled, a
// person's id ErrNotFound.
func (s *Service) CreateAutomationToken(ctx context.Context, p Principal, m Meta, accountID uuid.UUID, in NewToken) (string, Token, error) {
	if p.Kind != rbac.UserSession {
		return "", Token{}, ErrUnauthenticated
	}
	services, err := in.validate()
	if err != nil {
		return "", Token{}, err
	}
	var (
		secret string
		t      Token
	)
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// The account's row FOR SHARE: a disabling (FOR UPDATE, which revokes its tokens) waits for this token or runs
		// first and refuses it.
		var (
			username, role string
			disabled       bool
		)
		err := tx.QueryRow(ctx, `SELECT username::text, coalesce(role, ''), disabled_at IS NOT NULL FROM users
WHERE id = $1 AND auth_source = 'automation' FOR SHARE`, accountID).Scan(&username, &role, &disabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read automation account: %w", err)
		}
		if disabled {
			return ErrAutomationDisabled
		}
		grants, err := authz.LoadGrants(ctx, tx, accountID)
		if err != nil {
			return err
		}
		owner := rbac.Subject{Role: rbac.Role(role), Grants: grants}
		if !owner.AllowsScopeAnywhere(in.Scope) {
			return ErrTokenScopeNotAllowed
		}
		if err := checkTokenServices(ctx, tx, owner, services); err != nil {
			return err
		}
		secret, t, err = s.insertToken(ctx, tx, p.Actor(m), accountID, in, services,
			map[string]string{"account_id": accountID.String(), "account": username})
		return err
	})
	if err != nil {
		return "", Token{}, err
	}
	return secret, t, nil
}

// ListAutomationTokens lists the live tokens of an automation account, newest first; a person's id is ErrNotFound.
func (s *Service) ListAutomationTokens(ctx context.Context, accountID uuid.UUID) ([]Token, error) {
	if _, err := getAutomation(ctx, s.pool, accountID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, "SELECT "+tokenColumns+" FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC", accountID)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("list tokens: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	return out, nil
}

// RevokeAutomationToken revokes a live token of an automation account; audit token.revoked by the Administrator. A
// token of another account (or person), a revoked one or an unknown one is ErrNotFound.
func (s *Service) RevokeAutomationToken(ctx context.Context, p Principal, m Meta, accountID, tokenID uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var one int
		err := tx.QueryRow(ctx, `SELECT 1 FROM api_tokens t JOIN users u ON u.id = t.user_id
WHERE t.id = $1 AND t.user_id = $2 AND u.auth_source = 'automation' AND t.revoked_at IS NULL FOR UPDATE OF t`, tokenID, accountID).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read token: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE api_tokens SET revoked_at = $2 WHERE id = $1", tokenID, s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("revoke token: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "token.revoked", ObjectType: "api_token", ObjectID: tokenID.String(),
			Result: audit.Success, Details: map[string]string{"token_id": tokenID.String(), "owner_id": accountID.String()}})
		return err
	})
}
