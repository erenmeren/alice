package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// API token format (SEC-026).
const (
	TokenPrefix  = "alice_"
	MaxTokenDays = 365
	prefixLen    = 12 // "alice_" + 6 characters, shown in lists
)

// Token is the public view of a personal API token; the secret is never stored.
type Token struct {
	ID, UserID uuid.UUID
	Name       string
	Prefix     string
	Scope      rbac.Scope
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

// NewToken is the input of CreateToken.
type NewToken struct {
	Name          string
	Scope         rbac.Scope
	ExpiresInDays int
}

func tokenHash(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// CreateToken issues a token for the caller. The secret is returned once.
func (s *Service) CreateToken(ctx context.Context, p Principal, m Meta, in NewToken) (string, Token, error) {
	if p.Kind != rbac.UserSession {
		return "", Token{}, ErrUnauthenticated
	}
	var v validate.Errors
	switch {
	case strings.TrimSpace(in.Name) == "":
		v.Add("name", validate.Required, nil)
	case utf8.RuneCountInString(in.Name) > maxTokenName:
		v.Add("name", validate.TooLong, map[string]string{"max": strconv.Itoa(maxTokenName)})
	}
	if _, ok := rbac.ParseScope(string(in.Scope)); !ok {
		v.Add("scope", validate.OneOf, map[string]string{"values": "read, operate"})
	}
	if in.ExpiresInDays < 1 || in.ExpiresInDays > MaxTokenDays {
		v.Add("expires_in_days", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(MaxTokenDays)})
	}
	if err := v.Err(); err != nil {
		return "", Token{}, err
	}
	if !p.Role.AllowsScope(in.Scope) {
		return "", Token{}, ErrTokenScopeNotAllowed
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret := TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	now := s.clock.Now().UTC()
	t := Token{ID: uuid.Must(uuid.NewV7()), UserID: p.UserID, Name: in.Name, Prefix: secret[:prefixLen], Scope: in.Scope,
		ExpiresAt: now.Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour), CreatedAt: now}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// The principal's role may predate a role change or disabling; the scope is checked
		// against the owner's current row, held with FOR SHARE so UpdateUser (FOR UPDATE)
		// cannot change it before this transaction commits.
		var role string
		err := tx.QueryRow(ctx, "SELECT role FROM users WHERE id = $1 AND disabled_at IS NULL FOR SHARE", p.UserID).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnauthenticated
		}
		if err != nil {
			return fmt.Errorf("read token owner: %w", err)
		}
		if !rbac.Role(role).AllowsScope(in.Scope) {
			return ErrTokenScopeNotAllowed
		}
		if _, err := tx.Exec(ctx, `INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, t.ID, t.UserID, t.Name, tokenHash(secret), t.Prefix, []string{string(t.Scope)}, t.ExpiresAt, now); err != nil {
			return fmt.Errorf("create token: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "token.created", ObjectType: "api_token", ObjectID: t.ID.String(),
			Result: audit.Success, Details: map[string]string{"token_id": t.ID.String(), "scope": string(t.Scope)}})
		return err
	})
	if err != nil {
		return "", Token{}, err
	}
	return secret, t, nil
}

const tokenColumns = "id, user_id, name, token_prefix, scopes[1], expires_at, last_used_at, created_at" //nolint:gosec // G101: column list, not a credential

func scanToken(row pgx.Row) (Token, error) {
	var t Token
	var scope string
	if err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &scope, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
		return Token{}, err
	}
	t.Scope = rbac.Scope(scope)
	t.ExpiresAt, t.CreatedAt = t.ExpiresAt.UTC(), t.CreatedAt.UTC()
	if t.LastUsedAt != nil {
		u := t.LastUsedAt.UTC()
		t.LastUsedAt = &u
	}
	return t, nil
}

// ListTokens returns the non-revoked tokens of userID (uuid.Nil = the caller).
// Only administrators may list another user's tokens; others get ErrNotFound.
func (s *Service) ListTokens(ctx context.Context, p Principal, userID uuid.UUID) ([]Token, error) {
	if userID == uuid.Nil {
		userID = p.UserID
	}
	if userID != p.UserID && p.Role != rbac.Admin {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, "SELECT "+tokenColumns+" FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC", userID)
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

// RevokeToken revokes a token of the caller, or any token when the caller is an administrator.
func (s *Service) RevokeToken(ctx context.Context, p Principal, m Meta, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var owner uuid.UUID
		err := tx.QueryRow(ctx, "SELECT user_id FROM api_tokens WHERE id = $1 AND revoked_at IS NULL FOR UPDATE", id).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner != p.UserID && p.Role != rbac.Admin) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read token: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE api_tokens SET revoked_at = $2 WHERE id = $1", id, s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("revoke token: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "token.revoked", ObjectType: "api_token", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"token_id": id.String(), "owner_id": owner.String()}})
		return err
	})
}

// AuthenticateToken resolves "Authorization: Bearer alice_..." (SEC-025). The token's scope must
// still be allowed by the owner's current role.
func (s *Service) AuthenticateToken(ctx context.Context, bearer string) (Principal, error) {
	if !strings.HasPrefix(bearer, TokenPrefix) {
		return Principal{}, ErrUnauthenticated
	}
	now := s.clock.Now().UTC()
	var (
		p        Principal
		role     string
		scope    string
		expires  time.Time
		revoked  bool
		disabled bool
	)
	err := s.pool.QueryRow(ctx, `SELECT t.id, t.scopes[1], t.expires_at, t.revoked_at IS NOT NULL,
u.id, u.username::text, u.display_name, u.role, u.locale, u.disabled_at IS NOT NULL
FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = $1`, tokenHash(bearer)).Scan(
		&p.TokenID, &scope, &expires, &revoked, &p.UserID, &p.Username, &p.DisplayName, &role, &p.Locale, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, fmt.Errorf("read token: %w", err)
	}
	p.Kind, p.Role, p.Scope = rbac.APIToken, rbac.Role(role), rbac.Scope(scope)
	if revoked || disabled || !now.Before(expires) || !p.Role.AllowsScope(p.Scope) {
		return Principal{}, ErrUnauthenticated
	}
	if _, err := s.pool.Exec(ctx, "UPDATE api_tokens SET last_used_at = $2 WHERE id = $1", p.TokenID, now); err != nil {
		return Principal{}, fmt.Errorf("touch token: %w", err)
	}
	return p, nil
}
