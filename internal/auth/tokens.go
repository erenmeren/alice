package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
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
	// ServiceIDs limits the token to these services (design §6.3, R54; sorted); nil: the owner's whole reach.
	ServiceIDs []uuid.UUID
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

// NewToken is the input of CreateToken and CreateAutomationToken. ServiceIDs (1 to MaxTokenServices, optional)
// limits the token to those services.
type NewToken struct {
	Name          string
	Scope         rbac.Scope
	ExpiresInDays int
	ServiceIDs    []uuid.UUID
}

// MaxTokenServices bounds the services one token may be limited to (api_tokens.service_ids, migration 00026).
const MaxTokenServices = 50

// ErrTokenServiceNotAllowed: a token is limited to a service its owner holds no role on (or that does not exist).
var ErrTokenServiceNotAllowed = errors.New("auth: the token's owner holds no role on a service the token is limited to")

// validate checks a new token's fields (SEC-026) and returns its services sorted and without repeats (nil: no limit).
func (in NewToken) validate() ([]uuid.UUID, error) {
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
	var services []uuid.UUID
	if in.ServiceIDs != nil {
		services = slices.Clone(in.ServiceIDs)
		slices.SortFunc(services, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
		services = slices.Compact(services)
		switch {
		case len(services) == 0:
			v.Add("service_ids", validate.Required, nil)
		case len(services) > MaxTokenServices:
			v.Add("service_ids", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(MaxTokenServices)})
		case slices.Contains(services, uuid.Nil):
			v.Add("service_ids", validate.Pattern, nil)
		}
	}
	return services, v.Err()
}

// checkTokenServices refuses a limit naming a service the owner holds no role on now, or one that does not exist
// (ErrTokenServiceNotAllowed, design §6.3); the services are key-share locked so none is deleted before the token is
// stored. owner is the owner's current subject (its global role and scoped grants).
func checkTokenServices(ctx context.Context, tx pgx.Tx, owner rbac.Subject, services []uuid.UUID) error {
	if services == nil {
		return nil
	}
	rows, err := tx.Query(ctx, "SELECT id FROM services WHERE id = ANY($1) FOR KEY SHARE", services)
	if err != nil {
		return fmt.Errorf("read the token's services: %w", err)
	}
	found, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return fmt.Errorf("read the token's services: %w", err)
	}
	if len(found) != len(services) {
		return ErrTokenServiceNotAllowed
	}
	if _, global := rbac.ParseRole(string(owner.Role)); global {
		return nil
	}
	for _, sv := range services {
		held := false
		for _, g := range owner.Grants {
			if slices.Contains(g.Services, sv) {
				held = true
				break
			}
		}
		if !held {
			return ErrTokenServiceNotAllowed
		}
	}
	return nil
}

// insertToken stores a new token of owner inside the caller's transaction and audits token.created by actor (with
// details); it returns the secret, shown once.
func (s *Service) insertToken(ctx context.Context, tx pgx.Tx, actor audit.Actor, owner uuid.UUID, in NewToken, services []uuid.UUID,
	details map[string]string) (string, Token, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret := TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	now := s.clock.Now().UTC()
	t := Token{ID: uuid.Must(uuid.NewV7()), UserID: owner, Name: in.Name, Prefix: secret[:prefixLen], Scope: in.Scope, ServiceIDs: services,
		ExpiresAt: now.Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour), CreatedAt: now}
	if _, err := tx.Exec(ctx, `INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, service_ids, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, t.ID, t.UserID, t.Name, tokenHash(secret), t.Prefix, []string{string(t.Scope)}, services,
		t.ExpiresAt, now); err != nil {
		return "", Token{}, fmt.Errorf("create token: %w", err)
	}
	d := map[string]string{"token_id": t.ID.String(), "scope": string(t.Scope)}
	if services != nil {
		d["service_ids"] = joinIDs(services)
	}
	maps.Copy(d, details)
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "token.created", ObjectType: "api_token", ObjectID: t.ID.String(),
		Result: audit.Success, Details: d}); err != nil {
		return "", Token{}, err
	}
	return secret, t, nil
}

// joinIDs is a list of ids for an audit row's details.
func joinIDs(ids []uuid.UUID) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return strings.Join(out, ",")
}

func tokenHash(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// CreateToken issues a token for the caller. The secret is returned once. A single sign-on user
// gets none (ErrSSOUser): the identity provider owns that identity (SEC-015), and a token would
// outlive the user's de-provisioning there, which Alice learns of only at the next sign-in (I-2).
// A directory user gets none either, for the same reason (ErrDirectoryUser).
func (s *Service) CreateToken(ctx context.Context, p Principal, m Meta, in NewToken) (string, Token, error) {
	if p.Kind != rbac.UserSession {
		return "", Token{}, ErrUnauthenticated
	}
	if p.AuthSource != "" && p.AuthSource != AuthLocal {
		return "", Token{}, sourceRefusal(p.AuthSource)
	}
	services, err := in.validate()
	if err != nil {
		return "", Token{}, err
	}
	if !p.Subject(s.clock.Now()).AllowsScopeAnywhere(in.Scope) {
		return "", Token{}, ErrTokenScopeNotAllowed
	}
	var (
		secret string
		t      Token
	)
	now := s.clock.Now().UTC()
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// The principal's role may predate a role change or disabling; the scope is checked
		// against the owner's current row, held with FOR SHARE so UpdateUser (FOR UPDATE)
		// cannot change it before this transaction commits.
		var role, source string
		err := tx.QueryRow(ctx, "SELECT coalesce(role, ''), auth_source FROM users WHERE id = $1 AND disabled_at IS NULL FOR SHARE", p.UserID).Scan(&role, &source)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnauthenticated
		}
		if err != nil {
			return fmt.Errorf("read token owner: %w", err)
		}
		if source != AuthLocal {
			return sourceRefusal(source)
		}
		// The caller's session is checked again under the row lock: a sign-out-everywhere or
		// password reset that held the row (FOR UPDATE) and committed while this request waited
		// has ended it, and a token minted now would outlive it (AUD-12).
		live, err := sessionLive(ctx, tx, p, "full", now)
		if err != nil {
			return err
		}
		if !live {
			return ErrUnauthenticated
		}
		// The owner's current grants (the global role and its roles on services, R49 Phase 2) decide the scope.
		grants, err := authz.LoadGrants(ctx, tx, p.UserID)
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
		secret, t, err = s.insertToken(ctx, tx, p.Actor(m), p.UserID, in, services, nil)
		return err
	})
	if err != nil {
		return "", Token{}, err
	}
	return secret, t, nil
}

const tokenColumns = "id, user_id, name, token_prefix, scopes[1], service_ids, expires_at, last_used_at, created_at" //nolint:gosec // G101: column list, not a credential

func scanToken(row pgx.Row) (Token, error) {
	var t Token
	var scope string
	if err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &scope, &t.ServiceIDs, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
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
// Only administrators may list another user's tokens; others get ErrNotFound,
// and the attempt is audited as an authorization denial.
func (s *Service) ListTokens(ctx context.Context, p Principal, m Meta, userID uuid.UUID) ([]Token, error) {
	if userID == uuid.Nil {
		userID = p.UserID
	}
	if userID != p.UserID && p.Role != rbac.Admin {
		if err := s.auditNotOwner(ctx, p, m, "user", userID); err != nil {
			return nil, err
		}
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
// Another user's token answers ErrNotFound like a missing one, and the attempt is audited as
// an authorization denial.
func (s *Service) RevokeToken(ctx context.Context, p Principal, m Meta, id uuid.UUID) error {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var owner uuid.UUID
		err := tx.QueryRow(ctx, "SELECT user_id FROM api_tokens WHERE id = $1 AND revoked_at IS NULL FOR UPDATE", id).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err == nil && owner != p.UserID && p.Role != rbac.Admin {
			return errNotOwner
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
	if errors.Is(err, errNotOwner) {
		if aerr := s.auditNotOwner(ctx, p, m, "api_token", id); aerr != nil {
			return aerr
		}
		return ErrNotFound
	}
	return err
}

// errNotOwner is RevokeToken's internal signal for another user's token; callers see ErrNotFound.
var errNotOwner = errors.New("auth: token belongs to another user")

// notOwnerAuditTimeout bounds the denial row of auditNotOwner, which outlives its request (AUD-15).
const notOwnerAuditTimeout = 5 * time.Second

// auditNotOwner records a refused access to another user's object as an authorization denial
// (SEC-070). The caller still answers ErrNotFound, so the object's existence is not revealed. The
// row is written on a context the caller's cancellation does not end, for at most
// notOwnerAuditTimeout, so a client that disconnects still leaves it (AUD-15). The HTTP layer
// refuses another user's token list itself, coalesced (AUD-06); this row is for the revoke path and
// for callers other than the HTTP layer.
func (s *Service) auditNotOwner(ctx context.Context, p Principal, m Meta, objectType string, id uuid.UUID) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notOwnerAuditTimeout)
	defer cancel()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "authz.denied", ObjectType: objectType, ObjectID: id.String(),
			Result: audit.Denied, Details: map[string]string{"reason": "not_owner"}})
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
	err := s.pool.QueryRow(ctx, `SELECT t.id, t.scopes[1], t.service_ids, t.expires_at, t.revoked_at IS NOT NULL,
u.id, u.username::text, u.display_name, coalesce(u.role, ''), u.locale, u.disabled_at IS NOT NULL
FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = $1`, tokenHash(bearer)).Scan(
		&p.TokenID, &scope, &p.TokenServices, &expires, &revoked, &p.UserID, &p.Username, &p.DisplayName, &role, &p.Locale, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, fmt.Errorf("read token: %w", err)
	}
	p.Kind, p.Role, p.Scope = rbac.APIToken, rbac.Role(role), rbac.Scope(scope)
	if revoked || disabled || !now.Before(expires) {
		return Principal{}, ErrUnauthenticated
	}
	// The owner's roles on services count as its global role does (R49 Phase 2): the token is valid while some grant of
	// the owner still allows its scope, and acts with the owner's grants as they are now (design §6.3).
	if p.Grants, err = authz.LoadGrants(ctx, s.pool, p.UserID); err != nil {
		return Principal{}, err
	}
	if p.TokenServices != nil {
		// A token limited to services (design §6.3, R54): the owner's grants now, only on those services. The global
		// role becomes a grant on them, so no platform route passes, whoever the owner is.
		sub := rbac.Subject{Role: p.Role, Grants: p.Grants}.Within(p.TokenServices)
		p.Role, p.Grants = sub.Role, sub.Grants
	}
	if !p.Subject(now).AllowsScopeAnywhere(p.Scope) {
		return Principal{}, ErrUnauthenticated
	}
	// Last use is recorded at minute granularity so a busy token does not write on every request.
	if _, err := s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = $2
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < $2::timestamptz - interval '1 minute')`, p.TokenID, now); err != nil {
		return Principal{}, fmt.Errorf("touch token: %w", err)
	}
	return p, nil
}
