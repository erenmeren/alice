package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/rbac"
)

// newSessionToken returns a 256-bit random cookie value (SEC-018).
func newSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken is the value stored in sessions.id_hash; the raw token is never stored.
func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// newSession describes a session row to insert.
type newSession struct {
	userID    uuid.UUID
	kind      string // "pending" | "full"
	createdAt time.Time
	expiresAt time.Time
	stepUp    *time.Time
}

// insertSession stores a session and returns its cookie value.
func (s *Service) insertSession(ctx context.Context, q db.Querier, ns newSession, m Meta) (string, error) {
	now := s.clock.Now().UTC()
	token := newSessionToken()
	idle := now.Add(SessionIdle)
	if ns.kind == "pending" || idle.After(ns.expiresAt) {
		idle = ns.expiresAt
	}
	var mfaAt *time.Time
	if ns.kind == "full" {
		mfaAt = &now
	}
	_, err := q.Exec(ctx, `INSERT INTO sessions (id_hash, user_id, kind, created_at, last_seen_at, expires_at, idle_expires_at, ip, user_agent, mfa_verified_at, stepup_until)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9, $10, $11)`,
		hashToken(token), ns.userID, ns.kind, ns.createdAt, now, ns.expiresAt, idle, ipParam(m.IP), truncateUA(m.UserAgent), mfaAt, ns.stepUp)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

// startFullSession creates a new full session with a fresh absolute lifetime and an open step-up window.
func (s *Service) startFullSession(ctx context.Context, q db.Querier, userID uuid.UUID, m Meta) (string, error) {
	now := s.clock.Now().UTC()
	stepUp := now.Add(StepUpWindow)
	return s.insertSession(ctx, q, newSession{userID: userID, kind: "full", createdAt: now, expiresAt: now.Add(SessionAbsolute), stepUp: &stepUp}, m)
}

// rotateSession replaces a full session by a new ID, keeping its absolute expiry (fixation defence, SEC-019).
func (s *Service) rotateSession(ctx context.Context, tx pgx.Tx, oldHash []byte, userID uuid.UUID, stepUp *time.Time, m Meta) (string, error) {
	var createdAt, expiresAt time.Time
	err := tx.QueryRow(ctx, "DELETE FROM sessions WHERE id_hash = $1 AND user_id = $2 RETURNING created_at, expires_at", oldHash, userID).Scan(&createdAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUnauthenticated
	}
	if err != nil {
		return "", fmt.Errorf("rotate session: %w", err)
	}
	return s.insertSession(ctx, tx, newSession{userID: userID, kind: "full", createdAt: createdAt.UTC(), expiresAt: expiresAt.UTC(), stepUp: stepUp}, m)
}

// Authenticate resolves a session cookie. Role and disabled state are read from users on
// every call (SEC-017). Full sessions slide their idle timeout; pending sessions do not.
func (s *Service) Authenticate(ctx context.Context, sessionToken string) (Principal, error) {
	if sessionToken == "" {
		return Principal{}, ErrUnauthenticated
	}
	now := s.clock.Now().UTC()
	h := hashToken(sessionToken)
	var (
		p                 Principal
		kind, role        string
		expires, idle     time.Time
		stepUp            *time.Time
		revoked, disabled bool
	)
	err := s.pool.QueryRow(ctx, `SELECT s.kind, s.expires_at, s.idle_expires_at, s.stepup_until, s.revoked_at IS NOT NULL,
u.id, u.username::text, u.display_name, u.role, u.locale, u.disabled_at IS NOT NULL
FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = $1`, h).Scan(
		&kind, &expires, &idle, &stepUp, &revoked, &p.UserID, &p.Username, &p.DisplayName, &role, &p.Locale, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, fmt.Errorf("read session: %w", err)
	}
	if revoked || disabled || !now.Before(expires) || !now.Before(idle) {
		return Principal{}, ErrUnauthenticated
	}
	p.Role = rbac.Role(role)
	p.SessionHash = h
	if stepUp != nil {
		p.StepUpUntil = stepUp.UTC()
	}
	p.Kind = rbac.PendingSession
	if kind == "full" {
		p.Kind = rbac.UserSession
		newIdle := now.Add(SessionIdle)
		if newIdle.After(expires) {
			newIdle = expires
		}
		if _, err := s.pool.Exec(ctx, "UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE id_hash = $1", h, now, newIdle); err != nil {
			return Principal{}, fmt.Errorf("touch session: %w", err)
		}
	}
	return p, nil
}

// SessionInfo returns the caller's session details and CSRF token.
func (s *Service) SessionInfo(ctx context.Context, p Principal, sessionToken string) (SessionInfo, error) {
	if p.Kind != rbac.UserSession {
		return SessionInfo{}, ErrUnauthenticated
	}
	var info SessionInfo
	var stepUp *time.Time
	err := s.pool.QueryRow(ctx, "SELECT expires_at, idle_expires_at, stepup_until FROM sessions WHERE id_hash = $1 AND user_id = $2",
		p.SessionHash, p.UserID).Scan(&info.ExpiresAt, &info.IdleExpiresAt, &stepUp)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionInfo{}, ErrUnauthenticated
	}
	if err != nil {
		return SessionInfo{}, fmt.Errorf("read session: %w", err)
	}
	u, err := getUser(ctx, s.pool, p.UserID)
	if err != nil {
		return SessionInfo{}, err
	}
	info.User = u
	info.CSRFToken = s.CSRFToken(sessionToken)
	info.ExpiresAt = info.ExpiresAt.UTC()
	info.IdleExpiresAt = info.IdleExpiresAt.UTC()
	if stepUp != nil && s.clock.Now().Before(*stepUp) {
		t := stepUp.UTC()
		info.StepUpUntil = &t
	}
	return info, nil
}

// resultFor builds a SessionResult for a freshly issued session token.
func (s *Service) resultFor(ctx context.Context, userID uuid.UUID, token string, codes []string) (SessionResult, error) {
	p, err := s.Authenticate(ctx, token)
	if err != nil {
		return SessionResult{}, err
	}
	info, err := s.SessionInfo(ctx, Principal{Kind: rbac.UserSession, UserID: userID, SessionHash: p.SessionHash}, token)
	if err != nil {
		return SessionResult{}, err
	}
	return SessionResult{Token: token, Info: info, RecoveryCodes: codes}, nil
}

// CSRFToken is HMAC-SHA256(K_csrf, session token), base64url (SEC-024).
func (s *Service) CSRFToken(sessionToken string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	mac.Write([]byte(sessionToken))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// CheckCSRF compares the header with the expected token in constant time.
func (s *Service) CheckCSRF(sessionToken, header string) bool {
	if sessionToken == "" || header == "" {
		return false
	}
	return hmac.Equal([]byte(s.CSRFToken(sessionToken)), []byte(header))
}

// Logout deletes the caller's session.
func (s *Service) Logout(ctx context.Context, p Principal, m Meta) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM sessions WHERE id_hash = $1", p.SessionHash); err != nil {
			return fmt.Errorf("delete session: %w", err)
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "auth.logout", ObjectType: "user", ObjectID: p.UserID.String(), Result: audit.Success})
		return err
	})
}

// revokeUserSessions deletes every session of a user.
func revokeUserSessions(ctx context.Context, q db.Querier, userID uuid.UUID) error {
	if _, err := q.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}
