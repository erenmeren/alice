package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// SupportedLocales are the UI languages a user may choose.
var SupportedLocales = []string{"en", "tr"}

// ChangePassword verifies the current password, applies the policy to the new one,
// revokes every session of the user and returns a new full session (SEC-019).
//
// A wrong current password counts toward the account's delay and lockout exactly like a
// failed login, on the same row-locked path (see lockAccount); while the account is
// delayed or locked the current password is not checked.
func (s *Service) ChangePassword(ctx context.Context, p Principal, current, next string, m Meta) (SessionResult, error) {
	if p.Kind != rbac.UserSession {
		return SessionResult{}, ErrUnauthenticated
	}
	if err := CheckPasswordPolicy(next); err != nil {
		return SessionResult{}, err
	}
	actor := p.Actor(m)
	cur := NormalizePassword(current)
	var (
		token  string
		failed bool
	)
	err := s.withCredentialSlot(ctx, func() error {
		return s.credentialTx(ctx, func(tx pgx.Tx) error {
			a, err := lockAccountByID(ctx, tx, p.UserID)
			if err != nil {
				return err
			}
			if a.hash == nil {
				return ErrUnauthenticated
			}
			now := s.clock.Now().UTC()
			if a.blocked(now) {
				// The dummy check runs under the account lock, where the real check runs (AUD-11).
				failed = true
				s.hasher.DummyVerify(ctx, cur)
				return s.auditFailure(ctx, tx, actor, "auth.password_changed", p.UserID.String(), "locked")
			}
			ok, _, err := s.hasher.Verify(ctx, *a.hash, cur)
			if err != nil {
				return err
			}
			if !ok {
				failed = true
				return s.recordFailure(ctx, tx, actor, p.UserID, "auth.password_changed", "current_password_invalid")
			}
			newHash, err := s.hasher.Hash(ctx, NormalizePassword(next))
			if err != nil {
				return err
			}
			var createdAt, expiresAt time.Time
			err = tx.QueryRow(ctx, "SELECT created_at, expires_at FROM sessions WHERE id_hash = $1 AND user_id = $2", p.SessionHash, p.UserID).Scan(&createdAt, &expiresAt)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUnauthenticated
			}
			if err != nil {
				return fmt.Errorf("read session: %w", err)
			}
			if _, err := tx.Exec(ctx, "UPDATE users SET password_hash = $2, password_changed_at = $3, updated_at = $3 WHERE id = $1", p.UserID, newHash, now); err != nil {
				return fmt.Errorf("update password: %w", err)
			}
			if err := revokeUserSessions(ctx, tx, p.UserID); err != nil {
				return err
			}
			token, err = s.insertSession(ctx, tx, newSession{userID: p.UserID, kind: "full", createdAt: createdAt.UTC(), expiresAt: expiresAt.UTC()}, m)
			if err != nil {
				return err
			}
			_, err = s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "auth.password_changed", ObjectType: "user", ObjectID: p.UserID.String(), Result: audit.Success})
			return err
		})
	})
	if err != nil {
		return SessionResult{}, err
	}
	if failed {
		return SessionResult{}, ErrCurrentPasswordInvalid
	}
	return s.resultFor(ctx, p.UserID, token, nil)
}

// SetLocale stores the caller's preferred UI language.
func (s *Service) SetLocale(ctx context.Context, p Principal, locale string) error {
	if p.Kind != rbac.UserSession {
		return ErrUnauthenticated
	}
	supported := false
	for _, l := range SupportedLocales {
		supported = supported || l == locale
	}
	if !supported {
		var v validate.Errors
		v.Add("locale", validate.OneOf, map[string]string{"values": "en, tr"})
		return v
	}
	if _, err := s.pool.Exec(ctx, "UPDATE users SET locale = $2, updated_at = $3 WHERE id = $1", p.UserID, locale, s.clock.Now().UTC()); err != nil {
		return fmt.Errorf("update locale: %w", err)
	}
	return nil
}
