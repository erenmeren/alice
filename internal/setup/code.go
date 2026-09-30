package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"alice/internal/auth"
	"alice/internal/auth/ratelimit"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// newCode returns 24 Crockford base32 characters (120 bits) as "XXXXXX-XXXXXX-XXXXXX-XXXXXX".
func newCode() string {
	b := make([]byte, 15)
	_, _ = rand.Read(b)
	s := crockford.EncodeToString(b)
	return strings.Join([]string{s[0:6], s[6:12], s[12:18], s[18:24]}, "-")
}

// hashCode normalizes like recovery codes (dashes, spaces, case, O/0, I/L/1 do not matter).
func hashCode(code string) string {
	h := sha256.Sum256([]byte(auth.NormalizeRecoveryCode(code)))
	return hex.EncodeToString(h[:])
}

// hashSessionToken is the setup_sessions primary key.
func hashSessionToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func newSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}

// ResetToken creates a new setup code (host-root CLI) and invalidates wizard sessions.
// It only works while no administrator exists.
func (s *Service) ResetToken(ctx context.Context) (string, error) {
	code := newCode()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// SHARE conflicts with BootstrapAdmin's EXCLUSIVE lock, so a reset racing the admin
		// creation either sees the administrator or finishes before it (and its hash is deleted).
		if _, err := tx.Exec(ctx, "LOCK TABLE users IN SHARE MODE"); err != nil {
			return fmt.Errorf("lock users: %w", err)
		}
		exists, err := adminExists(ctx, tx)
		if err != nil {
			return err
		}
		if exists {
			return ErrAlreadySetUp
		}
		if _, err := tx.Exec(ctx, "DELETE FROM setup_sessions"); err != nil {
			return fmt.Errorf("clear setup sessions: %w", err)
		}
		return settings.Set(ctx, tx, keyTokenHash, hashCode(code), s.clock.Now().UTC())
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// StartSession checks the setup code and opens a wizard session. Five wrong codes from
// one address (IPv6: one /64) lock that address for 15 minutes.
func (s *Service) StartSession(ctx context.Context, code string, m auth.Meta) (string, error) {
	exists, err := adminExists(ctx, s.pool)
	if err != nil {
		return "", err
	}
	if exists {
		return "", ErrAlreadySetUp
	}
	key := ratelimit.IPKey(m.IP)
	if locked, wait := s.lockout.Locked(key); locked {
		return "", &LockedError{RetryAfter: wait}
	}
	var stored string
	found, err := settings.Get(ctx, s.pool, keyTokenHash, &stored)
	if err != nil {
		return "", err
	}
	if err := s.checkCode(key, found, stored, code); err != nil {
		return "", err
	}
	token := newSessionToken()
	now := s.clock.Now().UTC()
	if _, err := s.pool.Exec(ctx, "INSERT INTO setup_sessions (id_hash, created_at, idle_expires_at) VALUES ($1, $2, $3)",
		hashSessionToken(token), now, now.Add(SessionIdle)); err != nil {
		return "", fmt.Errorf("create setup session: %w", err)
	}
	return token, nil
}

// checkCode compares code with the stored hash in constant time and counts a failure
// against key. The lock check, comparison and count happen under one mutex.
func (s *Service) checkCode(key string, found bool, stored, code string) error {
	s.codeMu.Lock()
	defer s.codeMu.Unlock()
	if locked, wait := s.lockout.Locked(key); locked {
		return &LockedError{RetryAfter: wait}
	}
	if !found || subtle.ConstantTimeCompare([]byte(stored), []byte(hashCode(code))) != 1 {
		s.lockout.Fail(key)
		return ErrCodeInvalid
	}
	s.lockout.Succeed(key)
	return nil
}

// Authenticate validates a wizard session and slides its 60-minute idle timeout.
func (s *Service) Authenticate(ctx context.Context, token string) error {
	if token == "" {
		return ErrSessionInvalid
	}
	now := s.clock.Now().UTC()
	tag, err := s.pool.Exec(ctx, `UPDATE setup_sessions SET idle_expires_at = $2
WHERE id_hash = $1 AND idle_expires_at > $3 AND NOT EXISTS (SELECT 1 FROM users)`, hashSessionToken(token), now.Add(SessionIdle), now)
	if err != nil {
		return fmt.Errorf("check setup session: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrSessionInvalid
	}
	return nil
}

// SetLanguage stores the default UI language chosen in the wizard.
func (s *Service) SetLanguage(ctx context.Context, token, language string) error {
	if err := s.Authenticate(ctx, token); err != nil {
		return err
	}
	if !slices.Contains(auth.SupportedLocales, language) {
		var v validate.Errors
		v.Add("language", validate.OneOf, map[string]string{"values": strings.Join(auth.SupportedLocales, ", ")})
		return v
	}
	return settings.Set(ctx, s.pool, keyLocale, language, s.clock.Now().UTC())
}
