package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/rbac"
)

// BootstrapAdmin is the first administrator created by the setup wizard.
type BootstrapAdmin struct {
	Username, DisplayName, Email string
	PasswordHash                 string // already hashed with Hasher
	TOTPSecret                   string
	Code                         string
	Locale                       string
}

// BootstrapAdmin creates the first (break-glass) administrator with enrolled TOTP and
// recovery codes and signs them in. inTx runs in the same transaction (setup uses it to
// delete the setup code), before the audit row is appended; it must not append audit
// events itself, because setup.admin_created is the first chain link.
func (s *Service) BootstrapAdmin(ctx context.Context, in BootstrapAdmin, m Meta, inTx func(tx pgx.Tx) error) (SessionResult, error) {
	step, ok := VerifyTOTP(in.TOTPSecret, in.Code, s.clock.Now(), 0)
	if !ok {
		return SessionResult{}, ErrMFAInvalid
	}
	codes := GenerateRecoveryCodes()
	hashes, err := s.hashRecoveryCodes(ctx, codes)
	if err != nil {
		return SessionResult{}, err
	}
	locale := in.Locale
	if locale == "" {
		locale = "en"
	}
	id := uuid.Must(uuid.NewV7())
	env, err := s.keyring.Seal(totpLocation(id), []byte(in.TOTPSecret))
	if err != nil {
		return SessionResult{}, err
	}
	now := s.clock.Now().UTC()
	var token string
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "LOCK TABLE users IN EXCLUSIVE MODE"); err != nil {
			return fmt.Errorf("lock users: %w", err)
		}
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users)").Scan(&exists); err != nil {
			return fmt.Errorf("check users: %w", err)
		}
		if exists {
			return ErrAdminExists
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, username, email, display_name, auth_source, password_hash, role, locale,
is_break_glass, password_changed_at, last_login_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'local', $5, $6, $7, true, $8, $8, $8, $8)`,
			id, in.Username, in.Email, in.DisplayName, in.PasswordHash, string(rbac.Admin), locale, now); err != nil {
			return fmt.Errorf("create administrator: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_mfa (user_id, totp_secret_ct, totp_nonce, totp_wrapped_dek, totp_key_version, enrolled_at, last_used_step, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $6)`, id, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, now, step); err != nil {
			return fmt.Errorf("store TOTP secret: %w", err)
		}
		if err := s.replaceRecoveryCodes(ctx, tx, id, hashes); err != nil {
			return err
		}
		var err error
		if token, err = s.startFullSession(ctx, tx, id, m); err != nil {
			return err
		}
		if inTx != nil {
			if err := inTx(tx); err != nil {
				return err
			}
		}
		// The audit row goes last, after every row lock of this transaction.
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: userActor(id, in.Username, m), Action: "setup.admin_created",
			ObjectType: "user", ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"username": in.Username}})
		return err
	})
	if err != nil {
		return SessionResult{}, err
	}
	return s.resultFor(ctx, id, token, codes)
}
