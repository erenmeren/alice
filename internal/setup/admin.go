package setup

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"alice/internal/auth"
	"alice/internal/platform/settings"
	"alice/internal/secrets"
)

// AdminInput is the administrator form of wizard step 2.
type AdminInput struct{ Username, DisplayName, Email, Password string }

func pendingLocation(idHash []byte) secrets.Location {
	return secrets.Location{Table: "setup_sessions", RowID: hex.EncodeToString(idHash), Column: "totp_secret"}
}

// BeginAdminEnrollment validates the administrator form, hashes the password and creates a
// TOTP secret that is kept (encrypted) with the wizard session until CreateAdmin.
func (s *Service) BeginAdminEnrollment(ctx context.Context, token string, in AdminInput) (auth.TOTPEnrollment, error) {
	if err := s.Authenticate(ctx, token); err != nil {
		return auth.TOTPEnrollment{}, err
	}
	if err := auth.ValidateProfile(in.Username, in.DisplayName, in.Email).Err(); err != nil {
		return auth.TOTPEnrollment{}, err
	}
	if err := auth.CheckPasswordPolicy(in.Password); err != nil {
		return auth.TOTPEnrollment{}, err
	}
	hash, err := s.hasher.Hash(ctx, auth.NormalizePassword(in.Password))
	if err != nil {
		return auth.TOTPEnrollment{}, err
	}
	enr, err := auth.NewTOTP(in.Username)
	if err != nil {
		return auth.TOTPEnrollment{}, err
	}
	idHash := hashSessionToken(token)
	env, err := s.keyring.Seal(pendingLocation(idHash), []byte(enr.Secret))
	if err != nil {
		return auth.TOTPEnrollment{}, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE setup_sessions SET pending_username = $2, pending_display_name = $3, pending_email = $4,
pending_password_hash = $5, totp_secret_ct = $6, totp_nonce = $7, totp_wrapped_dek = $8, totp_key_version = $9 WHERE id_hash = $1`,
		idHash, in.Username, in.DisplayName, in.Email, hash, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion)
	if err != nil {
		return auth.TOTPEnrollment{}, fmt.Errorf("store enrollment: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return auth.TOTPEnrollment{}, ErrSessionInvalid
	}
	return enr, nil
}

// CreateAdmin verifies the first TOTP code and creates the administrator. In the same
// transaction the setup code and all wizard sessions are deleted, so the wizard cannot be
// used again (spec §18.5 rule 4). The new administrator is signed in.
func (s *Service) CreateAdmin(ctx context.Context, token, code string, m auth.Meta) (auth.SessionResult, error) {
	if err := s.Authenticate(ctx, token); err != nil {
		return auth.SessionResult{}, err
	}
	idHash := hashSessionToken(token)
	var (
		username, displayName, email, hash *string
		env                                secrets.Envelope
		version                            *int
	)
	err := s.pool.QueryRow(ctx, `SELECT pending_username::text, pending_display_name, pending_email::text, pending_password_hash,
totp_secret_ct, totp_nonce, totp_wrapped_dek, totp_key_version FROM setup_sessions WHERE id_hash = $1`, idHash).Scan(
		&username, &displayName, &email, &hash, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.SessionResult{}, ErrSessionInvalid
	}
	if err != nil {
		return auth.SessionResult{}, fmt.Errorf("read enrollment: %w", err)
	}
	if username == nil || hash == nil || version == nil {
		return auth.SessionResult{}, ErrEnrollmentMissing
	}
	env.KeyVersion = *version
	secret, err := s.keyring.Open(pendingLocation(idHash), env)
	if err != nil {
		return auth.SessionResult{}, err
	}
	defer secret.Zero()
	locale := "en"
	if _, err := settings.Get(ctx, s.pool, keyLocale, &locale); err != nil {
		return auth.SessionResult{}, err
	}
	in := auth.BootstrapAdmin{Username: *username, DisplayName: deref(displayName), Email: deref(email),
		PasswordHash: *hash, TOTPSecret: string(secret.Bytes()), Code: code, Locale: locale}
	if s.beforeBootstrap != nil {
		s.beforeBootstrap()
	}
	res, err := s.auth.BootstrapAdmin(ctx, in, m, func(tx pgx.Tx) error {
		// AUD-21: BootstrapAdmin holds the users lock here, so a setup code reset (SHARE lock on users)
		// is either already committed or waits for this commit. A committed reset deleted every wizard
		// session, so the caller's own session must still exist: otherwise the reset won, and the
		// administrator is not created. The code the session was opened with is the current one, because
		// StartSession only inserts a session while the code's row is locked against a reset.
		tag, err := tx.Exec(ctx, "DELETE FROM setup_sessions WHERE id_hash = $1 AND idle_expires_at > $2", idHash, s.clock.Now().UTC())
		if err != nil {
			return fmt.Errorf("consume setup session: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrSessionInvalid
		}
		if s.inBootstrapTx != nil {
			s.inBootstrapTx()
		}
		if err := settings.Delete(ctx, tx, keyTokenHash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM setup_sessions"); err != nil {
			return fmt.Errorf("delete setup sessions: %w", err)
		}
		return nil
	})
	if errors.Is(err, auth.ErrAdminExists) {
		return auth.SessionResult{}, ErrAlreadySetUp
	}
	return res, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
