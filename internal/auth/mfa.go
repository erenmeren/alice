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

// EnrollMFA starts (or restarts) TOTP enrollment for a pending session whose user has no MFA yet.
// It holds the account lock so a restart cannot swap the secret under a running VerifyMFA.
func (s *Service) EnrollMFA(ctx context.Context, p Principal, m Meta) (TOTPEnrollment, error) {
	if p.Kind != rbac.PendingSession {
		return TOTPEnrollment{}, ErrUnauthenticated
	}
	enr, err := NewTOTP(p.Username)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	env, err := s.keyring.Seal(totpLocation(p.UserID), []byte(enr.Secret))
	if err != nil {
		return TOTPEnrollment{}, err
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		a, err := lockAccountByID(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if a.enrolled {
			return ErrMFAAlreadyEnrolled
		}
		tag, err := tx.Exec(ctx, `INSERT INTO user_mfa (user_id, totp_secret_ct, totp_nonce, totp_wrapped_dek, totp_key_version, enrolled_at, last_used_step, created_at)
VALUES ($1, $2, $3, $4, $5, NULL, 0, $6)
ON CONFLICT (user_id) DO UPDATE SET totp_secret_ct = EXCLUDED.totp_secret_ct, totp_nonce = EXCLUDED.totp_nonce,
  totp_wrapped_dek = EXCLUDED.totp_wrapped_dek, totp_key_version = EXCLUDED.totp_key_version, last_used_step = 0
WHERE user_mfa.enrolled_at IS NULL`, p.UserID, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, s.clock.Now().UTC())
		if err != nil {
			return fmt.Errorf("store TOTP secret: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrMFAAlreadyEnrolled
		}
		return nil
	})
	if err != nil {
		return TOTPEnrollment{}, err
	}
	return enr, nil
}

// checkTOTP verifies a code against the stored secret and consumes its step.
func (s *Service) checkTOTP(ctx context.Context, tx pgx.Tx, userID uuid.UUID, row mfaRow, code string, enroll bool) (bool, error) {
	secret, err := s.openSecret(userID, row)
	if err != nil {
		return false, err
	}
	defer secret.Zero()
	step, ok := VerifyTOTP(string(secret.Bytes()), code, s.clock.Now(), row.lastStep)
	if !ok {
		return false, nil
	}
	return consumeStep(ctx, tx, userID, step, enroll, s.clock.Now().UTC())
}

// maxRecoveryCodeInput bounds typed recovery codes (16 characters plus separators and
// spaces); longer input is rejected before any hashing.
const maxRecoveryCodeInput = 32

// useRecoveryCode marks a matching unused recovery code as used. The UPDATE is a
// compare-and-set on used_at, so a code is accepted at most once.
func (s *Service) useRecoveryCode(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) (bool, error) {
	if len(code) > maxRecoveryCodeInput {
		return false, nil
	}
	norm := NormalizeRecoveryCode(code)
	rows, err := tx.Query(ctx, "SELECT id, code_hash FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL", userID)
	if err != nil {
		return false, fmt.Errorf("read recovery codes: %w", err)
	}
	type rc struct {
		id   uuid.UUID
		hash string
	}
	var list []rc
	for rows.Next() {
		var r rc
		if err := rows.Scan(&r.id, &r.hash); err != nil {
			rows.Close()
			return false, fmt.Errorf("read recovery code: %w", err)
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("read recovery codes: %w", err)
	}
	for _, r := range list {
		ok, _, err := s.recovery.Verify(ctx, r.hash, norm)
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		tag, err := tx.Exec(ctx, "UPDATE recovery_codes SET used_at = $2 WHERE id = $1 AND used_at IS NULL", r.id, s.clock.Now().UTC())
		if err != nil {
			return false, fmt.Errorf("use recovery code: %w", err)
		}
		return tag.RowsAffected() == 1, nil
	}
	return false, nil
}

// hashRecoveryCodes hashes normalized codes with the recovery-code hasher.
func (s *Service) hashRecoveryCodes(ctx context.Context, codes []string) ([]string, error) {
	out := make([]string, len(codes))
	for i, c := range codes {
		h, err := s.recovery.Hash(ctx, NormalizeRecoveryCode(c))
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

// replaceRecoveryCodes deletes a user's codes and stores new hashes.
func (s *Service) replaceRecoveryCodes(ctx context.Context, tx pgx.Tx, userID uuid.UUID, hashes []string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM recovery_codes WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	now := s.clock.Now().UTC()
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, "INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES ($1, $2, $3, $4)",
			uuid.Must(uuid.NewV7()), userID, h, now); err != nil {
			return fmt.Errorf("store recovery code: %w", err)
		}
	}
	return nil
}

// pendingSessionExists reports whether the pending session is still stored. Attempts on
// one account are serialized by the account lock, so a session consumed by a concurrent
// successful VerifyMFA is seen as gone.
func pendingSessionExists(ctx context.Context, tx pgx.Tx, p Principal) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM sessions WHERE id_hash = $1 AND user_id = $2 AND kind = 'pending')",
		p.SessionHash, p.UserID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("read pending session: %w", err)
	}
	return ok, nil
}

// VerifyMFA completes a login: it checks a TOTP code (finishing enrollment when needed)
// or a recovery code, deletes the pending session and issues a new full session.
//
// Lock check, verification, failure count and session issue run in one transaction
// holding the account's row lock (see lockAccount).
func (s *Service) VerifyMFA(ctx context.Context, p Principal, in MFAInput, m Meta) (SessionResult, error) {
	if p.Kind != rbac.PendingSession {
		return SessionResult{}, ErrUnauthenticated
	}
	actor := userActor(p.UserID, p.Username, m)
	var (
		token  string
		codes  []string
		failed bool
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		a, err := lockAccountByID(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		exists, err := pendingSessionExists(ctx, tx, p)
		if err != nil {
			return err
		}
		if !exists {
			return ErrUnauthenticated
		}
		if a.disabled || a.blocked(s.clock.Now()) {
			failed = true
			return s.auditFailure(ctx, tx, actor, "auth.mfa_verify", p.UserID.String(), "locked")
		}
		row, found, err := loadMFA(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		method := "totp"
		ok := false
		switch {
		case !found:
		case in.RecoveryCode != "":
			method = "recovery_code"
			if row.enrolled {
				ok, err = s.useRecoveryCode(ctx, tx, p.UserID, in.RecoveryCode)
			}
		default:
			ok, err = s.checkTOTP(ctx, tx, p.UserID, row, in.Code, !row.enrolled)
		}
		if err != nil {
			return err
		}
		if !ok {
			failed = true
			return s.recordFailure(ctx, tx, actor, p.UserID, "auth.mfa_verify", "bad_"+method)
		}
		enrolledNow := !row.enrolled
		if enrolledNow {
			codes = GenerateRecoveryCodes()
			hashes, err := s.hashRecoveryCodes(ctx, codes)
			if err != nil {
				return err
			}
			if err := s.replaceRecoveryCodes(ctx, tx, p.UserID, hashes); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "DELETE FROM sessions WHERE id_hash = $1", p.SessionHash); err != nil {
			return fmt.Errorf("delete pending session: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = $2, updated_at = $2 WHERE id = $1",
			p.UserID, s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("reset failures: %w", err)
		}
		if token, err = s.startFullSession(ctx, tx, p.UserID, m); err != nil {
			return err
		}
		// Audit rows last, after every row lock of this transaction.
		if enrolledNow {
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "auth.mfa_enrolled", ObjectType: "user", ObjectID: p.UserID.String(), Result: audit.Success}); err != nil {
				return err
			}
		}
		if method == "recovery_code" {
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "auth.recovery_code_used", ObjectType: "user", ObjectID: p.UserID.String(), Result: audit.Success}); err != nil {
				return err
			}
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "auth.login", ObjectType: "user", ObjectID: p.UserID.String(),
			Result: audit.Success, Details: map[string]string{"method": method}})
		return err
	})
	if err != nil {
		return SessionResult{}, err
	}
	if failed {
		return SessionResult{}, ErrMFAInvalid
	}
	return s.resultFor(ctx, p.UserID, token, codes)
}

// StepUp re-verifies a TOTP code, opens a 5-minute step-up window and rotates the session ID.
// Like VerifyMFA it runs under the account's row lock and shares the failure counter.
func (s *Service) StepUp(ctx context.Context, p Principal, code string, m Meta) (SessionResult, error) {
	if p.Kind != rbac.UserSession {
		return SessionResult{}, ErrUnauthenticated
	}
	actor := p.Actor(m)
	var (
		token  string
		failed bool
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		a, err := lockAccountByID(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if a.disabled || a.blocked(s.clock.Now()) {
			failed = true
			return s.auditFailure(ctx, tx, actor, "auth.stepup", p.UserID.String(), "locked")
		}
		row, found, err := loadMFA(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		ok := false
		if found && row.enrolled {
			if ok, err = s.checkTOTP(ctx, tx, p.UserID, row, code, false); err != nil {
				return err
			}
		}
		if !ok {
			failed = true
			return s.recordFailure(ctx, tx, actor, p.UserID, "auth.stepup", "bad_totp")
		}
		stepUp := s.clock.Now().UTC().Add(StepUpWindow)
		if token, err = s.rotateSession(ctx, tx, p.SessionHash, p.UserID, &stepUp, m); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1", p.UserID); err != nil {
			return fmt.Errorf("reset failures: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "auth.stepup", ObjectType: "user", ObjectID: p.UserID.String(), Result: audit.Success})
		return err
	})
	if err != nil {
		return SessionResult{}, err
	}
	if failed {
		return SessionResult{}, ErrMFAInvalid
	}
	return s.resultFor(ctx, p.UserID, token, nil)
}

// RegenerateRecoveryCodes replaces the caller's recovery codes (SEC-008; the route requires step-up).
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, p Principal, m Meta) ([]string, error) {
	if p.Kind != rbac.UserSession {
		return nil, ErrUnauthenticated
	}
	codes := GenerateRecoveryCodes()
	hashes, err := s.hashRecoveryCodes(ctx, codes)
	if err != nil {
		return nil, err
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.replaceRecoveryCodes(ctx, tx, p.UserID, hashes); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "auth.recovery_codes_regenerated", ObjectType: "user", ObjectID: p.UserID.String(), Result: audit.Success})
		return err
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}
