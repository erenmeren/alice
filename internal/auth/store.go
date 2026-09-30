package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// userColumns selects a User from "users u".
const userColumns = `u.id, u.username::text, u.display_name, u.email::text, u.role, u.locale,
u.disabled_at IS NOT NULL,
EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enrolled_at IS NOT NULL),
u.last_login_at, u.created_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	var role string
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &role, &u.Locale,
		&u.Disabled, &u.MFAEnrolled, &u.LastLoginAt, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("read user: %w", err)
	}
	u.Role = rbac.Role(role)
	u.CreatedAt = u.CreatedAt.UTC()
	if u.LastLoginAt != nil {
		t := u.LastLoginAt.UTC()
		u.LastLoginAt = &t
	}
	return u, nil
}

func getUser(ctx context.Context, q db.Querier, id uuid.UUID) (User, error) {
	return scanUser(q.QueryRow(ctx, "SELECT "+userColumns+" FROM users u WHERE u.id = $1", id))
}

// ipParam returns a value for an inet parameter ($n::inet): NULL when unknown.
func ipParam(a netip.Addr) any {
	if !a.IsValid() {
		return nil
	}
	return a.Unmap().String()
}

// truncateUA bounds the stored user agent.
func truncateUA(s string) string {
	const maxUA = 256
	r := []rune(s)
	if len(r) > maxUA {
		return string(r[:maxUA])
	}
	return s
}

func totpLocation(userID uuid.UUID) secrets.Location {
	return secrets.Location{Table: "user_mfa", RowID: userID.String(), Column: "totp_secret"}
}

// mfaRow is the stored TOTP state of a user.
type mfaRow struct {
	env      secrets.Envelope
	enrolled bool
	lastStep int64
}

// loadMFA returns the TOTP state, or found=false.
func loadMFA(ctx context.Context, q db.Querier, userID uuid.UUID) (mfaRow, bool, error) {
	var r mfaRow
	var enrolledAt *time.Time
	err := q.QueryRow(ctx, `SELECT totp_secret_ct, totp_nonce, totp_wrapped_dek, totp_key_version, enrolled_at, last_used_step
FROM user_mfa WHERE user_id = $1`, userID).Scan(&r.env.Ciphertext, &r.env.Nonce, &r.env.WrappedDEK, &r.env.KeyVersion, &enrolledAt, &r.lastStep)
	if errors.Is(err, pgx.ErrNoRows) {
		return mfaRow{}, false, nil
	}
	if err != nil {
		return mfaRow{}, false, fmt.Errorf("read MFA state: %w", err)
	}
	r.enrolled = enrolledAt != nil
	return r, true, nil
}

// openSecret decrypts the TOTP secret. The caller must zero the result.
func (s *Service) openSecret(userID uuid.UUID, r mfaRow) (secrets.Plaintext, error) {
	return s.keyring.Open(totpLocation(userID), r.env)
}

// consumeStep records an accepted TOTP step; it fails when the step was already used (replay).
func consumeStep(ctx context.Context, q db.Querier, userID uuid.UUID, step int64, enroll bool, now time.Time) (bool, error) {
	tag, err := q.Exec(ctx, `UPDATE user_mfa SET last_used_step = $2,
enrolled_at = CASE WHEN $3 THEN coalesce(enrolled_at, $4) ELSE enrolled_at END
WHERE user_id = $1 AND last_used_step < $2`, userID, step, enroll, now)
	if err != nil {
		return false, fmt.Errorf("record TOTP step: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
