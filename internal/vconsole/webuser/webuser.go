// Package webuser keeps the people who may use the vendor web page: their accounts, one-time
// enrollment codes, stored passkeys and sign-in sessions. Codes and session tokens are 32 random
// bytes; only the SHA-256 of one is stored, so a database leak does not yield a usable token.
package webuser

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/vconsole/audit"
)

// Errors.
var (
	ErrNotFound      = errors.New("webuser: not found")
	ErrBadCode       = errors.New("webuser: the enrollment code is wrong, used or expired")
	ErrNoSession     = errors.New("webuser: no valid session")
	ErrDuplicateUser = errors.New("webuser: a user with this name already exists")
)

// Session limits.
const (
	SessionAbsolute = 8 * time.Hour
	SessionIdle     = 30 * time.Minute
)

// User is a person who may sign in to the web page.
type User struct {
	ID       int64
	Name     string
	Disabled bool
}

// StoredCredential is a passkey: its ID and the library's credential as JSON.
type StoredCredential struct {
	ID   []byte
	JSON []byte
}

func hashToken(t string) string { s := sha256.Sum256([]byte(t)); return hex.EncodeToString(s[:]) }

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("webuser: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const userCols = `id, name, disabled_at IS NOT NULL`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Name, &u.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("webuser: read user: %w", err)
	}
	return u, nil
}

// AddUser creates a web user (owner only). Names are 1-64 letters, digits, dot, underscore or
// dash, compared without regard to case.
func AddUser(ctx context.Context, q audit.Q, name string) (int64, error) {
	var id int64
	err := q.QueryRow(ctx, `INSERT INTO web_users (name) VALUES ($1) RETURNING id`, name).Scan(&id)
	if db.IsUniqueViolationOn(err, "web_users_name_key") {
		return 0, ErrDuplicateUser
	}
	if err != nil {
		return 0, fmt.Errorf("webuser: add user: %w", err)
	}
	return id, nil
}

// SetDisabled disables or enables a user (owner only). Disabling also deletes the user's sessions.
// It runs an UPDATE and then a DELETE: the caller should pass a transaction (a pgx.Tx), so a
// failure of the second leaves the user enabled instead of disabled with live sessions.
func SetDisabled(ctx context.Context, q audit.Q, name string, disabled bool, now time.Time) error {
	var id int64
	err := q.QueryRow(ctx, `UPDATE web_users SET disabled_at = CASE WHEN $2::boolean THEN $3::timestamptz END
		WHERE lower(name) = lower($1) RETURNING id`, name, disabled, now).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("webuser: set disabled: %w", err)
	}
	if disabled {
		if _, err := q.Exec(ctx, `DELETE FROM web_sessions WHERE user_id = $1`, id); err != nil {
			return fmt.Errorf("webuser: end sessions: %w", err)
		}
	}
	return nil
}

// SetEmail sets the address reminders for this person's requests go to ("" removes it). The
// database checks the address syntax and audits the change; the name is matched without regard
// to case, like everywhere else.
func SetEmail(ctx context.Context, q audit.Q, name, email string) error {
	tag, err := q.Exec(ctx, `UPDATE web_users SET email = $2 WHERE lower(name) = lower($1)`, name, email)
	if err != nil {
		return fmt.Errorf("webuser: set email: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListUsers returns all users by name.
func ListUsers(ctx context.Context, q audit.Q) ([]User, error) {
	rows, err := q.Query(ctx, `SELECT `+userCols+` FROM web_users ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("webuser: list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name, &u.Disabled); err != nil {
			return nil, fmt.Errorf("webuser: list users: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("webuser: list users: %w", err)
	}
	return out, nil
}

// GetUserByName finds a user by name, without regard to case.
func GetUserByName(ctx context.Context, q audit.Q, name string) (User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userCols+` FROM web_users WHERE lower(name) = lower($1)`, name))
}

// GetUserByID finds a user by ID.
func GetUserByID(ctx context.Context, q audit.Q, id int64) (User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userCols+` FROM web_users WHERE id = $1`, id))
}

// NewEnrollment issues a one-time code (owner only), valid for ttl, and returns it. The code is
// shown once; only its hash is stored.
func NewEnrollment(ctx context.Context, q audit.Q, userID int64, now time.Time, ttl time.Duration) (string, error) {
	code, err := newToken()
	if err != nil {
		return "", err
	}
	if _, err := q.Exec(ctx, `INSERT INTO web_enrollments (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		hashToken(code), userID, now.Add(ttl)); err != nil {
		return "", fmt.Errorf("webuser: new enrollment: %w", err)
	}
	return code, nil
}

// LookupEnrollment returns the user of a valid, unused code without consuming it.
func LookupEnrollment(ctx context.Context, q audit.Q, code string, now time.Time) (User, error) {
	var u User
	err := q.QueryRow(ctx, `SELECT u.id, u.name, false FROM web_enrollments e JOIN web_users u ON u.id = e.user_id
		WHERE e.token_hash = $1 AND e.used_at IS NULL AND e.expires_at > $2 AND u.disabled_at IS NULL`,
		hashToken(code), now).Scan(&u.ID, &u.Name, &u.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrBadCode
	}
	if err != nil {
		return User{}, fmt.Errorf("webuser: lookup enrollment: %w", err)
	}
	return u, nil
}

// ConsumeEnrollment marks the code used; ErrBadCode if it is wrong, used, expired or its user is disabled.
func ConsumeEnrollment(ctx context.Context, q audit.Q, code string, now time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE web_enrollments e SET used_at = $2
		FROM web_users u WHERE e.token_hash = $1 AND e.used_at IS NULL AND e.expires_at > $2
		AND u.id = e.user_id AND u.disabled_at IS NULL`, hashToken(code), now)
	if err != nil {
		return fmt.Errorf("webuser: consume enrollment: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrBadCode
	}
	return nil
}

// AddCredential stores a passkey for a user.
func AddCredential(ctx context.Context, q audit.Q, userID int64, id, credentialJSON []byte) error {
	if _, err := q.Exec(ctx, `INSERT INTO web_credentials (credential_id, user_id, credential) VALUES ($1, $2, $3)`,
		id, userID, credentialJSON); err != nil {
		return fmt.Errorf("webuser: add credential: %w", err)
	}
	return nil
}

// Credentials returns a user's passkeys.
func Credentials(ctx context.Context, q audit.Q, userID int64) ([]StoredCredential, error) {
	rows, err := q.Query(ctx, `SELECT credential_id, credential FROM web_credentials WHERE user_id = $1 ORDER BY created_at, credential_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("webuser: credentials: %w", err)
	}
	defer rows.Close()
	var out []StoredCredential
	for rows.Next() {
		var c StoredCredential
		if err := rows.Scan(&c.ID, &c.JSON); err != nil {
			return nil, fmt.Errorf("webuser: credentials: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("webuser: credentials: %w", err)
	}
	return out, nil
}

// UpdateCredential replaces a passkey's stored state (its sign counter changes on use) and records the use.
func UpdateCredential(ctx context.Context, q audit.Q, id, credentialJSON []byte, now time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE web_credentials SET credential = $2, last_used_at = $3 WHERE credential_id = $1`,
		id, credentialJSON, now)
	if err != nil {
		return fmt.Errorf("webuser: update credential: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// UserByCredential finds the owner of a passkey.
func UserByCredential(ctx context.Context, q audit.Q, id []byte) (User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT u.id, u.name, u.disabled_at IS NOT NULL FROM web_credentials c
		JOIN web_users u ON u.id = c.user_id WHERE c.credential_id = $1`, id))
}

// NewSession starts a session and returns its token.
func NewSession(ctx context.Context, q audit.Q, userID int64, now time.Time) (string, error) {
	tok, err := newToken()
	if err != nil {
		return "", err
	}
	if _, err := q.Exec(ctx, `INSERT INTO web_sessions (token_hash, user_id, created_at, expires_at, last_seen)
		VALUES ($1, $2, $3, $4, $3)`, hashToken(tok), userID, now, now.Add(SessionAbsolute)); err != nil {
		return "", fmt.Errorf("webuser: new session: %w", err)
	}
	return tok, nil
}

// Session returns the user of a valid token and extends last_seen. ErrNoSession for unknown, expired
// and idle-expired tokens and for disabled users.
func Session(ctx context.Context, q audit.Q, token string, now time.Time) (User, error) {
	var u User
	err := q.QueryRow(ctx, `UPDATE web_sessions s SET last_seen = $2
		FROM web_users u WHERE s.token_hash = $1 AND u.id = s.user_id AND u.disabled_at IS NULL
		AND s.expires_at > $2 AND s.last_seen > $3
		RETURNING u.id, u.name`, hashToken(token), now, now.Add(-SessionIdle)).Scan(&u.ID, &u.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNoSession
	}
	if err != nil {
		return User{}, fmt.Errorf("webuser: session: %w", err)
	}
	return u, nil
}

// EndSession deletes a session; an unknown token is not an error.
func EndSession(ctx context.Context, q audit.Q, token string) error {
	if _, err := q.Exec(ctx, `DELETE FROM web_sessions WHERE token_hash = $1`, hashToken(token)); err != nil {
		return fmt.Errorf("webuser: end session: %w", err)
	}
	return nil
}
