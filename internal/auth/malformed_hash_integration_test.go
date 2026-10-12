//go:build integration

package auth_test

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// Review I-7: a stored password hash that does not parse (a corrupted row) is a failed check, counted like a wrong
// password and logged, never an error answer before anything was counted. The same holds for the current password of a
// password change and for a stored recovery code.
func TestMalformedStoredHashIsAFailedCheck(t *testing.T) {
	e := newEnv(t)
	var logs bytes.Buffer
	kr, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	e.svc = auth.NewService(auth.Config{Pool: e.db.App, Keyring: kr, Audit: audit.New(e.clk), Clock: e.clk, Hasher: e.hasher,
		RecoveryHasher: e.hasher, Notifier: e.notes, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	secret, boot := e.bootstrap(t)
	res := e.signIn(t, "admin", adminPassword, secret)
	p := e.principal(t, res.Token)

	id := e.insertUser(t, "bob", rbac.Operator, "a long enough passphrase")
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE users SET password_hash = '$argon2id$v=19$m=64,t=1,p=1junk$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5a2V5' WHERE id = $1`, id)
	require.NoError(t, err)
	_, err = e.svc.Login(e.ctx, "bob", "a long enough passphrase", meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	assert.Equal(t, 1, e.failedLogins(t, "bob"), "the failure is counted")
	assert.Equal(t, 1, e.reasons(t, "auth.login")["bad_password"])
	assert.Contains(t, logs.String(), "stored password hash is malformed")
	assert.Contains(t, logs.String(), id.String())

	_, err = e.db.Owner.Exec(e.ctx, `UPDATE recovery_codes SET code_hash = '$argon2id$v=19junk' WHERE user_id = $1`, p.UserID)
	require.NoError(t, err)
	e.clk.Advance(30 * time.Second)
	lr, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.NoError(t, err)
	_, err = e.svc.VerifyMFA(e.ctx, e.principal(t, lr.SessionToken), auth.MFAInput{RecoveryCode: boot.RecoveryCodes[0]}, meta)
	require.ErrorIs(t, err, auth.ErrMFAInvalid)
	assert.Equal(t, 1, e.failedLogins(t, "admin"))
	assert.Equal(t, 1, e.reasons(t, "auth.mfa_verify")["bad_recovery_code"])
	assert.Contains(t, logs.String(), "stored recovery code hash is malformed")

	_, err = e.db.Owner.Exec(e.ctx, `UPDATE users SET password_hash = 'not a hash' WHERE username = 'admin'`)
	require.NoError(t, err)
	_, err = e.svc.ChangePassword(e.ctx, p, adminPassword, "another long passphrase", meta)
	require.ErrorIs(t, err, auth.ErrCurrentPasswordInvalid)
	assert.Equal(t, 2, e.failedLogins(t, "admin"))
	assert.Equal(t, 1, e.reasons(t, "auth.password_changed")["current_password_invalid"])
}
