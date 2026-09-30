//go:build integration

package auth_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
)

// These tests fire many wrong guesses at one account at the same moment. The lock
// check, the verification and the failure count run under one row lock per account,
// so once the account is delayed or locked no further guess is evaluated (C6, SEC-020).

func requireAll(t *testing.T, errs []error, target error) {
	t.Helper()
	for i, err := range errs {
		require.ErrorIs(t, err, target, "request %d", i)
	}
}

func TestParallelWrongPasswordsStopAtTheThreshold(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	wrong := func() error {
		_, err := e.svc.Login(e.ctx, "admin", "definitely not it", meta)
		return err
	}

	requireAll(t, parallel(20, wrong), auth.ErrInvalidCredentials)
	assert.Equal(t, auth.DelayThreshold, e.failedLogins(t, "admin"), "the fifth failure starts the delay; later guesses are not evaluated")
	r := e.reasons(t, "auth.login")
	assert.Equal(t, auth.DelayThreshold, r["bad_password"])
	assert.Equal(t, 20-auth.DelayThreshold, r["locked"])

	e.setFailures(t, "admin", auth.LockThreshold-1)
	requireAll(t, parallel(20, wrong), auth.ErrInvalidCredentials)
	assert.Equal(t, auth.LockThreshold, e.failedLogins(t, "admin"), "exactly one guess is evaluated before the lockout")
	assert.Equal(t, 1, e.countAction(t, "auth.lockout", "failure"))
	r = e.reasons(t, "auth.login")
	assert.Equal(t, auth.DelayThreshold+1, r["bad_password"])
	assert.Equal(t, 40-auth.DelayThreshold-1, r["locked"])

	_, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials, "the right password is refused while locked")
}

func TestParallelWrongTOTPCodesStopAtTheThreshold(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	e.clk.Advance(30 * time.Second)
	lr, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.NoError(t, err)
	pending := e.principal(t, lr.SessionToken)
	bad := code(t, secret, e.clk.Now().Add(time.Hour))
	wrong := func() error {
		_, err := e.svc.VerifyMFA(e.ctx, pending, auth.MFAInput{Code: bad}, meta)
		return err
	}

	requireAll(t, parallel(20, wrong), auth.ErrMFAInvalid)
	assert.Equal(t, auth.DelayThreshold, e.failedLogins(t, "admin"))
	r := e.reasons(t, "auth.mfa_verify")
	assert.Equal(t, auth.DelayThreshold, r["bad_totp"])
	assert.Equal(t, 20-auth.DelayThreshold, r["locked"])

	e.setFailures(t, "admin", auth.LockThreshold-1)
	requireAll(t, parallel(20, wrong), auth.ErrMFAInvalid)
	assert.Equal(t, auth.LockThreshold, e.failedLogins(t, "admin"))
	assert.Equal(t, 1, e.countAction(t, "auth.lockout", "failure"))
	assert.Equal(t, auth.DelayThreshold+1, e.reasons(t, "auth.mfa_verify")["bad_totp"])

	_, err = e.svc.VerifyMFA(e.ctx, pending, auth.MFAInput{Code: code(t, secret, e.clk.Now())}, meta)
	assert.ErrorIs(t, err, auth.ErrMFAInvalid, "the right code is refused while locked")
	assert.Equal(t, auth.LockThreshold, e.failedLogins(t, "admin"))
}

func TestParallelWrongStepUpCodesStopAtTheThreshold(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	res := e.signIn(t, "admin", adminPassword, secret)
	p := e.principal(t, res.Token)
	bad := code(t, secret, e.clk.Now().Add(time.Hour))
	errs := parallel(20, func() error {
		_, err := e.svc.StepUp(e.ctx, p, bad, meta)
		return err
	})
	requireAll(t, errs, auth.ErrMFAInvalid)
	assert.Equal(t, auth.DelayThreshold, e.failedLogins(t, "admin"))
	r := e.reasons(t, "auth.stepup")
	assert.Equal(t, auth.DelayThreshold, r["bad_totp"])
	assert.Equal(t, 20-auth.DelayThreshold, r["locked"])
}

func TestParallelWrongCurrentPasswordsStopAtTheThreshold(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	res := e.signIn(t, "admin", adminPassword, secret)
	p := e.principal(t, res.Token)
	errs := parallel(20, func() error {
		_, err := e.svc.ChangePassword(e.ctx, p, "not the current one", "another long passphrase", meta)
		return err
	})
	requireAll(t, errs, auth.ErrCurrentPasswordInvalid)
	assert.Equal(t, auth.DelayThreshold, e.failedLogins(t, "admin"))
	r := e.reasons(t, "auth.password_changed")
	assert.Equal(t, auth.DelayThreshold, r["current_password_invalid"])
	assert.Equal(t, 20-auth.DelayThreshold, r["locked"])
}

func TestWrongCurrentPasswordCountsLikeAFailedLogin(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	res := e.signIn(t, "admin", adminPassword, secret)
	p := e.principal(t, res.Token)
	for range auth.DelayThreshold {
		_, err := e.svc.ChangePassword(e.ctx, p, "not the current one", "another long passphrase", meta)
		require.ErrorIs(t, err, auth.ErrCurrentPasswordInvalid)
	}
	assert.Equal(t, auth.DelayThreshold, e.failedLogins(t, "admin"), "C7: the counter is shared with login")

	_, err := e.svc.ChangePassword(e.ctx, p, adminPassword, "another long passphrase", meta)
	require.ErrorIs(t, err, auth.ErrCurrentPasswordInvalid, "the right password is refused during the delay")
	_, err = e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials, "login shares the delay")
	assert.Equal(t, auth.DelayThreshold, e.failedLogins(t, "admin"), "refused attempts are not counted")

	e.clk.Advance(time.Second)
	_, err = e.svc.ChangePassword(e.ctx, p, adminPassword, "another long passphrase", meta)
	require.NoError(t, err)
}

func TestOverlongRecoveryCodeCountsAsAFailure(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	e.clk.Advance(30 * time.Second)
	lr, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.NoError(t, err)
	_, err = e.svc.VerifyMFA(e.ctx, e.principal(t, lr.SessionToken), auth.MFAInput{RecoveryCode: strings.Repeat("A", 33)}, meta)
	require.ErrorIs(t, err, auth.ErrMFAInvalid)
	assert.Equal(t, 1, e.failedLogins(t, "admin"))
	assert.Equal(t, 1, e.reasons(t, "auth.mfa_verify")["bad_recovery_code"])
}

func TestConcurrentReplayOfOneCodeSucceedsOnce(t *testing.T) {
	e := newEnv(t)
	secret, boot := e.bootstrap(t)
	e.clk.Advance(30 * time.Second)
	pendings := make([]auth.Principal, 8)
	for i := range pendings {
		lr, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
		require.NoError(t, err)
		pendings[i] = e.principal(t, lr.SessionToken)
	}
	succeeded := func(errs []error) int {
		n := 0
		for _, err := range errs {
			if err == nil {
				n++
			} else {
				require.ErrorIs(t, err, auth.ErrMFAInvalid)
			}
		}
		return n
	}

	totpCode := code(t, secret, e.clk.Now())
	var i atomic.Int32
	errs := parallel(4, func() error {
		_, err := e.svc.VerifyMFA(e.ctx, pendings[i.Add(1)-1], auth.MFAInput{Code: totpCode}, meta)
		return err
	})
	assert.Equal(t, 1, succeeded(errs), "a TOTP code is accepted once (SEC-006)")

	errs = parallel(4, func() error {
		_, err := e.svc.VerifyMFA(e.ctx, pendings[i.Add(1)-1], auth.MFAInput{RecoveryCode: boot.RecoveryCodes[0]}, meta)
		return err
	})
	assert.Equal(t, 1, succeeded(errs), "a recovery code is accepted once (SEC-008)")
}
