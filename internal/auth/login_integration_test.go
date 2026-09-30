//go:build integration

package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
)

func TestBootstrapAdminCreatesFirstChainLinkAndSession(t *testing.T) {
	e := newEnv(t)
	enr, err := auth.NewTOTP("admin")
	require.NoError(t, err)
	_, err = e.svc.BootstrapAdmin(e.ctx, auth.BootstrapAdmin{Username: "admin", DisplayName: "A", PasswordHash: "x",
		TOTPSecret: enr.Secret, Code: code(t, enr.Secret, e.clk.Now().Add(time.Hour))}, meta, nil)
	require.ErrorIs(t, err, auth.ErrMFAInvalid)

	_, res := e.bootstrap(t)
	assert.Len(t, res.RecoveryCodes, 10)
	assert.NotEmpty(t, res.Token)
	assert.Equal(t, rbac.Admin, res.Info.User.Role)
	assert.True(t, res.Info.User.MFAEnrolled)
	assert.Equal(t, "Ayşe Yılmaz", res.Info.User.DisplayName)
	assert.Equal(t, "tr", res.Info.User.Locale)
	require.NotNil(t, res.Info.StepUpUntil)
	assert.Equal(t, e.clk.Now().Add(auth.StepUpWindow), *res.Info.StepUpUntil)
	assert.Equal(t, e.svc.CSRFToken(res.Token), res.Info.CSRFToken)

	var seq int64
	var action string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT seq, action FROM audit_log ORDER BY seq LIMIT 1").Scan(&seq, &action))
	assert.Equal(t, int64(1), seq)
	assert.Equal(t, "setup.admin_created", action)

	enr2, err := auth.NewTOTP("second")
	require.NoError(t, err)
	_, err = e.svc.BootstrapAdmin(e.ctx, auth.BootstrapAdmin{Username: "second", DisplayName: "B", PasswordHash: "x",
		TOTPSecret: enr2.Secret, Code: code(t, enr2.Secret, e.clk.Now())}, meta, nil)
	assert.ErrorIs(t, err, auth.ErrAdminExists)
}

func TestLoginNeedsMFAAndIssuesANewSessionID(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	e.clk.Advance(30 * time.Second)

	lr, err := e.svc.Login(e.ctx, "ADMIN", adminPassword, meta) // usernames are case-insensitive
	require.NoError(t, err)
	assert.Equal(t, auth.StatusMFARequired, lr.Status)
	pending := e.principal(t, lr.SessionToken)
	assert.Equal(t, rbac.PendingSession, pending.Kind)
	_, err = e.svc.SessionInfo(e.ctx, pending, lr.SessionToken)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "a pending session is not a full session")

	res, err := e.svc.VerifyMFA(e.ctx, pending, auth.MFAInput{Code: code(t, secret, e.clk.Now())}, meta)
	require.NoError(t, err)
	assert.Empty(t, res.RecoveryCodes, "codes are only returned at enrollment")
	assert.NotEqual(t, lr.SessionToken, res.Token, "session ID changes after MFA (A-04)")
	_, err = e.svc.Authenticate(e.ctx, lr.SessionToken)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "the pending session is gone")
	full := e.principal(t, res.Token)
	assert.Equal(t, rbac.UserSession, full.Kind)
	assert.True(t, full.Subject(e.clk.Now()).StepUp, "a fresh MFA opens the step-up window")
	assert.Contains(t, e.actions(t), "auth.login:success")
}

func TestUnknownUserGetsTheGenericErrorAndIsNotRecordedByName(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	_, err := e.svc.Login(e.ctx, "my-secret-password-typed-as-name", "whatever whatever", meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	_, err = e.svc.Login(e.ctx, "admin", "wrong password here", meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials, "same error for a wrong password (SEC-004)")

	var name, reason string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT actor_name, details->>'reason' FROM audit_log
WHERE action = 'auth.login' AND result = 'failure' ORDER BY seq LIMIT 1`).Scan(&name, &reason))
	assert.Equal(t, "(unknown user)", name)
	assert.Equal(t, "unknown_user", reason)
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM audit_log
WHERE actor_name LIKE '%my-secret%' OR details::text LIKE '%my-secret%'`).Scan(&n))
	assert.Zero(t, n)
}

func TestProgressiveDelayThenLockout(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	wrong := func() {
		t.Helper()
		_, err := e.svc.Login(e.ctx, "admin", "definitely not it", meta)
		require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	}
	right := func() error {
		_, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
		return err
	}
	for range 5 {
		wrong()
	}
	assert.Equal(t, 5, e.failedLogins(t, "admin"))
	require.ErrorIs(t, right(), auth.ErrInvalidCredentials, "correct password is refused during the delay (R-01)")
	assert.Equal(t, 5, e.failedLogins(t, "admin"), "attempts during the delay are not counted")
	e.clk.Advance(time.Second)
	require.NoError(t, right(), "works once the 1 s delay has passed")

	for _, d := range []time.Duration{0, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second} {
		e.clk.Advance(d)
		wrong()
	}
	assert.Equal(t, 10, e.failedLogins(t, "admin"))
	assert.Contains(t, e.actions(t), "auth.lockout:failure")

	require.ErrorIs(t, right(), auth.ErrInvalidCredentials, "locked (R-02)")
	e.clk.Advance(auth.LockDuration - time.Second)
	require.ErrorIs(t, right(), auth.ErrInvalidCredentials, "still locked just before 15 min")
	e.clk.Advance(time.Second)
	e.signIn(t, "admin", adminPassword, secret)
	assert.Equal(t, 0, e.failedLogins(t, "admin"), "a full login resets the counter")
}

func TestWrongTOTPCountsAsAFailure(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	e.clk.Advance(30 * time.Second)
	lr, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.NoError(t, err)
	_, err = e.svc.VerifyMFA(e.ctx, e.principal(t, lr.SessionToken), auth.MFAInput{Code: code(t, secret, e.clk.Now().Add(time.Hour))}, meta)
	require.ErrorIs(t, err, auth.ErrMFAInvalid)
	assert.Equal(t, 1, e.failedLogins(t, "admin"))
	assert.Contains(t, e.actions(t), "auth.mfa_verify:failure")
}

func TestEnrollmentCodeCannotBeReusedButLaterStepsWork(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	e.insertUser(t, "operator1", rbac.Operator, adminPassword)
	secret, res := e.enroll(t, "operator1", adminPassword)
	assert.Len(t, res.RecoveryCodes, 10, "first enrollment returns recovery codes")
	assert.True(t, res.Info.User.MFAEnrolled)
	assert.Contains(t, e.actions(t), "auth.mfa_enrolled:success")

	lr, err := e.svc.Login(e.ctx, "operator1", adminPassword, meta)
	require.NoError(t, err)
	assert.Equal(t, auth.StatusMFARequired, lr.Status)
	pending := e.principal(t, lr.SessionToken)
	enrollCode := code(t, secret, e.clk.Now())
	_, err = e.svc.VerifyMFA(e.ctx, pending, auth.MFAInput{Code: enrollCode}, meta)
	require.ErrorIs(t, err, auth.ErrMFAInvalid, "the enrollment code is used up for this step")

	e.clk.Advance(60 * time.Second) // two steps later; the previous step is still newer than the used one
	prev := code(t, secret, e.clk.Now().Add(-30*time.Second))
	_, err = e.svc.VerifyMFA(e.ctx, pending, auth.MFAInput{Code: prev}, meta)
	require.NoError(t, err, "a code from the previous step is accepted when it is newer than the last used step")
}

func TestEnrollMFARefusedOnceEnrolled(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	e.clk.Advance(30 * time.Second)
	lr, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.NoError(t, err)
	_, err = e.svc.EnrollMFA(e.ctx, e.principal(t, lr.SessionToken), meta)
	assert.ErrorIs(t, err, auth.ErrMFAAlreadyEnrolled)
}

func TestDisabledUserIsRejectedAndLosesSessions(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	e.insertUser(t, "op", rbac.Operator, adminPassword)
	_, res := e.enroll(t, "op", adminPassword)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE users SET disabled_at = now() WHERE username = 'op'")
	require.NoError(t, err)
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	_, err = e.svc.Login(e.ctx, "op", adminPassword, meta)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
	var reason string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT details->>'reason' FROM audit_log WHERE action = 'auth.login' ORDER BY seq DESC LIMIT 1`).Scan(&reason))
	assert.Equal(t, "disabled", reason)
}

func TestRoleIsReadFromTheDatabaseOnEveryRequest(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	e.insertUser(t, "op", rbac.Operator, adminPassword)
	_, res := e.enroll(t, "op", adminPassword)
	assert.Equal(t, rbac.Operator, e.principal(t, res.Token).Role)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE users SET role = 'auditor' WHERE username = 'op'")
	require.NoError(t, err)
	assert.Equal(t, rbac.Auditor, e.principal(t, res.Token).Role, "SEC-017")
}
