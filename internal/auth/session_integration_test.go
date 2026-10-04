//go:build integration

package auth_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/platform/validate"
)

func TestIdleTimeoutSlidesAndAbsoluteLimitHolds(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)

	res := e.signIn(t, "admin", adminPassword, secret)
	e.clk.Advance(29 * time.Minute)
	e.principal(t, res.Token) // 29 min idle: valid, and the idle timer restarts (A-02)
	e.clk.Advance(29 * time.Minute)
	e.principal(t, res.Token)
	e.clk.Advance(31 * time.Minute)
	_, err := e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "31 min idle ends the session")

	res = e.signIn(t, "admin", adminPassword, secret)
	start := e.clk.Now() // the session was created now
	for e.clk.Now().Add(29 * time.Minute).Before(start.Add(auth.SessionAbsolute)) {
		e.clk.Advance(29 * time.Minute)
		e.principal(t, res.Token)
	}
	e.clk.Set(start.Add(auth.SessionAbsolute))
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "12 h absolute limit even when active (A-03)")
}

func TestStepUpOpensWindowAndRotatesSession(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	res := e.signIn(t, "admin", adminPassword, secret)
	e.clk.Advance(6 * time.Minute)
	p := e.principal(t, res.Token)
	assert.False(t, p.Subject(e.clk.Now()).StepUp, "the login step-up window lasts 5 minutes")
	info, err := e.svc.SessionInfo(e.ctx, p, res.Token)
	require.NoError(t, err)
	assert.Nil(t, info.StepUpUntil)

	_, err = e.svc.StepUp(e.ctx, p, code(t, secret, e.clk.Now().Add(time.Hour)), meta)
	require.ErrorIs(t, err, auth.ErrMFAInvalid)

	up, err := e.svc.StepUp(e.ctx, p, code(t, secret, e.clk.Now()), meta)
	require.NoError(t, err)
	assert.NotEqual(t, res.Token, up.Token, "step-up issues a new session ID (SEC-019)")
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	np := e.principal(t, up.Token)
	assert.True(t, np.Subject(e.clk.Now()).StepUp)
	require.NotNil(t, up.Info.StepUpUntil)
	assert.Equal(t, e.clk.Now().Add(auth.StepUpWindow), *up.Info.StepUpUntil)
	assert.Equal(t, info.ExpiresAt, up.Info.ExpiresAt, "rotation keeps the absolute expiry")
	assert.Contains(t, e.actions(t), "auth.stepup:success")
	assert.Contains(t, e.actions(t), "auth.stepup:failure")
}

func TestLogoutInvalidatesTheSession(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	res := e.signIn(t, "admin", adminPassword, secret)
	require.NoError(t, e.svc.Logout(e.ctx, e.principal(t, res.Token), meta))
	_, err := e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "A-05")
	assert.Contains(t, e.actions(t), "auth.logout:success")
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	e := newEnv(t)
	secret, _ := e.bootstrap(t)
	a := e.signIn(t, "admin", adminPassword, secret)
	b := e.signIn(t, "admin", adminPassword, secret)
	p := e.principal(t, a.Token)

	_, err := e.svc.ChangePassword(e.ctx, p, "not the current one", "another long passphrase", meta)
	require.ErrorIs(t, err, auth.ErrCurrentPasswordInvalid)
	_, err = e.svc.ChangePassword(e.ctx, p, adminPassword, "short", meta)
	require.ErrorIs(t, err, auth.ErrPasswordTooShort)
	_, err = e.svc.ChangePassword(e.ctx, p, adminPassword, "qwerty123456", meta)
	require.ErrorIs(t, err, auth.ErrPasswordBreached)

	res, err := e.svc.ChangePassword(e.ctx, p, adminPassword, "another long passphrase", meta)
	require.NoError(t, err)
	for _, old := range []string{a.Token, b.Token} {
		_, err = e.svc.Authenticate(e.ctx, old)
		assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	}
	e.principal(t, res.Token)
	e.signIn(t, "admin", "another long passphrase", secret)
	assert.Contains(t, e.actions(t), "auth.password_changed:success")
	assert.Contains(t, e.actions(t), "auth.password_changed:failure")
}

func TestRecoveryCodesAreSingleUseAndRegenerable(t *testing.T) {
	e := newEnv(t)
	_, boot := e.bootstrap(t)
	login := func(rc string) error {
		lr, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
		require.NoError(t, err)
		_, err = e.svc.VerifyMFA(e.ctx, e.principal(t, lr.SessionToken), auth.MFAInput{RecoveryCode: rc}, meta)
		return err
	}
	typed := " " + strings.ReplaceAll(boot.RecoveryCodes[0], "-", " ") + " " // spaces instead of dashes still work
	require.NoError(t, login(typed))
	require.ErrorIs(t, login(boot.RecoveryCodes[0]), auth.ErrMFAInvalid, "single use")
	assert.Contains(t, e.actions(t), "auth.recovery_code_used:success")

	codes, err := e.svc.RegenerateRecoveryCodes(e.ctx, e.principal(t, boot.Token), meta)
	require.NoError(t, err)
	require.Len(t, codes, 10)
	require.ErrorIs(t, login(boot.RecoveryCodes[1]), auth.ErrMFAInvalid, "old set is invalid")
	require.NoError(t, login(codes[0]))
}

func TestCSRFTokenIsBoundToTheSession(t *testing.T) {
	e := newEnv(t)
	_, res := e.bootstrap(t)
	tok := e.svc.CSRFToken(res.Token)
	assert.True(t, e.svc.CheckCSRF(res.Token, tok))
	assert.False(t, e.svc.CheckCSRF(res.Token, tok+"x"))
	assert.False(t, e.svc.CheckCSRF("other-session", tok))
	assert.False(t, e.svc.CheckCSRF(res.Token, ""))
	assert.False(t, e.svc.CheckCSRF("", ""))
}

func TestSetLocale(t *testing.T) {
	e := newEnv(t)
	_, res := e.bootstrap(t)
	p := e.principal(t, res.Token)
	var v validate.Errors
	require.ErrorAs(t, e.svc.SetLocale(e.ctx, p, "de"), &v)
	assert.Equal(t, validate.OneOf, v[0].Code)
	require.NoError(t, e.svc.SetLocale(e.ctx, p, "en"))
	info, err := e.svc.SessionInfo(e.ctx, p, res.Token)
	require.NoError(t, err)
	assert.Equal(t, "en", info.User.Locale)
}

func TestSessionStoresAZonedIPv6AddressWithoutItsZone(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	m := meta
	m.IP = netip.MustParseAddr("fe80::1%eth0")

	lr, err := e.svc.Login(e.ctx, "admin", adminPassword, m)
	require.NoError(t, err, "a link-local client address with a zone must not break sign-in")
	var ip string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT host(ip) FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = 'admin') AND kind = 'pending'").Scan(&ip))
	assert.Equal(t, "fe80::1", ip)
	assert.NotEmpty(t, lr.SessionToken)
}

// AUD-01 (from the audit's TestZZAuditBackgroundPollDefeatsIdleTimeout): the web UI's
// minute-by-minute license poll is answered but never extends the idle timeout.
func TestBackgroundPollsDoNotExtendTheIdleTimeout(t *testing.T) {
	e := newEnv(t)
	_, res := e.bootstrap(t) // the session's last activity is now
	alive := 0
	for range 11 * 60 { // the PoC's 11 hours of one poll per minute, nobody at the keyboard
		e.clk.Advance(time.Minute)
		if _, err := e.svc.AuthenticatePassive(e.ctx, res.Token); err != nil {
			assert.ErrorIs(t, err, auth.ErrUnauthenticated)
			break
		}
		alive++
	}
	assert.Equal(t, 29, alive, "valid until 30 minutes after the last activity, however often it is polled")
}

// sessionTimes reads last_seen_at and idle_expires_at of the only session of the given kind.
func (e *env) sessionTimes(t *testing.T, kind string) (lastSeen, idle time.Time) {
	t.Helper()
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT last_seen_at, idle_expires_at FROM sessions WHERE kind = $1", kind).Scan(&lastSeen, &idle))
	return lastSeen.UTC(), idle.UTC()
}

// AUD-01: a person's action slides the timer; a poll after it neither slides it nor moves last_seen_at.
func TestActivitySlidesAndPollsDoNotTouchTheSession(t *testing.T) {
	e := newEnv(t)
	_, res := e.bootstrap(t)
	e.clk.Advance(20 * time.Minute)
	p, err := e.svc.AuthenticatePassive(e.ctx, res.Token)
	require.NoError(t, err)
	_, idle := e.sessionTimes(t, "full")
	assert.True(t, idle.Equal(e.clk.Now().Add(10*time.Minute).UTC()), "a poll leaves the deadline where it was")

	require.NoError(t, e.svc.RecordActivity(e.ctx, p)) // a person's action
	seen, idle := e.sessionTimes(t, "full")
	assert.True(t, seen.Equal(e.clk.Now().UTC()))
	assert.True(t, idle.Equal(e.clk.Now().Add(auth.SessionIdle).UTC()))

	e.clk.Advance(29 * time.Minute)
	_, err = e.svc.AuthenticatePassive(e.ctx, res.Token)
	require.NoError(t, err, "29 minutes after the action")
	again, idleAgain := e.sessionTimes(t, "full")
	assert.True(t, seen.Equal(again), "a poll does not move last_seen_at")
	assert.True(t, idle.Equal(idleAgain), "a poll does not move idle_expires_at")
	e.clk.Advance(time.Minute)
	_, err = e.svc.AuthenticatePassive(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "30 minutes after the action")
}

// Recording activity never revives an ended session, never passes the absolute lifetime and never
// slides a pending (pre-MFA) session.
func TestRecordActivityNeverRevivesOrOutlivesASession(t *testing.T) {
	e := newEnv(t)
	secret, res := e.bootstrap(t)
	p, err := e.svc.AuthenticatePassive(e.ctx, res.Token)
	require.NoError(t, err)

	e.clk.Advance(auth.SessionIdle)
	require.NoError(t, e.svc.RecordActivity(e.ctx, p), "a late activity is not an error")
	_, err = e.svc.AuthenticatePassive(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "an idle-expired session stays ended")
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)

	res = e.signIn(t, "admin", adminPassword, secret)
	start := e.clk.Now()
	p, err = e.svc.AuthenticatePassive(e.ctx, res.Token)
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "DELETE FROM sessions WHERE kind = 'full' AND id_hash <> $1", p.SessionHash)
	require.NoError(t, err)
	e.clk.Set(start.Add(auth.SessionAbsolute - 10*time.Minute))
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE sessions SET idle_expires_at = $1 WHERE id_hash = $2", e.clk.Now().Add(time.Minute), p.SessionHash)
	require.NoError(t, err)
	require.NoError(t, e.svc.RecordActivity(e.ctx, p))
	_, idle := e.sessionTimes(t, "full")
	assert.True(t, idle.Equal(start.Add(auth.SessionAbsolute).UTC()), "the idle deadline never passes the absolute one: %v", idle)

	require.NoError(t, e.svc.Logout(e.ctx, p, meta))
	require.NoError(t, e.svc.RecordActivity(e.ctx, p), "a signed-out session is not an error")
	_, err = e.svc.AuthenticatePassive(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)

	lr, err := e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.NoError(t, err)
	pending, err := e.svc.AuthenticatePassive(e.ctx, lr.SessionToken)
	require.NoError(t, err)
	_, before := e.sessionTimes(t, "pending")
	e.clk.Advance(time.Minute)
	require.NoError(t, e.svc.RecordActivity(e.ctx, pending))
	_, after := e.sessionTimes(t, "pending")
	assert.True(t, before.Equal(after), "a pending session never slides")
}
