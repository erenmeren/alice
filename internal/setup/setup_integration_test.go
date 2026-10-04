//go:build integration

package setup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var (
	fastParams = auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
	fastKDF    = secrets.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}
	ip1        = auth.Meta{IP: netip.MustParseAddr("192.0.2.1"), RequestID: "r1"}
	ip2        = auth.Meta{IP: netip.MustParseAddr("192.0.2.2"), RequestID: "r2"}
)

const (
	password   = "correct horse battery staple"
	passphrase = "uzun ve güvenli bir kurtarma parolası"
)

type env struct {
	ctx     context.Context
	clk     *clock.Fake
	db      *pgtest.DB
	auth    *auth.Service
	setup   *setup.Service
	license *stubLicense
}

// stubLicense stands in for license.Service in the wizard tests. It records whether it was
// asked inside a transaction.
type stubLicense struct {
	installed bool
	inTx      []bool
}

func (s *stubLicense) Installed(_ context.Context, q db.Querier) (bool, error) {
	_, tx := q.(pgx.Tx)
	s.inTx = append(s.inTx, tx)
	return s.installed, nil
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := pgtest.New(t)
	clk := clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	kr, err := secrets.NewKeyring(1, bytes.Repeat([]byte{9}, 32))
	require.NoError(t, err)
	h := auth.NewHasher(fastParams, 4)
	log := audit.New(clk)
	a := auth.NewService(auth.Config{Pool: d.App, Keyring: kr, Audit: log, Clock: clk, Hasher: h, RecoveryHasher: h})
	lic := &stubLicense{}
	s := setup.New(setup.Config{Pool: d.App, Auth: a, Keyring: kr, Audit: log, Clock: clk, Hasher: h, BackupKDF: fastKDF, License: lic})
	return &env{ctx: context.Background(), clk: clk, db: d, auth: a, setup: s, license: lic}
}

func (e *env) session(t *testing.T) string {
	t.Helper()
	code, err := e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	token, err := e.setup.StartSession(e.ctx, code, ip1)
	require.NoError(t, err)
	return token
}

// createAdmin runs wizard steps 0-2 and returns the new session and TOTP secret.
func (e *env) createAdmin(t *testing.T) (auth.SessionResult, string) {
	t.Helper()
	token := e.session(t)
	require.NoError(t, e.setup.SetLanguage(e.ctx, token, "tr"))
	enr, err := e.setup.BeginAdminEnrollment(e.ctx, token, setup.AdminInput{Username: "admin", DisplayName: "Ayşe Yılmaz", Password: password})
	require.NoError(t, err)
	code, err := totp.GenerateCode(enr.Secret, e.clk.Now())
	require.NoError(t, err)
	res, err := e.setup.CreateAdmin(e.ctx, token, code, ip1)
	require.NoError(t, err)
	return res, enr.Secret
}

func (e *env) settingRaw(t *testing.T, key string) string {
	t.Helper()
	var raw string
	err := e.db.Owner.QueryRow(e.ctx, "SELECT value::text FROM settings WHERE key = $1", key).Scan(&raw)
	if err != nil {
		return ""
	}
	return raw
}

func TestResetTokenWorksOnlyBeforeTheAdminExists(t *testing.T) {
	e := newEnv(t)
	st, err := e.setup.Status(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, setup.Status{DefaultLocale: "en"}, st)

	code, err := e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	assert.Regexp(t, `^[0-9A-Z]{6}(-[0-9A-Z]{6}){3}$`, code)
	stored := e.settingRaw(t, "setup.token_hash")
	assert.Len(t, strings.Trim(stored, `"`), 64, "only the SHA-256 is stored")
	assert.NotContains(t, stored, strings.ReplaceAll(code, "-", ""))

	e.createAdmin(t)
	_, err = e.setup.ResetToken(e.ctx)
	assert.ErrorIs(t, err, setup.ErrAlreadySetUp)
}

func TestStartSessionChecksTheCodeAndLocksOneAddress(t *testing.T) {
	e := newEnv(t)
	_, err := e.setup.StartSession(e.ctx, "anything", ip1)
	require.ErrorIs(t, err, setup.ErrCodeInvalid, "no code has been created yet")
	e.setup.ResetLockouts()

	code, err := e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	for range setup.MaxCodeFailures {
		_, err = e.setup.StartSession(e.ctx, "WRONG1-WRONG2-WRONG3-WRONG4", ip1)
		require.ErrorIs(t, err, setup.ErrCodeInvalid)
	}
	_, err = e.setup.StartSession(e.ctx, code, ip1)
	var locked *setup.LockedError
	require.ErrorAs(t, err, &locked, "five wrong codes lock this address, even for the right code")
	assert.Equal(t, setup.CodeLockDuration, locked.RetryAfter)

	lower := strings.Map(unicode.ToLower, strings.ReplaceAll(code, "-", " ")) // ASCII code typed in lower case
	_, err = e.setup.StartSession(e.ctx, lower, ip2)
	require.NoError(t, err, "another address is not locked; case and separators do not matter")

	e.clk.Advance(setup.CodeLockDuration)
	_, err = e.setup.StartSession(e.ctx, code, ip1)
	require.NoError(t, err)

	first, err := e.setup.StartSession(e.ctx, code, ip1)
	require.NoError(t, err)
	_, err = e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	assert.ErrorIs(t, e.setup.Authenticate(e.ctx, first), setup.ErrSessionInvalid, "a new code ends old wizard sessions")
	_, err = e.setup.StartSession(e.ctx, code, ip2)
	assert.ErrorIs(t, err, setup.ErrCodeInvalid, "the old code no longer works")
}

func TestSetupSessionIdleTimeout(t *testing.T) {
	e := newEnv(t)
	token := e.session(t)
	e.clk.Advance(59 * time.Minute)
	require.NoError(t, e.setup.Authenticate(e.ctx, token))
	e.clk.Advance(59 * time.Minute)
	require.NoError(t, e.setup.Authenticate(e.ctx, token), "activity restarts the 60 minute timer")
	e.clk.Advance(61 * time.Minute)
	assert.ErrorIs(t, e.setup.Authenticate(e.ctx, token), setup.ErrSessionInvalid)
	assert.ErrorIs(t, e.setup.Authenticate(e.ctx, ""), setup.ErrSessionInvalid)
	assert.ErrorIs(t, e.setup.Authenticate(e.ctx, "garbage"), setup.ErrSessionInvalid)
}

func TestSetLanguage(t *testing.T) {
	e := newEnv(t)
	token := e.session(t)
	var v validate.Errors
	require.ErrorAs(t, e.setup.SetLanguage(e.ctx, token, "de"), &v)
	assert.Equal(t, "language", v[0].Field)
	assert.ErrorIs(t, e.setup.SetLanguage(e.ctx, "bad", "tr"), setup.ErrSessionInvalid)
	require.NoError(t, e.setup.SetLanguage(e.ctx, token, "tr"))
	st, err := e.setup.Status(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, "tr", st.DefaultLocale)
}

func TestBeginAdminEnrollmentValidatesAndEncrypts(t *testing.T) {
	e := newEnv(t)
	token := e.session(t)
	var v validate.Errors
	_, err := e.setup.BeginAdminEnrollment(e.ctx, token, setup.AdminInput{Username: "İsmail", DisplayName: "İsmail", Password: password})
	require.ErrorAs(t, err, &v)
	assert.Equal(t, validate.Pattern, v[0].Code)
	_, err = e.setup.BeginAdminEnrollment(e.ctx, token, setup.AdminInput{Username: "admin", DisplayName: "A", Password: "kısa"})
	require.ErrorIs(t, err, auth.ErrPasswordTooShort)
	_, err = e.setup.BeginAdminEnrollment(e.ctx, token, setup.AdminInput{Username: "admin", DisplayName: "A", Password: "qwerty123456"})
	require.ErrorIs(t, err, auth.ErrPasswordBreached)

	enr, err := e.setup.BeginAdminEnrollment(e.ctx, token, setup.AdminInput{Username: "admin", DisplayName: "A", Password: password})
	require.NoError(t, err)
	assert.NotEmpty(t, enr.Secret)
	assert.NotEmpty(t, enr.QRPNG)
	var hash string
	var ct []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT pending_password_hash, totp_secret_ct FROM setup_sessions").Scan(&hash, &ct))
	assert.True(t, strings.HasPrefix(hash, "$argon2id$"))
	assert.NotContains(t, string(ct), enr.Secret, "the pending TOTP secret is encrypted")
}

func TestCreateAdminEndsTheWizard(t *testing.T) {
	e := newEnv(t)
	token := e.session(t)
	_, err := e.setup.CreateAdmin(e.ctx, token, "123456", ip1)
	require.ErrorIs(t, err, setup.ErrEnrollmentMissing)

	require.NoError(t, e.setup.SetLanguage(e.ctx, token, "tr"))
	enr, err := e.setup.BeginAdminEnrollment(e.ctx, token, setup.AdminInput{Username: "admin", DisplayName: "Ayşe Yılmaz", Password: password})
	require.NoError(t, err)
	wrong, err := totp.GenerateCode(enr.Secret, e.clk.Now().Add(time.Hour))
	require.NoError(t, err)
	_, err = e.setup.CreateAdmin(e.ctx, token, wrong, ip1)
	require.ErrorIs(t, err, auth.ErrMFAInvalid)

	right, err := totp.GenerateCode(enr.Secret, e.clk.Now())
	require.NoError(t, err)
	res, err := e.setup.CreateAdmin(e.ctx, token, right, ip1)
	require.NoError(t, err)
	assert.Len(t, res.RecoveryCodes, 10)
	assert.Equal(t, rbac.Admin, res.Info.User.Role)
	assert.Equal(t, "tr", res.Info.User.Locale, "the wizard language becomes the admin's language")
	assert.Equal(t, "Ayşe Yılmaz", res.Info.User.DisplayName)

	var seq int64
	var action string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT seq, action FROM audit_log ORDER BY seq LIMIT 1").Scan(&seq, &action))
	assert.Equal(t, int64(1), seq)
	assert.Equal(t, "setup.admin_created", action, "the admin creation is the first link of the audit chain")
	assert.Empty(t, e.settingRaw(t, "setup.token_hash"), "the setup code is deleted")
	var sessions int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM setup_sessions").Scan(&sessions))
	assert.Zero(t, sessions)

	assert.ErrorIs(t, e.setup.Authenticate(e.ctx, token), setup.ErrSessionInvalid)
	_, err = e.setup.StartSession(e.ctx, "whatever", ip2)
	assert.ErrorIs(t, err, setup.ErrAlreadySetUp)
	st, err := e.setup.Status(e.ctx)
	require.NoError(t, err)
	assert.True(t, st.AdminExists)

	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	assert.Equal(t, rbac.UserSession, p.Kind)
}

func TestRecoveryPassphraseAndCompletion(t *testing.T) {
	e := newEnv(t)
	res, _ := e.createAdmin(t)
	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)

	require.ErrorIs(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, "too short 15 ch", "too short 15 ch"), setup.ErrPassphraseTooShort)
	require.ErrorIs(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase+"x"), setup.ErrPassphraseMismatch)
	var v validate.Errors
	long := strings.Repeat("ş", setup.MaxPassphraseLength+1)
	require.ErrorAs(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, long, long), &v)
	_, err = e.setup.Complete(e.ctx, p, ip1)
	require.ErrorIs(t, err, setup.ErrIncomplete)

	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase))
	raw := e.settingRaw(t, "backup.key")
	assert.NotContains(t, raw, "kurtarma", "the passphrase itself is never stored")
	var w secrets.WrappedBackupKey
	require.NoError(t, json.Unmarshal([]byte(raw), &w))
	priv, err := w.Unwrap([]byte(passphrase))
	require.NoError(t, err)
	assert.Equal(t, w.PublicKey, priv.PublicKey().Bytes())
	_, err = w.Unwrap([]byte("wrong passphrase, long enough"))
	assert.ErrorIs(t, err, secrets.ErrDecrypt)
	require.ErrorIs(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase), setup.ErrPassphraseAlreadySet)

	_, err = e.setup.Complete(e.ctx, p, ip1)
	require.ErrorIs(t, err, setup.ErrLicenseChoiceMissing, "the license step comes before Finish")
	st, err := e.setup.ChooseEvaluation(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.True(t, st.LicenseChosen)
	assert.False(t, st.Completed)
	_, err = e.setup.ChooseEvaluation(e.ctx, p, ip1)
	require.NoError(t, err, "choosing twice is harmless")

	st, err = e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.Equal(t, setup.Status{AdminExists: true, RecoveryPassphraseSet: true, LicenseChosen: true, Completed: true, DefaultLocale: "tr"}, st)
	_, err = e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err, "completing twice is harmless")

	rows, err := e.db.Owner.Query(e.ctx, "SELECT action FROM audit_log WHERE action LIKE 'setup.%' ORDER BY seq")
	require.NoError(t, err)
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var a string
		require.NoError(t, rows.Scan(&a))
		actions = append(actions, a)
	}
	assert.Equal(t, []string{"setup.admin_created", "setup.recovery_passphrase_set", "setup.evaluation_chosen", "setup.completed"}, actions)
}

func TestCodeLockoutGroupsIPv6By64(t *testing.T) {
	e := newEnv(t)
	code, err := e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	at := func(ip string) auth.Meta { return auth.Meta{IP: netip.MustParseAddr(ip)} }
	for i := range setup.MaxCodeFailures {
		// Rotating through addresses of one /64 does not escape the lockout.
		_, err = e.setup.StartSession(e.ctx, "WRONG1-WRONG2-WRONG3-WRONG4", at(fmt.Sprintf("2001:db8:1:2::%x", i+1)))
		require.ErrorIs(t, err, setup.ErrCodeInvalid)
	}
	var locked *setup.LockedError
	_, err = e.setup.StartSession(e.ctx, code, at("2001:db8:1:2:ffff::9"))
	require.ErrorAs(t, err, &locked, "the whole /64 is locked")
	_, err = e.setup.StartSession(e.ctx, code, at("2001:db8:1:3::1"))
	require.NoError(t, err, "another /64 is not locked")
	_, err = e.setup.StartSession(e.ctx, code, at("::ffff:192.0.2.1"))
	require.NoError(t, err, "an IPv4-mapped address is keyed as IPv4")
}

func TestParallelWrongCodesAreCountedExactly(t *testing.T) {
	e := newEnv(t)
	_, err := e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	const n = 20
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { _, errs[i] = e.setup.StartSession(e.ctx, "WRONG1-WRONG2-WRONG3-WRONG4", ip1) })
	}
	wg.Wait()
	invalid, lockedCount := 0, 0
	for _, err := range errs {
		var locked *setup.LockedError
		switch {
		case errors.Is(err, setup.ErrCodeInvalid):
			invalid++
		case errors.As(err, &locked):
			lockedCount++
		default:
			t.Fatalf("unexpected result: %v", err)
		}
	}
	assert.Equal(t, setup.MaxCodeFailures, invalid, "no more than five codes are compared before the lock")
	assert.Equal(t, n-setup.MaxCodeFailures, lockedCount)
}

func TestConcurrentCreateAdminMakesExactlyOneAdministrator(t *testing.T) {
	e := newEnv(t)
	code, err := e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	const n = 2
	tokens := make([]string, n)
	codes := make([]string, n)
	for i := range n {
		tokens[i], err = e.setup.StartSession(e.ctx, code, ip1)
		require.NoError(t, err)
		enr, err := e.setup.BeginAdminEnrollment(e.ctx, tokens[i], setup.AdminInput{Username: fmt.Sprintf("admin%d", i), DisplayName: "A", Password: password})
		require.NoError(t, err)
		codes[i], err = totp.GenerateCode(enr.Secret, e.clk.Now())
		require.NoError(t, err)
	}
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { _, errs[i] = e.setup.CreateAdmin(e.ctx, tokens[i], codes[i], ip1) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		assert.True(t, errors.Is(err, setup.ErrAlreadySetUp) || errors.Is(err, setup.ErrSessionInvalid), "loser gets %v", err)
	}
	assert.Equal(t, 1, ok, "exactly one browser creates the administrator")
	var users, links int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM users").Scan(&users))
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM audit_log WHERE action = 'setup.admin_created'").Scan(&links))
	assert.Equal(t, 1, users)
	assert.Equal(t, 1, links)
}

func TestPassphraseIsNormalized(t *testing.T) {
	e := newEnv(t)
	res, _ := e.createAdmin(t)
	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	composed := "şifre çözme anahtarı güçlü"                                       // precomposed ş, ç, ö, ü
	decomposed := "s\u0327ifre c\u0327o\u0308zme anahtarı gu\u0308c\u0327lu\u0308" // the same text, decomposed
	require.NotEqual(t, composed, decomposed)
	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, decomposed, composed), "NFKC makes both typings equal")
	var w secrets.WrappedBackupKey
	require.NoError(t, json.Unmarshal([]byte(e.settingRaw(t, "backup.key")), &w))
	_, err = w.Unwrap([]byte(composed))
	require.NoError(t, err, "the NFKC form wraps the key")
}

func TestConcurrentPassphrasesSetExactlyOnce(t *testing.T) {
	e := newEnv(t)
	res, _ := e.createAdmin(t)
	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	const n = 4
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { errs[i] = e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		assert.ErrorIs(t, err, setup.ErrPassphraseAlreadySet)
	}
	assert.Equal(t, 1, ok)
	var links int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM audit_log WHERE action = 'setup.recovery_passphrase_set'").Scan(&links))
	assert.Equal(t, 1, links)
}

// TestPassphraseAndCompleteRequireSettingsManage checks the service-level guard: only an
// administrator's browser session inside its step-up window may set the passphrase or
// finish the wizard, even if a route were misconfigured.
func TestPassphraseAndCompleteRequireSettingsManage(t *testing.T) {
	e := newEnv(t)
	res, _ := e.createAdmin(t)
	admin, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)

	// A real Operator session (inside its own step-up window).
	_, err = e.auth.CreateUser(e.ctx, admin, ip1, auth.NewUser{Username: "operator1", DisplayName: "O", Role: rbac.Operator, Password: password})
	require.NoError(t, err)
	lr, err := e.auth.Login(e.ctx, "operator1", password, ip1)
	require.NoError(t, err)
	pending, err := e.auth.Authenticate(e.ctx, lr.SessionToken)
	require.NoError(t, err)
	enr, err := e.auth.EnrollMFA(e.ctx, pending, ip1)
	require.NoError(t, err)
	opCode, err := totp.GenerateCode(enr.Secret, e.clk.Now())
	require.NoError(t, err)
	opRes, err := e.auth.VerifyMFA(e.ctx, pending, auth.MFAInput{Code: opCode}, ip1)
	require.NoError(t, err)
	operator, err := e.auth.Authenticate(e.ctx, opRes.Token)
	require.NoError(t, err)
	require.Equal(t, rbac.Operator, operator.Role)

	// An API token of the administrator.
	bearer, _, err := e.auth.CreateToken(e.ctx, admin, ip1, auth.NewToken{Name: "ci", Scope: rbac.ScopeOperate, ExpiresInDays: 30})
	require.NoError(t, err)
	token, err := e.auth.AuthenticateToken(e.ctx, bearer)
	require.NoError(t, err)
	require.Equal(t, rbac.APIToken, token.Kind)

	for name, p := range map[string]auth.Principal{"operator": operator, "api token": token} {
		assert.ErrorIs(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase), setup.ErrForbidden, name)
	}
	assert.Empty(t, e.settingRaw(t, "backup.key"), "nothing was stored")

	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, admin, ip1, passphrase, passphrase))
	for name, p := range map[string]auth.Principal{"operator": operator, "api token": token} {
		_, err = e.setup.Complete(e.ctx, p, ip1)
		assert.ErrorIs(t, err, setup.ErrForbidden, name)
		_, err = e.setup.ChooseEvaluation(e.ctx, p, ip1)
		assert.ErrorIs(t, err, setup.ErrForbidden, name)
	}

	e.clk.Advance(auth.StepUpWindow + time.Second)
	stale, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	assert.ErrorIs(t, e.setup.SetRecoveryPassphrase(e.ctx, stale, ip1, passphrase, passphrase), setup.ErrForbidden,
		"an administrator without a recent step-up is refused before anything else is checked")
	_, err = e.setup.Complete(e.ctx, stale, ip1)
	assert.ErrorIs(t, err, setup.ErrForbidden)
	_, err = e.setup.ChooseEvaluation(e.ctx, stale, ip1)
	assert.ErrorIs(t, err, setup.ErrForbidden)
	assert.Empty(t, e.settingRaw(t, "setup.license_choice"))
	assert.Empty(t, e.settingRaw(t, "setup.completed_at"), "the wizard is not completed")

	var completed int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM audit_log WHERE action = 'setup.completed'").Scan(&completed))
	assert.Zero(t, completed)
}

// An uploaded license completes the license step without the evaluation choice.
func TestAnInstalledLicenseCompletesTheLicenseStep(t *testing.T) {
	e := newEnv(t)
	res, _ := e.createAdmin(t)
	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase))
	st, err := e.setup.Status(e.ctx)
	require.NoError(t, err)
	assert.False(t, st.LicenseChosen)

	e.license.installed = true
	st, err = e.setup.Status(e.ctx)
	require.NoError(t, err)
	assert.True(t, st.LicenseChosen)
	e.license.inTx = nil
	st, err = e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.True(t, st.Completed)
	require.NotEmpty(t, e.license.inTx)
	assert.True(t, e.license.inTx[0], "Complete asks inside its transaction (B4): no second connection under the advisory lock")
}

func TestEvaluationChoiceNeedsThePassphraseFirst(t *testing.T) {
	e := newEnv(t)
	res, _ := e.createAdmin(t)
	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	_, err = e.setup.ChooseEvaluation(e.ctx, p, ip1)
	require.ErrorIs(t, err, setup.ErrIncomplete)
	assert.Empty(t, e.settingRaw(t, "setup.license_choice"))
}

// An install that finished setup (also under Phase 1, before the license step existed)
// stays finished: completing again answers as before, without asking for a license choice.
func TestCompletingAFinishedInstallNeedsNoLicenseChoice(t *testing.T) {
	e := newEnv(t)
	res, _ := e.createAdmin(t)
	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase))
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('setup.completed_at', '"2026-09-01T00:00:00Z"', now())`)
	require.NoError(t, err)

	st, err := e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err, "no new 409 for a finished install")
	assert.True(t, st.Completed)
}

func (e *env) readyToCreate(t *testing.T) (token, code string) {
	t.Helper()
	token = e.session(t)
	enr, err := e.setup.BeginAdminEnrollment(e.ctx, token, setup.AdminInput{Username: "admin", DisplayName: "A", Password: password})
	require.NoError(t, err)
	code, err = totp.GenerateCode(enr.Secret, e.clk.Now())
	require.NoError(t, err)
	return token, code
}

func (e *env) userCount(t *testing.T) int {
	t.Helper()
	var users int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM users").Scan(&users))
	return users
}

// waitForLockWait blocks until some backend waits for a lock: the statement under test is queued
// behind the transaction the test holds open (no sleeps: it polls the server's own wait state).
func (e *env) waitForLockWait(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		var n int
		err := e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()").Scan(&n)
		return err == nil && n > 0
	}, 10*time.Second, 5*time.Millisecond)
}

// AUD-21: a setup code reset between the session check and the administrator's creation wins: no
// administrator is created and the old session is refused.
func TestResetDuringAdminCreationWins(t *testing.T) {
	e := newEnv(t)
	token, code := e.readyToCreate(t)
	setup.SetBeforeBootstrap(e.setup, func() {
		_, err := e.setup.ResetToken(e.ctx) // the host-root CLI, between the check and the creation
		require.NoError(t, err)
	})
	_, err := e.setup.CreateAdmin(e.ctx, token, code, ip1)
	require.ErrorIs(t, err, setup.ErrSessionInvalid)
	assert.Zero(t, e.userCount(t))
}

// AUD-21: the creation commits first; the reset then finds the administrator and changes nothing.
func TestResetAfterAdminCreationReportsTheAdministrator(t *testing.T) {
	e := newEnv(t)
	token, code := e.readyToCreate(t)
	_, err := e.setup.CreateAdmin(e.ctx, token, code, ip1)
	require.NoError(t, err)
	_, err = e.setup.ResetToken(e.ctx)
	require.ErrorIs(t, err, setup.ErrAlreadySetUp)
	assert.Equal(t, 1, e.userCount(t))
}

// AUD-21: the reset arrives while the creation holds the users lock: it waits, the creation
// commits, and the reset reports the administrator.
func TestResetWaitingBehindAdminCreationFindsTheAdministrator(t *testing.T) {
	e := newEnv(t)
	token, code := e.readyToCreate(t)
	resetErr := make(chan error, 1)
	setup.SetInBootstrapTx(e.setup, func() {
		go func() {
			_, err := e.setup.ResetToken(e.ctx)
			resetErr <- err
		}()
		e.waitForLockWait(t) // the reset is queued behind the creating transaction
		select {
		case err := <-resetErr:
			t.Errorf("the reset finished while the creation was open: %v", err)
		default:
		}
	})
	_, err := e.setup.CreateAdmin(e.ctx, token, code, ip1)
	require.NoError(t, err)
	assert.ErrorIs(t, <-resetErr, setup.ErrAlreadySetUp)
	assert.Equal(t, 1, e.userCount(t))
}

// AUD-21: a wizard session opened with the old code whose commit races the reset does not
// survive it: the session cannot create the administrator afterwards.
func TestSessionOpenedWithTheOldCodeDoesNotSurviveAConcurrentReset(t *testing.T) {
	e := newEnv(t)
	old, err := e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	resetDone := make(chan string, 1)
	setup.SetAfterCodeCheck(e.setup, func() {
		go func() {
			c, err := e.setup.ResetToken(e.ctx)
			assert.NoError(t, err)
			resetDone <- c
		}()
		e.waitForLockWait(t) // the reset is queued behind the code's row lock
	})
	token, err := e.setup.StartSession(e.ctx, old, ip1)
	require.NoError(t, err)
	fresh := <-resetDone
	assert.ErrorIs(t, e.setup.Authenticate(e.ctx, token), setup.ErrSessionInvalid, "the reset deleted the session")
	_, err = e.setup.StartSession(e.ctx, old, ip1)
	assert.ErrorIs(t, err, setup.ErrCodeInvalid)
	_, err = e.setup.StartSession(e.ctx, fresh, ip1)
	assert.NoError(t, err)
}

// AUD-21: a reset that committed before the comparison makes the old code invalid.
func TestOldCodeIsRefusedAfterAReset(t *testing.T) {
	e := newEnv(t)
	old, err := e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	_, err = e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	_, err = e.setup.StartSession(e.ctx, old, ip1)
	assert.ErrorIs(t, err, setup.ErrCodeInvalid)
}

// AUD-21: truly concurrent creation and reset: exactly one outcome, and an administrator only
// ever exists when the creation committed before the reset (the reset then reports it).
func TestConcurrentResetAndCreateHaveExactlyOneOutcome(t *testing.T) {
	for range 5 {
		e := newEnv(t)
		token, code := e.readyToCreate(t)
		var createErr, resetErr error
		var wg sync.WaitGroup
		wg.Go(func() { _, createErr = e.setup.CreateAdmin(e.ctx, token, code, ip1) })
		wg.Go(func() { _, resetErr = e.setup.ResetToken(e.ctx) })
		wg.Wait()
		if createErr == nil {
			assert.ErrorIs(t, resetErr, setup.ErrAlreadySetUp)
			assert.Equal(t, 1, e.userCount(t))
		} else {
			assert.ErrorIs(t, createErr, setup.ErrSessionInvalid)
			assert.NoError(t, resetErr)
			assert.Zero(t, e.userCount(t))
		}
	}
}
