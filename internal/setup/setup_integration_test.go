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

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/clock"
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
	ctx   context.Context
	clk   *clock.Fake
	db    *pgtest.DB
	auth  *auth.Service
	setup *setup.Service
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
	s := setup.New(setup.Config{Pool: d.App, Auth: a, Keyring: kr, Audit: log, Clock: clk, Hasher: h, BackupKDF: fastKDF})
	return &env{ctx: context.Background(), clk: clk, db: d, auth: a, setup: s}
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

	st, err := e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.Equal(t, setup.Status{AdminExists: true, RecoveryPassphraseSet: true, Completed: true, DefaultLocale: "tr"}, st)
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
	assert.Equal(t, []string{"setup.admin_created", "setup.recovery_passphrase_set", "setup.completed"}, actions)
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
